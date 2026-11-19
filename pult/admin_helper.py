"""Помощник с правами администратора: zapret (WinDivert) и режим TUN (сетевой адаптер и маршруты).

Windows даёт ему права один раз за сеанс (окно «Разрешить этому приложению вносить изменения?»).
Он умеет только запускать и останавливать заранее известные программы из папки программы
(и разово выполнить команду клиента AmneziaWG из Program Files — включить или выключить наш туннель):
- слушает только 127.0.0.1 и требует секретный ключ;
- запускает только те файлы, пути к которым ему передали при старте (--allow вид=путь);
- для каждой программы проверяет параметры: ничего, что могло бы записать файлы в чужие места
  или выполнить команду с правами администратора;
- сам всё останавливает и закрывается, когда программа закрыта.
Файл не зависит от остальной программы (запускается отдельно, со своими правами).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time

IS_WINDOWS = sys.platform == "win32"


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return True
    if IS_WINDOWS:
        import ctypes
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(handle)
        return code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _norm(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _inside(path: str, folder: str) -> bool:
    p, f = _norm(path), _norm(folder)
    return p == f or p.startswith(f.rstrip("\\/") + os.sep)


AWG_NAME = re.compile(r"^[A-Za-z0-9_=+.-]{1,32}$")
AWG_SCRIPT_KEYS = {"preup", "postup", "predown", "postdown"}  # команды в конфиге WireGuard — с правами администратора нельзя
AWG_CONF_MAX = 65536


def awg_exe() -> str:
    """Клиент AmneziaWG — только из Program Files (туда может писать лишь администратор), путь не берётся извне."""
    if not IS_WINDOWS:
        return ""
    for env in ("ProgramW6432", "ProgramFiles"):
        root = os.environ.get(env)
        if root:
            path = os.path.join(root, "AmneziaWG", "amneziawg.exe")
            if os.path.isfile(path):
                return path
    return ""


T2P_FLAGS_WITH_VALUE = {"--proxy", "--dns", "--tun", "--bypass", "--verbosity", "-v"}
T2P_FLAGS = {"--setup", "--ipv6-enabled", "--exit-on-fatal-error"}


class Helper:
    def __init__(self, token: str, allowed: dict[str, str], parent: int, data_dir: str):
        self.token = token
        self.allowed = {k: _norm(v) for k, v in allowed.items()}
        self.parent = parent
        self.data_dir = data_dir
        self.procs: dict[str, subprocess.Popen] = {}
        self.tails: dict[str, bytes] = {}
        self.lock = threading.Lock()
        self.stop_flag = threading.Event()
        self.awg_exe = awg_exe

    # ---------- проверка параметров ----------

    def _check_config(self, path: str, kind: str) -> str:
        """Конфиг ядра читается помощником сам: пути журналов — только в папке data программы."""
        if not _inside(path, self.data_dir) or not os.path.isfile(path):
            return "конфиг вне папки программы"
        try:
            with open(path, encoding="utf-8") as f:
                cfg = json.load(f)
        except (OSError, ValueError):
            return "конфиг не читается"
        log = cfg.get("log") if isinstance(cfg.get("log"), dict) else {}
        if kind in ("xray", "xray_legacy"):
            for key in ("access", "error"):
                value = log.get(key)
                if value and not _inside(str(value), self.data_dir):
                    return "журнал вне папки программы"
        else:  # sing-box
            if log.get("output") or "experimental" in cfg:
                return "лишние параметры в конфиге"
        return ""

    def _check_args(self, kind: str, args: list) -> str:
        if not all(isinstance(a, str) for a in args):
            return "неверные параметры"
        if kind == "winws":
            if any(a.lower().startswith("--debug") for a in args):
                return "неверные параметры"
            return ""
        if kind in ("xray", "xray_legacy", "singbox"):
            if len(args) != 3 or args[0] != "run" or args[1] != "-c":
                return "неверные параметры"
            return self._check_config(args[2], kind)
        if kind == "tun2proxy":
            i = 0
            while i < len(args):
                a = args[i]
                if a in T2P_FLAGS:
                    i += 1
                elif a in T2P_FLAGS_WITH_VALUE and i + 1 < len(args):
                    if a == "--proxy" and not args[i + 1].startswith("socks5://127.0.0.1:"):
                        return "неверные параметры"
                    i += 2
                else:
                    return "неверные параметры"
            return ""
        return "запрещённая программа"

    def _check_run(self, kind: str, args: list) -> str:
        """Разовые команды: только клиент AmneziaWG и только «включить наш конфиг» или «выключить туннель»."""
        if kind != "awg":
            return "запрещённая программа"
        if len(args) != 2 or not all(isinstance(a, str) for a in args):
            return "неверные параметры"
        if args[0] == "/uninstalltunnelservice":
            return "" if AWG_NAME.match(args[1]) else "неверные параметры"
        if args[0] != "/installtunnelservice":
            return "неверные параметры"
        path, folder = args[1], os.path.join(self.data_dir, "awg")
        base = os.path.basename(path)
        if not _inside(path, folder) or os.path.islink(path) or not base.endswith(".conf") \
                or not AWG_NAME.match(base[:-5]) or not os.path.isfile(path):
            return "конфиг вне папки программы"
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read(AWG_CONF_MAX + 1)
        except (OSError, UnicodeDecodeError):
            return "конфиг не читается"
        if len(text) > AWG_CONF_MAX:
            return "конфиг слишком большой"
        for line in text.splitlines():
            if line.split("=", 1)[0].strip().lower() in AWG_SCRIPT_KEYS:
                return "в конфиге есть команды PreUp/PostUp — они запрещены"
        return ""

    def run(self, kind: str, args: list, timeout: float = 40.0) -> dict:
        error = self._check_run(kind, list(args))
        if error:
            return {"ok": False, "error": error}
        exe = self.awg_exe()
        if not exe:
            return {"ok": False, "error": "клиент AmneziaWG не установлен"}
        try:
            r = self._exec([exe] + list(args), timeout)
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "клиент AmneziaWG не ответил"}
        except OSError as exc:
            return {"ok": False, "error": str(exc)}
        out = (r.stdout + r.stderr).decode("utf-8", "replace").strip()[-400:]
        return {"ok": r.returncode == 0, "code": r.returncode,
                "error": "" if r.returncode == 0 else (out or f"код выхода {r.returncode}")}

    @staticmethod
    def _exec(cmd: list, timeout: float) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
                              creationflags=0x08000000 if IS_WINDOWS else 0)

    # ---------- процессы ----------

    def _read_out(self, name: str, proc: subprocess.Popen) -> None:
        try:
            for line in proc.stdout:
                self.tails[name] = (self.tails.get(name, b"") + line)[-3000:]
        except (OSError, ValueError):
            pass

    def start(self, name: str, kind: str, exe: str, args: list, cwd: str) -> dict:
        if kind not in self.allowed or _norm(exe) != self.allowed[kind]:
            return {"ok": False, "error": "запрещённая программа"}
        error = self._check_args(kind, list(args))
        if error:
            return {"ok": False, "error": error}
        self.stop(name)
        flags = 0x08000000 if IS_WINDOWS else 0  # без окна консоли
        try:
            proc = subprocess.Popen([exe] + list(args), cwd=cwd or None, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=flags)
        except OSError as exc:
            return {"ok": False, "error": str(exc)}
        with self.lock:
            self.procs[name] = proc
            self.tails[name] = b""
        threading.Thread(target=self._read_out, args=(name, proc), daemon=True).start()
        time.sleep(1.0)
        if proc.poll() is not None:
            time.sleep(0.2)
            return {"ok": False, "error": self._tail(name) or f"код выхода {proc.returncode}"}
        return {"ok": True, "pid": proc.pid}

    def _tail(self, name: str) -> str:
        return self.tails.get(name, b"").decode("utf-8", "replace").strip()[-400:]

    def stop(self, name: str) -> dict:
        with self.lock:
            proc = self.procs.pop(name, None)
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
        return {"ok": True}

    def stop_all(self) -> None:
        for name in list(self.procs):
            self.stop(name)

    def status(self, name: str) -> dict:
        proc = self.procs.get(name)
        running = bool(proc and proc.poll() is None)
        return {"ok": True, "running": running, "error": "" if running else self._tail(name), "log": self._tail(name)}

    def handle(self, msg: dict) -> dict:
        if msg.get("token") != self.token:
            return {"ok": False, "error": "неверный ключ"}
        cmd = msg.get("cmd")
        name = str(msg.get("name") or "main")
        if cmd == "ping":
            return {"ok": True}
        if cmd == "start":
            return self.start(name, str(msg.get("kind", "")), str(msg.get("exe", "")), list(msg.get("args") or []),
                              str(msg.get("cwd", "")))
        if cmd == "stop":
            return self.stop(name)
        if cmd == "run":
            return self.run(str(msg.get("kind", "")), list(msg.get("args") or []))
        if cmd == "status":
            return self.status(name)
        if cmd == "quit":
            self.stop_all()
            self.stop_flag.set()
            return {"ok": True}
        return {"ok": False, "error": "неизвестная команда"}

    def watchdog(self) -> None:
        while not self.stop_flag.wait(3):
            if not pid_alive(self.parent):
                self.stop_all()
                self.stop_flag.set()


def serve(helper: Helper, port_file: str) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(1.0)
    tmp = port_file + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"port": srv.getsockname()[1], "pid": os.getpid()}, f)
    os.replace(tmp, port_file)
    threading.Thread(target=helper.watchdog, daemon=True).start()
    while not helper.stop_flag.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        threading.Thread(target=_client, args=(helper, conn), daemon=True).start()
    helper.stop_all()
    srv.close()


def _client(helper: Helper, conn: socket.socket) -> None:
    with conn:
        conn.settimeout(15)
        data = b""
        try:
            while not data.endswith(b"\n") and len(data) < 1_000_000:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
            reply = helper.handle(json.loads(data.decode("utf-8") or "{}"))
        except (OSError, ValueError) as exc:
            reply = {"ok": False, "error": str(exc)}
        try:
            conn.sendall(json.dumps(reply, ensure_ascii=False).encode() + b"\n")
        except OSError:
            pass


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--token", required=True)
    p.add_argument("--port-file", required=True)
    p.add_argument("--parent", type=int, default=0)
    p.add_argument("--data", required=True)
    p.add_argument("--allow", action="append", default=[])
    a = p.parse_args()
    allowed = dict(item.split("=", 1) for item in a.allow if "=" in item)
    serve(Helper(a.token, allowed, a.parent, a.data), a.port_file)


if __name__ == "__main__":
    main()
