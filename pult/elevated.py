"""Связь с помощником с правами администратора (pult/admin_helper.py).

Один помощник на сеанс: Windows спрашивает разрешение один раз, при первом включении zapret или TUN.
Через него запускаются winws.exe (zapret), sing-box, tun2proxy и Xray в режиме TUN,
и включается туннель AmneziaWG (команда его клиента из Program Files).
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import sys
import threading
import time

IS_WINDOWS = sys.platform == "win32"


class AdminError(RuntimeError):
    """Windows не дала прав администратора."""


class AdminHelper:
    def __init__(self, app_dir: str, data_dir: str, allowed: dict[str, str]):
        self.app_dir = app_dir
        self.data_dir = data_dir
        self.allowed = allowed  # вид → путь к exe
        self.port = 0
        self.token = ""
        self.pid = 0
        self._lock = threading.Lock()

    def alive(self) -> bool:
        if not self.port:
            return False
        try:
            return bool(self.call({"cmd": "ping"}, timeout=2).get("ok"))
        except OSError:
            return False

    def ensure(self, wait: float = 60.0) -> None:
        with self._lock:
            if self.alive():
                return
            self.token = secrets.token_hex(16)
            port_file = os.path.join(self.data_dir, "admin_helper.json")
            try:
                os.remove(port_file)
            except OSError:
                pass
            script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "admin_helper.py")
            params = [script, "--token", self.token, "--port-file", port_file, "--parent", str(os.getpid()),
                      "--data", self.data_dir]
            for kind, path in self.allowed.items():
                params += ["--allow", f"{kind}={path}"]
            if IS_WINDOWS:
                import ctypes
                exe = sys.executable
                folder, name = os.path.split(exe)
                if name.lower() == "python.exe" and os.path.isfile(os.path.join(folder, "pythonw.exe")):
                    exe = os.path.join(folder, "pythonw.exe")
                rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, subprocess.list2cmdline(params),
                                                         self.app_dir, 0)
                if rc <= 32:
                    raise AdminError("Windows не дала права администратора")
            else:
                subprocess.Popen([sys.executable] + params, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
            deadline = time.time() + wait
            while time.time() < deadline:
                try:
                    with open(port_file, encoding="utf-8") as f:
                        info = json.load(f)
                    self.port, self.pid = int(info["port"]), int(info.get("pid") or 0)
                    if self.alive():
                        return
                except (OSError, ValueError, KeyError):
                    pass
                time.sleep(0.3)
            raise AdminError("не получил права администратора — нажми «Да» в окне Windows, когда оно появится")

    def call(self, msg: dict, timeout: float = 20.0) -> dict:
        msg = dict(msg, token=self.token)
        with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as s:
            s.sendall(json.dumps(msg).encode() + b"\n")
            data = b""
            while not data.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        return json.loads(data.decode("utf-8") or "{}")

    def start(self, name: str, kind: str, args: list[str], cwd: str = "") -> dict:
        self.ensure()
        exe = self.allowed[kind]
        return self.call({"cmd": "start", "name": name, "kind": kind, "exe": exe, "args": args,
                          "cwd": cwd or os.path.dirname(exe)})

    def run(self, kind: str, args: list[str], timeout: float = 40.0) -> dict:
        """Разовая команда (клиент AmneziaWG): помощник сам проверяет программу и параметры."""
        self.ensure()
        try:
            return self.call({"cmd": "run", "kind": kind, "args": args}, timeout=timeout + 5)
        except (OSError, ValueError) as exc:
            return {"ok": False, "error": str(exc)}

    def status(self, name: str) -> dict:
        if not self.port:
            return {"running": False, "error": ""}
        try:
            return self.call({"cmd": "status", "name": name}, timeout=3)
        except OSError:
            return {"running": False, "error": ""}

    def stop(self, name: str) -> None:
        if self.port:
            try:
                self.call({"cmd": "stop", "name": name}, timeout=8)
            except OSError:
                pass

    def shutdown(self) -> None:
        if self.port:
            try:
                self.call({"cmd": "quit"}, timeout=3)
            except OSError:
                pass
        self.port = 0
