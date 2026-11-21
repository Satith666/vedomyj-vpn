"""Обход замедлений без VPN: zapret (winws.exe из сборки Flowseal/zapret-discord-youtube) и ByeDPI (ciadpi.exe).

Как это работает:
- zapret перехватывает пакеты на уровне Windows (драйвер WinDivert), поэтому ему нужны права администратора.
  Его запускает помощник admin_helper.py, которому Windows один раз за сеанс даёт эти права.
- ByeDPI — обычная программа-прокси (SOCKS5 на 127.0.0.1), прав администратора не требует.
- Стратегия — набор параметров запуска. Программа перебирает стратегии и проверяет YouTube и Discord.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

from . import netutil

IS_WINDOWS = sys.platform == "win32"
ZAPRET_REPO = "Flowseal/zapret-discord-youtube"
BYEDPI_REPO = "hufrea/byedpi"

YOUTUBE_DOMAINS = ["youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com", "youtube-nocookie.com",
                   "youtubei.googleapis.com", "yt.be"]
DISCORD_DOMAINS = ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com",
                   "discord.dev", "discord.new", "discord.gift", "discordstatus.com", "dis.gd"]

# Что проверяем: (хост, путь, сколько байт скачать). Замедление видно по тому, что большая страница
# не докачивается или качается очень медленно; блокировка — по обрыву соединения.
CHECKS = {
    "youtube": [("www.youtube.com", "/", 600_000), ("redirector.googlevideo.com", "/report_mapping", 2_000)],
    "discord": [("discord.com", "/api/v9/experiments", 2_000), ("gateway.discord.gg", "/", 500)],
}

# Наборы параметров ByeDPI: (понятное название, параметры)
BYEDPI_STRATEGIES = [
    ("Перестановка частей", "--disorder 1"),
    ("Разделение и запись TLS", "--split 1+s --tlsrec 1+s"),
    ("Перестановка и запись TLS", "--disorder 1 --tlsrec 1+s"),
    ("Поддельный пакет", "--fake -1 --ttl 8"),
    ("Поддельный пакет и запись TLS", "--fake -1 --ttl 8 --tlsrec 1+s"),
    ("Разделение и перестановка", "--split 1+s --disorder 3+s"),
    ("Перестановка с поддельным пакетом", "--disorder 1 --fake -1"),
    ("Внеполосные данные", "--oob 1"),
    ("Внеполосные данные и запись TLS", "--oob 1 --tlsrec 1+s"),
    ("Авто: при сбросе соединения", "--disorder 1 --auto=torst --tlsrec 1+s"),
    ("Поддельный пакет, короткий TTL", "--fake -1 --ttl 5"),
    ("Разделение SNI", "--split 1+h --disorder 1+h"),
]


class DpiError(RuntimeError):
    pass


class DpiAdminError(DpiError):
    """Windows не дала прав администратора — без них zapret не работает."""


# ---------- пути ----------

class DpiPaths:
    def __init__(self, bin_dir: str, data_dir: str):
        self.zapret_dir = os.path.join(bin_dir, "zapret")
        self.byedpi_dir = os.path.join(bin_dir, "byedpi")
        self.data_dir = data_dir

    @property
    def winws(self) -> str:
        return os.path.join(self.zapret_dir, "bin", "winws.exe")

    @property
    def ciadpi(self) -> str:
        return os.path.join(self.byedpi_dir, "ciadpi.exe" if IS_WINDOWS else "ciadpi")

    def zapret_installed(self) -> bool:
        return os.path.isfile(self.winws)

    def byedpi_installed(self) -> bool:
        return os.path.isfile(self.ciadpi)

    def version(self, which: str) -> str:
        path = os.path.join(self.zapret_dir if which == "zapret" else self.byedpi_dir, "version.txt")
        try:
            with open(path, encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            return ""


# ---------- стратегии zapret из .bat-файлов ----------

def _expand(text: str, root: str) -> str:
    bin_dir = os.path.join(root, "bin") + os.sep
    lists = os.path.join(root, "lists") + os.sep
    values = {"BIN": bin_dir, "LISTS": lists, "GAMEFILTER": "12", "GAMEFILTERTCP": "12", "GAMEFILTERUDP": "12"}
    text = text.replace("%~dp0", root + os.sep)
    return re.sub(r"%(\w+)%", lambda m: values.get(m.group(1).upper(), ""), text)


def _split_args(text: str) -> list[str]:
    """Разбор как в cmd.exe: пробелы разделяют, кавычки группируют и убираются."""
    args, cur, quoted, has = [], [], False, False
    for ch in text:
        if ch == '"':
            quoted = not quoted
            has = True
        elif ch.isspace() and not quoted:
            if cur or has:
                args.append("".join(cur))
            cur, has = [], False
        else:
            cur.append(ch)
    if cur or has:
        args.append("".join(cur))
    return [a for a in args if a not in ("^", "^^")]


def parse_strategy(bat_text: str, root: str) -> list[str] | None:
    """Достаёт параметры winws.exe из .bat-файла стратегии. None — если запуска winws там нет."""
    lines = bat_text.replace("\r\n", "\n").split("\n")
    for i, line in enumerate(lines):
        if "winws.exe" not in line.lower():
            continue
        parts = [line]
        j = i
        while parts[-1].rstrip().endswith("^") and j + 1 < len(lines):
            parts[-1] = parts[-1].rstrip()[:-1]
            j += 1
            parts.append(lines[j])
        cmd = " ".join(p.strip() for p in parts)
        pos = cmd.lower().find("winws.exe")
        rest = cmd[pos + len("winws.exe"):]
        if rest.startswith('"'):
            rest = rest[1:]
        return _split_args(_expand(rest, root))
    return None


def list_strategies(root: str) -> list[dict]:
    """[{name, args}] из всех .bat-файлов сборки (кроме service.bat)."""
    out = []
    try:
        names = sorted(os.listdir(root), key=lambda n: (n.lower() != "general.bat", n.lower()))
    except OSError:
        return []
    for name in names:
        if not name.lower().endswith(".bat") or name.lower().startswith("service"):
            continue
        try:
            with open(os.path.join(root, name), encoding="utf-8", errors="replace") as f:
                args = parse_strategy(f.read(), root)
        except OSError:
            continue
        if args:
            out.append({"name": name[:-4], "args": args})
    return out


def ensure_list_files(args: list[str]) -> None:
    """Сборка может ссылаться на пользовательские списки, которых ещё нет, — winws тогда не запустится."""
    for a in args:
        if "=" not in a:
            continue
        key, value = a.split("=", 1)
        if key in ("--hostlist", "--hostlist-exclude", "--ipset", "--ipset-exclude") and value and not os.path.exists(value):
            try:
                os.makedirs(os.path.dirname(value), exist_ok=True)
                open(value, "a", encoding="utf-8").close()
            except OSError:
                pass


def add_custom_domains(root: str, domains: list[str]) -> None:
    """Свои сайты пользователя дописываются в общий список zapret (после обновления — снова)."""
    path = os.path.join(root, "lists", "list-general.txt")
    if not domains or not os.path.isfile(path):
        return
    with open(path, encoding="utf-8", errors="replace") as f:
        have = {ln.strip().lower() for ln in f if ln.strip()}
    new = [d for d in domains if d.lower() not in have]
    if new:
        with open(path, "a", encoding="utf-8") as f:
            f.write("\n" + "\n".join(new) + "\n")


# ---------- скачивание с GitHub ----------

def latest_release(repo: str, proxy_port: int | None = None) -> dict:
    headers = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("GITHUB_TOKEN"):
        # только проверка в облаке GitHub: без ключа общий лимит запросов на адрес машины часто исчерпан
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    status, _, body = netutil.http_get(f"https://api.github.com/repos/{repo}/releases/latest", proxy_port=proxy_port,
                                       timeout=20, max_bytes=2 * 1024 * 1024, headers=headers)
    if status != 200:
        raise DpiError(f"GitHub не ответил ({status}) — попробуй позже или включи VPN")
    return json.loads(body.decode("utf-8", "replace"))


def _pick_asset(release: dict, patterns: list[str]) -> str:
    assets = release.get("assets") or []
    for pat in patterns:
        for a in assets:
            if re.search(pat, a.get("name", ""), re.I):
                return a.get("browser_download_url", "")
    return ""


def _extract(zip_path: str, dest: str, marker: str) -> str:
    """Распаковывает архив и возвращает папку, в которой лежит marker (например, bin/winws.exe)."""
    tmp = dest + ".unpack"
    shutil.rmtree(tmp, ignore_errors=True)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(tmp)
    for root, _, files in os.walk(tmp):
        rel = os.path.join(root, marker)
        if os.path.isfile(rel) or (os.sep not in marker and marker in files):
            return root
    shutil.rmtree(tmp, ignore_errors=True)
    raise DpiError("в архиве нет нужных файлов — возможно, изменился формат сборки")


def _swap_in(found: str, dest: str, version: str, keep: tuple[str, ...] = ()) -> None:
    saved = {}
    for rel in keep:
        p = os.path.join(dest, rel)
        if os.path.isfile(p):
            with open(p, "rb") as f:
                saved[rel] = f.read()
    old = dest + ".old"
    shutil.rmtree(old, ignore_errors=True)
    if os.path.isdir(dest):
        os.replace(dest, old)
    shutil.move(found, dest)
    shutil.rmtree(dest + ".unpack", ignore_errors=True)
    shutil.rmtree(old, ignore_errors=True)
    for rel, data in saved.items():
        with open(os.path.join(dest, rel), "wb") as f:
            f.write(data)
    with open(os.path.join(dest, "version.txt"), "w", encoding="utf-8") as f:
        f.write(version)


# Запасной источник сборки Flowseal: точное зеркало SourceForge (копирует выпуски с GitHub). Им пользуемся,
# только если GitHub не открывается ни напрямую, ни через VPN (так было в июле 2026, когда аккаунт Flowseal
# приостановили). Программы из зеркала (winws.exe, драйвер WinDivert) берём, только если они побайтно
# совпадают с теми, что уже были проверены по GitHub: winws.exe работает с правами администратора,
# и подменённый файл в «зеркале» был бы опасен. Списки сайтов и стратегии (текстовые файлы) — обновляются.
ZAPRET_MIRROR = "https://sourceforge.net/projects/flowseal.mirror/files/latest/download"
HASHES_FILE = "zapret_verified.json"  # хеши программ из последней сборки, проверенной по GitHub
_BINARY = re.compile(r"\.(exe|sys|dll)$", re.I)


def _sha256(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _asset_digest(release: dict, url: str) -> str:
    """Контрольная сумма файла, которую показывает сам GitHub (поле digest: «sha256:…»)."""
    for a in release.get("assets") or []:
        if a.get("browser_download_url") == url:
            d = str(a.get("digest") or "")
            return d.split(":", 1)[1].lower() if d.lower().startswith("sha256:") else ""
    return ""


def _binary_hashes(folder: str) -> dict[str, str]:
    out = {}
    for root, _, files in os.walk(folder):
        for name in files:
            if _BINARY.search(name):
                full = os.path.join(root, name)
                out[os.path.relpath(full, folder).replace(os.sep, "/").lower()] = _sha256(full)
    return out


def _load_verified(paths: DpiPaths) -> dict[str, str]:
    try:
        with open(os.path.join(paths.data_dir, HASHES_FILE), encoding="utf-8") as f:
            data = json.load(f)
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_verified(paths: DpiPaths, hashes: dict[str, str]) -> None:
    try:
        with open(os.path.join(paths.data_dir, HASHES_FILE), "w", encoding="utf-8") as f:
            json.dump(hashes, f, ensure_ascii=False, indent=1, sort_keys=True)
    except OSError:
        pass


def download_zapret(paths: DpiPaths, proxy_port: int | None = None, release: dict | None = None) -> str:
    try:
        release = release or latest_release(ZAPRET_REPO, proxy_port)
    except Exception as exc:
        try:
            return download_zapret_mirror(paths, proxy_port)
        except DpiError as mirror_exc:
            raise DpiError(f"{exc}; запасное зеркало: {mirror_exc}") from exc
        except Exception:
            raise exc
    tag = str(release.get("tag_name") or "").lstrip("vV")
    url = _pick_asset(release, [r"\.zip$"]) or release.get("zipball_url") or ""
    if not url:
        raise DpiError("в выпуске zapret нет архива")
    zip_path = os.path.join(paths.data_dir, "zapret_download.zip")
    netutil.download_file(url, zip_path, proxy_port=proxy_port, timeout=120)
    want = _asset_digest(release, url)
    if want and _sha256(zip_path) != want:
        os.remove(zip_path)
        raise DpiError("архив zapret не совпал с контрольной суммой на GitHub — не ставлю его")
    found = _extract(zip_path, paths.zapret_dir, os.path.join("bin", "winws.exe"))
    hashes = _binary_hashes(found)
    _swap_in(found, paths.zapret_dir, tag)
    os.remove(zip_path)
    _save_verified(paths, hashes)  # эти программы пришли с GitHub — по ним проверяем зеркало
    return tag


def download_zapret_mirror(paths: DpiPaths, proxy_port: int | None = None, url: str = ZAPRET_MIRROR) -> str:
    """Сборка Flowseal из запасного зеркала. Программы внутри должны совпасть с уже проверенными."""
    verified = _load_verified(paths)
    if not verified and os.path.isfile(os.path.join(paths.zapret_dir, "bin", "winws.exe")):
        # уже стоящая сборка когда-то скачана программой с GitHub — её программы и считаем проверенными
        verified = {k: v for k, v in _binary_hashes(paths.zapret_dir).items()}
        _save_verified(paths, verified)
    if not verified:
        raise DpiError("GitHub недоступен, а с зеркала программы с правами администратора без проверки не ставлю — "
                       "включи VPN и повтори")
    zip_path = os.path.join(paths.data_dir, "zapret_mirror.zip")
    netutil.download_file(url, zip_path, proxy_port=proxy_port, timeout=120)
    try:
        found = _extract(zip_path, paths.zapret_dir, os.path.join("bin", "winws.exe"))
    finally:
        try:
            os.remove(zip_path)
        except OSError:
            pass
    got = _binary_hashes(found)
    strange = sorted(k for k, v in got.items() if verified.get(k) != v)
    if strange:
        shutil.rmtree(found, ignore_errors=True)
        shutil.rmtree(paths.zapret_dir + ".unpack", ignore_errors=True)
        raise DpiError("в зеркале другие программы, чем на GitHub (" + ", ".join(strange[:3]) +
                       ") — не ставлю; обновлю, когда GitHub откроется")
    tag = ""
    for root, _, files in os.walk(found):  # версия сборки — в service.bat («set "LOCAL_VERSION=1.10.4"»)
        if "service.bat" in files:
            try:
                with open(os.path.join(root, "service.bat"), encoding="utf-8", errors="replace") as f:
                    m = re.search(r'LOCAL_VERSION=([0-9][0-9A-Za-z.\-]*)', f.read())
                tag = m.group(1) if m else ""
            except OSError:
                pass
            break
    _swap_in(found, paths.zapret_dir, tag or "mirror")
    return tag or "mirror"


def download_byedpi(paths: DpiPaths, proxy_port: int | None = None, release: dict | None = None) -> str:
    release = release or latest_release(BYEDPI_REPO, proxy_port)
    tag = str(release.get("tag_name") or "").lstrip("vV")
    url = _pick_asset(release, [r"x86_64.*w64.*\.zip$", r"w64.*\.zip$", r"win.*64.*\.zip$", r"win.*\.zip$"])
    if not url:
        raise DpiError("в выпуске ByeDPI нет сборки для Windows")
    zip_path = os.path.join(paths.data_dir, "byedpi_download.zip")
    netutil.download_file(url, zip_path, proxy_port=proxy_port, timeout=120)
    found = _extract(zip_path, paths.byedpi_dir, os.path.basename(paths.ciadpi))
    _swap_in(found, paths.byedpi_dir, tag)
    os.remove(zip_path)
    return tag


# ---------- проверка YouTube и Discord ----------

def _socks_connect(host: str, port: int, socks_port: int, timeout: float) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        s.close()
        raise OSError("прокси ByeDPI не ответил")
    hb = host.encode("idna")
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + port.to_bytes(2, "big"))
    head = s.recv(4)
    if len(head) < 4 or head[1] != 0:
        s.close()
        raise OSError("прокси ByeDPI не смог соединиться")
    atyp = head[3]
    rest = {1: 4, 4: 16}.get(atyp)
    if rest is None:
        rest = s.recv(1)[0]
    s.recv(rest + 2)
    return s


def https_probe(host: str, path: str, want: int, socks_port: int | None = None, timeout: float = 8.0,
                port: int = 443) -> dict:
    """Открывает https://host/path напрямую или через SOCKS5 и читает до want байт.
    Возвращает {"ok", "bytes", "ms", "kbps", "detail"}."""
    t0 = time.perf_counter()
    got = 0
    try:
        raw = _socks_connect(host, port, socks_port, timeout) if socks_port else \
            socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        ctx = netutil.ssl_context()
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            s.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {netutil.BROWSER_UA}\r\n"
                       "Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").encode())
            deadline = t0 + timeout
            head = b""
            while got < want and time.perf_counter() < deadline:
                chunk = s.recv(65536)
                if not chunk:
                    break
                if not head:
                    head = chunk[:16]
                got += len(chunk)
    except Exception as exc:  # noqa: BLE001 — любая сетевая ошибка значит «не открывается»
        return {"ok": False, "bytes": got, "ms": None, "kbps": 0, "detail": netutil.human_error(exc)}
    ms = round((time.perf_counter() - t0) * 1000)
    if not got:
        return {"ok": False, "bytes": 0, "ms": ms, "kbps": 0, "detail": "сервер ничего не прислал"}
    kbps = round(got / 1024 / max(0.001, ms / 1000))
    complete = got >= want or ms < timeout * 1000 - 200
    return {"ok": complete, "bytes": got, "ms": ms, "kbps": kbps,
            "detail": "" if complete else "очень медленно — похоже на замедление"}


def check_targets(socks_port: int | None = None, targets: tuple[str, ...] = ("youtube", "discord"),
                  timeout: float = 8.0, checks: dict | None = None) -> dict:
    """{"youtube": {"ok", "kbps", "detail"}, "discord": {...}} — открываются ли сервисы этим путём."""
    checks = checks or CHECKS
    out = {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        futs = {t: [pool.submit(https_probe, h, p, n, socks_port, timeout) for h, p, n in checks[t]] for t in targets}
        for t, fl in futs.items():
            res = [f.result() for f in fl]
            ok = all(r["ok"] for r in res)
            bad = next((r for r in res if not r["ok"]), None)
            out[t] = {"ok": ok, "kbps": max(r["kbps"] for r in res), "detail": "" if ok else bad["detail"]}
    return out


def score(result: dict) -> tuple:
    """Чем больше, тем лучше: сначала сколько сервисов работает, потом скорость YouTube."""
    yt, dc = result.get("youtube") or {}, result.get("discord") or {}
    return (int(bool(yt.get("ok"))) + int(bool(dc.get("ok"))), int(bool(yt.get("ok"))), yt.get("kbps") or 0)


# ---------- запуск ----------

def _popen_kwargs() -> dict:
    if IS_WINDOWS:
        return {"creationflags": 0x08000000}  # CREATE_NO_WINDOW
    return {}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ByeDpiRunner:
    """ByeDPI как локальный SOCKS5-прокси на 127.0.0.1."""

    def __init__(self, paths: DpiPaths):
        self.paths = paths
        self.proc: subprocess.Popen | None = None
        self.port = 0
        self.args: list[str] = []
        self.bind_ip = ""  # в режиме TUN без отбора по программам — адрес основного адаптера

    def start(self, args: str | list[str], port: int | None = None) -> int:
        self.stop()
        if not self.paths.byedpi_installed():
            raise DpiError("ByeDPI ещё не скачан")
        self.port = port or free_port()
        self.args = args.split() if isinstance(args, str) else list(args)
        cmd = [self.paths.ciadpi, "-i", "127.0.0.1", "-p", str(self.port)] + self.args
        if self.bind_ip:
            cmd += ["-I", self.bind_ip]
        self.proc = subprocess.Popen(cmd, cwd=self.paths.byedpi_dir, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, **_popen_kwargs())
        deadline = time.time() + 5
        while time.time() < deadline:
            if self.proc.poll() is not None:
                err = (self.proc.stderr.read() or b"").decode("utf-8", "replace").strip()[-200:]
                raise DpiError(f"ByeDPI не запустился: {err or f'код выхода {self.proc.returncode}'}")
            with socket.socket() as s:
                s.settimeout(0.3)
                if s.connect_ex(("127.0.0.1", self.port)) == 0:
                    return self.port
            time.sleep(0.1)
        raise DpiError("ByeDPI не начал принимать соединения")

    def alive(self) -> bool:
        return bool(self.proc and self.proc.poll() is None)

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None


class ZapretRunner:
    """Запуск winws.exe. В Windows — через помощника с правами администратора (один запрос на сеанс)."""

    NAME = "zapret"

    def __init__(self, paths: DpiPaths, helper):
        self.paths = paths
        self.helper = helper  # elevated.AdminHelper
        self.running_name = ""
        self._lock = threading.Lock()

    def start(self, strategy: dict) -> None:
        from .elevated import AdminError
        with self._lock:
            if not self.paths.zapret_installed():
                raise DpiError("zapret ещё не скачан")
            ensure_list_files(strategy["args"])
            try:
                r = self.helper.start(self.NAME, "winws", strategy["args"], os.path.dirname(self.paths.winws))
            except AdminError as exc:
                raise DpiAdminError(str(exc)) from exc
            if not r.get("ok"):
                raise DpiError(f"zapret не запустился: {r.get('error') or 'неизвестная ошибка'}")
            self.running_name = strategy["name"]

    def alive(self) -> bool:
        return bool(self.running_name) and bool(self.helper.status(self.NAME).get("running"))

    def stop(self) -> None:
        with self._lock:
            self.running_name = ""
            self.helper.stop(self.NAME)

    def shutdown(self) -> None:
        self.stop()
