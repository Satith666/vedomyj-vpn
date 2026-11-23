"""Режим TUN: весь трафик компьютера идёт через программу, а не только браузеры.

Три движка, все работают через помощника с правами администратора (pult/admin_helper.py):
- «Xray TUN» — встроен в ядро Xray: само ядро запускается с правами администратора и создаёт адаптер.
  Нужен wintun.dll рядом с xray.exe (скачивается с wintun.net, проверяется по SHA-256).
- «Sing-box» — отдельная программа создаёт адаптер и передаёт всё в Xray через локальный SOCKS.
  Трафик самого Xray и ByeDPI отпускается напрямую по имени процесса, чтобы не было петли.
- «tun2proxy» — небольшая программа, делает то же через SOCKS. Чтобы не было петли, исходящие соединения
  Xray привязываются к основному сетевому адаптеру.
«Авто» пробует движки по очереди и запоминает тот, что заработал.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import zipfile

from . import netutil

IS_WINDOWS = sys.platform == "win32"
EXE = ".exe" if IS_WINDOWS else ""

SINGBOX_REPO = "SagerNet/sing-box"
TUN2PROXY_REPO = "tun2proxy/tun2proxy"
WINTUN_URL = "https://www.wintun.net/builds/wintun-0.14.1.zip"
WINTUN_SHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
XRAY_TUN_MIN = (26, 3, 27)  # с этой версии в Xray есть автоматические маршруты для TUN

ENGINES = ("xray", "singbox", "tun2proxy")
ENGINE_NAMES = {"xray": "Xray TUN", "singbox": "Sing-box", "tun2proxy": "tun2proxy"}
ADAPTER = "VedomyjVPN"
V4_ADDR = "172.19.0.1/30"
V6_ADDR = "fdfe:dcba:9876::1/126"
DNS_REMOTE = ["1.1.1.1", "1.0.0.1"]
DNS_RU = "77.88.8.8"  # Яндекс DNS, базовый режим
# российские адреса — через российский DNS, чтобы сайты отдавали ближайшие к тебе серверы
RU_SUFFIXES = ["ru", "su", "xn--p1ai", "by", "kz", "yandex.net", "yastatic.net", "vk.com", "userapi.com",
               "mail.ru", "ok.ru", "avito.st", "wbstatic.net", "wbbasket.ru", "ozone.ru", "sberbank.ru"]


class TunError(RuntimeError):
    pass


class TunPaths:
    def __init__(self, bin_dir: str, data_dir: str, xray_exe: str, legacy_xray: str):
        self.bin_dir = bin_dir
        self.data_dir = data_dir
        self.singbox_dir = os.path.join(bin_dir, "sing-box")
        self.singbox = os.path.join(self.singbox_dir, "sing-box" + EXE)
        self.t2p_dir = os.path.join(bin_dir, "tun2proxy")
        self.tun2proxy = os.path.join(self.t2p_dir, "tun2proxy-bin" + EXE)
        self.xray = xray_exe
        self.legacy_xray = legacy_xray
        self.singbox_config = os.path.join(data_dir, "singbox.json")

    def wintun_ready(self, folder: str) -> bool:
        return not IS_WINDOWS or os.path.isfile(os.path.join(folder, "wintun.dll"))

    def installed(self, engine: str) -> bool:
        if engine == "xray":
            return os.path.isfile(self.xray) and self.wintun_ready(self.bin_dir)
        if engine == "singbox":
            return os.path.isfile(self.singbox)
        if engine == "tun2proxy":
            return os.path.isfile(self.tun2proxy) and self.wintun_ready(self.t2p_dir)
        return False

    def version(self, engine: str) -> str:
        folder = {"singbox": self.singbox_dir, "tun2proxy": self.t2p_dir}.get(engine)
        try:
            with open(os.path.join(folder, "version.txt"), encoding="utf-8") as f:
                return f.read().strip()
        except (OSError, TypeError):
            return ""


def version_tuple(text: str) -> tuple[int, ...]:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else ()


def xray_supports_tun(version: str) -> bool:
    v = version_tuple(version)
    return bool(v) and v >= XRAY_TUN_MIN


# ---------- скачивание ----------

def ensure_wintun(paths: TunPaths, folder: str, proxy_port: int | None = None) -> None:
    """wintun.dll нужен рядом с exe, который создаёт адаптер. Основная копия лежит в bin рядом с xray.exe.
    Скачивается с официального сайта WireGuard и сверяется по SHA-256 — подменённый файл не ставится."""
    if not IS_WINDOWS or os.path.isfile(os.path.join(folder, "wintun.dll")):
        return
    master = os.path.join(paths.bin_dir, "wintun.dll")
    if not os.path.isfile(master):
        zip_path = os.path.join(paths.data_dir, "wintun_download.zip")
        netutil.download_file(WINTUN_URL, zip_path, proxy_port=proxy_port, timeout=60)
        with open(zip_path, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        if digest != WINTUN_SHA256:
            os.remove(zip_path)
            raise TunError("файл wintun.dll не прошёл проверку — попробуй позже")
        with zipfile.ZipFile(zip_path) as zf:
            data = zf.read("wintun/bin/amd64/wintun.dll")
        os.remove(zip_path)
        with open(master, "wb") as f:
            f.write(data)
    if os.path.normcase(os.path.abspath(folder)) != os.path.normcase(os.path.abspath(paths.bin_dir)):
        os.makedirs(folder, exist_ok=True)
        shutil.copyfile(master, os.path.join(folder, "wintun.dll"))


def download_singbox(paths: TunPaths, proxy_port: int | None = None, release: dict | None = None) -> str:
    from .dpi import _extract, _pick_asset, _swap_in, latest_release
    release = release or latest_release(SINGBOX_REPO, proxy_port)
    tag = str(release.get("tag_name") or "").lstrip("vV")
    url = _pick_asset(release, [r"^sing-box-[\d.]+-windows-amd64\.zip$"])
    if not url:
        raise TunError("в выпуске sing-box нет сборки для Windows")
    zip_path = os.path.join(paths.data_dir, "singbox_download.zip")
    netutil.download_file(url, zip_path, proxy_port=proxy_port, timeout=180)
    found = _extract(zip_path, paths.singbox_dir, os.path.basename(paths.singbox))
    _swap_in(found, paths.singbox_dir, tag)
    os.remove(zip_path)
    return tag


def download_tun2proxy(paths: TunPaths, proxy_port: int | None = None, release: dict | None = None) -> str:
    from .dpi import _extract, _pick_asset, _swap_in, latest_release
    release = release or latest_release(TUN2PROXY_REPO, proxy_port)
    tag = str(release.get("tag_name") or "").lstrip("vV")
    url = _pick_asset(release, [r"x86_64-pc-windows-msvc\.zip$", r"x86_64.*windows.*\.zip$"])
    if not url:
        raise TunError("в выпуске tun2proxy нет сборки для Windows")
    zip_path = os.path.join(paths.data_dir, "tun2proxy_download.zip")
    netutil.download_file(url, zip_path, proxy_port=proxy_port, timeout=120)
    found = _extract(zip_path, paths.t2p_dir, os.path.basename(paths.tun2proxy))
    _swap_in(found, paths.t2p_dir, tag, keep=("wintun.dll",))
    os.remove(zip_path)
    return tag


# ---------- настройки движков ----------

def xray_tun_inbound(ipv6: bool, leak: bool) -> dict:
    """Вход TUN для ядра Xray: адаптер, маршруты и защита от утечек средствами Windows (WFP)."""
    settings = {
        "name": ADAPTER, "desc": "VEDOMYJ VPN", "mtu": 1500,
        "gateway": [V4_ADDR] + ([V6_ADDR] if ipv6 else []),
        "dns": DNS_REMOTE,
        "autoSystemRoutingTable": ["0.0.0.0/0"] + (["::/0"] if ipv6 else []),
        "autoOutboundsInterface": "auto",
    }
    if leak:
        settings["autoSystemWfpBlockLeak"] = ["dns", "misconfigtun"]
    return {"tag": "tun-in", "protocol": "tun", "settings": settings,
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}}


def xray_dns(encrypted: bool, ipv6: bool, use_geo: bool) -> dict:
    """Встроенный DNS ядра: российские адреса — через Яндекс напрямую, остальное — через VPN.
    encrypted=True — запросы шифруются (DNS через HTTPS)."""
    ru_domains = [f"domain:{s}" for s in RU_SUFFIXES]
    if use_geo:
        ru_domains.append("geosite:ru-available-only-inside")
    ru = {"address": f"https://{DNS_RU}/dns-query" if encrypted else DNS_RU, "domains": ru_domains,
          "skipFallback": True}
    remote = [f"https://{ip}/dns-query" if encrypted else ip for ip in DNS_REMOTE]
    return {"tag": "dns-internal", "queryStrategy": "UseIP" if ipv6 else "UseIPv4", "servers": [ru] + remote}


def singbox_config(socks_port: int, leak: bool, encrypted: bool, ipv6: bool, direct_apps: tuple = (),
                   block_apps: tuple = ()) -> dict:
    """sing-box: адаптер TUN → всё в Xray через SOCKS. Формат — для sing-box 1.12 и новее.
    direct_apps / block_apps — имена процессов (без .exe): эти приложения мимо VPN или без сети."""
    tun = {"type": "tun", "tag": "tun-in", "interface_name": ADAPTER,
           "address": [V4_ADDR] + ([V6_ADDR] if ipv6 else []),
           "mtu": 9000, "auto_route": True, "strict_route": bool(leak)}
    dns_type = "https" if encrypted else "tcp"
    return {
        "log": {"level": "warn", "timestamp": False},
        "dns": {
            "servers": [
                {"type": dns_type, "tag": "remote", "server": DNS_REMOTE[0], "detour": "xray"},
                {"type": "https" if encrypted else "udp", "tag": "local", "server": DNS_RU},
            ],
            "rules": [{"domain_suffix": RU_SUFFIXES, "action": "route", "server": "local"}],
            "final": "remote",
            "strategy": "prefer_ipv4" if ipv6 else "ipv4_only",
        },
        "inbounds": [tun],
        "outbounds": [
            {"type": "socks", "tag": "xray", "server": "127.0.0.1", "server_port": int(socks_port), "version": "5"},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                # собственный трафик Xray и ByeDPI — напрямую, иначе получится петля
                {"process_name": ["xray.exe", "ciadpi.exe"], "action": "route", "outbound": "direct"},
                {"ip_is_private": True, "action": "route", "outbound": "direct"},
            ] + ([{"process_name": [f"{n}.exe" for n in block_apps], "action": "reject"}] if block_apps else [])
              + ([{"process_name": [f"{n}.exe" for n in direct_apps], "action": "route", "outbound": "direct"}]
                 if direct_apps else []),
            "final": "xray",
            "auto_detect_interface": True,
            "default_domain_resolver": "local",
        },
    }


def tun2proxy_args(socks_port: int, ipv6: bool) -> list[str]:
    args = ["--proxy", f"socks5://127.0.0.1:{int(socks_port)}", "--setup", "--dns", "virtual", "--tun", ADAPTER,
            "--exit-on-fatal-error"]
    if ipv6:
        args.append("--ipv6-enabled")
    return args


def default_interface() -> str:
    """Имя основного сетевого адаптера (по маршруту по умолчанию) — к нему привязываются соединения Xray."""
    if not IS_WINDOWS:
        return ""
    cmd = ("(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
           f"Where-Object {{ $_.InterfaceAlias -ne '{ADAPTER}' }} | "
           "Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1).InterfaceAlias")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd], capture_output=True,
                             text=True, timeout=15, creationflags=0x08000000).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.strip().splitlines()[0].strip() if out.strip() else ""


def ipv6_available() -> bool:
    """Есть ли у компьютера IPv6 — без него адаптер TUN с IPv6-адресом не запустится."""
    import socket
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.connect(("2606:4700:4700::1111", 53))
            addr = s.getsockname()[0]
        return not addr.startswith("fe80") and addr != "::1"
    except OSError:
        return False


def remove_engine(paths: TunPaths, engine: str) -> None:
    folder = {"singbox": paths.singbox_dir, "tun2proxy": paths.t2p_dir}.get(engine)
    if folder:
        shutil.rmtree(folder, ignore_errors=True)


# ---------- процессы ----------

class ElevatedXray:
    """Ядро Xray, запущенное помощником с правами администратора (для «Xray TUN»).
    Повторяет то, чем движок пользуется у обычного процесса: start / alive / stop / lines."""

    NAME = "xray"

    def __init__(self, helper, paths, kind_for_exe):
        self.helper = helper
        self.paths = paths  # xray.Paths
        self.kind_for_exe = kind_for_exe  # exe → вид для помощника ("xray" или "xray_legacy")
        self.lines: list[str] = []
        self.exe = ""
        self.running = False

    def alive(self) -> bool:
        return self.running and bool(self.helper.status(self.NAME).get("running"))

    def start(self, config: dict, config_path: str, wait_for: list[int], timeout: float = 15.0,
              exe: str | None = None) -> None:
        import json
        from .xray import XrayError, short_error
        self.stop()
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False, indent=1)
        self.exe = exe or self.paths.xray
        r = self.helper.start(self.NAME, self.kind_for_exe(self.exe), ["run", "-c", config_path])
        if not r.get("ok"):
            raise XrayError(short_error(r.get("error") or "") or "Xray не запустился")
        self.running = True
        from .xray import wipe
        if not netutil.wait_ports(wait_for, timeout=timeout, alive=self.alive):
            log = self.helper.status(self.NAME).get("log") or ""
            self.stop()
            wipe(config_path)
            raise XrayError(short_error(log) or "Xray не запустился")
        wipe(config_path)
        self.lines = []

    def stop(self) -> None:
        if self.running:
            self.helper.stop(self.NAME)
        self.running = False

    def death_note(self, wait: float = 0.0) -> str:
        """Почему ядро (запущенное помощником) остановилось: что помощник успел увидеть в его выводе."""
        st = self.helper.status(self.NAME)
        log = [ln for ln in str(st.get("log") or st.get("error") or "").splitlines() if ln.strip()]
        panic = next((i for i, ln in enumerate(log) if ln.startswith(("panic:", "fatal error:"))), None)
        pick = log[panic:panic + 6] if panic is not None else log[-4:]
        return "\n".join(["ядро в режиме TUN (через помощника)"] + pick)


class TunProcess:
    """sing-box или tun2proxy, запущенные помощником."""

    NAME = "tun"

    def __init__(self, helper, paths: TunPaths):
        self.helper = helper
        self.paths = paths
        self.engine = ""

    def start(self, engine: str, socks_port: int, leak: bool, encrypted: bool, ipv6: bool, direct_apps: tuple = (),
              block_apps: tuple = ()) -> None:
        import json
        self.stop()
        if engine == "singbox":
            with open(self.paths.singbox_config, "w", encoding="utf-8") as f:
                json.dump(singbox_config(socks_port, leak, encrypted, ipv6, direct_apps, block_apps), f,
                          ensure_ascii=False, indent=1)
            r = self.helper.start(self.NAME, "singbox", ["run", "-c", self.paths.singbox_config])
        elif engine == "tun2proxy":
            r = self.helper.start(self.NAME, "tun2proxy", tun2proxy_args(socks_port, ipv6))
        else:
            raise TunError("неизвестный движок TUN")
        if not r.get("ok"):
            raise TunError(_short(r.get("error") or "") or "движок TUN не запустился")
        self.engine = engine

    def alive(self) -> bool:
        return bool(self.engine) and bool(self.helper.status(self.NAME).get("running"))

    def error(self) -> str:
        return _short(self.helper.status(self.NAME).get("error") or "")

    def death_note(self) -> str:
        """Подробнее, чем error(): последние строки вывода sing-box или tun2proxy (для «проблемы» и отчёта)."""
        st = self.helper.status(self.NAME)
        log = [ln.strip() for ln in str(st.get("log") or st.get("error") or "").splitlines() if ln.strip()]
        return "\n".join(log[-5:]) or "без подробностей"

    def stop(self) -> None:
        if self.engine:
            self.helper.stop(self.NAME)
        self.engine = ""


def _short(text: str) -> str:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    return lines[-1][:300] if lines else ""
