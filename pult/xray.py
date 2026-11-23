"""Работа с ядром Xray: файлы, загрузка, конфиги, запуск, статистика."""

from __future__ import annotations

import collections
import copy
import json
import os
import platform
import re
import secrets
import subprocess
import sys
import threading
import time
import zipfile

from . import dialect, links, netutil, routing
from .links import Server

IS_WINDOWS = sys.platform == "win32"
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW

GEO_BASE = "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/"
GEO_FILES = {"geosite.dat": GEO_BASE + "geosite.dat", "geoip.dat": GEO_BASE + "geoip.dat"}
# запасные адреса тех же файлов (ветка release): GitHub в России иногда открывается не целиком
GEO_MIRRORS = ["https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/",
               "https://cdn.jsdelivr.net/gh/runetfreedom/russia-v2ray-rules-dat@release/"]
GEO_MARK = "geo_source.txt"
# Ядра новее ~26.7 запрещают VLESS/Trojan без TLS к публичным адресам. Для таких серверов (их ещё понимает Happ)
# держим рядом проверенную старую версию.
LEGACY_VERSION = "26.6.27"


class XrayError(RuntimeError):
    pass


class Paths:
    def __init__(self, app_dir: str):
        self.app_dir = app_dir
        self.bin_dir = os.path.join(app_dir, "bin")
        self.data_dir = os.path.join(app_dir, "data")
        os.makedirs(self.bin_dir, exist_ok=True)
        os.makedirs(self.data_dir, exist_ok=True)
        self.xray = os.path.join(self.bin_dir, "xray.exe" if IS_WINDOWS else "xray")
        self.legacy_dir = os.path.join(self.bin_dir, "legacy")
        self.legacy_xray = os.path.join(self.legacy_dir, os.path.basename(self.xray))
        self.run_config = os.path.join(self.data_dir, "config.json")
        self.test_config = os.path.join(self.data_dir, "test_config.json")
        self.access_log = os.path.join(self.data_dir, "access.log")
        self.pid_file = os.path.join(self.data_dir, "xray.pid")

    def xray_exists(self) -> bool:
        return os.path.isfile(self.xray)

    def legacy_exists(self) -> bool:
        return os.path.isfile(self.legacy_xray)

    def exe_for(self, server) -> str:
        return self.legacy_xray if getattr(server, "insecure", False) else self.xray

    def geo_ready(self) -> bool:
        return all(os.path.isfile(os.path.join(self.bin_dir, f)) for f in GEO_FILES) and \
            os.path.isfile(os.path.join(self.bin_dir, GEO_MARK))

    def geo_age_days(self) -> float | None:
        mark = os.path.join(self.bin_dir, GEO_MARK)
        if not os.path.isfile(mark):
            return None
        return (time.time() - os.path.getmtime(mark)) / 86400


# ---------- версии и загрузка ----------

def _popen_kwargs(cwd: str) -> dict:
    env = dict(os.environ)
    env["XRAY_LOCATION_ASSET"] = cwd
    kw = {"cwd": cwd, "env": env, "creationflags": NO_WINDOW}
    return kw


def xray_version(paths: Paths, exe: str | None = None) -> str | None:
    exe = exe or paths.xray
    if not os.path.isfile(exe):
        return None
    try:
        out = subprocess.run([exe, "version"], capture_output=True, text=True, timeout=8,
                             **_popen_kwargs(paths.bin_dir)).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"Xray\s+(\S+)", out or "")
    return m.group(1) if m else None


def xray_zip_name() -> str:
    machine = platform.machine().lower()
    if IS_WINDOWS:
        if machine in ("arm64", "aarch64"):
            return "Xray-windows-arm64-v8a.zip"
        return "Xray-windows-64.zip" if machine in ("amd64", "x86_64", "") else "Xray-windows-32.zip"
    if sys.platform == "darwin":
        return "Xray-macos-arm64-v8a.zip" if machine in ("arm64", "aarch64") else "Xray-macos-64.zip"
    return "Xray-linux-arm64-v8a.zip" if machine in ("arm64", "aarch64") else "Xray-linux-64.zip"


def download_xray(paths: Paths, proxy_port: int | None = None, progress=None, install: bool = True) -> str:
    """Скачивает последнюю версию ядра. install=False — оставить файл рядом (.new), чтобы поставить позже,
    когда ядро будет остановлено (работающий .exe в Windows заменить нельзя)."""
    url = "https://github.com/XTLS/Xray-core/releases/latest/download/" + xray_zip_name()
    zip_path = os.path.join(paths.data_dir, "xray_download.zip")
    netutil.download_file(url, zip_path, proxy_port=proxy_port, timeout=90, progress=progress)
    exe_name = os.path.basename(paths.xray)
    new_path = paths.xray + ".new"
    try:
        with zipfile.ZipFile(zip_path) as zf:
            member = next((n for n in zf.namelist() if os.path.basename(n).lower() == exe_name), None)
            if not member:
                raise XrayError("в архиве нет файла " + exe_name)
            with zf.open(member) as src, open(new_path, "wb") as dst:
                dst.write(src.read())
            # стандартные гео-файлы ставим, только если списков ещё нет совсем
            for geo in GEO_FILES:
                target = os.path.join(paths.bin_dir, geo)
                if not os.path.isfile(target) and geo in zf.namelist():
                    with zf.open(geo) as src, open(target, "wb") as dst:
                        dst.write(src.read())
    except zipfile.BadZipFile as exc:
        raise XrayError("скачанный архив повреждён") from exc
    finally:
        try:
            os.remove(zip_path)
        except OSError:
            pass
    if install:
        install_pending_xray(paths)
    return xray_version(paths) or "?"


def download_legacy_xray(paths: Paths, proxy_port: int | None = None) -> str:
    """Совместимая версия ядра для серверов без шифрования."""
    url = f"https://github.com/XTLS/Xray-core/releases/download/v{LEGACY_VERSION}/" + xray_zip_name()
    os.makedirs(paths.legacy_dir, exist_ok=True)
    zip_path = os.path.join(paths.data_dir, "xray_legacy.zip")
    netutil.download_file(url, zip_path, proxy_port=proxy_port, timeout=90)
    exe_name = os.path.basename(paths.xray)
    try:
        with zipfile.ZipFile(zip_path) as zf:
            member = next((n for n in zf.namelist() if os.path.basename(n).lower() == exe_name), None)
            if not member:
                raise XrayError("в архиве нет файла " + exe_name)
            with zf.open(member) as src, open(paths.legacy_xray + ".new", "wb") as dst:
                dst.write(src.read())
    except zipfile.BadZipFile as exc:
        raise XrayError("скачанный архив повреждён") from exc
    finally:
        try:
            os.remove(zip_path)
        except OSError:
            pass
    os.replace(paths.legacy_xray + ".new", paths.legacy_xray)
    if not IS_WINDOWS:
        os.chmod(paths.legacy_xray, 0o755)
    return xray_version(paths, paths.legacy_xray) or LEGACY_VERSION


XRAY_API_LATEST = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
XRAY_PAGE_LATEST = "https://github.com/XTLS/Xray-core/releases/latest"


def latest_xray_version(proxy_port: int | None = None) -> str | None:
    """Номер последней версии ядра на GitHub — маленький запрос, без скачивания архива."""
    try:
        status, _, body = netutil.http_get(XRAY_API_LATEST,
                                           proxy_port=proxy_port, timeout=20, max_bytes=512 * 1024, doh=True,
                                           headers={"Accept": "application/vnd.github+json"})
    except OSError:
        status, body = 0, b""
    tag = ""
    if status == 200:
        try:
            tag = json.loads(body.decode("utf-8", "replace")).get("tag_name") or ""
        except ValueError:
            tag = ""
    if not tag:
        # API GitHub ограничивает число запросов с одного адреса (у VPN-серверов он общий) —
        # тогда номер версии берём из адреса, куда ведёт страница последнего выпуска
        final = netutil.final_url(XRAY_PAGE_LATEST, proxy_port, timeout=20)
        m = re.search(r"/releases/tag/v?([0-9][0-9A-Za-z.\-]*)$", final or "")
        tag = m.group(1) if m else ""
    return tag.lstrip("vV") or None


def install_pending_xray(paths: Paths) -> bool:
    new_path = paths.xray + ".new"
    if not os.path.isfile(new_path):
        return False
    try:
        os.replace(new_path, paths.xray)
    except PermissionError as exc:
        raise XrayError("файл ядра занят — отключись и повтори") from exc
    if not IS_WINDOWS:
        os.chmod(paths.xray, 0o755)
    return True


def download_geo(paths: Paths, proxy_port: int | None = None, progress=None) -> None:
    """Оба файла сначала скачиваются рядом (своё временное имя на каждый вызов — два обновления подряд не мешают
    друг другу), потом заменяются вместе: ядро не получит новый geosite со старым geoip. Каждый файл — с основного
    адреса или с запасных."""
    done = []
    suffix = f".{secrets.token_hex(4)}.tmp"
    try:
        for name, url in GEO_FILES.items():
            dest = os.path.join(paths.bin_dir, name)
            last: Exception | None = None
            for u in [url] + [m + name for m in GEO_MIRRORS]:
                try:
                    size = netutil.download_file(u, dest + suffix, proxy_port=proxy_port, timeout=120, progress=progress)
                    if size < 10_000:
                        raise XrayError(f"{name}: файл слишком маленький, похоже, скачалось не то")
                    last = None
                    break
                except (OSError, XrayError, ValueError) as exc:
                    last = exc
            if last is not None:
                raise last
            done.append(name)
    except BaseException:
        for name in GEO_FILES:
            try:
                os.remove(os.path.join(paths.bin_dir, name) + suffix)
            except OSError:
                pass
        raise
    for name in done:
        dest = os.path.join(paths.bin_dir, name)
        os.replace(dest + suffix, dest)
    with open(os.path.join(paths.bin_dir, GEO_MARK), "w", encoding="utf-8") as f:
        f.write("runetfreedom/russia-v2ray-rules-dat\n" + time.strftime("%Y-%m-%d %H:%M") + "\n")


# ---------- конфиги ----------

def pin_address(ob: dict, domain: str, ip: str) -> None:
    """DNS провайдера не знает адрес сервера (его так заблокировали) — подключаемся по адресу из защищённого DNS.
    Имя сервера остаётся там, где оно важно: в TLS (SNI) и в заголовке Host для CDN."""
    st = ob.get("settings") or {}
    for item in (st.get("vnext") or []) + (st.get("servers") or []):
        if item.get("address") == domain:
            item["address"] = ip
    if st.get("address") == domain:  # формат нового ядра (address прямо в settings)
        st["address"] = ip
    ss = ob.get("streamSettings")
    if not isinstance(ss, dict):
        return
    tls = ss.get("tlsSettings")
    if ss.get("security") == "tls" and isinstance(tls, dict) and not tls.get("serverName"):
        tls["serverName"] = domain
    for key in ("wsSettings", "httpupgradeSettings", "xhttpSettings"):
        if isinstance(ss.get(key), dict) and not ss[key].get("host"):
            ss[key]["host"] = domain
    if isinstance(ss.get("grpcSettings"), dict) and not ss["grpcSettings"].get("authority") and ss.get("security") == "tls":
        ss["grpcSettings"]["authority"] = domain
    if isinstance(ss.get("httpSettings"), dict) and not ss["httpSettings"].get("host"):
        ss["httpSettings"]["host"] = [domain]


FINGERPRINTS = ("chrome", "firefox", "safari", "edge", "ios", "android", "randomized")


def fingerprint_of(ob: dict) -> str | None:
    """Отпечаток TLS outbound'а: строка (может быть пустой) или None — у этого сервера нет TLS/Reality
    (или это QUIC — Hysteria2: отпечаток браузера там не меняется)."""
    ss = ob.get("streamSettings") or {}
    if ss.get("network") in ("hysteria", "quic", "kcp", "mkcp"):
        return None
    for key in ("realitySettings", "tlsSettings"):
        if isinstance(ss.get(key), dict):
            return str(ss[key].get("fingerprint") or "")
    return None


def set_fingerprint(ob: dict, fp: str) -> bool:
    """Подменить отпечаток TLS (каким браузером «притворяется» подключение). False — у сервера нет TLS/Reality."""
    ss = ob.get("streamSettings") or {}
    done = False
    for key in ("realitySettings", "tlsSettings"):
        if isinstance(ss.get(key), dict):
            ss[key]["fingerprint"] = fp
            done = True
    return done


CERT_PINS: dict = {}  # ключ сервера → SHA-256 его сертификата (для серверов «не проверять сертификат»; заполняет движок)


def tagged_outbounds(server: Server, tag: str) -> list[dict]:
    """Outbound сервера с нужным тегом плюс вспомогательные (фрагментация и т.п.) с переименованными тегами.
    Отпечаток TLS, который подобрала программа (result["fp"]), заменяет отпечаток из ссылки."""
    if getattr(server, "engine", "xray") == "singbox":
        # TUIC, AnyTLS: ядро Xray отдаёт трафик мосту sing-box на этом компьютере, мост — серверу
        return [{"tag": tag, "protocol": "socks",
                 "settings": {"servers": [{"address": "127.0.0.1", "port": int(server.sidecar_port or 0)}]}}]
    if getattr(server, "engine", "xray") == "awg":
        raise XrayError("AmneziaWG запускается своим клиентом, а не ядром Xray")
    main = copy.deepcopy(server.outbound)
    main["tag"] = tag
    if getattr(server, "tls_unverified", False):
        pin = CERT_PINS.get(server.key)
        tls = (main.get("streamSettings") or {}).get("tlsSettings")
        if pin and isinstance(tls, dict):
            tls["pinnedPeerCertSha256"] = pin  # вместо allowInsecure: закреплённый сертификат этого сервера
    if getattr(server, "pinned_ip", ""):
        pin_address(main, server.address, server.pinned_ip)
    fp = (getattr(server, "result", None) or {}).get("fp")
    if fp in FINGERPRINTS:
        set_fingerprint(main, fp)
    mapping, extras = {}, []
    for ex in server.extra_outbounds:
        ex = copy.deepcopy(ex)
        old = ex.get("tag", "")
        new = f"{old}@{tag}"  # имя основного — в конце: префикс балансировщика (proxy, bk) их не захватит
        mapping[old] = new
        ex["tag"] = new
        extras.append(ex)
    for ob in [main] + extras:
        so = (ob.get("streamSettings") or {}).get("sockopt") or {}
        if so.get("dialerProxy") in mapping:
            so["dialerProxy"] = mapping[so["dialerProxy"]]
        ps = ob.get("proxySettings") or {}
        if ps.get("tag") in mapping:
            ps["tag"] = mapping[ps["tag"]]
    return [main] + extras


FINALMASK_MIN = (26, 10, 31)  # с этой версии дробление TLS настраивается в finalmask, а не во freedom
FM_MIN = (26, 3, 27)          # Finalmask целиком (fm в ссылках, шум UDP, перебор портов Hysteria2)
# шум перед пакетами QUIC (Hysteria2): «маскировка» для UDP-серверов, как дробление TLS — для TCP
NOISE_VARIANTS = {
    1: [{"rand": "64-128", "delay": "5-10"}],
    2: [{"rand": "512-1024", "delay": "10-20"}, {"rand": "64-128", "delay": "10-20"}],
}


def _ver(text: str) -> tuple[int, ...]:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else ()


# варианты маскировки: 1 — режем приветствие TLS на куски по 100–200 байт; 2 — первые пакеты на мелкие кусочки
MASK_VARIANTS = {
    1: {"packets": "tlshello", "lengths": ["100-200"], "delays": ["10-20"], "length": "100-200", "interval": "10-20"},
    2: {"packets": "1-3", "lengths": ["1-5"], "delays": ["5-10"], "length": "1-5", "interval": "5-10"},
}


def mask_outbounds(obs: list[dict], version: str, variant: int = 1) -> list[dict]:
    """Маскировка: первый пакет TLS к серверу режется на кусочки с паузами — оборудование провайдера (ТСПУ)
    не узнаёт сервер по нему и не блокирует. Свои настройки сервера (цепочки, finalmask) не трогаем.
    variant — какой способ дробления (MASK_VARIANTS): если первый не помог, программа пробует второй."""
    v = MASK_VARIANTS.get(int(variant) if variant else 1, MASK_VARIANTS[1])
    main = obs[0]
    ss = main.setdefault("streamSettings", {})
    if ss.get("network") == "hysteria" and _ver(version) >= FM_MIN:
        # Hysteria2 (QUIC): шум UDP перед пакетами; своя маскировка сервера (Salamander) остаётся внутри
        fm = ss.setdefault("finalmask", {})
        noise = NOISE_VARIANTS.get(int(variant) if variant else 1, NOISE_VARIANTS[1])
        fm["udp"] = [x for x in fm.get("udp") or [] if x.get("type") != "noise"] + \
            [{"type": "noise", "settings": {"noise": [dict(n) for n in noise]}}]
        return obs
    if ss.get("network") in ("kcp", "mkcp", "quic", "hysteria") or (ss.get("sockopt") or {}).get("dialerProxy") \
            or ss.get("finalmask") or main.get("proxySettings"):
        return obs
    if _ver(version) >= FINALMASK_MIN:
        ss["finalmask"] = {"tcp": [{"type": "fragment", "settings": {
            "packets": v["packets"], "lengths": v["lengths"], "delays": v["delays"]}}]}
        return obs
    tag = f"mask@{main['tag']}"
    ss.setdefault("sockopt", {})["dialerProxy"] = tag
    return obs + [{"tag": tag, "protocol": "freedom",
                   "settings": {"fragment": {"packets": v["packets"], "length": v["length"], "interval": v["interval"]}},
                   "streamSettings": {"sockopt": {"TcpNoDelay": True}}}]


def fm_for_core(obs: list[dict], version: str) -> list[dict]:
    """Старое ядро (до 26.3.27) не знает Finalmask целиком: оставляем только Salamander (он есть с 26.2),
    без шума, перебора портов и своей маскировки из ссылки — сервер работает на основном порту.
    DNS-туннель (xdns) у ядра до 26.10.21 не заработает вовсе (другие настройки) — вместо него «заглушка»,
    чтобы из-за одного сервера не отказался запускаться весь конфиг."""
    if version and _ver(version) < links.XDNS_MIN:
        obs = [{"tag": ob.get("tag", ""), "protocol": "blackhole"}
               if links.xdns_domain_of(ob.get("streamSettings") or {}) else ob for ob in obs]
    if version and _ver(version) < dialect.PROTO_MIN:  # свой протокол — тоже только новое ядро
        obs = [{"tag": ob.get("tag", ""), "protocol": "blackhole"}
               if dialect.is_vproto_ss(ob.get("streamSettings") or {}) else ob for ob in obs]
    if not version or _ver(version) >= FM_MIN:
        return obs
    for ob in obs:
        ss = ob.get("streamSettings") or {}
        fm = ss.get("finalmask")
        if not fm:
            continue
        udp = [x for x in fm.get("udp") or [] if x.get("type") == "salamander"]
        if udp:
            ss["finalmask"] = {"udp": udp}
        else:
            ss.pop("finalmask", None)
    return obs


def needs_new_core(server: Server, version: str) -> bool:
    """Ссылка просит то, чего старое ядро не умеет (fm, перебор портов, DNS-туннель): подсказать обновить ядро."""
    if version and links.is_xdns(server) and _ver(version) < links.XDNS_MIN:
        return True
    if version and dialect.is_vproto(server) and _ver(version) < dialect.PROTO_MIN:
        return True
    if not version or _ver(version) >= FM_MIN:
        return False
    fm = (server.outbound.get("streamSettings") or {}).get("finalmask") or {}
    return bool(fm.get("tcp") or fm.get("quicParams") or any(x.get("type") != "salamander" for x in fm.get("udp") or []))


def proxy_outbounds(server: Server, tag: str, mask: bool | int = False, version: str = "", bind: str = "") -> list[dict]:
    """mask: False — без маскировки, True или 1 — первый вариант, 2 — второй."""
    obs = fm_for_core(tagged_outbounds(server, tag), version)
    if mask:
        obs = mask_outbounds(obs, version, 1 if mask is True else int(mask))
    return [bind_outbound(o, bind) for o in obs]


def custom_proxy_outbound(p: dict, tag: str, bind: str = "") -> dict:
    """Свой прокси (SOCKS5 или HTTP) как outbound. p["chain"] — подключаться к прокси через основной VPN:
    провайдер видит только VPN, а сайт — адрес прокси."""
    server: dict = {"address": p["host"], "port": int(p["port"])}
    if p.get("user"):
        server["users"] = [{"user": p["user"], "pass": p.get("pass", "")}]
    ob: dict = {"tag": tag, "protocol": "http" if p.get("type") == "http" else "socks", "settings": {"servers": [server]}}
    if p.get("type") == "http" and p.get("tls"):
        ob["streamSettings"] = {"security": "tls", "tlsSettings": {"serverName": p["host"]}}
    if p.get("chain", True):
        ob.setdefault("streamSettings", {})["sockopt"] = {"dialerProxy": "proxy"}
        return ob
    return bind_outbound(ob, bind)


def route_outbounds(routes: list[dict] | None, version: str = "", bind: str = "") -> list[dict]:
    """Outbound'ы для своих маршрутов: выбранные серверы и свои прокси (каждый тег — один раз)."""
    out, seen = [], set()
    for r in routes or []:
        tag = r.get("tag", "")
        if tag in seen:
            continue
        if r.get("server") is not None:
            out += proxy_outbounds(r["server"], tag, r.get("mask", False), version, bind)
        elif r.get("warp"):
            out.append(dict(copy.deepcopy(r["warp"]), tag=tag))  # WARP после VPN: соединение к Cloudflare — через proxy
        elif r.get("proxy"):
            out.append(custom_proxy_outbound(r["proxy"], tag, bind))
        else:
            continue
        seen.add(tag)
    return out


def build_proxy_test_config(p: dict, port: int, main: Server | None, mask: bool = False, version: str = "") -> dict:
    """Проверка своего прокси: вход HTTP → прокси (если p["chain"] — через основной сервер)."""
    chain = bool(p.get("chain", True) and main is not None)
    outbounds = [custom_proxy_outbound(dict(p, chain=chain), "test")]
    if chain:
        outbounds += proxy_outbounds(main, "proxy", mask, version)
    outbounds.append({"tag": "direct", "protocol": "freedom"})
    return {"log": {"loglevel": "error"},
            "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": port, "protocol": "http", "settings": {}}],
            "outbounds": outbounds,
            "routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "inboundTag": ["in"], "outboundTag": "test"}]}}


def build_test_config(servers: list[Server], ports: list[int], mask: bool | int | None = False, version: str = "") -> dict:
    """mask: True/1/2 — все с маскировкой (вариант), None — как запомнено у сервера, False — без неё."""
    inbounds, outbounds, rules = [], [], []
    for i, (srv, port) in enumerate(zip(servers, ports)):
        inbounds.append({"tag": f"in{i}", "listen": "127.0.0.1", "port": port, "protocol": "http", "settings": {}})
        use = mask if mask is not None else ((srv.result or {}).get("mask") or False)
        outbounds.extend(proxy_outbounds(srv, f"out{i}", use, version))
        rules.append({"type": "field", "inboundTag": [f"in{i}"], "outboundTag": f"out{i}"})
    outbounds.append({"tag": "direct", "protocol": "freedom"})
    return {"log": {"loglevel": "error"}, "inbounds": inbounds, "outbounds": outbounds,
            "routing": {"domainStrategy": "AsIs", "rules": rules}}


def bind_outbound(ob: dict, interface: str) -> dict:
    """Привязать исходящие соединения к сетевому адаптеру (нужно для tun2proxy, чтобы не было петли)."""
    if interface:
        ob.setdefault("streamSettings", {}).setdefault("sockopt", {})["interface"] = interface
    return ob


def build_run_config(server: Server, settings: dict, ports: dict, access_log: str, use_geo: bool,
                     geo_ru_ip: bool = True, dpi: dict | None = None, tun: dict | None = None,
                     mask: bool = False, core_version: str = "", multi: list[dict] | None = None,
                     routes: list[dict] | None = None, ads: str | None = None,
                     failover: list[dict] | None = None) -> dict:
    """tun: {"engine": "xray"|"singbox"|"tun2proxy", "ipv6": bool, "leak": bool, "bind": имя адаптера}.
    routes: свои маршруты сервисов и сайтов — [{"tag", "domains", "ips", "server"?, "mask"?, "proxy"?}]."""
    from . import tun as tunmod
    sniff = {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}
    listen = "127.0.0.1"
    inbounds = [
        {"tag": "socks-in", "listen": listen, "port": ports["socks"], "protocol": "socks",
         "settings": {"udp": True}, "sniffing": sniff},
        {"tag": "http-in", "listen": listen, "port": ports["http"], "protocol": "http", "settings": {},
         "sniffing": sniff},
        # служебный вход: всегда через VPN — для пинга, проверок и автопилота
        {"tag": "health-in", "listen": "127.0.0.1", "port": ports["health"], "protocol": "http", "settings": {}},
    ]
    if settings.get("allow_lan"):
        # для других устройств в сети — свои порты на всех адресах и, по умолчанию, логин с паролем
        acc = [{"user": settings.get("lan_user") or "pult", "pass": settings.get("lan_pass")}] \
            if settings.get("lan_auth", True) and settings.get("lan_pass") else []
        socks_set: dict = {"udp": True}
        http_set: dict = {}
        if acc:
            socks_set.update(auth="password", accounts=acc)
            http_set["accounts"] = acc
        inbounds.append({"tag": "lan-socks-in", "listen": "0.0.0.0", "port": int(settings.get("lan_socks_port", 10810)),
                         "protocol": "socks", "settings": socks_set, "sniffing": sniff})
        inbounds.append({"tag": "lan-http-in", "listen": "0.0.0.0", "port": int(settings.get("lan_http_port", 10811)),
                         "protocol": "http", "settings": http_set, "sniffing": sniff})
    if ports.get("direct"):
        # служебный вход «напрямую»: проверки без VPN работают и в режиме TUN
        inbounds.append({"tag": "direct-in", "listen": "127.0.0.1", "port": ports["direct"], "protocol": "socks",
                         "settings": {"udp": False}})
    if ports.get("direct_http"):
        inbounds.append({"tag": "direct-http-in", "listen": "127.0.0.1", "port": ports["direct_http"],
                         "protocol": "http", "settings": {}})
    if tun and tun.get("engine") == "xray":
        inbounds.append(tunmod.xray_tun_inbound(tun.get("ipv6", False), tun.get("leak", True)))
    mode = settings.get("mode", "smart")
    encrypted = bool(settings.get("dns_encrypted"))
    ipv6 = bool(tun and tun.get("ipv6"))
    bind = (tun or {}).get("bind", "")
    proxy_obs = proxy_outbounds(server, "proxy", mask, core_version, bind)
    direct = bind_outbound({"tag": "direct", "protocol": "freedom"}, bind)
    if encrypted:
        # прямые соединения узнают адрес через встроенный (зашифрованный) DNS, а не через DNS провайдера
        direct["settings"] = {"domainStrategy": "UseIP" if ipv6 else "UseIPv4"}
    block = {"tag": "block", "protocol": "blackhole"}
    if ads is None:  # старый вызов: только переключатель «Без рекламы» и списки runetfreedom
        ads = "geo" if settings.get("block_ads") else ""
    # первый outbound — маршрут по умолчанию для всего, что не попало ни в одно правило
    if routing.default_outbound(mode) == "proxy":
        outbounds = proxy_obs + [direct, block]
    else:
        outbounds = [direct] + proxy_obs + [block]
    outbounds.append({"tag": "adblock", "protocol": "blackhole"})  # реклама — отдельно, чтобы считать в журнале
    for m in multi or []:  # Мультисервер: дополнительные серверы для отдельных сервисов
        outbounds += proxy_outbounds(m["server"], m["tag"], m.get("mask", False), core_version, bind)
    outbounds += route_outbounds(routes, core_version, bind)  # свои маршруты: выбранный сервер или свой прокси
    for i, b in enumerate((failover or [])[:1], 1):  # запасной сервер внутри ядра (мгновенное переключение)
        outbounds += proxy_outbounds(b["server"], f"bk{i}", b.get("mask", False), core_version, bind)
    if dpi and dpi.get("mode") == "byedpi" and dpi.get("port"):
        outbounds.append({"tag": "byedpi", "protocol": "socks",
                          "settings": {"servers": [{"address": "127.0.0.1", "port": int(dpi["port"])}]}})
    rules = [{"type": "field", "inboundTag": ["health-in"], "outboundTag": "proxy"}]
    if ports.get("direct") or ports.get("direct_http"):
        rules.append({"type": "field", "inboundTag": ["direct-in", "direct-http-in"], "outboundTag": "direct"})
    # WARP (WireGuard) сам ищет адреса сайтов встроенным DNS ядра — без него спросил бы DNS провайдера
    use_dns = bool(tun) or encrypted or server.protocol == "wireguard" or any(r.get("warp") for r in routes or [])
    if tun and tun.get("engine") == "xray":
        outbounds.append({"tag": "dns-out", "protocol": "dns"})
        rules.append({"type": "field", "inboundTag": ["tun-in"], "port": 53, "outboundTag": "dns-out"})
    if use_dns:
        # запросы встроенного DNS: российский — напрямую (в «Глобальной» тоже через VPN), остальные — через VPN
        if mode != "vpn":
            rules.append({"type": "field", "inboundTag": ["dns-internal"], "ip": [tunmod.DNS_RU],
                          "outboundTag": "direct"})
        rules.append({"type": "field", "inboundTag": ["dns-internal"], "outboundTag": "proxy"})
        # DNS-серверы, к которым обращается движок TUN, — всегда через VPN: провайдер не увидит запросы
        rules.append({"type": "field", "ip": tunmod.DNS_REMOTE, "port": "53,443", "outboundTag": "proxy"})
    rules += routing.build_rules(mode, settings.get("proxy_list", ""), settings.get("direct_list", ""),
                                 settings.get("block_list", ""), ru_direct=settings.get("ru_direct", True),
                                 use_geo=use_geo, geo_ru_ip=geo_ru_ip, dpi=dpi,
                                 block_ads=ads, multi=multi, routes=routes,
                                 torrent=settings.get("torrent_route", "direct") if server.protocol != "direct" else "",
                                 block_quic=bool(tun) and settings.get("block_quic", True))
    if failover:
        # «через VPN» — через балансировщик: пока основной сервер отвечает, всё идёт через него; перестал —
        # новые соединения сразу идут через запасной (ядро само проверяет оба раз в 15 секунд).
        # Проверка связи программы (health-in) остаётся на основном — по ней программа сменит основной сервер.
        for r in rules:
            if r.get("outboundTag") == "proxy" and r.get("inboundTag") != ["health-in"]:
                r.pop("outboundTag")
                r["balancerTag"] = "failover"
        if routing.default_outbound(mode) == "proxy":
            rules.append({"type": "field", "network": "tcp,udp", "balancerTag": "failover"})
    cfg = {
        "log": {"loglevel": "warning", "access": access_log, "dnsLog": False},
        "api": {"tag": "api", "listen": f"127.0.0.1:{ports['api']}", "services": ["StatsService", "HandlerService", "RoutingService"]},
        "stats": {},
        "policy": {"system": {"statsOutboundUplink": True, "statsOutboundDownlink": True}},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": routing.domain_strategy(mode), "rules": rules},
    }
    if ports.get("metrics"):
        # страница метрик (/debug/vars): скорость и трафик читаются по HTTP, без запуска xray.exe
        cfg["metrics"] = {"tag": "metrics", "listen": f"127.0.0.1:{ports['metrics']}"}
    if use_dns:
        cfg["dns"] = tunmod.xray_dns(encrypted, ipv6, use_geo)
    if failover:
        cfg["routing"]["balancers"] = [{"tag": "failover", "selector": ["proxy"], "fallbackTag": "bk1",
                                        "strategy": {"type": "random"}}]
        ping = f"https://{settings.get('ping_host') or 'www.gstatic.com'}{settings.get('ping_path') or '/generate_204'}"
        cfg["burstObservatory"] = {"subjectSelector": ["proxy", "bk1"],
                                   "pingConfig": {"destination": ping, "interval": "15s", "sampling": 2,
                                                  "timeout": "6s", "connectivity": ""}}
    return cfg


# в Windows с шифрованием данных: настройки ядра (там ключи серверов) удаляются с диска сразу после запуска
WIPE_CONFIGS = False


def wipe(path: str) -> None:
    if WIPE_CONFIGS:
        try:
            os.remove(path)
        except OSError:
            pass


def check_config(paths: Paths, config: dict, path: str | None = None, exe: str | None = None) -> tuple[bool, str]:
    """Проверка конфига без запуска (xray run -test)."""
    path = path or os.path.join(paths.data_dir, "check_config.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=1)
    try:
        proc = subprocess.run([exe or paths.xray, "run", "-test", "-c", path], capture_output=True, text=True,
                              timeout=20, encoding="utf-8", errors="replace", **_popen_kwargs(paths.bin_dir))
    except (OSError, subprocess.SubprocessError) as exc:
        wipe(path)
        return False, f"не удалось запустить Xray: {exc}"
    wipe(path)
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode == 0:
        return True, ""
    lines = [ln for ln in out.strip().splitlines() if ln.strip()]
    return False, short_error("\n".join(lines[-3:]))


KNOWN_ERRORS = [
    ("without TLS or other encryption is prohibited",
     "сервер без шифрования (без TLS/Reality): новые версии ядра такие не пускают"),
    ("failed to load geosite", "в списках сайтов нет нужной категории"),
    ("code not found in geoip", "в списках адресов нет нужной категории"),
    ("address already in use", "порт уже занят другой программой"),
    ("Only one usage of each socket address", "порт уже занят другой программой"),
    ("invalid \"publicKey\"", "неверный ключ Reality у сервера"),
    ("unknown transport protocol", "ядро не знает такой транспорт"),
]


def short_error(text: str) -> str:
    text = text.strip()
    for needle, human in KNOWN_ERRORS:
        if needle.lower() in text.lower():
            return human
    for marker in ("Failed to start: ", "failed to load config files: "):
        if marker in text:
            text = text.split(marker, 1)[1]
    text = re.sub(r"^\[[^\]]*\]\s*>\s*", "", text)  # путь к файлу конфига не нужен
    text = re.sub(r"\s*>\s*", " > ", text)
    return text[:300]


AV_HINT = ("Похоже, ядро заблокировал антивирус (Xray — сетевая программа, некоторые антивирусы считают такие "
           "«потенциально нежелательными»). Добавь папку программы в исключения антивируса и нажми "
           "«Обновления → Обновить ядро».")


VIRUS_WORDS = ("virus", "вирус")  # текст ошибки Windows на английском и русском


def start_error(exc: OSError, exe: str) -> str:
    """Понятная причина, почему ядро не запустилось. Частая — антивирус удалил или заблокировал файл."""
    win = getattr(exc, "winerror", None)
    if win == 225 or any(w in str(exc).lower() for w in VIRUS_WORDS):  # «файл содержит вирус»
        return "антивирус заблокировал ядро Xray. " + AV_HINT
    if isinstance(exc, FileNotFoundError) or not os.path.isfile(exe):
        return "файл ядра Xray пропал. " + AV_HINT
    if isinstance(exc, PermissionError) or win in (5, 1260):  # «отказано в доступе», «заблокировано политикой»
        return "Windows не дала запустить ядро Xray (отказано в доступе). " + AV_HINT
    return f"не удалось запустить Xray: {exc}"


class XrayProcess:
    def __init__(self, paths: Paths, on_line=None):
        self.paths = paths
        self.on_line = on_line
        self.exe = paths.xray
        self.proc: subprocess.Popen | None = None
        self.lines: collections.deque = collections.deque(maxlen=200)
        self._lock = threading.Lock()
        self._reader_thread: threading.Thread | None = None

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self, config: dict, config_path: str, wait_for: list[int], timeout: float = 8.0,
              exe: str | None = None) -> None:
        self.stop()
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False, indent=1)
        self.lines.clear()
        self.exe = exe or self.paths.xray
        try:
            self.proc = subprocess.Popen([self.exe, "run", "-c", config_path], stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                         **_popen_kwargs(self.paths.bin_dir))
        except OSError as exc:
            raise XrayError(start_error(exc, self.exe)) from exc
        self._reader_thread = threading.Thread(target=self._reader, args=(self.proc,), daemon=True)
        self._reader_thread.start()
        if not netutil.wait_ports(wait_for, timeout=timeout, alive=self.alive):
            time.sleep(0.3)
            tail = "\n".join(list(self.lines)[-4:])
            self.stop()
            wipe(config_path)
            raise XrayError(short_error(tail) or "Xray не запустился")
        wipe(config_path)  # ядро уже прочитало настройки
        if config_path == self.paths.run_config:
            try:
                with open(self.paths.pid_file, "w") as f:
                    f.write(str(self.proc.pid))
            except OSError:
                pass

    def death_note(self, wait: float = 1.5) -> str:
        """Почему ядро остановилось: код выхода и последние строки вывода. Ядро уже закрылось, а читатель вывода
        мог ещё не дочитать его (паника Go печатается в самом конце) — ждём его до wait секунд."""
        t = getattr(self, "_reader_thread", None)
        if t is not None:
            t.join(wait)
        proc = self.proc
        code = proc.poll() if proc is not None else None
        lines = list(self.lines)
        # паника: первая строка «panic: …» и место, где она случилась, важнее хвоста из адресов памяти
        panic = next((i for i, ln in enumerate(lines) if ln.startswith(("panic:", "fatal error:"))), None)
        pick = lines[panic:panic + 6] if panic is not None else lines[-4:]
        head = f"код выхода {code}" if code is not None else "процесс пропал"
        return "\n".join([head] + pick)

    def _reader(self, proc: subprocess.Popen):
        assert proc.stdout is not None
        for raw in iter(proc.stdout.readline, b""):
            line = raw.decode("utf-8", "replace").rstrip()
            if not line:
                continue
            self.lines.append(line)
            if self.on_line:
                try:
                    self.on_line(line)
                except Exception:
                    pass

    def stop(self) -> None:
        with self._lock:
            proc, self.proc = self.proc, None
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=4)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass


def query_stats(paths: Paths, api_port: int, exe: str | None = None) -> dict[str, dict[str, int]]:
    """Счётчики трафика по outbound: {"proxy": {"uplink": n, "downlink": n}, ...}."""
    proc = subprocess.run([exe or paths.xray, "api", "statsquery", f"--server=127.0.0.1:{api_port}"],
                          capture_output=True, text=True, timeout=5, **_popen_kwargs(paths.bin_dir))
    if proc.returncode != 0:
        raise XrayError(short_error(proc.stderr or proc.stdout or "statsquery failed"))
    data = json.loads(proc.stdout or "{}")
    items = []
    for item in data.get("stat", []) or []:
        parts = str(item.get("name", "")).split(">>>")
        if len(parts) == 4 and parts[0] == "outbound" and parts[2] == "traffic":
            items.append((parts[1], parts[3], item.get("value", 0)))
    return _merge_outbound_stats(items)


def _merge_outbound_stats(items) -> dict[str, dict[str, int]]:
    """(тег, направление, байты) → {"proxy": {"uplink": n, "downlink": n}, ...}; вспомогательные outbound
    («имя@proxy») считаем вместе с основным."""
    result: dict[str, dict[str, int]] = {}
    for tag, way, value in items:
        if way not in ("uplink", "downlink"):
            continue
        try:
            value = int(value or 0)
        except (TypeError, ValueError):
            value = 0
        bucket = result.setdefault(str(tag).rsplit("@", 1)[-1], {"uplink": 0, "downlink": 0})
        bucket[way] = bucket.get(way, 0) + value
    return result


def read_metrics(port: int, timeout: float = 2.0) -> dict:
    """Страница метрик ядра (/debug/vars) — обычный HTTP на 127.0.0.1, без запуска xray.exe.
    Напрямую, мимо системного прокси (он указывает на само ядро)."""
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", int(port), timeout=timeout)
    try:
        conn.request("GET", "/debug/vars", headers={"Connection": "close"})
        resp = conn.getresponse()
        body = resp.read(4 * 1024 * 1024)
        if resp.status != 200:
            raise XrayError(f"метрики ядра: HTTP {resp.status}")
    finally:
        conn.close()
    data = json.loads(body.decode("utf-8", "replace") or "{}")
    if not isinstance(data, dict):
        raise XrayError("метрики ядра: непонятный ответ")
    return data


def stats_from_metrics(data: dict) -> dict[str, dict[str, int]]:
    """Счётчики outbound из страницы метрик: {"stats": {"outbound": {тег: {"uplink", "downlink"}}}}."""
    stats = data.get("stats")
    if not isinstance(stats, dict) or not isinstance(stats.get("outbound"), dict):
        raise XrayError("метрики ядра: нет счётчиков трафика")
    return _merge_outbound_stats((tag, way, v) for tag, ways in stats["outbound"].items() if isinstance(ways, dict)
                                 for way, v in ways.items())


def query_metrics(port: int, timeout: float = 2.0) -> dict[str, dict[str, int]]:
    """То же, что query_stats, но через страницу метрик — без запуска процесса (раньше это был
    запуск xray.exe каждые 2 секунды, и каждый такой запуск проверял антивирус)."""
    return stats_from_metrics(read_metrics(port, timeout))


def api_command(paths: Paths, api_port: int, args: list[str], exe: str | None = None) -> bool:
    """Команда управления работающим ядром (xray api ...). True — выполнено."""
    try:
        proc = subprocess.run([exe or paths.xray, "api", args[0], f"--server=127.0.0.1:{api_port}", *args[1:]],
                              capture_output=True, text=True, timeout=8, **_popen_kwargs(paths.bin_dir))
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def kill_stale(paths: Paths) -> bool:
    """Если программа в прошлый раз закрылась аварийно, гасим оставшийся процесс Xray."""
    if not os.path.isfile(paths.pid_file):
        return False
    try:
        pid = int(open(paths.pid_file).read().strip())
    except (OSError, ValueError):
        pid = 0
    killed = False
    if pid and IS_WINDOWS:
        try:
            out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"], capture_output=True,
                                 text=True, timeout=5, creationflags=NO_WINDOW).stdout
            if "xray" in out.lower():
                subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, timeout=5,
                               creationflags=NO_WINDOW)
                killed = True
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        os.remove(paths.pid_file)
    except OSError:
        pass
    return killed


ACCESS_RE = re.compile(r"accepted\s+(?:(tcp|udp):)?(\S+):(\d+)\s+\[([^\]]+)\]")


def parse_access_line(line: str) -> dict | None:
    m = ACCESS_RE.search(line)
    if not m:
        return None
    route = m.group(4)
    parts = re.split(r"\s*(?:->|>>)\s*", route)
    inbound = parts[0].strip() if parts else ""
    outbound = parts[-1].strip() if len(parts) > 1 else ""
    if inbound in ("health-in", "api"):
        return None
    return {"time": line[11:19] if len(line) > 19 else "", "network": m.group(1) or "tcp", "host": m.group(2),
            "port": int(m.group(3)), "inbound": inbound, "outbound": outbound.rsplit("@", 1)[-1]}
