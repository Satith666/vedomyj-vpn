"""Разбор ссылок серверов в настройки движков.

Xray: vless, vmess, trojan, ss, socks, hysteria2 (hy2) и JSON-конфиги Xray.
sing-box (на ПК, отдельным процессом-«мостом»): tuic, anytls — у Server engine="singbox", настройки в sb_outbound.
AmneziaWG (запускается отдельно, своим клиентом): конфиг [Interface]/[Peer] и ключи Amnezia vpn:// — хранятся
одной строкой awg://<base64>, у Server engine="awg", текст конфига — в awg_conf (в нём закрытый ключ: только
в зашифрованных настройках, в отчётах вычищается)."""

from __future__ import annotations

import base64
import copy
import hashlib
import ipaddress
import json
import re
import struct
import zlib
from dataclasses import dataclass, field
from urllib.parse import quote, unquote, urlsplit

PROXY_PROTOCOLS = ("vless", "vmess", "trojan", "shadowsocks", "socks", "http", "wireguard", "hysteria")

UNSUPPORTED_SCHEMES = {
    "hysteria": "Hysteria первой версии не поддерживается — нужен Hysteria2",
    "wireguard": "обычный WireGuard в России блокируют — нужен AmneziaWG",
    "wg": "обычный WireGuard в России блокируют — нужен AmneziaWG",
    "tg": "MTProto-прокси работает только в Telegram",
    "ssr": "ShadowsocksR не поддерживается ядром Xray",
}


@dataclass
class Server:
    name: str
    protocol: str
    address: str = ""
    port: int = 0
    outbound: dict = field(default_factory=dict)
    extra_outbounds: list = field(default_factory=list)
    link: str = ""
    supported: bool = True
    note: str = ""
    source: str = "link"  # link | json
    result: dict = field(default_factory=dict)
    sub_id: str = ""
    insecure: bool = False  # без TLS/Reality/шифрования VLESS: новые ядра Xray такие запрещают
    stub: bool = False      # не сервер, а сообщение провайдера (адрес 0.0.0.0 и т.п.)
    pinned_ip: str = ""     # DNS провайдера не знает имя сервера — адрес из защищённого DNS (на ключ не влияет)
    engine: str = "xray"    # xray | singbox (мост sing-box, на ПК) | awg (AmneziaWG — отдельным клиентом)
    sb_outbound: dict = field(default_factory=dict)  # настройки sing-box (engine="singbox")
    awg_conf: str = ""      # текст конфига AmneziaWG (engine="awg"); содержит закрытый ключ
    sidecar_port: int = 0   # порт моста sing-box для основного подключения (выставляет движок)
    tls_unverified: bool = False  # ссылка просит не проверять сертификат (allowInsecure): программа закрепляет его сама

    @property
    def key(self) -> str:
        raw = self.link or json.dumps(self.outbound, sort_keys=True, ensure_ascii=False)
        return hashlib.sha1((self.sub_id + "|" + raw).encode("utf-8")).hexdigest()[:12]

    @property
    def endpoint(self) -> str:
        if not self.address:
            return ""
        host = f"[{self.address}]" if ":" in self.address else self.address
        return f"{host}:{self.port}"


class LinkError(ValueError):
    pass


STUB_HOSTS = {"0.0.0.0", "::", "127.0.0.1", "::1", "localhost", "example.com", "0.0.0.1"}
# Слова из типичных «серверов-сообщений»: «Включите отправку HWID», «Обновите приложение», «Подписка истекла»…
STUB_WORDS = ("hwid", "включите", "обновите", "устройств", "истек", "истёк", "закончил", "продлите", "не поддерж",
              "приложени", "оплатите", "заблокирован", "лимит", "subscription expired", "update app", "enable hwid")
ZERO_UUID = "00000000-0000-0000-0000-000000000000"


def is_private_host(host: str) -> bool:
    host = (host or "").strip("[]").lower()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host == "localhost" or host.endswith((".local", ".lan", ".internal", ".home.arpa", ".localhost"))
    return ip.is_private or ip.is_loopback or ip.is_link_local


def drop_allow_insecure(ob: dict) -> bool:
    """Ядра Xray с 1 июня 2026 не принимают allowInsecure («не проверять сертификат»): настройки с ним не запускаются.
    Убирает его; True — проверку просили отключить, а отпечатка сертификата (pinnedPeerCertSha256) нет."""
    tls = (ob.get("streamSettings") or {}).get("tlsSettings")
    if not isinstance(tls, dict) or "allowInsecure" not in tls:
        return False
    asked = bool(tls.pop("allowInsecure"))
    return asked and not tls.get("pinnedPeerCertSha256")


def _hy2_via_singbox(srv: "Server") -> None:
    """Hysteria2 с самоподписанным сертификатом без отпечатка: Xray так не умеет (его по QUIC и не снять заранее),
    а sing-box — умеет. Такой сервер идёт через мост sing-box (на компьютере)."""
    st = srv.outbound.get("settings") or {}
    ss = srv.outbound.get("streamSettings") or {}
    tls = ss.get("tlsSettings") or {}
    ob: dict = {"type": "hysteria2", "server": st.get("address", srv.address), "server_port": int(st.get("port", srv.port)),
                "password": (ss.get("hysteriaSettings") or {}).get("auth", ""),
                "tls": {"enabled": True, "server_name": tls.get("serverName") or srv.address, "insecure": True,
                        "alpn": tls.get("alpn") or ["h3"]}}
    for m in (ss.get("finalmask") or {}).get("udp") or []:
        if m.get("type") == "salamander":
            ob["obfs"] = {"type": "salamander", "password": (m.get("settings") or {}).get("password", "")}
    srv.engine = "singbox"
    srv.sb_outbound = ob


def mark_flags(srv: "Server") -> "Server":
    """Помечает заглушки провайдера и серверы без шифрования; убирает allowInsecure (см. drop_allow_insecure)."""
    unverified = drop_allow_insecure(srv.outbound)
    for ex in srv.extra_outbounds:
        drop_allow_insecure(ex)
    if unverified and srv.engine == "xray":
        srv.tls_unverified = True
        if (srv.outbound.get("streamSettings") or {}).get("network") == "hysteria":
            _hy2_via_singbox(srv)
    host = (srv.address or "").strip("[]").lower()
    uid = ""
    st = srv.outbound.get("settings") or {}
    vnext = st.get("vnext") or []
    if vnext and vnext[0].get("users"):
        uid = str(vnext[0]["users"][0].get("id", ""))
    if srv.protocol in ("vless", "vmess", "trojan", "shadowsocks", "socks") and (
            host in STUB_HOSTS or srv.port in (0, 1) or uid == ZERO_UUID):
        srv.stub = True
        srv.supported = False
        srv.note = "это не сервер, а сообщение провайдера"
        return srv
    if srv.supported and srv.protocol in ("vless", "trojan"):
        security = ((srv.outbound.get("streamSettings") or {}).get("security") or "none").lower()
        encryption = "none"
        if vnext and vnext[0].get("users"):
            encryption = str(vnext[0]["users"][0].get("encryption") or "none").lower()
        elif srv.protocol == "vless":
            encryption = str(st.get("encryption") or "none").lower()
        if security == "none" and encryption == "none" and not is_private_host(host):
            if any(w in srv.name.lower() for w in STUB_WORDS):
                srv.stub = True
                srv.supported = False
                srv.note = "это не сервер, а сообщение провайдера"
                return srv
            srv.insecure = True
            srv.note = "сервер без шифрования (без TLS/Reality)"
    return srv


# ---------- вспомогательное ----------

def b64decode_loose(data: str) -> bytes:
    """Base64 в любом виде: обычный, url-safe, без выравнивания, с переносами строк."""
    s = "".join(data.split())
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def try_b64_text(data: str) -> str | None:
    try:
        text = b64decode_loose(data).decode("utf-8")
    except Exception:
        return None
    return text


def parse_query(query: str) -> dict:
    """Разбор параметров ссылки. Плюс не превращается в пробел — в ключах Reality он не встречается,
    а в JSON-параметрах может быть значимым."""
    params: dict[str, str] = {}
    if not query:
        return params
    for part in query.split("&"):
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
        else:
            k, v = part, ""
        k = unquote(k).strip()
        if k and k not in params:
            params[k] = unquote(v).strip()
    return params


def split_host_port(hostport: str) -> tuple[str, int]:
    hostport = hostport.strip().rstrip("/")
    if hostport.startswith("["):
        end = hostport.find("]")
        if end < 0:
            raise LinkError("неверный IPv6-адрес")
        host = hostport[1:end]
        rest = hostport[end + 1:]
        if not rest.startswith(":"):
            raise LinkError("не указан порт")
        port_s = rest[1:]
    else:
        if ":" not in hostport:
            raise LinkError("не указан порт")
        host, port_s = hostport.rsplit(":", 1)
    try:
        port = int(port_s)
    except ValueError as exc:
        raise LinkError("неверный порт") from exc
    if not host or not (0 < port < 65536):
        raise LinkError("неверный адрес или порт")
    return host, port


def _first(*values) -> str:
    for v in values:
        if v:
            return str(v)
    return ""


def _truthy(v) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


# ---------- транспорт и шифрование ----------

def build_stream(p: dict, address: str, default_security: str = "none") -> dict:
    net = (p.get("type") or p.get("net") or "tcp").strip().lower()
    if net == "raw":
        net = "tcp"
    if net == "splithttp":
        net = "xhttp"
    security = (p.get("security") or default_security or "none").strip().lower()
    if security in ("", "0", "false"):
        security = "none"
    host = p.get("host", "")
    path = p.get("path", "")

    ss: dict = {"network": net, "security": security}

    if net == "tcp":
        if p.get("headerType", "").lower() == "http":
            hosts = [h.strip() for h in host.split(",") if h.strip()]
            request: dict = {"path": [path or "/"]}
            if hosts:
                request["headers"] = {"Host": hosts}
            ss["tcpSettings"] = {"header": {"type": "http", "request": request}}
    elif net == "ws":
        ws: dict = {"path": path or "/"}
        if host:
            ws["host"] = host
        ss["wsSettings"] = ws
    elif net == "grpc":
        grpc: dict = {"serviceName": _first(p.get("serviceName"), path), "multiMode": p.get("mode", "") == "multi"}
        if p.get("authority"):
            grpc["authority"] = p["authority"]
        ss["grpcSettings"] = grpc
    elif net == "httpupgrade":
        hu: dict = {"path": path or "/"}
        if host:
            hu["host"] = host
        ss["httpupgradeSettings"] = hu
    elif net == "xhttp":
        xs: dict = {"path": path or "/"}
        if host:
            xs["host"] = host
        if p.get("mode"):
            xs["mode"] = p["mode"]
        if p.get("extra"):
            try:
                xs["extra"] = json.loads(p["extra"])
            except ValueError:
                pass
        ss["xhttpSettings"] = xs
    elif net == "kcp":
        kcp: dict = {"header": {"type": p.get("headerType") or "none"}}
        if p.get("seed"):
            kcp["seed"] = p["seed"]
        ss["kcpSettings"] = kcp
    elif net in ("http", "h2"):
        ss["network"] = "http"
        h2: dict = {"path": path or "/"}
        hosts = [h.strip() for h in host.split(",") if h.strip()]
        if hosts:
            h2["host"] = hosts
        ss["httpSettings"] = h2
    else:
        raise LinkError(f"транспорт «{net}» не поддерживается")

    sni = _first(p.get("sni"), p.get("peer"), p.get("serverName"))
    fp = p.get("fp") or p.get("fingerprint") or ""

    if security == "tls":
        tls: dict = {"serverName": sni or (host.split(",")[0].strip() if host else address)}
        tls["fingerprint"] = fp or "chrome"
        if p.get("alpn"):
            tls["alpn"] = [a.strip() for a in p["alpn"].split(",") if a.strip()]
        if _truthy(p.get("allowInsecure", "")) or _truthy(p.get("insecure", "")):
            tls["allowInsecure"] = True
        if p.get("ech"):
            tls["echConfigList"] = p["ech"]
        if p.get("pcs"):
            tls["pinnedPeerCertSha256"] = p["pcs"]
        ss["tlsSettings"] = tls
    elif security == "reality":
        pbk = p.get("pbk") or p.get("publicKey") or p.get("password") or ""
        if not pbk:
            raise LinkError("нет публичного ключа Reality (pbk)")
        rs: dict = {
            "serverName": sni,
            "fingerprint": fp or "chrome",
            "publicKey": pbk,
            "shortId": p.get("sid", ""),
            "spiderX": p.get("spx") or "/",
        }
        if p.get("pqv"):
            rs["mldsa65Verify"] = p["pqv"]
        ss["realitySettings"] = rs
    elif security != "none":
        raise LinkError(f"шифрование «{security}» не поддерживается")

    return ss


# ---------- протоколы ----------

def _split_link(link: str) -> tuple[str, str, str, str]:
    """Возвращает (userinfo, hostport, query, name) для ссылок вида scheme://user@host:port?q#name."""
    parts = urlsplit(link)
    name = unquote(parts.fragment or "")
    netloc = parts.netloc
    if "@" not in netloc:
        raise LinkError("нет данных пользователя в ссылке")
    userinfo, hostport = netloc.rsplit("@", 1)
    return unquote(userinfo), hostport, parts.query, name


def parse_vless(link: str) -> Server:
    uid, hostport, query, name = _split_link(link)
    host, port = split_host_port(hostport)
    p = parse_query(query)
    user: dict = {"id": uid, "encryption": p.get("encryption") or "none"}
    if p.get("flow"):
        user["flow"] = p["flow"]
    outbound = {
        "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
        "streamSettings": build_stream(p, host),
    }
    return Server(name=name or f"VLESS {host}", protocol="vless", address=host, port=port, outbound=outbound, link=link)


def parse_trojan(link: str) -> Server:
    password, hostport, query, name = _split_link(link)
    host, port = split_host_port(hostport)
    p = parse_query(query)
    server: dict = {"address": host, "port": port, "password": password}
    if p.get("flow"):
        server["flow"] = p["flow"]
    outbound = {
        "protocol": "trojan",
        "settings": {"servers": [server]},
        "streamSettings": build_stream(p, host, default_security="tls"),
    }
    return Server(name=name or f"Trojan {host}", protocol="trojan", address=host, port=port, outbound=outbound, link=link)


def parse_vmess(link: str) -> Server:
    body = link[len("vmess://"):]
    name_hint = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        name_hint = unquote(frag)
    text = try_b64_text(body.split("?")[0])
    if text and text.strip().startswith("{"):
        try:
            v = json.loads(text)
        except ValueError as exc:
            raise LinkError("повреждённая vmess-ссылка") from exc
        host = str(v.get("add", "")).strip()
        try:
            port = int(v.get("port", 0))
        except (TypeError, ValueError) as exc:
            raise LinkError("неверный порт") from exc
        if not host or not port:
            raise LinkError("нет адреса сервера")
        net = str(v.get("net") or "tcp")
        tls = str(v.get("tls") or "").lower()
        p = {
            "type": net,
            "headerType": str(v.get("type") or ""),
            "host": str(v.get("host") or ""),
            "path": str(v.get("path") or ""),
            "security": tls if tls in ("tls", "reality") else "none",
            "sni": str(v.get("sni") or ""),
            "alpn": str(v.get("alpn") or ""),
            "fp": str(v.get("fp") or ""),
            "pbk": str(v.get("pbk") or ""),
            "sid": str(v.get("sid") or ""),
            "allowInsecure": str(v.get("allowInsecure") or v.get("skip-cert-verify") or ""),
        }
        if net == "grpc":
            p["serviceName"] = p["path"]
            p["mode"] = str(v.get("type") or "")
        outbound = {
            "protocol": "vmess",
            "settings": {"vnext": [{"address": host, "port": port, "users": [
                {"id": str(v.get("id", "")), "security": str(v.get("scy") or "auto")}]}]},
            "streamSettings": build_stream(p, host),
        }
        name = str(v.get("ps") or "") or name_hint or f"VMess {host}"
        return Server(name=name, protocol="vmess", address=host, port=port, outbound=outbound, link=link)
    # новый формат vmess://uuid@host:port?...
    uid, hostport, query, name = _split_link(link)
    host, port = split_host_port(hostport)
    p = parse_query(query)
    outbound = {
        "protocol": "vmess",
        "settings": {"vnext": [{"address": host, "port": port, "users": [
            {"id": uid, "security": p.get("encryption") or "auto"}]}]},
        "streamSettings": build_stream(p, host),
    }
    return Server(name=name or f"VMess {host}", protocol="vmess", address=host, port=port, outbound=outbound, link=link)


def parse_ss(link: str) -> Server:
    body = link[len("ss://"):]
    name = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        name = unquote(frag)
    query = ""
    if "?" in body:
        body, query = body.split("?", 1)
    p = parse_query(query)
    if p.get("plugin"):
        raise LinkError("плагины Shadowsocks не поддерживаются")
    body = body.rstrip("/")
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        plain = unquote(userinfo)
        if ":" in plain:
            method, password = plain.split(":", 1)
        else:
            decoded = try_b64_text(userinfo)
            if not decoded or ":" not in decoded:
                raise LinkError("не удалось прочитать метод и пароль")
            method, password = decoded.split(":", 1)
    else:
        decoded = try_b64_text(body)
        if not decoded or "@" not in decoded:
            raise LinkError("повреждённая ss-ссылка")
        cred, hostport = decoded.rsplit("@", 1)
        if ":" not in cred:
            raise LinkError("не удалось прочитать метод и пароль")
        method, password = cred.split(":", 1)
    host, port = split_host_port(hostport)
    outbound = {
        "protocol": "shadowsocks",
        "settings": {"servers": [{"address": host, "port": port, "method": method, "password": password}]},
    }
    return Server(name=name or f"Shadowsocks {host}", protocol="shadowsocks", address=host, port=port,
                  outbound=outbound, link=link)


def parse_socks(link: str) -> Server:
    scheme, rest = link.split("://", 1)
    name = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
        name = unquote(frag)
    rest = rest.split("?", 1)[0].rstrip("/")
    user = password = ""
    if "@" in rest:
        userinfo, hostport = rest.rsplit("@", 1)
        plain = unquote(userinfo)
        if ":" in plain:
            user, password = plain.split(":", 1)
        else:
            decoded = try_b64_text(userinfo)
            if decoded and ":" in decoded:
                user, password = decoded.split(":", 1)
            else:
                user = plain
    else:
        hostport = rest
    host, port = split_host_port(hostport)
    srv: dict = {"address": host, "port": port}
    if user:
        srv["users"] = [{"user": user, "pass": password}]
    outbound = {"protocol": "socks", "settings": {"servers": [srv]}}
    return Server(name=name or f"SOCKS5 {host}", protocol="socks", address=host, port=port,
                  outbound=outbound, link=link)


def _tls_params(p: dict, host: str, alpn_default: list | None = None) -> dict:
    sni = _first(p.get("sni"), p.get("peer"), p.get("serverName"))
    tls: dict = {"serverName": sni or host}
    alpn = [a.strip() for a in (p.get("alpn") or "").split(",") if a.strip()] or alpn_default
    if alpn:
        tls["alpn"] = alpn
    if _truthy(p.get("insecure", "")) or _truthy(p.get("allowInsecure", "")) or _truthy(p.get("allow_insecure", "")):
        tls["allowInsecure"] = True
    pin = _first(p.get("pinSHA256"), p.get("pcs"))
    if pin:
        tls["pinnedPeerCertSha256"] = pin
    return tls


def parse_hysteria2(link: str) -> Server:
    """hysteria2://пароль@адрес:порт/?sni=…&obfs=salamander&obfs-password=…&insecure=1#имя → Xray (protocol hysteria).
    Нужен Xray 26.2+; маскировка Salamander — через finalmask. Перебор портов (mport) не поддерживается."""
    parts = urlsplit(link)
    name = unquote(parts.fragment or "")
    netloc = parts.netloc
    auth = ""
    if "@" in netloc:
        auth, netloc = netloc.rsplit("@", 1)
        auth = unquote(auth)
    host, port = split_host_port(netloc if re.search(r":\d+$", netloc) else f"{netloc}:443")
    p = parse_query(parts.query)
    if not host:
        raise LinkError("нет адреса сервера")
    ss: dict = {"network": "hysteria", "hysteriaSettings": {"version": 2, "auth": auth},
                "security": "tls", "tlsSettings": _tls_params(p, host, ["h3"])}
    obfs = (p.get("obfs") or "").lower()
    if obfs and obfs != "salamander":
        raise LinkError(f"маскировка «{obfs}» не поддерживается")
    if obfs:
        ss["finalmask"] = {"udp": [{"type": "salamander", "settings": {"password": p.get("obfs-password", "")}}]}
    ob = {"tag": "proxy", "protocol": "hysteria", "settings": {"version": 2, "address": host, "port": port},
          "streamSettings": ss}
    return Server(name=name or f"Hysteria2 {host}", protocol="hysteria2", address=host, port=port, outbound=ob,
                  link=link)


def _sb_tls(p: dict, host: str, alpn_default: list | None = None) -> dict:
    t = _tls_params(p, host, alpn_default)
    out: dict = {"enabled": True, "server_name": t["serverName"]}
    if t.get("alpn"):
        out["alpn"] = t["alpn"]
    if t.get("allowInsecure"):
        out["insecure"] = True
    return out


def parse_tuic(link: str) -> Server:
    """tuic://uuid:пароль@адрес:порт?congestion_control=bbr&udp_relay_mode=native&sni=…#имя → мост sing-box."""
    userinfo, hostport, query, name = _split_link(link)
    host, port = split_host_port(hostport)
    uid, _, password = userinfo.partition(":")
    p = parse_query(query)
    if not uid:
        raise LinkError("нет UUID")
    sb: dict = {"type": "tuic", "server": host, "server_port": port, "uuid": uid, "password": password,
                "congestion_control": p.get("congestion_control") or p.get("congestion") or "bbr",
                "udp_relay_mode": p.get("udp_relay_mode") or "native", "tls": _sb_tls(p, host, ["h3"])}
    return Server(name=name or f"TUIC {host}", protocol="tuic", address=host, port=port, link=link,
                  engine="singbox", sb_outbound=sb)


def parse_anytls(link: str) -> Server:
    """anytls://пароль@адрес:порт?sni=…&insecure=1#имя → мост sing-box."""
    userinfo, hostport, query, name = _split_link(link)
    host, port = split_host_port(hostport)
    p = parse_query(query)
    sb = {"type": "anytls", "server": host, "server_port": port, "password": userinfo, "tls": _sb_tls(p, host)}
    return Server(name=name or f"AnyTLS {host}", protocol="anytls", address=host, port=port, link=link,
                  engine="singbox", sb_outbound=sb)


# ---------- AmneziaWG ----------

AWG_KEYS = ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5")


def awg_parse_conf(text: str) -> dict:
    """[Interface]/[Peer] → {"interface": {...}, "peer": {...}}. Ошибка — LinkError."""
    sect, out = "", {"interface": {}, "peer": {}}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        m = re.fullmatch(r"\[(\w+)\]", line)
        if m:
            sect = m.group(1).lower()
            continue
        if "=" in line and sect in out:
            k, v = line.split("=", 1)
            out[sect].setdefault(k.strip(), v.strip())
    i, p = out["interface"], out["peer"]
    if not i.get("PrivateKey") or not p.get("PublicKey") or not p.get("Endpoint"):
        raise LinkError("в конфиге AmneziaWG нет ключей или адреса сервера")
    return out


def awg_link(conf: str, name: str = "") -> str:
    """Конфиг AmneziaWG → одна строка awg://… (так он хранится вместе с другими своими серверами)."""
    awg_parse_conf(conf)
    body = base64.urlsafe_b64encode(conf.strip().encode("utf-8")).decode().rstrip("=")
    return f"awg://{body}" + (f"#{quote(name, safe='')}" if name else "")


def amnezia_key_configs(key: str) -> list[tuple[str, str]]:
    """Ключ AmneziaVPN vpn://… → [(вид, текст)]: ("awg", конфиг AmneziaWG) и/или ("xray", JSON Xray).
    Формат: base64url от qCompress (4 байта длины + zlib) JSON с контейнерами и их last_config."""
    raw = key.strip()[len("vpn://"):]
    data = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    for blob in (data[4:], data):
        try:
            data = zlib.decompress(blob)
            break
        except zlib.error:
            continue
    try:
        root = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise LinkError("ключ Amnezia не читается") from exc
    found: list[tuple[str, str]] = []

    def walk(x, depth=0):
        if depth > 8:
            return
        if isinstance(x, dict):
            if "outbounds" in x and isinstance(x["outbounds"], list):
                found.append(("xray", json.dumps(x, ensure_ascii=False)))
                return
            for v in x.values():
                walk(v, depth + 1)
        elif isinstance(x, list):
            for v in x:
                walk(v, depth + 1)
        elif isinstance(x, str):
            if x.lstrip().startswith("{"):  # last_config — JSON строкой; внутри него уже сам конфиг
                try:
                    walk(json.loads(x), depth + 1)
                    return
                except ValueError:
                    pass
            if "[Interface]" in x and "[Peer]" in x:
                found.append(("awg", x))
    walk(root)
    name = str(root.get("description") or "") if isinstance(root, dict) else ""
    return [(kind, text) for kind, text in found] if not name else [(k, t) for k, t in found] + [("name", name)]


def parse_awg(link: str) -> Server:
    body, _, frag = link[len("awg://"):].partition("#")
    try:
        conf = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise LinkError("ссылка AmneziaWG повреждена") from exc
    c = awg_parse_conf(conf)
    host, port = split_host_port(c["peer"]["Endpoint"])
    name = unquote(frag) or f"AmneziaWG {host}"
    obf = sum(1 for k in AWG_KEYS if c["interface"].get(k) not in (None, "", "0"))
    return Server(name=name, protocol="amneziawg", address=host, port=port, link=link, engine="awg", awg_conf=conf,
                  note="" if obf else "без маскировки AmneziaWG это обычный WireGuard — в России его блокируют")


def text_to_links(text: str) -> list[str]:
    """Вставленный текст → строки-ссылки: конфиг AmneziaWG целиком превращается в awg://, ключ Amnezia vpn:// —
    в awg:// и/или ссылки из его настроек Xray; остальное — как есть, построчно."""
    text = (text or "").strip()
    if "[Interface]" in text and "[Peer]" in text:
        name = ""
        m = re.search(r"^#\s*(?:Name\s*=\s*)?(.+)$", text, re.M)
        if m:
            name = m.group(1).strip()[:60]
        return [awg_link(text, name)]
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("vpn://"):
            items = amnezia_key_configs(line)
            name = next((t for k, t in items if k == "name"), "")
            for kind, body in items:
                if kind == "awg":
                    out.append(awg_link(body, name))
                elif kind == "xray":
                    for srv in servers_from_json(json.loads(body)):
                        out.append("xrayjson://" + base64.urlsafe_b64encode(
                            json.dumps({"remarks": name or srv.name, "outbounds": [srv.outbound] + srv.extra_outbounds},
                                       ensure_ascii=False).encode()).decode().rstrip("="))
            if not any(k in ("awg", "xray") for k, _ in items):
                raise LinkError("в ключе Amnezia нет ни AmneziaWG, ни Xray")
        elif line:
            out.append(line)
    return out


def parse_xrayjson(link: str) -> Server:
    body = link[len("xrayjson://"):]
    data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode("utf-8"))
    servers = servers_from_json(data)
    if not servers:
        raise LinkError("в настройках Xray нет сервера")
    srv = servers[0]
    srv.link = link
    srv.source = "link"
    return srv


PARSERS = {
    "vless": parse_vless,
    "vmess": parse_vmess,
    "trojan": parse_trojan,
    "ss": parse_ss,
    "socks": parse_socks,
    "socks5": parse_socks,
    "hysteria2": parse_hysteria2,
    "hy2": parse_hysteria2,
    "tuic": parse_tuic,
    "anytls": parse_anytls,
    "awg": parse_awg,
    "xrayjson": parse_xrayjson,
}


def parse_link(line: str) -> Server | None:
    """Разбирает одну строку. None — строка не является ссылкой на сервер."""
    line = line.strip()
    if "://" not in line:
        return None
    scheme = line.split("://", 1)[0].lower()
    if scheme == "happ":
        lowered = line.lower()
        if lowered.startswith("happ://crypt"):
            return Server(name="Зашифрованная ссылка Happ", protocol="happ", link=line, supported=False,
                          note="Провайдер зашифровал ссылку только для Happ. Попробуй другой User-Agent в настройках.")
        return None  # happ://routing/... и прочие служебные ссылки
    if scheme in ("http", "https") and "t.me/proxy" in line:
        return Server(name="MTProto-прокси", protocol="mtproto", link=line, supported=False,
                      note=UNSUPPORTED_SCHEMES["tg"])
    if scheme in UNSUPPORTED_SCHEMES:
        name = unquote(line.split("#", 1)[1]) if "#" in line else scheme.upper()
        return Server(name=name, protocol=scheme, link=line, supported=False, note=UNSUPPORTED_SCHEMES[scheme])
    parser = PARSERS.get(scheme)
    if not parser:
        return None
    try:
        return mark_flags(parser(line))
    except LinkError as exc:
        name = unquote(line.split("#", 1)[1]) if "#" in line else scheme.upper()
        return Server(name=name, protocol=scheme, link=line, supported=False, note=str(exc))
    except Exception as exc:  # повреждённая ссылка не должна ронять весь разбор
        name = unquote(line.split("#", 1)[1]) if "#" in line else scheme.upper()
        return Server(name=name, protocol=scheme, link=line, supported=False, note=f"не удалось разобрать: {exc}")


def kind_of(srv: Server) -> str:
    """Движок для «Движок» на главной: xray, hy2 (Hysteria2 — в Xray или, с самоподписанным сертификатом, через мост),
    singbox (мост: TUIC, AnyTLS), awg."""
    if srv.engine == "awg":
        return "awg"
    if srv.protocol in ("hysteria2", "hy2", "hysteria"):
        return "hy2"
    return "singbox" if srv.engine == "singbox" else "xray"


# ---------- JSON-конфиги ----------

def _outbound_endpoint(ob: dict) -> tuple[str, int]:
    st = ob.get("settings") or {}
    for key in ("vnext", "servers", "peers"):
        lst = st.get(key)
        if isinstance(lst, list) and lst:
            item = lst[0]
            addr = item.get("address") or item.get("endpoint", "")
            port = item.get("port", 0)
            if not port and isinstance(addr, str) and addr.count(":") == 1:
                addr, port = addr.split(":")
            try:
                return str(addr), int(port or 0)
            except (TypeError, ValueError):
                return str(addr), 0
    try:
        return str(st.get("address", "")), int(st.get("port", 0) or 0)
    except (TypeError, ValueError):
        return str(st.get("address", "")), 0


def _referenced_tags(ob: dict) -> list[str]:
    tags = []
    so = (ob.get("streamSettings") or {}).get("sockopt") or {}
    if so.get("dialerProxy"):
        tags.append(so["dialerProxy"])
    ps = ob.get("proxySettings") or {}
    if ps.get("tag"):
        tags.append(ps["tag"])
    return tags


def servers_from_json(data) -> list[Server]:
    configs = data if isinstance(data, list) else [data]
    result: list[Server] = []
    for i, cfg in enumerate(configs, 1):
        if not isinstance(cfg, dict):
            continue
        outbounds = [o for o in cfg.get("outbounds", []) if isinstance(o, dict)]
        by_tag = {o.get("tag"): o for o in outbounds if o.get("tag")}
        proxies = [o for o in outbounds if o.get("protocol") in PROXY_PROTOCOLS]
        if not proxies:
            continue
        main = by_tag.get("proxy") if by_tag.get("proxy") in proxies else proxies[0]
        extras, queue, seen = [], list(_referenced_tags(main)), set()
        while queue:
            tag = queue.pop(0)
            if tag in seen or tag not in by_tag:
                continue
            seen.add(tag)
            extras.append(copy.deepcopy(by_tag[tag]))
            queue.extend(_referenced_tags(by_tag[tag]))
        addr, port = _outbound_endpoint(main)
        name = str(cfg.get("remarks") or "") or f"JSON-сервер {i}"
        protocol = str(main.get("protocol"))
        # JSON от провайдера уже написан для Xray, поэтому берём outbound как есть
        srv = Server(name=name, protocol=protocol, address=addr, port=port, outbound=copy.deepcopy(main),
                     extra_outbounds=extras, source="json")
        result.append(mark_flags(srv))
    return result
