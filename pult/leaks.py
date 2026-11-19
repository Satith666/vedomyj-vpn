"""Проверка утечек: видят ли сайты настоящий IP, через кого идут запросы DNS, не уходит ли WebRTC/UDP
и IPv6 мимо VPN. Только стандартная библиотека."""

from __future__ import annotations

import json
import os
import socket
import struct

from . import netutil

STUN = ("stun.l.google.com", 19302)
IPAPI = "http://ip-api.com/json/?fields=status,countryCode,isp,query"  # у бесплатной версии только http
EDNS = "http://edns.ip-api.com/json"
IPV6 = "https://api6.ipify.org"


def stun_mapped(server: tuple[str, int] = STUN, timeout: float = 4.0) -> str:
    """Какой адрес видит сервер STUN (так же WebRTC в браузере узнаёт адрес). '' — UDP не прошёл."""
    tid = os.urandom(12)
    req = struct.pack("!HHI", 0x0001, 0, 0x2112A442) + tid  # Binding Request, magic cookie
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(req, (socket.gethostbyname(server[0]), server[1]))
            data, _ = s.recvfrom(2048)
    except OSError:
        return ""
    if len(data) < 20 or data[8:20] != tid:
        return ""
    i = 20
    while i + 4 <= len(data):
        atype, alen = struct.unpack("!HH", data[i:i + 4])
        val = data[i + 4:i + 4 + alen]
        if atype in (0x0020, 0x0001) and len(val) >= 8 and val[1] == 0x01:  # XOR-MAPPED / MAPPED, IPv4
            raw = struct.unpack("!I", val[4:8])[0]
            if atype == 0x0020:
                raw ^= 0x2112A442
            return socket.inet_ntoa(struct.pack("!I", raw))
        i += 4 + alen + ((4 - alen % 4) % 4)
    return ""


def _json(url: str, proxy_port: int | None) -> dict:
    status, _, body = netutil.http_get(url, proxy_port=proxy_port, timeout=10, max_bytes=65536)
    if status != 200:
        raise IOError(f"код {status}")
    return json.loads(body.decode("utf-8", "replace") or "{}")


def ip_info(proxy_port: int | None) -> dict:
    """{"ip", "isp", "country"} — как видят нас сайты по этому пути."""
    d = _json(IPAPI, proxy_port)
    return {"ip": d.get("query", ""), "isp": d.get("isp", ""), "country": d.get("countryCode", "")}


def dns_info(proxy_port: int | None) -> dict:
    """Через какой DNS-сервер узнаются адреса: {"ip", "geo"} (geo — «Страна - Компания»)."""
    d = _json(EDNS, proxy_port).get("dns") or {}
    return {"ip": d.get("ip", ""), "geo": d.get("geo", "")}


def ipv6_address() -> str:
    try:
        status, _, body = netutil.http_get(IPV6, timeout=6, max_bytes=256)
        return body.decode().strip() if status == 200 and ":" in body.decode(errors="replace") else ""
    except Exception:
        return ""


def same_isp(isp: str, geo: str) -> bool:
    """Похоже ли, что DNS — от того же провайдера (сравниваем значимые слова названия)."""
    words = {w.lower().strip(".,") for w in (isp or "").split() if len(w) > 3}
    words -= {"limited", "company", "llc", "ltd.", "ojsc", "pjsc", "network", "networks", "telecom", "communications"}
    g = (geo or "").lower()
    return bool(words) and any(w in g for w in words)
