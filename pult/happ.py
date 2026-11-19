"""Выгрузка настроек в Happ через официальный формат профиля маршрутизации (happ://routing/onadd/...)."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time

from . import routing
from .xray import GEO_FILES

PROFILE_NAME = "VEDOMYJ VPN"


def build_profile(settings: dict) -> dict:
    mode = settings.get("mode", "smart")
    p_dom, p_ip, _ = routing.split_entries(settings.get("proxy_list", ""))
    d_dom, d_ip, _ = routing.split_entries(settings.get("direct_list", ""))
    b_dom, b_ip, _ = routing.split_entries(settings.get("block_list", ""))

    direct_sites = d_dom + routing.GEO_INSIDE_ONLY
    if settings.get("ru_direct", True):
        direct_sites += routing.RU_DIRECT_DOMAINS
    proxy_sites = p_dom + routing.GEO_PROXY_DOMAINS + routing.BUILTIN_PROXY_DOMAINS
    proxy_ips = p_ip + routing.GEO_PROXY_IPS + routing.BUILTIN_PROXY_IPS

    return {
        "Name": PROFILE_NAME,
        "GlobalProxy": "true" if mode == "vpn" else "false",
        "RemoteDNSType": "DoH",
        "RemoteDNSDomain": "https://cloudflare-dns.com/dns-query",
        "RemoteDNSIP": "1.1.1.1",
        "DomesticDNSType": "DoU",
        "DomesticDNSDomain": "",
        "DomesticDNSIP": "77.88.8.8",
        "Geoipurl": GEO_FILES["geoip.dat"],
        "Geositeurl": GEO_FILES["geosite.dat"],
        "LastUpdated": str(int(time.time())),
        "DnsHosts": {"cloudflare-dns.com": "1.1.1.1"},
        "DirectSites": _dedupe(direct_sites),
        "DirectIp": _dedupe(d_ip + routing.PRIVATE_IPS),
        "ProxySites": _dedupe(proxy_sites),
        "ProxyIp": _dedupe(proxy_ips),
        "BlockSites": _dedupe(b_dom),
        "BlockIp": _dedupe(b_ip),
        "DomainStrategy": "IPIfNonMatch",
        "FakeDNS": "false",
    }


def _dedupe(items: list[str]) -> list[str]:
    seen, out = set(), []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def profile_link(settings: dict, activate: bool = True) -> str:
    data = json.dumps(build_profile(settings), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    action = "onadd" if activate else "add"
    return f"happ://routing/{action}/" + base64.b64encode(data).decode("ascii")


def open_link(link: str) -> None:
    """Открывает happ://-ссылку: если Happ установлен, он сам примет профиль."""
    if sys.platform == "win32":
        os.startfile(link)  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", link])
    else:
        subprocess.Popen(["xdg-open", link])
