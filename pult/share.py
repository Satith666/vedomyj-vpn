"""Перенос настроек на другой компьютер: файл настроек.

В файл попадают только безопасные и переносимые настройки. Ключ устройства (HWID), порты, доступ из сети,
автозапуск и подобранные под конкретную сеть результаты не переносятся. Ссылки на подписки и свои серверы —
только по отдельной галочке: по ним любой сможет пользоваться VPN.

Чужой файл — недоверенные данные: каждое значение проверяется, неизвестное и неверное пропускается.
"""

from __future__ import annotations

import re
import time

from . import APP_VERSION

FORMAT = "pult-vpn-settings"
MAX_SUBS = 20
MAX_SERVERS = 100


def _bool(v):
    if isinstance(v, bool):
        return v
    raise ValueError


def _choice(*options):
    def check(v):
        if v in options:
            return v
        raise ValueError
    return check


def _hours(v):
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not 0 <= v <= 24 * 90:
        raise ValueError
    return float(v)


def _text(limit: int):
    def check(v):
        if isinstance(v, str) and len(v) <= limit and "\x00" not in v:
            return v
        raise ValueError
    return check


def _host(v):
    if isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9.\-]{1,253}(:\d{1,5})?", v):
        return v
    raise ValueError


def _path(v):
    if isinstance(v, str) and v.startswith("/") and len(v) <= 300 and re.fullmatch(r"[\x21-\x7e]+", v):
        return v
    raise ValueError


def _ads_lists(v):
    if not isinstance(v, dict):
        raise ValueError
    return {k: bool(v[k]) for k in ("popups", "threats", "ru", "telemetry") if k in v and isinstance(v[k], bool)}


def _strategy_name(v):
    if v == "" or (isinstance(v, str) and len(v) <= 120 and re.fullmatch(r"[\w .()+\-]+", v)):
        return v
    raise ValueError


def _byedpi_args(v):
    if v == "" or (isinstance(v, str) and len(v) <= 400 and v.startswith("-")
                   and not re.search(r'[\x00-\x1f"&|<>^%]', v)):
        return " ".join(v.split())
    raise ValueError


FIELDS = {
    "mode": _choice("smart", "vpn"),
    "ru_direct": _bool,
    "block_quic": _bool,
    "proxy_list": _text(200_000),
    "direct_list": _text(200_000),
    "block_list": _text(200_000),
    "system_proxy": _bool,
    "autopilot": _bool,
    "game_mode": _bool,
    "auto_connect_on_start": _bool,
    "auto_update_hours": _hours,
    "geo_update_hours": _hours,
    "core_update_hours": _hours,
    "dpi_update_hours": _hours,
    "zapret_enabled": _bool,
    "zapret_strategy": _strategy_name,
    "byedpi_role": _choice("main", "backup", "off"),
    "byedpi_strategy": _byedpi_args,
    "byedpi_custom": _byedpi_args,
    "dpi_youtube": _bool,
    "dpi_discord": _bool,
    "dpi_custom": _text(20_000),
    "tun_enabled": _bool,
    "tun_engine": _choice("auto", "xray", "singbox", "tun2proxy"),
    "leak_protection": _bool,
    "dns_encrypted": _bool,
    "block_ads": _bool,
    "ads_level": _choice("light", "normal", "pro", "pro_plus"),
    "ads_lists": _ads_lists,
    "ads_custom": _text(200_000),
    "ads_allow": _text(200_000),
    "ads_without_vpn": _bool,
    "mask_auto": _bool,
    "multi_enabled": _bool,
    "auto_routes": _bool,
    "auto_stall": _bool,
    "ads_ask_sites": _bool,
    "torrent_route": _choice("direct", "proxy", "block"),
    "failover": _bool,
    "sub_alerts": _bool,
    "hotkey_enabled": _bool,
    "whitelist_auto": _bool,
    "background": _bool,
    "lan_auth": _bool,
    "ping_host": _host,
    "ping_path": _path,
    "user_agent": _text(200),
}


def export(settings: dict, with_subs: bool = False, with_servers: bool = False) -> dict:
    data = {
        "format": FORMAT, "version": 1, "app": APP_VERSION, "created": time.strftime("%Y-%m-%d %H:%M"),
        "settings": {k: settings[k] for k in FIELDS if k in settings},
    }
    if with_subs:
        data["subscriptions"] = [{"name": m.get("name", ""), "url": m["url"]} for m in settings.get("subscriptions", [])]
    if with_servers:
        data["servers"] = list(settings.get("manual_links", []))
    return data


def parse(data) -> dict:
    """Проверяет чужой файл. Возвращает {settings, subscriptions, servers, skipped}. Ничего не меняет."""
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise ValueError("Это не файл настроек VEDOMYJ VPN.")
    raw = data.get("settings")
    raw = raw if isinstance(raw, dict) else {}
    settings, skipped = {}, []
    for key, value in raw.items():
        check = FIELDS.get(key)
        if not check:
            skipped.append(str(key)[:40])
            continue
        try:
            settings[key] = check(value)
        except (ValueError, TypeError):
            skipped.append(key)
    subs = []
    for item in (data.get("subscriptions") or [])[:MAX_SUBS] if isinstance(data.get("subscriptions"), list) else []:
        url = item.get("url") if isinstance(item, dict) else None
        name = item.get("name") if isinstance(item, dict) else ""
        if isinstance(url, str) and len(url) <= 4000 and re.match(r"(https?|happ)://", url, re.I) \
                and not url.lower().startswith("happ://crypt"):
            subs.append({"url": url.strip(), "name": name.strip()[:80] if isinstance(name, str) else ""})
        else:
            skipped.append("subscription")
    servers = []
    for link in (data.get("servers") or [])[:MAX_SERVERS] if isinstance(data.get("servers"), list) else []:
        if isinstance(link, str) and "://" in link and len(link) <= 8000 and "\n" not in link.strip():
            servers.append(link.strip())
        else:
            skipped.append("server")
    return {"settings": settings, "subscriptions": subs, "servers": servers, "skipped": skipped}
