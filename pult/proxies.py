"""Свои прокси (SOCKS5 и HTTP) для отдельных сервисов и сайтов — например, резидентный прокси для TikTok.

Логин и пароль прокси — секрет: в журнал, отчёты, интерфейс и файл переноса настроек они не попадают.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlsplit

TYPES = ("socks", "http")
SCHEMES = {"socks": "socks", "socks5": "socks", "socks5h": "socks", "http": "http", "https": "http"}
MAX = 30

_HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9_]([a-z0-9_-]{0,62}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,62}[a-z0-9_])?)*$")


class ProxyError(ValueError):
    pass


def _host(value: str) -> str:
    h = (value or "").strip().strip("[]").lower()
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        pass
    if not _HOST_RE.match(h) or "." not in h:
        raise ProxyError("Не похоже на адрес прокси. Пример: socks5://логин:пароль@1.2.3.4:1080")
    return h


def _port(value) -> int:
    try:
        port = int(str(value).strip())
    except ValueError:
        port = 0
    if not 1 <= port <= 65535:
        raise ProxyError("Порт прокси — число от 1 до 65535.")
    return port


def _split_plain(s: str) -> tuple[str, str, str, str]:
    """Без схемы: user:pass@host:port, host:port:user:pass, user:pass:host:port, host:port."""
    if "@" in s:
        cred, _, hp = s.rpartition("@")
        user, _, pw = cred.partition(":")
        if hp.startswith("["):
            host, _, port = hp[1:].partition("]:")
        else:
            host, _, port = hp.rpartition(":")
        return host, port, user, pw
    if s.startswith("["):  # [IPv6]:port
        host, _, rest = s[1:].partition("]:")
        port, _, cred = rest.partition(":")
        user, _, pw = cred.partition(":")
        return host, port, user, pw
    parts = s.split(":")
    if len(parts) == 2:
        return parts[0], parts[1], "", ""
    if len(parts) >= 4:
        if parts[1].isdigit():  # host:port:user:pass (пароль может содержать «:»)
            return parts[0], parts[1], parts[2], ":".join(parts[3:])
        if parts[-1].isdigit() and len(parts) == 4:  # user:pass:host:port
            return parts[2], parts[3], parts[0], parts[1]
    raise ProxyError("Не понял формат прокси. Подходит: socks5://логин:пароль@адрес:порт, "
                     "http://логин:пароль@адрес:порт или адрес:порт:логин:пароль.")


def parse(raw: str, kind: str = "auto") -> dict:
    """Строка от продавца прокси → {"type", "tls", "host", "port", "user", "pass", "type_known"}.
    kind — тип, выбранный в списке (auto — по схеме ссылки; без схемы сначала пробуется SOCKS5)."""
    s = (raw or "").strip()
    if not s:
        raise ProxyError("Вставь адрес прокси, например socks5://логин:пароль@1.2.3.4:1080.")
    if len(s) > 600 or re.search(r"[\s\x00-\x1f]", s):
        raise ProxyError("В адресе прокси не должно быть пробелов и переносов строк.")
    typ, tls = "", False
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://", s)
    if m:
        scheme = m.group(1).lower()
        if scheme not in SCHEMES:
            if scheme in ("vless", "vmess", "trojan", "ss", "hy2", "hysteria2", "tuic", "anytls", "awg", "vpn"):
                raise ProxyError("Это ссылка на VPN-сервер, а не прокси. Добавь её на вкладке «Серверы» — "
                                 "потом её можно выбрать в списке «Через сервер».")
            raise ProxyError("Поддерживаются прокси SOCKS5 и HTTP.")
        typ, tls = SCHEMES[scheme], scheme == "https"
        rest = s[m.end():].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in rest or rest.startswith("[") or rest.count(":") <= 1:
            u = urlsplit(f"{scheme}://{rest}")
            try:
                port = u.port
            except ValueError as exc:
                raise ProxyError("Порт прокси — число от 1 до 65535.") from exc
            host, user, pw = u.hostname or "", unquote(u.username or ""), unquote(u.password or "")
        else:  # socks5://host:port:user:pass — так тоже иногда выдают
            host, port, user, pw = _split_plain(rest)
    else:
        host, port, user, pw = _split_plain(s)
    if port in (None, ""):
        raise ProxyError("В адресе прокси нет порта. Пример: 1.2.3.4:1080.")
    if len(user) > 200 or len(pw) > 200:
        raise ProxyError("Слишком длинный логин или пароль.")
    known = bool(typ) or kind in TYPES
    if not typ:
        typ = kind if kind in TYPES else "socks"
    return {"type": typ, "tls": tls, "host": _host(host), "port": _port(port), "user": user, "pass": pw,
            "type_known": known}


def label(p: dict) -> str:
    """Короткая подпись без логина и пароля: «SOCKS5 1.2.3.4:1080»."""
    kind = "HTTPS" if p.get("tls") else ("HTTP" if p.get("type") == "http" else "SOCKS5")
    host = f"[{p['host']}]" if ":" in p.get("host", "") else p.get("host", "")
    return f"{kind} {host}:{p.get('port', '')}"


def public(p: dict) -> dict:
    """Что можно показать в интерфейсе: без логина и пароля."""
    return {"id": p["id"], "name": p.get("name", ""), "label": label(p), "type": p.get("type", "socks"),
            "auth": bool(p.get("user")), "chain": bool(p.get("chain", True)), "check": dict(p.get("check") or {})}
