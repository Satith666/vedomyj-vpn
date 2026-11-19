"""Загрузка и разбор подписки."""

from __future__ import annotations

import html
import json
import re
import time
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

from . import netutil
from .links import Server, parse_link, servers_from_json, try_b64_text

# Разные программы — разный формат ответа. Пробуем по очереди, пока не получим список серверов.
USER_AGENTS = ["v2rayN/7.13.8", "Happ/2.0.0", "v2rayNG/1.10.5", "Streisand/1.6.40", "v2rayTun/2.5"]

SERVER_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "socks://", "socks5://", "hy2://", "hysteria2://",
                  "tuic://", "anytls://", "wireguard://", "awg://", "vpn://", "xrayjson://")
LINK_RE = re.compile(r"(?:vless|vmess|trojan|ss|socks5?|hy2|hysteria2|tuic|anytls)://[^\s\"'<>`]+", re.IGNORECASE)


class SubscriptionError(RuntimeError):
    pass


@dataclass
class Subscription:
    servers: list[Server] = field(default_factory=list)
    title: str = ""
    upload: int | None = None
    download: int | None = None
    total: int | None = None
    expire: int | None = None
    provider_routing: str = ""
    fetched_at: float = 0.0
    raw: str = ""
    user_agent: str = ""
    route: str = ""
    warnings: list[str] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)  # сообщения провайдера вместо серверов

    def usage(self) -> dict:
        return {"upload": self.upload, "download": self.download, "total": self.total, "expire": self.expire}

    def usage_text(self) -> str:
        return usage_text(self.usage())


def usage_text(u: dict) -> str:
    parts = []
    if u.get("download") is not None or u.get("upload") is not None:
        used = (u.get("download") or 0) + (u.get("upload") or 0)
        parts.append(f"трафик: {human_bytes(used)} из {human_bytes(u['total'])}" if u.get("total")
                     else f"трафик: {human_bytes(used)}")
    if u.get("expire"):
        days = int((u["expire"] - time.time()) // 86400)
        parts.append(f"до {time.strftime('%d.%m.%Y', time.localtime(u['expire']))} (осталось {max(days, 0)} дн.)")
    return ", ".join(parts)


def human_bytes(n: float) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if abs(n) < 1024 or unit == "ТБ":
            return f"{n:.1f} {unit}" if unit != "Б" else f"{int(n)} {unit}"
        n /= 1024
    return f"{n:.1f} ТБ"


def _parse_userinfo(value: str, sub: Subscription) -> None:
    for part in value.split(";"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip().lower()
        try:
            num = int(float(v.strip()))
        except ValueError:
            continue
        if k in ("upload", "download", "total", "expire"):
            setattr(sub, k, num if (k != "expire" or num > 0) else None)


def _decode_title(value: str) -> str:
    value = value.strip()
    if value.lower().startswith("base64:"):
        return try_b64_text(value[7:]) or ""
    return value


# ---------- что вставил человек ----------

def looks_like_server_link(text: str) -> bool:
    return text.strip().lower().startswith(SERVER_SCHEMES)


def normalize_url(raw: str) -> str:
    """Достаёт адрес подписки из того, что вставил человек: обычная ссылка, happ://add/…, v2rayng://install-sub?url=…
    и прочие ссылки-приглашения."""
    s = raw.strip().strip("\"'<> \t\r\n")
    low = s.lower()
    if not s:
        raise SubscriptionError("Вставь ссылку на подписку.")
    if low.startswith("happ://crypt"):
        raise SubscriptionError(
            "Это зашифрованная ссылка Happ: открыть её может только сам Happ, другие программы её не прочитают. "
            "Попроси у провайдера обычную ссылку на подписку, которая начинается с https:// — обычно она есть в "
            "личном кабинете или в боте как «ссылка для других приложений» или «для v2rayN / v2RayTun».")
    if looks_like_server_link(s):
        raise SubscriptionError("Это ссылка на один сервер, а не на подписку. Добавь её кнопкой «Добавить сервер».")
    m = re.search(r"https?://[^\s\"'<>]+", s, re.IGNORECASE)
    if m:
        return m.group(0)
    m = re.search(r"https?%3a%2f%2f[^\s\"'<>&]+", s, re.IGNORECASE)
    if m:
        return unquote(m.group(0))
    tail = s.rsplit("/", 1)[-1].split("#", 1)[0].split("?", 1)[0]
    decoded = try_b64_text(tail) if len(tail) > 12 else None
    if decoded and decoded.strip().lower().startswith(("http://", "https://")):
        return decoded.strip()
    raise SubscriptionError("Не похоже на ссылку подписки: она должна начинаться с https:// "
                            "(или быть ссылкой-приглашением вроде happ://add/https://…).")


# ---------- разбор ответа ----------

def parse_body(text: str) -> Subscription:
    sub = Subscription()
    stripped = text.strip().lstrip("﻿")
    sub.raw = stripped
    if stripped[:1] in ("[", "{"):
        try:
            data = json.loads(stripped)
        except ValueError:
            data = None
        if data is not None:
            sub.servers = servers_from_json(data)
            return sub
    if "://" not in stripped:
        decoded = try_b64_text(stripped)
        if decoded is not None and decoded.strip():
            stripped = decoded.strip()
            sub.raw = stripped
            if stripped[:1] in ("[", "{"):
                try:
                    sub.servers = servers_from_json(json.loads(stripped))
                    return sub
                except ValueError:
                    pass
    for line in stripped.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("happ://routing/"):
            sub.provider_routing = line
            continue
        srv = parse_link(line)
        if srv:
            sub.servers.append(srv)
    if not sub.servers:
        # ссылки могут быть внутри HTML-страницы или текста с мусором
        seen = set()
        for match in LINK_RE.findall(html.unescape(stripped)):
            link = match.rstrip(".,;)")
            if link not in seen:
                seen.add(link)
                srv = parse_link(link)
                if srv:
                    sub.servers.append(srv)
    return sub


# признаки страницы-заглушки провайдера интернета («доступ ограничен по решению…»)
BLOCK_PAGE_MARKS = ("роскомнадзор", "rkn.gov.ru", "eais.rkn", "warning.rt.ru", "доступ ограничен", "доступ к ресурсу ограничен",
                    "ресурс заблокирован", "сайт заблокирован", "единый реестр", "blocked by", "blocklist")


def describe(text: str, sub: Subscription) -> str:
    """Короткое человеческое описание ответа, в котором не нашлось рабочих серверов."""
    t = text.strip().lstrip("﻿")
    low = t[:400].lower()
    if sub.servers:
        stubs = [s.name for s in sub.servers if s.stub]
        if stubs and len(stubs) == len(sub.servers):
            return "вместо серверов пришло сообщение провайдера: «" + "», «".join(stubs[:3]) + "»"
        if any(s.protocol == "happ" for s in sub.servers):
            return "ссылки на серверы зашифрованы только для Happ"
        if any(s.insecure for s in sub.servers):
            return "серверы без шифрования (без TLS/Reality)"
        protos = sorted({s.protocol for s in sub.servers})
        return "серверы есть, но не поддерживаются: " + ", ".join(protos)
    if not t:
        return "пустой ответ"
    if low.startswith(("<!doctype", "<html", "<")):
        page = t[:20000].lower()
        if any(m in page for m in BLOCK_PAGE_MARKS):
            return "провайдер интернета показал страницу блокировки"
        return "пришла веб-страница вместо списка серверов"
    if "proxies:" in low or "proxy-groups:" in low:
        return "формат Clash (YAML) — не подходит"
    if t[:1] in ("{", "[") and '"outbounds"' in t and '"type"' in t:
        return "формат sing-box — не подходит"
    if low.startswith("happ://crypt"):
        return "подписка зашифрована только для Happ"
    return "непонятный формат ответа"


def _route_list(proxy_port: int | None, own_http_port: int | None) -> list[tuple[str, object]]:
    routes: list[tuple[str, object]] = [("напрямую", None)]
    sys_proxy = netutil.system_proxy_url()
    if sys_proxy and not (own_http_port and f":{own_http_port}" in sys_proxy):
        routes.append(("через системный прокси", netutil.SYSTEM_PROXY))
    if proxy_port:
        routes.append(("через VPN", proxy_port))
    return routes


def device_headers(hwid: str) -> dict:
    """Заголовки устройства, как у Happ и v2RayTun: многие панели (Remnawave и др.) без них отдают заглушку
    или ошибку. Провайдер увидит программу как отдельное устройство «VedomyjVPN»."""
    import platform
    if not hwid:
        return {}
    return {"x-hwid": hwid, "x-device-os": "Windows" if platform.system() == "Windows" else platform.system(),
            "x-ver-os": platform.release() or "10", "x-device-model": "VedomyjVPN"}


def _hwid_note(headers: dict) -> str:
    if str(headers.get("x-hwid-max-devices-reached", "")).lower() == "true" or \
            str(headers.get("x-hwid-limit", "")).lower() == "true":
        return ("достигнут лимит устройств в подписке — удали лишнее устройство в боте или личном кабинете "
                "провайдера и обнови подписку")
    if str(headers.get("x-hwid-not-supported", "")).lower() == "true":
        return "провайдер требует идентификатор устройства"
    return ""


# заголовки, которые ставит панель подписки (Remnawave, Marzban, 3x-ui…): ответ точно от провайдера VPN
PROVIDER_HEADERS = ("subscription-userinfo", "profile-title", "profile-update-interval", "profile-web-page-url",
                    "support-url", "announce", "x-hwid-limit", "x-hwid-max-devices-reached", "x-hwid-not-supported")
ROUTE_DOH = "напрямую через защищённый DNS"
BLOCKED_HINT = ("Похоже, провайдер интернета блокирует адрес подписки. Если не поможет и VPN — попроси у провайдера VPN "
                "запасную ссылку (зеркало) и добавь её.")


def fetch(url: str, user_agent: str = "", proxy_port: int | None = None, own_http_port: int | None = None,
          timeout: float = 20.0, hwid: str = "", relay=None) -> Subscription:
    """Скачивает подписку, перебирая способы и User-Agent, пока не найдёт нормальные серверы.

    Способы по очереди: напрямую; если DNS провайдера не знает адрес — напрямую по адресу из защищённого DNS;
    системный прокси; через VPN; relay — через другие серверы (временное ядро): relay(attempt) вызывает
    attempt(название, порт) для каждого сервера и возвращает первую удачную подписку или None."""
    url = normalize_url(url)
    host = urlsplit(url).hostname or "сервер подписки"
    agents = [user_agent] if user_agent else []
    agents += [ua for ua in USER_AGENTS if ua not in agents]
    extra = device_headers(hwid)
    notes: list[str] = []
    state = {"best": None, "best_q": (-1, -1, -1), "answered": False, "dns_failed": False}

    def attempt(route_name: str, route, pin: dict | None = None, wait: float = timeout) -> Subscription | None:
        """Одна попытка одним способом (все User-Agent). Подписка с серверами — сразу результат."""
        for ua in agents:
            label = ua.split("/")[0]
            try:
                status, headers, body = netutil.http_get(url, proxy_port=route, timeout=wait, user_agent=ua,
                                                         headers=extra, pin=pin)
            except Exception as exc:
                if route is None and not pin and netutil.is_dns_error(exc):
                    state["dns_failed"] = True
                notes.append(f"{route_name}: {netutil.human_error(exc)}")
                return None  # сеть не пускает — другие User-Agent тут не помогут
            hw = _hwid_note(headers)
            provider = any(h in headers for h in PROVIDER_HEADERS)
            if status >= 400:
                # ответ с заголовками подписки — это сам провайдер; без них — может быть провайдер интернета
                # или запрет для страны: тогда пробуем другие пути
                state["answered"] = state["answered"] or provider
                notes.append(f"{route_name}, как {label}: сервер ответил кодом {status}" + (f" ({hw})" if hw else ""))
                continue
            text = body.decode("utf-8", "replace")
            sub = parse_body(text)
            # страница блокировки провайдера интернета или чужая страница — не ответ подписки, ищем дальше
            state["answered"] = state["answered"] or provider or bool(sub.servers)
            if headers.get("subscription-userinfo"):
                _parse_userinfo(headers["subscription-userinfo"], sub)
            if headers.get("profile-title"):
                sub.title = _decode_title(headers["profile-title"])
            if headers.get("routing", "").lower().startswith("happ://routing/"):
                sub.provider_routing = headers["routing"]
            sub.fetched_at = time.time()
            sub.user_agent = ua
            sub.route = route_name
            sub.notices = [s.name for s in sub.servers if s.stub]
            if hw:
                sub.warnings.append("Провайдер: " + hw + ".")
            good = sum(1 for s in sub.servers if s.supported and not s.insecure)
            usable = sum(1 for s in sub.servers if s.supported)
            if good:
                return sub
            notes.append(f"{route_name}, как {label}: {describe(text, sub)}" + (f" ({hw})" if hw else ""))
            q = (good, usable, len(sub.servers))
            if q > state["best_q"]:
                state["best"], state["best_q"] = sub, q
        return None

    doh_ips: list[str] = []
    for route_name, route in _route_list(proxy_port, own_http_port):
        sub = attempt(route_name, route)
        if sub:
            return sub
        if route is None and state["dns_failed"] and not state["answered"]:
            # DNS провайдера не знает адрес (часто так блокируют) — спрашиваем защищённый DNS и идём по адресу
            doh_ips = netutil.doh_resolve(host)
            if doh_ips:
                sub = attempt(ROUTE_DOH, None, pin={host: doh_ips[0]}, wait=min(timeout, 12.0))
                if sub:
                    return sub
            else:
                notes.append("защищённый DNS: адрес тоже не найден")
        if state["answered"]:
            break  # сервер подписки отвечает — другой путь ответ не изменит
    if not state["answered"] and relay is not None:
        sub = relay(lambda name, port: attempt(name, port, wait=min(timeout, 15.0)))
        if sub:
            return sub
    best, best_q = state["best"], state["best_q"]
    if best is not None and best_q[1] > 0:
        best.warnings.append("В подписке только серверы без шифрования. Для них программа использует "
                             "совместимую версию ядра Xray.")
        return best
    if best is not None and best.servers:
        best.warnings.append("В подписке нет серверов, которые поддерживает программа: " + describe(best.raw, best) + ".")
        return best
    unique = list(dict.fromkeys(notes))
    text = f"Не удалось получить серверы с {host}.\n" + "\n".join("• " + n for n in unique[:8])
    blocked = (state["dns_failed"] and doh_ips) or any("страницу блокировки" in n for n in unique)
    if blocked and not state["answered"]:
        text += "\n" + BLOCKED_HINT
    raise SubscriptionError(text)
