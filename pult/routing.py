"""Правила маршрутизации: что идёт через VPN, что напрямую, что блокируется."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

MODES = {
    "vpn": "Всё через VPN (российские сайты — напрямую)",
    "smart": "Экономный: через VPN только заблокированное",
}

# Адреса домашней сети с именами (страница роутера и т.п.): всегда напрямую. В режиме «всё через VPN» ядро
# не узнаёт адреса сайтов заранее (так быстрее и DNS провайдера ничего не видит), поэтому такие имена — списком.
LAN_DOMAINS = [
    "domain:local", "domain:lan", "domain:home.arpa", "domain:internal", "domain:localdomain", "domain:box",
    "full:my.keenetic.net", "full:router.asus.com", "domain:tplinkwifi.net", "domain:tplinklogin.net",
    "domain:routerlogin.net", "full:miwifi.com", "domain:mywifiext.net", "full:speedport.ip",
]

PRIVATE_IPS = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "100.64.0.0/10", "224.0.0.0/4", "255.255.255.255/32", "::1/128", "fc00::/7", "fe80::/10",
]

# Российские сайты: работают только напрямую (многие блокируют зарубежные IP).
RU_DIRECT_DOMAINS = [
    # российские доменные зоны: .ru, .su, .рф, .дети, .москва, .moscow, .tatar
    "domain:ru", "domain:su", "domain:xn--p1ai", "domain:xn--d1acj3b", "domain:xn--80adxhks",
    "domain:moscow", "domain:tatar",
    # российские сервисы на других доменах
    "domain:yandex.net", "domain:yandex.com", "domain:yastatic.net", "domain:yandexcloud.net",
    "domain:vk.com", "domain:vk.me", "domain:vk.link", "domain:vkuser.net", "domain:userapi.com",
    "domain:vk-cdn.net", "domain:vkuseraudio.net", "domain:vkuservideo.net", "domain:mycdn.me",
    "domain:mradx.net", "domain:sberbank.com", "domain:ozonusercontent.com", "domain:wbstatic.net",
    "domain:wbbasket.ru", "domain:avito.st", "domain:2gis.com", "domain:max.im",
]

# Популярные сервисы, заблокированные или ограниченные в России.
# Работает даже без списков runetfreedom; дополняется своими правилами на вкладке «Маршрутизация».
BUILTIN_PROXY_DOMAINS = [
    # YouTube
    "domain:youtube.com", "domain:youtu.be", "domain:googlevideo.com", "domain:ytimg.com", "domain:ggpht.com",
    "domain:youtube-nocookie.com", "domain:youtubei.googleapis.com", "domain:yt.be",
    # Discord
    "domain:discord.com", "domain:discord.gg", "domain:discordapp.com", "domain:discordapp.net",
    "domain:discord.media", "domain:discordcdn.com", "domain:discord.dev", "domain:discord.gift",
    "domain:discordstatus.com", "domain:dis.gd",
    # Telegram
    "domain:telegram.org", "domain:t.me", "domain:telegram.me", "domain:telesco.pe", "domain:tdesktop.com",
    "domain:telegra.ph", "domain:telegram-cdn.org",
    # Meta, WhatsApp
    "domain:instagram.com", "domain:cdninstagram.com", "domain:facebook.com", "domain:fbcdn.net", "domain:fb.com",
    "domain:facebook.net", "domain:whatsapp.com", "domain:whatsapp.net", "domain:wa.me", "domain:threads.net",
    "domain:threads.com",
    # X / Twitter
    "domain:x.com", "domain:twitter.com", "domain:twimg.com", "domain:t.co",
    # ИИ-сервисы (блокируют российские IP)
    "domain:openai.com", "domain:chatgpt.com", "domain:oaistatic.com", "domain:oaiusercontent.com",
    "domain:claude.ai", "domain:claude.com", "domain:anthropic.com", "domain:gemini.google.com",
    "domain:aistudio.google.com", "domain:generativelanguage.googleapis.com", "domain:perplexity.ai",
    "domain:grok.com", "domain:x.ai", "domain:copilot.microsoft.com",
    # прочее
    "domain:linkedin.com", "domain:licdn.com", "domain:medium.com", "domain:soundcloud.com", "domain:sndcdn.com",
    "domain:spotify.com", "domain:scdn.co", "domain:spotifycdn.com", "domain:patreon.com", "domain:notion.so",
    "domain:canva.com", "domain:netflix.com", "domain:nflxvideo.net", "domain:signal.org", "domain:proton.me",
    "domain:protonmail.com", "domain:torproject.org", "domain:rutracker.org", "domain:viber.com",
    "domain:speedtest.net", "domain:ookla.com", "domain:roblox.com", "domain:rbxcdn.com", "domain:snapchat.com",
    "domain:twitch.tv", "domain:ttvnw.net", "domain:jtvnw.net",
]

# Сети Telegram (приложение часто подключается напрямую по IP)
BUILTIN_PROXY_IPS = [
    "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.20.0/22", "91.108.56.0/22",
    "91.105.192.0/23", "95.161.64.0/20", "149.154.160.0/20", "185.76.151.0/24",
    "2001:67c:4e8::/48", "2001:b28:f23c::/47", "2001:b28:f23f::/48", "2a0a:f280::/32",
]

GEO_PROXY_DOMAINS = ["geosite:ru-blocked"]
GEO_PROXY_IPS = ["geoip:ru-blocked"]
GEO_INSIDE_ONLY = ["geosite:ru-available-only-inside"]
GEO_RU_IPS = ["geoip:ru"]

DOMAIN_PREFIXES = ("domain:", "full:", "regexp:", "keyword:", "geosite:", "ext:", "dotless:")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def normalize_entry(raw: str) -> tuple[str, str] | None:
    """Строка из пользовательского списка → ("domain"|"ip", значение для Xray). None — пусто или комментарий."""
    s = raw.strip()
    if not s or s.startswith("#"):
        return None
    if "#" in s:
        s = s.split("#", 1)[0].strip()
    low = s.lower()
    if low.startswith("geoip:"):
        return "ip", low
    if low.startswith(DOMAIN_PREFIXES):
        return "domain", s if low.startswith("regexp:") else low
    if "://" in s:
        s = urlsplit(s).hostname or ""
    s = s.strip().strip("/").lower()
    if s.startswith("*."):
        s = s[2:]
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    if _is_ip(s):
        return "ip", s
    if s.startswith("www."):
        s = s[4:]
    if not s or " " in s or "." not in s and not s.isalnum():
        raise ValueError(raw.strip())
    try:
        s = s.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(raw.strip()) from exc
    return "domain", f"domain:{s}"


def split_entries(text_or_list) -> tuple[list[str], list[str], list[str]]:
    """Разбор пользовательского списка. Возвращает (домены, IP, нераспознанные строки)."""
    lines = text_or_list.splitlines() if isinstance(text_or_list, str) else list(text_or_list)
    domains, ips, bad = [], [], []
    for line in lines:
        try:
            item = normalize_entry(line)
        except ValueError:
            bad.append(line.strip())
            continue
        if item is None:
            continue
        kind, value = item
        target = domains if kind == "domain" else ips
        if value not in target:
            target.append(value)
    return domains, ips, bad


def site_entry(host: str) -> str:
    """Хост из журнала соединений → строка для списка (основной домен или IP)."""
    host = host.strip().strip("[]").lower()
    if _is_ip(host):
        return host
    labels = [x for x in host.split(".") if x]
    if len(labels) <= 2:
        return ".".join(labels)
    second = labels[-2]
    if len(labels[-1]) == 2 and second in ("co", "com", "net", "org", "gov", "edu", "ac", "msk", "spb"):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _entry_matches(entry: str, host: str) -> bool:
    host = host.lower().strip(".").strip("[]")
    if entry.startswith("domain:"):
        d = entry[7:]
        return host == d or host.endswith("." + d)
    if entry.startswith("full:"):
        return host == entry[5:]
    if entry.startswith("keyword:"):
        return entry[8:] in host
    if _is_ip(host) and _is_ip(entry):
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return False
    return False


USER_LISTS = (("block_list", "block"), ("direct_list", "direct"), ("proxy_list", "proxy"))


def user_rule(host: str, settings: dict) -> str:
    """Какое своё правило действует на сайт: "proxy" / "direct" / "block" или ""."""
    for key, tag in USER_LISTS:
        for line in (settings.get(key) or "").splitlines():
            try:
                item = normalize_entry(line)
            except ValueError:
                continue
            if item and _entry_matches(item[1], host):
                return tag
    return ""


def remove_host(text: str, host: str) -> tuple[str, list[str]]:
    """Убирает из списка строки, которые задевают этот сайт. Возвращает (новый текст, убранные строки)."""
    kept, removed = [], []
    for line in (text or "").splitlines():
        try:
            item = normalize_entry(line)
        except ValueError:
            item = None
        if item and _entry_matches(item[1], host):
            removed.append(line.strip())
        else:
            kept.append(line)
    return "\n".join(kept).strip("\n"), removed


def default_outbound(mode: str) -> str:
    return "proxy" if mode == "vpn" else "direct"


def domain_strategy(mode: str) -> str:
    """Как ядро сверяет сайты с правилами по IP. «Всё через VPN»: только по имени (AsIs) — ядро не спрашивает
    DNS провайдера про каждый сайт: быстрее, провайдер не видит имён, а подменённый им адрес (заглушка
    с российским IP) не уводит заблокированный сайт «напрямую». Экономный режим: заблокированное узнаётся и по IP."""
    return "AsIs" if mode == "vpn" else "IPIfNonMatch"


ADS_RULE = "ext:adblock.dat:ads"  # = adblock.RULE (файл собирает pult/adblock.py)


def is_ip_entry(value: str) -> bool:
    """Запись — IP-адрес или подсеть (а не домен)."""
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def build_rules(mode: str, user_proxy: str, user_direct: str, user_block: str, ru_direct: bool = True,
                use_geo: bool = False, geo_ru_ip: bool = True, dpi: dict | None = None,
                block_ads: bool | str = False, multi: list[dict] | None = None,
                routes: list[dict] | None = None, torrent: str = "", block_quic: bool = False) -> list[dict]:
    """Правила Xray. Порядок важен: первое совпадение побеждает.
    Если ни одно правило не подошло, трафик уходит в первый outbound — его выбирает default_outbound().
    block_quic — в режиме TUN: QUIC (UDP 443) мимо российских сайтов блокируется, браузер и YouTube сразу
    переходят на обычное соединение. Через VPN QUIC едет внутри TCP и работает заметно хуже (лаги видео)."""
    rules: list[dict] = []

    def add(domains: list[str], ips: list[str], tag: str):
        if domains:
            rules.append({"type": "field", "domain": list(domains), "outboundTag": tag})
        if ips:
            rules.append({"type": "field", "ip": list(ips), "outboundTag": tag})

    add(LAN_DOMAINS, PRIVATE_IPS, "direct")
    if block_quic:
        if ru_direct:  # российские сайты идут напрямую — им QUIC не мешает
            rules.append({"type": "field", "network": "udp", "port": "443",
                          "domain": RU_DIRECT_DOMAINS + (GEO_INSIDE_ONLY if use_geo else []), "outboundTag": "direct"})
        rules.append({"type": "field", "network": "udp", "port": "443", "outboundTag": "block"})
    # торренты (ядро узнаёт протокол BitTorrent): напрямую или блок — многие VPN-сервисы блокируют за них
    if torrent in ("direct", "block"):
        rules.append({"type": "field", "protocol": ["bittorrent"], "outboundTag": torrent})

    def add_routes(items: list[dict]):
        for r in items:
            if r.get("process"):  # приложение: правило по процессу
                rules.append({"type": "field", "process": list(r["process"]), "outboundTag": r["tag"]})
                continue
            if "block_udp" in r:
                # через свой прокси UDP не ходит или ходит плохо: QUIC (UDP 443) блокируем — приложения сразу на TCP
                udp = {"type": "field", "network": "udp", "outboundTag": "block"}
                if r["block_udp"]:
                    udp["port"] = r["block_udp"]
                if r.get("domains"):
                    rules.append(dict(udp, domain=list(r["domains"])))
                if r.get("ips"):
                    rules.append(dict(udp, ip=list(r["ips"])))
            add(r.get("domains") or [], r.get("ips") or [], r["tag"])

    # свои маршруты сайтов (выбор на странице «Свои правила») — раньше всего остального
    add_routes([r for r in routes or [] if r.get("early") and not r.get("auto") and not r.get("app")])
    for text, tag in ((user_block, "block"), (user_direct, "direct"), (user_proxy, "proxy")):
        d, i, _ = split_entries(text)
        add(d, i, tag)
    # свои маршруты сервисов: выбранный сервер, свой прокси, обход замедления
    add_routes([r for r in routes or [] if not r.get("early") and not r.get("auto") and not r.get("app")])
    # реклама, всплывающие окна, трекеры и опасные сайты — в «чёрную дыру» (свои правила выше и важнее).
    # "dat" — свои списки (adblock.dat), True/"geo" — запасной список рекламы из файлов runetfreedom
    if block_ads == "dat":
        add([ADS_RULE], [], "adblock")
    elif block_ads and use_geo:
        add(["geosite:category-ads-all"], [], "adblock")
    # приложения (Discord, игры, торрент-клиенты): после рекламы — реклама в них тоже блокируется,
    # и раньше автоматики — выбор человека для приложения главнее
    add_routes([r for r in routes or [] if r.get("app")])
    # автоподбор: сайты, которые программа сама проверила и увела в VPN или на другой сервер.
    # Ниже своих правил и рекламы (реклама не уходит в VPN мимо блокировщика), выше встроенных списков
    add_routes([r for r in routes or [] if r.get("auto")])
    # обход замедлений: YouTube и Discord идут напрямую (их чинит zapret) или через ByeDPI, а не через VPN.
    # В «Глобальной» маршрутизации всё идёт через VPN — там обход не используется.
    if dpi and mode != "vpn" and dpi.get("domains"):
        add([f"domain:{d}" for d in dpi["domains"]], [], "byedpi" if dpi.get("mode") == "byedpi" else "direct")
    # Мультисервер: сервисы, которые не открываются через основной сервер, — через свой сервер
    for m in multi or []:
        add([f"domain:{d}" for d in m["domains"]], [], m["tag"])
    if use_geo:
        add(GEO_INSIDE_ONLY, [], "direct")
        add(GEO_PROXY_DOMAINS, GEO_PROXY_IPS, "proxy")
    add(BUILTIN_PROXY_DOMAINS, BUILTIN_PROXY_IPS, "proxy")
    if ru_direct:
        add(RU_DIRECT_DOMAINS, GEO_RU_IPS if (use_geo and geo_ru_ip) else [], "direct")
    return rules


def route_for_host(host: str, mode: str, user_proxy: str, user_direct: str, user_block: str,
                   ru_direct: bool = True) -> str:
    """Примерная оценка, куда пойдёт сайт (без гео-файлов). Нужна для подсказок в интерфейсе."""
    host = host.lower().strip(".")

    def match(entries: list[str]) -> bool:
        for e in entries:
            if e.startswith("domain:"):
                d = e[7:]
                if host == d or host.endswith("." + d):
                    return True
            elif e.startswith("full:") and host == e[5:]:
                return True
            elif e.startswith("keyword:") and e[8:] in host:
                return True
        return False

    for text, tag in ((user_block, "block"), (user_direct, "direct"), (user_proxy, "proxy")):
        if match(split_entries(text)[0]):
            return tag
    if match(BUILTIN_PROXY_DOMAINS):
        return "proxy"
    if ru_direct and match(RU_DIRECT_DOMAINS):
        return "direct"
    return default_outbound(mode)
