"""Блокировка рекламы: списки фильтров, свои сайты, исключения и сборка файла для ядра.

Списки скачиваются в data/adblock/, собираются в один файл bin/adblock.dat (формат geosite, как у списков
runetfreedom) и подключаются правилом «ext:adblock.dat:ads». Так ядро держит сотни тысяч адресов
без замедления, а конфиг остаётся маленьким.

Блокировка идёт по адресам сайтов (как у AdGuard DNS и Blokada): реклама, которая приходит с того же
адреса, что и сам сайт (YouTube, VK Видео), так не убирается — для неё нужно расширение в браузере.
"""

from __future__ import annotations

import os
import re
import time

from . import netutil

TAG = "ads"
DAT = "adblock.dat"
RULE = f"ext:{DAT}:{TAG}"
OUTBOUND = "adblock"  # отдельный «чёрный ящик» — чтобы в журнале отличать рекламу от своих блокировок

_HAGEZI = ("https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/{}-onlydomains.txt",
           "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/{}-onlydomains.txt")
_ADGUARD_RU = ("https://filters.adtidy.org/extension/ublock/filters/1.txt",
               "https://filters.adtidy.org/windows/filters/1.txt")

# сила основного списка: HaGeZi Multi Light / Normal / Pro / Pro++
LEVELS = {"light": "light", "normal": "multi", "pro": "pro", "pro_plus": "pro.plus"}
DEFAULT_LEVEL = "normal"  # «Сильная» и выше чаще закрывают нужные сайты — их включают сами

# Встроенная защита: блокировщик не должен закрывать сами сайты.
# SAFE_TREE — сайт и все его поддомены не блокируются никогда (хостинги картинок и файлов, мессенджеры,
# банки, госуслуги, разработка: на этих адресах нет рекламы, а поломка заметна сразу).
SAFE_TREE = frozenset("""
telegram.org t.me telegram.me telesco.pe tdesktop.com telegra.ph
discord.com discord.gg discordapp.com discordapp.net discord.media discordcdn.com
whatsapp.com whatsapp.net signal.org
imgur.com i.imgur.com ibb.co imgbb.com postimg.cc postimages.org catbox.moe litter.catbox.moe iili.io
0x0.st pixeldrain.com gofile.io files.fm mega.nz mega.io dropbox.com dropboxusercontent.com
github.com githubusercontent.com githubassets.com github.io gitlab.com bitbucket.org
pypi.org pythonhosted.org npmjs.com npmjs.org jsdelivr.net unpkg.com cdnjs.cloudflare.com
gosuslugi.ru esia.gosuslugi.ru nalog.gov.ru mos.ru pfr.gov.ru sfr.gov.ru
sberbank.ru sber.ru online.sberbank.ru tbank.ru tinkoff.ru vtb.ru alfabank.ru gazprombank.ru raiffeisen.ru
pochtabank.ru sovcombank.ru open.ru mtsbank.ru psbank.ru rshb.ru nspk.ru mironline.ru qiwi.com yoomoney.ru
paypal.com stripe.com
steampowered.com steamcommunity.com steamstatic.com steamcontent.com epicgames.com riotgames.com
""".split())
# SAFE_SITES — сами сайты (адрес и www) не блокируются, а их рекламные поддомены — как обычно.
SAFE_SITES = frozenset("""
google.com google.ru youtube.com youtu.be yandex.ru ya.ru yandex.com dzen.ru vk.com vk.ru vkvideo.ru ok.ru mail.ru
rutube.ru avito.ru ozon.ru wildberries.ru wb.ru market.yandex.ru kinopoisk.ru ivi.ru okko.tv kion.ru 2gis.ru
habr.com pikabu.ru lenta.ru ria.ru rbc.ru kommersant.ru dtf.ru vc.ru drom.ru auto.ru cian.ru hh.ru
facebook.com instagram.com x.com twitter.com tiktok.com reddit.com twitch.tv linkedin.com pinterest.com
wikipedia.org wikimedia.org microsoft.com live.com outlook.com office.com bing.com apple.com icloud.com
amazon.com aliexpress.com aliexpress.ru ebay.com netflix.com spotify.com soundcloud.com
openai.com chatgpt.com claude.ai anthropic.com gemini.google.com perplexity.ai deepseek.com
stackoverflow.com medium.com quora.com tumblr.com deviantart.com artstation.com pixiv.net
""".split())

# названия рекламных и следящих адресов — о таких «сайт закрыт» не спрашиваем
AD_NAME = re.compile(r"(^|[.\-])(ads?|adv|adverts?|advertising|adserv(er|ice)s?|adsystem|banners?|track(er|ers|ing)?|pixels?|metrics?|"
                     r"analytics?|stats?|counters?|telemetry|beacons?|pop(up|under|ads?)s?|clicks?|clicktrack|promos?|affiliates?|"
                     r"tagmanager|doubleclick|syndication)([.\-]|\d|$)|"
                     r"doubleclick|googlesyndication|googletagmanager|google-analytics|googleadservices|adservice|"
                     r"taboola|outbrain|criteo|adfox|adriver|mgid|hotjar|scorecardresearch|quantserve|adnxs|rubiconproject|"
                     r"pubmatic|openx|smartadserver|moatads|exoclick|propeller|adsterra|clickadu|popads|popcash|juicyads|"
                     r"trafficjunky|yandexadexchange|adhigh|admitad|getintent|buzzoola|segmento|relap|smi2|24smi|"
                     r"marketgid|lentainform|adskeeper|appsflyer|branch\.io|onesignal|pushwoosh|sendpulse|amplitude|mixpanel|"
                     r"segment\.(io|com)|newrelic|nr-data|sentry|bugsnag|crashlytics")

# отдельные списки: id → (адреса, формат)
EXTRA = {
    "popups": ([u.format("popupads") for u in _HAGEZI], "domains"),      # всплывающие окна и «попандеры»
    "threats": ([u.format("tif.mini") for u in _HAGEZI], "domains"),     # мошенничество, вирусы, фишинг
    "ru": (list(_ADGUARD_RU), "adblock"),                                # российские рекламные сети (AdGuard Russian)
    "telemetry": ([u.format("native.winoffice") for u in _HAGEZI], "domains"),  # слежка Windows и Office
}
DEFAULT_LISTS = {"popups": True, "threats": True, "ru": True, "telemetry": False}

_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
_ADBLOCK_RE = re.compile(r"^\|\|([a-z0-9._-]+)\^(\$important)?$")


def main_url(list_id: str, level: str = DEFAULT_LEVEL) -> list[str]:
    if list_id == "main":
        return [u.format(LEVELS.get(level, LEVELS[DEFAULT_LEVEL])) for u in _HAGEZI]
    return list(EXTRA[list_id][0])


def cache_name(list_id: str, level: str = DEFAULT_LEVEL) -> str:
    return f"main-{LEVELS.get(level, LEVELS[DEFAULT_LEVEL])}.txt" if list_id == "main" else f"{list_id}.txt"


def _clean(value: str) -> str:
    v = value.strip().lower().rstrip(".")
    if v.startswith("*."):
        v = v[2:]
    return v if _DOMAIN_RE.match(v) else ""


def parse(text: str, fmt: str = "domains") -> set[str]:
    """Текст списка → множество доменов. domains — по одному в строке (можно «0.0.0.0 домен» и «*.домен»),
    adblock — только правила вида ||домен^ без условий (правила с $… нельзя проверить по одному адресу)."""
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#!" or line.startswith("["):
            continue
        if fmt == "adblock" or line.startswith("||"):
            m = _ADBLOCK_RE.match(line.lower())
            d = _clean(m.group(1)) if m else ""
        else:
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::", "::1"):
                parts = parts[1:]
            d = _clean(parts[0].split("#", 1)[0])
        if d:
            out.add(d)
    return out


def parse_user(text: str) -> set[str]:
    """Свои сайты или исключения из поля ввода: адреса, ссылки, *.домен, ||домен^."""
    out: set[str] = set()
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if "://" in line:
            line = line.split("://", 1)[1]
        line = line.split("/", 1)[0].split(":", 1)[0]
        if line.startswith("||"):
            line = line[2:].rstrip("^")
        d = _clean(line)
        if d:
            out.add(d)
    return out


def _parents(domain: str):
    parts = domain.split(".")
    for i in range(1, len(parts) - 1):
        yield ".".join(parts[i:])


def minimize(domains: set[str]) -> list[str]:
    """Убирает поддомены, если в списке уже есть сам сайт (правило ядра действует на поддомены)."""
    return sorted(d for d in domains if not any(p in domains for p in _parents(d)))


def apply_allow(domains: set[str], allow: set[str]) -> set[str]:
    """Исключения: сайт из исключений, его поддомены и «родители» не блокируются."""
    if not allow:
        return domains
    out = set()
    for d in domains:
        if d in allow or any(p in allow for p in _parents(d)):
            continue  # сам сайт или его поддомен
        out.add(d)
    for a in allow:  # родительская запись (example.com) заблокировала бы и исключение (cdn.example.com)
        for p in _parents(a):
            out.discard(p)
    return out


def protect(domains: set[str]) -> set[str]:
    """Встроенная защита сайтов (см. SAFE_TREE и SAFE_SITES)."""
    keep_site = set(SAFE_SITES) | {"www." + d for d in SAFE_SITES}
    shield = keep_site | SAFE_TREE
    out = set()
    for d in domains:
        if d in shield or d in SAFE_TREE or any(p in SAFE_TREE for p in _parents(d)):
            continue  # сам защищённый сайт, его www или поддомен «неприкасаемого» сайта
        out.add(d)
    # запись-«родитель» (com.example → example.com) закрыла бы защищённый сайт вместе с поддоменами
    for h in shield:
        for p in _parents(h):
            out.discard(p)
    return out


def protected(host: str) -> str:
    """Почему адрес не блокируется встроенной защитой ('' — не защищён)."""
    h = host.lower().rstrip(".")
    if h in SAFE_TREE or any(p in SAFE_TREE for p in _parents(h)):
        return "tree"
    if h in SAFE_SITES or (h.startswith("www.") and h[4:] in SAFE_SITES):
        return "site"
    return ""


def site_name(host: str) -> str:
    """Основной адрес сайта, если host — это сам сайт (example.com или www.example.com), иначе ''."""
    h = host.lower().rstrip(".")
    base = h[4:] if h.startswith("www.") else h
    parts = base.split(".")
    if len(parts) < 2 or not _DOMAIN_RE.match(base):
        return ""
    short = ("co", "com", "net", "org", "gov", "edu", "ac", "msk", "spb")
    if len(parts) == 2 or (len(parts) == 3 and len(parts[-1]) == 2 and parts[-2] in short):
        return base
    return ""


def looks_like_ads(host: str) -> bool:
    return bool(AD_NAME.search(host.lower()))


def is_blocked(host: str, domains: set[str]) -> bool:
    host = host.lower().rstrip(".")
    return host in domains or any(p in domains for p in _parents(host))


# ---------- файл для ядра (формат geosite: GeoSiteList → GeoSite → Domain) ----------

def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _field(num: int, payload: bytes) -> bytes:
    return _varint(num << 3 | 2) + _varint(len(payload)) + payload


def encode_geosite(tag: str, domains: list[str]) -> bytes:
    """GeoSiteList с одной категорией. Тип домена 2 (Domain) — сам сайт и все его поддомены."""
    body = [_field(1, tag.upper().encode())]
    for d in domains:
        body.append(_field(2, b"\x08\x02" + _field(2, d.encode())))
    site = b"".join(body)
    return _field(1, site)


def decode_geosite(data: bytes) -> dict[str, list[str]]:
    """Обратное чтение (для самопроверки)."""
    def read_varint(buf, i):
        shift = n = 0
        while True:
            b = buf[i]
            i += 1
            n |= (b & 0x7F) << shift
            if not b & 0x80:
                return n, i
            shift += 7

    def fields(buf):
        i = 0
        while i < len(buf):
            key, i = read_varint(buf, i)
            if key & 7 == 2:
                ln, i = read_varint(buf, i)
                yield key >> 3, buf[i:i + ln]
                i += ln
            elif key & 7 == 0:
                val, i = read_varint(buf, i)
                yield key >> 3, val
            else:
                raise ValueError("неожиданный тип поля")

    out: dict[str, list[str]] = {}
    for num, site in fields(data):
        if num != 1:
            continue
        code, doms = "", []
        for n2, v in fields(site):
            if n2 == 1:
                code = v.decode()
            elif n2 == 2:
                doms += [x.decode() for n3, x in fields(v) if n3 == 2]
        out[code] = doms
    return out


# ---------- скачивание и сборка ----------

def download(list_id: str, cache_dir: str, level: str = DEFAULT_LEVEL, proxy_port: int | None = None,
             timeout: float = 60.0) -> int:
    """Скачивает список (с запасным адресом). Возвращает число адресов в нём."""
    os.makedirs(cache_dir, exist_ok=True)
    dest = os.path.join(cache_dir, cache_name(list_id, level))
    fmt = "domains" if list_id == "main" else EXTRA[list_id][1]
    last: Exception | None = None
    for url in main_url(list_id, level):
        try:
            netutil.download_file(url, dest + ".new", proxy_port=proxy_port, timeout=timeout)
            with open(dest + ".new", encoding="utf-8", errors="replace") as f:
                count = len(parse(f.read(), fmt))
            if count < 50:
                raise IOError("в скачанном списке почти нет адресов")
            os.replace(dest + ".new", dest)
            return count
        except Exception as exc:  # пробуем запасной адрес
            last = exc
            try:
                os.remove(dest + ".new")
            except OSError:
                pass
    raise last or IOError("список не скачался")


def cache_path(list_id: str, cache_dir: str, level: str = DEFAULT_LEVEL) -> str:
    """Файл списка в кэше. Основного списка нужной силы ещё нет (силу только что сменили) —
    пока берём ближайший уже скачанный, мягкий в первую очередь."""
    path = os.path.join(cache_dir, cache_name(list_id, level))
    if list_id != "main" or os.path.isfile(path):
        return path
    for other in ("normal", "light", "pro", "pro_plus"):
        alt = os.path.join(cache_dir, cache_name("main", other))
        if os.path.isfile(alt):
            return alt
    return path


def load(list_id: str, cache_dir: str, level: str = DEFAULT_LEVEL) -> set[str]:
    path = cache_path(list_id, cache_dir, level)
    if not os.path.isfile(path):
        return set()
    fmt = "domains" if list_id == "main" else EXTRA[list_id][1]
    with open(path, encoding="utf-8", errors="replace") as f:
        return parse(f.read(), fmt)


def lookup(cache_dir: str, level: str, lists: dict, custom: str, allow: str, host: str) -> dict:
    """«Проверить сайт»: в каких скачанных списках есть сам сайт или его «родитель», есть ли он в своих сайтах
    и в исключениях. Списки читаются построчно, без загрузки в память."""
    h = _clean((host or "").strip())
    if not h:
        raise ValueError("Не похоже на адрес сайта. Пример: example.com.")
    cand = {h, *_parents(h)}
    found = []
    for list_id in ["main"] + [k for k in EXTRA if lists.get(k)]:
        path = cache_path(list_id, cache_dir, level)
        if not os.path.isfile(path):
            continue
        fmt = "domains" if list_id == "main" else EXTRA[list_id][1]
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                got = parse(line, fmt)
                hit = next(iter(got & cand), None) if got else None
                if hit:
                    found.append({"id": list_id, "match": hit})
                    break
    own = next(iter(parse_user(custom) & cand), "")
    al = parse_user(allow)
    allowed = h in al or any(p in al for p in _parents(h))
    safe = protected(h)
    return {"host": h, "lists": found, "custom": own, "allowed": allowed, "protected": bool(safe) and not own,
            "blocked": not allowed and not (safe and not own) and bool(found or own)}


def build(cache_dir: str, out_path: str, level: str, lists: dict, custom: str = "", allow: str = "") -> dict:
    """Собирает adblock.dat из скачанных списков, своих сайтов и исключений.
    Возвращает {"total", "lists": {id: число}, "missing": [id, …], "built_at"}."""
    counts, missing = {}, []
    domains: set[str] = set()
    for list_id in ["main"] + [k for k in EXTRA if lists.get(k)]:
        got = load(list_id, cache_dir, level)
        if not got:
            missing.append(list_id)
        counts[list_id] = len(got)
        domains |= got
    domains = protect(domains)  # свои сайты из «Блокировать» главнее встроенной защиты
    own = parse_user(custom)
    counts["custom"] = len(own)
    domains |= own
    final = minimize(apply_allow(domains, parse_user(allow)))
    if not final:
        final = ["example.invalid"]  # пустая категория ядру не нравится
    data = encode_geosite(TAG, final)
    tmp = out_path + ".part"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, out_path)
    return {"total": len(final), "lists": counts, "missing": missing, "built_at": time.time()}
