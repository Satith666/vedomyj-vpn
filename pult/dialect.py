"""Свой протокол VEDOMYJ (1.26, эксперимент): шифрование — проверенное (VLESS Encryption ядра Xray),
вид трафика — свой «диалект» у каждого сервера. Своего шифра нет.

Как выглядит со стороны провайдера (проверено на GitHub, build/proto_lab.py): соединение начинается обычным
HTTP-запросом и ответом «200 OK» (свои у сервера: путь, сайт, браузер, сервер), дальше весь поток — печатные
знаки (sudoku в режиме «текст»: энтропия ~6 бит/байт вместо 8 у «шума» шифрования) со случайным паддингом.
Общего признака у серверов нет: диалект случайный и меняется одной кнопкой (переустановка).

Ограничение: на чужой «стук» сервер не прикидывается веб-сервером — молчит или сбрасывает соединение.
Против белых списков не помогает (там блокируют по адресу).
"""
from __future__ import annotations

import re
import secrets

PROTO_MIN = (26, 10, 21)   # sudoku и header-custom TCP в нужном виде — проверено на 26.11.9
LABEL = "VEDOMYJ"
NAME = "Свой протокол"
PORTS = (80, 8080, 8880, 2052, 2082, 2086, 2095)   # обычные порты HTTP — первый свободный на сервере

_SYL = ("ba", "ve", "do", "mi", "ra", "lo", "ki", "su", "ne", "to", "za", "pe", "ri", "mo", "la", "ny", "te", "vi",
        "go", "sa", "ku", "re", "na", "bo")
_SUB = ("cdn", "static", "img", "media", "api", "files", "assets", "content")
_TLD = ("ru", "net", "com", "io", "su", "org")
_WORDS = ("api", "static", "feed", "media", "assets", "sync", "update", "content", "files", "img", "data", "v1", "v2",
          "v3", "stream", "news", "lib", "events", "chunk", "pkg")
_PARAMS = ("lang", "v", "id", "t", "ref", "page", "s", "rev")
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
       "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0",
       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Safari/605.1.15",
       "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36")
_SERVERS = ("nginx", "nginx/1.24.0", "nginx/1.26.3", "openresty", "Apache")
_CTYPES = ("application/octet-stream", "text/plain; charset=utf-8", "application/json", "text/html; charset=utf-8")
_HEX = "0123456789abcdef"

_RX = {
    "path": re.compile(r"/[a-z0-9/]{1,60}"),
    "query": re.compile(r"[a-z]{1,8}=[0-9a-f]{1,16}"),
    "host": re.compile(r"[a-z0-9]{1,12}\.[a-z]{2,12}\.[a-z]{2,4}"),
    "ua": re.compile(r"[A-Za-z0-9 ()/.,;:_-]{10,160}"),
    "server": re.compile(r"[A-Za-z0-9/._-]{2,24}"),
    "ctype": re.compile(r"[a-z/+.-]{3,40}(; charset=utf-8)?"),
}


def make(rnd=None) -> dict:
    """Случайный диалект сервера. rnd(n) → 0…n-1 (для сверки с телефоном — предсказуемый)."""
    rnd = rnd or secrets.randbelow

    def pick(seq):
        return seq[rnd(len(seq))]

    word = "".join(pick(_SYL) for _ in range(3 + rnd(2)))  # 3–4 слога: не похоже на настоящие короткие домены
    path = "/" + "/".join(pick(_WORDS) for _ in range(1 + rnd(3)))
    query = pick(_PARAMS) + "=" + "".join(pick(_HEX) for _ in range(4 + rnd(9)))
    pad_min = 1 + rnd(8)
    return {"path": path, "query": query, "host": f"{pick(_SUB)}.{word}.{pick(_TLD)}", "ua": pick(_UA),
            "server": pick(_SERVERS), "ctype": pick(_CTYPES), "padMin": pad_min, "padMax": pad_min + 4 + rnd(15)}


def check(d: dict) -> dict:
    """Диалект попадает в скрипт сервера и настройки ядра: только известные поля и безопасные знаки."""
    if not isinstance(d, dict):
        raise ValueError("dialect")
    out = {}
    for key, rx in _RX.items():
        v = d.get(key)
        if not isinstance(v, str) or not rx.fullmatch(v):
            raise ValueError(f"dialect: {key}")
        out[key] = v
    lo, hi = d.get("padMin"), d.get("padMax")
    if not (isinstance(lo, int) and isinstance(hi, int) and 0 <= lo <= hi <= 40):
        raise ValueError("dialect: padding")
    out["padMin"], out["padMax"] = lo, hi
    return out


def request(d: dict) -> str:
    return (f"GET {d['path']}?{d['query']} HTTP/1.1\r\nHost: {d['host']}\r\nUser-Agent: {d['ua']}\r\n"
            f"Accept: */*\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\n\r\n")


def response(d: dict) -> str:
    return (f"HTTP/1.1 200 OK\r\nServer: {d['server']}\r\nContent-Type: {d['ctype']}\r\n"
            f"Cache-Control: no-store\r\nConnection: keep-alive\r\n\r\n")


def mask(d: dict, password: str) -> dict:
    """Finalmask протокола: внутри (первый слой) — sudoku «текст» с паддингом, снаружи — HTTP-приветствие."""
    d = check(d)
    return {"tcp": [
        {"type": "sudoku", "settings": {"password": password, "ascii": "prefer_ascii",
                                        "paddingMin": d["padMin"], "paddingMax": d["padMax"]}},
        {"type": "header-custom", "settings": {"clients": [[{"delay": 0, "type": "str", "packet": request(d)}]],
                                               "servers": [[{"delay": 0, "type": "str", "packet": response(d)}]]}},
    ]}


def is_vproto_ss(ss: dict) -> bool:
    types = {x.get("type") for x in (((ss or {}).get("finalmask") or {}).get("tcp") or []) if isinstance(x, dict)}
    return {"sudoku", "header-custom"} <= types


def is_vproto(srv) -> bool:
    """Сервер говорит на своём протоколе (sudoku + HTTP-приветствие поверх голого TCP)."""
    return is_vproto_ss(((getattr(srv, "outbound", None) or {}).get("streamSettings")) or {})
