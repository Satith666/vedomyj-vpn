"""Проверка популярных сервисов: напрямую, через VPN и так, как сейчас настроена маршрутизация."""

from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from . import netutil

SERVICES: list[dict] = [
    {"name": "Telegram", "urls": ["https://web.telegram.org/", "https://api.telegram.org/"],
     "domains": ["telegram.org", "t.me", "telesco.pe", "telegram-cdn.org"]},
    {"name": "WhatsApp", "urls": ["https://web.whatsapp.com/"], "domains": ["whatsapp.com", "whatsapp.net"]},
    {"name": "Discord", "urls": ["https://discord.com/api/v10/gateway", "https://cdn.discordapp.com/"],
     "domains": ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"]},
    {"name": "YouTube", "urls": ["https://www.youtube.com/generate_204", "https://i.ytimg.com/generate_204",
                                 "https://redirector.googlevideo.com/report_mapping"],
     "domains": ["youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com", "youtu.be"]},
    {"name": "Instagram", "urls": ["https://www.instagram.com/"], "domains": ["instagram.com", "cdninstagram.com"]},
    {"name": "TikTok", "urls": ["https://www.tiktok.com/"],
     "domains": ["tiktok.com", "tiktokv.com", "tiktokcdn.com", "tiktokcdn-us.com", "tiktokcdn-eu.com", "tiktokv.us",
                 "tiktokv.eu", "tiktokw.us", "tiktokw.eu", "ttwstatic.com", "byteoversea.com", "ibytedtos.com",
                 "ibyteimg.com", "musical.ly", "tiktok-row.net", "byteintlapi.com"]},
    {"name": "Facebook", "urls": ["https://www.facebook.com/"], "domains": ["facebook.com", "fbcdn.net"]},
    {"name": "X (Twitter)", "urls": ["https://x.com/"], "domains": ["x.com", "twitter.com", "twimg.com"]},
    {"name": "ChatGPT", "urls": ["https://api.openai.com/v1/models"], "region": True,
     "domains": ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"]},
    {"name": "Claude", "urls": ["https://api.anthropic.com/v1/models"], "region": True,
     "domains": ["claude.ai", "anthropic.com", "claude.com"]},
    {"name": "Twitch", "urls": ["https://www.twitch.tv/"], "domains": ["twitch.tv", "ttvnw.net", "jtvnw.net"]},
    {"name": "Spotify", "urls": ["https://open.spotify.com/"], "domains": ["spotify.com", "scdn.co"]},
    {"name": "Steam", "urls": ["https://store.steampowered.com/", "https://steamcommunity.com/"],
     "domains": ["steampowered.com", "steamcommunity.com", "steamstatic.com"]},
    {"name": "Google", "urls": ["https://www.google.com/generate_204"], "domains": ["google.com"]},
    {"name": "Госуслуги", "urls": ["https://www.gosuslugi.ru/"], "russian": True, "domains": ["gosuslugi.ru"]},
    {"name": "Сбербанк", "urls": ["https://online.sberbank.ru/"], "russian": True,
     "domains": ["sberbank.ru", "sberbank.com"]},
    {"name": "Т-Банк", "urls": ["https://www.tbank.ru/"], "russian": True, "domains": ["tbank.ru", "tinkoff.ru"]},
    {"name": "Яндекс", "urls": ["https://ya.ru/"], "russian": True, "domains": ["ya.ru", "yandex.ru", "yandex.net"]},
    {"name": "VK", "urls": ["https://vk.com/"], "russian": True, "domains": ["vk.com", "userapi.com"]},
    {"name": "Ozon", "urls": ["https://www.ozon.ru/"], "russian": True, "domains": ["ozon.ru"]},
    {"name": "Wildberries", "urls": ["https://www.wildberries.ru/"], "russian": True,
     "domains": ["wildberries.ru", "wb.ru"]},
]

OK, SLOW, REGION, BLOCKED, SKIP = "ok", "slow", "region", "blocked", "skip"
SLOW_MS = 4000


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # редирект = сайт ответил, этого достаточно


def _opener(proxy_port: int | None):
    proxy = {"http": f"http://127.0.0.1:{proxy_port}", "https": f"http://127.0.0.1:{proxy_port}"} \
        if proxy_port else {}
    return urllib.request.build_opener(urllib.request.ProxyHandler(proxy), _NoRedirect(),
                                       urllib.request.HTTPSHandler(context=netutil.ssl_context()))


def check_url(url: str, proxy_port: int | None, region_sensitive: bool, timeout: float = 10.0) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": netutil.BROWSER_UA, "Accept": "*/*"})
    t0 = time.perf_counter()
    code, headers = 0, {}
    try:
        with _opener(proxy_port).open(req, timeout=timeout) as resp:
            resp.read(2048)
            code, headers = resp.status, {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        code, headers = exc.code, {k.lower(): v for k, v in exc.headers.items()}
    except Exception as exc:
        reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
        if isinstance(reason, ssl.SSLCertVerificationError):
            # сайт ответил, но Python не доверяет его сертификату (например, российский УЦ Минцифры,
            # которого нет в системе, или строгая проверка Python 3.13). Для проверки «открывается ли» — достаточно.
            ms = round((time.perf_counter() - t0) * 1000)
            return {"state": SLOW if ms > SLOW_MS else OK, "detail": f"сайт отвечает (сертификат не проверен), {ms} мс",
                    "ms": ms}
        return {"state": BLOCKED, "detail": netutil.human_error(exc), "ms": None}
    ms = round((time.perf_counter() - t0) * 1000)
    challenge = headers.get("cf-mitigated", "").lower() == "challenge"
    if code == 451:
        return {"state": BLOCKED, "detail": "451: заблокировано по закону", "ms": ms}
    if code == 403 and region_sensitive and not challenge:
        return {"state": REGION, "detail": "403: доступ закрыт для этой страны", "ms": ms}
    state = SLOW if ms > SLOW_MS else OK
    return {"state": state, "detail": f"код {code}, {ms} мс", "ms": ms}


# ---------- «качается ли»: зависание соединения после первых килобайт ----------
# Некоторые провайдеры пропускают у части адресов (зарубежные хостинги и CDN) только первые ~16–20 КБ, а потом
# соединение «замерзает»: маленькая страница успевает открыться, а картинки и видео — нет. Проверка открывает
# одно соединение и просит страницу несколько раз подряд (keep-alive), пока не получит STALL_TARGET байт.

STALL_OK, STALL_STALL, STALL_FAIL, STALL_SMALL = "ok", "stall", "fail", "small"
STALL_TARGET = 64 * 1024


def _read_response(sock, deadline: float, counter: list) -> tuple[int, str, bool]:
    """Читает один ответ HTTP/1.1. Возвращает (код, Location, соединение закрыто)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(16384)
        if not chunk:
            raise EOFError("closed")  # сервер сам закрыл соединение между ответами — это норма
        counter[0] += len(chunk)
        buf += chunk
        if len(buf) > 256 * 1024:
            raise ValueError("headers too long")
    head, body = buf.split(b"\r\n\r\n", 1)
    lines = head.decode("latin-1").split("\r\n")
    try:
        code = int(lines[0].split()[1])
    except (IndexError, ValueError):
        code = 0
    hdr = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdr[k.strip().lower()] = v.strip()
    closing = hdr.get("connection", "").lower() == "close"
    if hdr.get("transfer-encoding", "").lower() == "chunked":
        data = body
        while True:
            while b"\r\n" not in data:
                chunk = sock.recv(16384)
                if not chunk:
                    return code, hdr.get("location", ""), True
                counter[0] += len(chunk)
                data += chunk
            size_line, data = data.split(b"\r\n", 1)
            try:
                size = int(size_line.split(b";")[0].strip() or b"0", 16)
            except ValueError:
                return code, hdr.get("location", ""), True
            while len(data) < size + 2:
                chunk = sock.recv(16384)
                if not chunk:
                    return code, hdr.get("location", ""), True
                counter[0] += len(chunk)
                data += chunk
            data = data[size + 2:]
            if size == 0:
                return code, hdr.get("location", ""), closing
    if "content-length" in hdr:
        try:
            left = int(hdr["content-length"]) - len(body)
        except ValueError:
            left = 0
        while left > 0:
            chunk = sock.recv(min(65536, left))
            if not chunk:
                return code, hdr.get("location", ""), True
            counter[0] += len(chunk)
            left -= len(chunk)
        return code, hdr.get("location", ""), closing
    if code in (204, 304) or 100 <= code < 200:
        return code, hdr.get("location", ""), closing
    while time.monotonic() < deadline:  # длина не указана — до закрытия
        chunk = sock.recv(65536)
        if not chunk:
            break
        counter[0] += len(chunk)
    return code, hdr.get("location", ""), True


def stall_test(host: str, proxy_port: int | None = None, port: int = 443, stall_s: float = 4.0,
               total_s: float = 14.0, target: int = STALL_TARGET) -> dict:
    """Проверка «качается ли» с сайта: {"state", "bytes", "detail", "ms"}.
    ok — получили target байт; stall — получили немного и соединение замерло; fail — не открылся совсем;
    small — сайт отдаёт мало и закрывает соединение (зависание не проверить, считаем нормой)."""
    import socket as _socket
    t0 = time.monotonic()
    deadline = t0 + total_s
    counter = [0]
    sock = None
    try:
        if proxy_port:
            sock = _socket.create_connection(("127.0.0.1", proxy_port), timeout=8)
            sock.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = sock.recv(4096)
                if not chunk:
                    raise ConnectionResetError("proxy closed")
                resp += chunk
            if b" 200" not in resp.split(b"\r\n", 1)[0]:
                raise ConnectionRefusedError("proxy refused")
        else:
            sock = _socket.create_connection((host, port), timeout=8)
        if port == 443:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # только замер скорости, никаких данных не отправляем
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(stall_s)
    except Exception as exc:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
        return {"state": STALL_FAIL, "bytes": 0, "detail": netutil.human_error(exc), "ms": None}
    path, requests_done = "/", 0
    started = 0  # сколько байт было до начала текущего ответа
    try:
        while counter[0] < target and requests_done < 40 and time.monotonic() < deadline:
            started = counter[0]
            req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {netutil.BROWSER_UA}\r\nAccept: */*\r\n"
                   f"Accept-Encoding: identity\r\nConnection: keep-alive\r\n\r\n")
            sock.sendall(req.encode())
            requests_done += 1
            code, location, closed = _read_response(sock, deadline, counter)
            if closed:
                break
            if 300 <= code < 400 and location.startswith("/") and not location.startswith("//"):
                path = location  # перенаправление на том же адресе — дальше просим его
    except (_socket.timeout, TimeoutError):
        ms = round((time.monotonic() - t0) * 1000)
        if counter[0] >= 1024:
            kb = max(1, counter[0] // 1024)
            return {"state": STALL_STALL, "bytes": counter[0], "detail": f"соединение замирает после {kb} КБ", "ms": ms}
        return {"state": STALL_FAIL, "bytes": counter[0], "detail": "сайт не отвечает", "ms": ms}
    except EOFError:
        pass
    except Exception as exc:
        ms = round((time.monotonic() - t0) * 1000)
        if counter[0] == 0:
            return {"state": STALL_FAIL, "bytes": 0, "detail": netutil.human_error(exc), "ms": ms}
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, ssl.SSLError)) and counter[0] < target \
                and counter[0] > started:  # оборвали посреди ответа (между ответами — сервер просто закрыл соединение)
            kb = max(1, counter[0] // 1024)  # оборвали посреди передачи — так тоже режут
            return {"state": STALL_STALL, "bytes": counter[0], "detail": f"соединение обрывается после {kb} КБ", "ms": ms}
        return {"state": STALL_SMALL, "bytes": counter[0], "detail": "", "ms": ms}
    finally:
        try:
            sock.close()
        except OSError:
            pass
    ms = round((time.monotonic() - t0) * 1000)
    if counter[0] >= target:
        return {"state": STALL_OK, "bytes": counter[0], "detail": f"{counter[0] // 1024} КБ за {ms} мс", "ms": ms}
    return {"state": STALL_SMALL, "bytes": counter[0], "detail": "", "ms": ms}


def check_service(svc: dict, proxy_port: int | None) -> dict:
    region = bool(svc.get("region") or svc.get("russian"))
    worst = None
    order = {OK: 0, SLOW: 1, REGION: 2, BLOCKED: 3}
    for url in svc["urls"]:
        r = check_url(url, proxy_port, region)
        r["url"] = url
        if worst is None or order[r["state"]] > order[worst["state"]]:
            worst = r
        if r["state"] == BLOCKED:
            break
    return worst or {"state": BLOCKED, "detail": "нет адресов", "ms": None}


def check_all(paths: dict[str, int | None], services: list[dict] | None = None, on_result=None,
              stop_event=None) -> dict:
    """paths: {"direct": None, "vpn": порт, "current": порт}; порт False — пропустить колонку.
    Возвращает {имя сервиса: {колонка: результат}}."""
    services = services or SERVICES
    results: dict = {s["name"]: {} for s in services}
    jobs = []
    with ThreadPoolExecutor(max_workers=16) as pool:
        for svc in services:
            for column, port in paths.items():
                if port is False:
                    results[svc["name"]][column] = {"state": SKIP, "detail": "", "ms": None}
                    continue
                jobs.append((svc, column, pool.submit(check_service, svc, port)))
        for svc, column, fut in jobs:
            if stop_event and stop_event.is_set():
                pool.shutdown(wait=False, cancel_futures=True)
                break
            results[svc["name"]][column] = fut.result()
            if on_result:
                on_result(svc["name"], column, results[svc["name"]][column])
    return results



def split_failures(results: dict) -> tuple[list[str], list[str]]:
    """(не открываются «как сейчас» — это можно исправить маршрутом,
        российские сайты, которые не отвечают даже напрямую — дело не в VPN: сбой сайта, защита от ботов, сеть)."""
    failed = (BLOCKED, REGION)
    russian = {s["name"] for s in SERVICES if s.get("russian")}
    bad, outside = [], []
    for name, r in results.items():
        cur = r.get("current", {})
        if cur.get("state") not in failed:
            continue
        if name in russian and r.get("direct", {}).get("state") in failed:
            detail = cur.get("detail") or ""
            outside.append(f"{name} ({detail})" if detail else name)
        else:
            bad.append(name)
    return bad, outside

# белые списки: российские сайты из списка разрешённых и обычные зарубежные адреса для сравнения
WL_ALLOWED = ["https://ya.ru/", "https://www.gosuslugi.ru/", "https://vk.com/"]
WL_FOREIGN = ["https://www.google.com/generate_204", "https://cp.cloudflare.com/generate_204",
              "https://www.wikipedia.org/"]


def whitelist_probe(proxy_port: int | None = None) -> str:
    """«whitelist» — открываются только разрешённые российские сайты (режим белых списков),
    «open» — интернет открыт, «offline» — не открывается ничего."""
    from concurrent.futures import ThreadPoolExecutor
    urls = WL_ALLOWED + WL_FOREIGN
    with ThreadPoolExecutor(max_workers=len(urls)) as pool:
        states = list(pool.map(lambda u: check_url(u, proxy_port, False, timeout=6)["state"], urls))
    ok = [st in (OK, SLOW) for st in states]
    allowed, foreign = any(ok[:len(WL_ALLOWED)]), any(ok[len(WL_ALLOWED):])
    if foreign:
        return "open"
    return "whitelist" if allowed else "offline"


def exit_info(proxy_port: int | None) -> dict:
    """IP и страна, под которыми нас видят сайты (Cloudflare trace)."""
    try:
        status, _, body = netutil.http_get("https://www.cloudflare.com/cdn-cgi/trace", proxy_port=proxy_port,
                                           timeout=10)
    except Exception as exc:
        return {"ip": "", "loc": "", "error": netutil.human_error(exc)}
    info = {}
    for line in body.decode("utf-8", "replace").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            info[k.strip()] = v.strip()
    return {"ip": info.get("ip", ""), "loc": info.get("loc", ""), "error": "" if status == 200 else str(status)}
