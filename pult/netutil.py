"""Сетевые мелочи: HTTP-запросы (напрямую или через локальный прокси), свободные порты, замер пинга."""

from __future__ import annotations

import base64
import functools
import http.client
import ipaddress
import json
import socket
import sys
import ssl
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/130.0 Safari/537.36")


SYSTEM_PROXY = "system"


def system_proxy_url() -> str | None:
    """Адрес системного прокси Windows/окружения, если он задан."""
    proxies = urllib.request.getproxies()
    return proxies.get("https") or proxies.get("http")


def ssl_context() -> ssl.SSLContext:
    """Обычная проверка сертификатов. Python 3.13 включил сверхстрогий режим (VERIFY_X509_STRICT), из-за
    которого не открываются некоторые нормальные сайты и серверы подписок — возвращаем поведение Python 3.12."""
    ctx = ssl.create_default_context()
    strict = getattr(ssl, "VERIFY_X509_STRICT", 0)
    if strict:
        ctx.verify_flags &= ~strict
    return ctx


class _PinMixin:
    """Куда подключаться: адрес из pin (защищённый DNS) или обычный DNS. auto — если обычный DNS не знает сайт,
    спросить защищённый (только для своих загрузок: списки, ядро, обновления, подписки)."""
    _pin: dict
    _auto: bool

    def _target_ip(self) -> str | None:
        host = (self.host or "").lower()
        ip = self._pin.get(host)
        if ip or not self._auto:
            return ip
        try:
            socket.getaddrinfo(host, self.port, type=socket.SOCK_STREAM)
            return None  # обычный DNS знает адрес — подключаемся как обычно
        except socket.gaierror:
            ips = doh_resolve(host)
            if not ips:
                raise
            self._pin[host] = ips[0]
            return ips[0]


class _PinnedHTTPS(_PinMixin, http.client.HTTPSConnection):
    """Соединение по заранее известному адресу (из защищённого DNS), но с настоящим именем сайта в TLS:
    сертификат проверяется как обычно."""

    def __init__(self, host, *args, pin=None, auto=False, **kwargs):
        super().__init__(host, *args, **kwargs)
        self._pin, self._auto = pin if pin is not None else {}, auto

    def connect(self):
        ip = self._target_ip()
        if not ip:
            return super().connect()
        sock = socket.create_connection((ip, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTP(_PinMixin, http.client.HTTPConnection):
    def __init__(self, host, *args, pin=None, auto=False, **kwargs):
        super().__init__(host, *args, **kwargs)
        self._pin, self._auto = pin if pin is not None else {}, auto

    def connect(self):
        ip = self._target_ip()
        if not ip:
            return super().connect()
        self.sock = socket.create_connection((ip, self.port), self.timeout, self.source_address)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, pin: dict, context, auto: bool):
        super().__init__(context=context)
        self._pin, self._auto = pin, auto

    def https_open(self, req):
        return self.do_open(functools.partial(_PinnedHTTPS, pin=self._pin, auto=self._auto), req, context=self._context)


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, pin: dict, auto: bool):
        super().__init__()
        self._pin, self._auto = pin, auto

    def http_open(self, req):
        return self.do_open(functools.partial(_PinnedHTTP, pin=self._pin, auto=self._auto), req)


class _OwnProxyHandler(urllib.request.ProxyHandler):
    """Наш прокси (вход ядра) — для ЛЮБОГО адреса. Обычный ProxyHandler сверяется с «исключениями» системного
    прокси Windows (<local>, 127.*, свои сайты): тогда запрос «через VPN» тихо уходил бы напрямую."""

    def __init__(self, port: int):
        self._hostport = f"127.0.0.1:{port}"
        proxy = f"http://{self._hostport}"
        super().__init__({"http": proxy, "https": proxy})

    def proxy_open(self, req, proxy, type):
        req.set_proxy(self._hostport, "http")
        return None  # дальше — обычный обработчик: http — через прокси, https — туннель CONNECT


def make_opener(proxy_port=None, pin: dict | None = None, doh: bool = False) -> urllib.request.OpenerDirector:
    """proxy_port: None — напрямую, число — наш локальный прокси, "system" — системный прокси.
    pin — {имя сайта: адрес}: напрямую, но по адресу из защищённого DNS (в обход DNS провайдера).
    doh — напрямую; если DNS провайдера не знает сайт, адрес берётся из защищённого DNS. Только для своих загрузок:
    проверки сайтов должны видеть, что DNS провайдера сайт не отдаёт."""
    handlers: list = []
    if (pin or doh) and not proxy_port:
        pin = {k.lower(): v for k, v in (pin or {}).items()}
        return urllib.request.build_opener(urllib.request.ProxyHandler({}), _PinnedHTTPHandler(pin, doh),
                                           _PinnedHTTPSHandler(pin, ssl_context(), doh))
    if proxy_port == SYSTEM_PROXY:
        handlers.append(urllib.request.ProxyHandler())  # берёт настройки Windows
    elif proxy_port:
        handlers.append(_OwnProxyHandler(proxy_port))
    else:
        # пустой ProxyHandler — игнорируем системный прокси Windows (он может указывать на нас же)
        handlers.append(urllib.request.ProxyHandler({}))
    handlers.append(urllib.request.HTTPSHandler(context=ssl_context()))
    return urllib.request.build_opener(*handlers)


def http_get(url: str, proxy_port=None, timeout: float = 20.0, user_agent: str = BROWSER_UA,
             max_bytes: int = 64 * 1024 * 1024, headers: dict | None = None,
             pin: dict | None = None, doh: bool = False) -> tuple[int, dict, bytes]:
    """GET-запрос. Возвращает (код, заголовки в нижнем регистре, тело). HTTP-ошибки не выбрасываются.
    doh — для своих загрузок: если DNS провайдера не знает адрес, взять его из защищённого DNS."""
    req = urllib.request.Request(url, headers={"User-Agent": user_agent, "Accept": "*/*", **(headers or {})})
    opener = make_opener(proxy_port, pin, doh)
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        body = b""
        try:
            body = exc.read(65536)
        except Exception:
            pass
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, body
    with resp:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        chunks, total = [], 0
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise IOError("слишком большой ответ")
        return resp.status, headers, b"".join(chunks)


# Проверка «страницы входа» (Wi-Fi в кафе, гостинице, метро): без входа такая сеть подменяет любой сайт своей
# страницей. Адрес — тот же, что проверяет Android/Chrome; обычный ответ — пустой «204».
CAPTIVE_URL = "http://connectivitycheck.gstatic.com/generate_204"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def captive_portal(timeout: float = 5.0) -> bool:
    """True — сеть просит войти (вместо пустого ответа пришла страница или перенаправление).
    Нет ответа вовсе — False: это не страница входа (нет интернета или белые списки)."""
    req = urllib.request.Request(CAPTIVE_URL, headers={"User-Agent": BROWSER_UA})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status != 204 or bool(resp.read(64))
    except urllib.error.HTTPError as exc:
        return 300 <= exc.code < 400 or exc.code in (401, 407, 511)
    except OSError:
        return False


def clock_skew(timeout: float = 6.0) -> float | None:
    """На сколько секунд часы компьютера расходятся с точным временем (по заголовку Date сервера Google).
    None — не узнали. Плюс — часы спешат."""
    import email.utils
    req = urllib.request.Request(CAPTIVE_URL, headers={"User-Agent": BROWSER_UA})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        t0 = time.time()
        try:
            resp = opener.open(req, timeout=timeout)
            date = resp.headers.get("Date")
            resp.close()
        except urllib.error.HTTPError as exc:
            date = exc.headers.get("Date") if exc.headers else None
        if not date:
            return None
        server = email.utils.parsedate_to_datetime(date).timestamp()
        return round((t0 + time.time()) / 2 - server, 1)
    except (OSError, ValueError, TypeError):
        return None


def final_url(url: str, proxy_port=None, timeout: float = 20.0) -> str:
    """Куда в итоге ведёт адрес после перенаправлений (тело не читается). "" — не открылся."""
    req = urllib.request.Request(url, headers={"User-Agent": BROWSER_UA})
    try:
        with make_opener(proxy_port, doh=True).open(req, timeout=timeout) as resp:
            return resp.geturl()
    except urllib.error.HTTPError as exc:
        return exc.geturl() or ""
    except OSError:
        return ""


def download_file(url: str, dest: str, proxy_port: int | None = None, timeout: float = 60.0,
                  progress=None) -> int:
    """Скачивает файл во временный и атомарно заменяет dest. Возвращает размер.
    Напрямую: если DNS провайдера не знает адрес (GitHub и т.п.), он берётся из защищённого DNS."""
    import os
    req = urllib.request.Request(url, headers={"User-Agent": BROWSER_UA})
    opener = make_opener(proxy_port, doh=True)
    tmp = dest + ".part"
    total = 0
    with opener.open(req, timeout=timeout) as resp:
        size = int(resp.headers.get("Content-Length") or 0)
        with open(tmp, "wb") as f:
            while True:
                chunk = resp.read(256 * 1024)
                if not chunk:
                    break
                f.write(chunk)
                total += len(chunk)
                if progress:
                    progress(total, size)
    if total == 0:
        os.remove(tmp)
        raise IOError("скачан пустой файл")
    os.replace(tmp, dest)
    return total


def is_port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if sys.platform != "win32":
            # Linux/macOS: старые соединения в TIME_WAIT не мешают слушать порт (в Windows этот флаг значит другое)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def find_free_ports(count: int, start: int = 20800, avoid: set | None = None) -> list[int]:
    avoid = avoid or set()
    ports, port = [], start
    while len(ports) < count and port < 65000:
        if port not in avoid and is_port_free(port):
            ports.append(port)
        port += 1
    if len(ports) < count:
        raise OSError("не нашлось свободных портов")
    return ports


def wait_ports(ports: list[int], timeout: float = 6.0, alive=None) -> bool:
    """Ждёт, пока все порты начнут принимать соединения."""
    deadline = time.monotonic() + timeout
    pending = list(ports)
    while pending and time.monotonic() < deadline:
        if alive and not alive():
            return False
        still = []
        for p in pending:
            try:
                with socket.create_connection(("127.0.0.1", p), timeout=0.3):
                    pass
            except OSError:
                still.append(p)
        pending = still
        if pending:
            time.sleep(0.15)
    return not pending


# ---------- пинг через HTTP на открытом соединении ----------

class _Conn:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = b""

    def _recv(self, deadline: float):
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            raise TimeoutError("время ожидания истекло")
        self.sock.settimeout(remaining)
        chunk = self.sock.recv(65536)
        if not chunk:
            raise ConnectionError("соединение закрыто")
        self.buf += chunk

    def read_until(self, marker: bytes, deadline: float) -> bytes:
        while marker not in self.buf:
            if len(self.buf) > 1024 * 1024:
                raise ConnectionError("слишком длинный ответ")
            self._recv(deadline)
        i = self.buf.index(marker) + len(marker)
        data, self.buf = self.buf[:i], self.buf[i:]
        return data

    def read_exact(self, n: int, deadline: float) -> bytes:
        while len(self.buf) < n:
            self._recv(deadline)
        data, self.buf = self.buf[:n], self.buf[n:]
        return data


def _read_response(conn: _Conn, deadline: float) -> tuple[int, bool]:
    head = conn.read_until(b"\r\n\r\n", deadline).decode("latin-1")
    lines = head.split("\r\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError) as exc:
        raise ConnectionError("непонятный ответ сервера") from exc
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip().lower()
    reusable = headers.get("connection") != "close"
    if status in (204, 304) or 100 <= status < 200:
        return status, reusable
    if "content-length" in headers:
        conn.read_exact(int(headers["content-length"] or 0), deadline)
        return status, reusable
    if "chunked" in headers.get("transfer-encoding", ""):
        while True:
            size_line = conn.read_until(b"\r\n", deadline)
            size = int(size_line.split(b";")[0].strip() or b"0", 16)
            if size == 0:
                conn.read_until(b"\r\n", deadline)
                break
            conn.read_exact(size + 2, deadline)
        return status, reusable
    return status, False


def http_ping(host: str, path: str = "/generate_204", proxy_port: int | None = None, rounds: int = 4,
              timeout: float = 6.0) -> dict:
    """Замер задержки.

    delay_ms — время до первого ответа на новом соединении (рукопожатие + запрос): так ощущается открытие сайтов.
    ping_ms  — медиана времени ответа на уже открытом соединении: так ощущаются игры и звонки.
    """
    result: dict = {"ok": False, "delay_ms": None, "ping_ms": None, "jitter_ms": None, "error": ""}
    host = host.strip()
    port = 80
    if host.count(":") == 1:  # host:port (IPv6 без порта не трогаем)
        host, port_s = host.split(":")
        port = int(port_s) if port_s.isdigit() else 80
    host_header = host if port == 80 else f"{host}:{port}"
    t_start = time.perf_counter()
    deadline = t_start + timeout
    sock = None
    try:
        if proxy_port:
            sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
        else:
            sock = socket.create_connection((host, port), timeout=timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conn = _Conn(sock)
        if proxy_port:
            sock.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
            head = conn.read_until(b"\r\n\r\n", deadline).decode("latin-1")
            if " 200" not in head.split("\r\n", 1)[0]:
                raise ConnectionError("прокси не открыл соединение")
        request = (f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: Mozilla/5.0\r\n"
                   f"Connection: keep-alive\r\n\r\n").encode()
        sock.sendall(request)
        status, reusable = _read_response(conn, deadline)
        result["delay_ms"] = round((time.perf_counter() - t_start) * 1000)
        result["status"] = status
        rtts = []
        if reusable:
            for _ in range(rounds):
                t = time.perf_counter()
                sock.sendall(request)
                _, reusable = _read_response(conn, t + timeout)
                rtts.append((time.perf_counter() - t) * 1000)
                if not reusable:
                    break
        if rtts:
            result["ping_ms"] = round(statistics.median(rtts))
            result["jitter_ms"] = round(max(rtts) - min(rtts))
        else:
            result["ping_ms"] = result["delay_ms"]
            result["jitter_ms"] = 0
        result["ok"] = True
    except (OSError, ConnectionError, TimeoutError, ValueError) as exc:
        result["error"] = _human_error(exc)
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
    return result


def _human_error(exc: Exception) -> str:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "нет ответа (таймаут)"
    if isinstance(exc, ConnectionRefusedError):
        return "соединение отклонено"
    if isinstance(exc, ConnectionResetError):
        return "соединение сброшено"
    if isinstance(exc, socket.gaierror):
        return "адрес не найден (DNS)"
    text = str(exc) or exc.__class__.__name__
    return text[:120]


def is_dns_error(exc: Exception) -> bool:
    """Ошибка «адрес не найден»: DNS провайдера не знает сайт (или блокирует его)."""
    if isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, Exception):
        exc = exc.reason
    return isinstance(exc, socket.gaierror)


# Защищённый DNS (DoH, RFC 8484). Подключаемся к нему по известному адресу — сам запрос не уходит в DNS провайдера,
# а сертификат проверяется по имени сервиса. Несколько сервисов: провайдер может закрыть один из них.
DOH_SERVERS = [
    ("https://cloudflare-dns.com/dns-query", "cloudflare-dns.com", "1.1.1.1"),
    ("https://dns.google/dns-query", "dns.google", "8.8.8.8"),
    ("https://dns.quad9.net/dns-query", "dns.quad9.net", "9.9.9.9"),
    ("https://dns.adguard-dns.com/dns-query", "dns.adguard-dns.com", "94.140.14.14"),
]
_DOH_CACHE: dict = {}
DOH_TTL = 600.0


def dns_query(host: str) -> bytes:
    """Запрос DNS (тип A) в формате «как по сети»."""
    out = bytearray(b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")  # id 0 (как велит RFC 8484), RD, 1 вопрос
    for label in host.rstrip(".").encode("idna").split(b"."):
        if not 0 < len(label) < 64:
            raise ValueError("неверное имя")
        out += bytes([len(label)]) + label
    out += b"\x00\x00\x01\x00\x01"  # конец имени, тип A, класс IN
    return bytes(out)


def _skip_name(data: bytes, i: int) -> int:
    while True:
        n = data[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:  # ссылка на имя выше
            return i + 2
        i += 1 + n


def dns_answers(data: bytes) -> list[str]:
    """IPv4-адреса из ответа DNS. Битый ответ — пустой список."""
    try:
        if len(data) < 12 or data[3] & 0x0F:  # код ответа не NOERROR
            return []
        qd, an = int.from_bytes(data[4:6], "big"), int.from_bytes(data[6:8], "big")
        i = 12
        for _ in range(qd):
            i = _skip_name(data, i) + 4
        ips = []
        for _ in range(an):
            i = _skip_name(data, i)
            rtype, rlen = int.from_bytes(data[i:i + 2], "big"), int.from_bytes(data[i + 8:i + 10], "big")
            i += 10
            if rtype == 1 and rlen == 4 and i + 4 <= len(data):
                ip = ".".join(str(b) for b in data[i:i + 4])
                if not ipaddress.ip_address(ip).is_unspecified:
                    ips.append(ip)
            i += rlen
        return ips
    except (IndexError, ValueError):
        return []


def doh_resolve(host: str, timeout: float = 6.0) -> list[str]:
    """IPv4-адреса сайта через защищённый DNS — в обход DNS провайдера. [] — не узнали."""
    try:
        ipaddress.ip_address(host)
        return []  # это уже адрес
    except ValueError:
        pass
    host = (host or "").lower().rstrip(".")
    if not host or len(host) > 253:
        return []
    hit = _DOH_CACHE.get(host)
    if hit and time.time() - hit[0] < DOH_TTL:
        return list(hit[1])
    try:
        q = base64.urlsafe_b64encode(dns_query(host)).decode().rstrip("=")
    except (ValueError, UnicodeError):
        return []
    for url, pin_host, pin_ip in DOH_SERVERS:
        try:
            status, _, body = http_get(f"{url}?dns={q}", timeout=timeout, max_bytes=65536,
                                       headers={"Accept": "application/dns-message"},
                                       pin={pin_host: pin_ip} if pin_host else None)
            ips = dns_answers(body) if status == 200 else []
            if ips:
                _DOH_CACHE[host] = (time.time(), ips)
                return ips
        except Exception:
            continue
    return []


def human_error(exc: Exception) -> str:
    if isinstance(exc, urllib.error.URLError) and exc.reason:
        reason = exc.reason
        if isinstance(reason, Exception):
            return _human_error(reason)
        return str(reason)[:120]
    return _human_error(exc)


def speed_test(proxy_port: int | None, urls: list[str], seconds: float = 8.0, stop_event=None) -> dict:
    """Скорость скачивания в Мбит/с. Время считается после получения заголовков ответа."""
    last_error = ""
    for url in urls:
        req = urllib.request.Request(url, headers={"User-Agent": BROWSER_UA})
        try:
            with make_opener(proxy_port).open(req, timeout=12) as resp:
                t0 = time.perf_counter()
                total = 0
                while True:
                    chunk = resp.read(128 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if time.perf_counter() - t0 >= seconds or (stop_event and stop_event.is_set()):
                        break
                elapsed = max(time.perf_counter() - t0, 0.001)
            if total < 64 * 1024:
                last_error = "слишком мало данных"
                continue
            return {"ok": True, "mbps": round(total * 8 / elapsed / 1_000_000, 1), "bytes": total, "error": ""}
        except Exception as exc:  # пробуем следующий адрес
            last_error = human_error(exc)
    return {"ok": False, "mbps": None, "bytes": 0, "error": last_error or "не удалось"}


DATA_NEED = 64 * 1024  # «данные идут» — значит, скачались хотя бы 64 КБ (пинг в 2026 году часто проходит, а данные — нет)


def data_check(proxy_port: int | None, urls: list[str], need: int = DATA_NEED, timeout: float = 8.0,
               stop_event=None) -> dict:
    """Идут ли через подключение настоящие данные: скачать need байт. {"ok", "bytes", "ms", "error"}.
    Ловит «подключено, но пусто» и замирание после первых килобайт, которые пинг не видит.
    Если все проверочные адреса ответили ошибкой HTTP (403, 404…) — данные через туннель всё же ходят, просто
    адреса недоступны: результат ok с пометкой inconclusive, чтобы не забраковать рабочий сервер."""
    last = ""
    got_max = 0
    http_errors = 0
    broken = 0
    stalled = False
    for url in urls:
        if stop_event and stop_event.is_set():
            break
        req = urllib.request.Request(url, headers={"User-Agent": BROWSER_UA})
        t0 = time.perf_counter()
        got = 0
        try:
            with make_opener(proxy_port).open(req, timeout=timeout) as resp:
                while got < need and time.perf_counter() - t0 < timeout:
                    chunk = resp.read(min(65536, need - got))
                    if not chunk:
                        break
                    got += len(chunk)
        except urllib.error.HTTPError as exc:
            http_errors += 1
            last = f"код {exc.code}"
            continue
        except Exception as exc:
            last = human_error(exc)
        if got >= need:
            return {"ok": True, "bytes": got, "ms": int((time.perf_counter() - t0) * 1000), "error": ""}
        got_max = max(got_max, got)
        if got:
            last = f"данные замерли после {max(1, got // 1024)} КБ"
            stalled = True
        broken += 1
        if broken >= 2:
            break  # два адреса подряд не качаются — дело в подключении, а не в адресах
    if http_errors and not stalled:  # ответ через туннель пришёл — просто адрес недоступен
        return {"ok": True, "bytes": 0, "ms": None, "error": "", "inconclusive": True}
    return {"ok": False, "bytes": got_max, "ms": None, "error": last or "данные не идут"}


def lan_ip() -> str:
    """Адрес этого компьютера в домашней сети (для подключения других устройств). Пакеты не отправляются."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.168.0.1", 9))
        ip = sock.getsockname()[0]
        return "" if ip.startswith("127.") else ip
    except OSError:
        return ""
    finally:
        sock.close()
