"""Блокировка рекламы «через DNS»: программа сама отвечает компьютеру (и, по желанию, всему дому), какой адрес
у сайта. Рекламный адрес → 0.0.0.0 (для IPv6 — ::), остальное — спрашиваем у прежнего DNS и отдаём ответ.

Так реклама закрывается во всех программах — и в тех, что не слушают системный прокси, — без VPN и без TUN.
Списки — те же, что у блокировки в ядре (adblock.dat): своих сайтов, исключений и встроенной защиты.

Сервер маленький и осторожный:
- отвечает только на обычные запросы (одна запись в вопросе), остальное честно передаёт выше;
- запросы выше — только к прежним DNS компьютера (их программа запомнила перед включением) по UDP, ответ
  проверяется по номеру запроса и вопросу, кэш — не дольше 5 минут;
- в журнал не пишет, какие сайты спрашивали (только счётчики и закрытую рекламу — как журнал рекламы ядра).
"""

from __future__ import annotations

import collections
import ipaddress
import socket
import struct
import threading
import time

from . import adblock

BLOCK_TTL = 60
CACHE_MAX_TTL = 300
CACHE_SIZE = 2000
UPSTREAM_TIMEOUT = 2.5
MAX_PACKET = 4096
QTYPE_A, QTYPE_AAAA = 1, 28


def parse_question(data: bytes) -> tuple[str, int, int] | None:
    """(имя, тип, конец вопроса) или None, если это не обычный запрос с одним вопросом."""
    if len(data) < 17:
        return None
    flags, qd = struct.unpack(">HH", data[2:6])
    if flags & 0x8000 or (flags >> 11) & 0xF or qd != 1:  # ответ, не QUERY или вопросов не один
        return None
    i, labels = 12, []
    while True:
        if i >= len(data):
            return None
        n = data[i]
        i += 1
        if n == 0:
            break
        if n & 0xC0 or i + n > len(data):
            return None  # в вопросе сжатия не бывает
        try:
            labels.append(data[i:i + n].decode("ascii").lower())
        except UnicodeDecodeError:
            return None
        i += n
    if i + 4 > len(data):
        return None
    qtype, _qclass = struct.unpack(">HH", data[i:i + 4])
    return ".".join(labels), qtype, i + 4


def blocked_answer(query: bytes, qtype: int, qend: int) -> bytes:
    """Ответ «0.0.0.0» (A), «::» (AAAA) или пустой ответ (другие типы) — без ошибки, чтобы программы не повторяли."""
    rd = query[2] & 0x01
    flags = 0x8000 | (rd << 8) | 0x0080  # ответ, RD как в вопросе, RA
    if qtype == QTYPE_A:
        rdata = b"\x00\x00\x00\x00"
    elif qtype == QTYPE_AAAA:
        rdata = b"\x00" * 16
    else:
        rdata = b""
    an = 1 if rdata else 0
    head = query[:2] + struct.pack(">HHHHH", flags, 1, an, 0, 0)
    body = query[12:qend]
    if rdata:
        body += b"\xc0\x0c" + struct.pack(">HHIH", qtype, 1, BLOCK_TTL, len(rdata)) + rdata
    return head + body


def _min_ttl(resp: bytes, qend: int) -> int:
    """Наименьший TTL в ответах (для кэша); 0 — не кэшировать."""
    try:
        an = struct.unpack(">H", resp[6:8])[0]
        i, ttl = qend, CACHE_MAX_TTL
        for _ in range(an):
            if resp[i] & 0xC0 == 0xC0:
                i += 2
            else:
                while resp[i]:
                    i += resp[i] + 1
                i += 1
            _t, _c, t, ln = struct.unpack(">HHIH", resp[i:i + 10])
            ttl = min(ttl, t)
            i += 10 + ln
        return ttl if an else 0
    except (IndexError, struct.error):
        return 0


class DnsFilter:
    """DNS-сервер с блокировкой рекламы. upstreams — прежние DNS компьютера (IP)."""

    def __init__(self, upstreams: list[str], log=None, on_block=None):
        self.upstreams = [u for u in upstreams if _valid_upstream(u)]
        self.domains: set[str] = set()
        self.log = log or (lambda text: None)
        self.on_block = on_block or (lambda host: None)
        self.socks: list[socket.socket] = []
        self.threads: list[threading.Thread] = []
        self.running = False
        self.cache: collections.OrderedDict = collections.OrderedDict()
        self.stats = {"queries": 0, "blocked": 0, "failed": 0}
        self._lock = threading.Lock()

    # ---------- списки ----------

    def set_domains(self, domains: set[str]) -> None:
        self.domains = set(domains)
        with self._lock:
            self.cache.clear()

    def is_blocked(self, host: str) -> bool:
        return bool(host) and adblock.is_blocked(host, self.domains)

    # ---------- ответ на запрос ----------

    def answer(self, query: bytes) -> bytes | None:
        q = parse_question(query)
        self.stats["queries"] += 1
        if not q:
            return self._forward(query)
        name, qtype, qend = q
        if self.is_blocked(name):
            self.stats["blocked"] += 1
            self.on_block(name)
            return blocked_answer(query, qtype, qend)
        key = (name, qtype)
        with self._lock:
            hit = self.cache.get(key)
            if hit and hit[0] > time.monotonic():
                self.cache.move_to_end(key)
                return query[:2] + hit[1][2:]
        resp = self._forward(query)
        if resp and len(resp) >= 12 and resp[12:qend] == query[12:qend]:
            ttl = _min_ttl(resp, qend)
            if ttl > 0:
                with self._lock:
                    self.cache[key] = (time.monotonic() + ttl, resp)
                    while len(self.cache) > CACHE_SIZE:
                        self.cache.popitem(last=False)
        return resp

    def _forward(self, query: bytes) -> bytes | None:
        for up in self.upstreams:
            fam = socket.AF_INET6 if ":" in up else socket.AF_INET
            s = socket.socket(fam, socket.SOCK_DGRAM)
            s.settimeout(UPSTREAM_TIMEOUT)
            try:
                s.sendto(query, (up, 53))
                while True:
                    resp, addr = s.recvfrom(MAX_PACKET)
                    if addr[0] == up and resp[:2] == query[:2]:  # чужие и поддельные пакеты — мимо
                        return resp
            except OSError:
                continue
            finally:
                s.close()
        self.stats["failed"] += 1
        return None

    # ---------- сервер ----------

    def start(self, hosts: list[str], port: int = 53) -> None:
        """Слушает UDP и TCP на каждом адресе. Порт занят — OSError (с понятным текстом наверху)."""
        self.stop()
        socks = []
        try:
            for h in hosts:
                fam = socket.AF_INET6 if ":" in h else socket.AF_INET
                u = socket.socket(fam, socket.SOCK_DGRAM)
                u.bind((h, port))
                socks.append(u)
                t = socket.socket(fam, socket.SOCK_STREAM)
                t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                t.bind((h, port))
                t.listen(16)
                socks.append(t)
        except OSError:
            for s in socks:
                s.close()
            raise
        self.socks = socks
        self.running = True
        self.threads = []
        for s in socks:
            s.settimeout(0.5)  # раз в полсекунды смотрим, не пора ли остановиться (закрытие не будит recv в Linux)
            target = self._serve_udp if s.type == socket.SOCK_DGRAM else self._serve_tcp
            th = threading.Thread(target=target, args=(s,), daemon=True)
            th.start()
            self.threads.append(th)

    def stop(self) -> None:
        self.running = False
        for th in self.threads:  # потоки выходят сами за полсекунды — тогда порт точно свободен
            th.join(2)
        for s in self.socks:
            try:
                s.close()
            except OSError:
                pass
        self.socks, self.threads = [], []

    def _serve_udp(self, s: socket.socket) -> None:
        while self.running:
            try:
                data, addr = s.recvfrom(MAX_PACKET)
            except socket.timeout:
                continue
            except OSError:
                if not self.running:
                    return
                continue  # Windows: ICMP «порт закрыт» от прошлого ответа — не повод останавливаться
            threading.Thread(target=self._reply_udp, args=(s, data, addr), daemon=True).start()

    def _reply_udp(self, s: socket.socket, data: bytes, addr) -> None:
        try:
            resp = self.answer(data)
            if resp:
                s.sendto(resp, addr)
        except OSError:
            pass

    def _serve_tcp(self, s: socket.socket) -> None:
        while self.running:
            try:
                c, _ = s.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._reply_tcp, args=(c,), daemon=True).start()

    def _reply_tcp(self, c: socket.socket) -> None:
        c.settimeout(10)
        try:
            head = c.recv(2)
            if len(head) < 2:
                return
            n = struct.unpack(">H", head)[0]
            data = b""
            while len(data) < n:
                chunk = c.recv(n - len(data))
                if not chunk:
                    return
                data += chunk
            resp = self.answer(data)
            if resp:
                c.sendall(struct.pack(">H", len(resp)) + resp)
        except OSError:
            pass
        finally:
            c.close()


def _valid_upstream(ip: str) -> bool:
    """Выше спрашиваем только настоящий DNS: не себя (127.x, ::1) и не «пустые» адреса."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_loopback or a.is_unspecified or a.is_multicast)
