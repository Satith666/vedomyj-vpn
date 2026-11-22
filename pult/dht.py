"""Сеть торрентов (Mainline DHT) как почтовый ящик «Семьи» — без своих серверов (1.22).

Как это устроено:
  • DHT — общая «доска объявлений» торрент-клиентов: миллионы компьютеров хранят понемногу записей по их адресу.
    По BEP 44 туда можно положить свою запись до 1000 байт, подписанную ключом ed25519, и потом обновлять её
    (номер записи растёт). Записи живут около двух часов — отправитель перекладывает их, пока посылка нужна;
  • ключ записи у пары «помощник — устройство» общий и выводится из секрета пары (как ключи шифрования):
    положить посылку может только тот, у кого есть секрет; прочитать — только он же (посылка и так зашифрована);
  • программа — «клиент только для чтения» (BEP 43, "ro"): сама записи чужих не хранит и в чужие таблицы
    не попадает. Узлы сети видят адрес компьютера (как у любого торрент-клиента), но не содержимое;
  • ed25519 (RFC 8032) и bencode написаны здесь же, без сторонних библиотек; проверка — по официальным
    тестовым значениям (RFC 8032, BEP 44) в самопроверке.
Телефон — core/Dht.java, формат тот же (сверка в android/coretest/run.sh).
"""

from __future__ import annotations

import hashlib
import os
import secrets
import select
import socket
import struct
import time

BOOTSTRAP = (("router.bittorrent.com", 6881), ("dht.transmissionbt.com", 6881), ("router.utorrent.com", 6881),
             ("dht.libtorrent.org", 25401))
K = 8                 # столько ближайших узлов хранят запись
ALPHA = 4             # запросов одновременно
MAX_V = 1000          # bencode значения — не длиннее (BEP 44)
MAX_SALT = 64
LOOKUP_S = 12.0       # поиск целиком — не дольше
QUERY_S = 2.0         # ответ узла — не дольше


class DhtError(RuntimeError):
    pass


# ---------- bencode ----------

def bencode(v) -> bytes:
    if isinstance(v, bool):
        v = int(v)
    if isinstance(v, int):
        return b"i%de" % v
    if isinstance(v, str):
        v = v.encode("utf-8")
    if isinstance(v, (bytes, bytearray)):
        return b"%d:" % len(v) + bytes(v)
    if isinstance(v, (list, tuple)):
        return b"l" + b"".join(bencode(x) for x in v) + b"e"
    if isinstance(v, dict):
        items = sorted(((k.encode("utf-8") if isinstance(k, str) else bytes(k)), x) for k, x in v.items())
        return b"d" + b"".join(bencode(k) + bencode(x) for k, x in items) + b"e"
    raise TypeError(f"bencode: {type(v).__name__}")


def bdecode(data: bytes, max_depth: int = 16):
    """Строгий разбор: ключи словаря — байты; лишние байты в конце — ошибка."""
    def parse(i: int, depth: int):
        if depth > max_depth:
            raise ValueError("bencode: слишком глубоко")
        if i >= len(data):
            raise ValueError("bencode: обрыв")
        c = data[i:i + 1]
        if c == b"i":
            j = data.index(b"e", i)
            text = data[i + 1:j]
            if not text or (text[:1] == b"0" and len(text) > 1) or text.startswith(b"-0") or \
                    not text.lstrip(b"-").isdigit():
                raise ValueError("bencode: неверное число")
            return int(text), j + 1
        if c == b"l":
            out, i = [], i + 1
            while data[i:i + 1] != b"e":
                x, i = parse(i, depth + 1)
                out.append(x)
            return out, i + 1
        if c == b"d":
            out, i = {}, i + 1
            while data[i:i + 1] != b"e":
                k, i = parse(i, depth + 1)
                if not isinstance(k, bytes):
                    raise ValueError("bencode: ключ не строка")
                out[k], i = parse(i, depth + 1)
            return out, i + 1
        if c.isdigit():
            j = data.index(b":", i)
            n = int(data[i:j])
            if j + 1 + n > len(data):
                raise ValueError("bencode: обрыв строки")
            return data[j + 1:j + 1 + n], j + 1 + n
        raise ValueError("bencode: неизвестный тип")
    try:
        v, end = parse(0, 0)
    except IndexError:
        raise ValueError("bencode: обрыв") from None
    if end != len(data):
        raise ValueError("bencode: лишние байты")
    return v


# ---------- ed25519 (RFC 8032) ----------

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P:
        x = x * _I % _P
    if x % 2:
        x = _P - x
    return x


_BY = 4 * _inv(5) % _P
_BX = _xrecover(_BY)
_B = (_BX, _BY, 1, _BX * _BY % _P)


def _add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    dd = z1 * 2 * z2 % _P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s: int, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _encode(p) -> bytes:
    x, y, z, _ = p
    zi = _inv(z)
    x, y = x * zi % _P, y * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode(b: bytes):
    if len(b) != 32:
        raise ValueError("ed25519: неверная длина точки")
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        raise ValueError("ed25519: неверная точка")
    xx = (y * y - 1) * _inv(_D * y * y + 1) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P:
        x = x * _I % _P
    if (x * x - xx) % _P:
        raise ValueError("ed25519: точки нет на кривой")
    if x == 0 and sign:
        raise ValueError("ed25519: неверная точка")
    if (x & 1) != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


def _eq(p, q) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _h(*parts: bytes) -> int:
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little")


def ed_expand(seed: bytes) -> bytes:
    """Секрет 32 байта → «развёрнутый» ключ 64 байта (скаляр + префикс), как в BEP 44."""
    h = bytearray(hashlib.sha512(seed).digest())
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return bytes(h)


def ed_public(expanded: bytes) -> bytes:
    return _encode(_mul(int.from_bytes(expanded[:32], "little"), _B))


def ed_sign(expanded: bytes, msg: bytes, public: bytes | None = None) -> bytes:
    a = int.from_bytes(expanded[:32], "little")
    pub = public or ed_public(expanded)
    r = _h(expanded[32:64], msg) % _L
    big_r = _encode(_mul(r, _B))
    s = (r + _h(big_r, pub, msg) * a) % _L
    return big_r + s.to_bytes(32, "little")


def ed_verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    if len(sig) != 64 or len(public) != 32:
        return False
    try:
        a = _decode(public)
        r = _decode(sig[:32])
    except ValueError:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    return _eq(_mul(s, _B), _add(r, _mul(_h(sig[:32], public, msg) % _L, a)))


# ---------- записи BEP 44 ----------

def target(k: bytes, salt: bytes = b"") -> bytes:
    return hashlib.sha1(k + salt).digest()


def sign_buf(salt: bytes, seq: int, v_bencoded: bytes) -> bytes:
    """Что подписывается: «4:salt6:foobar3:seqi4e1:v12:Hello world!» (без соли — без первой части)."""
    return (b"4:salt" + bencode(salt) if salt else b"") + b"3:seqi%de1:v" % seq + v_bencoded


class Keys:
    """Ключ записи пары: из 32 байт секрета (общий у обеих сторон)."""

    def __init__(self, seed: bytes):
        if len(seed) != 32:
            raise ValueError("нужен секрет 32 байта")
        self.expanded = ed_expand(seed)
        self.public = ed_public(self.expanded)

    def item(self, salt: bytes, seq: int, v) -> dict:
        vb = bencode(v)
        if len(vb) > MAX_V or len(salt) > MAX_SALT:
            raise DhtError("запись слишком большая")
        return {"k": self.public, "salt": salt, "seq": seq, "v": v,
                "sig": ed_sign(self.expanded, sign_buf(salt, seq, vb), self.public)}


def check_item(k: bytes, salt: bytes, r: dict) -> tuple[int, object] | None:
    """Ответ узла с записью → (номер, значение), если запись нашего ключа и подпись верна."""
    if r.get(b"k") != k or not isinstance(r.get(b"seq"), int) or b"v" not in r or not isinstance(r.get(b"sig"), bytes):
        return None
    vb = bencode(r[b"v"])
    if len(vb) > MAX_V or not ed_verify(k, sign_buf(salt, r[b"seq"], vb), r[b"sig"]):
        return None
    return r[b"seq"], r[b"v"]


# ---------- клиент KRPC ----------

def _nodes(blob) -> list[tuple[bytes, tuple[str, int]]]:
    out = []
    if not isinstance(blob, bytes):
        return out
    for i in range(0, len(blob) - len(blob) % 26, 26):
        nid = blob[i:i + 20]
        ip = socket.inet_ntoa(blob[i + 20:i + 24])
        port = struct.unpack(">H", blob[i + 24:i + 26])[0]
        if port and (_LOCAL_OK or not ip.startswith(("0.", "127.", "255."))):
            out.append((nid, (ip, port)))
    return out


_LOCAL_OK = False  # самопроверка: узлы сети — на этом же компьютере


def _dist(a: bytes, b: bytes) -> int:
    return int.from_bytes(a, "big") ^ int.from_bytes(b, "big")


class Client:
    """Один поиск или запись — один сокет. Не узел сети: на чужие запросы не отвечает (BEP 43, ro=1)."""

    def __init__(self, bootstrap=BOOTSTRAP, timeout: float = LOOKUP_S, stop=None):
        self.bootstrap = list(bootstrap)
        self.timeout = timeout
        self.stop = stop
        self.nid = secrets.token_bytes(20)

    def _addrs(self) -> list[tuple[str, int]]:
        out = []
        for host, port in self.bootstrap:
            try:
                for info in socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM):
                    out.append(info[4][:2])
            except OSError:
                continue
        return list(dict.fromkeys(out))

    def _exchange(self, sock, queries: list[tuple[tuple[str, int], bytes, dict]], wait: float) -> list:
        """Отправить запросы, собрать ответы за wait секунд → [(адрес, r)]."""
        pending = {}
        for addr, q, a in queries:
            tid = secrets.token_bytes(4)
            msg = {"t": tid, "y": "q", "q": q, "a": dict(a, id=self.nid), "ro": 1}
            try:
                sock.sendto(bencode(msg), addr)
                pending[tid] = addr
            except OSError:
                continue
        out = []
        end = time.monotonic() + wait
        while pending and time.monotonic() < end:
            if self.stop is not None and self.stop.is_set():
                break
            r, _, _ = select.select([sock], [], [], max(0.0, min(0.25, end - time.monotonic())))
            if not r:
                continue
            try:
                data, src = sock.recvfrom(4096)
                msg = bdecode(data)
            except (OSError, ValueError):
                continue
            if not isinstance(msg, dict):
                continue
            addr = pending.get(msg.get(b"t"))
            if addr is None or addr[0] != src[0]:
                continue
            del pending[msg[b"t"]]
            if msg.get(b"y") == b"r" and isinstance(msg.get(b"r"), dict):
                out.append((addr, msg[b"r"]))
            elif msg.get(b"y") == b"e":
                out.append((addr, {b"_error": msg.get(b"e")}))
        return out

    def lookup(self, tgt: bytes, check=None) -> tuple[list, object]:
        """Поиск ближайших к tgt узлов запросом get (BEP 44). check(r) → найденная запись или None.
        → ([(расстояние, id, адрес, token)] ближайших ответивших, лучшая найденная запись)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("0.0.0.0", 0))
            seen: set = set()
            cands: dict = {}           # адрес → id (b"" — ещё не знаем)
            for addr in self._addrs():
                cands[addr] = b""
            done: dict = {}            # адрес → (id, token)
            best = None
            end = time.monotonic() + self.timeout
            while time.monotonic() < end:
                if self.stop is not None and self.stop.is_set():
                    break
                order = sorted((a for a in cands if a not in seen),
                               key=lambda a: (cands[a] != b"", _dist(cands[a], tgt) if cands[a] else 0))
                closest = sorted(((_dist(i, tgt), a) for a, (i, _) in done.items()))[:K]
                if closest and order:
                    worst = closest[-1][0] if len(closest) >= K else None
                    order = [a for a in order if not cands[a] or worst is None or _dist(cands[a], tgt) < worst]
                if not order:
                    break
                batch = order[:ALPHA * 2]
                for a in batch:
                    seen.add(a)
                for addr, r in self._exchange(sock, [(a, "get", {"target": tgt}) for a in batch],
                                              min(QUERY_S, max(0.2, end - time.monotonic()))):
                    if b"_error" in r:
                        continue
                    nid = r.get(b"id")
                    if not isinstance(nid, bytes) or len(nid) != 20:
                        continue
                    done[addr] = (nid, r.get(b"token") if isinstance(r.get(b"token"), bytes) else b"")
                    if check:
                        got = check(r)
                        if got is not None and (best is None or got[0] > best[0]):
                            best = got
                    for n_id, n_addr in _nodes(r.get(b"nodes")):
                        if n_addr not in cands and len(cands) < 2000:
                            cands[n_addr] = n_id
            res = sorted((_dist(i, tgt), i, a, tok) for a, (i, tok) in done.items())[:K]
            return res, best
        finally:
            sock.close()

    def get(self, k: bytes, salt: bytes = b"") -> tuple[int, object] | None:
        """Свежая запись ключа k с солью salt: (номер, значение) или None."""
        _, best = self.lookup(target(k, salt), lambda r: check_item(k, salt, r))
        return best

    def put(self, item: dict) -> int:
        """Положить запись (Keys.item) на ближайшие узлы → сколько узлов приняли."""
        k, salt = item["k"], item["salt"]
        closest, best = self.lookup(target(k, salt), lambda r: check_item(k, salt, r))
        if best is not None and best[0] > item["seq"]:
            raise DhtError("в сети уже есть запись новее")
        args = [(addr, "put", dict({"k": k, "seq": item["seq"], "sig": item["sig"], "v": item["v"], "token": tok},
                                   **({"salt": salt} if salt else {})))
                for _, _, addr, tok in closest if tok]
        if not args:
            return 0
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("0.0.0.0", 0))
            return sum(1 for _, r in self._exchange(sock, args, QUERY_S * 1.5) if b"_error" not in r)
        finally:
            sock.close()


# ---------- узел для самопроверки (в программе не запускается) ----------

class LocalNode:
    """Простой узел сети на 127.0.0.1: отвечает на get/put/find_node/ping, хранит записи (с проверкой подписи
    и номера). Знает соседей — для поиска в несколько шагов."""

    def __init__(self, peers: list | None = None):
        import threading
        self.nid = secrets.token_bytes(20)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.addr = self.sock.getsockname()
        self.peers: list = list(peers or [])   # [(id, адрес)]
        self.store: dict = {}
        self.secret = os.urandom(8)
        self.puts = 0
        self.alive = True
        threading.Thread(target=self._loop, daemon=True).start()

    def _token(self, ip: str) -> bytes:
        return hashlib.sha1(self.secret + ip.encode()).digest()[:8]

    def _compact(self) -> bytes:
        return b"".join(nid + socket.inet_aton(a[0]) + struct.pack(">H", a[1]) for nid, a in self.peers[:8])

    def _loop(self):
        while self.alive:
            try:
                data, src = self.sock.recvfrom(4096)
                msg = bdecode(data)
                q, a = msg[b"q"], msg[b"a"]
            except (OSError, ValueError, KeyError, TypeError):
                if not self.alive:
                    return
                continue
            r: dict = {"id": self.nid}
            err = None
            if q in (b"get", b"find_node"):
                r["nodes"] = self._compact()
                r["token"] = self._token(src[0])
                it = self.store.get(a.get(b"target"))
                if q == b"get" and it:
                    r.update(it)
            elif q == b"put":
                salt = a.get(b"salt", b"")
                ok = a.get(b"token") == self._token(src[0]) and isinstance(a.get(b"seq"), int)
                tgt = target(a.get(b"k", b""), salt)
                old = self.store.get(tgt)
                if not ok:
                    err = [203, "bad token"]
                elif not ed_verify(a.get(b"k", b""), sign_buf(salt, a[b"seq"], bencode(a.get(b"v"))), a.get(b"sig", b"")):
                    err = [206, "invalid signature"]
                elif old and old["seq"] > a[b"seq"]:
                    err = [302, "sequence number less than current"]
                else:
                    self.store[tgt] = {"k": a[b"k"], "seq": a[b"seq"], "sig": a[b"sig"], "v": a[b"v"]}
                    self.puts += 1
            reply = {"t": msg.get(b"t", b""), "y": "e", "e": err} if err else {"t": msg.get(b"t", b""), "y": "r", "r": r}
            try:
                self.sock.sendto(bencode(reply), src)
            except OSError:
                pass

    def close(self):
        self.alive = False
        try:
            self.sock.close()
        except OSError:
            pass
