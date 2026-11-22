"""Бесплатный WARP (Cloudflare) своим конфигом AmneziaWG — без сайтов-генераторов.

Как это устроено:
  • ключи (X25519) создаются здесь же; закрытый ключ никуда не отправляется, Cloudflare получает только открытый;
  • регистрация — тот же запрос, что делает приложение 1.1.1.1 для Android (api.cloudflareclient.com или
    запасной адрес api.devices.cloudflare.com); если VPN включён — через него, иначе напрямую;
  • сервер Cloudflare — обычный WireGuard, поэтому из маскировки AmneziaWG работает только то, что
    не меняет сами пакеты WireGuard: «мусорные» пакеты перед подключением (Jc/Jmin/Jmax) и пакет-обманка I1,
    похожий на начало обычного протокола (QUIC, DNS, STUN, SIP). S1–S4 = 0, H1–H4 = 1…4 — иначе Cloudflare
    не поймёт пакеты;
  • наборов обманок несколько (адрес и порт Cloudflare + вид пакета I1): если один не пробивает блокировку,
    программа пробует следующий и запоминает рабочий для этой сети.

Python без сторонних библиотек: X25519 (RFC 7748) и AES-128 (FIPS-197, нужен только для пакета-обманки QUIC)
написаны здесь, проверяются по официальным тестовым значениям в самопроверке.
Идея наборов обманок и генераторов I1 — по мотивам warpscout (MIT, (c) 2026 Nikita S.) и wgcf (MIT, (c) 2020 ViRb3).
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import re
import secrets
import ssl
import struct
import urllib.error
import urllib.request

# Открытый ключ сервера WARP — один на всех (по нему программа узнаёт конфиги WARP, в том числе с сайтов).
PEER_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
# Что сообщает о себе приложение 1.1.1.1 для Android (как в wgcf 2.3, октябрь 2026).
API_VERSION = "v0a5641"
CLIENT_VERSION = "a-6.38.9-5641"
USER_AGENT = "1.1.1.1/6.38.9-5641 (Android 16.0.0)"
API_HOSTS = ("api.cloudflareclient.com", "api.devices.cloudflare.com")
TRACE_URL = "https://1.1.1.1/cdn-cgi/trace"  # через WARP отвечает «warp=on»
NAME = "WARP (бесплатный)"

# ---------- X25519 (RFC 7748) ----------

_P = 2 ** 255 - 19
_A24 = 121665


def x25519(scalar: bytes, u: bytes) -> bytes:
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    n = int.from_bytes(k, "little")
    ub = bytearray(u)
    ub[31] &= 127
    x1 = int.from_bytes(ub, "little") % _P
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        bit = (n >> t) & 1
        if swap ^ bit:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % _P, (x2 - z2) % _P
        aa, bb = a * a % _P, b * b % _P
        e = (aa - bb) % _P
        c, d = (x3 + z3) % _P, (x3 - z3) % _P
        da, cb = d * a % _P, c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def keypair(seed: bytes | None = None) -> tuple[str, str]:
    """(закрытый, открытый) ключ WireGuard в base64."""
    priv = bytearray(seed if seed is not None else secrets.token_bytes(32))
    priv[0] &= 248
    priv[31] &= 127
    priv[31] |= 64
    pub = x25519(bytes(priv), (9).to_bytes(32, "little"))
    return base64.b64encode(bytes(priv)).decode(), base64.b64encode(pub).decode()


def public_of(private_b64: str) -> str:
    return base64.b64encode(x25519(base64.b64decode(private_b64), (9).to_bytes(32, "little"))).decode()


# ---------- AES-128, только шифрование блока (FIPS-197) ----------

def _rotl8(x: int, s: int) -> int:
    return ((x << s) | (x >> (8 - s))) & 0xFF


def _make_sbox() -> list[int]:
    sbox = [0] * 256
    p = q = 1
    while True:
        p = (p ^ (p << 1) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        sbox[p] = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4) ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


_SBOX = _make_sbox()


def _xtime(b: int) -> int:
    return ((b << 1) ^ 0x1B) & 0xFF if b & 0x80 else b << 1


def _expand_key(key: bytes) -> list[list[int]]:
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [_SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [sum(w[r * 4:r * 4 + 4], []) for r in range(11)]


def aes128_block(key: bytes, block: bytes) -> bytes:
    return _encrypt_rk(_expand_key(key), block)


def aes128_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-128-CTR (счётчик — все 16 байт, big-endian, как AES/CTR/NoPadding в Java). Шифрование = расшифровка."""
    rk = _expand_key(key)
    n = int.from_bytes(iv, "big")
    out = bytearray()
    for i in range(0, len(data), 16):
        ks = _encrypt_rk(rk, ((n + i // 16) % (1 << 128)).to_bytes(16, "big"))
        out += bytes(a ^ b for a, b in zip(data[i:i + 16], ks))
    return bytes(out)


def _encrypt_rk(rk: list, block: bytes) -> bytes:
    s = [b ^ k for b, k in zip(block, rk[0])]
    for rnd in range(1, 11):
        s = [_SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]  # ShiftRows (столбцы по 4 байта)
        if rnd != 10:
            out = []
            for c in range(4):
                a = s[c * 4:c * 4 + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                out += [a[i] ^ t ^ _xtime(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
            s = out
        s = [b ^ k for b, k in zip(s, rk[rnd])]
    return bytes(s)


# ---------- пакеты-обманки I1 (формат CPS AmneziaWG: <b 0x…> байты, <r N> случайные, <rc N> буквы, <rd N> цифры) ----------

class _Chain:
    def __init__(self):
        self.parts: list[str] = []

    def raw(self, b: bytes) -> "_Chain":
        if b:
            self.parts.append(f"<b 0x{b.hex()}>")
        return self

    def text(self, s: str) -> "_Chain":
        return self.raw(s.encode())

    def tag(self, name: str, n: int) -> "_Chain":
        self.parts.append(f"<{name} {n}>")
        return self

    def __str__(self) -> str:
        return "".join(self.parts)


def _varint(x: int) -> bytes:
    if x < 0x40:
        return bytes([x])
    if x < 0x4000:
        return struct.pack(">H", x | 0x4000)
    return struct.pack(">I", x | 0x80000000)


def _hkdf_label(secret: bytes, label: str, length: int) -> bytes:
    full = b"tls13 " + label.encode()
    info = struct.pack(">H", length) + bytes([len(full)]) + full + b"\x00"
    return hmac.new(secret, info + b"\x01", hashlib.sha256).digest()[:length]


QUIC_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


def quic_keys(dcid: bytes) -> tuple[bytes, bytes, bytes]:
    """Ключи пакета Initial клиента (RFC 9001, 5.2): key, iv, hp."""
    initial = hmac.new(QUIC_SALT, dcid, hashlib.sha256).digest()
    client = _hkdf_label(initial, "client in", 32)
    return _hkdf_label(client, "quic key", 16), _hkdf_label(client, "quic iv", 12), _hkdf_label(client, "quic hp", 16)


def _ext(kind: int, data: bytes) -> bytes:
    return struct.pack(">HH", kind, len(data)) + data


def client_hello(sni: str, key_share: bytes) -> tuple[bytes, int]:
    """ClientHello TLS 1.3 для QUIC: (сообщение, где начинаются 32 байта random)."""
    name = sni.encode()
    tp = (b"\x01\x04" + struct.pack(">I", 0x80007530)        # max_idle_timeout 30 с
          + b"\x04\x04" + struct.pack(">I", 0x80F00000)      # initial_max_data
          + b"\x08\x02" + struct.pack(">H", 0x4064)          # initial_max_streams_bidi 100
          + b"\x0f\x00")                                     # initial_source_connection_id (пустой)
    exts = (_ext(0, struct.pack(">HBH", len(name) + 3, 0, len(name)) + name)
            + _ext(0x0A, bytes.fromhex("0004001d0017"))                       # группы: x25519, secp256r1
            + _ext(0x0D, bytes.fromhex("000a04030804040105030805"))           # подписи
            + _ext(0x10, bytes.fromhex("0003026833"))                         # ALPN h3
            + _ext(0x2B, bytes.fromhex("020304"))                             # TLS 1.3
            + _ext(0x33, struct.pack(">HHH", 36, 0x1D, 32) + key_share)       # key_share x25519
            + _ext(0x2D, bytes.fromhex("0101"))                               # psk_key_exchange_modes
            + _ext(0x39, tp))                                                 # параметры QUIC
    body = (b"\x03\x03" + bytes(32) + b"\x00" + bytes.fromhex("0006130113021303") + b"\x01\x00"
            + struct.pack(">H", len(exts)) + exts)
    return b"\x01" + len(body).to_bytes(3, "big") + body, 4 + 2


QUIC_SIZE = 1200  # настоящий первый пакет QUIC не короче 1200 байт


def quic_i1(sni: str, dcid: bytes, key_share: bytes) -> str:
    """Первый пакет QUIC (Initial) к сайту sni. Расшифровать его может любой (так устроен QUIC) — оборудование
    провайдера видит обычное начало соединения с этим сайтом. 32 байта random и метка проверки — случайные
    в каждом пакете (<r …>), остальное — постоянное."""
    hello, rand_at = client_hello(sni, key_share)
    frame = b"\x06" + _varint(0) + _varint(len(hello))
    hdr_fixed = b"\xc0" + struct.pack(">I", 1) + bytes([len(dcid)]) + dcid + b"\x00\x00"
    pn = b"\x00"
    room = QUIC_SIZE - len(hdr_fixed) - 2 - len(pn) - 16  # 2 — длина (varint из двух байт)
    payload = frame + hello
    payload += bytes(max(0, room - len(payload)))  # PADDING
    header = hdr_fixed + _varint(len(pn) + len(payload) + 16)
    if len(_varint(len(pn) + len(payload) + 16)) != 2:
        raise ValueError("QUIC: неожиданная длина")
    header += pn
    key, iv, hp = quic_keys(dcid)
    nonce = iv[:-1] + bytes([iv[-1] ^ pn[0]])
    stream = b"".join(aes128_block(key, nonce + struct.pack(">I", 2 + i)) for i in range((len(payload) + 15) // 16))
    ct = bytes(a ^ b for a, b in zip(payload, stream))
    mask = aes128_block(hp, ct[4 - len(pn):20 - len(pn)])
    header = bytearray(header)
    header[0] ^= mask[0] & 0x0F
    header[-1] ^= mask[1]
    r_from = len(frame) + rand_at  # где в зашифрованных данных лежит random
    # начало зашифрованных данных (байты 3…18) — образец для защиты заголовка: он должен быть постоянным
    r_from, r_end = max(r_from, 20 - len(pn)), r_from + 32
    return str(_Chain().raw(bytes(header) + ct[:r_from]).tag("r", r_end - r_from).raw(ct[r_end:]).tag("r", 16))


def dns_i1(host: str, pad: int) -> str:
    """Обычный DNS-запрос (A) с дополнением EDNS0 (RFC 7830) — дополнение случайное."""
    qname = b"".join(bytes([len(x)]) + x.encode() for x in host.strip(".").split(".")) + b"\x00"
    opt = b"\x00" + struct.pack(">HHIH", 41, 4096, 0, pad + 4) + struct.pack(">HH", 12, pad)
    return str(_Chain().tag("r", 2).raw(bytes.fromhex("01000001000000000001") + qname + b"\x00\x01\x00\x01" + opt)
               .tag("r", pad))


# Пакет-обманка из инструкции Amnezia (ответ DNS для yabs.yandex.ru) — docs.amnezia.org, «upgrade-awg-config».
DNS_YANDEX_I1 = ("<r 2><b 0x8580000100010000000004796162730679616e6465780272750000010001c00c000100010000026d000457fa27d1>")


def stun_i1(software: int) -> str:
    """Запрос STUN Binding (так начинают звонки в браузерах и мессенджерах)."""
    return str(_Chain().raw(struct.pack(">HHI", 1, 4 + software, 0x2112A442)).tag("r", 12)
               .raw(struct.pack(">HH", 0x8022, software)).tag("rc", software))


def sip_i1(host: str, a: int, b: int) -> str:
    """SIP OPTIONS — так телефоны и IP-АТС проверяют, что собеседник на связи."""
    return str(_Chain().text(f"OPTIONS sip:{host} SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.{a}.{b}:5060;branch=z9hG4bK")
               .tag("rc", 10).text("\r\nFrom: <sip:").tag("rc", 8).text(f"@{host}>;tag=").tag("rd", 6)
               .text(f"\r\nTo: <sip:{host}>\r\nCall-ID: ").tag("rc", 16).text(f"@{host}\r\nCSeq: ").tag("rd", 4)
               .text(" OPTIONS\r\nMax-Forwards: 70\r\nUser-Agent: PJSIP/2.13\r\nContent-Length: 0\r\n\r\n"))


# Наборы обманок: адрес и порт Cloudflare + вид пакета I1. Порядок — от самых частых рабочих.
PRESETS = (
    ("162.159.192.1:2408", "quic", "yandex.ru"),
    ("188.114.97.1:4500", "dns_yandex", ""),
    ("162.159.195.1:500", "stun", ""),
    ("188.114.99.1:1701", "quic", "vk.com"),
    ("162.159.192.7:4500", "dns", "icloud.com"),
    ("188.114.96.1:2408", "sip", "www.google.com"),
    ("162.159.195.5:4500", "quic", "www.google.com"),
)


def _rand(lo: int, hi: int) -> int:
    return lo + secrets.randbelow(hi - lo + 1)


def preset(index: int) -> dict:
    """Параметры набора обманок номер index (по кругу): адрес, мусорные пакеты, I1. Случайное — каждый раз новое."""
    endpoint, kind, host = PRESETS[index % len(PRESETS)]
    if kind == "quic":
        i1 = quic_i1(host, secrets.token_bytes(8), secrets.token_bytes(32))
    elif kind == "dns":
        i1 = dns_i1(host, _rand(60, 180))
    elif kind == "stun":
        i1 = stun_i1(_rand(4, 8) * 4)
    elif kind == "sip":
        i1 = sip_i1(host, _rand(0, 255), _rand(2, 254))
    else:
        i1 = DNS_YANDEX_I1
    jmin = _rand(10, 50)
    return {"endpoint": endpoint, "jc": _rand(4, 8), "jmin": jmin, "jmax": jmin + _rand(20, 100), "i1": i1,
            "label": kind + (f" ({host})" if host else "")}


# ---------- конфиг ----------

OBF_KEYS = ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5")
_OBF_LOWER = {k.lower() for k in OBF_KEYS}


def build_conf(acct: dict, params: dict) -> str:
    addr = ", ".join(x for x in (f"{acct['v4']}/32" if acct.get("v4") else "",
                                 f"{acct['v6']}/128" if acct.get("v6") else "") if x)
    lines = ["[Interface]", f"PrivateKey = {acct['private_key']}", f"Address = {addr}",
             "DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111", "MTU = 1280"]
    lines += _obf_lines(params)
    lines += ["", "[Peer]", f"PublicKey = {acct.get('peer') or PEER_KEY}", "AllowedIPs = 0.0.0.0/0, ::/0",
              f"Endpoint = {params['endpoint']}", "PersistentKeepalive = 25"]
    return "\n".join(lines) + "\n"


def _obf_lines(params: dict) -> list[str]:
    return [f"Jc = {params['jc']}", f"Jmin = {params['jmin']}", f"Jmax = {params['jmax']}", "S1 = 0", "S2 = 0",
            "H1 = 1", "H2 = 2", "H3 = 3", "H4 = 4", f"I1 = {params['i1']}"]


def is_warp(conf: str) -> bool:
    m = re.search(r"^\s*PublicKey\s*=\s*(\S+)", conf or "", re.M | re.I)
    return bool(m and m.group(1) == PEER_KEY)


def variant(conf: str, params: dict) -> str:
    """Тот же конфиг WARP (ключи и адреса — свои) с другим набором обманок: в [Interface] заменяются
    параметры маскировки, в [Peer] — адрес сервера. Остальные строки не трогаются."""
    out, sect, obf_done = [], "", False
    for raw in conf.strip().splitlines():
        line = raw.strip()
        m = re.fullmatch(r"\[(\w+)\]", line)
        if m:
            if sect == "interface" and not obf_done:
                while out and not out[-1].strip():
                    out.pop()
                out += _obf_lines(params) + [""]
                obf_done = True
            sect = m.group(1).lower()
            out.append(raw)
            continue
        key = line.split("=", 1)[0].strip().lower() if "=" in line else ""
        if sect == "interface" and key in _OBF_LOWER:
            continue
        if sect == "peer" and key.lower() == "endpoint":
            out.append(f"Endpoint = {params['endpoint']}")
            continue
        out.append(raw)
    if sect == "interface" and not obf_done:
        out += _obf_lines(params)
    return "\n".join(out) + "\n"


def current_params(conf: str) -> dict:
    """Параметры маскировки и адрес из конфига — чтобы запомнить рабочий набор для этой сети."""
    p: dict = {}
    sect = ""
    for raw in (conf or "").splitlines():
        line = raw.strip()
        m = re.fullmatch(r"\[(\w+)\]", line)
        if m:
            sect = m.group(1).lower()
            continue
        if "=" not in line:
            continue
        k, v = (x.strip() for x in line.split("=", 1))
        kl = k.lower()
        if sect == "interface" and kl in ("jc", "jmin", "jmax", "i1"):
            p[kl] = int(v) if kl != "i1" and v.isdigit() else v
        elif sect == "peer" and k.lower() == "endpoint":
            p["endpoint"] = v
    ok = all(k in p for k in ("jc", "jmin", "jmax", "i1", "endpoint"))
    return dict(p, label="saved") if ok else {}


# ---------- регистрация ----------

class WarpError(RuntimeError):
    """Регистрация не удалась; .kind: blocked (сеть не пускает к Cloudflare), limit (429/403), bad (ответ непонятен)."""

    def __init__(self, text: str, kind: str):
        super().__init__(text)
        self.kind = kind


def _ssl() -> ssl.SSLContext:
    from .netutil import ssl_context
    ctx = ssl_context()
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2  # как приложение 1.1.1.1 для Android
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


def _call(opener, method: str, url: str, body: dict, token: str = "", timeout: float = 12.0) -> dict:
    headers = {"Content-Type": "application/json; charset=UTF-8", "User-Agent": USER_AGENT,
               "CF-Client-Version": CLIENT_VERSION, "Accept-Encoding": "identity"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method=method)
    try:
        with opener.open(req, timeout=timeout) as resp:
            data = resp.read(1 << 16)
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 429):
            raise WarpError(f"Cloudflare отказал (код {exc.code})", "limit") from None
        raise WarpError(f"Cloudflare ответил ошибкой {exc.code}", "bad") from None
    except (OSError, ssl.SSLError) as exc:
        raise WarpError(str(exc) or exc.__class__.__name__, "blocked") from None
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise WarpError("непонятный ответ Cloudflare", "bad") from None


def register(opener, base: str, model: str = "PC", seed: bytes | None = None) -> dict:
    """Новое устройство WARP. base — «https://api.cloudflareclient.com» (или запасной адрес).
    Возвращает {private_key, peer, v4, v6}. Метка доступа Cloudflare нужна только для включения WARP и дальше
    не хранится."""
    priv, pub = keypair(seed)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    url = f"{base.rstrip('/')}/{API_VERSION}/reg"
    r = _call(opener, "POST", url, {"key": pub, "install_id": "", "fcm_token": "", "tos": now, "model": model,
                                    "serial_number": "", "os_version": "16.0.0", "key_type": "curve25519",
                                    "tunnel_type": "wireguard", "locale": "en_US"})
    r = r.get("result", r) if isinstance(r, dict) else {}
    cfg = r.get("config") or {}
    peers = cfg.get("peers") or [{}]
    addrs = ((cfg.get("interface") or {}).get("addresses")) or {}
    acct = {"private_key": priv, "peer": (peers[0] or {}).get("public_key") or "", "v4": addrs.get("v4") or "",
            "v6": addrs.get("v6") or ""}
    if not r.get("id") or not r.get("token") or not acct["peer"] or not acct["v4"]:
        raise WarpError("в ответе Cloudflare нет ключей", "bad")
    if not (r.get("warp_enabled") or (r.get("account") or {}).get("warp_enabled")):
        _call(opener, "PATCH", f"{url}/{r['id']}", {"warp_enabled": True}, token=r["token"])
    return acct


def opener_for(proxy_port: int | None):
    """Запросы к Cloudflare: напрямую (без системного прокси) или через наш вход «через VPN»."""
    from .netutil import _OwnProxyHandler
    handlers: list = [_OwnProxyHandler(proxy_port) if proxy_port else urllib.request.ProxyHandler({}),
                      urllib.request.HTTPSHandler(context=_ssl())]
    return urllib.request.build_opener(*handlers)


def trace_ok(timeout: float = 4.0, url: str = TRACE_URL) -> bool:
    """Идёт ли трафик компьютера через WARP: Cloudflare сам отвечает «warp=on» (или «plus»)."""
    from .netutil import ssl_context
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ssl_context()))
    try:
        with opener.open(urllib.request.Request(url, headers={"User-Agent": "curl/8"}), timeout=timeout) as resp:
            body = resp.read(4096).decode("utf-8", "replace")
    except (OSError, ssl.SSLError, ValueError):
        return False
    return bool(re.search(r"^warp=(on|plus)\s*$", body, re.M))


# ---------- WARP во встроенном ядре Xray (без программы AmneziaWG) ----------
# Ядро Xray умеет WireGuard само, а Finalmask (с 26.3.27) — «шум» перед первым пакетом: тот же приём, что
# мусорные пакеты Jc и пакет-обманка I1 у AmneziaWG. Пакет I1 собирается здесь же из записи CPS
# (случайные части — заново при каждом запуске ядра), мусорные пакеты — случайной длины Jmin…Jmax.

_CPS_TAG = re.compile(r"<(b|r|rc|rd|t|c|n)(?:\s+([^>]*))?>")
_LETTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
CPS_MAX = 4096  # такой пакет-обманка уже не похож ни на что настоящее


def _cps_count(arg: str, rnd) -> int:
    a, _, b = (arg or "").strip().partition("-")
    lo = int(a)
    hi = int(b) if b else lo
    if lo < 0 or hi < lo or hi > CPS_MAX:
        raise ValueError("CPS: неверная длина")
    return lo + rnd(hi - lo + 1) if hi > lo else lo


def cps_bytes(expr: str, rnd=secrets.randbelow, now=None) -> bytes:
    """Запись CPS AmneziaWG (<b 0x…>, <r N>, <rc N>, <rd N>, <t>, <c>, <n>) → байты одного пакета.
    rnd(n) — случайное 0…n-1 (самопроверка подставляет предсказуемое)."""
    out = bytearray()
    pos = 0
    text = (expr or "").strip()
    for m in _CPS_TAG.finditer(text):
        if text[pos:m.start()].strip():
            raise ValueError("CPS: лишний текст между тегами")
        pos = m.end()
        kind, arg = m.group(1), (m.group(2) or "").strip()
        if kind == "b":
            h = arg[2:] if arg.lower().startswith("0x") else arg
            out += bytes.fromhex(h)
        elif kind == "r":
            out += bytes(rnd(256) for _ in range(_cps_count(arg, rnd)))
        elif kind == "rc":
            out += "".join(_LETTERS[rnd(len(_LETTERS))] for _ in range(_cps_count(arg, rnd))).encode()
        elif kind == "rd":
            out += "".join(str(rnd(10)) for _ in range(_cps_count(arg, rnd))).encode()
        elif kind == "t":
            out += struct.pack(">I", int(now if now is not None else datetime.datetime.now().timestamp()) & 0xFFFFFFFF)
        elif kind == "c":
            out += struct.pack(">I", 1)
        else:
            out += bytes(rnd(256) for _ in range(8))
        if len(out) > CPS_MAX:
            raise ValueError("CPS: слишком длинный пакет")
    if text[pos:].strip():
        raise ValueError("CPS: лишний текст после тегов")
    return bytes(out)


def parse_conf(conf: str) -> dict:
    """Нужное ядру Xray из конфига WARP: ключи, адреса, сервер и обманки."""
    out: dict = {"address": [], "mtu": 1280}
    sect = ""
    for raw in (conf or "").splitlines():
        line = raw.strip()
        if line.startswith(("#", ";")):
            continue
        m = re.fullmatch(r"\[(\w+)\]", line)
        if m:
            sect = m.group(1).lower()
            continue
        if "=" not in line:
            continue
        k, v = (x.strip() for x in line.split("=", 1))
        kl = k.lower()
        if sect == "interface":
            if kl == "privatekey":
                out["private_key"] = v
            elif kl == "address":
                out["address"] = [a.strip() for a in v.split(",") if a.strip()]
            elif kl == "mtu" and v.isdigit():
                out["mtu"] = max(1200, min(1420, int(v)))
            elif kl in ("jc", "jmin", "jmax") and v.isdigit():
                out[kl] = int(v)
            elif kl == "i1":
                out["i1"] = v
        elif sect == "peer":
            if kl == "publickey":
                out["peer"] = v
            elif kl == "endpoint":
                out["endpoint"] = v
    if not out.get("private_key") or not out.get("peer") or not out.get("endpoint") or not out["address"]:
        raise ValueError("в конфиге WARP нет ключей или адреса сервера")
    return out


NOISE_DELAY = "1-3"  # мс между пакетами шума: порядок сохраняется, а подключение почти не замедляется


def noise_items(p: dict, rnd=secrets.randbelow) -> list[dict]:
    """Шум перед подключением, как у AmneziaWG: сначала пакет-обманка I1, затем Jc мусорных пакетов."""
    items: list[dict] = []
    if p.get("i1"):
        try:
            items.append({"type": "hex", "packet": cps_bytes(p["i1"], rnd).hex(), "delay": NOISE_DELAY})
        except ValueError:
            pass
    jc, lo, hi = int(p.get("jc") or 0), int(p.get("jmin") or 0), int(p.get("jmax") or 0)
    if jc > 0 and 0 < lo <= hi <= 1280:
        items += [{"rand": f"{lo}-{hi}" if hi > lo else str(lo), "delay": NOISE_DELAY} for _ in range(min(jc, 10))]
    return items


def xray_outbound(conf: str, tag: str = "proxy", noise: bool = True, rnd=secrets.randbelow) -> dict:
    """Outbound WireGuard для ядра Xray (WARP) с шумом Finalmask вместо обманок AmneziaWG."""
    p = parse_conf(conf)
    ob: dict = {"tag": tag, "protocol": "wireguard",
                "settings": {"secretKey": p["private_key"], "address": p["address"],
                             "peers": [{"publicKey": p["peer"], "endpoint": p["endpoint"], "keepAlive": 25}],
                             "mtu": p["mtu"], "noKernelTun": True}}
    items = noise_items(p, rnd) if noise else []
    if items:
        ob["streamSettings"] = {"finalmask": {"udp": [{"type": "noise", "settings": {"noise": items}}]}}
    return ob


def share_conf(conf: str) -> str:
    """Конфиг для другого устройства (QR-код): без строк, которые не нужны клиенту AmneziaWG на телефоне,
    а пакет-обманка — короткий из инструкции Amnezia, если свой слишком длинный для QR-кода."""
    lines = [x for x in (conf or "").strip().splitlines() if not x.lstrip().startswith("#")]
    text = "\n".join(lines) + "\n"
    if len(text.encode()) > 1800:
        text = re.sub(r"(?im)^\s*I1\s*=.*$", f"I1 = {DNS_YANDEX_I1}", text)
    return text
