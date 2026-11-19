"""Проверка сертификатов: не подменяет ли кто-то защищённые соединения (HTTPS).

1. Хранилище сертификатов системы: стоит ли корневой сертификат Минцифры («Russian Trusted Root CA» / «Sub CA»).
   Им можно подписать сертификат ЛЮБОГО сайта, и браузер поверит. Сам по себе он не подмена — его ставят, чтобы
   открывались Сбербанк и Госуслуги, — но если он стоит, перехват соединений браузер уже не заметит.
2. Контрольные сайты (Google, GitHub, Википедия, Cloudflare): кто выдал их сертификаты — напрямую и через VPN.
   Сертификат от Минцифры или неизвестного центра, или настоящий через VPN, но поддельный напрямую — соединения
   в этой сети перехватывают. Поддельный через VPN — подменяет сам сервер VPN.
Антивирусы (Касперский, ESET и др.) тоже «перехватывают» HTTPS, чтобы проверять страницы: это отмечается отдельно.

Адреса и содержимое страниц не сохраняются: смотрим только, кто выдал сертификат.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
import sys

from . import netutil

PROBE_HOSTS = ["www.google.com", "github.com", "www.wikipedia.org", "www.cloudflare.com"]

# признаки сертификатов Минцифры (в DER они лежат как UTF8String/PrintableString)
RUSSIAN_MARKS = {
    b"Russian Trusted Root CA": "Russian Trusted Root CA",
    b"Russian Trusted Sub CA": "Russian Trusted Sub CA",
    "Минцифры".encode(): "Минцифры России",
    b"Ministry of Digital Development": "Минцифры России",
}
# антивирусы и корпоративные фильтры, которые проверяют HTTPS (ставят свой корневой сертификат)
INTERCEPTORS = ("Kaspersky", "ESET", "Avast", "AVG", "Bitdefender", "Dr.Web", "Doctor Web", "Norton", "Fortinet",
                "FortiGate", "Zscaler", "Sophos", "Cisco Umbrella", "Check Point", "Palo Alto", "Netskope", "Blue Coat",
                "Symantec Web", "McAfee Web", "Trend Micro", "WebTitan", "Adguard", "AdGuard")
# известные публичные центры сертификации: их сертификаты у больших сайтов — норма
PUBLIC_CAS = ("Google Trust Services", "DigiCert", "Sectigo", "Let's Encrypt", "Internet Security Research Group",
              "GlobalSign", "Amazon", "Microsoft", "Cloudflare", "Entrust", "GoDaddy", "Starfield", "IdenTrust",
              "Certum", "Asseco", "Baltimore", "SSL.com", "HARICA", "Buypass", "Actalis", "QuoVadis", "COMODO",
              "Comodo", "USERTrust", "Apple", "Thawte", "GeoTrust", "RapidSSL", "Encryption Everywhere", "Telia",
              "Certainly", "Fastly", "Akamai", "ZeroSSL", "TrustAsia", "WoTrus", "Wikimedia", "GTS", "Go Daddy",
              "Network Solutions", "Gandi", "SwissSign", "D-TRUST", "T-Systems", "Deutsche Telekom", "Izenpe",
              "Firmaprofesional", "Chunghwa", "Secom", "SECOM", "Cybertrust", "Verizon", "VeriSign", "Symantec",
              "Trustwave", "SecureTrust", "Network Solutions", "AffirmTrust", "Atos", "emSign", "e-Tugra", "Hongkong Post")


def russian_names(der: bytes) -> list[str]:
    found = []
    for mark, name in RUSSIAN_MARKS.items():
        if mark in der and name not in found:
            found.append(name)
    return found


def interceptor_name(text: str | bytes) -> str:
    raw = text.decode("latin-1", "replace") if isinstance(text, bytes) else text
    for name in INTERCEPTORS:
        if name.lower() in raw.lower():
            return name
    return ""


# ---------- хранилище системы ----------

def system_roots() -> list[bytes]:
    """Корневые и промежуточные сертификаты системы (DER). Windows — хранилища ROOT и CA; иначе — файл ssl."""
    out: list[bytes] = []
    if sys.platform == "win32":
        for store in ("ROOT", "CA"):
            try:
                out += [cert for cert, enc, _trust in ssl.enum_certificates(store) if enc == "x509_asn"]
            except (OSError, AttributeError):
                pass
        return out
    import base64
    import re
    paths = ssl.get_default_verify_paths()
    for path in (paths.cafile, paths.openssl_cafile):
        try:
            with open(path or "", encoding="ascii", errors="ignore") as f:
                pem = f.read()
        except OSError:
            continue
        for block in re.findall(r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", pem, re.S):
            try:
                out.append(base64.b64decode("".join(block.split())))
            except ValueError:
                pass
        if out:
            break
    return out


def russian_roots(certs: list[bytes] | None = None) -> list[str]:
    """Какие сертификаты Минцифры стоят в системе (имена), [] — нет."""
    found: list[str] = []
    for der in system_roots() if certs is None else certs:
        for name in russian_names(der):
            if name not in found:
                found.append(name)
    return found


# ---------- сертификат сайта ----------

def _connect(host: str, proxy_port: int | None, timeout: float) -> socket.socket:
    if not proxy_port:
        return socket.create_connection((host, 443), timeout=timeout)
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    sock.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            sock.close()
            raise ConnectionResetError("прокси закрыл соединение")
        resp += chunk
    if b" 200" not in resp.split(b"\r\n", 1)[0]:
        sock.close()
        raise ConnectionRefusedError("прокси не пустил")
    return sock


def _issuer_of(info: dict) -> tuple[str, str]:
    org = cn = ""
    for rdn in info.get("issuer", ()):
        for key, value in rdn:
            if key == "organizationName" and not org:
                org = value
            elif key == "commonName" and not cn:
                cn = value
    return org, cn


def verify_context() -> ssl.SSLContext:
    """Проверка сертификата так же, как в браузере: по хранилищу системы (в Windows — оно же у Chrome и Edge)."""
    return ssl.create_default_context()


def fetch(host: str, proxy_port: int | None = None, timeout: float = 8.0) -> dict:
    """{"state": "ok"|"bad"|"fail", "issuer", "russian": [...], "interceptor", "sha256", "error"}.
    ok — сертификат проверен системой; bad — проверку не прошёл (поддельный или чужой); fail — не соединились."""
    ctx = verify_context()
    try:
        with _connect(host, proxy_port, timeout) as raw, ctx.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(True) or b""
            org, cn = _issuer_of(tls.getpeercert() or {})
            issuer = org or cn
            return {"state": "ok", "issuer": issuer, "russian": russian_names(der),
                    "interceptor": interceptor_name(f"{org} {cn}"), "sha256": hashlib.sha256(der).hexdigest(), "error": ""}
    except ssl.SSLCertVerificationError as exc:
        error = netutil.human_error(exc)
    except (OSError, ssl.SSLError) as exc:
        return {"state": "fail", "issuer": "", "russian": [], "interceptor": "", "sha256": "", "error": netutil.human_error(exc)}
    # проверку не прошёл: смотрим, что за сертификат подсунули
    loose = ssl.create_default_context()
    loose.check_hostname = False
    loose.verify_mode = ssl.CERT_NONE  # только чтобы прочитать поддельный сертификат, данные не отправляем
    try:
        with _connect(host, proxy_port, timeout) as raw, loose.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(True) or b""
    except (OSError, ssl.SSLError):
        der = b""
    names = russian_names(der)
    return {"state": "bad", "issuer": names[0] if names else (interceptor_name(der) or ""), "russian": names,
            "interceptor": interceptor_name(der), "sha256": hashlib.sha256(der).hexdigest() if der else "", "error": error}


def known_public(issuer: str) -> bool:
    return any(ca.lower() in issuer.lower() for ca in PUBLIC_CAS)


# ---------- проверка целиком ----------

def check(vpn_port: int | None = None, hosts: list[str] | None = None, roots: list[str] | None = None,
          fetcher=None, direct: bool = True) -> dict:
    """Итог для окна и отчётов: {"items": [{"state","title","detail","fix"}], "mitm": bool, "vpn_mitm": bool,
    "russian_root": [...], "errors", "warnings"}. vpn_port — порт программы, через который всё идёт в VPN.
    direct=False — только путь через VPN (без хранилища системы и прямых соединений)."""
    hosts = hosts or PROBE_HOSTS
    fetcher = fetcher or fetch
    roots = (russian_roots() if roots is None else roots) if direct else []
    items: list[dict] = []

    def add(state: str, title: str, detail: str = "", fix: str = "") -> None:
        items.append({"state": state, "title": title, "detail": detail, "fix": fix})

    if not direct:
        pass
    elif roots:
        add("warn", f"В системе стоит сертификат Минцифры: {', '.join(roots)}",
            "Им можно подписать любой сайт, и браузер не заметит подмену. Обычно его ставят ради Сбербанка и Госуслуг.",
            "Не нужен — удали: Win+R → certmgr.msc → «Доверенные корневые центры» → Russian Trusted Root CA. "
            "Для банков есть браузеры, где он уже встроен (Яндекс Браузер, Атом).")
    else:
        add("ok", "Сертификатов Минцифры в системе нет")
    mitm = vpn_mitm = False
    direct_ok: list[str] = []
    av = ""
    for host in hosts:
        d = fetcher(host, None) if direct else {"state": "fail"}
        v = fetcher(host, vpn_port) if vpn_port else None
        vpn_bad = bool(v) and (v["state"] == "bad" or (v["state"] == "ok" and (
            bool(v["russian"]) or (not known_public(v["issuer"]) and not v["interceptor"]))))
        if vpn_bad:
            vpn_mitm = True
            add("error", f"Через VPN сертификат {host} поддельный",
                v["issuer"] or v["error"], "Сервер VPN подменяет защищённые соединения. Не вводи пароли и смени сервер.")
        if d["state"] == "fail":
            continue  # сайт закрыт провайдером — сертификат не посмотреть, и это нормально
        if d["state"] == "bad" or d["russian"]:
            mitm = True
            how = f"сертификат выдан: {d['issuer']}" if d["issuer"] else d["error"]
            also = " Через VPN он настоящий." if v and v["state"] == "ok" and not vpn_mitm else ""
            add("error", f"Напрямую сертификат {host} подменён", how + "." + also,
                "Соединения в этой сети перехватывают. Включи «Всё через VPN» и kill switch, пароли вводи только через VPN.")
        elif d["interceptor"]:
            av = d["interceptor"]
        elif not known_public(d["issuer"]):
            mitm = True
            add("warn", f"Сертификат {host} выдан неизвестным центром «{d['issuer']}»",
                "Так бывает в сетях с проверкой трафика (работа, учёба, публичный Wi-Fi) или при перехвате.",
                "Пароли и личное — только через VPN.")
        else:
            direct_ok.append(host)
    if av:
        add("info", f"Антивирус проверяет защищённые соединения ({av})",
            "Он видит, какие страницы ты открываешь. Это не провайдер — так работает твой антивирус.",
            "Не нравится — выключи в антивирусе «проверку защищённых соединений» (HTTPS).")
    if direct_ok and not mitm:
        add("ok", "Подмены сертификатов напрямую нет", ", ".join(direct_ok))
    if vpn_port and not vpn_mitm:
        add("ok", "Через VPN сертификаты настоящие")
    errors = sum(1 for i in items if i["state"] == "error")
    warnings = sum(1 for i in items if i["state"] == "warn")
    return {"items": items, "mitm": mitm, "vpn_mitm": vpn_mitm, "russian_root": roots,
            "errors": errors, "warnings": warnings}
