"""Отпечаток сертификата для серверов «не проверять сертификат» (allowInsecure в ссылке).

Ядра Xray с июня 2026 года не умеют отключать проверку сертификата: вместо этого нужно указать SHA-256 сертификата
сервера (pinnedPeerCertSha256). Программа узнаёт его сама — подключается к серверу по TLS (как это сделало бы ядро),
берёт его сертификат и запоминает отпечаток. Это не слабее allowInsecure, а надёжнее: если сертификат вдруг подменят,
отпечаток не совпадёт. Сменил сервер сертификат — при следующей проверке серверов отпечаток обновится.
Для Hysteria2 (QUIC) так не получится — такие серверы идут через мост sing-box (links._hy2_via_singbox).
"""

from __future__ import annotations

import hashlib
import socket
import ssl
import threading

from .links import Server

TIMEOUT = 8.0


def target(srv: Server) -> tuple[str, int, str] | None:
    """(адрес для подключения, порт, SNI) сервера с TLS поверх TCP; None — снимать нечего."""
    if not getattr(srv, "tls_unverified", False) or srv.engine != "xray":
        return None
    ss = srv.outbound.get("streamSettings") or {}
    if (ss.get("security") or "").lower() != "tls" or ss.get("network") in ("hysteria", "kcp", "mkcp", "quic"):
        return None
    tls = ss.get("tlsSettings") or {}
    host = getattr(srv, "pinned_ip", "") or srv.address
    if not host or not srv.port:
        return None
    return host.strip("[]"), int(srv.port), tls.get("serverName") or srv.address


def fetch(host: str, port: int, sni: str, timeout: float = TIMEOUT) -> str:
    """SHA-256 сертификата сервера (hex) — тот, что он показывает этому SNI."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # сертификат как раз и нужно увидеть, не проверяя: его отпечаток станет проверкой
    with socket.create_connection((host, port), timeout=timeout) as raw:
        server_name = sni if sni and not _is_ip(sni) else None
        with ctx.wrap_socket(raw, server_hostname=server_name) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise ssl.SSLError("сервер не показал сертификат")
    return hashlib.sha256(der).hexdigest()


def _is_ip(text: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in text else socket.AF_INET, text)
        return True
    except OSError:
        return False


def fill(servers: list[Server], pins: dict, refresh: bool = False, timeout: float = TIMEOUT) -> int:
    """Снимает отпечатки параллельно (не дольше timeout на всё). refresh — и тем, что уже известны.
    Возвращает, сколько отпечатков записано. Не ответил сервер — остаётся прежний отпечаток (или никакого)."""
    jobs = []
    for srv in servers:
        t = target(srv)
        if t and (refresh or srv.key not in pins):
            jobs.append((srv.key, t))
    if not jobs:
        return 0
    got: dict = {}

    def one(key: str, t: tuple) -> None:
        try:
            got[key] = fetch(*t, timeout=timeout)
        except (OSError, ssl.SSLError, ValueError):
            pass
    threads = [threading.Thread(target=one, args=job, daemon=True) for job in jobs[:64]]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout + 2)
    pins.update(got)
    return len(got)
