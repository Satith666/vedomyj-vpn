"""Шифрование секретов на диске: ссылки подписок, серверы, логины и пароли прокси.

В Windows — DPAPI (CryptProtectData): расшифровать может только этот пользователь на этом компьютере.
Скопировали папку программы на другой компьютер — подписки придётся добавить заново (или перенести
настройки через «Поделиться → файл настроек»). Не в Windows шифрования нет (в самопроверке подменяется).
"""

from __future__ import annotations

import base64
import sys

IS_WINDOWS = sys.platform == "win32"
PREFIX = "VDMSEC1:"
_ENTROPY = b"VEDOMYJ VPN secrets v1"

# подмена в самопроверке: (зашифровать, расшифровать) для bytes
BACKEND = None


class SecureError(Exception):
    pass


def available() -> bool:
    return BACKEND is not None or IS_WINDOWS


def _dpapi(data: bytes, encrypt: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def blob(b: bytes) -> BLOB:
        buf = ctypes.create_string_buffer(b, len(b))
        return BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    src, ent, out = blob(data), blob(_ENTROPY), BLOB()
    fn = crypt32.CryptProtectData if encrypt else crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(src), None, ctypes.byref(ent), None, None, 0x1, ctypes.byref(out))  # UI_FORBIDDEN
    if not ok:
        raise SecureError(f"DPAPI: ошибка {ctypes.get_last_error()}")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def protect(data: bytes) -> bytes:
    if BACKEND is not None:
        return BACKEND[0](data)
    return _dpapi(data, True)


def unprotect(data: bytes) -> bytes:
    if BACKEND is not None:
        return BACKEND[1](data)
    return _dpapi(data, False)


def is_encrypted(text: str) -> bool:
    return isinstance(text, str) and text.startswith(PREFIX)


def encode(text: str) -> str:
    """Текст → зашифрованная строка (или как есть, если шифрование недоступно)."""
    if not available():
        return text
    return PREFIX + base64.b64encode(protect(text.encode("utf-8"))).decode("ascii")


def decode(text: str) -> str:
    """Обратно. Не расшифровывается (другой компьютер или пользователь) — SecureError."""
    if not is_encrypted(text):
        return text
    if not available():
        raise SecureError("шифрование недоступно")
    try:
        return unprotect(base64.b64decode(text[len(PREFIX):])).decode("utf-8")
    except SecureError:
        raise
    except Exception as exc:
        raise SecureError(str(exc)) from exc
