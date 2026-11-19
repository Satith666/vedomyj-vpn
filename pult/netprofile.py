"""Профили сетей: какая сеть сейчас — домашняя или чужая (открытый Wi-Fi в кафе, гостинице, аэропорту).

В чужой сети программа сама включает VPN, пускает весь трафик через него и включает kill switch.
Чужой считается открытая сеть Wi-Fi (без пароля) и сети, которые человек сам отметил чужими.
Сеть, отмеченная своей, — всегда своя. Проводная сеть — своя.
"""

from __future__ import annotations

import re
import subprocess
import sys

IS_WINDOWS = sys.platform == "win32"

# значения из вывода netsh на английской и русской Windows (это шаблоны поиска, а не сообщения)
AUTH_RX = "^(wpa|wep|open|открыт|shared|общ|owe)"
CIPHER_RX = "^(ccmp|gcmp|tkip|wep|none|нет)$"
OPEN_RX = "^(open|открыт)"
NONE_RX = "^(none|нет)$"
PATTERNS = (AUTH_RX, CIPHER_RX, OPEN_RX, NONE_RX)


def parse_netsh(text: str) -> dict:
    """Вывод «netsh wlan show interfaces» (на любом языке Windows) → {"ssid", "open", "connected"}."""
    ssid, auths, ciphers, connected = "", [], [], False
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        low = key.lower()
        if low == "ssid":
            ssid = value
            connected = True
        elif re.match(AUTH_RX, value, re.I):
            auths.append(value)
        elif re.match(CIPHER_RX, value, re.I):
            ciphers.append(value)
    auth = auths[0] if auths else ""
    is_open = bool(connected and (re.match(OPEN_RX, auth, re.I) or (not auth and any(
        re.match(NONE_RX, c, re.I) for c in ciphers))))
    return {"ssid": ssid, "open": is_open, "connected": connected, "auth": auth}


def current(runner=None) -> dict:
    """Текущая сеть Wi-Fi: {"kind": "wifi"|"wired"|"", "ssid", "open"}. runner — подмена в самопроверке."""
    if runner is not None:
        text = runner()
    elif IS_WINDOWS:
        try:
            raw = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, timeout=8,
                                 creationflags=0x08000000).stdout
        except (OSError, subprocess.SubprocessError):
            return {"kind": "", "ssid": "", "open": False}
        try:
            text = raw.decode("oem")  # netsh пишет в кодировке консоли
        except (LookupError, UnicodeDecodeError):
            text = raw.decode("utf-8", "replace")
    else:
        return {"kind": "", "ssid": "", "open": False}
    info = parse_netsh(text)
    if info["connected"] and info["ssid"]:
        return {"kind": "wifi", "ssid": info["ssid"], "open": info["open"]}
    return {"kind": "wired", "ssid": "", "open": False}


def classify(net: dict, trusted: list, untrusted: list) -> str:
    """'public' — чужая сеть, 'home' — своя."""
    ssid = net.get("ssid", "")
    if net.get("kind") != "wifi" or not ssid:
        return "home"
    if ssid in trusted:
        return "home"
    if ssid in untrusted or net.get("open"):
        return "public"
    return "home"
