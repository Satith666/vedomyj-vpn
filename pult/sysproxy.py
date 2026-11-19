"""Системный прокси Windows (браузеры и большинство программ берут его отсюда)."""

from __future__ import annotations

import sys

IS_WINDOWS = sys.platform == "win32"
KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
BYPASS = ("localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;"
          "172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>")

if IS_WINDOWS:
    import ctypes
    import winreg


def _read(name: str):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def _write(name: str, value, kind) -> None:
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY, 0, winreg.KEY_SET_VALUE) as k:
        if value is None:
            try:
                winreg.DeleteValue(k, name)
            except OSError:
                pass
        else:
            winreg.SetValueEx(k, name, 0, kind, value)


def _refresh() -> None:
    try:
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        wininet.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH
    except Exception:
        pass


def get_state() -> dict | None:
    if not IS_WINDOWS:
        return None
    return {
        "ProxyEnable": _read("ProxyEnable"),
        "ProxyServer": _read("ProxyServer"),
        "ProxyOverride": _read("ProxyOverride"),
        "AutoConfigURL": _read("AutoConfigURL"),
    }


def is_ours(port: int) -> bool:
    if not IS_WINDOWS:
        return False
    return bool(_read("ProxyEnable")) and str(_read("ProxyServer") or "") == f"127.0.0.1:{port}"


def enable(port: int) -> dict | None:
    """Включает системный прокси на 127.0.0.1:port. Возвращает прежние настройки для восстановления."""
    if not IS_WINDOWS:
        return None
    backup = get_state()
    _write("ProxyServer", f"127.0.0.1:{port}", winreg.REG_SZ)
    _write("ProxyOverride", BYPASS, winreg.REG_SZ)
    _write("AutoConfigURL", None, winreg.REG_SZ)
    _write("ProxyEnable", 1, winreg.REG_DWORD)
    _refresh()
    return backup


def restore(backup: dict | None) -> None:
    if not IS_WINDOWS:
        return
    if not backup:
        _write("ProxyEnable", 0, winreg.REG_DWORD)
        _refresh()
        return
    _write("ProxyEnable", int(backup.get("ProxyEnable") or 0), winreg.REG_DWORD)
    _write("ProxyServer", backup.get("ProxyServer"), winreg.REG_SZ)
    _write("ProxyOverride", backup.get("ProxyOverride"), winreg.REG_SZ)
    _write("AutoConfigURL", backup.get("AutoConfigURL"), winreg.REG_SZ)
    _refresh()
