"""Запуск программы вместе с Windows: запись в реестре HKCU\\...\\Run (права администратора не нужны)."""

from __future__ import annotations

import os
import sys

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE = "VedomyjVPN"
OLD_VALUES = ("PultVPN",)  # прежнее название программы: такую запись убираем, чтобы не было двух автозапусков


def command(app_dir: str) -> str:
    launcher = os.path.join(app_dir, "VedomyjVPN.exe")  # установленная или портативная сборка
    if os.path.isfile(launcher):
        return f'"{launcher}" --autostart'
    exe = sys.executable or "pythonw.exe"
    folder, name = os.path.split(exe)
    if name.lower() == "python.exe" and os.path.isfile(os.path.join(folder, "pythonw.exe")):
        exe = os.path.join(folder, "pythonw.exe")  # без чёрного окна консоли
    return f'"{exe}" "{os.path.join(app_dir, "main.py")}" --autostart'


def is_enabled() -> bool:
    if os.name != "nt":
        return False
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            for name in (VALUE,) + OLD_VALUES:
                try:
                    winreg.QueryValueEx(key, name)
                    return True
                except OSError:
                    continue
            return False
    except OSError:
        return False


def set_enabled(app_dir: str, enabled: bool) -> None:
    """Включает или выключает автозапуск. На других системах ничего не делает."""
    if os.name != "nt":
        return
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        for name in OLD_VALUES:
            try:
                winreg.DeleteValue(key, name)
            except FileNotFoundError:
                pass
        if enabled:
            winreg.SetValueEx(key, VALUE, 0, winreg.REG_SZ, command(app_dir))
        else:
            try:
                winreg.DeleteValue(key, VALUE)
            except FileNotFoundError:
                pass
