"""Смена сети без опроса: Windows сама сообщает, что поменялись адреса (NotifyAddrChange из iphlpapi).

Раньше программа каждые 15 секунд запускала «netsh wlan show interfaces» — это 4 запуска программы
в минуту, и каждый проверял антивирус. Теперь netsh запускается только когда сеть правда сменилась
(подключился к другому Wi-Fi, воткнул кабель, проснулся компьютер) и изредка для подстраховки.
"""

from __future__ import annotations

import sys
import threading
import time

IS_WINDOWS = sys.platform == "win32"

_lock = threading.Lock()
_state: dict = {"thread": None, "ok": False, "callbacks": []}


def start(callback) -> bool:
    """Подписаться на смену сети. True — Windows будет сообщать сама (опрос можно делать редко)."""
    with _lock:
        _state["callbacks"].append(callback)
        if _state["thread"] is not None or not IS_WINDOWS:
            return _state["ok"]
        try:
            import ctypes
            notify = ctypes.windll.iphlpapi.NotifyAddrChange
            notify.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            notify.restype = ctypes.c_ulong
        except (AttributeError, OSError, ImportError):
            return False

        def loop() -> None:
            fails = 0
            while True:
                try:
                    rc = notify(None, None)  # ждёт (без нагрузки), пока не поменяются адреса
                except Exception:
                    rc = -1
                if rc == 0:
                    fails = 0
                    for cb in list(_state["callbacks"]):
                        try:
                            cb()
                        except Exception:
                            pass
                    continue
                fails += 1
                if fails >= 5:
                    _state["ok"] = False  # не работает — монитор вернётся к частому опросу
                    return
                time.sleep(5)

        th = threading.Thread(target=loop, daemon=True, name="netwatch")
        _state["thread"] = th
        _state["ok"] = True
        th.start()
        return True


def active() -> bool:
    return bool(_state["ok"])
