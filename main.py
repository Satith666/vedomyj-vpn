"""VEDOMYJ VPN. Запуск: двойной клик по start.bat (или python main.py).

Программа поднимает локальный интерфейс на 127.0.0.1 и открывает его в отдельном окне Microsoft Edge
(режим приложения, без адресной строки). У часов Windows появляется значок программы.
Если включена «Работа в фоне», закрытие окна не останавливает VPN: программа остаётся у часов,
выйти можно через меню значка. Без фона закрытие окна завершает программу и отключает VPN.
Параметр --autostart (запуск вместе с Windows): при работе в фоне окно не открывается — только значок."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import time
import urllib.request
import webbrowser

APP_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, APP_DIR)


def _apply_update() -> str:
    """Скачанное обновление ставится до загрузки кода программы — новая версия запускается целиком новой."""
    import importlib.util
    path = os.path.join(APP_DIR, "pult", "apply_update.py")
    if not os.path.isdir(os.path.join(APP_DIR, "data", "update")) or not os.path.isfile(path):
        return ""
    try:
        spec = importlib.util.spec_from_file_location("vedomyj_apply_update", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.apply(APP_DIR)
    except Exception:
        return ""


UPDATED_TO = _apply_update()

from pult import autostart, errorlog  # noqa: E402
from pult.engine import Engine  # noqa: E402
from pult.tray import Tray  # noqa: E402
from pult.webui import UIServer  # noqa: E402

TRAY_TEXTS = {
    "ru": {"tray_open": "Открыть VEDOMYJ VPN", "tray_connect": "Подключить", "tray_disconnect": "Отключить",
           "tray_exit": "Выход", "on": "подключено", "off": "отключено", "tray_hour": "Включить на 1 час",
           "bg_title": "VEDOMYJ VPN работает в фоне",
           "bg_text": "VPN продолжает работать. Открыть окно — двойной щелчок по значку, выйти — правой кнопкой → «Выход»."},
    "en": {"tray_open": "Open VEDOMYJ VPN", "tray_connect": "Connect", "tray_disconnect": "Disconnect",
           "tray_exit": "Exit", "on": "connected", "off": "disconnected", "tray_hour": "Turn on for 1 hour",
           "bg_title": "VEDOMYJ VPN is running in the background",
           "bg_text": "VPN keeps working. Double-click the icon to open the window, right-click → “Exit” to quit."},
}

IS_WINDOWS = sys.platform == "win32"
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


def browser_candidates() -> list[str]:
    if not IS_WINDOWS:
        return []
    roots = [os.environ.get(k, "") for k in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA")]
    rel = [r"Microsoft\Edge\Application\msedge.exe", r"Google\Chrome\Application\chrome.exe",
           r"Yandex\YandexBrowser\Application\browser.exe", r"BraveSoftware\Brave-Browser\Application\brave.exe"]
    found = []
    for r in rel:
        for root in roots:
            p = os.path.join(root, r) if root else ""
            if p and os.path.isfile(p) and p not in found:
                found.append(p)
    return found


def open_window(url: str, profile_dir: str) -> subprocess.Popen | None:
    """Окно-приложение без вкладок и адресной строки. Если подходящего браузера нет — обычная вкладка."""
    for exe in browser_candidates():
        try:
            return subprocess.Popen([exe, f"--app={url}", f"--user-data-dir={profile_dir}", "--window-size=820,920",
                                     "--no-first-run", "--no-default-browser-check", "--disable-features=Translate",
                                     "--disable-sync"], creationflags=NO_WINDOW)
        except OSError:
            continue
    webbrowser.open(url)
    return None


def existing_instance(ui_file: str) -> str | None:
    """Если программа уже запущена — возвращает адрес её окна."""
    try:
        with open(ui_file, encoding="utf-8") as f:
            info = json.load(f)
        url = f"http://127.0.0.1:{info['port']}/?t={info['token']}"
        req = urllib.request.Request(f"http://127.0.0.1:{info['port']}/api/ping",
                                     headers={"X-Token": info["token"]})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=2) as resp:
            if resp.status == 200:
                return url
    except Exception:
        return None
    return None


def main() -> None:
    data_dir = os.path.join(APP_DIR, "data")
    os.makedirs(data_dir, exist_ok=True)
    ui_file = os.path.join(data_dir, "ui.json")
    profile_dir = os.path.join(data_dir, "window")

    url = existing_instance(ui_file)
    if url:
        open_window(url, profile_dir)
        return

    token = secrets.token_urlsafe(24)
    ui = UIServer(os.path.join(APP_DIR, "ui"), token)
    engine = Engine(APP_DIR, ui.notify)
    errorlog.install_hooks(engine.errors)  # необработанные исключения — в журнал ошибок
    ui.engine = engine
    if UPDATED_TO:
        engine.just_updated = UPDATED_TO
        engine.log(f"Программа обновлена до версии {UPDATED_TO}.")
    port = ui.start()
    with open(ui_file, "w", encoding="utf-8") as f:
        json.dump({"port": port, "token": token, "pid": os.getpid()}, f)

    engine.startup()
    try:
        # автозапуск включён — обновить запись: новый путь программы и новое имя (старая «PultVPN» убирается)
        if autostart.is_enabled():
            autostart.set_enabled(APP_DIR, True)
    except Exception:
        pass
    url = f"http://127.0.0.1:{port}/?t={token}"

    def text(key: str) -> str:
        return TRAY_TEXTS.get(engine.settings.get("lang", "ru"), TRAY_TEXTS["ru"])[key]

    def toggle() -> None:
        try:
            ui.dispatch("toggle", {})
        except Exception:
            pass

    def for_hour() -> None:
        try:
            ui.dispatch("connect_for", {"minutes": 60})
        except Exception:
            pass

    tray = Tray(os.path.join(APP_DIR, "ui", "icons", "app.ico"), on_open=lambda: open_window(url, profile_dir),
                on_toggle=toggle, on_exit=ui.exit_event.set, texts=text, on_hour=for_hour)
    background = lambda: bool(engine.settings.get("background")) and tray.ok  # noqa: E731
    if not ("--autostart" in sys.argv and background()):
        open_window(url, profile_dir)

    hotkey = None  # применённая горячая клавиша; меняется в «Функциях» — подхватываем на лету
    started = time.monotonic()
    fallback_done = False
    window_open = False
    last_tip = ""
    try:
        while not ui.exit_event.is_set():
            time.sleep(1)
            st = "on" if engine.connected else "off"
            where = engine.current.name if engine.connected and engine.current else ""
            tip = f"VEDOMYJ VPN — {text(st)}" + (f": {where}" if where else "")
            if tip != last_tip:
                tray.update(engine.connected, tip)
                last_tip = tip
            want = engine.settings.get("hotkey", "Ctrl+Alt+V") if engine.settings.get("hotkey_enabled", True) else ""
            if want != hotkey:
                hotkey = want
                tray.set_hotkey(want)
            engine.hotkey_state = {"key": hotkey, "ok": tray.hotkey_ok, "supported": tray.ok}
            clients = ui.client_count()
            engine.ui_clients = clients
            mins = int(engine.settings.get("pin_lock_minutes") or 0)
            if ui.pin_set() and ui.unlocked and (
                    (not clients and time.monotonic() - ui.last_client_change > 12)  # окно закрыли
                    or (mins and time.monotonic() - ui.last_action > mins * 60)):  # давно ничего не делали
                ui.lock_window()
            if engine.tray_queue:
                title, msg = engine.tray_queue.popleft()
                if not clients:  # окно открыто — там уже показан вопрос с кнопками
                    tray.balloon(title, msg)
            if clients:
                window_open = True
                continue
            idle = time.monotonic() - ui.last_client_change
            if ui.had_client and idle > 12:
                if not background():
                    break  # окно закрыто — выходим
                if window_open:
                    window_open = False
                    if not engine.settings.get("background_hint_shown"):
                        tray.balloon(text("bg_title"), text("bg_text"))
                        engine.settings["background_hint_shown"] = True
                        engine.save()
                continue
            if not ui.had_client and not background():
                waited = time.monotonic() - started
                if waited > 25 and not fallback_done:
                    webbrowser.open(url)  # окно не открылось — пробуем обычный браузер
                    fallback_done = True
                elif waited > 120:
                    break
    except KeyboardInterrupt:
        pass
    finally:
        tray.stop()
        engine.shutdown()
        ui.stop()
        try:
            os.remove(ui_file)
        except OSError:
            pass
        if ui.restart:  # «Перезапустить и обновить»: новая копия программы поставит обновление при запуске
            try:
                subprocess.Popen([sys.executable, os.path.join(APP_DIR, "main.py")], cwd=APP_DIR,
                                 creationflags=NO_WINDOW, close_fds=True)
            except OSError:
                pass


if __name__ == "__main__":
    main()
