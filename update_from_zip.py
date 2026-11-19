"""Обновление VEDOMYJ VPN из архива поверх старой версии. Запуск: «Обновить.bat» (можно перетащить архив на него).

Что остаётся как было: папка data (подписки, настройки, вход в аккаунт подписки, свои серверы и правила),
bin (ядро Xray и списки сайтов), python (встроенный Python сборки). Заменяется только код программы.
Перед заменой настройки копируются в data/backups — на всякий случай.
"""

import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

APP_DIR = os.path.dirname(os.path.abspath(__file__))
KEEP = ("data", "bin", "python", ".git", "__pycache__")  # это из архива не берём и в программе не трогаем
BACKUPS_KEEP = 3


def say(text: str = "") -> None:
    print(text, flush=True)


def version_of(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("APP_VERSION"):
            return line.split("=", 1)[1].strip().strip("\"'")
    return "?"


def current_version() -> str:
    try:
        with open(os.path.join(APP_DIR, "pult", "__init__.py"), encoding="utf-8") as f:
            return version_of(f.read())
    except OSError:
        return "?"


def find_zip(args: list[str]) -> str:
    """Архив: перетащенный на «Обновить.bat» или самый новый VedomyjVPN-*.zip в Загрузках, на рабочем столе,
    рядом с программой."""
    for a in args:
        if a.lower().endswith(".zip") and os.path.isfile(a):
            return os.path.abspath(a)
    home = os.path.expanduser("~")
    places = [os.path.join(home, "Downloads"), os.path.join(home, "Загрузки"), os.path.join(home, "Desktop"),
              os.path.join(home, "OneDrive", "Desktop"), os.path.dirname(APP_DIR), APP_DIR]
    found = []
    for place in places:
        found += glob.glob(os.path.join(place, "VedomyjVPN*.zip"))
    found = [f for f in set(found) if os.path.isfile(f)]
    return max(found, key=os.path.getmtime) if found else ""


def read_zip(path: str) -> tuple[zipfile.ZipFile, str, str]:
    """(архив, папка программы внутри архива, версия). Чужой архив — ошибка."""
    z = zipfile.ZipFile(path)
    names = z.namelist()
    roots = [n[:-len("pult/__init__.py")] for n in names if n.endswith("pult/__init__.py")
             and n.count("/") <= 2]
    roots = [r for r in roots if r + "main.py" in names]
    if not roots:
        raise RuntimeError("это не архив VEDOMYJ VPN (внутри нет main.py и pult)")
    root = min(roots, key=len)
    version = version_of(z.read(root + "pult/__init__.py").decode("utf-8", "replace"))
    return z, root, version


def safe_target(rel: str) -> str | None:
    """Куда положить файл из архива; None — пропустить (наши данные или подозрительный путь)."""
    rel = rel.replace("\\", "/")
    parts = [p for p in rel.split("/") if p]
    if not parts or parts[0] in KEEP or any(p in ("..", ".") for p in parts) or ":" in parts[0]:
        return None
    target = os.path.normpath(os.path.join(APP_DIR, *parts))
    if os.path.commonpath([target, APP_DIR]) != APP_DIR:
        return None
    return target


def ui_info() -> dict | None:
    try:
        with open(os.path.join(APP_DIR, "data", "ui.json"), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def api(info: dict, action: str, timeout: float = 4.0) -> bool:
    req = urllib.request.Request(f"http://127.0.0.1:{info['port']}/api/action",
                                 data=json.dumps({"action": action, "args": {}}).encode(),
                                 headers={"X-Token": info["token"], "Content-Type": "application/json"})
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=timeout) as resp:
            return resp.status == 200
    except OSError:
        return False


def running(info: dict | None) -> bool:
    if not info:
        return False
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(f"http://127.0.0.1:{info['port']}/api/state", headers={"X-Token": info["token"]})
        with opener.open(req, timeout=2):
            return True
    except urllib.error.HTTPError:
        return True  # отвечает (например, заперто пин-кодом) — значит, работает
    except OSError:
        return False


def stop_program() -> bool:
    """Аккуратно закрывает работающую программу (она сама вернёт настройки прокси Windows). True — была запущена."""
    info = ui_info()
    if not running(info):
        return False
    say("Закрываю работающую программу…")
    api(info, "quit")
    for _ in range(40):
        time.sleep(0.5)
        if not running(info):
            time.sleep(1.5)  # ядро Xray останавливается следом
            return True
    raise RuntimeError("программа не закрылась сама. Закрой её через значок у часов (правой кнопкой → «Выход») "
                       "и запусти обновление ещё раз")


def backup_settings() -> str:
    """Копия настроек и подписок (маленькие файлы из data) — в data/backups. Хранятся три последние."""
    data = os.path.join(APP_DIR, "data")
    if not os.path.isdir(data):
        return ""
    root = os.path.join(data, "backups")
    dest = os.path.join(root, time.strftime("before-update-%Y%m%d-%H%M%S"))
    os.makedirs(dest, exist_ok=True)
    for name in os.listdir(data):
        src = os.path.join(data, name)
        if os.path.isfile(src) and os.path.getsize(src) <= 5 * 1024 * 1024:
            shutil.copy2(src, os.path.join(dest, name))
    old = sorted(d for d in os.listdir(root) if d.startswith("before-update-"))
    for d in old[:-BACKUPS_KEEP]:
        shutil.rmtree(os.path.join(root, d), ignore_errors=True)
    return dest


def install(z: zipfile.ZipFile, root: str) -> int:
    """Распаковывает код поверх старого. Каждый файл — через временный, чтобы сбой не оставил половину файла."""
    count = 0
    for info in z.infolist():
        if not info.filename.startswith(root) or info.is_dir():
            continue
        target = safe_target(info.filename[len(root):])
        if not target:
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(target), prefix=".upd-")
        with os.fdopen(fd, "wb") as out, z.open(info) as src:
            shutil.copyfileobj(src, out)
        os.replace(tmp, target)
        count += 1
    # старые скомпилированные копии кода — пусть Python соберёт их заново из новых файлов
    for cache in glob.glob(os.path.join(APP_DIR, "pult", "__pycache__")):
        shutil.rmtree(cache, ignore_errors=True)
    return count


def start_program() -> None:
    bat = os.path.join(APP_DIR, "start.bat")
    if sys.platform == "win32" and os.path.isfile(bat):
        subprocess.Popen(["cmd", "/c", bat], cwd=APP_DIR, creationflags=0x00000008)  # DETACHED_PROCESS


def main(args: list[str]) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ask = "--yes" not in args
    no_start = "--no-start" in args
    say("Обновление VEDOMYJ VPN поверх старой версии")
    say("Подписки, настройки и вход в аккаунт подписки остаются — папка data не трогается.")
    say()
    path = find_zip([a for a in args if not a.startswith("--")])
    if not path:
        say("Не нашёл архив с новой версией (VedomyjVPN-….zip) в Загрузках, на рабочем столе и рядом с программой.")
        say("Перетащи архив мышкой на файл «Обновить.bat».")
        return 1
    try:
        z, root, new = read_zip(path)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        say(f"Архив {os.path.basename(path)} не подходит: {exc}.")
        return 1
    old = current_version()
    say(f"Архив:          {path}")
    say(f"Сейчас стоит:   {old}")
    say(f"Новая версия:   {new}")
    if ask:
        say()
        reply = input("Обновить? Enter — да, N и Enter — нет: ").strip().lower()
        if reply in ("n", "н", "no", "нет"):
            say("Ничего не менял.")
            return 0
    try:
        was_running = stop_program()
        saved = backup_settings()
        if saved:
            say(f"Копия настроек: {os.path.relpath(saved, APP_DIR)}")
        n = install(z, root)
    except (OSError, RuntimeError) as exc:
        say()
        say(f"Не получилось: {exc}.")
        say("Старая версия и все данные на месте. Закрой программу и антивирусные проверки папки и попробуй ещё раз.")
        return 1
    finally:
        z.close()
    say(f"Готово: обновлено файлов — {n}. Версия {old} → {new}.")
    if (was_running or ask) and not no_start:
        say("Запускаю программу…")
        start_program()
    return 0


if __name__ == "__main__":
    code = main(sys.argv[1:])
    if "--yes" not in sys.argv:
        try:
            input("\nНажми Enter, чтобы закрыть окно.")
        except EOFError:
            pass
    sys.exit(code)
