"""Установка скачанного обновления при запуске программы. Только стандартная библиотека и без импорта
остальной программы: main.py загружает этот файл напрямую, до того как прочитает код программы,
чтобы новая версия запустилась целиком новой."""

import json
import os
import shutil

KEEP = ("data", "bin", "python", ".git")


def apply(app_dir: str) -> str:
    """data/update/files → папка программы. Возвращает новую версию или ''. Данные и ядро не трогаются."""
    root = os.path.join(app_dir, "data", "update")
    ready = os.path.join(root, "ready.json")
    files = os.path.join(root, "files")
    if not os.path.isfile(ready) or not os.path.isdir(files):
        return ""
    try:
        with open(ready, encoding="utf-8") as f:
            version = json.load(f).get("version", "")
        for base, _dirs, names in os.walk(files):
            rel = os.path.relpath(base, files)
            if rel.split(os.sep)[0] in KEEP:
                continue
            target = app_dir if rel == "." else os.path.join(app_dir, rel)
            os.makedirs(target, exist_ok=True)
            for name in names:
                shutil.copy2(os.path.join(base, name), os.path.join(target, name))
        return version
    finally:
        shutil.rmtree(root, ignore_errors=True)
