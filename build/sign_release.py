"""Подписать файл выпуска latest.json (в GitHub Actions после сборки).

    RELEASE_KEY='{"n": "...", "e": 65537, "d": "..."}' python build/sign_release.py latest.json

Превращает файл в {"payload": …, "sig": …}. Ключ берётся только из переменной окружения RELEASE_KEY (секрет GitHub).
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from pult.update import pack, unpack  # noqa: E402

if __name__ == "__main__":
    raw = os.environ.get("RELEASE_KEY", "")
    if not raw:
        sys.exit("Нет переменной RELEASE_KEY (секрет GitHub с закрытым ключом).")
    key = json.loads(raw)
    n, d, e = int(key["n"]), int(key["d"]), int(key.get("e", 65537))
    path = sys.argv[1]
    with open(path, encoding="utf-8") as f:
        manifest = json.load(f)
    if "payload" in manifest:
        sys.exit("Файл уже подписан.")
    signed = pack(manifest, n, d)
    if unpack(signed, {"n": n, "e": e}) != manifest:
        sys.exit("Подпись не проверилась — ключ испорчен.")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(signed, f, ensure_ascii=False, indent=1)
    print("Подписано:", path)
