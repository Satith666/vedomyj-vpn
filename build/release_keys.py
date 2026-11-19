"""Создать ключи подписи выпусков (один раз, на своём компьютере). Только стандартная библиотека.

    python build/release_keys.py

Выведет:
  • ОТКРЫТЫЙ ключ — вставь его в pult/update.py (PUBLIC_KEY) и в Android (core/Update.java, PUBLIC_N);
  • ЗАКРЫТЫЙ ключ — сохранится в файл release_key.json рядом. Положи его содержимое в секрет GitHub
    RELEASE_KEY (Settings → Secrets → Actions) и УДАЛИ файл. Никому не показывай и не клади в репозиторий.
"""

import json
import os
import secrets
import sys


def _probable_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(40):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int) -> int:
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _probable_prime(c):
            return c


def generate(bits: int = 3072) -> dict:
    e = 65537
    while True:
        p, q = _prime(bits // 2), _prime(bits // 2)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e:
            break
    return {"n": p * q, "e": e, "d": pow(e, -1, phi)}


if __name__ == "__main__":
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "release_key.json")
    if os.path.exists(out):
        sys.exit("release_key.json уже есть — не перезаписываю.")
    key = generate()
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"n": str(key["n"]), "e": key["e"], "d": str(key["d"])}, f)
    print("Открытый ключ (вставь в pult/update.py → PUBLIC_KEY):")
    print(json.dumps({"n": key["n"], "e": key["e"]}))
    print(f"\nЗакрытый ключ записан в {out} — перенеси в секрет GitHub RELEASE_KEY и удали файл.")
