"""Обновление самой программы: файл выпуска latest.json на GitHub, подписанный ключом владельца.

latest.json: {"payload": "<JSON-строка>", "sig": "<base64>"}. В payload: {"version", "notes", "pc": {"url", "sha256"},
"android": {"url", "sha256", "version_code"}}. Подпись — RSA PKCS#1 v1.5 + SHA-256 над байтами payload (UTF-8):
программа для ПК и телефона проверяют одни и те же байты, без пересборки JSON.
Открытый ключ вшит сюда (PUBLIC_KEY); закрытый хранится только у владельца (секрет GitHub Actions).
Пока ключа и адреса нет (UPDATE_URL пустой), автообновление выключено — программа так и пишет.

Скачанное обновление проверяется по SHA-256 из подписанного файла, распаковывается в data/update/ и
ставится при следующем запуске (main.py → apply_staged) — до загрузки остального кода программы.
Папки data/, bin/ и python/ обновление не трогает.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import zipfile

from . import APP_VERSION, netutil

# адрес latest.json, например https://github.com/<владелец>/vedomyj-vpn/releases/latest/download/latest.json
UPDATE_URL = ""
# открытый ключ подписи выпусков: {"n": <модуль>, "e": 65537} (создаётся build/release_keys.py)
PUBLIC_KEY: dict = {}

KEEP = ("data", "bin", "python", ".git")
ALLOW_HTTP = False  # только для самопроверки (локальный сервер без https)
_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


class UpdateError(Exception):
    pass


def configured() -> bool:
    return bool(UPDATE_URL and PUBLIC_KEY.get("n"))


def pack(manifest: dict, n: int, d: int) -> dict:
    """Подписать выпуск (build/sign_release.py)."""
    import base64
    payload = json.dumps(manifest, ensure_ascii=False, sort_keys=True)
    return {"payload": payload, "sig": base64.b64encode(rsa_sign(payload.encode("utf-8"), n, d)).decode()}


def rsa_verify(message: bytes, sig: bytes, n: int, e: int) -> bool:
    """RSA PKCS#1 v1.5 с SHA-256: сравниваем блок целиком — без разбора, поэтому без известных обходов."""
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    m = pow(int.from_bytes(sig, "big"), e, n)
    em = m.to_bytes(k, "big")
    t = _SHA256_PREFIX + hashlib.sha256(message).digest()
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return em == expected


def rsa_sign(message: bytes, n: int, d: int) -> bytes:
    k = (n.bit_length() + 7) // 8
    t = _SHA256_PREFIX + hashlib.sha256(message).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")


def unpack(signed: dict, key: dict | None = None) -> dict | None:
    """Проверить подпись и вернуть выпуск (или None, если подпись не сходится)."""
    import base64
    key = key or PUBLIC_KEY
    try:
        payload = signed["payload"]
        sig = base64.b64decode(signed.get("sig", ""))
        if not rsa_verify(payload.encode("utf-8"), sig, int(key["n"]), int(key.get("e", 65537))):
            return None
        manifest = json.loads(payload)
        return manifest if isinstance(manifest, dict) else None
    except Exception:
        return None


def newer(a: str, b: str) -> bool:
    """Версия a новее b ("1.10.0" > "1.9.3")."""
    def parts(v):
        return tuple(int(x) for x in (v or "0").split(".") if x.isdigit())
    return parts(a) > parts(b)


def fetch_manifest(proxy_port: int | None = None, url: str | None = None, key: dict | None = None) -> dict:
    status, _, body = netutil.http_get(url or UPDATE_URL, proxy_port=proxy_port, timeout=20, max_bytes=256 * 1024,
                                       doh=True)
    if status != 200:
        raise UpdateError(f"файл выпуска не скачался (код {status})")
    try:
        signed = json.loads(body.decode("utf-8"))
    except ValueError as exc:
        raise UpdateError("файл выпуска испорчен") from exc
    manifest = unpack(signed, key) if isinstance(signed, dict) else None
    if manifest is None:
        raise UpdateError("подпись выпуска не сходится — обновление не будет установлено")
    return manifest


def stage(manifest: dict, data_dir: str, proxy_port: int | None = None) -> str:
    """Скачать архив для ПК, проверить SHA-256, распаковать в data/update/files. → путь к готовому обновлению."""
    pc = manifest.get("pc") or {}
    url, want = pc.get("url", ""), str(pc.get("sha256", "")).lower()
    if not (url.startswith("https://") or (ALLOW_HTTP and url.startswith("http://"))) or len(want) != 64:
        raise UpdateError("в файле выпуска нет архива для компьютера")
    root = os.path.join(data_dir, "update")
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root, exist_ok=True)
    archive = os.path.join(root, "update.zip")
    netutil.download_file(url, archive, proxy_port=proxy_port, timeout=300)
    h = hashlib.sha256()
    with open(archive, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    if h.hexdigest() != want:
        shutil.rmtree(root, ignore_errors=True)
        raise UpdateError("архив обновления повреждён (не совпала контрольная сумма)")
    files = os.path.join(root, "files")
    with zipfile.ZipFile(archive) as z:
        for info in z.infolist():
            name = info.filename.replace("\\", "/")
            parts = [p for p in name.split("/") if p]
            if parts and parts[0] == "VedomyjVPN":
                parts = parts[1:]
            if not parts or ".." in parts or name.startswith("/") or ":" in parts[0] or parts[0] in KEEP:
                continue  # чужие пути и папки с данными не трогаем
            dest = os.path.join(files, *parts)
            if info.is_dir():
                os.makedirs(dest, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with z.open(info) as src, open(dest, "wb") as out:
                shutil.copyfileobj(src, out)
    os.remove(archive)
    with open(os.path.join(root, "ready.json"), "w", encoding="utf-8") as f:
        json.dump({"version": manifest.get("version", ""), "from": APP_VERSION}, f)
    return root


def apply_staged(app_dir: str) -> str:
    """Поставить готовое обновление (см. apply_update.py — его main.py вызывает до загрузки программы)."""
    from .apply_update import apply
    return apply(app_dir)
