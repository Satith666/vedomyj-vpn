"""Опыт для «своего протокола» (1.26): какие сочетания частей ядра Xray работают поверх шифрования VLESS
на голом TCP, с какой скоростью и как трафик выглядит со стороны провайдера.

Только для сведения (на GitHub, рядом с проверкой своего сервера): ничего не ставит, всегда выходит с кодом 0.
Запуск: python3 build/proto_lab.py [путь к xray]
Между клиентом и сервером стоит «прослушка» (простая пересылка TCP): она считает долю печатных знаков,
случайность (энтропию) и вес байтов — то, по чему оборудование провайдера отличает «шифрованный шум».
"""
from __future__ import annotations

import json
import math
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

XRAY = sys.argv[1] if len(sys.argv) > 1 else "/usr/local/bin/xray"
UUID = "3f1c2a9e-1b2c-4d5e-8f90-1234567890ab"
URL204 = "https://www.gstatic.com/generate_204"
BIG = ("https://proof.ovh.net/files/1Mb.dat", "https://speed.cloudflare.com/__down?bytes=1000000")
UA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/140.0 Safari/537.36"
HTTP_REQ = "GET /api/v2/feed?lang=ru HTTP/1.1\r\nHost: static.example.ru\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n"
HTTP_RESP = "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Tap:
    """Пересылка TCP с записью первых байтов в обе стороны."""

    LIMIT = 256 * 1024

    def __init__(self, target: int):
        self.target = target
        self.up = bytearray()
        self.down = bytearray()
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(64)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _pipe(self, a: socket.socket, b: socket.socket, buf: bytearray) -> None:
        try:
            while True:
                data = a.recv(65536)
                if not data:
                    break
                if len(buf) < self.LIMIT:
                    buf.extend(data[: self.LIMIT - len(buf)])
                b.sendall(data)
        except OSError:
            pass
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _accept(self) -> None:
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            try:
                u = socket.create_connection(("127.0.0.1", self.target), timeout=5)
                u.settimeout(None)
            except OSError:
                c.close()
                continue
            threading.Thread(target=self._pipe, args=(c, u, self.up), daemon=True).start()
            threading.Thread(target=self._pipe, args=(u, c, self.down), daemon=True).start()

    def close(self) -> None:
        self.srv.close()


def stats(data: bytes) -> str:
    if not data:
        return "нет данных"
    n = len(data)
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    ent = -sum(c / n * math.log2(c / n) for c in counts if c)
    weight = sum(bin(b).count("1") for b in data) / n
    head = data[:20]
    shown = "".join(chr(b) if 32 <= b < 127 else "·" for b in head)
    return f"текст {printable * 100 // n}%, энтропия {ent:.2f} бит/байт, вес {weight:.2f}, начало «{shown}»"


def vlessenc() -> tuple[str, str]:
    out = subprocess.run([XRAY, "vlessenc"], capture_output=True, text=True, timeout=30).stdout
    encs = re.findall(r'"encryption": *"([^"]+)"', out)
    decs = re.findall(r'"decryption": *"([^"]+)"', out)
    i = next((k for k, e in enumerate(encs) if len(e) < 300), -1)
    return (encs[i], decs[i]) if 0 <= i < len(decs) else ("", "")


def run(cfg: dict, name: str) -> tuple[subprocess.Popen | None, str]:
    path = os.path.join(tempfile.gettempdir(), f"proto-lab-{name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    t = subprocess.run([XRAY, "run", "-test", "-c", path], capture_output=True, text=True, timeout=30)
    if t.returncode != 0:
        tail = [ln for ln in (t.stdout + t.stderr).splitlines() if ln.strip()][-2:]
        return None, " / ".join(tail)[-300:]
    p = subprocess.Popen([XRAY, "run", "-c", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return p, ""


def fetch(port: int, url: str, timeout: float = 60.0) -> tuple[int, int, float]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(
        {"http": f"http://127.0.0.1:{port}", "https": f"http://127.0.0.1:{port}"}))
    t0 = time.time()
    try:
        with opener.open(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=timeout) as r:
            return r.status, len(r.read()), time.time() - t0
    except urllib.error.HTTPError as exc:
        return exc.code, 0, time.time() - t0
    except OSError:
        return 0, 0, time.time() - t0


def probe(port: int, payload: bytes) -> str:
    """Что видит чужой, который постучался на порт сервера."""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(payload)
        s.settimeout(4)
        t0 = time.time()
        got = b""
        try:
            while len(got) < 512:
                d = s.recv(512)
                if not d:
                    break
                got += d
        except socket.timeout:
            return f"молчит {time.time() - t0:.0f}+ с" + (f", прислал {len(got)} байт" if got else "")
        s.close()
        return f"закрыл через {time.time() - t0:.1f} с" + (f", прислал {len(got)} байт: {got[:40]!r}" if got else "")
    except OSError as exc:
        return f"ошибка {exc}"


def variants(pw: str) -> list[tuple[str, list]]:
    hc = {"type": "header-custom", "settings": {
        "clients": [[{"delay": 0, "type": "str", "packet": HTTP_REQ}]],
        "servers": [[{"delay": 0, "type": "str", "packet": HTTP_RESP}]]}}
    return [
        ("без маскировки (только шифрование VLESS)", []),
        ("sudoku, режим «текст»", [{"type": "sudoku", "settings": {"password": pw, "ascii": "prefer_ascii"}}]),
        ("sudoku, режим «шум»", [{"type": "sudoku", "settings": {"password": pw, "ascii": "prefer_entropy"}}]),
        ("sudoku «текст» + паддинг 5–15", [{"type": "sudoku", "settings": {"password": pw, "ascii": "prefer_ascii",
                                                                       "paddingMin": 5, "paddingMax": 15}}]),
        ("sudoku, своя таблица xpxvvpvv", [{"type": "sudoku", "settings": {"password": pw, "customTable": "xpxvvpvv"}}]),
        ("поддельное HTTP-приветствие", [hc]),
        ("sudoku «текст» + HTTP-приветствие", [{"type": "sudoku", "settings": {"password": pw, "ascii": "prefer_ascii"}}, hc]),
    ]


def main() -> int:
    ver = subprocess.run([XRAY, "version"], capture_output=True, text=True).stdout.splitlines()[:1]
    print(f"\n== Опыт: свой протокол. Ядро: {ver[0] if ver else '?'}")
    enc, dec = vlessenc()
    if not enc:
        print("[INFO] ядро не создало ключ шифрования VLESS — опыт пропущен")
        return 0
    pw = "vedomyj-lab-" + os.urandom(6).hex()
    for name, masks in variants(pw):
        sport, cport = free_port(), free_port()
        tap = Tap(sport)
        fm = {"finalmask": {"tcp": masks}} if masks else {}
        scfg = {"log": {"loglevel": "warning"},
                "inbounds": [{"listen": "127.0.0.1", "port": sport, "protocol": "vless",
                              "settings": {"clients": [{"id": UUID}], "decryption": dec},
                              "streamSettings": {"network": "raw", **fm}}],
                "outbounds": [{"protocol": "freedom"}]}
        ccfg = {"log": {"loglevel": "warning"},
                "inbounds": [{"listen": "127.0.0.1", "port": cport, "protocol": "http", "settings": {}}],
                "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": tap.port,
                               "users": [{"id": UUID, "encryption": enc}]}]},
                               "streamSettings": {"network": "raw", **fm}}]}
        procs = []
        try:
            sp, serr = run(scfg, "server")
            cp, cerr = run(ccfg, "client")
            procs = [p for p in (sp, cp) if p]
            if serr or cerr:
                print(f"[INFO] {name}: ядро не приняло — {serr or cerr}")
                continue
            time.sleep(1.2)
            code, _, sec = fetch(cport, URL204)
            if code != 204:
                print(f"[INFO] {name}: не работает (ответ {code}, {sec:.1f} с)")
                continue
            got = (0, 0, 0.0)
            for url in BIG:
                got = fetch(cport, url, timeout=90)
                if got[0] == 200:
                    break
            mbit = got[1] * 8 / max(got[2], 0.01) / 1e6
            print(f"[INFO] {name}: работает, 1 МБ за {got[2]:.1f} с ≈ {mbit:.1f} Мбит/с")
            print(f"       клиент→сервер: {stats(bytes(tap.up))}")
            print(f"       сервер→клиент: {stats(bytes(tap.down))}")
            print(f"       чужой «зонд» HTTP: {probe(sport, b'GET / HTTP/1.1' + bytes([13, 10]) + b'Host: x' + bytes([13, 10, 13, 10]))}")
            print(f"       чужой «зонд» шум:  {probe(sport, os.urandom(300))}")
        finally:
            for p in procs:
                p.terminate()
            tap.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 — опыт не должен валить проверку
        print(f"[INFO] опыт прерван: {exc}")
        sys.exit(0)
