"""Самопроверка кода: проверяет весь функционал программы на имитации серверов, без интернета и без настоящего Xray.

Запуск: python -m pult.selftest            (отчёт в консоль)
        python -m pult.selftest --json     (отчёт в JSON — так его читает «Проверка программы»)

Внимание: модуль подменяет части программы заглушками, поэтому его нельзя импортировать в работающую программу —
только запускать отдельным процессом.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import http.server
import json
import os
import re
import select
import shutil
import socket
import socketserver
import ssl
import sys
import tempfile
import urllib.error
import urllib.parse
import threading
import time
import traceback
import urllib.request
import zipfile

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

for _k in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "all_proxy"):
    os.environ.pop(_k, None)

from pult import (autostart, certpin, diagnostics, dpi, engine as engmod, happ, hotspot, i18n, links, netutil, qr,  # noqa: E402
                  routing, services, share, subscription, tester, tray, tun, vps, xray)
from pult.webui import UIServer  # noqa: E402

RESULTS: list[dict] = []
MESSAGES: list[str] = []  # все сообщения для проверки перевода


def case(name: str):
    def deco(fn):
        def run():
            t0 = time.perf_counter()
            try:
                fn()
                RESULTS.append({"name": name, "ok": True, "ms": round((time.perf_counter() - t0) * 1000)})
            except AssertionError as exc:
                RESULTS.append({"name": name, "ok": False, "error": str(exc) or "проверка не прошла",
                                "trace": traceback.format_exc(limit=3)})
            except Exception as exc:
                RESULTS.append({"name": name, "ok": False, "error": f"{exc.__class__.__name__}: {exc}",
                                "trace": traceback.format_exc(limit=5)})
        run.__name__ = fn.__name__
        CASES.append(run)
        return run
    return deco


CASES: list = []


def check(cond, msg: str):
    if not cond:
        raise AssertionError(msg)


# ---------- имитация: веб-сервер, прокси-«серверы», ядро ----------

BIG = b"x" * (4 * 1024 * 1024)
SUB_LINKS = [
    "vless://11111111-1111-1111-1111-111111111111@fast.example:443?security=reality&pbk=K&sni=a.com&type=tcp"
    "#%F0%9F%87%B3%F0%9F%87%B1%20Fast",
    "vless://22222222-2222-2222-2222-222222222222@slow.example:443?security=reality&pbk=K&sni=a.com&type=xhttp"
    "&path=%2Fx#Slow",
    "trojan://pw@dead.example:443?sni=d#Dead",
    "hysteria://x@h.example:443#Hy2",  # Hysteria первой версии — не поддерживается
]
STUB = "vless://1b2c3d4e-0000-4000-8000-000000000001@45.12.0.1:443?security=none&type=tcp#Включите отправку HWID"


class Web(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body: bytes, headers=None):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (ConnectionResetError, BrokenPipeError):
            pass  # проверка «идут ли данные» берёт первые 64 КБ и закрывает соединение

    def do_GET(self):
        path = self.path.split("://", 1)[1].split("/", 1)[1] if "://" in self.path else self.path.lstrip("/")
        path = "/" + path
        hwid = self.headers.get("x-hwid")
        if path.startswith("/generate_204"):
            return self._send(204, b"")
        if path.startswith("/big"):
            return self._send(200, BIG)
        if path.startswith("/sub"):
            body = base64.b64encode("\n".join(SUB_LINKS).encode())
            return self._send(200, body, {"subscription-userinfo": "upload=1048576; download=5368709120; "
                                                                   "total=53687091200; expire=1893456000",
                                          "profile-title": "base64:" + base64.b64encode("Мой VPN".encode()).decode()})
        if path.startswith("/hwid"):
            body = "\n".join(SUB_LINKS[:2]) if hwid else STUB
            return self._send(200, base64.b64encode(body.encode()))
        if path.startswith("/limit"):
            return self._send(200, base64.b64encode(STUB.encode()), {"x-hwid-max-devices-reached": "true"})
        if path.startswith("/html"):
            return self._send(200, b"<!doctype html><html>page</html>")
        if path.startswith("/captive"):
            if CAPTIVE["on"]:
                return self._send(302, b"", {"Location": "http://login.cafe.example/"})
            return self._send(204, b"")
        if path.startswith("/geo/"):  # списки сайтов: основной адрес «не открывается» (404), запасной — да
            if path.startswith("/geo/main/") and not self.headers.get("X-Fake-Proxy"):
                return self._send(404, b"")
            return self._send(200, b"G" * 20000)
        if path.startswith("/xray-api"):  # API GitHub исчерпал лимит запросов
            return self._send(403, b'{"message":"API rate limit exceeded"}')
        if path.startswith("/xray-page"):
            return self._send(302, b"", {"Location": "/xray/releases/tag/v26.12.1"})
        if path.startswith("/xray/releases/tag/"):
            return self._send(200, b"release page")
        if path.startswith("/rkn"):  # заглушка провайдера интернета вместо подписки
            if self.headers.get("X-Fake-Proxy"):  # через VPN — настоящая подписка
                return self._send(200, base64.b64encode("\n".join(SUB_LINKS).encode()))
            return self._send(200, "<html><body>Доступ к ресурсу ограничен по решению Роскомнадзора</body></html>".encode())
        if path.startswith("/403"):
            return self._send(403, b"no")
        if path.startswith("/doh"):  # защищённый DNS (RFC 8484): знает только «pinned…» и «*.example» серверов
            DOH_HITS.append(path)
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query).get("dns", [""])[0]
            wire = base64.urlsafe_b64decode(q + "=" * (-len(q) % 4))
            labels, i = [], 12
            while wire[i]:
                labels.append(wire[i + 1:i + 1 + wire[i]].decode())
                i += 1 + wire[i]
            name = ".".join(labels)
            ip = DOH_ANSWERS.get(name) or ("127.0.0.1" if name.startswith("pinned") else "")
            head = bytes.fromhex("00008180" if ip else "00008183") + b"\x00\x01" + (b"\x00\x01" if ip else b"\x00\x00") + b"\x00" * 4
            body = head + wire[12:i + 5]
            if ip:
                body += bytes.fromhex("c00c000100010000003c0004") + bytes(int(x) for x in ip.split("."))
            return self._send(200, body, {"Content-Type": "application/dns-message"})
        if path.startswith("/release/"):  # выпуск программы для автообновления
            body = RELEASE.get(path[9:])
            return self._send(200, body) if body is not None else self._send(404, b"")
        if path.startswith("/ads/"):  # списки рекламы: основной (по силе), всплывающие окна, российская реклама
            name = path[5:]
            if name == "broken":
                return self._send(500, b"")
            body = ADS_LISTS.get(name, "")
            return self._send(200, body.encode()) if body else self._send(404, b"")
        return self._send(302, b"", {"Location": "/x"})


RELEASE: dict = {}
DOH_HITS: list = []
CAPTIVE = {"on": False}
DOH_ANSWERS: dict = {}  # имя → адрес, который «знает» защищённый DNS


def _ot(rule: dict) -> str:
    """Куда ведёт правило; балансировщик мгновенного переключения — это тот же «через VPN»."""
    return rule.get("outboundTag") or ("proxy" if rule.get("balancerTag") == "failover" else "")


ADS_LISTS = {
    "main-multi": "# HaGeZi Multi Normal\n" + "\n".join(f"ads{i}.example-ads.net" for i in range(60))
                  + "\ndoubleclick.net\nad.doubleclick.net\n*.tracker.example\ncdn.allowed-ads.com\n"
                  + "yandex.ru\nwww.youtube.com\ni.imgur.com\nmanga-site.example\n",
    "main-light": "# light\n" + "\n".join(f"light{i}.example-ads.net" for i in range(60)) + "\n",
    "popups": "\n".join(f"pop{i}.popunder.example" for i in range(60)) + "\n0.0.0.0 popads.net\n",
    "threats": "\n".join(f"phish{i}.bad.example" for i in range(60)) + "\n",
    "ru": "! Title: AdGuard Russian filter\n" + "\n".join(f"||ru{i}.adnet.example^" for i in range(60))
          + "\n||yandex.ru^$third-party\n||an.yandex.ru^\n##.banner\n||site.example/ads/*\n",
}


class _TS(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


WEB_SERVER = _TS(("127.0.0.1", 0), Web)
WEB = WEB_SERVER.server_address[1]
threading.Thread(target=WEB_SERVER.serve_forever, daemon=True).start()

BEHAVIOR: dict[int, str] = {}
DEAD: set[str] = set()


def _pipe(a, b):
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 20)
            if not r:
                break
            for s in r:
                d = s.recv(65536)
                if not d:
                    return
                (b if s is a else a).sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass


class FakeProxy:
    """Ведёт себя как HTTP-вход Xray: принимает CONNECT/GET и пересылает на локальный веб-сервер."""

    def __init__(self, port: int):
        self.port = port
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(64)
        self.alive = True
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while self.alive:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(c,), daemon=True).start()

    def handle(self, c):
        try:
            buf = b""
            while b"\r\n\r\n" not in buf:
                d = c.recv(65536)
                if not d:
                    return
                buf += d
            head, rest = buf.split(b"\r\n\r\n", 1)
            method, target, _ = head.split(b"\r\n")[0].decode().split(" ", 2)
            beh = BEHAVIOR.get(self.port, "fast")
            if beh == "empty" and method != "CONNECT":
                c.close()  # «подключено, но пусто»: пинг (туннель) проходит, а загрузка данных — нет
                return
            if beh == "dead":
                if method == "CONNECT":
                    c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    c.recv(1000)
                c.close()
                return
            if beh == "slow":
                time.sleep(0.03)
            up = socket.create_connection(("127.0.0.1", WEB))
            if method == "CONNECT":
                c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                if rest:
                    up.sendall(rest)
            else:
                path = "/" + target.split("://", 1)[1].split("/", 1)[1]
                # пометка «пришло через сервер VPN» — веб-сервер теста отвечает по-разному напрямую и через VPN
                up.sendall(head.replace(target.encode(), path.encode(), 1) + b"\r\nX-Fake-Proxy: 1\r\n\r\n" + rest)
            _pipe(c, up)
        except OSError:
            pass

    def stop(self):
        self.alive = False
        for fn in (lambda: self.sock.shutdown(socket.SHUT_RDWR), self.sock.close):
            try:
                fn()
            except OSError:
                pass


def _addr_behavior(addr: str, masked: bool = False, fp: str | None = "") -> str:
    if addr.startswith("bridge:"):  # ядро Xray ведёт в мост sing-box: работает, если работает сервер за мостом
        return BEHAVIOR.get(int(addr[7:] or 0), "dead")
    if addr in DEAD or addr == "dead.example":
        return "dead"
    if addr.startswith("fpblocked"):  # провайдер режет отпечаток Chrome (как в мае 2026)
        return "dead" if (fp or "chrome") == "chrome" else "fast"
    if addr.startswith("empty"):  # пинг есть, данных нет
        return "empty"
    if addr.startswith("dnsblocked"):  # имя сервера DNS провайдера не находит — работает только по адресу
        return "dead"
    if addr.startswith("dpiblocked"):  # такой сервер провайдер режет, пока нет маскировки
        return "fast" if masked else "dead"
    return "slow" if addr.startswith("slow") else "fast"


def install_fakes():
    def fake_check(paths, cfg, path=None, exe=None):
        json.dumps(cfg)  # конфиг должен сериализоваться
        if "allowInsecure" in json.dumps(cfg):
            return False, "allowInsecure больше не поддерживается ядром"  # как настоящий Xray с июня 2026
        return True, ""

    def fake_pin(host, port, sni, timeout=8.0):
        if host in DEAD or host == "dead.example":
            raise OSError("сервер не отвечает")
        return hashlib.sha256(f"{host}|{sni}".encode()).hexdigest()

    certpin.fetch = fake_pin

    def fake_start(self, config, config_path, wait_for, timeout=8.0, exe=None):
        self.stop()
        self.exe = exe or self.paths.xray
        self._fakes = []
        if "route" in config:  # мост sing-box: вход in{i} → выход out{i} (TUIC, AnyTLS) — поведение по адресу сервера
            SINGBOX_CONFIGS.append(config)
            obs = {o["tag"]: o for o in config["outbounds"]}
            for ib, rule in zip(config["inbounds"], config["route"]["rules"]):
                BEHAVIOR[ib["listen_port"]] = _addr_behavior(obs[rule["outbound"]].get("server", ""))
                self._fakes.append(FakeProxy(ib["listen_port"]))
            self.proc = None
            return
        addr, masked, fps = {}, {}, {}
        for ob in config["outbounds"]:
            st = ob.get("settings", {})
            lst = st.get("vnext") or st.get("servers") or [{}]
            addr[ob.get("tag")] = lst[0].get("address", "") or st.get("address", "")  # Hysteria2: адрес прямо в settings
            if ob.get("protocol") == "socks" and lst[0].get("address") == "127.0.0.1":
                addr[ob.get("tag")] = f"bridge:{lst[0].get('port')}"  # сервер за мостом sing-box
            ss = ob.get("streamSettings") or {}
            masked[ob.get("tag")] = bool(ss.get("finalmask")) or \
                str((ss.get("sockopt") or {}).get("dialerProxy", "")).startswith("mask@")
            fps[ob.get("tag")] = xray.fingerprint_of(ob)
        rules = {r["inboundTag"][0]: r.get("outboundTag") or ("proxy" if r.get("balancerTag") else "")
                 for r in config["routing"]["rules"] if r.get("inboundTag")}
        for ib in config["inbounds"]:
            tag = rules.get(ib["tag"], "proxy")
            key = tag if tag in addr else "proxy"
            BEHAVIOR[ib["port"]] = _addr_behavior(addr.get(key, ""), masked.get(key, False), fps.get(key))
            self._fakes.append(FakeProxy(ib["port"]))
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False)
        self.proc = None

    def fake_stop(self):
        for fp in getattr(self, "_fakes", []):
            fp.stop()
        self._fakes = []

    counter = {"n": 0}

    def fake_stats(paths, port, exe=None):
        counter["n"] += 1
        n = counter["n"]
        return {"proxy": {"uplink": n * 1000, "downlink": n * 50000}, "direct": {"uplink": n * 10, "downlink": n * 900}}

    def fake_api(paths, port, args, exe=None):
        if args[0] == "ado":
            with open(args[1], encoding="utf-8") as f:
                obs = json.load(f)["outbounds"]
            new = obs[0]["settings"].get("vnext", obs[0]["settings"].get("servers", [{}]))[0].get("address", "")
            ss = obs[0].get("streamSettings") or {}
            masked = bool(ss.get("finalmask")) or str((ss.get("sockopt") or {}).get("dialerProxy", "")).startswith("mask@")
            for p, beh in list(BEHAVIOR.items()):
                if HEALTH_PORT.get("port") == p:
                    BEHAVIOR[p] = _addr_behavior(new, masked, xray.fingerprint_of(obs[0]))
        return True

    xray.check_config = fake_check
    tester.check_config = fake_check
    xray.XrayProcess.start = fake_start
    xray.XrayProcess.stop = fake_stop
    xray.XrayProcess.alive = lambda self: bool(getattr(self, "_fakes", []))
    xray.query_stats = fake_stats
    xray.api_command = fake_api
    xray.xray_version = lambda paths, exe=None: "selftest"
    tester.SPEED_URLS = [f"http://127.0.0.1:{WEB}/big"]
    tester.DATA_URLS = [f"http://127.0.0.1:{WEB}/big"]
    tester.DATA_TIMEOUT = 3.0
    netutil.DOH_SERVERS = [(f"http://127.0.0.1:{WEB}/doh", "", "")]  # защищённый DNS — местный, без интернета
    netutil.CAPTIVE_URL = f"http://127.0.0.1:{WEB}/captive"  # «страница входа» Wi-Fi — по команде теста
    # системный прокси Windows (например, работающий VEDOMYJ VPN) не должен влиять на самопроверку
    netutil.system_proxy_url = lambda: None
    services.exit_info = lambda port: {"ip": "203.0.113.5", "loc": "NL", "error": ""}


HEALTH_PORT: dict = {}
SINGBOX_CONFIGS: list = []


def make_engine(tmp: str):
    os.makedirs(os.path.join(tmp, "bin"), exist_ok=True)
    open(os.path.join(tmp, "bin", "xray.exe" if sys.platform == "win32" else "xray"), "w").close()
    events: list[tuple[str, dict]] = []

    def notify(ev, **d):
        events.append((ev, d))
        if isinstance(d.get("text"), str):
            MESSAGES.append(d["text"])

    e = engmod.Engine(tmp, notify)
    e.settings.update(ping_host=f"127.0.0.1:{WEB}", socks_port=netutil.find_free_ports(1, 34000)[0],
                      http_port=netutil.find_free_ports(1, 34100)[0], system_proxy=False, autopilot=False)
    e.events = events
    return e


def wait_idle(e, timeout=30):
    t0 = time.time()
    time.sleep(0.15)
    while e.is_busy() and time.time() - t0 < timeout:
        time.sleep(0.05)
    check(not e.is_busy(), "задача не завершилась вовремя")


# ---------- тесты: разбор ссылок ----------

@case("Ссылки: VLESS Reality / xHTTP / WS / gRPC, VMess, Trojan, Shadowsocks, SOCKS")
def t_links():
    samples = {
        "vless://u@1.2.3.4:443?security=reality&pbk=K&sni=x&fp=chrome&type=tcp&flow=xtls-rprx-vision#a": "reality",
        "vless://u@[2001:db8::1]:8443?type=xhttp&security=tls&sni=e.com&path=%2Fx&mode=packet-up#b": "tls",
        "vless://u@w.example:443?type=ws&security=tls&host=cdn.example&path=%2Fws#c": "tls",
        "vless://u@g.example:443?type=grpc&security=reality&pbk=K&sni=a&serviceName=s#d": "reality",
        "trojan://p%40ss@t.example:443?sni=t.example#e": "tls",
    }
    for link, sec in samples.items():
        s = links.parse_link(link)
        check(s and s.supported, f"не разобралась ссылка {link[:30]}")
        check(s.outbound["streamSettings"]["security"] == sec, f"неверное шифрование у {link[:30]}")
    vm = base64.b64encode(json.dumps({"add": "v.example", "port": 443, "id": "x", "net": "ws", "tls": "tls",
                                      "path": "/p", "ps": "VM"}).encode()).decode()
    s = links.parse_link("vmess://" + vm)
    check(s.supported and s.name == "VM" and s.outbound["streamSettings"]["network"] == "ws", "VMess")
    s = links.parse_link("ss://" + base64.urlsafe_b64encode(b"aes-256-gcm:pw").decode().rstrip("=") + "@1.1.1.1:8388#ss")
    check(s.supported and s.outbound["settings"]["servers"][0]["method"] == "aes-256-gcm", "Shadowsocks")
    s = links.parse_link("socks5://u:p@10.0.0.1:1080#sk")
    check(s.supported and s.outbound["settings"]["servers"][0]["users"][0]["user"] == "u", "SOCKS")


@case("Ссылки: заглушки провайдера, серверы без шифрования, неподдерживаемые")
def t_links_flags():
    s = links.parse_link(STUB)
    check(s.stub and not s.supported, "заглушка «Включите HWID» не распознана")
    s = links.parse_link("vless://u@0.0.0.0:1?security=none#Подписка истекла")
    check(s.stub, "заглушка с адресом 0.0.0.0 не распознана")
    s = links.parse_link("vless://u@plain.example:8080?security=none&type=ws#Обычный")
    check(s.insecure and s.supported, "сервер без шифрования не помечен")
    s = links.parse_link("vless://u@10.0.0.5:8080?security=none#LAN")
    check(not s.insecure, "сервер в локальной сети ошибочно помечен как небезопасный")
    for bad in ("hysteria://x@h:443#h", "https://t.me/proxy?server=1&port=2&secret=3", "happ://crypt3/abc",
                "vless://u@h.com:443?security=reality#nokey"):
        s = links.parse_link(bad)
        check(s is not None and not s.supported, f"неподдерживаемая ссылка принята: {bad[:25]}")


# ---------- тесты: подписки ----------

@case("Подписка: обычная, ссылки-приглашения, трафик и срок")
def t_sub_basic():
    base = f"http://127.0.0.1:{WEB}/sub"
    for raw in (base, "happ://add/" + base, "v2rayng://install-sub?url=" + base.replace(":", "%3A").replace("/", "%2F")):
        sub = subscription.fetch(raw, "v2rayN/7.13.8", timeout=5, hwid="a" * 32)
        check(len(sub.servers) == 4, f"ожидалось 4 сервера, пришло {len(sub.servers)} для {raw[:20]}")
    check(sub.total and sub.expire and sub.title == "Мой VPN", "не прочитаны трафик/срок/название")


@case("Подписка: HWID, лимит устройств, веб-страница, ошибки")
def t_sub_edge():
    sub = subscription.fetch(f"http://127.0.0.1:{WEB}/hwid", "v2rayN/7.13.8", timeout=5, hwid="b" * 32)
    check(len([s for s in sub.servers if s.supported]) == 2, "с HWID должны прийти настоящие серверы")
    sub = subscription.fetch(f"http://127.0.0.1:{WEB}/hwid", "v2rayN/7.13.8", timeout=5, hwid="")
    check(sub.notices, "без HWID должна прийти заглушка")
    sub = subscription.fetch(f"http://127.0.0.1:{WEB}/limit", "v2rayN/7.13.8", timeout=5, hwid="c" * 32)
    check(any("лимит устройств" in w for w in sub.warnings), "нет предупреждения о лимите устройств")
    for path, word in (("/html", "веб-страница"), ("/403", "403")):
        try:
            subscription.fetch(f"http://127.0.0.1:{WEB}{path}", "v2rayN/7.13.8", timeout=5)
            raise AssertionError(f"{path}: ожидалась ошибка")
        except subscription.SubscriptionError as exc:
            check(word in str(exc), f"{path}: в ошибке нет пояснения «{word}»")
    for raw in ("happ://crypt2/zzz", "vless://u@a:1#x", "просто текст"):
        try:
            subscription.normalize_url(raw)
            raise AssertionError(f"«{raw}» должна быть отклонена")
        except subscription.SubscriptionError:
            pass


@case("Подписка заблокирована у провайдера: защищённый DNS, другие серверы, понятная подсказка")
def t_sub_blocked():
    # «через VPN» — всегда через наш прокси, даже для адресов из «исключений» системного прокси Windows
    # (127.*, <local>) и переменной no_proxy: иначе запрос тихо уходит напрямую
    opener = netutil.make_opener(12345)
    req = urllib.request.Request("http://127.0.0.1/x")
    for h in opener.handlers:
        if isinstance(h, urllib.request.ProxyHandler):
            h.proxy_open(req, "http://127.0.0.1:12345", "http")
    check(req.has_proxy() and req.host == "127.0.0.1:12345", "запрос к 127.0.0.1 идёт через наш прокси")
    saved_env = {k: os.environ.get(k) for k in ("no_proxy", "NO_PROXY")}
    os.environ["no_proxy"] = os.environ["NO_PROXY"] = "*"
    try:
        dead = FakeProxy(netutil.find_free_ports(1, 36800)[0])
        BEHAVIOR[dead.port] = "dead"
        try:
            netutil.http_get(f"http://127.0.0.1:{WEB}/sub", proxy_port=dead.port, timeout=3)
            check(False, "no_proxy=* не должен уводить запрос мимо нашего прокси")
        except OSError:
            pass
        finally:
            dead.stop()
    finally:
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    netutil._DOH_CACHE.clear()
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    try:
        check(netutil.is_dns_error(urllib.error.URLError(socket.gaierror(-2, "x"))) and
              not netutil.is_dns_error(ConnectionResetError()), "распознавание ошибки DNS")
        check(netutil.doh_resolve("pinned.invalid") == ["127.0.0.1"] and netutil.doh_resolve("gone.invalid") == [],
              "защищённый DNS")
        # DNS провайдера не знает адрес, защищённый — знает: идём напрямую по адресу, сертификат/имя — настоящие
        sub = subscription.fetch(f"http://pinned.invalid:{WEB}/sub", "v2rayN/7.13.8", timeout=5)
        check(sub.route == subscription.ROUTE_DOH and len(sub.servers) == 4, f"по адресу из защищённого DNS: {sub.route}")
        # адрес есть, но по нему не пускают, а VPN сбрасывает соединение — подсказка про блокировку
        dead = FakeProxy(netutil.find_free_ports(1, 36500)[0])
        BEHAVIOR[dead.port] = "dead"
        closed = netutil.find_free_ports(1, 36600)[0]
        try:
            subscription.fetch(f"http://pinned.invalid:{closed}/sub", "v2rayN/7.13.8", proxy_port=dead.port, timeout=3)
            check(False, "должна быть ошибка")
        except subscription.SubscriptionError as exc:
            msg = str(exc)
            check("напрямую: адрес не найден (DNS)" in msg and subscription.ROUTE_DOH in msg and "через VPN:" in msg
                  and subscription.BLOCKED_HINT in msg, f"понятная ошибка:\n{msg}")
            prev = i18n.lang()
            i18n.set_lang("en")
            try:
                en = i18n.tr(msg)
            finally:
                i18n.set_lang(prev)
            check("Looks like your internet provider blocks" in en and "direct via secure DNS" in en,
                  f"перевод:\n{en}")
        finally:
            dead.stop()
        # напрямую — страница блокировки провайдера интернета: это не ответ подписки, пробуем через VPN
        vpn = FakeProxy(netutil.find_free_ports(1, 36700)[0])
        BEHAVIOR[vpn.port] = "fast"
        try:
            sub = subscription.fetch(f"http://127.0.0.1:{WEB}/rkn", "v2rayN/7.13.8", proxy_port=vpn.port, timeout=5)
            check(sub.route == "через VPN" and len(sub.servers) == 4, f"заглушка провайдера не останавливает: {sub.route}")
            try:
                subscription.fetch(f"http://127.0.0.1:{WEB}/rkn", "v2rayN/7.13.8", timeout=5)
                check(False, "без VPN — ошибка")
            except subscription.SubscriptionError as exc:
                check("страницу блокировки" in str(exc) and subscription.BLOCKED_HINT in str(exc), str(exc))
        finally:
            vpn.stop()
        # нигде не пускает: подписка скачивается через другой рабочий сервер (временное ядро), текущий не трогаем
        e = make_engine(tmp)
        e.startup()
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        e.add_servers("vless://33333333-3333-3333-3333-333333333333@ru.example:443?security=reality&pbk=K&sni=a.com"
                      "&type=tcp#%F0%9F%87%B7%F0%9F%87%BA%20Moscow")
        e.test_all()
        fast = next(x for x in e.servers if x.endpoint.startswith("fast"))
        e.connect(fast)
        relay = e._relay_servers()
        check(relay and relay[0].name.endswith("Moscow") and all(x.key != fast.key for x in relay),
              f"сначала российский сервер, без текущего: {[x.name for x in relay]}")
        BEHAVIOR[e.ports["health"]] = "dead"  # «через VPN: соединение сброшено»
        meta = {"id": "blk", "name": "Blocked", "url": f"http://gone.invalid:{WEB}/sub", "title": "", "usage": {},
                "last_update": 0}
        old_wipe, xray.WIPE_CONFIGS = xray.WIPE_CONFIGS, True  # как в программе: настройки с ключами стираются
        try:
            got = e._fetch_into(meta)
        finally:
            xray.WIPE_CONFIGS = old_wipe
        check(got.route.startswith("через сервер «") and "Moscow" in got.route and len(got.servers) == 4,
              f"подписка через другой сервер: {got.route}")
        check(not os.path.exists(os.path.join(e.paths.data_dir, "relay.json")), "настройки временного ядра стёрты")
        check(e.connected and e.current.key == fast.key, "подключение не тронуто")
    finally:
        if e:
            e.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


@case("Свои загрузки в обход блокировок: запасные адреса списков, лимит GitHub, другие серверы")
def t_fetch_any():
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    old = (dict(xray.GEO_FILES), list(xray.GEO_MIRRORS), xray.XRAY_API_LATEST, xray.XRAY_PAGE_LATEST)
    try:
        # номер новой версии ядра, когда API GitHub не отвечает (лимит запросов)
        xray.XRAY_API_LATEST = f"http://127.0.0.1:{WEB}/xray-api"
        xray.XRAY_PAGE_LATEST = f"http://127.0.0.1:{WEB}/xray-page"
        check(xray.latest_xray_version() == "26.12.1", "версия ядра — по адресу страницы выпуска")
        e = make_engine(tmp)
        e.startup()
        wait_idle(e)  # автообновление списков после запуска — до наших проверок
        # основной адрес списков не открывается, запасной — да
        for name in xray.GEO_FILES:
            xray.GEO_FILES[name] = f"http://127.0.0.1:{WEB}/geo/main/{name}"
        xray.GEO_MIRRORS[:] = [f"http://127.0.0.1:{WEB}/geo/broken-", f"http://127.0.0.1:{WEB}/geo/mirror/"]
        e.update_geo()
        check(os.path.getsize(os.path.join(e.paths.bin_dir, "geoip.dat")) == 20000, "списки скачались с запасного адреса")
        # адрес не находится ни в DNS провайдера, ни в защищённом, VPN выключен — через другой рабочий сервер
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        e.test_all()
        for name in xray.GEO_FILES:
            xray.GEO_FILES[name] = f"http://geo.invalid:{WEB}/geo/main/{name}"
        xray.GEO_MIRRORS[:] = []
        os.remove(os.path.join(e.paths.bin_dir, "geoip.dat"))
        e.update_geo()
        check(os.path.isfile(os.path.join(e.paths.bin_dir, "geoip.dat")), "списки скачались через другой сервер")
        check(any("скачано через другой сервер" in m for m in MESSAGES), "в журнале видно, как скачано")
        # и нигде не вышло — понятная ошибка, временное ядро не запускается на каждый файл подряд
        BEHAVIOR_SAVE = dict(BEHAVIOR)
        for p in list(BEHAVIOR):
            BEHAVIOR[p] = "dead"
        DEAD.update({"fast.example", "slow.example"})
        try:
            e._relay_failed_at = 0
            try:
                e.update_geo()
                check(False, "должна быть ошибка")
            except Exception as exc:
                check(netutil.is_dns_error(exc) or "адрес" in netutil.human_error(exc), f"ошибка: {exc}")
            check(e._relay_failed_at > 0, "неудача запомнена")
        finally:
            DEAD.difference_update({"fast.example", "slow.example"})
            BEHAVIOR.update(BEHAVIOR_SAVE)
    finally:
        xray.GEO_FILES.clear()
        xray.GEO_FILES.update(old[0])
        xray.GEO_MIRRORS[:] = old[1]
        xray.XRAY_API_LATEST, xray.XRAY_PAGE_LATEST = old[2], old[3]
        if e:
            e.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


@case("Имя сервера заблокировано в DNS провайдера: адрес из защищённого DNS, имя остаётся в TLS и Host")
def t_server_dns():
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    DOH_ANSWERS["dnsblocked.example"] = "45.12.0.20"
    try:
        e = make_engine(tmp)
        e.startup()
        e.add_servers("vless://44444444-4444-4444-4444-444444444444@dnsblocked.example:443?security=tls&type=ws"
                      "&path=%2Fw#DNS blocked")
        srv = next(x for x in e.servers if x.address == "dnsblocked.example")
        key = srv.key
        e.test_all([srv])
        check(srv.pinned_ip == "45.12.0.20" and (srv.result or {}).get("ok"), f"сервер работает по адресу: {srv.result}")
        check(srv.key == key, "ключ сервера не меняется")
        ob = xray.proxy_outbounds(srv, "proxy")[0]
        ss = ob["streamSettings"]
        check(ob["settings"]["vnext"][0]["address"] == "45.12.0.20" and ss["tlsSettings"]["serverName"] == "dnsblocked.example"
              and ss["wsSettings"]["host"] == "dnsblocked.example", f"имя осталось в TLS и Host: {ob}")
        check(any("DNS провайдера не знает адрес серверов: 1" in m for m in MESSAGES), "в журнале видно")
        e.connect(srv)
        with open(e.paths.run_config, encoding="utf-8") as f:
            cfg = json.load(f)
        proxy = next(o for o in cfg["outbounds"] if o["tag"] == "proxy")
        check(proxy["settings"]["vnext"][0]["address"] == "45.12.0.20", "и в рабочем подключении")
        e.disconnect()
        check(next(x for x in e.servers if x.address == "dnsblocked.example").pinned_ip == "45.12.0.20", "адрес запомнен")
        fast = links.parse_link(SUB_LINKS[0])
        e._pin_server_dns([fast])
        check(fast.pinned_ip == "", "имя, которое не знает никто, не трогаем")
    finally:
        DOH_ANSWERS.pop("dnsblocked.example", None)
        if e:
            e.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


# ---------- тесты: маршруты и конфиги ----------

@case("Маршруты: записи, порядок правил, российские сайты, сброс")
def t_routing():
    check(routing.normalize_entry("https://www.YouTube.com/x") == ("domain", "domain:youtube.com"), "URL → домен")
    check(routing.normalize_entry("1.2.3.0/24") == ("ip", "1.2.3.0/24"), "подсеть")
    check(routing.normalize_entry("домен.рф")[1].startswith("domain:xn--"), "кириллический домен")
    rules = routing.build_rules("smart", "x.com", "", "ads.com", ru_direct=True, use_geo=True)
    tags = [_ot(r) for r in rules]
    check(tags[0] == "direct" and "block" in tags, "частные сети и блокировка должны идти первыми")
    check(tags.index("block") < tags.index("proxy"), "свои правила должны проверяться раньше встроенных")
    check(any("domain:ru" in r.get("domain", []) and _ot(r) == "direct" for r in rules), "нет правила .ru → напрямую")
    s = {"proxy_list": "example.com\nyoutube.com", "direct_list": "", "block_list": ""}
    check(routing.user_rule("www.example.com", s) == "proxy", "не найдено своё правило")
    text, removed = routing.remove_host(s["proxy_list"], "www.example.com")
    check(removed == ["example.com"] and "youtube.com" in text, "сброс правила для сайта")
    # QUIC в режиме TUN: российский — напрямую, остальной закрыт (браузер и YouTube сразу идут по TCP через VPN)
    rules = routing.build_rules("vpn", "", "", "", ru_direct=True, use_geo=True, block_quic=True)
    quic = [r for r in rules if r.get("network") == "udp" and r.get("port") == "443"]
    check(len(quic) == 2 and _ot(quic[0]) == "direct" and "domain:ru" in quic[0]["domain"] and _ot(quic[1]) == "block",
          f"QUIC: российский напрямую, остальной закрыт: {quic}")
    check("domain:local" in rules[0].get("domain", []) and _ot(rules[0]) == "direct", "домашняя сеть по имени — напрямую")
    check(rules.index(quic[1]) < next(i for i, r in enumerate(rules) if r.get("network") != "udp" and _ot(r) == "direct"
                                      and "domain:ru" in r.get("domain", [])), "запрет QUIC — раньше остальных правил")
    check(not any(r.get("port") == "443" for r in routing.build_rules("vpn", "", "", "", block_quic=False)),
          "запрет QUIC выключается")
    check(routing.domain_strategy("vpn") == "AsIs" and routing.domain_strategy("smart") == "IPIfNonMatch",
          "всё через VPN — адреса сайтов не спрашиваются у провайдера")


@case("Конфиги Xray: проверочный и рабочий, теги и порты")
def t_configs():
    servers = [links.parse_link(x) for x in SUB_LINKS[:2]]
    cfg = xray.build_test_config(servers, [41001, 41002])
    tags = [o["tag"] for o in cfg["outbounds"]]
    check(len(tags) == len(set(tags)), "повторяющиеся теги в проверочном конфиге")
    run = xray.build_run_config(servers[0], {"mode": "smart", "proxy_list": "", "direct_list": "", "block_list": ""},
                                {"socks": 41010, "http": 41011, "health": 41012, "api": 41013}, "access.log", True)
    check(run["outbounds"][0]["tag"] == "direct", "в умном режиме по умолчанию должно быть «напрямую»")
    check("HandlerService" in run["api"]["services"], "нет HandlerService для переключения на лету")
    known = {o["tag"] for o in run["outbounds"]}
    for r in run["routing"]["rules"]:
        check(_ot(r) in known, f"правило ссылается на несуществующий тег {r['outboundTag']}")
    run2 = xray.build_run_config(servers[0], {"mode": "vpn"}, {"socks": 1, "http": 2, "health": 3, "api": 4}, "a", False)
    check(run2["outbounds"][0]["tag"] == "proxy", "в режиме «всё через VPN» по умолчанию должен быть VPN")
    check(run2["routing"]["domainStrategy"] == "AsIs" and run["routing"]["domainStrategy"] == "IPIfNonMatch",
          "стратегия адресов по режиму")
    check(not any(r.get("port") == "443" for r in run2["routing"]["rules"]), "без TUN QUIC не трогается")
    run3 = xray.build_run_config(servers[0], {"mode": "vpn"}, {"socks": 1, "http": 2, "health": 3, "api": 4}, "a", False,
                                 tun={"engine": "xray"})
    check(any(r.get("port") == "443" and _ot(r) == "block" for r in run3["routing"]["rules"]), "в TUN QUIC закрыт")
    from pult import settings as setmod
    check(setmod.DEFAULTS["mode"] == "vpn" and setmod.DEFAULTS["block_quic"], "по умолчанию всё через VPN")


@case("Всё через VPN: сайт не открывается через сервер — другой сервер; ни через один — вопрос «напрямую?»")
def t_auto_vpn():
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    old_check, old_api, old_stall = services.check_url, xray.api_command, services.stall_test
    probes = []
    try:
        e = make_engine(tmp)
        e.startup()
        check(e.settings["mode"] == "vpn", "по умолчанию всё через VPN")
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        e.test_all()
        e.connect(e.best())
        check(e.connected, "подключено")
        health, http_port = e.ports["health"], e.ports["http"]
        tries: dict = {}

        def where(port):
            return "direct" if port in (None, e._direct_http()) else "vpn" if port == health else \
                "current" if port == http_port else "other"

        def fake_check(url, port, region_sensitive, timeout=10.0):
            host, how = url.split("/")[2], where(port)
            probes.append((host, how))
            fail = {"state": services.BLOCKED, "detail": "соединение сброшено", "ms": None}
            ok = {"state": services.OK, "detail": "код 200", "ms": 5}
            if how == "direct":
                return ok
            if host.endswith("flaky.example") and how == "vpn":
                tries[host] = tries.get(host, 0) + 1
                return fail if tries[host] == 1 else ok
            if host.endswith(("nlsite.example", "nocdn.example", "manual.example", "direct.example")):
                return fail  # не открывается ни через один сервер
            if host.endswith(("srv.example", "check.example")) and how in ("vpn", "current"):
                return fail  # через этот сервер нет, через другой — да
            if how == "current" and host.endswith("direct.example"):
                return fail
            return ok
        services.check_url = fake_check
        xray.api_command = lambda paths, port, args, exe=None: True

        def wait_queue():
            deadline = time.time() + 20
            while time.time() < deadline and (e._auto_q or e._auto_queued):
                time.sleep(0.05)

        e._auto_offer("www.srv.example", "proxy", 443)
        e._auto_offer("flaky.example", "proxy", 443)
        e._auto_offer("nlsite.example", "proxy", 443)
        e._auto_offer("img.nocdn.example", "proxy", 443)  # не сам сайт, а его картинки — не спрашиваем
        wait_queue()
        auto = e.settings["auto_sites"]
        check(auto.get("srv.example", {}).get("via") == "server", f"через этот сервер нет — через другой: {auto}")
        check("flaky.example" not in auto and "flaky.example" in e.settings["auto_seen"],
              "разовый сбой соединения — правило не нужно")
        asked = [d["item"]["site"] for ev, d in e.events if ev == "vpn_site"]
        check(asked == ["nlsite.example"], f"спросили только про сам сайт: {asked}")
        check([x["site"] for x in e.state()["vpn_suspects"]] == ["nlsite.example"], "вопрос виден в окне программы")
        check(not any(how == "direct" for h, how in probes), "сайты через VPN напрямую не проверялись")
        check("nlsite.example" not in (e.settings.get("direct_list") or ""), "без ответа напрямую не пускает")
        # VPN сам подводит — сайт не виноват, ничего не решаем
        e._health_check = lambda: None  # монитор не должен «починить» счётчик посреди проверки
        deadline = time.time() + 20  # отложенное переподключение после автоправил тоже сбрасывает счётчик — дождёмся его
        while (getattr(e, "_auto_reconnect_pending", False) or e.conn_busy()) and time.time() < deadline:
            time.sleep(0.1)
        e.connect = lambda *a, **k: None  # и никаких переподключений, пока VPN «подводит»
        e._ping_failures = 2
        # подмена — до того, как сайт попадёт в очередь: иначе фоновая проверка может успеть спросить старую подмену
        services.check_url = lambda url, port, region_sensitive, timeout=10.0: {"state": services.BLOCKED, "detail": "x", "ms": None}
        e._auto_offer("down.example.org", "proxy", 443)
        wait_queue()
        check("example.org" not in e.settings["auto_sites"] and "example.org" not in e.settings["auto_seen"],
              "VPN не отвечает — сайт не помечается и не уходит на другой сервер")
        e._ping_failures = 0
        del e._health_check, e.connect
        services.check_url = fake_check
        # ответ «Напрямую»
        e.vpn_site_answer("nlsite.example", True)
        check(e._site_choice("nlsite.example") == "direct",
              "ответ «Напрямую» — своё правило")
        check(not e.state()["vpn_suspects"], "вопрос убран")
        e._vpn_site_ask("manual.example", "x")
        e.vpn_site_answer("manual.example", False)
        check(e.settings["auto_seen"]["manual.example"].get("ignore") and e._site_choice("manual.example") == "auto",
              "ответ «Оставить через VPN» — больше не спрашивает")
        e._vpn_site_asked.clear()
        e.settings["auto_ask_direct"] = False
        n = len([1 for ev, _ in e.events if ev == "vpn_site"])
        e._vpn_site_ask("other.example", "x")
        check(len([1 for ev, _ in e.events if ev == "vpn_site"]) == n, "вопрос выключается")
        # «Проверить сайт»: через этот сервер нет — другой сервер; ни через один — напрямую (человек сам попросил)
        r = e.check_site("check.example")
        check(r["action"] == "server" and r["route"].startswith("server:") and r["results"].get("other"),
              f"проверка сайта: другой сервер: {r['verdict']}")
        r = e.check_site("https://direct.example/page")
        check(r["action"] == "direct" and r["route"] == "direct", f"проверка сайта: напрямую: {r['verdict']}")
        r = e.check_site("fine.example.net")
        check(r["action"] == "" and r["route"] == "auto" and "выбери ниже" in r["verdict"],
              f"сайт отвечает — можно выбрать путь вручную: {r['verdict']}")
        # «Работает не полностью»: ни через один сервер не качается, напрямую — да
        def fake_stall(host, proxy_port=None, **kw):
            if where(proxy_port) == "direct" or not host.endswith("repair.example"):
                return {"state": services.STALL_OK, "bytes": 70000, "detail": "68 КБ", "ms": 300}
            return {"state": services.STALL_FAIL, "bytes": 0, "detail": "соединение сброшено", "ms": None}
        services.stall_test = fake_stall
        rr = e.repair_site("repair.example")
        check(rr["fixed"] == 1 and any(x.get("fix") == "direct" for x in rr["hosts"])
              and routing.user_rule("repair.example", e.settings) == "direct", f"починка: напрямую: {rr}")
        e.disconnect()
    finally:
        services.check_url, xray.api_command, services.stall_test = old_check, old_api, old_stall
        if e:
            e.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


def _fake_socks_udp() -> tuple[int, callable]:
    """Мини-SOCKS5 с UDP ASSOCIATE: на запрос DNS отвечает одним адресом A (для проверки socks_udp_dns)."""
    tcp = socket.socket()
    tcp.bind(("127.0.0.1", 0))
    tcp.listen(4)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    alive = [True]

    def serve_tcp():
        while alive[0]:
            try:
                c, _ = tcp.accept()
            except OSError:
                return
            try:
                c.recv(3)
                c.sendall(b"\x05\x00")
                c.recv(10)
                c.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + udp.getsockname()[1].to_bytes(2, "big"))
                time.sleep(3)
            except OSError:
                pass
            finally:
                c.close()

    def serve_udp():
        while alive[0]:
            try:
                data, addr = udp.recvfrom(4096)
            except OSError:
                return
            hdr, query = data[:10], data[10:]
            if data[3] != 1:
                continue
            answer = bytearray(query[:2]) + b"\x81\x80" + query[4:6] + b"\x00\x01\x00\x00\x00\x00" + query[12:]
            answer += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton("142.250.1.1")
            udp.sendto(hdr + bytes(answer), addr)

    threading.Thread(target=serve_tcp, daemon=True).start()
    threading.Thread(target=serve_udp, daemon=True).start()

    def close():
        alive[0] = False
        tcp.close()
        udp.close()
    return tcp.getsockname()[1], close


@case("Полная проверка: сеть провайдера, VPN в бою, отпечатки TLS, UDP, отчёт без секретов")
def t_fullcheck():
    from pult import fullcheck
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    from pult import certcheck
    saved = (services.check_url, services.stall_test, netutil.speed_test, netutil.doh_resolve, fullcheck._system_ips,
             fullcheck.udp_dns, fullcheck.socks_udp_dns, fullcheck._data_flow, fullcheck.battle_config)
    saved_fetch, saved_roots = certcheck.fetch, certcheck.russian_roots
    certcheck.fetch = lambda host, proxy_port=None, timeout=8.0: {"state": "ok", "issuer": "Google Trust Services",
                                                                    "russian": [], "interceptor": "", "sha256": "", "error": ""}
    certcheck.russian_roots = lambda certs=None: []
    close_socks = None
    try:
        # SOCKS5 UDP: настоящий разбор ответа ядра
        port, close_socks = _fake_socks_udp()
        check(fullcheck.socks_udp_dns(port, timeout=3), "UDP через SOCKS5: запрос DNS дошёл и ответ разобран")
        close_socks()
        close_socks = None
        check(not fullcheck.socks_udp_dns(netutil.find_free_ports(1, 47000)[0], timeout=1), "нет ядра — UDP не работает")

        e = make_engine(tmp)
        e.startup()
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        e.test_all()
        lines = []
        c = fullcheck.Collector(lines.append)

        # блокировки в сети: DNS-заглушка, UDP закрыт, белые списки
        fullcheck._system_ips = lambda host: ["127.0.0.1"] if host == "rutracker.org" else []
        netutil.doh_resolve = lambda host, timeout=6.0: ["104.16.0.1"]
        fullcheck.udp_dns = lambda server, timeout=3.0: False
        blocked = {"state": services.BLOCKED, "detail": "соединение сброшено", "ms": None}
        fine = {"state": services.OK, "detail": "код 200", "ms": 30}
        services.check_url = lambda url, port, region_sensitive=False, timeout=10.0: fine if "ya.ru" in url else blocked
        fullcheck.stage_network(c)
        got = {(i["level"], i["title"].split(":")[0]) for i in c.items}
        check(("info", "DNS провайдера прячет заблокированные сайты") in got, f"подмена DNS замечена: {got}")
        check(any(i["level"] == "warn" and "UDP за границу не проходит" in i["title"] for i in c.items), "UDP закрыт")
        check(any(i["level"] == "error" and "белые списки" in i["title"] for i in c.items), "белые списки замечены")
        c.items.clear()
        services.check_url = lambda url, port, region_sensitive=False, timeout=10.0: fine
        fullcheck.udp_dns = lambda server, timeout=3.0: True
        fullcheck.stage_network(c)
        check(any(i["level"] == "ok" and "Белых списков нет" in i["title"] for i in c.items)
              and any(i["level"] == "ok" and "UDP за границу проходит" in i["title"] for i in c.items), "обычная сеть")

        # VPN в бою: лучший сервер — данные идут, второй — замирают; потом лучший — «подключено, но пусто»
        c.items.clear()
        ok_flow = {"state": services.STALL_OK, "bytes": 70000, "detail": "", "ms": 400}
        flows = iter([ok_flow, {"state": services.STALL_STALL, "bytes": 16000, "detail": "замирает", "ms": 4000},
                      {"state": services.STALL_FAIL, "bytes": 0, "detail": "сайт не отвечает", "ms": None}])
        fullcheck._data_flow = lambda port: next(flows, ok_flow)
        netutil.speed_test = lambda port, urls, seconds=8.0, stop_event=None: {"ok": True, "mbps": 42.5, "bytes": 1, "error": ""}
        fullcheck.socks_udp_dns = lambda port, server=("1.1.1.1", 53), timeout=6.0: True
        spy: dict = {}
        orig_cfg = saved[8]

        def capture(servers, ports, fp_ports, udp_port, version):
            cfg = orig_cfg(servers, ports, fp_ports, udp_port, version)
            spy.update(fp=list(fp_ports), cfg=cfg, n=len(servers), udp=udp_port)
            return cfg
        fullcheck.battle_config = capture

        def check_fp(url, port, region_sensitive=False, timeout=10.0):
            return blocked if spy.get("fp") and port == spy["fp"][0] else fine  # отпечаток chrome режут
        services.check_url = check_fp
        fullcheck.stage_battle(c, e)
        cfg = spy["cfg"]
        n = spy["n"]
        check(n == min(fullcheck.TOP_SERVERS, len(tester.ranked(e.servers))) >= 2
              and len(spy["fp"]) == len(fullcheck.FINGERPRINTS), f"лучшие серверы и все отпечатки: {n}")
        fps = [fullcheck._current_fp(cfg, f"out{n + i}") for i in range(len(fullcheck.FINGERPRINTS))]
        check(fps == fullcheck.FINGERPRINTS, f"отпечатки выставлены на копии первого сервера: {fps}")
        check(any(ib["protocol"] == "socks" and ib["settings"].get("udp") for ib in cfg["inbounds"])
              and {"type": "field", "inboundTag": ["udp0"], "outboundTag": "out0"} in cfg["routing"]["rules"],
              "вход SOCKS с UDP ведёт на лучший сервер")
        lv = [i["level"] for i in c.items]
        titles = " | ".join(i["title"] for i in c.items)
        check(lv[:2] == ["ok", "error"] and "замирают" in c.items[1]["title"], f"данные по серверам: {titles}")
        check(any("42.5 Мбит/с" in i["title"] for i in c.items), "скорость")
        check(any(i["level"] == "warn" and "«chrome» из ссылки режут" in i["title"] for i in c.items),
              f"отпечаток из ссылки режут, другие проходят: {titles}")
        check(any(i["level"] == "ok" and "UDP через VPN работает" in i["title"] for i in c.items), "UDP через VPN")
        battle = list(c.items)
        c.items.clear()
        fullcheck.stage_battle(c, e)  # теперь у лучшего сервера пинг есть, а данных нет
        check(c.items[0]["level"] == "error" and "данные не идут" in c.items[0]["title"],
              f"«подключено, но пусто»: {c.items[0]}")
        c.items[:] = battle

        # отчёт: разделы, итоги, нет адресов серверов и ссылки подписки
        c.items.append({"section": "battle", "level": "info", "title": e.servers[0].address,
                        "detail": f"http://127.0.0.1:{WEB}/sub"})
        rep = fullcheck.finish(c, e, 12.0)
        with open(rep["path"], encoding="utf-8") as f:
            text = f.read()
        check(os.path.dirname(rep["path"]).endswith(os.path.join("data", "reports")), "отчёт в data/reports")
        check(e.servers[0].address not in text and "/sub" not in text and e.servers[0].link not in text,
              "в отчёте нет адресов серверов и ссылки подписки")
        check("== VPN в бою ==" in text and any(x.startswith("VPN в бою: ошибок") for x in rep["summary"]),
              f"разделы и итоги: {rep['summary']}")
        c2 = fullcheck.Collector()
        c2.start("battle")
        c2.add("skip", "ядра нет")
        check(fullcheck.finish(c2, e, 1.0)["summary"] == ["VPN в бою: пропущено"], "пропущенный раздел — не «всё хорошо»")

        # функции Windows: итоги field_check одной строкой JSON
        fake_app = os.path.join(tmp, "fake_app")
        os.makedirs(fake_app)
        with open(os.path.join(fake_app, "field_check.py"), "w", encoding="utf-8") as f:
            f.write("import json\nprint('проверяю…')\nprint(json.dumps({'results': [{'section': 'Windows', "
                    "'level': 'warn', 'title': 'Wi-Fi', 'detail': 'нет адаптера'}]}))\n")
        c.items.clear()
        fullcheck.stage_windows(c, fake_app)
        check(c.items and c.items[0]["title"] == "Windows: Wi-Fi" and c.items[0]["level"] == "warn",
              f"итоги field_check разобраны: {c.items}")
    finally:
        (services.check_url, services.stall_test, netutil.speed_test, netutil.doh_resolve, fullcheck._system_ips,
         fullcheck.udp_dns, fullcheck.socks_udp_dns, fullcheck._data_flow, fullcheck.battle_config) = saved
        certcheck.fetch, certcheck.russian_roots = saved_fetch, saved_roots
        if close_socks:
            close_socks()
        if e:
            e.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


@case("Что нового: в CHANGELOG.md описана текущая версия")
def t_changelog():
    from pult import APP_VERSION
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, "CHANGELOG.md")
    if not os.path.isfile(path):
        return  # в собранной программе файла может не быть
    with open(path, encoding="utf-8") as f:
        text = f.read()
    m = re.search(rf"^## {re.escape(APP_VERSION)}(?![\d.])[^\n]*\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    check(m and m.group(1).strip(), f"нет раздела «## {APP_VERSION}» в CHANGELOG.md")
    android = os.path.join(root, "android", "app", "build.gradle")
    if os.path.isfile(android):
        with open(android, encoding="utf-8") as f:
            aver = re.search(r"versionName '([^']+)'", f.read())
        check(aver and f"Android {aver.group(1)}" in m.group(0).split("\n", 1)[0],
              f"в заголовке раздела нет версии Android ({aver.group(1) if aver else '?'})")


@case("Журнал ошибок: сбои кода, проблемы, склейка, заявка на GitHub без секретов")
def t_errorlog():
    from pult import errorlog
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    old_hooks = (sys.excepthook, threading.excepthook)
    try:
        secret = "vless://11111111-2222-3333-4444-555555555555@203.0.113.7:443"
        log = errorlog.ErrorLog(tmp, scrub=lambda t: t.replace("203.0.113.7", "<адрес>"), app_dir=tmp)
        log.record("problem", "Сервер 3 не отвечает", "через 203.0.113.7", where="server_down")
        log.record("problem", "Сервер 5 не отвечает", "через 203.0.113.7", where="server_down")
        check(len(log.entries) == 1 and log.entries[0]["count"] == 2, "одинаковые записи склеиваются (цифры не мешают)")
        try:
            {}["нет-ключа"]
        except KeyError as exc:
            log.record_exc(exc, "задача: тест")
        crash = log.entries[-1]
        check(crash["kind"] == "crash" and "KeyError" in crash["title"] and "Traceback" in crash["trace"], "сбой кода с трассировкой")
        with open(log.path, "a", encoding="utf-8") as f:
            f.write("{битая строка\n")
        again = errorlog.ErrorLog(tmp)
        check(len(again.entries) == 2, "журнал читается после перезапуска, битая строка пропускается")
        with open(log.path, encoding="utf-8") as f:
            raw = f.read()
        check("203.0.113.7" not in raw and tmp not in raw, "в файле нет адресов и папки программы")
        text = log.issue_text()
        check(text["title"].startswith("[") and "KeyError" in text["title"] and "```" in text["body"]
              and "Что я делал" in text["body"], "заявка: заголовок, трассировка, место для описания")
        url = log.issue_url("me/vedomyj-vpn")
        check(url.startswith("https://github.com/me/vedomyj-vpn/issues/new?") and "labels=bug" in url, "ссылка на заявку")
        check(errorlog.repo_from_url("https://github.com/me/vedomyj-vpn/releases/latest/download/latest.json") == "me/vedomyj-vpn"
              and errorlog.repo_from_url("") == "", "репозиторий из адреса обновлений")
        for i in range(errorlog.MAX_ENTRIES + 20):
            log.record("check", f"запись {'x' * (i % 7)}{chr(1040 + i % 30)}", where=str(i))
        check(len(errorlog.ErrorLog(tmp).entries) <= errorlog.MAX_ENTRIES, "журнал не растёт бесконечно")
        log.clear()
        threading.excepthook = lambda args: None  # стандартный вывод трассировки в самопроверке не нужен
        errorlog.install_hooks(log)
        th = threading.Thread(target=lambda: [][1], name="тест")
        th.start()
        th.join()
        check(any(x["kind"] == "crash" and "IndexError" in x["title"] for x in log.entries), "падение потока — в журнал")
        sys.excepthook, threading.excepthook = old_hooks

        # движок: проблемы и неожиданные ошибки задач — в журнал; понятные ошибки — только как проблема
        e = make_engine(tmp)
        e.startup()
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        e.errors.clear()
        e.problem("test_problem", "Test problem", "address " + e.servers[0].address)
        rec = e.errors.entries[-1]
        check(rec["kind"] == "problem" and e.servers[0].address not in json.dumps(rec, ensure_ascii=False),
              "проблема записана без адреса сервера")

        def boom():
            return {}["x"]

        def polite():
            raise RuntimeError("Clear error for a human")
        e.run_task("Crash test", boom)
        wait_idle(e)
        e.run_task("Polite test", polite)
        wait_idle(e)
        kinds = [(x["kind"], x["where"]) for x in e.errors.entries]
        check(("crash", "задача: Crash test") in kinds, f"неожиданная ошибка задачи — сбой кода: {kinds}")
        check(("crash", "задача: Polite test") not in kinds, "понятная ошибка — не сбой кода")
        ui = UIServer(os.path.join(APP_DIR, "ui"), "tok")
        ui.engine = e
        st = ui.dispatch("errors_list", {})
        check(st["items"] and st["items"][0]["kind"] in ("crash", "problem") and "file" in st, "журнал в окне")
        check(ui.dispatch("errors_repo", {"repo": "me/vedomyj-vpn"}) == "me/vedomyj-vpn"
              and e.errors_state()["repo"] == "me/vedomyj-vpn", "свой репозиторий сохраняется")
        res = ui.dispatch("errors_issue", {})
        check(res["url"].startswith("https://github.com/me/vedomyj-vpn/issues/new"), "заявка на GitHub из окна")
        try:
            ui.dispatch("errors_repo", {"repo": "not a repo"})
            check(False, "мусор вместо репозитория не принимается")
        except RuntimeError:
            pass
        ui.dispatch("errors_clear", {})
        check(not e.errors.entries and e.state()["errors_count"] == 0, "журнал очищается")
    finally:
        sys.excepthook, threading.excepthook = old_hooks
        if e:
            e.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


# сертификат «Минцифры» только для проверки (самоподписанный, localhost, 2026–2046) — хранится без PEM-заголовков
TEST_CA_KEY = ("MHcCAQEEIOCyOriDuL/WE/Oty3nNTpOWhivR73atIQXRy3A/beuLoAoGCCqGSM49AwEHoUQDQgAEoVLNTg40kcdnuGVMyHKpNzUvmyw40aX+"
               "DbzUkW2Tzc57GkVKMb1xctVdxqqasaXMwsNAbMXNbfQAcikE/gKhOA==")
TEST_CA_CERT = ("MIICSTCCAe+gAwIBAgIUdhQyq2MT2A/lg3togWRyN8u/ClMwCgYIKoZIzj0EAwIwbzELMAkGA1UEBhMCUlUxPzA9BgNVBAoMNlRoZSBNaW5p"
                "c3RyeSBvZiBEaWdpdGFsIERldmVsb3BtZW50IGFuZCBDb21tdW5pY2F0aW9uczEfMB0GA1UEAwwWUnVzc2lhbiBUcnVzdGVkIFN1YiBDQTAe"
                "Fw0yNjExMTgxOTQxMTJaFw00NjExMTMxOTQxMTJaMG8xCzAJBgNVBAYTAlJVMT8wPQYDVQQKDDZUaGUgTWluaXN0cnkgb2YgRGlnaXRhbCBE"
                "ZXZlbG9wbWVudCBhbmQgQ29tbXVuaWNhdGlvbnMxHzAdBgNVBAMMFlJ1c3NpYW4gVHJ1c3RlZCBTdWIgQ0EwWTATBgcqhkjOPQIBBggqhkjO"
                "PQMBBwNCAAShUs1ODjSRx2e4ZUzIcqk3NS+bLDjRpf4NvNSRbZPNznsaRUoxvXFy1V3GqpqxpczCw0Bsxc1t9AByKQT+AqE4o2kwZzAdBgNV"
                "HQ4EFgQUMkOHN5TPpcyACdRX+1fzXlihT1gwHwYDVR0jBBgwFoAUMkOHN5TPpcyACdRX+1fzXlihT1gwDwYDVR0TAQH/BAUwAwEB/zAUBgNV"
                "HREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSAAwRQIgB76HcdDi8cqUF0Zg8IPZTTeinBHT9UiKXpQmT2xwIhQCIQCxhzukar1MEl8O"
                "1+yNcd0v+0W0l6rQLkg9DRw+t9Y7yg==")


def _pem(kind: str, b64: str) -> str:
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "\n".join(["-----BEGIN " + kind + "-----", *lines, "-----END " + kind + "-----", ""])


@case("Сертификаты: сертификат Минцифры в системе, подмена напрямую и через VPN, антивирус, значок «!»")
def t_certcheck():
    from pult import certcheck
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    saved = (certcheck._connect, certcheck.verify_context, certcheck.check)
    srv = None
    try:
        der = base64.b64decode(TEST_CA_CERT)
        check(certcheck.russian_names(der)[:1] == ["Russian Trusted Sub CA"] and certcheck.russian_roots([der, b"x"])
              and not certcheck.russian_roots([b"GlobalSign Root"]), "сертификат Минцифры узнаётся по содержимому")
        # настоящий TLS: локальный сервер с «сертификатом Минцифры»
        cert_path, key_path = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
        with open(cert_path, "w") as f:
            f.write(_pem("CERTIFICATE", TEST_CA_CERT))
        with open(key_path, "w") as f:
            f.write(_pem("EC PRIVATE KEY", TEST_CA_KEY))
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(cert_path, key_path)
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        port = srv.getsockname()[1]

        def serve():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                try:
                    with sctx.wrap_socket(c, server_side=True) as t:
                        t.recv(10)
                except (OSError, ssl.SSLError):
                    pass
        threading.Thread(target=serve, daemon=True).start()
        certcheck._connect = lambda host, proxy_port, timeout: socket.create_connection(("127.0.0.1", port), timeout=timeout)
        bad = certcheck.fetch("localhost")
        check(bad["state"] == "bad" and "Russian Trusted Sub CA" in bad["russian"], f"чужой сертификат пойман: {bad}")
        trusting = ssl.create_default_context(cafile=cert_path)
        certcheck.verify_context = lambda: trusting  # как будто сертификат Минцифры стоит в системе
        ok = certcheck.fetch("localhost")
        check(ok["state"] == "ok" and ok["russian"] and "Ministry" in ok["issuer"], f"с сертификатом в системе: {ok}")
        certcheck._connect, certcheck.verify_context = saved[0], saved[1]

        # итог: разные случаи подмены
        def site(issuer="Google Trust Services", state="ok", russian=(), av=""):
            return {"state": state, "issuer": issuer, "russian": list(russian), "interceptor": av, "sha256": "", "error": "x"}
        clean = certcheck.check(10808, hosts=["a.com"], roots=[], fetcher=lambda h, p: site())
        check(not clean["mitm"] and not clean["vpn_mitm"] and clean["errors"] == 0, "чисто — ошибок нет")
        r = certcheck.check(None, hosts=["a.com"], roots=["Russian Trusted Root CA"], fetcher=lambda h, p: site())
        check(r["warnings"] == 1 and not r["mitm"] and "Минцифры" in r["items"][0]["title"], "сертификат в системе — предупреждение")
        r = certcheck.check(10808, hosts=["a.com"], roots=[],
                            fetcher=lambda h, p: site() if p else site("Russian Trusted Sub CA", russian=["Russian Trusted Sub CA"]))
        check(r["mitm"] and not r["vpn_mitm"] and any("подменён" in i["title"] and "через vpn он настоящий" in i["detail"].lower()
                                                     for i in r["items"]), "подмена напрямую, через VPN — настоящий")
        r = certcheck.check(10808, hosts=["a.com"], roots=[], fetcher=lambda h, p: site(state="bad") if p else site())
        check(r["vpn_mitm"] and not r["mitm"], "подменяет сам сервер VPN")
        r = certcheck.check(None, hosts=["a.com"], roots=[], fetcher=lambda h, p: site("Kaspersky Anti-Virus Personal Root", av="Kaspersky"))
        check(not r["mitm"] and any(i["state"] == "info" and "Kaspersky" in i["title"] for i in r["items"]), "антивирус — не подмена")
        r = certcheck.check(None, hosts=["a.com"], roots=[], fetcher=lambda h, p: site("Acme Office Proxy"))
        check(r["mitm"] and r["warnings"] == 1, "неизвестный выпускающий центр — предупреждение")
        r = certcheck.check(None, hosts=["a.com"], roots=[], fetcher=lambda h, p: site(state="fail"))
        check(r["errors"] == 0 and not r["mitm"], "закрытый провайдером сайт — не подмена")

        # движок: значки «!», «Понятно», журнал
        e = make_engine(tmp)
        e.startup()
        certcheck.check = lambda vpn_port=None, hosts=None, roots=None, fetcher=None, direct=True: saved[2](
            vpn_port, hosts=["a.com"], roots=["Russian Trusted Root CA"],
            fetcher=lambda h, p: site("Russian Trusted Sub CA", russian=["Russian Trusted Sub CA"]))
        res = e.cert_check()
        keys = {p["key"]: p["level"] for p in e.problems_list()}
        check(keys.get("cert_mitm") == "error" and "cert_root" in keys and res["mitm"], f"значки «!»: {keys}")
        check(any(x["where"] == "cert_mitm" for x in e.errors.entries), "подмена — в журнал ошибок")
        e.cert_ack()
        check("cert_root" not in {p["key"] for p in e.problems_list()} and e.settings["cert_root_ack"] == ["Russian Trusted Root CA"],
              "«Понятно» убирает значок про сертификат в системе")
        e.cert_check()
        check("cert_root" not in {p["key"] for p in e.problems_list()} and e.state()["certs"]["acked"],
              "после «Понятно» тот же сертификат больше не тревожит")
        certcheck.check = lambda vpn_port=None, hosts=None, roots=None, fetcher=None, direct=True: saved[2](
            vpn_port, hosts=["a.com"], roots=[], fetcher=lambda h, p: site())
        e.cert_check()
        check("cert_mitm" not in {p["key"] for p in e.problems_list()}, "подмена пропала — значок тоже")
    finally:
        certcheck._connect, certcheck.verify_context, certcheck.check = saved
        if srv:
            srv.close()
        if e:
            e.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


@case("Старый «умный» режим → «всё через VPN» один раз; сервер под нагрузкой не меняется зря")
def t_routing_v2():
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = e2 = None
    real_ping = netutil.http_ping
    try:
        e = make_engine(tmp)
        e.settings.update(mode="smart", ru_direct=False, routing_v2=False)
        e.startup()
        check(e.settings["mode"] == "vpn" and e.settings["ru_direct"] and e.settings["routing_v2"],
              f"старый умный режим → всё через VPN: {e.settings['mode']}")
        check(any("Маршрутизация: теперь через VPN идёт всё" in x for x in e.logs_view()), "в журнале объяснение")
        e.settings["mode"] = "smart"  # потом сам выбрал экономный — больше не трогаем
        e.save()
        e.shutdown()
        e2 = make_engine(tmp)
        e2.startup()
        check(e2.settings["mode"] == "smart", "выбранный потом экономный режим не сбрасывается")
        e2.settings["mode"] = "vpn"
        e2.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        e2.test_all()
        e2.connect(e2.best())
        check(e2.connected, "подключено")
        e2._poll_stats = lambda: None  # скорость задаёт тест
        dead = {"ok": False, "error": "нет ответа", "ping_ms": None, "delay_ms": None}
        netutil.http_ping = lambda *a, **k: dict(dead)
        e2.live.update(main_down=400 * 1024, proxy_down=400 * 1024, proxy_up=0)
        for _ in range(3):
            e2._health_check()
        check(e2._ping_failures == 0 and not any(p["key"] == "server_down" for p in e2.problems_list()),
              "видео качается через сервер — проверка не пробилась, но сервер жив")
        e2.live.update(main_down=0, proxy_down=0)
        e2._health_check()
        e2._health_check()
        check(any(p["key"] == "server_down" for p in e2.problems_list()), "данных нет и проверка не проходит — сервер упал")
        netutil.http_ping = lambda *a, **k: {"ok": True, "error": "", "ping_ms": 120, "delay_ms": 5000}
        e2.live.update(proxy_down=2 * 1024 * 1024)
        for _ in range(4):
            e2._health_check()
        check(e2._slow_count == 0, "медленно под загрузкой — не повод менять сервер")
        e2.live.update(proxy_down=0)
        for _ in range(3):
            e2._health_check()
        check(e2._slow_count >= 3, "медленно без загрузки — сервер правда медленный")
        e2.disconnect()
    finally:
        netutil.http_ping = real_ping
        for x in (e, e2):
            if x:
                x.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


@case("Выгрузка в Happ: ссылка профиля")
def t_happ():
    link = happ.profile_link({"mode": "smart", "proxy_list": "x.com", "direct_list": "", "block_list": ""})
    check(link.startswith("happ://routing/onadd/"), "неверная ссылка")
    prof = json.loads(base64.b64decode(link.split("/onadd/")[1]))
    check(prof["Name"] and "domain:x.com" in prof["ProxySites"] and prof["GlobalProxy"] == "false", "содержимое профиля")


@case("Разбор журнала соединений Xray")
def t_access():
    item = xray.parse_access_line("2026/11/11 22:30:01.1 from 127.0.0.1:5 accepted tcp:www.youtube.com:443 [http-in -> proxy]")
    check(item and item["host"] == "www.youtube.com" and item["outbound"] == "proxy", "строка журнала")
    check(xray.parse_access_line("x accepted tcp:a.com:80 [health-in -> proxy]") is None, "служебные строки должны скрываться")


# ---------- тесты: движок целиком ----------

@case("Движок: подписка → проверка → скорость → подключение → статистика")
def t_engine_flow():
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    try:
        e = make_engine(tmp)
        e.startup()
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        check(len(e.servers) == 4, "серверы подписки не появились")
        working = e.test_all()
        check(working == 2, f"ожидалось 2 рабочих сервера, получилось {working}")
        e.speed_top(3)
        best = e.best()
        check(best and best.name.endswith("Fast"), "лучшим должен быть быстрый сервер")
        e.connect(best)
        check(e.connected, "не подключилось")
        HEALTH_PORT["port"] = e.ports["health"]
        e._poll_stats()
        time.sleep(0.1)
        e._poll_stats()
        check(e.live["proxy_down"] > 0, "не считается скорость")
        with open(e.paths.access_log, "a") as f:
            f.write("2026/11/11 22:30:01.1 from 127.0.0.1:5 accepted tcp:www.youtube.com:443 [http-in -> proxy]\n")
        e._tail_access_log()
        check("www.youtube.com" in e.connections, "журнал соединений не читается")
        st = e.state()
        json.dumps(st)
        check(st["connected"] and st["current"]["name"].endswith("Fast"), "состояние для интерфейса")
        e.disconnect()
        check(not e.connected, "не отключилось")
        e.shutdown()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@case("Две очереди: пока идёт долгая задача (zapret, списки), VPN включается, переключается и выключается")
def t_lanes():
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    try:
        e = make_engine(tmp)
        e.startup()
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        e.test_all()
        fast = next(s for s in e.servers if s.endpoint.startswith("fast"))
        slow = next(s for s in e.servers if s.endpoint.startswith("slow"))
        done = {"bg": False}

        def long_job():  # как подбор стратегии zapret: долго и с проверкой «Стоп»
            for _ in range(30):
                e.check_stop()
                time.sleep(0.05)
            done["bg"] = True

        check(e.run_task("Подбираю стратегию zapret", long_job), "долгая задача запущена")
        time.sleep(0.05)
        check(e.bg_busy() and not e.conn_busy(), "занята только фоновая очередь")
        check(not e.run_task("Обновляю списки", lambda: None), "вторая долгая задача ждёт")
        check(e.run_task("Подключаюсь", e.connect, fast, lane="conn"), "подключение не ждёт долгую задачу")
        t0 = time.time()
        while (not e.connected or e.conn_busy()) and time.time() - t0 < 5:  # очередь подключения освободилась
            time.sleep(0.02)
        check(e.connected and e.bg_busy(), "подключено, пока долгая задача ещё идёт")
        st = e.state()
        check(st["busy"].startswith("Подбираю") and st["conn_busy"] == "", f"состояние для интерфейса: {st['busy']!r} / {st['conn_busy']!r}")
        check(e.run_task("Подключаюсь", e.connect, slow, lane="conn"), "смена сервера во время долгой задачи")
        t0 = time.time()
        while (e.conn_busy() or not e.current or e.current.key != slow.key) and time.time() - t0 < 5:
            time.sleep(0.02)
        check(e.current.key == slow.key and e.bg_busy(), "сервер сменился, долгая задача идёт дальше")
        check(e.run_task("Отключаюсь", e.disconnect, lane="conn"), "отключение во время долгой задачи")
        t0 = time.time()
        while e.connected and time.time() - t0 < 5:
            time.sleep(0.02)
        check(not e.connected, "отключилось")
        while e.is_busy() and time.time() - t0 < 10:
            time.sleep(0.05)
        check(done["bg"], "долгая задача дошла до конца — её не прервали")
        # «Остановить» останавливает долгую задачу, а не подключение
        check(e.run_task("Подбираю стратегию zapret", long_job), "снова долгая задача")
        time.sleep(0.05)
        done["bg"] = False
        e.stop_current()
        t0 = time.time()
        while e.bg_busy() and time.time() - t0 < 5:
            time.sleep(0.02)
        check(not done["bg"] and not e.bg_busy(), "«Остановить» прервал долгую задачу")
        wait_idle(e)
    finally:
        if e:
            e.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


@case("Движок: кнопка «Стоп» прерывает проверку")
def t_engine_cancel():
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    try:
        e = make_engine(tmp)
        e.startup()
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        DEAD.update({"fast.example", "slow.example"})  # все серверы «висят» — проверка длилась бы долго
        t0 = time.time()
        e.run_task("Проверяю серверы", e.test_all)
        time.sleep(0.5)
        e.stop_event.set()
        wait_idle(e, 15)
        check(time.time() - t0 < 6, "проверка не остановилась быстро")
        check(any(ev == "info" for ev, _ in e.events), "нет сообщения «Остановлено»")
        check(not any(s.result.get("testing") for s in e.servers), "после остановки остались серверы «проверяю…»")
        e.shutdown()
    finally:
        DEAD.clear()
        shutil.rmtree(tmp, ignore_errors=True)


@case("Автопилот: сервер завис → переключение на запасной без перезапуска")
def t_engine_failover():
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    try:
        e = make_engine(tmp)
        e.settings["autopilot"] = True
        e.startup()
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        e.connect(e.best())
        HEALTH_PORT["port"] = e.ports["health"]
        first = e.current.name
        DEAD.add(e.current.address)
        BEHAVIOR[e.ports["health"]] = "dead"
        for _ in range(2):
            e._health_check()
        wait_idle(e, 30)
        check(e.connected and e.current.name != first, f"не переключился (остался {e.current.name})")
        r = netutil.http_ping(e.settings["ping_host"], "/generate_204", e.ports["health"], rounds=1, timeout=3)
        check(r["ok"], "после переключения нет связи")
        check("server_down" not in e.problems, "проблема «сервер не отвечает» не снялась после переключения")
        e.shutdown()
    finally:
        DEAD.clear()
        shutil.rmtree(tmp, ignore_errors=True)


@case("Лестница: другой отпечаток TLS, «подключено, но пусто», память сети, без петли, сторож данных")
def t_ladder():
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    real_check_all = engmod.services.check_all
    try:
        e = make_engine(tmp)
        e.settings["autopilot"] = True
        e.startup()
        q = "?security=reality&pbk=K&sni=a.com&type=tcp"
        e.add_servers("\n".join([
            f"vless://51111111-1111-4111-8111-111111111111@fpblocked.example:443{q}&fp=chrome#FP",
            f"vless://52222222-2222-4222-8222-222222222222@empty.example:443{q}#Empty",
            f"vless://53333333-3333-4333-8333-333333333333@backup.example:443{q}#Backup",
            f"vless://54444444-4444-4444-8444-444444444444@backup.example:8443{q}#Backup2"]))
        wait_idle(e)
        by = {x.name: x for x in e.servers}
        r403 = netutil.data_check(None, [f"http://127.0.0.1:{WEB}/403", f"http://127.0.0.1:{WEB}/403"], timeout=2)
        check(r403["ok"] and r403.get("inconclusive"), f"проверочный адрес недоступен — сервер не бракуется: {r403}")
        rdead = netutil.data_check(None, ["http://127.0.0.1:1/", "http://127.0.0.1:1/x"], timeout=2)
        check(not rdead["ok"] and not rdead.get("inconclusive"), f"соединение не открывается — данные не идут: {rdead}")
        # проверка серверов: Chrome режут — другой отпечаток помогает и запоминается
        e.test_all()
        fp = by["FP"]
        check(fp.result.get("ok") and fp.result.get("fp") == "firefox", f"отпечаток подобран: {fp.result}")
        check(any("Другой отпечаток TLS помог 1" in x for x in e.logs_view()), "в журнале — что помогло")
        info = next(x for x in e.state()["servers"] if x["key"] == fp.key)
        check(info["fp"] == "firefox", "окно видит подобранный отпечаток")
        cfg = xray.build_test_config([fp], [12345])
        check(cfg["outbounds"][0]["streamSettings"]["realitySettings"]["fingerprint"] == "firefox", "в настройках ядра")
        # «подключено, но пусто»: пинг проходит, данные нет — лестница уходит на другой сервер
        check(by["Empty"].result.get("ok"), "по пингу пустой сервер выглядит рабочим")
        e.connect(by["Empty"])
        HEALTH_PORT["port"] = e.ports["health"]
        check(not e._data_ok()["ok"], "данные через пустой сервер не идут")
        e.failover("данные через сервер не идут")
        check(e.connected and e.current.key != by["Empty"].key and e._data_ok()["ok"],
              f"лестница нашла сервер, через который идут данные: {e.current.name}")
        logs = " | ".join(e.logs_view())
        check("Лестница: данные пошли" in logs, f"в журнале шаг лестницы: {logs[-600:]}")
        nid = e._net_id()
        check(nid and e.settings["net_ways"].get(nid, {}).get("server") == e.current.key, "способ запомнен для сети")
        # «Подключено, но пусто» после переключения тоже ловится: _switch_to проверяет данные, а не только пинг
        check(not e._switch_to(by["Empty"]), "на пустой сервер не переключаемся")
        check(by["Empty"].result.get("status") == "нет данных", f"пометка сервера: {by['Empty'].result}")
        # отпечаток Chrome заблокировали у текущего сервера — шаг «другой отпечаток» на том же сервере
        fp.result.pop("fp", None)
        e.settings["net_ways"] = {}  # без памяти сети: проверяем именно шаг «другой отпечаток»
        e.connect(fp)
        HEALTH_PORT["port"] = e.ports["health"]
        check(not e._data_ok()["ok"], "с Chrome данные не идут")
        e.failover("сервер перестал отвечать")
        check(e.current.key == fp.key and fp.result.get("fp") == "firefox" and e._data_ok()["ok"],
              f"тот же сервер с другим отпечатком: {e.current.name} {fp.result.get('fp')}")
        check("Лестница: данные пошли — отпечаток firefox" in " | ".join(e.logs_view()), "шаг «отпечаток» в журнале")
        check(e.state()["ladder"]["way"] == "отпечаток firefox", f"способ в окне: {e.state()['ladder']}")
        # память сети: в этой сети работал Backup — при смене сети программа сразу берёт его
        e.settings["net_ways"][nid] = {"server": by["Backup"].key, "fp": "", "mask": 0, "at": time.time()}
        e._apply_net_way()
        check(e.current.key == by["Backup"].key, f"способ из памяти сети: {e.current.name}")
        # другой вход того же сервера (шаг 5): основной вход Backup режут, второй порт работает
        DEAD.add("backup.example")
        engmod.services.check_all = lambda paths, svcs=None, on_result=None, stop_event=None: {
            s["name"]: {"direct": {"state": "ok" if s["name"] in ("Google", "Telegram") else "blocked"}} for s in svcs or []}
        # ничего не работает: без петли, «что работает напрямую», повтор позже
        DEAD.update({"fpblocked.example", "empty.example"})
        e.failover("сервер перестал отвечать")
        st = e.state()["ladder"]
        ww = st["what_works"] or {}
        check(any(p["key"] == "no_working" for p in e.problems_list()), "«все серверы недоступны»")
        check(st["retry_at"] > time.time() + 60 and [i["name"] for i in ww.get("items", []) if i["ok"]] == ["Google", "Telegram"],
              f"пауза и «что работает напрямую»: {st}")
        real_ping = netutil.http_ping
        netutil.http_ping = lambda *a, **k: {"ok": False, "error": "нет ответа", "ping_ms": None, "delay_ms": None}
        try:
            for _ in range(3):
                e._health_check()
        finally:
            netutil.http_ping = real_ping
        check(not e.conn_busy(), "во время паузы лестница не крутится по кругу")
        DEAD.clear()
        ui = UIServer(os.path.join(APP_DIR, "ui"), "tok")
        ui.engine = e
        ui.dispatch("ladder_retry", {})
        wait_idle(e, 60)
        check(e.connected and e._data_ok()["ok"] and not e.state()["ladder"]["what_works"]
              and not any(p["key"] == "no_working" for p in e.problems_list()), "«Попробовать сейчас» — снова работает")
        # окно «Состояние»: данные, последнее действие лестницы, «Проверить всё»
        ui.dispatch("data_check", {})
        wait_idle(e)
        lad = e.state()["ladder"]
        check(lad["data"] and lad["data"]["ok"] and lad["data"]["ms"] is not None, f"данные в окне: {lad['data']}")
        check(lad["last"] and lad["last"]["ok"] and lad["last"]["text"].startswith("данные пошли"), f"последнее действие: {lad['last']}")
        calls = []
        e.cert_check = lambda quick=False: calls.append("certs")
        e.leak_test = lambda: calls.append("leaks")
        ui.dispatch("health_check", {})
        wait_idle(e)
        del e.cert_check, e.leak_test
        check(calls == ["certs", "leaks"] and e.state()["busy_kind"] == "", f"«Проверить всё»: {calls}")
        # сторож данных: уходит, а не приходит 15 секунд — проверка данных и лестница
        e._poll_stats = lambda: None  # скорость задаёт тест: монитор не должен «увидеть» входящие данные
        e.connect(by["Empty"])
        HEALTH_PORT["port"] = e.ports["health"]
        wait_idle(e)
        check(e.current.key == by["Empty"].key, f"снова на пустом: {e.current.name}")
        e._silent_checked = 0
        t0 = time.monotonic()
        e._data_watch(5000, 0, t0)
        e._data_watch(5000, 0, t0 + 16)
        time.sleep(0.3)
        wait_idle(e, 60)
        check(any("Сторож данных" in x for x in e.logs_view()) and e.current.key != by["Empty"].key,
              f"сторож заметил тишину и сменил сервер: {e.current.name}")
        # выключатели: без подбора отпечатка подобранные убираются; память сетей забывается
        ui.dispatch("auto_flags", {"fp_auto": False})
        wait_idle(e)
        check(not any((x.result or {}).get("fp") for x in e.servers) and e.state()["settings"]["fp_auto"] is False,
              "подбор отпечатка выключается")
        ui.dispatch("net_memory_clear", {})
        check(e.state()["ladder"]["count"] == 0, "память сетей очищается")
    finally:
        engmod.services.check_all = real_check_all
        DEAD.clear()
        if e:
            e.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


@case("Сервисы: проверка и автоисправление маршрутов")
def t_services():
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    old = services.SERVICES
    try:
        services.SERVICES = [
            {"name": "Google", "urls": [f"http://127.0.0.1:{WEB}/generate_204"], "domains": ["google.com"]},
            {"name": "Госуслуги", "urls": [f"http://127.0.0.1:{WEB}/403"], "russian": True, "domains": ["gosuslugi.ru"]},
        ]
        e = make_engine(tmp)
        e.startup()
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        e.connect(e.best())
        res = e.check_services()
        check(res["Google"]["current"]["state"] == "ok", "Google должен открываться")
        check(res["Госуслуги"]["current"]["state"] == "region", "403 у российского сайта = закрыт для страны")
        check("services" not in e.problems,
              "российский сайт, который и напрямую отвечает 403 (защита от ботов), — не проблема программы")
        # сертификат, которому Python не доверяет (российский УЦ, строгий режим Python 3.13): сайт всё равно отвечает
        orig_opener = services._opener

        class _CertFail:
            def open(self, req, timeout=None):
                raise urllib.error.URLError(ssl.SSLCertVerificationError(1, "certificate verify failed"))
        services._opener = lambda port: _CertFail()
        try:
            r = services.check_url("https://online.sberbank.ru/", None, True)
        finally:
            services._opener = orig_opener
        check(r["state"] == "ok", f"ошибка сертификата не значит «заблокировано»: {r}")
        ctx = netutil.ssl_context()
        check(ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname, "сертификаты по-прежнему проверяются")
        check(not (ctx.verify_flags & getattr(ssl, "VERIFY_X509_STRICT", 0)), "без сверхстрогого режима Python 3.13")
        fake = {"Google": {"direct": {"state": "blocked"}, "vpn": {"state": "ok"}, "current": {"state": "blocked"}},
                "Госуслуги": {"direct": {"state": "ok"}, "vpn": {"state": "region"}, "current": {"state": "region"}}}
        changes = e.autofix(fake)
        check(len(changes) == 2 and "google.com" in e.settings["proxy_list"] and "gosuslugi.ru" in e.settings["direct_list"],
              "автоисправление")
        e.set_service_route("Google", "auto")
        check("google.com" not in e.settings["proxy_list"], "маршрут сервиса не сбросился")
        e.shutdown()
    finally:
        services.SERVICES = old
        shutil.rmtree(tmp, ignore_errors=True)


@case("Самопроверка выводит отчёт и в русской Windows (кодировка cp1251)")
def t_selftest_encoding():
    import subprocess
    app = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    code = ("import sys, pult.selftest as st; "
            "st.run_all = lambda: {'results': [{'name': 'подписка \u2192 проверка', 'ok': True}], "
            "'total': 1, 'failed': 0, 'seconds': 0}; sys.argv = ['x', '--json']; st.main()")
    env = dict(os.environ, PYTHONIOENCODING="cp1251")
    env.pop("PYTHONUTF8", None)
    p = subprocess.run([sys.executable, "-c", code], cwd=app, capture_output=True, env=env, timeout=60)
    lines = p.stdout.decode("utf-8", "replace").strip().splitlines()
    check(lines and json.loads(lines[-1])["results"][0]["name"] == "подписка \u2192 проверка",
          "отчёт самопроверки не вывелся: " + p.stderr.decode("utf-8", "replace")[-300:])
    bad, outside = services.split_failures({
        "Сбербанк": {"direct": {"state": "blocked"}, "current": {"state": "blocked", "detail": "x"}},
        "Госуслуги": {"direct": {"state": "ok"}, "current": {"state": "region"}},
        "YouTube": {"direct": {"state": "blocked"}, "current": {"state": "blocked"}}})
    check(bad == ["Госуслуги", "YouTube"] and outside == ["Сбербанк (x)"], f"разбор неудач: {bad} {outside}")


@case("Ядро скачано — предупреждение «не скачано» сразу пропадает")
def t_core_missing():
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    old = xray.download_xray
    try:
        e = make_engine(tmp)
        os.remove(e.paths.xray)
        e._check_files()
        check("xray_missing" in e.problems, "без ядра должно быть предупреждение")

        def fake_download(paths, proxy_port=None, install=True):
            open(paths.xray, "w").close()
        xray.download_xray = fake_download
        e.update_xray()
        check("xray_missing" not in e.problems, "после скачивания ядра предупреждение должно исчезнуть сразу")
        e.shutdown()
    finally:
        xray.download_xray = old
        shutil.rmtree(tmp, ignore_errors=True)


@case("Автоподбор для сайтов: не открылся напрямую — сам в VPN; закрыт для страны — на другой сервер; на лету")
def t_auto_routes():
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    old_check, old_api, old_stall = services.check_url, xray.api_command, services.stall_test
    calls, probes = [], []
    try:
        def fake_stall(host, proxy_port=None, **kw):
            direct = proxy_port in (None, e._direct_http())
            if host.endswith("freeze.example") and direct:
                return {"state": services.STALL_STALL, "bytes": 16000, "detail": "соединение замирает после 15 КБ", "ms": 4000}
            return {"state": services.STALL_OK, "bytes": 70000, "detail": "68 КБ за 300 мс", "ms": 300}
        services.stall_test = fake_stall
        e = make_engine(tmp)
        e.startup()
        e.settings["mode"] = "smart"  # автоподбор нужен в экономном режиме: там обычные сайты идут напрямую
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        e.test_all()
        e.connect(e.best())
        check(e.connected, "подключено")
        health = e.ports["health"]

        def fake_check(url, port, region_sensitive, timeout=10.0):
            host = url.split("/")[2]
            probes.append((host, "direct" if port in (None, e._direct_http()) else "vpn" if port == health else "other"))
            if port in (None, e._direct_http()):  # напрямую
                return {"state": services.BLOCKED if host.endswith("blocked.example") else services.OK, "detail": "x", "ms": 1}
            if port == health:  # через текущий сервер
                return {"state": services.REGION if host.endswith("region.example") else services.OK, "detail": "403", "ms": 1}
            return {"state": services.OK, "detail": "ok", "ms": 1}  # через другой сервер (временное ядро)
        services.check_url = fake_check

        def rec_api(paths, port, args, exe=None):
            if args[0] in ("adrules", "ado"):
                with open(args[-1], encoding="utf-8") as f:
                    calls.append((args[0], json.load(f)))
            return old_api(paths, port, args, exe)
        xray.api_command = rec_api

        # открыли новый сайт — напрямую он не открывается
        e._auto_offer("www.site.blocked.example", "direct", 443)
        e._auto_offer("ok.example.org", "direct", 443)
        e._auto_offer("cdn.region.example", "proxy", 443)
        e._auto_offer("youtube.com", "direct", 443)  # обход/встроенные — нет; но и не проверять повторно
        e._auto_offer("img.freeze.example", "direct", 443)  # открывается, но качать не даёт (картинки, видео)
        e._auto_offer("d111.cloudfront.net", "direct", 443)  # общий CDN — правило на сам адрес, не на весь CDN
        deadline = time.time() + 15
        while time.time() < deadline and (e._auto_q or e._auto_queued):
            time.sleep(0.05)
        auto = e.settings["auto_sites"]
        check(auto.get("blocked.example", {}).get("via") == "proxy", f"не открылся напрямую — в VPN: {auto}")
        check(auto.get("region.example", {}).get("via") == "server", f"закрыт для страны — другой сервер: {auto}")
        check("example.org" not in auto and "example.org" in e.settings["auto_seen"], "открывается — правила не нужно")
        check(auto.get("freeze.example", {}).get("via") == "proxy" and "картинки" in auto["freeze.example"]["why"],
              f"открывается, но зависает после первых килобайт — в VPN: {auto.get('freeze.example')}")
        check("d111.cloudfront.net" in e.settings["auto_seen"] and "cloudfront.net" not in e.settings["auto_seen"],
              "общий CDN проверяется по своему адресу")
        check(not any(h.endswith("region.example") and how == "direct" for h, how in probes),
              "сайт, который идёт через VPN, напрямую не проверялся (провайдер его не видит)")
        rules = [c[1]["routing"]["rules"][0] for c in calls if c[0] == "adrules"]
        check(any(r.get("domain") == ["domain:blocked.example"] and _ot(r) == "proxy" for r in rules),
              f"правило добавлено на лету через API ядра: {rules}")
        check(any(c[0] == "ado" for c in calls), "для другого сервера на лету добавлен его выход")
        # повторно тот же сайт не проверяется
        n = len(probes)
        e._auto_offer("other.ok.example.org", "direct", 443)
        e._auto_offer("x.blocked.example", "direct", 443)
        time.sleep(0.3)
        check(len(probes) == n, "уже проверенные сайты не проверяются снова")
        # своё правило главнее автоподбора
        e.route_site("blocked.example", "direct", main_domain=False)
        plan = e._route_plan(e.current, e.proc.exe)
        check(not any(r.get("auto") and "domain:blocked.example" in r["domains"] for r in plan), "своё правило главнее")
        check(any(r.get("auto") and "domain:region.example" in r["domains"] and r["tag"].startswith("pin") for r in plan),
              "автоправило «другой сервер» в настройках ядра")
        st_ = e.settings
        text = json.dumps(routing.build_rules("smart", st_.get("proxy_list", ""), st_.get("direct_list", ""),
                                              st_.get("block_list", ""), use_geo=True, block_ads="dat", routes=plan))
        check(text.index("ext:adblock.dat:ads") < text.index("domain:region.example") < text.index("geosite:ru-blocked"),
              "автоправила — после рекламы, но до встроенных списков")
        st = e.state()["auto"]
        check(st["enabled"] and any(x["site"] == "region.example" for x in st["items"]), f"состояние для интерфейса: {st}")
        e.auto_forget("region.example")
        check("region.example" not in e.settings["auto_sites"] and e.settings["auto_seen"]["region.example"].get("ignore"),
              "убранное правило больше само не вернётся")
        # сбой сети: напрямую не открывается ничего — в VPN всё подряд не уезжает
        services.check_url = lambda url, port, region_sensitive, timeout=10.0: {"state": services.BLOCKED if port in (None, e._direct_http())
                                                                 else services.OK, "detail": "x", "ms": 1}
        e._auto_offer("new.down.example", "direct", 443)
        deadline = time.time() + 10
        while time.time() < deadline and (e._auto_q or e._auto_queued):
            time.sleep(0.05)
        check("down.example" not in e.settings["auto_sites"] and e._auto_pause_until > time.time(),
              "при сбое сети автоподбор ждёт, а не уводит всё в VPN")
        e.disconnect()
    finally:
        services.check_url, xray.api_command, services.stall_test = old_check, old_api, old_stall
        if e:
            e.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


@case("«Сайт работает не полностью»: зависание после 16 КБ, адреса сайта, починка через VPN и другой сервер")
def t_repair_site():
    import socket as _s
    # сама проверка «качается ли» — на настоящих соединениях
    def serve(mode):
        srv = _s.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)

        def run():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return

                def handle(c=c):
                    sent = 0
                    try:
                        while True:
                            data = b""
                            while b"\r\n\r\n" not in data:
                                d = c.recv(4096)
                                if not d:
                                    return
                                data += d
                            body = b"x" * 5000
                            resp = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body
                            for i in range(0, len(resp), 1000):
                                if mode == "freeze" and sent > 16000:
                                    time.sleep(5)
                                    return
                                c.sendall(resp[i:i + 1000])
                                sent += len(resp[i:i + 1000])
                            if mode == "close":
                                c.close()
                                return
                    except OSError:
                        pass
                    finally:
                        c.close()
                threading.Thread(target=handle, daemon=True).start()
        threading.Thread(target=run, daemon=True).start()
        return srv, srv.getsockname()[1]
    servers = []
    try:
        for mode, want in (("ok", services.STALL_OK), ("freeze", services.STALL_STALL), ("close", services.STALL_SMALL)):
            srv, port = serve(mode)
            servers.append(srv)
            r = services.stall_test("127.0.0.1", None, port=port, stall_s=1.5)
            check(r["state"] == want, f"проверка «качается ли» ({mode}): {r}")
        check(services.stall_test("127.0.0.1", None, port=1, stall_s=1)["state"] == services.STALL_FAIL, "не открывается совсем")
    finally:
        for srv in servers:
            srv.close()

    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    old_stall, old_api = services.stall_test, xray.api_command
    tested = []
    try:
        e = make_engine(tmp)
        e.settings["auto_routes"] = False  # фоновый автоподбор здесь не мешает
        e.startup()
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        e.test_all()
        e.connect(e.best())
        health = e.ports["health"]

        def fake_stall(host, proxy_port=None, **kw):
            how = "direct" if proxy_port in (None, e._direct_http()) else "vpn" if proxy_port == health else "other"
            tested.append((host, how))
            if host == "img.cdnfreeze.example" and how == "direct":
                return {"state": services.STALL_STALL, "bytes": 16000, "detail": "соединение замирает после 15 КБ", "ms": 4000}
            if host == "video.region2.example" and how == "vpn":
                return {"state": services.STALL_FAIL, "bytes": 0, "detail": "сайт не отвечает", "ms": None}
            if host == "dead.example":
                return {"state": services.STALL_FAIL, "bytes": 0, "detail": "сайт не отвечает", "ms": None}
            return {"state": services.STALL_OK, "bytes": 70000, "detail": "68 КБ за 300 мс", "ms": 300}
        services.stall_test = fake_stall
        xray.api_command = lambda *a, **kw: ""
        now = time.time()
        for dt, h, out in ((-400, "unrelated.example", "direct"), (-30, "www.site.example", "direct"),
                           (-29, "img.cdnfreeze.example", "direct"), (-28, "video.region2.example", "proxy"),
                           (-27, "ads.tracker.example", "adblock"), (-26, "static.site.example", "direct")):
            e._host_log.append((now + dt, h, out))
            e.connections[h] = {"host": h, "count": 1, "route": out, "last": "", "port": 443}
        r = e.repair_site("https://www.site.example/page")
        hosts = {x["host"]: x for x in r["hosts"]}
        check(r["site"] == "site.example" and "unrelated.example" not in hosts and "img.cdnfreeze.example" in hosts,
              f"адреса, которые загружал сайт: {list(hosts)}")
        check(list(hosts)[:2] == ["www.site.example", "static.site.example"] or list(hosts)[0].endswith("site.example"),
              "сначала адреса самого сайта")
        check(hosts["img.cdnfreeze.example"]["fix"] == "proxy" and e.settings["auto_sites"]["cdnfreeze.example"]["via"] == "proxy",
              f"зависал напрямую — теперь через VPN: {hosts['img.cdnfreeze.example']}")
        check(hosts["video.region2.example"]["fix"] == "server" and e.settings["auto_sites"]["region2.example"]["via"] == "server",
              f"не работал через этот сервер — теперь через другой: {hosts['video.region2.example']}")
        check(hosts["ads.tracker.example"]["state"] == "blocked", "закрытый блокировщиком адрес показан, но не трогается")
        check(not any(h == "video.region2.example" and how == "direct" for h, how in tested),
              "адрес, который шёл через VPN, напрямую не проверялся")
        check(r["fixed"] == 2 and "Починил 2" in r["verdict"], f"итог: {r['verdict']}")
        # сайт ещё не открывали — проверяется только он сам, и программа подсказывает открыть его
        r2 = e.repair_site("fresh.example")
        check(not r2["seen"] and r2["hosts"][0]["host"] == "fresh.example" and "Открой его" in r2["verdict"],
              f"сайт не открывали: {r2['verdict']}")
        try:
            e.disconnect()
            e.repair_site("site.example")
            check(False, "без VPN починка не запускается")
        except RuntimeError:
            pass
    finally:
        services.stall_test, xray.api_command = old_stall, old_api
        if e:
            e.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


@case("Приложения: свой путь для программы, подбор для Discord, торренты, старое ядро без правил по процессам")
def t_apps():
    from pult import apps, tun
    check(apps.clean_name("C:\\Users\\me\\AppData\\Local\\Discord\\app-1.0\\Discord.exe") == "Discord"
          and apps.clean_name("bad/../name<>") == "" and apps.rule_process("DiscordPTB") == ["Discord", "DiscordPTB", "DiscordCanary"],
          "имя процесса для правила")
    rows = [(10, "C:\\Program Files\\Discord\\Discord.exe", 3), (11, "C:\\Windows\\System32\\svchost.exe", 9),
            (12, "C:\\Games\\game.exe", 5), (13, "C:\\Discord\\Discord.exe", 2)]
    got = apps.running(lambda: rows)
    check([a["name"] for a in got] == ["Discord", "game"] and got[0]["conns"] == 5, f"приложения в сети: {got}")
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    old_check, old_start = services.check_url, engmod.XrayProcess.start
    try:
        e = make_engine(tmp)
        e._apps_lister = lambda: rows
        e.startup()
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        e.test_all()
        e.connect(e.best())
        e.apps_scan()
        st = e.apps_state()
        check(st["supported"] and [x["name"] for x in st["running"]] == ["Discord", "game"], f"список для выбора: {st['running']}")
        e.set_app_route("C:/Games/game.exe", "direct")
        e.set_app_route("qbittorrent", "block")
        other = next(x for x in e.servers if x.supported and x.key != e.current.key)
        e.set_app_route("Discord", f"server:{other.key}")
        plan = e._route_plan(e.current, e.proc.exe)
        procs = {tuple(r["process"]): r["tag"] for r in plan if r.get("app")}
        check(procs.get(("game",)) == "direct" and procs.get(("qbittorrent",)) == "block"
              and procs.get(("Discord", "DiscordPTB", "DiscordCanary"), "").startswith("pin"), f"правила приложений: {procs}")
        e.reconnect()
        with open(e.paths.run_config, encoding="utf-8") as f:
            cfg = json.load(f)
        rules = cfg["routing"]["rules"]
        idx = lambda pred: next(i for i, r in enumerate(rules) if pred(r))  # noqa: E731
        check(rules[idx(lambda r: r.get("protocol") == ["bittorrent"])]["outboundTag"] == "direct", "торренты напрямую")
        i_app = idx(lambda r: r.get("process") == ["game"])
        i_ads = idx(lambda r: any("ads" in d for d in r.get("domain", [])) and _ot(r) == "adblock") \
            if any(r.get("outboundTag") == "adblock" for r in rules) else -1
        check(i_app > i_ads, "правила приложений после рекламы — реклама в них тоже блокируется")
        st = e.apps_state()
        disc = next(x for x in st["items"] if x["name"] == "Discord")
        check("TUN" in disc["warn"] and disc["preset"] and disc["voice"], f"подсказка про TUN для Discord: {disc}")
        check([x["name"] for x in st["running"]] == [], "уже выбранные приложения не предлагаются снова")
        # sing-box: «напрямую» и «блок» — его собственными правилами
        sb = tun.singbox_config(10808, False, False, False, *e._tun_apps())
        sb_rules = sb["route"]["rules"]
        check({"process_name": ["game.exe"], "action": "route", "outbound": "direct"} in sb_rules
              and {"process_name": ["qbittorrent.exe"], "action": "reject"} in sb_rules, "sing-box: приложения мимо VPN и без сети")
        # торренты через VPN
        e.settings["torrent_route"] = "proxy"
        e.reconnect()
        with open(e.paths.run_config, encoding="utf-8") as f:
            check('"bittorrent"' not in f.read(), "торренты через VPN — отдельного правила нет")
        # «Подобрать» для Discord: напрямую не работает, через VPN работает
        services.check_url = lambda url, port, region_sensitive, timeout=10.0: {
            "state": services.BLOCKED if port in (None, e._direct_http()) else services.OK, "detail": "x", "ms": 1}
        r = e.pick_app("Discord")
        check(r["choice"] == "proxy" and e.settings["app_routes"]["Discord"]["via"] == "proxy" and "TUN" in r["verdict"],
              f"подбор для Discord: {r}")
        services.check_url = lambda url, port, region_sensitive, timeout=10.0: {"state": services.OK, "detail": "x", "ms": 1}
        check(e.pick_app("Discord")["choice"] == "direct", "напрямую работает — напрямую (быстрее)")
        # старое ядро не знает «process» — запускаемся без правил приложений
        def picky(self, config, *a, **kw):
            if '"process"' in json.dumps(config):
                raise engmod.XrayError("failed to build routing: unknown field process")
            return old_start(self, config, *a, **kw)
        engmod.XrayProcess.start = picky
        e.reconnect()
        check(e.connected and e._apps_off and any("обнови ядро" in x["warn"].lower() for x in e.apps_state()["items"]),
              "старое ядро — подключение без маршрутов приложений и подсказка обновить")
        engmod.XrayProcess.start = old_start
        e.set_app_route("game", "auto")
        check("game" not in e.settings["app_routes"], "убрать свой путь приложения")
        e.disconnect()
    finally:
        services.check_url, engmod.XrayProcess.start = old_check, old_start
        if e:
            e.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


@case("Мгновенное переключение: запасной сервер внутри ядра, проверка связи — на основном, старое ядро")
def t_failover():
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    old_start = engmod.XrayProcess.start
    try:
        e = make_engine(tmp)
        e.startup()
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        e.test_all()
        e.connect(e.best())
        with open(e.paths.run_config, encoding="utf-8") as f:
            cfg = json.load(f)
        obs = {o["tag"]: o for o in cfg["outbounds"]}
        bal = (cfg["routing"].get("balancers") or [{}])[0]
        check(bal.get("selector") == ["proxy"] and bal.get("fallbackTag") == "bk1" and "bk1" in obs,
              f"балансировщик с запасным сервером: {bal}")
        check(obs["bk1"] != obs["proxy"] and json.dumps(obs["bk1"].get("settings")) != json.dumps(obs["proxy"].get("settings")),
              "запасной — другой сервер")
        check(cfg["burstObservatory"]["subjectSelector"] == ["proxy", "bk1"]
              and cfg["burstObservatory"]["pingConfig"]["destination"].startswith("https://"), "ядро само проверяет оба")
        rules = cfg["routing"]["rules"]
        check(next(r for r in rules if r.get("inboundTag") == ["health-in"])["outboundTag"] == "proxy",
              "проверка связи программы — на основном сервере")
        check(not any(r.get("outboundTag") == "proxy" for r in rules if r.get("inboundTag") != ["health-in"])
              and any(r.get("balancerTag") == "failover" for r in rules), "«через VPN» — через балансировщик")
        check(all(not t.startswith(("proxy", "bk1")) or t in ("proxy", "bk1") for t in obs),
              f"вспомогательные выходы не попадают под выбор балансировщика: {list(obs)}")
        # выключили — обычные правила
        e.settings["failover"] = False
        e.reconnect()
        with open(e.paths.run_config, encoding="utf-8") as f:
            cfg = json.load(f)
        check("balancers" not in cfg["routing"] and "burstObservatory" not in cfg, "выключено — без балансировщика")
        e.settings["failover"] = True
        # ядро не понимает балансировщик — подключение без него
        def picky(self, config, *a, **kw):
            if "burstObservatory" in config:
                raise engmod.XrayError("infra/conf: unknown config id: burstObservatory")
            return old_start(self, config, *a, **kw)
        engmod.XrayProcess.start = picky
        e.reconnect()
        check(e.connected and e._failover_off, "старое ядро — без запасного сервера внутри, но подключено")
        engmod.XrayProcess.start = old_start
        # подписка скоро закончится и кончается трафик — предупреждение заранее, раз в день
        meta = e.settings["subscriptions"][0]
        meta["usage"] = {"upload": 10, "download": 95 * 2 ** 30, "total": 100 * 2 ** 30, "expire": time.time() + 2 * 86400}
        e.tray_queue.clear()
        e._sub_alerts()
        keys = {p["key"]: p for p in e.problems_list()}
        check(f"sub_expire:{meta['id']}" in keys and f"sub_traffic:{meta['id']}" in keys and len(e.tray_queue) == 2,
              f"предупреждения о подписке: {list(keys)}")
        e._sub_alerts()
        check(len(e.tray_queue) == 2, "сообщение у трея — не чаще раза в день")
        meta["usage"]["expire"] = time.time() - 10
        e._sub_alerts()
        check(keys and next(p for p in e.problems_list() if p["key"] == f"sub_expire:{meta['id']}")["level"] == "error",
              "подписка закончилась — ошибка")
        e.settings["sub_alerts"] = False
        e._sub_alerts()
        check(not any(p["key"].startswith("sub_") for p in e.problems_list()), "выключили — предупреждений нет")
        e.disconnect()
    finally:
        engmod.XrayProcess.start = old_start
        if e:
            e.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


@case("Kill switch и профили сетей: VPN сломался — «через VPN» никуда; в открытом Wi-Fi — VPN сам и всё через него")
def t_kill_net():
    from pult import netprofile
    cafe = "    SSID                   : Cafe_Free\n    BSSID   : 1\n    Authentication         : Open\n    Cipher                 : None\n"
    home = "    SSID                   : Дом_5G\n    Проверка подлинности   : WPA2-Personal\n    Шифр                   : CCMP\n"
    check(netprofile.current(lambda: cafe) == {"kind": "wifi", "ssid": "Cafe_Free", "open": True}
          and netprofile.current(lambda: home)["open"] is False and netprofile.current(lambda: "")["kind"] == "wired",
          "определение сети (английская и русская Windows)")
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    try:
        e = make_engine(tmp)
        net = {"text": home}
        e._net_runner = lambda: net["text"]
        e.startup()
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        e.test_all()
        srv = e.best()
        e.connect(srv)
        # kill switch выключен: переподключиться не вышло — честно отключаемся
        real_connect = e.connect

        def broken(server):
            raise RuntimeError("timeout")
        e.connect = broken
        try:
            e._recover(srv)
            check(False, "без kill switch ошибка должна дойти до задачи")
        except RuntimeError:
            pass
        check(not e.core_running and not e.kill_on, "без kill switch — отключено")
        e.connect = real_connect
        e.connect(srv)
        e.settings["kill_switch"] = True
        e.connect = broken
        e._recover(srv)
        check(e.kill_on and not e.connected and e.proc.alive(), "kill switch: ядро работает без сервера")
        with open(e.paths.run_config, encoding="utf-8") as f:
            cfg = json.load(f)
        proxy = next(o for o in cfg["outbounds"] if o["tag"] == "proxy")
        check(proxy["protocol"] == "blackhole" and any(p["key"] == "kill_switch" for p in e.problems_list()),
              "«через VPN» — в никуда, и это видно")
        check(e.state()["kill_on"], "состояние для интерфейса")
        e.connect = real_connect
        e._kill_retry()
        check(e.connected and not e.kill_on and not any(p["key"] == "kill_switch" for p in e.problems_list()),
              "VPN снова работает — kill switch снят")
        e.connect = broken
        e._recover(srv)
        e.connect = real_connect
        e.disconnect()
        check(not e.kill_on and not e.core_running, "«Отключить» открывает интернет без VPN")
        e.settings["kill_switch"] = False
        # профили сетей: открытый Wi-Fi — VPN сам, всё через VPN, kill switch
        e._net_watch()
        check(e.net_profile["profile"] == "home" and not e.kill_switch_active(), "своя сеть — обычные настройки")
        net["text"] = cafe
        CAPTIVE["on"] = True  # кафе сначала просит войти: VPN и kill switch закрыли бы страницу входа
        try:
            e._net_watch()
            wait_idle(e)
            check(e.net_profile.get("captive") and not e.kill_switch_active() and not e.connected,
                  f"страница входа: ждём входа, ничего не закрываем: {e.net_profile}")
            check(any("просит войти" in m for m in MESSAGES), "человеку сказано, что делать")
        finally:
            CAPTIVE["on"] = False
        # ядро пропало (антивирус) — понятная причина; не запустилось из-за антивируса — тоже
        exe = e.paths.xray
        os.rename(exe, exe + ".bak")
        try:
            e._check_files()
            check(any(p["key"] == "xray_missing" and "антивирус" in p["title"] for p in e.problems_list()),
                  "пропавшее ядро — подсказка про антивирус")
        finally:
            os.rename(exe + ".bak", exe)
            e._check_files()
        err = OSError(22, "Operation did not complete successfully because the file contains a virus")
        err.winerror = 225
        check("антивирус" in xray.start_error(err, exe) and "антивирус" in xray.start_error(PermissionError(13, "x"), exe),
              "антивирус при запуске ядра")
        # часы: по заголовку Date сервера (здесь — местный, расхождения нет), сбитые часы — «!» с подсказкой
        skew = netutil.clock_skew()
        check(skew is not None and abs(skew) < 5, f"расхождение часов: {skew}")
        real_skew = netutil.clock_skew
        try:
            netutil.clock_skew = lambda timeout=6.0: -900.0
            e._clock_check()
            check(any(p["key"] == "clock" and "отстают на 15 мин" in p["title"] for p in e.problems_list()), "часы отстают")
            netutil.clock_skew = lambda timeout=6.0: 3.0
            e._clock_check()
            check(not any(p["key"] == "clock" for p in e.problems_list()), "часы точные — «!» убран")
        finally:
            netutil.clock_skew = real_skew
        e._net_watch()  # вошёл — обычная защита чужой сети
        wait_idle(e)
        check(any("Вход в сеть «Cafe_Free» выполнен" in m for m in MESSAGES), "вход замечен")
        check(e.net_profile["profile"] == "public" and e.kill_switch_active() and e.connected, f"чужая сеть: {e.net_profile}")
        with open(e.paths.run_config, encoding="utf-8") as f:
            cfg = json.load(f)
        check(cfg["outbounds"][0]["tag"] == "proxy", "в чужой сети всё через VPN (по умолчанию — VPN)")
        check(e.state()["net"]["profile"] == "public", "интерфейс видит чужую сеть")
        e.net_mark("home")
        wait_idle(e)
        check(e.net_profile["profile"] == "home" and "Cafe_Free" in e.settings["net_trusted"], "отметил своей — своя")
        with open(e.paths.run_config, encoding="utf-8") as f:
            cfg = json.load(f)
        check(cfg["outbounds"][0]["tag"] == ("direct" if e.settings["mode"] == "smart" else "proxy"),
              "в своей сети — снова выбранный режим")
        e.settings["net_trusted"] = []
        e.settings["net_profiles"] = False
        e._net_watch()
        check(e.net_profile["profile"] == "public" and not e.kill_switch_active(), "профили выключены — ничего не меняется")
        e.disconnect()
    finally:
        if e:
            e.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


@case("Проверка утечек: адрес через VPN, DNS, WebRTC, IPv6")
def t_leaks():
    from pult import leaks
    import struct as _st
    # настоящий разбор ответа STUN (как WebRTC узнаёт адрес)
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))

    def stun_reply():
        data, addr = srv.recvfrom(2048)
        ip = _st.unpack("!I", socket.inet_aton("203.0.113.7"))[0] ^ 0x2112A442
        attr = _st.pack("!HHBBH", 0x0020, 8, 0, 1, 5000 ^ 0x2112) + _st.pack("!I", ip)
        srv.sendto(_st.pack("!HHI", 0x0101, len(attr), 0x2112A442) + data[8:20] + attr, addr)
    threading.Thread(target=stun_reply, daemon=True).start()
    check(leaks.stun_mapped(("127.0.0.1", srv.getsockname()[1]), timeout=3) == "203.0.113.7", "разбор ответа STUN")
    srv.close()
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    saved = (leaks.ip_info, leaks.dns_info, leaks.stun_mapped, leaks.ipv6_address)
    try:
        e = make_engine(tmp)
        e.startup()
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        e.test_all()
        try:
            e.leak_test()
            check(False, "без VPN проверка не запускается")
        except RuntimeError:
            pass
        e.connect(e.best())
        health = e.ports["health"]
        leaks.ip_info = lambda port: {"ip": "45.1.1.1", "isp": "Hosting", "country": "NL"} if port == health \
            else {"ip": "95.2.2.2", "isp": "Rostelecom", "country": "RU"}
        leaks.dns_info = lambda port: {"ip": "1.1.1.1", "geo": "Netherlands - Cloudflare"}
        leaks.stun_mapped = lambda *a, **k: "95.2.2.2"
        leaks.ipv6_address = lambda: ""
        r = e.leak_test()
        st = {x["title"]: x["state"] for x in r["items"]}
        check(st.get("Сайты через VPN видят адрес сервера, а не твой") == "ok", f"адрес через VPN: {st}")
        check(st.get("WebRTC в браузере может показать сайтам настоящий адрес") == "warn", "WebRTC в режиме прокси")
        check(any(x["state"] == "info" and "Российские сайты идут напрямую" in x["title"] for x in r["items"]),
              "подсказка: российские сайты напрямую")
        check(e.state()["leaks"]["warnings"] == 1 and r["errors"] == 0, f"итог: {r['errors']}/{r['warnings']}")
        logs = "\n".join(e.logs_view())
        check("95.2.2.2" not in logs and "45.1.1.1" not in logs, "адреса не попадают в журнал")
        leaks.ip_info = lambda port: {"ip": "95.2.2.2", "isp": "Rostelecom", "country": "RU"}
        check(e.leak_test()["errors"] >= 1, "VPN не меняет адрес — ошибка")
        e.disconnect()
    finally:
        leaks.ip_info, leaks.dns_info, leaks.stun_mapped, leaks.ipv6_address = saved
        if e:
            e.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


@case("Шифрование данных: подписки и пароли на диске, перенос на другой компьютер, удаление настроек ядра")
def t_secure():
    from pult import secure, settings as settings_mod
    key = {"k": 0x5A}
    xor = lambda b: bytes(x ^ key["k"] for x in b)  # noqa: E731
    old_backend, old_wipe = secure.BACKEND, xray.WIPE_CONFIGS
    secure.BACKEND = (lambda b: b"OK" + xor(b), lambda b: xor(b[2:]) if b[:2] == b"OK" and key["k"] == 0x5A else
                      (_ for _ in ()).throw(secure.SecureError("bad key")))
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    try:
        path = os.path.join(tmp, "settings.json")
        st = settings_mod.Settings(path)
        st["subscriptions"] = [{"id": "a", "url": "https://secret.example/sub/TOKEN123"}]
        st["proxies"] = [{"id": "p", "host": "1.2.3.4", "user": "me", "pass": "Very-Secret-Pw"}]
        st["mode"] = "vpn"
        st.save()
        raw = open(path, encoding="utf-8").read()
        check("TOKEN123" not in raw and "Very-Secret-Pw" not in raw and '"_secure": "VDMSEC1:' in raw and '"mode": "vpn"' in raw,
              "на диске секреты зашифрованы, остальное как есть")
        st2 = settings_mod.Settings(path)
        check(st2["subscriptions"][0]["url"].endswith("TOKEN123") and st2["proxies"][0]["pass"] == "Very-Secret-Pw"
              and not st2.secure_failed, "читается обратно")
        key["k"] = 0x11  # «другой компьютер»
        st3 = settings_mod.Settings(path)
        check(st3.secure_failed and st3["subscriptions"] == [], "на другом компьютере не расшифровать")
        st3["mode"] = "smart"
        st3.save()
        key["k"] = 0x5A
        check(settings_mod.Settings(path)["subscriptions"], "то, что не прочитали, не затирается")
        st4 = settings_mod.Settings(path)
        st4["encrypt_data"] = False
        st4.save()
        check("TOKEN123" in open(path, encoding="utf-8").read(), "шифрование можно выключить")
        # кэш подписки и настройки ядра
        e = make_engine(os.path.join(tmp, "app"))
        e.startup()
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        cache = e._sub_cache(e.settings["subscriptions"][0]["id"])
        check(open(cache, encoding="utf-8").read().startswith(secure.PREFIX), "кэш подписки зашифрован")
        e2 = make_engine(os.path.join(tmp, "app"))
        e2.load_cached()
        check(len(e2.servers) == len(e.servers) > 0, "зашифрованный кэш читается")
        probe = os.path.join(tmp, "probe.json")
        open(probe, "w").close()
        xray.WIPE_CONFIGS = False
        xray.wipe(probe)
        check(os.path.exists(probe), "без шифрования настройки ядра остаются")
        xray.WIPE_CONFIGS = True
        xray.wipe(probe)
        check(not os.path.exists(probe), "с шифрованием настройки ядра удаляются после запуска")
        e.shutdown()
        e2.shutdown()
    finally:
        secure.BACKEND, xray.WIPE_CONFIGS = old_backend, old_wipe
        shutil.rmtree(tmp, ignore_errors=True)


@case("Обновление программы: подпись выпуска, контрольная сумма, установка при запуске, данные не трогаются")
def t_app_update():
    import hashlib as _hl
    import io
    import zipfile as _zf
    from pult import update
    sys.path.insert(0, os.path.join(APP_DIR, "build"))
    import release_keys
    key = release_keys.generate(1024)
    old = (update.UPDATE_URL, dict(update.PUBLIC_KEY), update.ALLOW_HTTP)
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    try:
        buf = io.BytesIO()
        with _zf.ZipFile(buf, "w") as z:
            z.writestr("VedomyjVPN/pult/hello_update.txt", "новая версия")
            z.writestr("VedomyjVPN/main_new.txt", "main")
            z.writestr("VedomyjVPN/data/settings.json", "{}")       # данные обновление не трогает
            z.writestr("VedomyjVPN/bin/xray", "x")                  # ядро тоже
            z.writestr("../escape.txt", "x")                        # чужие пути — тем более
        archive = buf.getvalue()
        manifest = {"version": "99.0.0", "notes": "Тест", "pc": {"url": f"http://127.0.0.1:{WEB}/release/app.zip",
                                                                 "sha256": _hl.sha256(archive).hexdigest()}}
        signed = update.pack(manifest, key["n"], key["d"])
        RELEASE.update({"latest.json": json.dumps(signed).encode(), "app.zip": archive})
        forged = dict(signed, payload=signed["payload"].replace("99.0.0", "99.0.1"))
        RELEASE["forged.json"] = json.dumps(forged).encode()
        RELEASE["test-vector.json"] = json.dumps({"n": str(key["n"]), "signed": signed}).encode()
        update.UPDATE_URL = f"http://127.0.0.1:{WEB}/release/latest.json"
        update.PUBLIC_KEY = {"n": key["n"], "e": key["e"]}
        update.ALLOW_HTTP = True
        check(update.newer("1.10.0", "1.9.9") and not update.newer("1.5.0", "1.5.0"), "сравнение версий")
        try:
            update.fetch_manifest(url=f"http://127.0.0.1:{WEB}/release/forged.json")
            check(False, "подменённый выпуск должен отклоняться")
        except update.UpdateError as exc:
            check("подпись" in str(exc), f"подмена: {exc}")
        e = make_engine(tmp)
        e.startup()
        r = e.app_update_check()
        check(r["newer"] and r["staged"] and e.state()["app_update"]["info"]["staged"], f"скачано и подготовлено: {r}")
        staged = os.path.join(e.paths.data_dir, "update", "files")
        check(os.path.isfile(os.path.join(staged, "pult", "hello_update.txt"))
              and not os.path.exists(os.path.join(staged, "data")) and not os.path.exists(os.path.join(staged, "bin"))
              and not os.path.exists(os.path.join(tmp, "escape.txt")), "в обновлении только файлы программы")
        e.shutdown()
        e = None
        with open(os.path.join(tmp, "data", "settings.json"), encoding="utf-8") as f:
            before = f.read()
        check(update.apply_staged(tmp) == "99.0.0", "обновление ставится при запуске")
        check(os.path.isfile(os.path.join(tmp, "pult", "hello_update.txt")) and os.path.isfile(os.path.join(tmp, "main_new.txt"))
              and not os.path.isdir(os.path.join(tmp, "data", "update")), "файлы на месте, временная папка убрана")
        with open(os.path.join(tmp, "data", "settings.json"), encoding="utf-8") as f:
            check(f.read() == before, "настройки не тронуты")
        # повреждённый архив не ставится
        RELEASE["app.zip"] = archive + b"x"
        e = make_engine(tmp)
        e.startup()
        try:
            e.app_update_check()
            check(False, "повреждённый архив должен отклоняться")
        except update.UpdateError:
            pass
        check(not os.path.isdir(os.path.join(e.paths.data_dir, "update")), "повреждённое обновление не остаётся")
        update.UPDATE_URL = ""
        try:
            e.app_update_check()
            check(False, "без адреса выпуска проверка не идёт")
        except RuntimeError:
            pass
    finally:
        update.UPDATE_URL, update.PUBLIC_KEY, update.ALLOW_HTTP = old
        RELEASE.clear()
        if e:
            e.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


@case("История качества, VPN на время, умные уведомления, трафик за день")
def t_quality_timer():
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    try:
        e = make_engine(tmp)
        e.startup()
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        e.test_all()
        good = [x for x in e.servers if (x.result or {}).get("ok")]
        a, b = good[0], good[1]
        key = e._rank_key()
        check(key(a.result) is not None, "оценка работает")
        # часы подальше от текущего: фоновые проверки во время теста пишут историю в текущий час
        now_h = time.localtime().tm_hour
        bad_h, calm_h = (now_h + 12) % 24, (now_h + 6) % 24
        e.settings["server_hist"] = {}
        for _ in range(6):  # сервер a в «плохой» час часто отказывает
            e._note_quality(a.key, False, hour=bad_h)
        e._note_quality(a.key, True, hour=bad_h)
        check(e.hour_penalty(a.key, hour=bad_h) > 1000 and e.hour_penalty(a.key, hour=calm_h) == 0
              and e.hour_penalty(b.key, hour=bad_h) == 0, "в «плохой» час сервер штрафуется, в другие — нет")
        e.settings["server_hist"] = {}
        # VPN на время
        e.connect_for(30)
        check(e.connected and e.vpn_until > time.time() + 29 * 60 and e.state()["vpn_until"], "VPN на 30 минут")
        e.vpn_until = time.time() - 1
        e.tray_queue.clear()
        e._vpn_timer()
        wait_idle(e)
        check(not e.connected and e.vpn_until == 0 and e.tray_queue, "время вышло — выключен и сказано об этом")
        e.settings["smart_notices"] = False
        e.tray_queue.clear()
        e.tell("тест")
        check(not e.tray_queue, "умные уведомления выключаются")
        # трафик за день и месяц
        e._count_traffic(3000, 1000)
        tt = e.state()["traffic_totals"]
        check(tt["today"]["vpn"] == 3000 and tt["month"]["direct"] == 1000, f"трафик за день: {tt}")
    finally:
        if e:
            e.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


@case("Горячая клавиша: разбор сочетаний")
def t_hotkey():
    from pult import tray
    check(tray.parse_hotkey("Ctrl+Alt+V") == (tray.MOD_CONTROL | tray.MOD_ALT, ord("V")), "Ctrl+Alt+V")
    check(tray.parse_hotkey("ctrl + shift + f9") == (tray.MOD_CONTROL | tray.MOD_SHIFT, 0x78), "Ctrl+Shift+F9")
    for bad in ("V", "Ctrl+", "Ctrl+Alt+Пробел", "Foo+V", "Ctrl+F13", ""):
        check(tray.parse_hotkey(bad) is None, f"неверное сочетание отклоняется: {bad!r}")


@case("Проверка сайта, режим для игр, аккуратное автообновление")
def t_site_games_updates():
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    try:
        e = make_engine(tmp)
        e.startup()
        url = f"http://127.0.0.1:{WEB}/generate_204"
        r = e.check_site(url)
        check(r["results"]["direct"]["state"] == "ok" and "без VPN" in r["verdict"], f"проверка без подключения: {r}")
        try:
            e.check_site("not a site")
            check(False, "мусор вместо адреса должен давать понятную ошибку")
        except RuntimeError:
            pass
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        e.connect(e.best())
        r = e.check_site(url)
        check("Сайт отвечает" in r["verdict"] and not r["action"] and r["route"] == "auto", f"проверка при подключении: {r}")
        e.settings["game_mode"] = True
        ranked = tester.ranked(e.servers, key=tester.game_score)
        check(ranked and e.best().key == ranked[0].key, "режим для игр должен выбирать сервер по пингу")
        check(e.state()["backup"] is not None, "в состоянии нет запасного сервера для Автоперехода")
        e.settings.update(auto_update_hours=6, last_sub_update=0, geo_update_hours=0, core_update_hours=0)
        e._auto_update_check()
        deadline = time.time() + 15
        while time.time() < deadline and (e.is_busy() or not e.settings.get("last_sub_update")):
            time.sleep(0.1)
        check(e.settings.get("last_sub_update"), "автообновление серверов не сработало")
        check(e.connected, "автообновление не должно разрывать подключение")
    finally:
        try:
            e.shutdown()
        except Exception:
            pass
        shutil.rmtree(tmp, ignore_errors=True)


SAMPLE_BAT = """@echo off
chcp 65001 > nul
cd /d "%~dp0"
call service.bat status_zapret
set "BIN=%~dp0bin\\"
set "LISTS=%~dp0lists\\"
cd /d %BIN%

start "zapret: %~n0" /min "%BIN%winws.exe" --wf-tcp=80,443,%GameFilterTCP% --wf-udp=443,50000-50100,%GameFilterUDP% ^
--filter-udp=443 --hostlist="%LISTS%list-general.txt" --hostlist-exclude="%LISTS%list-exclude.txt" --dpi-desync=fake ^
--dpi-desync-fake-quic="%BIN%quic_initial_www_google_com.bin" --new ^
--filter-tcp=443 --hostlist="%LISTS%list-user.txt" --dpi-desync=multisplit --dpi-desync-split-pos=1
"""

FAKE_WINWS = """#!/usr/bin/env python3
import sys, time
open(sys.argv[0] + ".args", "w").write(" ".join(sys.argv[1:]))
while True:
    time.sleep(1)
"""

FAKE_CIADPI = """#!/usr/bin/env python3
import socket, sys
port = int(sys.argv[sys.argv.index("-p") + 1])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(8)
while True:
    c, _ = s.accept(); c.close()
"""


def _fake_dpi_install(e):
    """Имитация скачанных zapret и ByeDPI: три стратегии zapret и «ciadpi», который просто слушает порт."""
    zdir = e.dpi_paths.zapret_dir
    os.makedirs(os.path.join(zdir, "bin"), exist_ok=True)
    os.makedirs(os.path.join(zdir, "lists"), exist_ok=True)
    with open(os.path.join(zdir, "lists", "list-general.txt"), "w", encoding="utf-8") as f:
        f.write("youtube.com\n")
    with open(e.dpi_paths.winws, "w", encoding="utf-8") as f:
        f.write(FAKE_WINWS)
    os.chmod(e.dpi_paths.winws, 0o755)
    line = 'start "zapret: %~n0" /min "%BIN%winws.exe" --wf-tcp=443 --hostlist="%LISTS%list-general.txt" --mark={}\n'
    for name in ("general", "general (ALT)", "general (ALT2)"):
        with open(os.path.join(zdir, name + ".bat"), "w", encoding="utf-8") as f:
            f.write('set "BIN=%~dp0bin\\"\nset "LISTS=%~dp0lists\\"\n' + line.format(name.replace(" ", "_")))
    with open(os.path.join(zdir, "service.bat"), "w", encoding="utf-8") as f:
        f.write('start "" "%BIN%winws.exe" --must-not-be-used\n')
    with open(os.path.join(zdir, "version.txt"), "w", encoding="utf-8") as f:
        f.write("1.0")
    os.makedirs(e.dpi_paths.byedpi_dir, exist_ok=True)
    with open(e.dpi_paths.ciadpi, "w", encoding="utf-8") as f:
        f.write(FAKE_CIADPI)
    os.chmod(e.dpi_paths.ciadpi, 0o755)


@case("Zapret и ByeDPI: стратегии, подбор, маршрут, Автопереход и обновление")
def t_dpi():
    root = "C:\\zapret" if sys.platform == "win32" else "/opt/zapret"
    args = dpi.parse_strategy(SAMPLE_BAT, root)
    check(args and args[0] == "--wf-tcp=80,443,12" and args[1] == "--wf-udp=443,50000-50100,12",
          f"разбор .bat: подстановка GameFilter: {args[:2] if args else args}")
    check(os.path.join(root, "lists", "list-general.txt") in args[3] and "--new" in args and "^" not in args,
          f"разбор .bat: пути и переносы строк: {args}")
    check(args[-1] == "--dpi-desync-split-pos=1", "разбор .bat: последний параметр")
    if sys.platform == "win32":
        return  # на Windows настоящий zapret требует прав администратора — остальное проверяется на имитации в Linux
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    orig_check = engmod.dpi.check_targets
    orig_release, orig_dl_z, orig_dl_b = dpi.latest_release, dpi.download_zapret, dpi.download_byedpi
    works = {"zapret": {"general (ALT2)"}, "byedpi": {"--split 1+s --tlsrec 1+s"}}

    def fake_check(socks_port=None, targets=("youtube", "discord"), timeout=8.0, checks=None):
        if socks_port:
            with socket.create_connection(("127.0.0.1", socks_port), timeout=2):
                pass  # «ByeDPI» действительно слушает порт
            ok = " ".join(e.byedpi.args) in works["byedpi"] and e.byedpi.alive()
        else:
            ok = e.zapret.running_name in works["zapret"] and e.zapret.alive()
        return {t: {"ok": ok, "kbps": 900 if ok else 3, "detail": "" if ok else "очень медленно — похоже на замедление"}
                for t in targets}

    try:
        e = make_engine(tmp)
        e.dpi_supported = True
        _fake_dpi_install(e)
        engmod.dpi.check_targets = fake_check
        e.startup()
        names = [x["name"] for x in dpi.list_strategies(e.dpi_paths.zapret_dir)]
        check(names == ["general", "general (ALT)", "general (ALT2)"], f"список стратегий zapret: {names}")

        best = e.pick_zapret()
        check(best and best["name"] == "general (ALT2)", f"подбор zapret выбрал не ту стратегию: {best}")
        check(e.dpi_mode == "zapret" and e.zapret.alive(), "после подбора zapret должен работать")
        with open(e.dpi_paths.winws + ".args", encoding="utf-8") as f:
            check("--mark=general_(ALT2)" in f.read(), "winws запущен не с той стратегией")
        check(e.settings["dpi_networks"].get("203.0", {}).get("zapret") == "general (ALT2)",
              "стратегия не запомнилась для этой сети")

        best = e.pick_byedpi()
        check(best and best["args"] == "--split 1+s --tlsrec 1+s", f"подбор ByeDPI выбрал не то: {best}")
        check(e.dpi_mode == "zapret", "ByeDPI запасной: после подбора снова должен работать zapret")

        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        e.settings["mode"] = "smart"  # в режиме «всё через VPN» YouTube и так идёт через сервер
        e.connect(e.best())
        with open(e.paths.run_config, encoding="utf-8") as f:
            cfg = json.load(f)
        yt = [r for r in cfg["routing"]["rules"] if "domain:youtube.com" in r.get("domain", [])]
        check(yt and _ot(yt[0]) == "direct", "с zapret YouTube должен идти напрямую, а не через VPN")

        e.set_dpi({"dpi_custom": "https://www.example.org/page\nregexp:.*\nне сайт"})
        check(e.settings["dpi_custom"] == "example.org", f"свои сайты для обхода: {e.settings['dpi_custom']!r}")
        e.start_dpi()
        with open(os.path.join(e.dpi_paths.zapret_dir, "lists", "list-general.txt"), encoding="utf-8") as f:
            check("example.org" in f.read(), "свой сайт не попал в список zapret")

        # zapret перестал справляться → Автопереход: другая стратегия → ByeDPI → VPN
        works["zapret"] = set()
        e.settings["autopilot"] = True
        e._dpi_watch()
        e._dpi_watch()
        wait_idle(e)
        check(e.dpi_mode == "byedpi" and e.byedpi.alive(), f"Автопереход должен перевести на ByeDPI: {e.dpi_mode!r}")
        with open(e.paths.run_config, encoding="utf-8") as f:
            cfg = json.load(f)
        ob = [o for o in cfg["outbounds"] if o["tag"] == "byedpi"]
        yt = [r for r in cfg["routing"]["rules"] if "domain:youtube.com" in r.get("domain", [])]
        check(ob and ob[0]["settings"]["servers"][0]["port"] == e.byedpi.port and _ot(yt[0]) == "byedpi",
              "с ByeDPI ядро должно вести YouTube через его прокси")
        e.start_dpi(verify=True)
        check(e.dpi_mode == "byedpi" and not e.zapret.running_name,
              f"при включении с проверкой нерабочий zapret должен уступить ByeDPI: {e.dpi_mode!r}")
        works["byedpi"] = set()
        e._dpi_watch()
        e._dpi_watch()
        wait_idle(e)
        check(e.dpi_mode == "" and not e.byedpi.alive(), "когда ничего не помогает, YouTube должен пойти через VPN")
        check(any(p["key"] == "dpi" for p in e.problems_list()), "нет предупреждения, что обход перестал работать")
        e.settings["mode"] = "vpn"
        rules = routing.build_rules("vpn", "", "", "", dpi={"mode": "direct", "domains": ["youtube.com"]})
        check(not any("domain:youtube.com" in r.get("domain", []) and _ot(r) == "direct" for r in rules),
              "в «Глобальной» маршрутизации обход не должен уводить YouTube мимо VPN")

        # аккуратное обновление: качаем только новую версию, работающий zapret перезапускается
        works["zapret"] = {"general (ALT2)"}
        e.start_dpi()
        check(e.dpi_mode == "zapret", "zapret не включился снова")
        calls = []
        dpi.latest_release = lambda repo, proxy=None: {"tag_name": "1.0" if repo == dpi.ZAPRET_REPO else "v0.1"}

        def fake_dl(which):
            def dl(paths, proxy=None, rel=None):
                calls.append(which)
                check(which != "zapret" or not e.zapret.alive(), "zapret нужно остановить перед заменой файлов")
                return "x"
            return dl
        dpi.download_zapret, dpi.download_byedpi = fake_dl("zapret"), fake_dl("byedpi")
        with open(os.path.join(e.dpi_paths.byedpi_dir, "version.txt"), "w", encoding="utf-8") as f:
            f.write("0.0")
        e.update_dpi()
        check(calls == ["byedpi"], f"скачивать нужно только то, что обновилось: {calls}")
        dpi.latest_release = lambda repo, proxy=None: {"tag_name": "v2.0"}
        e.update_dpi()
        check(calls[-2:] == ["zapret", "byedpi"] and e.dpi_mode == "zapret" and e.zapret.alive(),
              f"после обновления zapret должен снова работать: {calls}, {e.dpi_mode!r}")
        st = e.state()["dpi"]
        check(st["zapret"]["strategy"] == "general (ALT2)" and st["zapret"]["running"] and st["byedpi"]["results"],
              "в состоянии для интерфейса нет данных обхода")
        # полный контроль: только ByeDPI, только zapret, выключено
        works["byedpi"] = {"--split 1+s --tlsrec 1+s"}
        e.set_dpi({"zapret_enabled": False, "byedpi_role": "main"})
        e.start_dpi(verify=True)
        check(e.dpi_mode == "byedpi" and not e.zapret.running_name, f"«Только ByeDPI»: {e.dpi_mode!r}")
        e.set_dpi({"zapret_enabled": True, "byedpi_role": "off"})
        e.start_dpi(verify=True)
        check(e.dpi_mode == "zapret" and not e.byedpi.alive(), f"«Только Zapret»: {e.dpi_mode!r}")
        e.set_dpi({"zapret_enabled": False, "byedpi_role": "off"})
        e.start_dpi()
        check(e.dpi_mode == "" and not e.zapret.running_name and not e.byedpi.alive(), "«Выключено»: обход должен остановиться")
    finally:
        engmod.dpi.check_targets = orig_check
        dpi.latest_release, dpi.download_zapret, dpi.download_byedpi = orig_release, orig_dl_z, orig_dl_b
        try:
            e.shutdown()
        except Exception:
            pass
        shutil.rmtree(tmp, ignore_errors=True)


FAKE_TOOL = """#!/usr/bin/env python3
import sys, time
open(sys.argv[0] + ".args", "w").write(" ".join(sys.argv[1:]))
while True:
    time.sleep(1)
"""

FAKE_TOOL_FAIL = """#!/usr/bin/env python3
import sys
print("FATAL: start tun: access denied")
sys.exit(1)
"""


def _write_tool(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(path, 0o755)


@case("Режим TUN: три движка, Авто, откат на прокси, защита помощника, DNS и реклама")
def t_tun():
    if sys.platform == "win32":
        return  # настоящий TUN требует прав администратора — проверяется на имитации в Linux
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    orig = (tun.ElevatedXray.start, tun.ElevatedXray.stop, tun.ElevatedXray.alive, tun.ipv6_available)
    fail_xray = {"on": False}

    def el_start(self, config, config_path, wait_for, timeout=15.0, exe=None):
        if fail_xray["on"]:
            raise xray.XrayError("Failed to create TUN device")
        ports_only = dict(config, inbounds=[i for i in config["inbounds"] if "port" in i])
        xray.XrayProcess.start(self, ports_only, config_path + ".ports", wait_for, timeout, exe)  # имитация портов
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f)
        r = self.helper.start(self.NAME, self.kind_for_exe(exe or self.paths.xray), ["run", "-c", config_path])
        check(r.get("ok"), f"помощник не запустил ядро: {r}")
        self.running = True

    def el_stop(self):
        xray.XrayProcess.stop(self)
        orig[1](self)

    def run_cfg():
        with open(e.paths.run_config, encoding="utf-8") as f:
            return json.load(f)

    try:
        tun.ElevatedXray.start, tun.ElevatedXray.stop = el_start, el_stop
        tun.ElevatedXray.alive = lambda self: bool(getattr(self, "_fakes", []))
        tun.ipv6_available = lambda: False
        e = make_engine(tmp)
        e.tun_supported = True
        _write_tool(e.paths.xray, FAKE_TOOL)
        _write_tool(e.tun_paths.singbox, FAKE_TOOL)
        _write_tool(e.tun_paths.tun2proxy, FAKE_TOOL)
        e.startup()
        e.xray_ver = "26.10.31"
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        best = e.best() or e.servers[0]
        e.settings.update(tun_enabled=True, tun_engine="auto", leak_protection=True)

        # Авто: первым пробуется встроенный в Xray TUN
        e.connect(best)
        cfg = run_cfg()
        tin = [i for i in cfg["inbounds"] if i["tag"] == "tun-in"]
        check(e.tun_active == "xray" and e.proc is e.xray_admin and tin, f"Авто должен включить Xray TUN: {e.tun_active!r}")
        st = tin[0]["settings"]
        check(st["autoSystemRoutingTable"] == ["0.0.0.0/0"] and st["autoOutboundsInterface"] == "auto"
              and st.get("autoSystemWfpBlockLeak"), f"настройки адаптера Xray TUN: {st}")
        check(any(r.get("outboundTag") == "dns-out" and r.get("port") == 53 for r in cfg["routing"]["rules"])
              and "dns" in cfg, "DNS из адаптера должен уходить во встроенный DNS ядра")
        check(e.admin.status("xray").get("running"), "ядро должно работать через помощника")
        check(e.settings["tun_engine_auto"] == "xray", "Авто должен запомнить рабочий движок")
        check(e._direct_http() == e.ports["direct_http"] and e._direct_socks() == e.ports["direct"],
              "проверки «без VPN» в режиме TUN должны идти через служебный вход")
        check(e.byedpi.bind_ip == e._phys_ip, "ByeDPI в режиме Xray TUN нужно привязать к основному адаптеру")

        e.settings["leak_protection"] = False
        e.reconnect()
        check("autoSystemWfpBlockLeak" not in [i for i in run_cfg()["inbounds"] if i["tag"] == "tun-in"][0]["settings"],
              "без защиты от утечек фильтры Windows не нужны")

        # Sing-box: ядро работает обычным процессом, адаптер — у sing-box
        e.settings.update(tun_engine="singbox", leak_protection=True, dns_encrypted=True)
        e.reconnect()
        cfg = run_cfg()
        check(e.tun_active == "singbox" and e.proc is e.xray_normal and not e.admin.status("xray").get("running"),
              f"Sing-box: {e.tun_active!r}")
        check(not [i for i in cfg["inbounds"] if i["tag"] == "tun-in"], "с sing-box в ядре не должно быть адаптера")
        with open(e.tun_paths.singbox_config, encoding="utf-8") as f:
            sb = json.load(f)
        t = sb["inbounds"][0]
        check(t["type"] == "tun" and t["auto_route"] and t["strict_route"] and "stack" not in t, f"адаптер sing-box: {t}")
        check(sb["outbounds"][0]["server_port"] == e.ports["socks"], "sing-box должен вести всё в Xray")
        check(any("xray.exe" in r.get("process_name", []) for r in sb["route"]["rules"]),
              "трафик самого Xray должен идти мимо адаптера, иначе петля")
        check(sb["dns"]["servers"][0]["type"] == "https" and cfg["dns"]["servers"][1].startswith("https://"),
              "шифрование DNS должно включаться и в sing-box, и в ядре")
        check(e.admin.status("tun").get("running") and e.byedpi.bind_ip == "", "sing-box должен работать через помощника")

        # tun2proxy
        e.settings["tun_engine"] = "tun2proxy"
        e.reconnect()
        with open(e.tun_paths.tun2proxy + ".args", encoding="utf-8") as f:
            args = f.read()
        check(e.tun_active == "tun2proxy" and f"socks5://127.0.0.1:{e.ports['socks']}" in args and "--setup" in args,
              f"tun2proxy: {e.tun_active!r} {args}")

        # движок не запустился → программа работает через прокси и показывает «!»
        _write_tool(e.tun_paths.singbox, FAKE_TOOL_FAIL)
        e.settings["tun_engine"] = "singbox"
        e.reconnect()
        check(e.connected and e.tun_active == "" and any(p["key"] == "tun" for p in e.problems_list()),
              f"при сбое TUN нужно подключиться без него и предупредить: {e.tun_active!r}")
        check("access denied" in e.tun_error, f"причина сбоя TUN: {e.tun_error!r}")

        # Авто: Xray TUN и sing-box не работают → tun2proxy
        fail_xray["on"] = True
        e.settings.update(tun_engine="auto", tun_engine_auto="")
        e.reconnect()
        check(e.tun_active == "tun2proxy" and e.settings["tun_engine_auto"] == "tun2proxy"
              and not any(p["key"] == "tun" for p in e.problems_list()), f"Авто должен найти рабочий движок: {e.tun_active!r}")
        fail_xray["on"] = False

        st = e.state()["tun"]
        check(st["enabled"] and st["active"] == "tun2proxy", "в состоянии для интерфейса нет режима TUN")

        e.disconnect()
        check(not e.tun_active and not e.admin.status("tun").get("running"), "при отключении TUN должен выключаться")

        # помощник с правами администратора не запускает лишнего
        bad = [("xray", ["run", "-c", "/etc/passwd"]), ("xray", ["version"]), ("winws", ["--debug=@/tmp/x"]),
               ("tun2proxy", ["--proxy", "socks5://127.0.0.1:1", "--admin-command", "calc"]),
               ("tun2proxy", ["--proxy", "socks5://10.0.0.1:1080"])]
        for kind, a in bad:
            r = e.admin.call({"cmd": "start", "name": "x", "kind": kind, "exe": e.admin.allowed[kind], "args": a,
                              "cwd": tmp})
            check(not r.get("ok"), f"помощник должен отказать: {kind} {a}")
        evil = os.path.join(e.paths.data_dir, "evil.json")
        with open(evil, "w", encoding="utf-8") as f:
            json.dump({"log": {"access": "/etc/cron.d/x"}}, f)
        r = e.admin.call({"cmd": "start", "name": "x", "kind": "xray", "exe": e.paths.xray, "args": ["run", "-c", evil],
                          "cwd": tmp})
        check(not r.get("ok"), "помощник не должен давать ядру писать журнал вне папки программы")
        r = e.admin.call({"cmd": "start", "name": "x", "kind": "xray", "exe": "/bin/sh", "args": [], "cwd": tmp})
        check(not r.get("ok"), "помощник должен запускать только известные файлы")

        # реклама: правило есть только со списками сайтов и только при включённой галочке
        rules = routing.build_rules("smart", "", "", "", use_geo=True, block_ads=True)
        check(any("geosite:category-ads-all" in r.get("domain", []) and _ot(r) == "adblock" for r in rules),
              "блокировка рекламы")
        check(not any("geosite:category-ads-all" in r.get("domain", []) for r in
                      routing.build_rules("smart", "", "", "", use_geo=False, block_ads=True)),
              "без списков сайтов правило рекламы ломало бы ядро")
    finally:
        tun.ElevatedXray.start, tun.ElevatedXray.stop, tun.ElevatedXray.alive, tun.ipv6_available = orig
        try:
            e.shutdown()
        except Exception:
            pass
        shutil.rmtree(tmp, ignore_errors=True)


@case("Маскировка: сервер, который режет провайдер, оживает и запоминается")
def t_mask():
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    try:
        e = make_engine(tmp)
        e.startup()
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        e.add_servers("vless://33333333-3333-3333-3333-333333333333@dpiblocked.example:443?security=reality&pbk=K"
                      "&sni=a.com&type=tcp#Blocked")
        blocked = next(s for s in e.servers if s.endpoint.startswith("dpiblocked"))
        e.settings["mask_auto"] = False
        e.test_all()
        check(not blocked.result.get("ok"), "без маскировки такой сервер не должен работать")
        e.settings["mask_auto"] = True
        e.test_all()
        check(blocked.result.get("ok") and blocked.result.get("mask"), f"маскировка должна оживить сервер: {blocked.result}")
        fast = next(s for s in e.servers if s.endpoint.startswith("fast"))
        check(not fast.result.get("mask"), "рабочему серверу маскировка не нужна")
        e.connect(blocked)
        with open(e.paths.run_config, encoding="utf-8") as f:
            cfg = json.load(f)
        obs = {o["tag"]: o for o in cfg["outbounds"]}
        check(obs["proxy"]["streamSettings"]["sockopt"]["dialerProxy"] == "mask@proxy"
              and obs["mask@proxy"]["settings"]["fragment"]["packets"] == "tlshello", "маскировка в настройках ядра")
        check(e._proxy_tags == ["proxy", "mask@proxy"], f"теги для горячей замены: {e._proxy_tags}")
        check(e._hot_swap(fast) and e._proxy_tags == ["proxy"], "горячая замена с маскированного сервера")
        new = xray.mask_outbounds(xray.tagged_outbounds(blocked, "proxy"), "26.10.31")
        check(len(new) == 1 and new[0]["streamSettings"]["finalmask"]["tcp"][0]["type"] == "fragment",
              "в новых версиях ядра маскировка — через finalmask")
        check(any(x.get("mask") for x in e.state()["servers"] if x["key"] == blocked.key), "интерфейс должен видеть метку")
    finally:
        try:
            e.shutdown()
        except Exception:
            pass
        shutil.rmtree(tmp, ignore_errors=True)


@case("Мультисервер: сервис, закрытый на основном сервере, идёт через другой")
def t_multi():
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    old_services, old_check = services.SERVICES, services.check_service
    try:
        services.SERVICES = [
            {"name": "ChatGPT", "urls": ["https://api.openai.com/v1/models"], "region": True,
             "domains": ["openai.com", "chatgpt.com"]},
            {"name": "Google", "urls": ["https://www.google.com/generate_204"], "domains": ["google.com"]},
        ]
        # ChatGPT открывается только через «медленный» сервер (например, он в другой стране)
        engmod.services.check_service = lambda svc, port: {"state": "ok" if BEHAVIOR.get(port) == "slow" else "region"}
        e = make_engine(tmp)
        e.startup()
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        fast = next(s for s in e.servers if s.endpoint.startswith("fast"))
        slow = next(s for s in e.servers if s.endpoint.startswith("slow"))
        e.connect(fast)
        bad = {"ChatGPT": {"vpn": {"state": "region"}}, "Google": {"vpn": {"state": "ok"}}}
        m = e.multi_check(bad)
        check(m == {"ChatGPT": slow.key}, f"ChatGPT должен пойти через другой сервер: {m}")
        with open(e.paths.run_config, encoding="utf-8") as f:
            cfg = json.load(f)
        ob = [o for o in cfg["outbounds"] if o["tag"] == "multi0"]
        rule = [r for r in cfg["routing"]["rules"] if "domain:openai.com" in r.get("domain", [])]
        check(ob and ob[0]["settings"]["vnext"][0]["address"].startswith("slow") and rule
              and _ot(rule[0]) == "multi0", "в ядре должен появиться второй сервер для ChatGPT")
        st = e.state()["multi"]
        check(st["map"] and st["map"][0]["service"] == "ChatGPT", "интерфейс должен видеть, что куда идёт")
        check(e._proxy_tags == ["proxy"], "дополнительный сервер не должен мешать горячей замене")
        # ChatGPT заработал на основном — отдельный сервер больше не нужен
        m = e.multi_check({"ChatGPT": {"vpn": {"state": "ok"}}})
        with open(e.paths.run_config, encoding="utf-8") as f:
            cfg = json.load(f)
        check(m == {} and not [o for o in cfg["outbounds"] if o["tag"].startswith("multi")], "лишний сервер нужно убрать")
        e.settings["multi_enabled"] = False
        check(e.multi_check(bad) == {}, "выключенный Мультисервер ничего не делает")
    finally:
        services.SERVICES, engmod.services.check_service = old_services, old_check
        try:
            e.shutdown()
        except Exception:
            pass
        shutil.rmtree(tmp, ignore_errors=True)


@case("Свои маршруты: сервис или сайт → другой сервер, свой прокси, обход замедления")
def t_routes():
    from pult import proxies
    good = {
        "socks5://u:p%40ss@1.2.3.4:1080": ("socks", False, "1.2.3.4", 1080, "u", "p@ss", True),
        "http://user:pw@Proxy.Example.com:8080/": ("http", False, "proxy.example.com", 8080, "user", "pw", True),
        "https://u:p@px.example:443": ("http", True, "px.example", 443, "u", "p", True),
        "1.2.3.4:5000:login:pa:ss": ("socks", False, "1.2.3.4", 5000, "login", "pa:ss", False),
        "login:pass:5.6.7.8:3128": ("socks", False, "5.6.7.8", 3128, "login", "pass", False),
        "login:pass@[2001:db8::1]:1080": ("socks", False, "2001:db8::1", 1080, "login", "pass", False),
        "9.9.9.9:1080": ("socks", False, "9.9.9.9", 1080, "", "", False),
        "socks5://1.2.3.4:1080:u:p": ("socks", False, "1.2.3.4", 1080, "u", "p", True),
    }
    for raw, want in good.items():
        p = proxies.parse(raw)
        got = (p["type"], p["tls"], p["host"], p["port"], p["user"], p["pass"], p["type_known"])
        check(got == want, f"прокси {raw}: {got}")
    check(proxies.parse("9.9.9.9:8080", "http")["type"] == "http", "тип из списка для адреса без схемы")
    for bad in ("", "vless://x@h.example:443", "ftp://h.example:21", "1.2.3.4", "h o s t:1", "1.2.3.4:99999",
                "just-text", "a:b:c"):
        try:
            proxies.parse(bad)
            check(False, f"прокси «{bad}» должен быть отклонён")
        except proxies.ProxyError:
            pass
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    old_exit, old_check = engmod.services.exit_info, engmod.services.check_service
    try:
        engmod.services.check_service = lambda svc, port: {"state": "ok"}
        e = make_engine(tmp)
        e.startup()
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        fast = next(s for s in e.servers if s.endpoint.startswith("fast"))
        slow = next(s for s in e.servers if s.endpoint.startswith("slow"))
        e.connect(fast)

        def run_cfg():
            with open(e.paths.run_config, encoding="utf-8") as f:
                return json.load(f)

        def rule_for(cfg, domain):
            return next((_ot(r) for r in cfg["routing"]["rules"] if domain in r.get("domain", [])), "")

        # сервис → другой сервер
        e.set_service_route("TikTok", f"server:{slow.key}")
        e.apply_routes()
        cfg = run_cfg()
        pin = [o for o in cfg["outbounds"] if o["tag"] == "pin0"]
        check(pin and pin[0]["settings"]["vnext"][0]["address"].startswith("slow"), "нет outbound выбранного сервера")
        check(rule_for(cfg, "domain:tiktok.com") == "pin0", "TikTok должен идти через выбранный сервер")
        check(e._proxy_tags == ["proxy"], "свой сервер не должен мешать горячей замене")
        svc = next(x for x in e.state()["services"] if x["name"] == "TikTok")
        check(svc["choice"] == f"server:{slow.key}" and not svc["warn"], f"выбор в интерфейсе: {svc['choice']}")
        check(not e._hot_swap(slow), "к серверу привязан маршрут — нужна полная пересборка, а не горячая замена")
        # выбран основной сервер — отдельный outbound не нужен
        e.set_service_route("TikTok", f"server:{fast.key}")
        e.apply_routes()
        cfg = run_cfg()
        check(rule_for(cfg, "domain:tiktok.com") == "proxy" and not [o for o in cfg["outbounds"] if o["tag"] == "pin0"],
              "сервер совпал с основным — через основной")
        # свой прокси, по умолчанию через VPN
        p = e.add_proxy("socks5://user:secret-pass@198.51.100.7:1080", "Резидент")
        wait_idle(e)
        check(p["chain"] and "pass" not in json.dumps(p), "в интерфейс не должен уходить пароль")
        p = e.check_proxy(p["id"])
        check(p["check"].get("ok") and p["check"].get("loc") == "NL" and p["type"] == "socks", f"проверка прокси: {p}")
        e.set_service_route("TikTok", f"custom:{p['id']}")
        e.apply_routes()
        cfg = run_cfg()
        ob = next((o for o in cfg["outbounds"] if o["tag"] == "custom0"), None)
        check(ob and ob["protocol"] == "socks" and ob["settings"]["servers"][0]["address"] == "198.51.100.7"
              and ob["settings"]["servers"][0]["users"][0]["pass"] == "secret-pass", "outbound своего прокси")
        check(ob["streamSettings"]["sockopt"]["dialerProxy"] == "proxy", "прокси по умолчанию — через основной VPN")
        check(rule_for(cfg, "domain:tiktok.com") == "block"
              and next(r for r in cfg["routing"]["rules"] if "domain:tiktok.com" in r.get("domain", []))
              .get("network") == "udp", "QUIC через свой прокси блокируется — приложения переходят на TCP")
        tcp = [_ot(r) for r in cfg["routing"]["rules"]
               if "domain:tiktokcdn.com" in r.get("domain", []) and not r.get("network")]
        check(tcp == ["custom0"], "TikTok должен идти через свой прокси")
        check(e.update_proxy(p["id"], chain=False), "смена «через VPN» у используемого прокси требует переподключения")
        e.reconnect()
        ob = next(o for o in run_cfg()["outbounds"] if o["tag"] == "custom0")
        check("dialerProxy" not in json.dumps(ob), "без «через VPN» прокси подключается напрямую")
        # сайты: адрес из формы берётся как есть, из журнала — основной домен
        entry, dpi_changed = e.route_site("https://www.music.example.org/path", "dpi", main_domain=False)
        check(entry == "music.example.org" and dpi_changed, f"адрес сайта: {entry}")
        check("music.example.org" in e.dpi_domains(), "сайт с обходом должен попасть в список обхода")
        check(e.route_site("cdn.ads.example.net", "block")[0] == "example.net", "сайт из журнала → основной домен")
        check(e.settings["routes"]["site:example.net"] == {"via": "block"}, "блок сайта — свой маршрут")
        e.settings["proxy_list"] += "\nexample.net\nimg.example.net\nexample.com"
        e.route_site("example.net", f"server:{slow.key}")
        check(e.settings["routes"]["site:example.net"]["via"] == "server" and "example.net" not in e.settings["proxy_list"]
              and "example.com" in e.settings["proxy_list"], "новый выбор заменяет старый для сайта и его поддоменов")
        # правило поддомена важнее правила всего сайта, в каком порядке их ни добавляй
        e.route_site("shop.example.info", "direct", main_domain=False)
        e.route_site("example.info", "block", main_domain=False)
        check("site:shop.example.info" not in e.settings["routes"], "правило сайта убирает старые правила поддоменов")
        e.route_site("pay.example.info", "proxy", main_domain=False)
        e.reconnect()
        cfg = run_cfg()
        check(rule_for(cfg, "domain:music.example.org") == "direct", "обход выключен — сайт идёт напрямую")
        check(rule_for(cfg, "domain:example.net") == "pin0", "сайт через выбранный сервер")
        rules = [r.get("outboundTag") for r in cfg["routing"]["rules"] if r.get("domain")]
        check(rules.index("pin0") < rules.index("custom0"), "правила сайтов должны стоять раньше правил сервисов")
        doms = [d for r in cfg["routing"]["rules"] for d in r.get("domain", [])]
        check(doms.index("domain:pay.example.info") < doms.index("domain:example.info") < doms.index("domain:example.com"),
              "поддомен раньше сайта, свои сайты раньше списков")
        check(rule_for(cfg, "domain:pay.example.info") == "proxy" and rule_for(cfg, "domain:example.info") == "block",
              "маршруты сайта и поддомена")
        rs = e.routes_state()
        dpi_row = next(x for x in rs["sites"] if x["site"] == "music.example.org")
        check(dpi_row["value"] == "dpi" and dpi_row["warn"], "интерфейс должен предупредить, что обход выключен")
        e._add_to_list("proxy_list", ["music.example.org"])  # «Проверить сайт» и подобное — последнее слово за списком
        check("site:music.example.org" not in e.settings["routes"], "список заменяет свой маршрут сайта")
        check(e.reset_site("example.net") and "site:example.net" not in e.settings["routes"], "сброс правил сайта")
        for bad in ("bogus", "server:nope", "custom:nope"):
            try:
                e.set_service_route("TikTok", bad)
                check(False, f"неверный выбор «{bad}» должен быть отклонён")
            except RuntimeError:
                pass
        # автоматика не трогает сервисы с ручным выбором
        e.settings["multi_enabled"] = True
        m = e.multi_check({"TikTok": {"vpn": {"state": "region"}}})
        check("TikTok" not in m, "Мультисервер не должен перебивать ручной выбор")
        check(not e.autofix({"TikTok": {"current": {"state": "blocked"}, "vpn": {"state": "ok"}}}),
              "автоисправление не должно трогать ручной выбор")
        # секреты: пароль прокси не попадает в журнал, отчёт, состояние и файл переноса настроек
        blob = "\n".join(e.logs) + e.problem_report() + json.dumps(e.state(), ensure_ascii=False) + \
            json.dumps(e.export_settings(True, True), ensure_ascii=False)
        check("secret-pass" not in blob and "198.51.100.7" not in "\n".join(e.logs), "пароль или адрес прокси утёк")
        # удаление прокси возвращает сервисы к «как по умолчанию»
        check(e.remove_proxy(p["id"]) and "svc:TikTok" not in e.settings["routes"], "маршрут удалённого прокси")
        # тип не указан и SOCKS5 не подошёл — программа пробует HTTP и запоминает
        def exit_http_only(port):
            with open(e.paths.test_config, encoding="utf-8") as f:
                ob = json.load(f)["outbounds"][0]
            return {"ip": "203.0.113.9", "loc": "US", "error": ""} if ob["protocol"] == "http" else \
                {"ip": "", "loc": "", "error": "нет ответа"}
        engmod.services.exit_info = exit_http_only
        p2 = e.add_proxy("203.0.113.9:8080:u:p")
        wait_idle(e)
        p2 = e.check_proxy(p2["id"])
        check(p2["type"] == "http" and p2["check"]["ok"], f"тип прокси должен определиться сам: {p2}")
        try:
            e.add_proxy("http://u:p@203.0.113.9:8080")
            check(False, "повтор прокси должен быть отклонён")
        except RuntimeError:
            pass
    finally:
        engmod.services.exit_info, engmod.services.check_service = old_exit, old_check
        try:
            e.shutdown()
        except Exception:
            pass
        shutil.rmtree(tmp, ignore_errors=True)


@case("Проверка программы: реклама, свои прокси и маршруты, отчёт без ссылок, ключей, адресов и паролей")
def t_diagnostics():
    from pult import adblock, diagnostics
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    old_url, old_svc = adblock.main_url, engmod.services.check_service
    try:
        adblock.main_url = lambda list_id, level="pro": ["http://127.0.0.1:%d/ads/%s" % (WEB, adblock.cache_name(list_id, level)[:-4])]
        engmod.services.check_service = lambda svc, port: {"state": "ok"}
        e = make_engine(tmp)
        e.startup()
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub?token=SECRET-TOKEN-42")
        wait_idle(e)
        e.set_ads(enabled=True)
        e.update_adblock(apply=False)
        p = e.add_proxy("socks5://alice:Very-Secret-Pw@198.51.100.77:1080", "Резидент")
        wait_idle(e)
        e.set_service_route("TikTok", f"custom:{p['id']}")
        e.route_site("example.info", "direct", main_domain=False)
        e.add_servers("# Дом\n" + AWG_CONF)  # AmneziaWG и TUIC: проверка не падает, ключи не попадают в отчёт
        e.add_servers("tuic://74444444-4444-4444-8444-444444444444:tuic-pass-9@tuic.example:443?sni=t.example#Tuic")
        wait_idle(e)
        e.settings.update(lan_user="lanuser1", lan_pass="lan-pass-77")
        fast = next(x for x in e.servers if x.endpoint.startswith("fast"))
        e.connect(fast)
        rep = diagnostics.run(e, include_selftest=False)
        text = rep["text"]
        titles = " | ".join(i["title"] for i in rep["items"])
        check("Списки рекламы:" in text and "Ядро принимает список рекламы" in text, "проверена блокировка рекламы:\n" + titles)
        check("Свой прокси «Резидент»: работает, страна NL (используется в маршрутах)" in text, "проверен свой прокси:\n" + titles)
        check("Свои маршруты: 2, все в порядке" in text, "проверены свои маршруты:\n" + titles)
        check("Настройки: mode=" in text and "routes=2" in text and "own_proxies=1" in text, "в отчёте сводка настроек")
        check("Состояние: подключено" in text, "в отчёте состояние")
        for leak in ("SECRET-TOKEN-42", "fast.example", "slow.example", "11111111-1111", "198.51.100.77", "alice",
                     "Very-Secret-Pw", "lanuser1", "lan-pass-77", "127.0.0.1", os.path.expanduser("~"),
                     "cHJpdmF0ZWtleX", "awg.example", "awg://", "tuic.example", "74444444", "tuic-pass-9"):
            check(leak not in text, f"в отчёт попало: {leak}")
            check(leak not in json.dumps(rep["items"], ensure_ascii=False), f"в пункты проверки попало: {leak}")
        check(rep.get("file", "").startswith("vedomyj-check-") and os.path.isfile(rep["path"]), "отчёт сохранён в файл")
        with open(rep["path"], encoding="utf-8") as f:
            check(f.read() == text, "в файле тот же отчёт")
        check(e.settings["proxies"][0].get("check", {}).get("ok") is None, "проверка не меняет сохранённые данные прокси")
        # старые отчёты не копятся
        for i in range(12):
            with open(os.path.join(tmp, "data", "reports", f"vedomyj-check-20200101-0000{i:02d}.txt"), "w") as f:
                f.write("x")
        diagnostics.run(e, include_selftest=False)
        check(len(os.listdir(os.path.join(tmp, "data", "reports"))) == 10, "хранятся только последние 10 отчётов")
        check(diagnostics.scrub("ip 10.1.2.3 и [2001:db8::1:2] vmess://abc 1b2c3d4e-0000-4000-8000-000000000001 в 20:10:23", set())
              == "ip <адрес> и <адрес> <ссылка> <ключ> в 20:10:23", "очистка адресов, ссылок и ключей")
        e.disconnect()
        wait_idle(e)
    finally:
        adblock.main_url, engmod.services.check_service = old_url, old_svc
        if e:
            e.shutdown()


@case("Блокировка рекламы: списки, исключения, файл для ядра, работа без VPN, пауза и журнал")
def t_adblock():
    from pult import adblock
    # разбор списков: домены, hosts, *.домен, правила ||домен^ без условий
    got = adblock.parse("# c\nexample-ads.com\n0.0.0.0 hosts.example\n*.wild.example\nbad domain\n||xy.example^\n", "domains")
    check(got == {"example-ads.com", "hosts.example", "wild.example", "xy.example"}, f"разбор списка: {got}")
    ru = adblock.parse(ADS_LISTS["ru"], "adblock")
    check("an.yandex.ru" in ru and "yandex.ru" not in ru and "site.example" not in ru and len(ru) == 61,
          "из правил AdGuard берутся только адреса целиком, без $third-party и путей")
    check(adblock.parse_user("https://Shop.Example.com/x\n||ads.site.ru^\n# комментарий\n*.cdn.example") ==
          {"shop.example.com", "ads.site.ru", "cdn.example"}, "свои сайты из поля ввода")
    # исключения: сам сайт, его поддомены и «родитель» не блокируются
    doms = {"example.com", "ads.example.com", "cdn.allowed.com", "allowed.com", "other.net"}
    check(adblock.apply_allow(doms, {"cdn.allowed.com", "example.com"}) == {"other.net"}, "исключения")
    check(adblock.minimize({"a.com", "x.a.com", "b.org"}) == ["a.com", "b.org"], "поддомены не дублируются")
    data = adblock.encode_geosite("ads", ["a.com", "b.org"])
    check(adblock.decode_geosite(data) == {"ADS": ["a.com", "b.org"]}, "файл для ядра читается обратно")

    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    old_url = adblock.main_url
    try:
        adblock.main_url = lambda list_id, level="pro": ["http://127.0.0.1:%d/ads/broken" % WEB,
                                                         "http://127.0.0.1:%d/ads/%s" % (WEB, adblock.cache_name(list_id, level)[:-4])]
        e = make_engine(tmp)
        e.startup()
        need_download, need_apply = e.set_ads(enabled=True)
        check(need_download and need_apply, "первое включение скачивает списки")
        info = e.update_adblock(apply=False)
        check(info["total"] > 200 and info["lists"]["main"] == 68 and not info["missing"], f"сборка: {info}")
        with open(e._ads_dat, "rb") as f:
            dat = adblock.decode_geosite(f.read())["ADS"]
        check("doubleclick.net" in dat and "ad.doubleclick.net" not in dat and "popads.net" in dat
              and "ru5.adnet.example" in dat, "в файле для ядра все списки, без лишних поддоменов")
        lk = e.ads_lookup("https://sub.doubleclick.net/path")
        check(lk["blocked"] and {"id": "main", "match": "doubleclick.net"} in lk["lists"], f"«Проверить сайт»: {lk}")
        check(not e.ads_lookup("example.com")["blocked"], "обычный сайт не блокируется")
        # встроенная защита: сами большие сайты и «неприкасаемые» (картинки, мессенджеры, банки) не блокируются
        check("yandex.ru" not in dat and "www.youtube.com" not in dat and "i.imgur.com" not in dat
              and "an.yandex.ru" in dat and "manga-site.example" in dat, "встроенная защита сайтов")
        ly = e.ads_lookup("yandex.ru")
        check(ly["protected"] and not ly["blocked"] and ly["lists"], f"«Проверить сайт»: защищённый сайт: {ly}")
        check(e.ads_lookup("an.yandex.ru")["blocked"], "рекламный поддомен защищённого сайта блокируется")
        check(adblock.site_name("www.manga-site.example") == "manga-site.example" and not adblock.site_name("cdn.x.example")
              and adblock.site_name("bbc.co.uk") == "bbc.co.uk", "адрес самого сайта")
        check(adblock.looks_like_ads("www.google-analytics.com") and adblock.looks_like_ads("popads.net")
              and not adblock.looks_like_ads("trackmania.com") and not adblock.looks_like_ads("statista.com"),
              "рекламные адреса узнаются по названию")
        # VPN выключен — реклама блокируется без него: ядро без сервера, всё остальное напрямую
        wait_idle(e)
        e.apply_ads()
        check(e.filter_on and not e.connected, "блокировка рекламы без VPN")
        with open(e.paths.run_config, encoding="utf-8") as f:
            cfg = json.load(f)
        proxy = next(o for o in cfg["outbounds"] if o["tag"] == "proxy")
        check(proxy["protocol"] == "freedom", "без VPN «через VPN» тоже напрямую")
        check(any(adblock.RULE in r.get("domain", []) and _ot(r) == "adblock" for r in cfg["routing"]["rules"]),
              "правило своих списков рекламы")
        check(e.state()["filter_on"] and not e.state()["connected"], "интерфейс: VPN выключен, реклама блокируется")
        # ядро не приняло файл списков — фильтр всё равно работает на запасном списке
        orig_start = engmod.XrayProcess.start

        def picky_start(self, config, *a, **kw):
            if adblock.RULE in json.dumps(config):
                raise engmod.XrayError("failed to load ext:adblock.dat: bad file")
            return orig_start(self, config, *a, **kw)
        engmod.XrayProcess.start = picky_start
        try:
            e.start_filter()
        finally:
            engmod.XrayProcess.start = orig_start
        with open(e.paths.run_config, encoding="utf-8") as f:
            text = f.read()
        check(e.filter_on and adblock.RULE not in text and not os.path.isfile(e._ads_dat),
              "файл рекламы не подошёл ядру — запасной список")
        e.update_adblock(apply=True)
        with open(e.paths.run_config, encoding="utf-8") as f:
            check(adblock.RULE in f.read(), "после пересборки снова свои списки")
        # подключение VPN заменяет фильтр, отключение возвращает его
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        fast = next(x for x in e.servers if x.endpoint.startswith("fast"))
        e.connect(fast)
        check(e.connected and not e.filter_on, "VPN заменяет фильтр")
        e.disconnect()
        check(e.filter_on and not e.connected, "после отключения VPN реклама снова блокируется")
        # журнал: реклама считается отдельно от своих блокировок, «Разрешить» — в исключения
        with open(e.paths.access_log, "a", encoding="utf-8") as f:
            f.write("2026/11/12 10:00:00.000000 from 127.0.0.1:5000 accepted tcp:ads1.example-ads.net:443 "
                    "[http-in -> adblock]\n")
            f.write("2026/11/12 10:00:01.000000 from 127.0.0.1:5001 accepted tcp:mine.example:443 [http-in -> block]\n")
        e._tail_access_log()
        st = e.ads_state()
        check(st["today"] == 1 and st["recent"][0]["host"] == "ads1.example-ads.net", f"журнал рекламы: {st['recent']}")
        check(e.ads_allow("ads1.example-ads.net") == "ads1.example-ads.net" and not e.ads_state()["recent"],
              "«Разрешить» из журнала")
        e.build_adblock()
        with open(e._ads_dat, "rb") as f:
            check("ads1.example-ads.net" not in adblock.decode_geosite(f.read())["ADS"], "исключение работает")
        # к закрытому сайту стучатся снова и снова — программа спрашивает, не разрешить ли его
        events = []
        e._raw_notify = lambda ev, **d: events.append((ev, d))
        with open(e.paths.access_log, "a", encoding="utf-8") as f:
            for i, h in enumerate(("www.manga-site.example", "manga-site.example", "doubleclick.net", "doubleclick.net",
                                   "pop1.popunder.example", "pop1.popunder.example")):
                f.write(f"2026/11/12 10:01:0{i}.000000 from 127.0.0.1:50{i}0 accepted tcp:{h}:443 [http-in -> adblock]\n")
        e._tail_access_log()
        for _ in range(50):
            if e.ads_suspects:
                break
            time.sleep(0.1)
        sus = list(e.ads_suspects)
        check(len(sus) == 1 and sus[0]["site"] == "manga-site.example" and sus[0]["lists"] == ["реклама и трекеры"],
              f"«сайт закрыт блокировщиком»: {sus}")
        check(any(ev == "ads_site" for ev, _ in events) and e.tray_queue, "вопрос в окне и у значка в трее")
        check(e.ads_state()["suspects"][0]["site"] == "manga-site.example", "закрытый сайт виден в разделе «Реклама»")
        e.ads_site_answer("manga-site.example", allow=False)
        check(not e.ads_suspects and "manga-site.example" in e.settings["ads_site_ignore"], "«Не надо» — больше не спрашивать")
        e._ads_site_asked.clear()
        e._ads_site_hit("manga-site.example"); e._ads_site_hit("manga-site.example")
        time.sleep(0.3)
        check(not e.ads_suspects, "после «Не надо» не спрашивает")
        e.settings["ads_site_ignore"] = []
        check(e.ads_site_answer("www.manga-site.example", allow=True) == "manga-site.example"
              and "manga-site.example" in e.settings["ads_allow"], "«Разрешить» сайт целиком")
        e._raw_notify = lambda ev, **d: None
        # сила списка: недостающий скачивается
        e.set_ads(level="light")
        e.update_adblock(apply=False, only_missing=True)
        check(e.settings["ads_info"]["lists"]["main"] == 60, "смена силы блокировки")
        # пауза: правила рекламы нет, а после паузы — снова есть
        e.ads_pause(5)
        e.apply_ads()
        check(not e._filter_wanted() and not e.filter_on, "на паузе фильтр без VPN не нужен")
        check(e._ads_mode() == "", "на паузе реклама не блокируется и с VPN")
        e.ads_pause(0)
        e.apply_ads()
        check(e.filter_on, "после паузы фильтр снова работает")
        # после обновления программы: «Сильная» → «Обычная» (один раз), списки пересобираются с защитой сайтов
        e.settings.update(ads_rev=0, ads_level="pro", ads_updated_at=time.time())
        e._ads_migrate()
        check(e.settings["ads_level"] == "normal" and e.settings["ads_rev"] == 2 and e.settings["ads_updated_at"] == 0,
              "переход на «Обычную» силу после обновления")
        e.settings["ads_level"] = "pro"
        e._ads_migrate()
        check(e.settings["ads_level"] == "pro", "выбор «Сильной» после перехода не сбрасывается")
        # выключили блокировку — фильтр без VPN останавливается
        e.set_ads(enabled=False)
        e.apply_ads()
        check(not e.filter_on and not e.proc.alive(), "выключение блокировки рекламы")
        wait_idle(e)
    finally:
        adblock.main_url = old_url
        try:
            e.shutdown()
        except Exception:
            pass
        shutil.rmtree(tmp, ignore_errors=True)


@case("Белые списки: программа замечает их, переходит на подходящий сервер и возвращается")
def t_whitelist():
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    old_probe = services.whitelist_probe
    mode = {"v": "open"}
    try:
        engmod.services.whitelist_probe = lambda port=None: mode["v"]
        e = make_engine(tmp)
        e.settings["autopilot"] = True
        e.startup()
        e.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        e.add_servers("vless://44444444-4444-4444-4444-444444444444@slow-wl.example:443?security=reality&pbk=K&sni=ya.ru"
                      "&type=tcp#Whitelist%20LTE")
        for name, want in (("🇷🇺 Обход белых списков", True), ("Белые списки МТС", True), ("Сервер БС", True),
                           ("Белград", False), ("Wildberries", False)):
            check(bool(e.WL_NAME.search(name)) == want, f"название сервера для белых списков: {name}")
        e.test_all()
        wl = next(s for s in e.servers if s.endpoint.startswith("slow-wl"))
        fast = next(s for s in e.servers if s.endpoint.startswith("fast"))
        check(e.is_wl_server(wl) and not e.is_wl_server(fast), "сервер для белых списков узнаётся по названию")
        e.connect(fast)
        # включились белые списки: обычные серверы недоступны
        mode["v"] = "whitelist"
        DEAD.update({"fast.example", "slow.example"})
        e.failover("сервер перестал отвечать")
        check(e.whitelist_mode and e.current.key == wl.key, f"при белых списках нужен подходящий сервер: {e.current.name}")
        check(any(p["key"] == "whitelist" for p in e.problems_list()), "нужно объяснить, что включены белые списки")
        check(e.state()["whitelist_mode"] and any(x["wl"] for x in e.state()["servers"]), "интерфейс должен это видеть")
        # белые списки отключились — возвращаемся к лучшему серверу
        mode["v"] = "open"
        DEAD.difference_update({"fast.example", "slow.example"})
        for _ in range(3):  # занята другая задача (на медленной машине бывает) — сторож пропускает ход, как и в программе
            wait_idle(e)
            e._whitelist_watch()
            wait_idle(e)
            if e.current.key != wl.key:
                break
        check(not e.whitelist_mode and not any(p["key"] == "whitelist" for p in e.problems_list()),
              "после белых списков предупреждение должно уйти")
        check(e.current.key != wl.key, f"нужно вернуться к лучшему обычному серверу: {e.current.name}")
        e.settings["whitelist_auto"] = False
        mode["v"] = "whitelist"
        check(not e._check_whitelist(), "выключенная функция ничего не проверяет")
    finally:
        engmod.services.whitelist_probe = old_probe
        DEAD.difference_update({"fast.example", "slow.example"})
        try:
            e.shutdown()
        except Exception:
            pass
        shutil.rmtree(tmp, ignore_errors=True)


@case("Работа в фоне и раздача по Wi-Fi: значок, автозапуск, сеть и её QR-код")
def t_background():
    check("--autostart" in autostart.command("/opt/pult"), "автозапуск должен запускать программу тихо, у часов")
    t = tray.Tray("x.ico", lambda: None, lambda: None, lambda: None, lambda k: k)
    t.update(True, "VEDOMYJ VPN")
    t.balloon("a", "b")
    t.stop()
    check(sys.platform == "win32" or not t.ok, "не в Windows значок не создаётся и ничего не ломает")
    check(hotspot.wifi_qr_text("Pult-1234", "a;b:c") == r"WIFI:T:WPA;S:Pult-1234;P:a\;b\:c;;", "QR-код сети Wi-Fi")
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    try:
        e = make_engine(tmp)
        e.startup()
        text = e.share_text("wifi")
        s = e.settings
        check(s["hotspot_ssid"].startswith("Pult-") and len(s["hotspot_pass"]) == 10 and s["hotspot_pass"] in text,
              "имя сети и пароль для раздачи придумываются сами")
        if sys.platform != "win32":
            try:
                e.hotspot_start()
                check(False, "не в Windows раздача должна давать понятную ошибку")
            except RuntimeError as exc:
                check("Windows" in str(exc), f"ошибка раздачи: {exc}")
            check(not e.state()["hotspot"]["on"] and e.state()["hotspot"]["error"], "состояние раздачи для интерфейса")
        check(e.settings["background"] is True, "работа в фоне по умолчанию включена")
    finally:
        try:
            e.shutdown()
        except Exception:
            pass
        shutil.rmtree(tmp, ignore_errors=True)


def _real_bash() -> str:
    """bash для проверки синтаксиса скриптов. В Windows «bash» из System32 — заглушка WSL (без Linux она не работает),
    поэтому там берётся bash из Git для Windows. Нет рабочего — проверка синтаксиса пропускается."""
    import subprocess as sp
    cands = []
    if sys.platform == "win32":
        for env in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"):
            if os.environ.get(env):
                cands.append(os.path.join(os.environ[env], "Git", "bin", "bash.exe"))
    found = shutil.which("bash")
    if found and not (sys.platform == "win32" and "system32" in found.lower()):
        cands.append(found)
    for exe in cands:
        try:
            r = sp.run([exe, "-c", "echo ok"], capture_output=True, timeout=20)
            if r.returncode == 0 and r.stdout.strip() == b"ok":
                return exe
        except (OSError, sp.SubprocessError):
            continue
    return ""


@case("Мастер своего сервера: скрипт, ход установки, ссылки и проверка")
def t_vps():
    import subprocess as sp
    sh = vps.script()
    check("XTLS/Xray-install" in sh and "xtls-rprx-vision" in sh and "PULT_RESULT" in sh and "\r" not in sh,
          "скрипт установки")
    bash = _real_bash()
    if bash:
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, newline="\n") as f:
            f.write(sh)
        check(sp.run([bash, "-n", f.name]).returncode == 0, "в скрипте установки ошибка синтаксиса")
        os.remove(f.name)
    for bad in (("1.2.3.4; rm -rf /", 22, "root"), ("1.2.3.4", 22, "root; ls"), ("1.2.3.4", "x", "root"), ("", 22, "root")):
        try:
            vps.check_input(*bad)
            check(False, f"мастер должен отклонить {bad}")
        except vps.VpsError:
            pass
    check(vps.check_input(" 203.0.113.10 ", "2222", "") == ("203.0.113.10", 2222, "root"), "ввод данных сервера")
    try:
        vps.make_links("1.2.3.4", "x|y|z|w", "a")
        check(False, "мусорный ответ сервера должен отклоняться")
    except vps.VpsError:
        pass
    # скрипты для своего сервера: состояние и ключи для друзей
    for body in (vps.status_script(), vps.friend_script("add"),
                 vps.friend_script("remove", "3f1c2a9e-1b2c-4d5e-8f90-1234567890ab")):
        check("\r" not in body and "__" not in body.replace("__name__", ""), "в скрипте остались заготовки")
        if bash:
            with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, newline="\n") as f:
                f.write(body)
            check(sp.run([bash, "-n", f.name]).returncode == 0, "в скрипте для сервера ошибка синтаксиса")
            os.remove(f.name)
    for bad in (("remove", "x; rm -rf /"), ("drop", "")):
        try:
            vps.friend_script(*bad)
            check(False, f"скрипт для друга должен отклонить {bad}")
        except vps.VpsError:
            pass
    if shutil.which("bash") and sys.platform != "win32":
        # скрипт состояния только читает — его можно запустить прямо здесь
        out = sp.run(["bash", "-c", vps.status_script()], capture_output=True, text=True, timeout=30).stdout
        line = next((ln[12:] for ln in out.splitlines() if ln.startswith("PULT_RESULT:")), "")
        st_ = vps.parse_status(line)
        check(st_["uptime_s"] > 0 and isinstance(st_["rx"], int), f"состояние сервера: {st_}")
    # правка настроек Xray на сервере (кусок на python): добавить и убрать пользователя в обоих входах
    py = vps.FRIEND_SCRIPT.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    cfg_text = vps.script().split("<<JSON\n", 1)[1].split("\nJSON\n", 1)[0]
    for k, v in (("$UUID", "11111111-2222-3333-4444-555555555555"), ("$PRIV", "privKEY"), ("$SID", "abcd"),
                 ("$XPATH", "f00d")):
        cfg_text = cfg_text.replace(k, v)
    work = tempfile.mkdtemp(prefix="pult-selftest-")
    try:
        cfg_path = os.path.join(work, "config.json")
        with open(cfg_path, "w") as f:
            f.write(cfg_text)
        fid = "3f1c2a9e-1b2c-4d5e-8f90-1234567890ab"
        r = sp.run([sys.executable, "-I", "-c", py, cfg_path, "add", fid], capture_output=True, text=True)
        check(r.returncode == 0 and r.stdout.strip() == "privKEY|abcd|f00d", f"скрипт для друга: {r.stdout} {r.stderr}")
        new = json.load(open(cfg_path + ".new"))
        ids = [[c["id"] for c in ib["settings"]["clients"]] for ib in new["inbounds"]]
        check(all(fid in i and "11111111-2222-3333-4444-555555555555" in i for i in ids),
              "ключ друга нужен в обоих входах, свой ключ остаётся")
        check(any(c.get("flow") == "xtls-rprx-vision" for c in new["inbounds"][0]["settings"]["clients"]
                  if c["id"] == fid), "у ключа друга в Reality нужен flow")
        os.replace(cfg_path + ".new", cfg_path)
        r = sp.run([sys.executable, "-I", "-c", py, cfg_path, "remove", fid], capture_output=True, text=True)
        new = json.load(open(cfg_path + ".new"))
        check(r.returncode == 0 and all(fid not in [c["id"] for c in ib["settings"]["clients"]] for ib in new["inbounds"]),
              "ключ друга должен удаляться")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    orig_start = vps.start
    scenario = {"lines": [], "bodies": []}

    def fake_start(host, port, user, script_path, out_path, hint="", body=None):
        check("пароль" in hint or "password" in hint, "в окне ssh нужна подсказка про пароль")
        scenario["bodies"].append(body)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(scenario["lines"]) + "\n")
        return sp.Popen([sys.executable, "-c", "import time; time.sleep(0.5)"])

    try:
        engmod.vps.start = fake_start
        e = make_engine(tmp)
        e.startup()
        scenario["lines"] = ["PULT_STEP:packages", "PULT_STEP:xray", "PULT_STEP:start",
                             "PULT_RESULT:3f1c2a9e-1b2c-4d5e-8f90-1234567890ab|"
                             "cHVibGljLWtleS1mb3ItdGVzdGluZy1yZWFsaXR5LXh4|0123456789abcdef|a1b2c3d4e5f6"]
        links_ = e.vps_setup("203.0.113.10", 22, "root", "My server")
        mine = [s for s in e.servers if s.link in links_]
        check(len(mine) == 2 and mine[0].name == "My server" and all((s.result or {}).get("tested_at") for s in mine),
              "мастер должен добавить и сразу проверить свой сервер")
        check(not os.path.exists(os.path.join(e.paths.data_dir, "vps_install.sh")), "скрипт после установки удаляется")
        check(not os.path.exists(os.path.join(e.paths.data_dir, "vps_install.log")),
              "ответ сервера с ключом после установки удаляется")
        hosts = e.vps_view()
        check(len(hosts) == 1 and hosts[0]["host"] == "203.0.113.10" and hosts[0]["name"] == "My server",
              f"настроенный сервер запоминается: {hosts}")
        from pult import settings as settings_mod
        check("vps_hosts" in settings_mod.SECRET_KEYS and not any("pass" in k for k in e.settings["vps_hosts"][0]),
              "свой сервер хранится зашифрованным и без пароля")
        vid = hosts[0]["id"]
        scenario["lines"] = ["PULT_RESULT:90061|0.15 0.10 0.05|310/1987|3.1G/25G|123456|654321|active|4|1"]
        st_ = e.vps_status(vid)
        check(st_["conns"] == 4 and st_["xray"] == "active" and e.vps_view()[0]["status"]["mem_mb"] == "310/1987",
              f"состояние своего сервера: {st_}")
        check(scenario["bodies"][-1] and "/proc/loadavg" in scenario["bodies"][-1], "на сервер уходит скрипт состояния")
        fid = "7e57f00d-1b2c-4d5e-8f90-1234567890ab"
        scenario["lines"] = [f"PULT_RESULT:{fid}|cHVibGljLWtleS1mb3ItdGVzdGluZy1yZWFsaXR5LXh4|0123456789abcdef|a1b2c3d4e5f6"]
        e.vps_friend_add(vid, "Alex")
        friends = e.vps_view()[0]["friends"]
        check(len(friends) == 1 and friends[0]["name"] == "Alex" and "links" not in friends[0],
              f"ключ для друга (в окно программы — без ссылки): {friends}")
        items = [i for i in e.share_items() if i["kind"] == "friend"]
        check(items and e.share_text(items[0]["id"]).startswith(f"vless://{fid}@203.0.113.10:443"),
              "QR-код для друга — его собственный ключ")
        scenario["lines"] = [f"PULT_RESULT:{fid}|cHVibGljLWtleS1mb3ItdGVzdGluZy1yZWFsaXR5LXh4|0123456789abcdef|a1b2c3d4e5f6"]
        e.vps_friend_remove(vid, fid)
        check(fid in scenario["bodies"][-1] and 'ACTION="remove"' in scenario["bodies"][-1] and not e.vps_view()[0]["friends"],
              "ключ друга удаляется на сервере и в программе")
        check(not os.path.exists(os.path.join(e.paths.data_dir, "vps_task.log")), "ответ сервера не остаётся на диске")
        scenario["lines"] = ["PULT_ERROR:noxray"]
        try:
            e.vps_friend_add(vid, "Petya")
            check(False, "ошибка на сервере должна дойти до человека")
        except RuntimeError as exc:
            check("мастер" in str(exc), f"понятная причина: {exc}")
        e.vps_forget(vid)
        check(not e.vps_view(), "сервер убирается из программы")
        scenario["lines"] = ["PULT_STEP:packages", "PULT_ERROR:port"]
        try:
            e.vps_setup("203.0.113.11", 22, "root")
            check(False, "ошибка на сервере должна дойти до человека")
        except RuntimeError as exc:
            check("443" in str(exc), f"понятная причина: {exc}")
        scenario["lines"] = []
        try:
            e.vps_setup("203.0.113.12", 22, "root")
            check(False, "неверный пароль должен давать понятную ошибку")
        except RuntimeError as exc:
            check("пароль" in str(exc), f"понятная причина: {exc}")
    finally:
        engmod.vps.start = orig_start
        try:
            e.shutdown()
        except Exception:
            pass
        shutil.rmtree(tmp, ignore_errors=True)


@case("Сборки: установщик, портативная версия и исходники")
def t_build():
    app = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    build = os.path.join(app, "build")
    if not os.path.isdir(build):
        return  # в установленной или портативной программе сборщика нет — это нормально
    import re as _re
    import struct
    for name in ("launcher.cs", "installer.cs"):
        with open(os.path.join(build, name), encoding="utf-8") as f:
            code = f.read()
        # штатный компилятор Windows (.NET Framework 4) понимает только C# 5
        bad = [m for m in ('$"', "?.", "nameof(", "=> ") if m in code]
        check(not bad, f"{name}: возможности новее C# 5 не соберутся штатным компилятором: {bad}")
        check(code.count("{") == code.count("}"), f"{name}: непарные фигурные скобки")
    with open(os.path.join(build, "installer.cs"), encoding="utf-8") as f:
        code = f.read()
    check("%VERSION%" in code and "/uninstall" in code and '"app.zip"' in code and "data\\\\" in code,
          "установщик: версия, удаление, встроенный архив и защита папки data")
    check("Substring(top.Length)" in code and "Substring(8)" not in code,
          "установщик отрезает имя корневой папки архива по её длине, а не числом")
    with open(os.path.join(build, "build.ps1"), "rb") as f:
        raw = f.read()
    check(raw.startswith(b"\xef\xbb\xbf"), "build.ps1 нужен с BOM, иначе Windows PowerShell испортит русские имена файлов")
    text = raw.decode("utf-8-sig")
    for ref in _re.findall(r"'([^']+\.(?:cs|manifest|py|bat|md|ico))'", text):
        if "\\" in ref or ref in ("main.py", "check.py", "field_check.py", "update_from_zip.py", "full_check.py",
                                   "start.bat", "Проверка.bat", "Проверка новых функций.bat", "Обновить.bat",
                                   "Полная проверка.bat", "README.md",
                                   "AI_GUIDE.md"):
            path = os.path.join(app, *ref.split("\\")) if not ref.endswith((".cs", ".manifest")) else os.path.join(build, ref)
            check(os.path.exists(path), f"build.ps1 ссылается на несуществующий файл: {ref}")
    check(os.path.isfile(os.path.join(app, "Собрать.bat")), "нет Собрать.bat")
    # сборка APK на компьютере пользователя: меню, скрипт Android и запуск из «Собрать.bat»
    for name in ("build.ps1", "build-all.ps1", "build-android.ps1"):
        with open(os.path.join(build, name), "rb") as f:
            raw = f.read()
        text = raw.decode("utf-8-sig")
        check(raw.startswith(b"\xef\xbb\xbf") and b"\r\n" in raw and b"\n" not in raw.replace(b"\r\n", b""),
              f"{name}: нужен BOM и переводы строк Windows")
        for a, b in ("{}", "()", "[]"):
            check(text.count(a) == text.count(b), f"{name}: непарные скобки {a}{b}")
    with open(os.path.join(build, "build-all.ps1"), encoding="utf-8-sig") as f:
        menu = f.read()
    check("'build.ps1'" in menu and "'build-android.ps1'" in menu, "меню сборки запускает обе сборки")
    with open(os.path.join(app, "Собрать.bat"), "rb") as f:
        bat = f.read()
    check(bat.isascii() and b"build-all.ps1" in bat, "Собрать.bat — только латиница (иначе cmd путает кодировку) и меню")
    with open(os.path.join(build, "build-android.ps1"), encoding="utf-8-sig") as f:
        andr = f.read()
    check("/XD keystore build .gradle libs" in andr and "GRADLE_USER_HOME" in andr and "IsAscii" in andr,
          "сборка APK: ключ и ядро не затираются, Gradle и SDK — в папке без русских букв")
    with open(os.path.join(app, "ui", "icons", "app.ico"), "rb") as f:
        head = f.read(6 + 16 * 16)
    _, kind, count = struct.unpack("<HHH", head[:6])
    sizes = {head[6 + 16 * i] or 256 for i in range(count)}
    check(kind == 1 and {16, 32, 48, 256} <= sizes, f"значок программы: {sizes}")
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    try:
        open(os.path.join(tmp, "VedomyjVPN.exe"), "w").close()
        check(autostart.command(tmp) == f'"{os.path.join(tmp, "VedomyjVPN.exe")}" --autostart',
              "в сборке автозапуск должен идти через VedomyjVPN.exe")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@case("Поделиться: QR-код, файл настроек и защита от чужих значений")
def t_share():
    import hashlib
    # эталоны проверены сторонним декодером QR при разработке — код должен получаться бит в бит таким же
    for text, size, want in (("https://example.com/sub/abc123", 29, "5b6b233fa4bbf4c1"),
                             ("tg://socks?server=192.168.1.20&port=10808", 29, "df8d637711bbf806")):
        m = qr.make(text)
        got = hashlib.sha256("".join("1" if v else "0" for row in m for v in row).encode()).hexdigest()[:16]
        check(len(m) == size and got == want, f"QR-код для {text[:20]}… получился не таким: {len(m)}, {got}")
    big = qr.make("x" * 2000)
    check(101 <= len(big) <= 177 and (len(big) - 17) % 4 == 0, f"размер большого QR-кода: {len(big)}")
    try:
        qr.make("x" * 5000)
        check(False, "слишком длинный текст должен давать понятную ошибку")
    except qr.QrTooLong:
        pass
    svg = qr.to_svg(qr.make("hi"))
    check(svg.startswith("<svg") and 'fill="#fff"' in svg and "<script" not in svg, "SVG QR-кода")

    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    tmp2 = tempfile.mkdtemp(prefix="pult-selftest-")
    a = b = None
    try:
        a = make_engine(tmp)
        a.startup()
        a.add_subscription(f"http://127.0.0.1:{WEB}/sub")
        a.add_servers("trojan://pw@vps.example:443?sni=vps.example#VPS")
        a.settings.update(mode="vpn", proxy_list="example.org\n", game_mode=True, byedpi_role="main",
                          byedpi_strategy="--disorder 1", dpi_custom="example.net", geo_update_hours=72.0)
        data = json.loads(json.dumps(a.export_settings()))
        check("subscriptions" not in data and "servers" not in data, "без галочки подписки не должны попадать в файл")
        check("hwid" not in json.dumps(data).lower() and "socks_port" not in data["settings"],
              "в файл не должны попадать ключ устройства и порты")
        full = json.loads(json.dumps(a.export_settings(True, True)))
        check(full["subscriptions"][0]["url"].endswith("/sub") and full["servers"], "подписки и серверы по галочке")

        b = make_engine(tmp2)
        b.startup()
        parsed = share.parse(full)
        b.import_settings(parsed)
        sb = b.settings
        check(sb["mode"] == "vpn" and sb["game_mode"] and sb["byedpi_role"] == "main" and sb["geo_update_hours"] == 72.0
              and "example.org" in sb["proxy_list"] and sb["dpi_custom"] == "example.net",
              "настройки из файла не применились")
        check(len(sb["subscriptions"]) == 1 and len(b.servers) >= 4, "подписка и сервер из файла не добавились")

        evil = {"format": share.FORMAT, "settings": {
            "mode": "evil", "geo_update_hours": -5, "ping_host": "a b; rm", "byedpi_strategy": "--x & calc",
            "zapret_strategy": "..\\..\\x", "socks_port": 80, "allow_lan": True, "hwid": "x", "autopilot": "yes",
            "ru_direct": False},
            "subscriptions": [{"url": "file:///etc/passwd"}, {"url": "happ://crypt4/xx"}], "servers": ["a\nb", 5]}
        p = share.parse(evil)
        check(p["settings"] == {"ru_direct": False} and not p["subscriptions"] and not p["servers"],
              f"чужой файл: должны пройти только правильные значения: {p['settings']}")
        for bad in ({"format": "other"}, [], "text", None):
            try:
                share.parse(bad)
                check(False, "не файл настроек должен отклоняться")
            except ValueError:
                pass

        items = {i["id"]: i for i in b.share_items()}
        sub_id = "sub:" + sb["subscriptions"][0]["id"]
        check(sub_id in items and not items["tg_lan"]["ready"], f"список для QR: {list(items)}")
        check(b.share_text(sub_id).endswith("/sub"), "QR подписки")
        try:
            b.share_text("tg_lan")
            check(False, "без доступа из сети QR для Telegram не должен строиться")
        except RuntimeError:
            pass
        b.settings["allow_lan"] = True
        orig_lan = netutil.lan_ip
        netutil.lan_ip = lambda: "192.168.1.20"
        try:
            b.ensure_lan_credentials()
            sb = b.settings
            check(len(sb["lan_pass"]) == 8 and b.share_text("tg_lan") ==
                  f"tg://socks?server=192.168.1.20&port={sb['lan_socks_port']}&user=pult&pass={sb['lan_pass']}",
                  "QR для Telegram на телефоне должен быть с логином и паролем")
            cfg = xray.build_run_config(b.servers[0], sb, {"socks": 1, "http": 2, "health": 3, "api": 4},
                                        "x.log", False)
            ins = {i["tag"]: i for i in cfg["inbounds"]}
            check(ins["socks-in"]["listen"] == "127.0.0.1" and ins["lan-socks-in"]["listen"] == "0.0.0.0"
                  and ins["lan-socks-in"]["settings"]["accounts"][0]["pass"] == sb["lan_pass"]
                  and ins["lan-http-in"]["settings"]["accounts"], "вход для сети должен быть с паролем, свой — без")
            sb["lan_auth"] = False
            cfg = xray.build_run_config(b.servers[0], sb, {"socks": 1, "http": 2, "health": 3, "api": 4}, "x.log", False)
            check("accounts" not in {i["tag"]: i for i in cfg["inbounds"]}["lan-socks-in"]["settings"],
                  "без галочки пароль не нужен")
            check(b.share_text("tg_lan").endswith(f"port={sb['lan_socks_port']}"), "QR без пароля")
        finally:
            netutil.lan_ip = orig_lan
    finally:
        for e in (a, b):
            try:
                e.shutdown()
            except Exception:
                pass
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.rmtree(tmp2, ignore_errors=True)


@case("Проблемы: жёлтый значок появляется и пропадает, отчёт без секретов")
def t_problems():
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    try:
        e = make_engine(tmp)
        e.startup()
        e.settings["subscriptions"].append({"id": "x1", "name": "", "url": "http://127.0.0.1:1/secret-token",
                                            "title": "", "usage": {}, "last_update": 0})
        try:
            e.update_subscription("x1")
        except Exception:
            pass
        check("sub:x1" in e.problems, "ошибка подписки не попала в проблемы")
        report = e.problem_report()
        check("secret-token" not in report, "в отчёте видна ссылка на подписку")
        e.remove_subscription("x1")
        check("sub:x1" not in e.problems, "проблема не снялась после удаления подписки")
        e.shutdown()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@case("Настройки: переход со старой версии, сохранение и HWID")
def t_settings():
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    try:
        os.makedirs(os.path.join(tmp, "data"))
        with open(os.path.join(tmp, "data", "settings.json"), "w", encoding="utf-8") as f:
            json.dump({"subscription_url": f"http://127.0.0.1:{WEB}/sub"}, f)
        e = make_engine(tmp)
        e.startup()
        check(len(e.settings["subscriptions"]) == 1, "старая подписка не перенеслась")
        hwid = e.settings["hwid"]
        check(len(hwid) == 32, "HWID не создан")
        e.save()
        e2 = make_engine(tmp)
        check(e2.settings["hwid"] == hwid, "HWID должен быть постоянным")
        e.shutdown()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@case("Интерфейс (API): защита и действия")
def t_api():
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    try:
        ui = UIServer(os.path.join(APP_DIR, "ui"), "tok")
        e = make_engine(tmp)
        e._raw_notify = ui.notify
        ui.engine = e
        port = ui.start()
        e.startup()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for hdrs in ({}, {"X-Token": "bad"}, {"X-Token": "tok", "Host": "evil.com"}):
            try:
                opener.open(urllib.request.Request(f"http://127.0.0.1:{port}/api/state", headers=hdrs), timeout=5)
                raise AssertionError(f"запрос без доступа прошёл: {hdrs}")
            except urllib.error.HTTPError as exc:
                check(exc.code == 403, "ожидался отказ 403")

        def call(action, **args):
            req = urllib.request.Request(f"http://127.0.0.1:{port}/api/action", headers={"X-Token": "tok"},
                                         data=json.dumps({"action": action, "args": args}).encode())
            return json.loads(opener.open(req, timeout=10).read())

        check(not call("add_sub", url="happ://crypt3/x")["ok"], "зашифрованная ссылка должна отклоняться сразу")
        check(call("add_sub", url=f"http://127.0.0.1:{WEB}/sub")["ok"], "добавление подписки")
        wait_idle(e)
        check(call("set_ui", lang="en")["ok"] and i18n.lang() == "en", "переключение языка")
        r = call("unknown_action")
        check(not r["ok"] and r["error"] == "Unknown action.", "ошибки должны переводиться на английский")
        call("set_ui", lang="ru")
        r = call("export_settings")
        check(r["ok"] and r["result"]["format"] == share.FORMAT, "сохранение файла настроек")
        check(not call("import_preview", data={"format": "x"})["ok"], "чужой файл должен отклоняться")
        r = call("import_preview", data=r["result"])
        check(r["ok"] and r["result"]["settings"] > 5, "проверка файла настроек")
        r = call("share_qr", id="sub:" + e.settings["subscriptions"][0]["id"])
        check(r["ok"] and r["result"]["svg"].startswith("<svg"), "QR-код подписки")
        check(not call("share_qr", id="tg_lan")["ok"], "QR для Telegram без доступа из сети")
        # свои маршруты и прокси: неверное отклоняется, пароль не возвращается в интерфейс
        check(not call("service_route", name="TikTok", target="server:nope")["ok"], "выбор несуществующего сервера")
        check(not call("route_site", host="не сайт", target="proxy")["ok"], "неверный адрес сайта")
        check(not call("add_proxy", url="vless://u@h.example:443")["ok"], "ссылка на сервер — не прокси")
        r = call("add_proxy", url="socks5://me:top-secret@192.0.2.10:1080", name="Тест")
        check(r["ok"] and "top-secret" not in json.dumps(r), "добавление прокси без пароля в ответе")
        wait_idle(e)
        check(call("route_site", host="example.com", target=f"custom:{r['result']['id']}", exact=True)["ok"], "сайт через прокси")
        st = json.loads(opener.open(urllib.request.Request(f"http://127.0.0.1:{port}/api/state",
                                                          headers={"X-Token": "tok"}), timeout=5).read())
        check("top-secret" not in json.dumps(st) and st["routes"]["sites"][0]["site"] == "example.com",
              "состояние: маршрут сайта есть, пароля нет")
        check(call("remove_proxy", id=r["result"]["id"])["ok"] and not e.settings["routes"], "удаление прокси")
        # сохранение настроек при включённом VPN: применяется переподключением, смена портов — тоже
        wait_idle(e)
        check(call("toggle")["ok"], "подключение")
        wait_idle(e)
        check(e.connected, "VPN включён")
        r = call("save_settings", ping_host="www.gstatic.com", autopilot=False)
        check(r["ok"], f"сохранение настроек при включённом VPN: {r}")
        wait_idle(e)
        check(e.connected and not e.settings["autopilot"], "настройки применились, VPN включён")
        new_socks, new_http = netutil.find_free_ports(2, 37100)
        r = call("save_settings", socks_port=new_socks, http_port=new_http)
        check(r["ok"], f"смена портов при включённом VPN: {r}")
        wait_idle(e)
        check(e.connected and e.settings["socks_port"] == new_socks and e.settings["http_port"] == new_http,
              "порты сменились, VPN снова включён")
        check(call("toggle")["ok"], "отключение")
        wait_idle(e)
        for name in ("index.html", "app.js", "i18n.js", "style.css", "icons/monogram.svg"):  # единственная иконка
            body = opener.open(f"http://127.0.0.1:{port}/{name}", timeout=5).read()
            check(len(body) > 100, f"файл интерфейса {name} не отдаётся")
        # пин-код на окно: без него — ни настроек, ни действий; перебор тормозится
        def state():
            return json.loads(opener.open(urllib.request.Request(f"http://127.0.0.1:{port}/api/state",
                                                                 headers={"X-Token": "tok"}), timeout=5).read())
        check(not call("pin_set", pin="12ab")["ok"], "пин-код — только цифры")
        check(call("pin_set", pin="2468", minutes=5)["ok"] and e.settings["pin_hash"] and "2468" not in json.dumps(e.settings),
              "пин-код хранится только хешем")
        ui.lock_window()
        st = state()
        check(st.get("locked") and "subscriptions" not in st and "servers" not in st, f"заблокировано: {list(st)}")
        check(not call("toggle")["ok"] and not call("export_settings")["ok"], "действия без пин-кода не работают")
        check(not call("unlock", pin="1111")["ok"], "неверный пин-код")
        check(call("unlock", pin="2468")["ok"] and "servers" in state(), "верный пин-код открывает окно")
        check(not call("pin_remove", old="0000")["ok"], "снять пин-код можно только зная его")
        ui.lock_window()
        for _ in range(5):
            call("unlock", pin="0000")
        r = call("unlock", pin="2468")
        check(not r["ok"] and "Слишком много" in r["error"], f"перебор тормозится: {r}")
        ui._pin_wait_until = 0
        check(call("unlock", pin="2468")["ok"] and call("pin_remove", old="2468")["ok"] and not ui.pin_set(), "пин-код снят")
        e.shutdown()
        ui.stop()
    finally:
        i18n.set_lang("ru")
        shutil.rmtree(tmp, ignore_errors=True)


@case("Обновление из архива поверх старой версии: подписки и настройки остаются")
def t_update_zip():
    import subprocess
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    try:
        app = os.path.join(tmp, "Мой VPN")  # старая версия: код, данные с подпиской, ядро
        os.makedirs(os.path.join(app, "pult"))
        os.makedirs(os.path.join(app, "data"))
        os.makedirs(os.path.join(app, "bin"))
        shutil.copy(os.path.join(APP_DIR, "update_from_zip.py"), app)
        with open(os.path.join(app, "pult", "__init__.py"), "w", encoding="utf-8") as f:
            f.write('APP_VERSION = "1.0.0"\n')
        with open(os.path.join(app, "main.py"), "w", encoding="utf-8") as f:
            f.write("old\n")
        secret = {"subscriptions": [{"url": "https://sub.example/s/SECRET-TOKEN"}], "mode": "smart"}
        with open(os.path.join(app, "data", "settings.json"), "w", encoding="utf-8") as f:
            json.dump(secret, f)
        with open(os.path.join(app, "bin", "xray.exe"), "wb") as f:
            f.write(b"core")
        # новый архив: код другой версии, а ещё «чужие» данные и попытки выйти за папку — их брать нельзя
        zpath = os.path.join(tmp, "VedomyjVPN-9.9.9.zip")
        with zipfile.ZipFile(zpath, "w") as z:
            z.writestr("VedomyjVPN/pult/__init__.py", 'APP_VERSION = "9.9.9"\n')
            z.writestr("VedomyjVPN/main.py", "new\n")
            z.writestr("VedomyjVPN/ui/app.js", "// new ui\n")
            z.writestr("VedomyjVPN/data/settings.json", "{}")
            z.writestr("VedomyjVPN/bin/xray.exe", "evil")
            z.writestr("VedomyjVPN/../escape.txt", "x")
        # «работающая программа»: её надо закрыть перед заменой файлов (через её же интерфейс, с токеном)
        quit_seen = []

        class FakeUI(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                ok = self.headers.get("X-Token") == "tok" and not quit_seen
                self.send_response(200 if ok else 403)
                self.end_headers()

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                if self.headers.get("X-Token") == "tok" and body.get("action") == "quit":
                    quit_seen.append(True)
                self.send_response(200)
                self.end_headers()
                if quit_seen:
                    threading.Thread(target=srv.shutdown, daemon=True).start()
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeUI)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        with open(os.path.join(app, "data", "ui.json"), "w", encoding="utf-8") as f:
            json.dump({"port": srv.server_address[1], "token": "tok"}, f)
        r = subprocess.run([sys.executable, os.path.join(app, "update_from_zip.py"), zpath, "--yes", "--no-start"],
                   capture_output=True, text=True, encoding="utf-8", timeout=60)
        srv.server_close()
        check(r.returncode == 0, f"обновление: {r.stdout} {r.stderr}")
        check(quit_seen and "Закрываю работающую программу" in r.stdout, f"программа закрыта перед обновлением: {r.stdout}")
        with open(os.path.join(app, "main.py"), encoding="utf-8") as f:
            check(f.read() == "new\n", "код заменён")
        check(os.path.isfile(os.path.join(app, "ui", "app.js")), "новые файлы добавлены")
        with open(os.path.join(app, "data", "settings.json"), encoding="utf-8") as f:
            check(json.load(f) == secret, "подписка и настройки не тронуты")
        os.remove(os.path.join(app, "data", "ui.json"))
        with open(os.path.join(app, "bin", "xray.exe"), "rb") as f:
            check(f.read() == b"core", "ядро не тронуто")
        check(not os.path.exists(os.path.join(tmp, "escape.txt")), "из папки программы не выйти")
        backups = os.listdir(os.path.join(app, "data", "backups"))
        check(len(backups) == 1 and os.path.isfile(os.path.join(app, "data", "backups", backups[0], "settings.json")),
              "копия настроек перед обновлением")
        check("1.0.0" in r.stdout and "9.9.9" in r.stdout and "SECRET-TOKEN" not in r.stdout, "понятный вывод без ссылок")
        # чужой архив не трогает ничего
        bad = os.path.join(tmp, "VedomyjVPN-bad.zip")
        with zipfile.ZipFile(bad, "w") as z:
            z.writestr("other/readme.txt", "x")
        r = subprocess.run([sys.executable, os.path.join(app, "update_from_zip.py"), bad, "--yes", "--no-start"],
                   capture_output=True, text=True, encoding="utf-8", timeout=60)
        check(r.returncode == 1 and "не подходит" in r.stdout, f"чужой архив: {r.stdout}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@case("Код: нет необъявленных имён (ошибки вида «name … is not defined»)")
def t_names():
    import builtins
    import glob
    import symtable
    files = sorted(glob.glob(os.path.join(APP_DIR, "pult", "*.py"))) + [
        os.path.join(APP_DIR, n) for n in ("main.py", "check.py", "field_check.py", "update_from_zip.py", "full_check.py")
        if os.path.isfile(os.path.join(APP_DIR, n))]
    bad = []
    for path in files:
        src = open(path, encoding="utf-8").read()
        tree = ast.parse(src)
        top = symtable.symtable(src, path, "exec")
        known = {x.get_name() for x in top.get_symbols() if x.is_assigned() or x.is_imported() or x.is_namespace()}
        known |= {n for node in ast.walk(tree) if isinstance(node, ast.Global) for n in node.names}
        known |= {"__file__", "__name__", "__doc__", "__spec__"}

        def walk(tab, where):
            for sym in tab.get_symbols():
                n = sym.get_name()
                if sym.is_referenced() and sym.is_global() and not sym.is_declared_global() \
                        and n not in known and not hasattr(builtins, n):
                    bad.append(f"{os.path.basename(path)}: {where}/{tab.get_name()} → {n}")
            for ch in tab.get_children():
                walk(ch, f"{where}/{tab.get_name()}" if tab.get_name() != "top" else "")
        walk(top, "")
    check(not bad, "необъявленные имена: " + "; ".join(bad[:10]))


@case("Перевод: все сообщения программы переводятся на английский")
def t_i18n():
    i18n.set_lang("en")
    try:
        skip = ("Мой VPN", "Fast", "Slow", "Dead", "Hy2", "Дом", "Мой AWG", "Мой сервер", "Включите отправку HWID",
                "Подписка истекла", "Госуслуги", "Обычный", "Резидент")
        bad = []
        for msg in dict.fromkeys(MESSAGES):
            text = msg[9:] if len(msg) > 9 and msg[2] == ":" and msg[5] == ":" else msg
            if i18n.untranslated(text, keep=skip):
                bad.append(text)
        check(not bad, "без перевода: " + " | ".join(bad[:8]))
    finally:
        i18n.set_lang("ru")


@case("Перевод: все фразы в коде программы имеют английский вариант")
def t_i18n_static():
    import ast
    import glob
    import re
    cyr = re.compile("[А-Яа-яЁё]")
    # служебные слова (поиск по тексту, внутренние статусы, названия сервисов) показывать не нужно
    skip_funcs = {"problem_report", "_busy_kind", "status_code", "human_bytes", "describe"}
    skip_strings = set(links.STUB_WORDS) | {s["name"] for s in services.SERVICES} | {
        "VEDOMYJ VPN", "работает", "не отвечает", "не поддерживается", "сообщение провайдера", "ошибка настроек",
        "ошибка ядра", "медленно/обрыв", "проверяю…", "замер скорости…", "перестал отвечать", "<ссылка на подписку>",
        "Провайдер:", engmod.Engine.WL_NAME.pattern, *__import__("pult.netprofile", fromlist=["x"]).PATTERNS,
        *subscription.BLOCK_PAGE_MARKS, "страницу блокировки", *xray.VIRUS_WORDS}
    i18n.set_lang("en")
    bad = []
    try:
        for path in sorted(glob.glob(os.path.join(APP_DIR, "pult", "*.py"))):
            if os.path.basename(path) in ("countries.py", "i18n.py", "selftest.py", "diagnostics.py", "fullcheck.py",
                                          "errorlog.py"):
                continue
            tree = ast.parse(open(path, encoding="utf-8").read())
            ignore = set()
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Module)) and node.body and \
                        isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant):
                    ignore.add(id(node.body[0].value))  # строки документации
                if isinstance(node, ast.FunctionDef) and node.name in skip_funcs:
                    ignore.update(id(n) for n in ast.walk(node))
                if isinstance(node, ast.JoinedStr):
                    ignore.update(id(v) for v in node.values)
            for node in ast.walk(tree):
                if id(node) in ignore:
                    continue
                if isinstance(node, ast.JoinedStr):
                    text = "".join(str(v.value) if isinstance(v, ast.Constant) else "7" for v in node.values)
                elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                    text = node.value
                else:
                    continue
                if cyr.search(text) and text not in skip_strings and i18n.untranslated(text):
                    bad.append(f"{os.path.basename(path)}:{node.lineno}: {text[:60]}")
    finally:
        i18n.set_lang("ru")
    check(not bad, f"без перевода ({len(bad)}): " + " | ".join(bad[:10]))


# ---------- тесты: движки (Hysteria2, мост sing-box, AmneziaWG) ----------

AWG_CONF = """[Interface]
PrivateKey = cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MTI=
Address = 10.8.1.7/32
DNS = 1.1.1.1
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 33
H1 = 1844
H2 = 2981
H3 = 3110
H4 = 4129

[Peer]
PublicKey = cHVibGlja2V5cHVibGlja2V5cHVibGlja2V5cHViMTI=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = awg.example:51820
PersistentKeepalive = 25
"""


def _amnezia_key(obj: dict) -> str:
    """Ключ AmneziaVPN vpn://: base64url(4 байта длины + zlib(JSON)) — как его делает приложение Amnezia."""
    import struct
    import zlib
    raw = json.dumps(obj).encode()
    return "vpn://" + base64.urlsafe_b64encode(struct.pack(">I", len(raw)) + zlib.compress(raw)).decode().rstrip("=")


@case("Движки: ссылки Hysteria2, TUIC, AnyTLS, конфиг и ключ AmneziaWG, секреты не попадают в отчёт")
def t_engine_links():
    from pult import diagnostics
    s = links.parse_link("hysteria2://p%40ss@h2.example:8443/?sni=s.example&obfs=salamander&obfs-password=op#H2")
    ob = s.outbound
    ss = ob["streamSettings"]
    check(s.supported and ob["protocol"] == "hysteria" and ob["settings"] == {"version": 2, "address": "h2.example", "port": 8443},
          f"Hysteria2 → Xray: {ob}")
    check(ss["network"] == "hysteria" and ss["hysteriaSettings"] == {"version": 2, "auth": "p@ss"}, f"пароль: {ss}")
    check(ss["tlsSettings"]["serverName"] == "s.example" and ss["tlsSettings"]["alpn"] == ["h3"], f"TLS: {ss['tlsSettings']}")
    check(ss["finalmask"]["udp"][0] == {"type": "salamander", "settings": {"password": "op"}}, "маскировка Salamander")
    check(links.kind_of(s) == "hy2" and xray.fingerprint_of(ob) is None and s.engine == "xray", "движок hy2, отпечатка TLS у QUIC нет")
    # «не проверять сертификат»: новые ядра Xray так не умеют (с 1.06.2026 allowInsecure — ошибка настроек)
    hi = links.parse_link("hysteria2://p%40ss@h2.example:8443/?sni=s.example&obfs=salamander&obfs-password=op&insecure=1#H2i")
    check(hi.engine == "singbox" and hi.tls_unverified and links.kind_of(hi) == "hy2"
          and hi.sb_outbound == {"type": "hysteria2", "server": "h2.example", "server_port": 8443, "password": "p@ss",
                                 "tls": {"enabled": True, "server_name": "s.example", "insecure": True, "alpn": ["h3"]},
                                 "obfs": {"type": "salamander", "password": "op"}},
          f"Hysteria2 с самоподписанным сертификатом — через мост sing-box: {hi.sb_outbound}")
    hp = links.parse_link("hy2://pw@h5.example:443?insecure=1&pinSHA256=" + "ab" * 32 + "#pinned")
    check(hp.engine == "xray" and not hp.tls_unverified
          and "allowInsecure" not in hp.outbound["streamSettings"]["tlsSettings"], "с отпечатком — прямо в Xray")
    v = links.parse_link("vless://71111111-1111-4111-8111-111111111111@self.example:443?type=ws&security=tls&sni=s.example"
                         "&allowInsecure=1#Self")
    check(v.tls_unverified and "allowInsecure" not in json.dumps(v.outbound), "allowInsecure убран из настроек ядра")
    from pult import certpin
    pins: dict = {}
    check(certpin.fill([v, s], pins) == 1 and len(pins[v.key]) == 64, f"отпечаток снят только у нужного: {pins}")
    old = dict(xray.CERT_PINS)
    try:
        xray.CERT_PINS.clear()
        xray.CERT_PINS.update(pins)
        tls = xray.tagged_outbounds(v, "proxy")[0]["streamSettings"]["tlsSettings"]
        check(tls.get("pinnedPeerCertSha256") == pins[v.key] and "allowInsecure" not in tls, f"в ядро — отпечаток: {tls}")
    finally:
        xray.CERT_PINS.clear()
        xray.CERT_PINS.update(old)
    cfg = links.servers_from_json({"outbounds": [{"protocol": "trojan", "settings": {"servers": [
        {"address": "j.example", "port": 443, "password": "p"}]}, "streamSettings": {"security": "tls", "tlsSettings": {
            "serverName": "j.example", "allowInsecure": True}}}]})
    check(cfg[0].tls_unverified and "allowInsecure" not in json.dumps(cfg[0].outbound), "и в JSON-подписках")
    s2 = links.parse_link("hy2://secret@h3.example#Short")
    check(s2.port == 443 and s2.name == "Short", "hy2:// без порта — 443")
    check(not links.parse_link("hy2://x@h.example:443?obfs=gfw#z").supported, "неизвестная маскировка — не поддерживается")
    check(not links.parse_link("hysteria://x@h.example:443#v1").supported, "Hysteria первой версии — нет")
    w = links.parse_link("wireguard://key@wg.example:51820#WG")
    check(not w.supported and "AmneziaWG" in w.note, f"обычный WireGuard: {w.note}")
    t = links.parse_link("tuic://3f1a0000-0000-4000-8000-000000000001:pw@t.example:443?sni=t.example&alpn=h3"
                         "&congestion_control=cubic#T")
    check(t.engine == "singbox" and links.kind_of(t) == "singbox", "TUIC — через мост sing-box")
    check(t.sb_outbound["type"] == "tuic" and t.sb_outbound["uuid"].startswith("3f1a") and t.sb_outbound["password"] == "pw"
          and t.sb_outbound["congestion_control"] == "cubic" and t.sb_outbound["tls"]["server_name"] == "t.example",
          f"TUIC: {t.sb_outbound}")
    a = links.parse_link("anytls://pw2@a.example:443?sni=a.example#A")
    check(a.engine == "singbox" and a.sb_outbound["type"] == "anytls" and a.sb_outbound["password"] == "pw2", "AnyTLS")
    # AmneziaWG: текст конфига целиком → одна строка awg://, обратно — тот же конфиг
    lst = links.text_to_links("# Мой AWG\n" + AWG_CONF)
    check(len(lst) == 1 and lst[0].startswith("awg://"), f"конфиг → awg://: {lst}")
    g = links.parse_link(lst[0])
    check(g.engine == "awg" and g.name == "Мой AWG" and g.address == "awg.example" and g.port == 51820, f"AWG: {g.name} {g.endpoint}")
    check("PrivateKey" in g.awg_conf and not g.note, "конфиг сохранён, маскировка есть")
    plain = links.parse_link(links.awg_link(AWG_CONF.replace("Jc = 4\n", "").replace("S1 = 15\n", "").replace("S2 = 33\n", "")
                                            .replace("H1 = 1844\nH2 = 2981\nH3 = 3110\nH4 = 4129\n", "")
                                            .replace("Jmin = 40\nJmax = 70\n", ""), "plain"))
    check("WireGuard" in plain.note, f"без маскировки — предупреждение: {plain.note}")
    try:
        links.text_to_links("[Interface]\nAddress = 1.2.3.4\n[Peer]\nAllowedIPs = 0.0.0.0/0")
        check(False, "конфиг без ключей принят")
    except links.LinkError:
        pass
    # ключ Amnezia vpn://: внутри AmneziaWG и Xray
    vless_ob = links.parse_link("vless://61111111-1111-4111-8111-111111111111@x.example:443?security=reality&pbk=K"
                                "&sni=a.com&type=tcp#X").outbound
    key = _amnezia_key({"description": "Мой сервер", "containers": [
        {"container": "amnezia-awg", "awg": {"last_config": json.dumps({"config": AWG_CONF})}},
        {"container": "amnezia-xray", "xray": {"last_config": json.dumps({"outbounds": [vless_ob]})}}]})
    got = links.text_to_links(key)
    check(len(got) == 2 and got[0].startswith("awg://") and got[1].startswith("xrayjson://"), f"ключ vpn:// → {got}")
    names = [links.parse_link(x).name for x in got]
    check(names[0] == "Мой сервер" and links.parse_link(got[1]).address == "x.example", f"имена и адрес: {names}")
    try:
        links.text_to_links(_amnezia_key({"containers": [{"container": "amnezia-openvpn"}]}))
        check(False, "пустой ключ принят")
    except links.LinkError as exc:
        check("ни AmneziaWG, ни Xray" in str(exc), str(exc))
    # секреты: ссылки и ключи не попадают в отчёт
    e = type("E", (), {})()
    e.settings = {}
    e.servers = [g, t, s]
    sec = diagnostics.secrets_of(e)
    text = (f"конфиг {g.awg_conf} ссылка {g.link} ключ {key} tuic {t.sb_outbound['password']} {t.sb_outbound['uuid']} "
            f"hy2 {s.link} пароль p@ss")
    out = diagnostics.scrub(text, sec)
    for bad in ("cHJpdmF0ZWtleX", "awg://", "vpn://", "3f1a0000", "awg.example", "hysteria2://", "p@ss"):
        check(bad not in out, f"в отчёте осталось {bad}: {out[:200]}")
    check(i18n.tr("маскировка «x» не поддерживается") == "маскировка «x» не поддерживается", "по-русски без изменений")


@case("Движки: мост sing-box (TUIC), выбор движка, AmneziaWG через помощника с проверкой параметров")
def t_engines():
    from pult import admin_helper, amneziawg, ladder, singbox
    tmp = tempfile.mkdtemp(prefix="pult-selftest-")
    e = None
    try:
        e = make_engine(tmp)
        e.startup()
        _write_tool(e.tun_paths.singbox, FAKE_TOOL)  # sing-box «скачан» (сам файл не запускается: ядро — имитация)
        q = "?security=reality&pbk=K&sni=a.com&type=tcp"
        e.add_servers("\n".join([
            f"vless://71111111-1111-4111-8111-111111111111@fast.example:443{q}#Vless",
            "tuic://72222222-2222-4222-8222-222222222222:pw@tuic.example:443?sni=t.example#Tuic",
            "tuic://73333333-3333-4333-8333-333333333333:pw@dead.example:443?sni=t.example#TuicDead",
            "hysteria2://pw@hy.example:443?sni=h.example#Hy",
        ]))
        e.add_servers("# Дом\n" + AWG_CONF)
        e.add_servers("vless://75555555-5555-4555-8555-555555555555@selfsigned.example:443?type=ws&security=tls"
                      "&sni=s.example&allowInsecure=1#Self")
        wait_idle(e)
        by = {x.name: x for x in e.servers}
        check(set(by) == {"Vless", "Tuic", "TuicDead", "Hy", "Дом", "Self"}, f"серверы: {sorted(by)}")
        SINGBOX_CONFIGS.clear()
        e.test_all()
        check(by["Tuic"].result.get("ok") and not by["TuicDead"].result.get("ok") and by["Hy"].result.get("ok"),
              f"проверка через мост: {by['Tuic'].result} / {by['TuicDead'].result}")
        check(SINGBOX_CONFIGS and {o["type"] for o in SINGBOX_CONFIGS[0]["outbounds"]} >= {"tuic"}, "временный мост sing-box")
        check(not by["Дом"].result, "AmneziaWG не проверяется ядром")
        pin = e.settings["cert_pins"].get(by["Self"].key, "")
        check(by["Self"].result.get("ok") and len(pin) == 64, f"«не проверять сертификат» → отпечаток снят: {by['Self'].result}")
        e.connect(by["Self"])
        with open(e.paths.run_config, encoding="utf-8") as f:
            run_cfg = f.read() if not xray.WIPE_CONFIGS else ""
        check(e.connected and (not run_cfg or (pin in run_cfg and "allowInsecure" not in run_cfg)), "ядро получило отпечаток")
        e.disconnect()
        st = e.state()
        check(st["engine"]["counts"] == {"auto": 5, "xray": 2, "hy2": 1, "singbox": 2, "awg": 1}, f"счёт: {st['engine']}")
        info = {x["name"]: x for x in st["servers"]}
        check(info["Tuic"]["kind"] == "singbox" and info["Дом"]["code"] == "awg" and info["Hy"]["protocol"] == "Hysteria2",
              f"окно: {info['Tuic']['kind']} {info['Дом']['code']} {info['Hy']['protocol']}")
        # движок «sing-box»: только TUIC/AnyTLS; подключение — ядро Xray ведёт в мост
        e.set_engine_pick("singbox")
        check({x.name for x in e.pool()} == {"Tuic", "TuicDead"}, "пул движка")
        target = e.toggle_target()
        check(target is by["Tuic"], f"лучший сервер движка: {target and target.name}")
        e.connect(target)
        HEALTH_PORT["port"] = e.ports["health"]
        check(e.connected and e.bridge.alive() and by["Tuic"].sidecar_port == e.bridge.ports[by["Tuic"].key], "мост поднят")
        check(e._data_ok()["ok"], "данные идут через Xray → мост → TUIC")
        check(not e._hot_swap(by["Vless"]), "через мост — только переподключение, не замена на лету")
        e.connect(by["Vless"])
        fo = e._failover_for(by["Vless"], e.paths.exe_for(by["Vless"]))
        check(fo and e.bridge.alive() == (fo[0]["server"].engine == "singbox"),
              "мост работает, только если запасной сервер внутри ядра — TUIC")
        e.settings["failover"] = False
        e.connect(by["Vless"])
        check(e.connected and not e.bridge.alive(), "мост остановлен, когда не нужен")
        e.settings["failover"] = True
        e.connect(by["Tuic"])
        e.disconnect()
        check(not e.bridge.alive(), "мост выключается вместе с VPN")
        # движок «Xray» и «Авто»: в «Авто» нет AmneziaWG; лестница сначала пробует другой транспорт
        e.set_engine_pick("xray")
        check([x.name for x in e.pool()] == ["Vless", "Self"], f"пул Xray: {[x.name for x in e.pool()]}")
        e.set_engine_pick("auto")
        check("Дом" not in {x.name for x in e.pool()}, "AmneziaWG не входит в «Авто»")
        check(ladder.transport_of(by["Hy"]) == "udp" and ladder.transport_of(by["Vless"]) == "tcp", "транспорт для лестницы")
        # AmneziaWG: помощник с правами проверяет программу и параметры; клиент — имитация
        helper = admin_helper.Helper("t", {}, 0, e.paths.data_dir)
        tunnel = {"on": False, "calls": []}

        def fake_exec(cmd, timeout):
            tunnel["calls"].append(cmd[1:])
            if cmd[1] == "/installtunnelservice":
                with open(cmd[2], encoding="utf-8") as f:
                    tunnel["conf"] = f.read()
                tunnel["on"] = True
            else:
                tunnel["on"] = False
            import subprocess
            return subprocess.CompletedProcess(cmd, 0, b"", b"")

        helper._exec = fake_exec
        helper.awg_exe = lambda: os.path.join(tmp, "AmneziaWG", "amneziawg.exe")
        check(helper.run("xray", ["/installtunnelservice", "x.conf"])["error"] == "запрещённая программа", "только AmneziaWG")
        outside = os.path.join(tmp, "evil.conf")
        with open(outside, "w") as f:
            f.write(AWG_CONF)
        check(not helper.run("awg", ["/installtunnelservice", outside])["ok"], "конфиг вне папки data не принимается")
        check(not helper.run("awg", ["/uninstalltunnelservice", "a b;c"])["ok"], "имя туннеля проверяется")
        check(not helper.run("awg", ["/installtunnelservice", e.awg.conf_path, "x"])["ok"], "лишние параметры")
        os.makedirs(e.awg.folder, exist_ok=True)
        with open(e.awg.conf_path, "w", encoding="utf-8") as f:
            f.write(AWG_CONF + "PostUp = calc.exe\n")
        r = helper.run("awg", ["/installtunnelservice", e.awg.conf_path])
        check(not r["ok"] and "PreUp/PostUp" in r["error"], f"команды в конфиге запрещены: {r}")
        check(not tunnel["calls"], "ни одна запрещённая команда не дошла до клиента")
        e.awg.write_conf(AWG_CONF + "PostUp = calc.exe\n")
        with open(e.awg.conf_path, encoding="utf-8") as f:
            check("PostUp" not in f.read(), "программа сама выкидывает PostUp")
        e.admin.run = lambda kind, args, timeout=40.0: helper.run(kind, args)
        e.awg.client = helper.awg_exe()
        e.awg.running = lambda: tunnel["on"]
        e.connect(by["Vless"])
        e.set_engine_pick("awg")
        check(e.toggle_target() is by["Дом"], "большая кнопка в режиме AmneziaWG")
        e.connect(by["Дом"])  # то же, что «connect» в окне
        check(e.awg_active is by["Дом"] and not e.connected and tunnel["on"], "AmneziaWG включён, Xray выключен")
        e.settings["block_ads"] = True
        check(not e._filter_wanted(), "пока работает AmneziaWG, «Без рекламы» без VPN не запускает ядро")
        e.settings["block_ads"] = False
        check("PrivateKey" in tunnel.get("conf", "") and tunnel["calls"][-1][0] == "/installtunnelservice", "клиент получил конфиг")
        st = e.state()
        check(st["awg"]["active"] == by["Дом"].key and st["awg"]["name"] == "Дом", f"окно: {st['awg']}")
        check(any(x["current"] for x in st["servers"] if x["name"] == "Дом"), "сервер отмечен текущим")
        e.disconnect_awg()
        check(not e.awg_active and not tunnel["on"] and not os.path.exists(e.awg.conf_path), "выключен, ключ стёрт")
        check(tunnel["calls"][-1] == ["/uninstalltunnelservice", amneziawg.TUNNEL], "выключение командой клиента")
        # туннель выключили в самом клиенте — программа это видит
        e.connect_awg(by["Дом"])
        tunnel["on"] = False
        e.awg_watch()
        check(not e.awg_active and any(p["key"] == "awg_down" for p in e.problems_list()), "«AmneziaWG остановился»")
        # клиента нет — понятная ошибка и ссылка на загрузку
        e.awg.client = ""
        e.awg.refresh = lambda: ""
        try:
            e.connect(by["Дом"])
            check(False, "без клиента AmneziaWG — ошибка")
        except RuntimeError as exc:
            check("AmneziaWG для Windows" in str(exc), str(exc))
        check(e.state()["awg"]["client"] is False and "amneziawg-windows-client" in e.state()["awg"]["download"], "ссылка")
        # мост не поднялся (sing-box нет и не скачался) — TUIC честно не подключается, остальное работает
        os.remove(e.tun_paths.singbox)
        e._fetch_any = lambda job, what: (_ for _ in ()).throw(RuntimeError("no network"))
        try:
            e.connect(by["Tuic"])
            check(False, "TUIC без sing-box подключился")
        except RuntimeError as exc:
            check("sing-box" in str(exc), str(exc))
        e.settings["engine_pick"] = "auto"
        e.connect(by["Vless"])
        check(e.connected, "Xray работает и без sing-box")
        e.disconnect()
        check(singbox.bridged([by["Tuic"], by["Vless"]]) == [by["Tuic"]], "кто идёт через мост")
    finally:
        if e:
            e.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)
        HEALTH_PORT.clear()


# ---------- запуск ----------

def run_all() -> dict:
    install_fakes()
    t0 = time.time()
    order = [c for c in CASES if c.__name__ != "t_i18n"] + [c for c in CASES if c.__name__ == "t_i18n"]
    for c in order:
        c()
    failed = [r for r in RESULTS if not r["ok"]]
    return {"total": len(RESULTS), "failed": len(failed), "seconds": round(time.time() - t0, 1), "results": RESULTS}


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    report = run_all()
    if "--json" in sys.argv:
        print(json.dumps(report, ensure_ascii=False))
        return
    for r in report["results"]:
        mark = "OK " if r["ok"] else "ОШИБКА"
        print(f"[{mark}] {r['name']}" + ("" if r["ok"] else f"\n        {r['error']}"))
        if not r["ok"] and os.environ.get("GITHUB_ACTIONS") == "true":
            print(diagnostics.gh_annotation("error", r["name"], r["error"] + "\n" + r.get("trace", "")))
    print(f"\nПройдено {report['total'] - report['failed']} из {report['total']} за {report['seconds']} с.")
    sys.exit(1 if report["failed"] else 0)


if __name__ == "__main__":
    main()
