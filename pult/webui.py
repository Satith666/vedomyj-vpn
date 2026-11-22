"""Локальный веб-сервер интерфейса: страницы, API для действий и поток событий (SSE).
Слушает только 127.0.0.1 и требует секретный токен, поэтому другие сайты и программы им управлять не могут."""

from __future__ import annotations

import json
import mimetypes
import os
import queue
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import protect, autostart, errorlog, happ, i18n, links, qr, routing, share, subscription, tester

STATIC = {"/": "index.html", "/index.html": "index.html", "/style.css": "style.css", "/app.js": "app.js",
          "/i18n.js": "i18n.js"}
ICON_RE = __import__("re").compile(r"^/icons/([a-z]+)\.svg$")


class UIServer:
    def __init__(self, ui_dir: str, token: str):
        self.ui_dir = ui_dir
        self.token = token
        self.engine = None
        self.clients: set[queue.Queue] = set()
        self.lock = threading.Lock()
        self.had_client = False
        self.last_client_change = time.monotonic()
        self.exit_event = threading.Event()
        self.httpd: ThreadingHTTPServer | None = None
        self.port = 0
        # пин-код на окно: пока не введён — интерфейс не получает ни настроек, ни журнала, ни действий
        self.unlocked = False
        self.restart = False
        self.last_action = time.monotonic()
        self._pin_fails = 0
        self._pin_wait_until = 0.0

    # ---------- пин-код ----------

    def pin_set(self) -> bool:
        return bool(self.engine is not None and self.engine.settings.get("pin_hash"))

    def is_locked(self) -> bool:
        return self.pin_set() and not self.unlocked

    def lock_window(self) -> None:
        if self.pin_set() and self.unlocked:
            self.unlocked = False
            self.notify("lock", locked=True)

    @staticmethod
    def pin_hash(pin: str, salt: str) -> str:
        import hashlib
        return hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), bytes.fromhex(salt), 200_000).hex()

    def check_pin(self, pin: str) -> bool:
        import hmac
        st = self.engine.settings
        return hmac.compare_digest(self.pin_hash(pin, st.get("pin_salt") or "00"), st.get("pin_hash") or "")

    # ---------- события ----------

    def notify(self, event: str, **data) -> None:
        if event not in ("lock", "unlocked") and self.is_locked():
            return  # окно заблокировано пин-кодом — ничего не рассказываем
        if event == "live" and self.engine is not None:
            data = {"live": dict(self.engine.live), "connected": self.engine.connected}
        elif event == "busy" and self.engine is not None:
            data = dict(data)
        msg = json.dumps({"event": event, "data": data}, ensure_ascii=False, default=str)
        with self.lock:
            clients = list(self.clients)
        for q in clients:
            try:
                q.put_nowait(msg)
            except queue.Full:
                pass

    def client_count(self) -> int:
        with self.lock:
            return len(self.clients)

    # ---------- сервер ----------

    def start(self) -> int:
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _host_ok(self) -> bool:
                host = (self.headers.get("Host") or "").split(":")[0]
                return host in ("127.0.0.1", "localhost")

            def _token_ok(self, query: dict) -> bool:
                return self.headers.get("X-Token") == server.token or query.get("t", [""])[0] == server.token

            def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def _json(self, obj, code: int = 200):
                self._send(code, json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8"),
                           "application/json; charset=utf-8")

            def do_GET(self):
                if not self._host_ok():
                    return self._send(403, b"forbidden", "text/plain")
                parts = urlsplit(self.path)
                query = parse_qs(parts.query)
                path = parts.path
                icon_m = ICON_RE.match(path)
                if path in STATIC or icon_m:
                    rel = STATIC[path] if path in STATIC else os.path.join("icons", icon_m.group(1) + ".svg")
                    fp = os.path.join(server.ui_dir, rel)
                    try:
                        with open(fp, "rb") as f:
                            body = f.read()
                    except OSError:
                        return self._send(404, b"not found", "text/plain")
                    ctype = mimetypes.guess_type(fp)[0] or "application/octet-stream"
                    if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml"):
                        ctype += "; charset=utf-8"
                    csp = ("default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                           "connect-src 'self'; script-src 'self'; frame-ancestors 'none'")
                    return self._send(200, body, ctype, {"Content-Security-Policy": csp})
                if not self._token_ok(query):
                    return self._send(403, b"forbidden", "text/plain")
                engine = server.engine
                if path == "/api/ping":
                    return self._json({"ok": True})
                if server.is_locked() and path != "/api/events":
                    if path == "/api/state":
                        return self._json({"locked": True, "lang": engine.settings.get("lang", "ru"),
                                           "theme": engine.settings.get("theme", "auto"),
                                           "pin_wait": max(0, round(server._pin_wait_until - time.monotonic()))})
                    return self._json({"locked": True})
                if path == "/api/state":
                    return self._json(engine.state())
                if path == "/api/connections":
                    return self._json(engine.connections_list())
                if path == "/api/logs":
                    return self._json(engine.logs_view())
                if path == "/api/events":
                    return self._sse()
                return self._send(404, b"not found", "text/plain")

            def _sse(self):
                q: queue.Queue = queue.Queue(maxsize=1000)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                with server.lock:
                    server.clients.add(q)
                    server.had_client = True
                    server.last_client_change = time.monotonic()
                try:
                    self.wfile.write(b": hello\n\n")
                    self.wfile.flush()
                    while not server.exit_event.is_set():
                        try:
                            msg = q.get(timeout=10)
                            self.wfile.write(f"data: {msg}\n\n".encode("utf-8"))
                        except queue.Empty:
                            self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                except (OSError, ValueError):
                    pass
                finally:
                    with server.lock:
                        server.clients.discard(q)
                        server.last_client_change = time.monotonic()
                    self.close_connection = True

            def do_POST(self):
                if not self._host_ok() or not self._token_ok({}):
                    return self._send(403, b"forbidden", "text/plain")
                if urlsplit(self.path).path != "/api/action":
                    return self._send(404, b"not found", "text/plain")
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    payload = json.loads(self.rfile.read(min(length, 2 * 1024 * 1024)) or b"{}")
                    action = str(payload.get("action", ""))
                    args = payload.get("args") or {}
                    result = server.dispatch(action, args)
                    self._json({"ok": True, "result": result})
                except ActionError as exc:
                    self._json({"ok": False, "error": i18n.tr(str(exc))})
                except Exception as exc:  # ошибка внутри действия — показываем текст
                    if server.engine and errorlog.is_bug(exc):
                        server.engine.errors.record_exc(exc, f"действие: {action}")
                    self._json({"ok": False, "error": i18n.tr(str(exc)) or exc.__class__.__name__})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self.port

    def stop(self) -> None:
        self.exit_event.set()
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()

    # ---------- действия ----------

    def dispatch(self, action: str, a: dict):
        e = self.engine
        if action == "unlock":
            return self._unlock(str(a.get("pin", "")))
        if self.is_locked() and action not in ("set_ui",):
            raise ActionError("Программа заблокирована — введи пин-код.")
        self.last_action = time.monotonic()
        if action in ("pin_set", "pin_remove"):
            return self._pin_change(action, a)

        def task(title, func, *args):
            """Долгая задача (фоновая очередь)."""
            if not e.run_task(title, func, *args, user=True):
                raise ActionError(f"Подожди: сейчас выполняется «{e.busy_text}».")
            return True

        def vpn_task(title, func, *args):
            """Действие с VPN (подключить, отключить, сменить сервер, применить настройки) — своя очередь:
            не ждёт долгих задач вроде подбора zapret или скачивания списков."""
            if not e.run_task(title, func, *args, lane="conn", user=True):
                raise ActionError(f"Подожди: сейчас выполняется «{e.conn_text}».")
            return True

        if action == "auto":
            if not e.settings["subscriptions"] and not e.servers:
                raise ActionError("Сначала добавь подписку.")
            return task("Автонастройка", e.auto_setup)
        if action == "add_sub":
            url = str(a.get("url", "")).strip()
            if not url:
                raise ActionError("Вставь ссылку на подписку.")
            if not subscription.looks_like_server_link(url):
                try:
                    subscription.normalize_url(url)  # понятная ошибка сразу, без ожидания
                except subscription.SubscriptionError as exc:
                    raise ActionError(str(exc)) from exc
            return task("Добавляю подписку", e.add_subscription, url, str(a.get("name", "")))
        if action == "update_sub":
            return task("Обновляю подписки", e.update_subscription, a.get("id") or None)
        if action == "remove_sub":
            e.remove_subscription(str(a.get("id")))
            return True
        if action == "rename_sub":
            e.rename_subscription(str(a.get("id")), str(a.get("name", "")))
            return True
        if action == "sub_link":
            meta = e._sub_meta(str(a.get("id")))
            if not meta:
                raise ActionError("Подписка не найдена.")
            return meta["url"]
        if action == "add_servers":
            return e.add_servers(str(a.get("text", "")))
        if action == "remove_server":
            e.remove_server(str(a.get("key")))
            return True
        if action == "test":
            servers = e.servers
            if a.get("sub"):
                servers = [s for s in e.servers if s.sub_id == a["sub"]]
            if a.get("key"):
                servers = [s for s in e.servers if s.key == a["key"]]
            if not servers:
                raise ActionError("Нет серверов для проверки — сначала добавь подписку.")
            return task("Проверяю серверы", e.test_all, servers)
        if action == "speed_top":
            return task("Замеряю скорость", e.speed_top, 3)
        if action == "speed_current":
            return task("Замеряю скорость подключения", e.speed_current)
        if action == "direct_ping":
            return task("Пинг без VPN", e.direct_ping)
        if action == "connect":
            srv = e.find(str(a.get("key", "")))
            if not srv:
                raise ActionError("Сервер не найден — обнови подписку.")
            if not srv.supported:
                raise ActionError(f"Этот сервер не поддерживается: {srv.note}")
            # выбор сервера в списке — это способ «VPN-сервер» (или AmneziaWG для его конфига)
            want = "awg" if srv.engine == "awg" else "server"
            if e.method() != want:
                e.set_method(want)
            return vpn_task("Подключаюсь", e.connect, srv)
        if action == "method":
            m = str(a.get("method", ""))
            if m == "awg" and not e.awg_servers():
                raise ActionError("Сначала добавь конфиг AmneziaWG: кнопка «+» над списком серверов → вставь текст "
                                  ".conf или ключ vpn://.")
            if m == "server" and not any(s.supported and s.engine != "awg" for s in e.servers):
                raise ActionError("Сначала добавь подписку или нажми «Автонастройка».")
            was_awg = bool(e.awg_active)
            e.set_method(m)
            if m == "off":
                if e.connected or e.awg_active or e.dpi_supported:
                    return vpn_task("Выключаю VPN, включаю ускорение", e.method_off)
                return True
            if m == "awg" and e.connected:
                srv = e.toggle_target()
                if srv:
                    return vpn_task("Подключаюсь", e.connect, srv)
            if m in ("auto", "server") and was_awg:
                srv = e.toggle_target()
                if srv:
                    return vpn_task("Подключаюсь", e.connect_start, srv)
            return True
        if action == "accel":
            if a.get("on"):
                return task("Включаю ускорение YouTube и Discord", e.accel_on)
            return task("Выключаю ускорение", e.accel_off)
        if action == "toggle" and e.method() == "off" and not (e.connected or e.awg_active or e.kill_on):
            # «Без VPN»: большая кнопка включает и выключает ускорение
            if e.dpi_mode:
                return task("Выключаю ускорение", e.accel_off)
            return task("Включаю ускорение YouTube и Discord", e.accel_on)
        if action == "toggle":
            if e.awg_active:
                return vpn_task("Отключаюсь", e.disconnect_awg)
            if e.connected or e.kill_on:  # kill switch: кнопка открывает интернет без VPN
                return vpn_task("Отключаюсь", e.disconnect)
            srv = e.toggle_target()
            if not srv and e.servers and e.settings.get("engine_pick", "auto") != "auto":
                # у выбранного способа или движка нет серверов (например, AmneziaWG без конфига) — не ошибка
                # на каждое нажатие, а «Авто» с обычными серверами
                e.settings["engine_pick"] = "auto"
                e.set_method("auto")
                srv = e.toggle_target()
                if srv:
                    e.notify("info", text="Для выбранного способа нет серверов — подключаюсь в режиме «Авто».")
            if not srv:
                raise ActionError("Сначала добавь подписку или нажми «Автонастройка».")
            return vpn_task("Подключаюсь", e.connect_start, srv)
        if action == "engine_pick":
            pick = str(a.get("pick", ""))
            e.set_engine_pick(pick)
            cur = e.current if e.connected else e.awg_active
            if cur and pick != "auto" and links.kind_of(cur) != pick:
                srv = e.toggle_target()  # подключено через другой движок — переходим на выбранный
                if srv:
                    return vpn_task("Подключаюсь", e.connect, srv)
            return True
        if action == "wl_set":
            on = bool(a.get("on"))
            before = {"wl_priority": bool(e.settings.get("wl_priority"))}
            srv = e.wl_set(on)
            if srv:
                e.guard_change(before, protect.change_label(before))
                return vpn_task("Подключаюсь", e.connect, srv)
            return True
        if action == "nw_targets":
            return e.nw_targets()
        if action == "nw_fix":
            kind = str(a.get("kind", ""))
            title = {"service": "Проверяю сервис", "app": "Проверяю программу", "site": "Проверяю сайт"}.get(kind, "Проверяю")
            return task(title, e.nw_fix, kind, str(a.get("value", ""))[:300], str(a.get("target", "")))
        if action == "nw_undo":
            return task("Возвращаю маршруты как было", e.nw_undo)
        if action == "connect_for":
            return vpn_task("Подключаюсь", e.connect_for, int(a.get("minutes", 60) or 60))
        if action == "disconnect":
            if e.awg_active:
                return vpn_task("Отключаюсь", e.disconnect_awg)
            return vpn_task("Отключаюсь", e.disconnect)
        if action == "set_mode":
            return vpn_task("Меняю режим", e.set_mode, str(a.get("mode")))
        if action == "check_services":
            e.service_results = {}
            return task("Проверяю сервисы", e.check_services)
        if action == "autofix":
            if not e.connected:
                raise ActionError("Сначала подключись и проверь сервисы.")
            if not e.service_results:
                raise ActionError("Сначала нажми «Проверить сервисы».")

            def fix():
                changes = e.autofix()
                if changes:
                    e.check_services()
                    e.notify("summary", text="Исправлено: " + ", ".join(changes) + ".")
                else:
                    e.notify("summary", text="Исправлять нечего: всё, что можно открыть, уже открывается.")
            return task("Исправляю маршруты", fix)
        if action == "save_routing":
            bad = []
            for key in ("proxy_list", "direct_list", "block_list"):
                value = str(a.get(key, "")).strip()
                bad += routing.split_entries(value)[2]
                e.settings[key] = value
            guard_before = {k: e.settings.get(k) for k in ("mode", "ru_direct")}
            if a.get("mode") in routing.MODES:
                e.settings["mode"] = a["mode"]
            if "ru_direct" in a:
                e.settings["ru_direct"] = bool(a["ru_direct"])
            e.save()
            if e.core_running:
                changed = {k: v for k, v in guard_before.items() if e.settings.get(k) != v}
                if changed:
                    e.guard_change(changed, protect.change_label(changed))
                vpn_task("Применяю маршрутизацию", e.reconnect)
            e.notify("settings")
            return {"bad": list(dict.fromkeys(bad))}
        if action == "route_site":
            # сайт → через VPN / напрямую / блок / обход замедления / другой сервер / свой прокси / как по умолчанию.
            # Сайты из журнала соединений сводятся к основному домену, адрес из формы берётся как есть.
            target = str(a.get("target", ""))
            hosts = [str(h) for h in (a.get("hosts") or [a.get("host")]) if h][:200]
            if not hosts:
                raise ActionError("Вставь адрес сайта, например example.com.")
            entries, dpi_changed = [], False
            for h in hosts:
                entry, changed = e.route_site(h, target, main_domain=not a.get("exact"))
                entries.append(entry)
                dpi_changed = dpi_changed or changed
            if e.core_running or dpi_changed:
                vpn_task("Применяю маршрут", e.apply_routes, dpi_changed)
            return sorted(set(entries))
        if action == "reset_site":
            removed = e.reset_site(str(a.get("host", "")))
            if removed and e.core_running:
                vpn_task("Применяю маршрут", e.reconnect)
            return removed
        if action == "reset_rules":
            key = a.get("list") or None
            if key and key not in ("proxy_list", "direct_list", "block_list"):
                raise ActionError("Неизвестный список.")
            e.reset_rules(key)
            if e.core_running:
                vpn_task("Применяю маршрутизацию", e.reconnect)
            return True
        if action == "clear_traffic":
            e.connections.clear()
            return True
        if action == "update_geo":
            return task("Обновляю списки сайтов", e.update_geo)
        if action == "update_xray":
            return task("Обновляю ядро Xray", e.update_xray)
        if action == "update_all":
            return task("Обновляю всё", e.update_all)
        if action == "save_settings":
            return self._save_settings(a, task, vpn_task)
        if action == "set_ui":
            if a.get("theme") in ("auto", "dark", "light"):
                e.settings["theme"] = a["theme"]
            for key in ("sort", "collapsed", "icon"):
                if key in a:
                    e.settings[key] = a[key]
            if a.get("lang") in ("ru", "en"):
                e.settings["lang"] = a["lang"]
                i18n.set_lang(a["lang"])
                e.notify("servers")
            e.save()
            return True
        if action == "service_route":
            dpi_changed = e.set_service_route(str(a.get("name", "")), str(a.get("target", "auto")))
            if e.core_running or dpi_changed:
                vpn_task("Применяю маршрут", e.apply_routes, dpi_changed)
            return True
        # свои прокси (SOCKS5 / HTTP) — для отдельных сервисов и сайтов
        if action == "add_proxy":
            kind = str(a.get("type", "auto"))
            p = e.add_proxy(str(a.get("url", "")), str(a.get("name", "")), kind if kind in ("socks", "http") else "auto",
                            bool(a.get("chain", True)))
            if not e.is_busy():
                e.run_task("Проверяю прокси", e.check_proxy, p["id"])
            return p
        if action == "check_proxy":
            return task("Проверяю прокси", e.check_proxy, str(a.get("id", "")))
        if action == "update_proxy":
            reconnect = e.update_proxy(str(a.get("id", "")), a.get("name"), a.get("chain"))
            if reconnect and e.core_running:
                vpn_task("Применяю маршрут", e.reconnect)
            return True
        if action == "ads_set":
            changes = {k: a[k] for k in ("enabled", "without_vpn", "level", "lists", "custom", "allow", "dns_system",
                                         "dns_home") if k in a}
            need_download, need_apply = e.set_ads(**changes)
            if need_download and e.settings.get("block_ads"):
                task("Скачиваю списки рекламы", e.update_adblock, True, "level" in changes or "lists" in changes)
            elif need_apply:
                def rebuild():
                    if e.settings.get("block_ads"):
                        e.build_adblock()
                    e.apply_ads()
                task("Применяю блокировку рекламы", rebuild)
            return e.ads_state()
        if action == "ads_update":
            return task("Скачиваю списки рекламы", e.update_adblock)
        # автоподбор для сайтов
        if action == "auto_flags":
            names = {"auto_routes": "Автоподбор для сайтов", "auto_stall": "Проверка, догружаются ли сайты",
                     "auto_ask_direct": "Вопрос «сайт не открывается через VPN»",
                     "cert_watch": "Слежка за подменой сертификатов",
                     "ads_ask_sites": "Вопрос «сайт закрыт блокировщиком»", "failover": "Мгновенное переключение",
                     "sub_alerts": "Предупреждения о подписке", "hotkey_enabled": "Горячая клавиша",
                     "kill_switch": "Kill switch", "net_profiles": "Профили сетей",
                     "app_update": "Автообновление программы", "smart_notices": "Умные уведомления",
                     "fp_auto": "Подбор отпечатка TLS", "data_watch": "Сторож данных", "net_memory": "Память сетей"}
            for key in e.AUTO_FLAGS:
                if key in a:
                    e.settings[key] = bool(a[key])
                    e.log(f"{names.get(key, key)}: " + ("включено." if a[key] else "выключено."))
            e.save()
            if "failover" in a and e.connected:
                vpn_task("Применяю настройки", e.reconnect)
            if "sub_alerts" in a:
                e._sub_alerts()
            if "net_profiles" in a:
                e._net_sig = None
                e._net_watch()
            if "fp_auto" in a and not a["fp_auto"]:
                had = bool(e.current and (e.current.result or {}).get("fp"))
                for srv in e.servers:  # подобранные отпечатки больше не нужны — как в ссылке
                    if srv.result and "fp" in srv.result:
                        srv.result = {k: v for k, v in srv.result.items() if k != "fp"}
                if had and e.connected:
                    vpn_task("Применяю настройки", e.reconnect)
            e.notify("settings")
            return True
        if action == "secure_set":
            e.settings["encrypt_data"] = bool(a.get("on"))
            e.save()  # сразу перезаписываем: секреты шифруются или, наоборот, лежат открыто
            for meta in e.settings.get("subscriptions") or []:
                sub = e.sub_objs.get(meta["id"])
                if sub is not None:
                    from . import secure
                    with open(e._sub_cache(meta["id"]), "w", encoding="utf-8") as f:
                        f.write(secure.encode(sub.raw) if e.settings["encrypt_data"] else sub.raw)
            from . import xray as _x, secure as _s
            _x.WIPE_CONFIGS = _s.IS_WINDOWS and e.settings["encrypt_data"]
            e.log("Шифрование данных включено." if e.settings["encrypt_data"] else "Шифрование данных выключено.")
            e.notify("settings")
            return True
        if action == "app_update_check":
            return task("Проверяю обновление программы", e.app_update_check)
        if action == "restart_app":
            self.restart = True  # main.py запустит программу заново (и поставит скачанное обновление)
            self.exit_event.set()
            return True
        if action == "cert_check":
            return task("Проверяю сертификаты", e.cert_check)
        if action == "cert_ack":
            e.cert_ack()
            return True
        if action == "ladder_retry":
            if not e.servers:
                raise ActionError("Список серверов пуст — сначала обнови подписку.")
            return vpn_task("Ищу рабочий способ", e.ladder_retry_now)
        if action == "data_check":
            return vpn_task("Проверяю, идут ли данные", e.data_check_now)
        if action == "health_check":
            return task("Проверяю всё", e.health_check)
        if action == "net_memory_clear":
            e.net_memory_clear()
            e.notify("settings")
            return True
        if action == "leak_test":
            return task("Проверяю утечки", e.leak_test)
        if action == "net_mark":
            kind = str(a.get("kind", ""))
            if kind not in ("home", "public"):
                raise ActionError("Неизвестное действие.")
            return e.net_mark(kind)
        if action == "net_forget":
            ssid = str(a.get("ssid", ""))
            e.settings["net_trusted"] = [x for x in e.settings.get("net_trusted") or [] if x != ssid]
            e.settings["net_untrusted"] = [x for x in e.settings.get("net_untrusted") or [] if x != ssid]
            e.save()
            e._net_watch()
            e.notify("settings")
            return True
        if action == "hotkey_set":
            from . import tray
            text = " ".join(str(a.get("value", "")).split())[:30]
            if not tray.parse_hotkey(text):
                raise ActionError("Так не получится. Пример: Ctrl+Alt+V или Ctrl+Shift+F9.")
            e.settings["hotkey"] = "+".join(p[:1].upper() + p[1:].lower() if len(p) > 1 else p.upper()
                                            for p in text.replace(" ", "").split("+"))
            e.settings["hotkey_enabled"] = True
            e.save()
            e.log(f"Горячая клавиша: {e.settings['hotkey']}.")
            e.notify("settings")
            return e.settings["hotkey"]
        if action == "auto_set":
            e.settings["auto_routes"] = bool(a.get("on"))
            e.save()
            e.log("Автоподбор для сайтов включён." if e.settings["auto_routes"] else "Автоподбор для сайтов выключен.")
            e.notify("settings")
            return True
        if action == "auto_forget":
            e.auto_forget(str(a.get("site", "")), pin=bool(a.get("pin")))
            if e.core_running:
                vpn_task("Применяю маршрут", e.reconnect)
            return True
        if action == "auto_clear":
            e.auto_clear()
            if e.core_running:
                vpn_task("Применяю маршрут", e.reconnect)
            return True
        if action == "ads_lookup":
            return e.ads_lookup(str(a.get("host", "")))
        if action == "ads_allow":
            entry = e.ads_allow(str(a.get("host", "")))

            def rebuild_allow():
                e.build_adblock()
                e.apply_ads()
            task("Применяю блокировку рекламы", rebuild_allow)
            return entry
        if action == "ads_site":
            allow = bool(a.get("allow"))
            entry = e.ads_site_answer(str(a.get("site", "")), allow)
            if allow:
                def rebuild_site():
                    e.build_adblock()
                    e.apply_ads()
                task("Применяю блокировку рекламы", rebuild_site)
            return entry
        if action == "vpn_site":
            # ответ на «сайт не открывается через VPN»: напрямую (своё правило) или оставить как есть
            direct = bool(a.get("direct"))
            try:
                entry = e.vpn_site_answer(str(a.get("site", "")), direct)
            except RuntimeError as exc:
                raise ActionError(str(exc)) from exc
            if direct and e.core_running:
                vpn_task("Применяю маршрут", e.apply_routes, False)
            return entry
        if action == "ads_pause":
            e.ads_pause(int(a.get("minutes", 0) or 0))
            vpn_task("Применяю блокировку рекламы", e.apply_ads)
            return True
        if action == "proxy_report":
            # страница проверки IP прокси (насколько он «засвечен») — адрес берётся только из результата проверки
            import ipaddress
            import webbrowser
            p = e._proxy_by_id(str(a.get("id", "")))
            ip = ((p or {}).get("check") or {}).get("ip", "")
            try:
                ipaddress.ip_address(ip)
            except ValueError as exc:
                raise ActionError("Сначала проверь прокси.") from exc
            webbrowser.open(f"https://scamalytics.com/ip/{ip}")
            return True
        if action == "remove_proxy":
            if e.remove_proxy(str(a.get("id", ""))) and e.core_running:
                vpn_task("Применяю маршрут", e.reconnect)
            return True
        if action == "check_site":
            return task("Проверяю сайт", e.check_site, str(a.get("url", "")))
        if action == "apps_scan":
            return e.apps_scan()
        if action == "app_route":
            name = e.set_app_route(str(a.get("name", "")), str(a.get("target", "auto")))
            if e.core_running:
                vpn_task("Применяю маршрут", e.reconnect)
            return name
        if action == "app_pick":
            def pick_and_apply(name):
                e.pick_app(name)
                if e.core_running:
                    e.reconnect()
            return task("Подбираю путь для приложения", pick_and_apply, str(a.get("name", "")))
        if action == "torrent_set":
            v = str(a.get("value", "direct"))
            if v not in ("direct", "proxy", "block"):
                raise RuntimeError("Неизвестное действие.")
            e.settings["torrent_route"] = v
            e.save()
            e.log({"direct": "Торренты: напрямую.", "proxy": "Торренты: через VPN.", "block": "Торренты: заблокированы."}[v])
            e.notify("settings")
            if e.core_running:
                vpn_task("Применяю маршрут", e.reconnect)
            return True
        if action == "repair_site":
            return task("Чиню сайт", e.repair_site, str(a.get("url", "")))
        # обход замедлений YouTube и Discord
        if action == "pick_zapret":
            return task("Подбираю стратегию zapret", e.pick_zapret)
        if action == "pick_byedpi":
            return task("Подбираю стратегию ByeDPI", e.pick_byedpi)
        if action == "check_dpi":
            return task("Проверяю YouTube и Discord", e.check_dpi)
        if action == "update_dpi":
            return task("Обновляю zapret и ByeDPI", e.update_dpi)
        if action == "select_zapret":
            return task("Включаю zapret", e.select_zapret, str(a.get("name", "")))
        if action == "select_byedpi":
            return task("Включаю ByeDPI", e.select_byedpi, str(a.get("args", "")))
        if action == "test_byedpi_custom":
            return task("Проверяю свою стратегию ByeDPI", e.test_byedpi_custom, str(a.get("args", "")))
        if action == "stop_dpi":
            return task("Выключаю обход замедлений", e.stop_dpi)
        if action == "set_dpi":
            vals = {k: a[k] for k in ("zapret_enabled", "dpi_youtube", "dpi_discord", "byedpi_role", "dpi_custom")
                    if k in a}
            if e.set_dpi(vals):
                st = e.settings
                # включили способ, для которого ещё не подобрана стратегия — сразу подбираем
                need = (st.get("zapret_enabled") and not st.get("zapret_strategy")) or \
                    (st.get("byedpi_role") != "off" and not st.get("byedpi_strategy"))
                if need and e.dpi_supported:
                    return task("Подбираю стратегию", e.setup_dpi)
                if not e.is_busy():
                    task("Включаю обход замедлений", e.start_dpi, True)
            return True
        if action == "run_check":
            return task("Проверка программы", e.run_check)
        if action == "problem_report":
            return e.problem_report()
        if action == "dismiss_problem":
            e.resolve(str(a.get("key", "")))
            return True
        if action == "happ_link":
            return e.happ_link()
        if action == "telegram_proxy":
            # ссылка tg://socks заставляет Telegram предложить «Включить прокси» в один клик
            link = f"tg://socks?server=127.0.0.1&port={int(e.settings['socks_port'])}"
            opened = False
            try:
                if sys.platform == "win32":
                    os.startfile(link)  # type: ignore[attr-defined]
                    opened = True
            except OSError:
                opened = False
            if not e.connected:
                e.log("Прокси для Telegram заработает, когда программа подключена к VPN.")
            return {"link": link, "opened": opened}
        if action == "happ_open":
            link = e.happ_link()
            try:
                happ.open_link(link)
            except OSError as exc:
                raise ActionError("Happ не открылся. Скопируй ссылку профиля и импортируй её в Happ.") from exc
            return True
        if action == "vps_setup":
            return task("Мастер своего сервера", e.vps_setup, str(a.get("host", "")), a.get("port", 22),
                        str(a.get("user", "root")), str(a.get("name", "")))
        if action == "vps_list":
            return e.vps_view()
        if action == "vps_add":
            return task("Свой сервер: проверка", e.vps_add, str(a.get("host", "")), a.get("port", 22),
                        str(a.get("user", "root")), str(a.get("name", "")))
        if action == "vps_status":
            return task("Свой сервер: проверка", e.vps_status, str(a.get("id", "")))
        if action == "vps_friend_add":
            return task("Свой сервер: ключ для друга", e.vps_friend_add, str(a.get("id", "")), str(a.get("name", "")))
        if action == "vps_friend_remove":
            return task("Свой сервер: удаляю ключ", e.vps_friend_remove, str(a.get("id", "")),
                        str(a.get("friend", "")))
        if action == "vps_forget":
            try:
                e.vps_forget(str(a.get("id", "")))
            except RuntimeError as exc:
                raise ActionError(str(exc)) from exc
            return True
        if action == "hotspot_start":
            return task("Включаю раздачу Wi-Fi", e.hotspot_start)
        if action == "hotspot_stop":
            return task("Выключаю раздачу Wi-Fi", e.hotspot_stop)
        if action == "lan_new_pass":
            e.ensure_lan_credentials(new=True)
            e.notify("settings")
            if e.core_running:
                vpn_task("Применяю настройки", e.reconnect)
            return True
        # перенос настроек и QR-коды
        if action == "export_settings":
            return e.export_settings(bool(a.get("subs")), bool(a.get("servers")))
        if action in ("import_preview", "import_settings"):
            try:
                parsed = share.parse(a.get("data"))
            except ValueError as exc:
                raise ActionError(str(exc)) from exc
            if action == "import_preview":
                return {"settings": len(parsed["settings"]), "subscriptions": len(parsed["subscriptions"]),
                        "servers": len(parsed["servers"]), "skipped": len(parsed["skipped"])}
            return task("Применяю настройки из файла", e.import_settings, parsed)
        if action == "share_items":
            return e.share_items()
        if action == "share_qr":
            try:
                text = e.share_text(str(a.get("id", "")))
                return {"svg": qr.to_svg(qr.make(text)), "text": text}
            except qr.QrTooLong as exc:
                raise ActionError("Слишком длинно для QR-кода — перенеси через файл настроек.") from exc
            except RuntimeError as exc:
                raise ActionError(str(exc)) from exc
        if action == "awg_conf":
            srv = e.find(str(a.get("key", "")))
            if not srv or srv.engine != "awg":
                raise ActionError("Это не конфиг AmneziaWG.")
            return e.awg_conf_text(srv)  # только в окно программы (127.0.0.1 с ключом) — для ручного переноса в AmneziaWG
        if action == "warp_create":
            return vpn_task("Создаю бесплатный WARP", e.warp_start)
        if action == "warp_route":
            # «Через VPN и WARP»: своего WARP нет — программа сначала создаёт его (это запрос в сеть — в фоне)
            if a.get("name"):
                return vpn_task("Включаю WARP после VPN", e.warp_route_set, "svc", str(a["name"]))
            hosts = [str(h) for h in (a.get("hosts") or [a.get("host")]) if h][:200]
            if not hosts:
                raise ActionError("Вставь адрес сайта, например example.com.")
            return vpn_task("Включаю WARP после VPN", e.warp_route_set, "site", hosts, bool(a.get("exact")))
        if action.startswith("family_"):
            return self._family(action, a, task)
        if action == "awg_download":
            import webbrowser
            from . import amneziawg
            webbrowser.open(amneziawg.DOWNLOAD_URL)  # постоянный адрес: страница выпусков клиента AmneziaWG
            return True
        if action == "server_link":
            srv = e.find(str(a.get("key", "")))
            if not srv or not srv.link:
                raise ActionError("У этого сервера нет ссылки (он из JSON-подписки).")
            return srv.link
        if action == "top_links":
            top = [s for s in tester.ranked(e.servers) if s.link][: int(a.get("count", 5))]
            if not top:
                raise ActionError("Сначала проверь серверы.")
            return "\n".join(s.link for s in top)
        if action == "stop":
            e.stop_current()
            return True
        if action == "show_report":
            # показать файл отчёта в Проводнике (его удобно перетащить в Telegram)
            name = str(a.get("name", ""))
            if not re.fullmatch(r"vedomyj-check-\d{8}-\d{6}\.txt", name):
                raise ActionError("Нет такого отчёта.")
            path = os.path.join(e.paths.data_dir, "reports", name)
            if not os.path.isfile(path):
                raise ActionError("Файл отчёта не найден — запусти проверку ещё раз.")
            if sys.platform == "win32":
                subprocess.Popen(f'explorer /select,"{path}"')
            else:
                subprocess.Popen(["xdg-open", os.path.dirname(path)])
            return True
        if action == "errors_list":
            return e.errors_state()
        if action == "errors_issue":
            ids = [str(x) for x in (a.get("ids") or [])][:20] or None
            text = e.errors.issue_text(ids)
            if not text["title"]:
                raise ActionError("Журнал ошибок пуст — сообщать не о чем.")
            repo = e.errors_state()["repo"]
            url = e.errors.issue_url(repo, ids)
            if url and a.get("open"):
                import webbrowser
                webbrowser.open(url)  # адрес собран из проверенного имени репозитория и вычищенного текста
            return dict(text, url=url)
        if action == "errors_clear":
            e.errors.clear()
            e.log("Журнал ошибок очищен.")
            return True
        if action == "errors_repo":
            raw = str(a.get("repo", "")).strip()
            if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", raw):
                raw = "https://github.com/" + raw
            repo = errorlog.repo_from_url(raw)
            if raw and not repo:
                raise ActionError("Нужен адрес вида https://github.com/имя/репозиторий.")
            e.settings["github_repo"] = f"https://github.com/{repo}" if repo else ""
            e.save()
            return repo
        if action == "errors_file":
            path = e.errors.path
            if not os.path.isfile(path):
                raise ActionError("Журнал ошибок пока пуст.")
            if sys.platform == "win32":
                subprocess.Popen(f'explorer /select,"{path}"')
            else:
                subprocess.Popen(["xdg-open", os.path.dirname(path)])
            return True
        # сбор ошибок, профессиональные настройки, предохранители (collect.py, protect.py)
        if action == "collect_start":
            return e.collect_start(a.get("hours", 24))
        if action == "collect_stop":
            return task("Собираю отчёт об ошибках", e.collect_stop)
        if action == "collect_report":
            path = e.settings.get("collect_report") or ""
            if not path or not os.path.isfile(path):
                raise ActionError("Отчёта пока нет: включи «Сбор ошибок» и дождись, пока он закончится.")
            if sys.platform == "win32":
                subprocess.Popen(f'explorer /select,"{path}"')
            else:
                subprocess.Popen(["xdg-open", os.path.dirname(path)])
            return True
        if action == "collect_text":
            path = e.settings.get("collect_report") or ""
            if not path or not os.path.isfile(path):
                raise ActionError("Отчёта пока нет.")
            with open(path, encoding="utf-8") as f:
                return f.read()[:400000]
        if action == "pro_set":
            vals = a.get("values") or {}
            before = {k: e.settings.get(k) for k in vals if k in protect.GUARDED_KEYS}
            e.pro_set(vals)
            e.notify("settings")
            if e.connected and any(k in vals for k in ("failover", "fp_auto", "mask_auto")):
                e.guard_change(before, "профессиональные настройки")
                vpn_task("Применяю настройки", e.reconnect)
            return e.pro_state()
        if action == "pro_reset":
            before = {k: e.settings.get(k) for k in protect.GUARDED_KEYS}
            changed = e.pro_reset()
            e.notify("settings")
            if e.connected and changed:
                e.guard_change(before, "«Вернуть как было»")
                vpn_task("Применяю настройки", e.reconnect)
            return changed
        if action == "fuses_clear":
            e.fuses_clear()
            e.notify("settings")
            return True
        if action == "ads_check":
            return task("Проверяю блокировку рекламы", e.ads_check)
        if action == "ads_apply":
            return vpn_task("Применяю блокировку рекламы", e.apply_ads)
        if action == "monster_open":
            # «Монстр» лежит рядом с программой (extras/monster-adblock), если его положили в архив
            folder = os.path.join(e.paths.app_dir, "extras", "monster-adblock")
            found = os.path.isfile(os.path.join(folder, "manifest.json"))
            if found and a.get("show"):
                if sys.platform == "win32":
                    os.startfile(folder)  # type: ignore[attr-defined]
                else:
                    subprocess.Popen(["xdg-open", folder])
            return {"found": found, "path": folder if found else ""}
        if action == "open_folder":
            if sys.platform == "win32":
                os.startfile(e.paths.app_dir)  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", e.paths.app_dir])
            return True
        if action == "quit":
            threading.Timer(0.3, self.exit_event.set).start()
            return True
        raise ActionError("Неизвестное действие.")

    @staticmethod
    def _qr(text: str) -> str:
        try:
            return qr.to_svg(qr.make(text))
        except qr.QrTooLong:
            return ""  # длинная посылка — только текстом

    def _family(self, action: str, a: dict, task):
        """«Семья»: приглашения и посылки. Секреты в окно не уходят — только тексты приглашений и посылок."""
        from . import family
        e = self.engine
        pair = str(a.get("pair", ""))
        if action == "family_me":
            e.family_set_me(str(a.get("name", "")))
            return True
        if action == "family_invite":
            r = e.family_invite(str(a.get("device", "")))
            return dict(r, svg=self._qr(r["text"]))
        if action == "family_receive":
            return e.family_receive(str(a.get("text", "")))
        if action == "family_accept":
            r = e.family_accept(str(a.get("text", "")), str(a.get("mode", "ask")))
            return dict(r, svg=self._qr(r["reply"]))
        if action == "family_apply":
            return task("Семья: устанавливаю настройки", e.family_apply, pair)
        if action == "family_decline":
            text = e.family_decline(pair)
            return {"text": text, "svg": self._qr(text)}
        if action == "family_send":
            text = e.family_send(pair, a.get("ops"))
            return {"text": text, "svg": self._qr(text)}
        if action == "family_report":
            text = e.family_report_text(pair)
            return {"text": text, "svg": self._qr(text)}
        if action == "family_mode":
            e.family_set_mode(pair, str(a.get("mode", "ask")))
            return True
        if action == "family_remove":
            e.family_remove(pair)
            return True
        if action == "family_qr":
            text = str(a.get("text", ""))
            if not text.startswith((family.INVITE, family.PACKET)):
                raise ActionError("Это не приглашение и не посылка «Семьи».")
            return self._qr(text)
        raise ActionError("Неизвестное действие.")

    def _save_settings(self, a: dict, task, vpn_task):
        e = self.engine
        s = e.settings
        try:
            socks = int(a.get("socks_port", s["socks_port"]))
            http = int(a.get("http_port", s["http_port"]))
            lan_socks = int(a.get("lan_socks_port", s["lan_socks_port"]))
            lan_http = int(a.get("lan_http_port", s["lan_http_port"]))
            hours = float(a.get("auto_update_hours", s["auto_update_hours"]) or 0)
            other_hours = {k: float(a.get(k, s.get(k)) or 0) for k in ("geo_update_hours", "core_update_hours",
                                                                          "dpi_update_hours")}
        except (TypeError, ValueError) as exc:
            raise ActionError("Порты и часы должны быть числами.") from exc
        all_ports = (socks, http, lan_socks, lan_http)
        if len(set(all_ports)) != 4 or not all(1024 <= x < 65536 for x in all_ports):
            raise ActionError("Порты должны быть разными, от 1024 до 65535.")
        for key in ("user_agent", "ping_host", "ping_path"):
            if key in a:
                s[key] = str(a[key]).strip()
        s["user_agent"] = s["user_agent"] or "v2rayN/7.13.8"
        s["ping_host"] = s["ping_host"] or "www.gstatic.com"
        s["ping_path"] = s["ping_path"] or "/generate_204"
        s["auto_update_hours"] = hours
        s.update({k: max(0.0, v) for k, v in other_hours.items()})
        guard_before = {k: s.get(k) for k in protect.GUARDED_KEYS
                        if k in a and k != "block_ads" and s.get(k) != (a[k] if k == "tun_engine" else bool(a[k]))}
        for key in ("system_proxy", "autopilot", "allow_lan", "auto_connect_on_start", "game_mode", "ru_direct",
                    "tun_enabled", "leak_protection", "dns_encrypted", "lan_auth",
                    "mask_auto", "multi_enabled", "whitelist_auto", "background", "block_quic"):
            if key in a:
                s[key] = bool(a[key])
        if a.get("tun_engine") in ("auto", "xray", "singbox", "tun2proxy"):
            s["tun_engine"] = a["tun_engine"]
        if "autostart" in a:
            try:
                autostart.set_enabled(e.paths.app_dir, bool(a["autostart"]))
            except OSError as exc:
                raise ActionError(f"Не удалось изменить автозапуск: {exc}") from exc
            s["autostart"] = bool(a["autostart"])
        e.ensure_lan_credentials()
        lan_changed = (lan_socks, lan_http) != (s["lan_socks_port"], s["lan_http_port"])
        s.update(lan_socks_port=lan_socks, lan_http_port=lan_http)
        ports_changed = (socks, http) != (s["socks_port"], s["http_port"]) or (lan_changed and s.get("allow_lan"))
        ads_download = False
        if "block_ads" in a:  # плитка «Без рекламы»: включает и блокировку без VPN
            ads_download, _ = e.set_ads(enabled=bool(a["block_ads"]))
        if e.core_running and ports_changed:
            server = e.current if e.connected else None

            def job():
                with e._conn_lock:  # смена портов — целиком, без вмешательства фоновых задач
                    e.disconnect(keep_filter=False)
                    s.update(socks_port=socks, http_port=http)
                    if server:
                        e.connect(server)
                    elif e._filter_wanted():
                        e.start_filter()
            vpn_task("Меняю порты", job)
        else:
            s.update(socks_port=socks, http_port=http)
            e.save()
            if ads_download:
                task("Скачиваю списки рекламы", e.update_adblock)
            elif e.core_running or e._filter_wanted():
                if guard_before:
                    e.guard_change(guard_before, protect.change_label(guard_before))
                vpn_task("Применяю настройки", e.reconnect)
        e.notify("settings")
        return True


    def _unlock(self, pin: str):
        if not self.pin_set():
            self.unlocked = True
            return True
        now = time.monotonic()
        if now < self._pin_wait_until:
            raise ActionError(f"Слишком много попыток. Подожди {round(self._pin_wait_until - now)} с.")
        if not self.check_pin(pin):
            self._pin_fails += 1
            if self._pin_fails >= 5:  # перебор: пауза растёт — 30 с, 60 с, 120 с…
                self._pin_wait_until = now + 30 * 2 ** min(self._pin_fails - 5, 6)
            raise ActionError("Неверный пин-код.")
        self._pin_fails = 0
        self.unlocked = True
        self.last_action = now
        self.notify("unlocked")
        return True

    def _pin_change(self, action: str, a: dict):
        import secrets as _secrets
        e = self.engine
        st = e.settings
        if self.pin_set() and not self.check_pin(str(a.get("old", ""))):
            raise ActionError("Текущий пин-код неверный.")
        if action == "pin_remove":
            st["pin_hash"], st["pin_salt"] = "", ""
            e.save()
            e.log("Пин-код снят.")
            e.notify("settings")
            return True
        pin = str(a.get("pin", ""))
        if not (pin.isdigit() and 4 <= len(pin) <= 12):
            raise ActionError("Пин-код — от 4 до 12 цифр.")
        salt = _secrets.token_hex(16)
        st["pin_salt"], st["pin_hash"] = salt, self.pin_hash(pin, salt)
        st["pin_lock_minutes"] = max(0, min(int(a.get("minutes", st.get("pin_lock_minutes", 0)) or 0), 240))
        e.save()
        self.unlocked = True
        e.log("Пин-код установлен: окно программы открывается только с ним.")
        e.notify("settings")
        return True


class ActionError(RuntimeError):
    pass
