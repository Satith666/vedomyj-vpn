"""Мозг программы: подписка, тесты, подключение, автопилот, автонастройка. Без интерфейса — только события."""

from __future__ import annotations

import collections
import ipaddress
import json
import os
import re
import secrets
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit, quote

from . import (APP_VERSION, adblock, amneziawg, apps, certcheck, certpin, countries, errorlog, ladder, leaks, netprofile, secure, update, dpi, elevated, happ, hotspot, i18n, netutil, proxies, routing,
               services, share, singbox, subscription, sysproxy, tester, tun, vps, xray)
from . import links
from .links import Server, is_private_host, parse_link
from .settings import Settings
from .xray import Paths, XrayError, XrayProcess


class Busy(RuntimeError):
    pass


class Cancelled(RuntimeError):
    """Человек нажал «Стоп»."""


class Engine(ladder.LadderMixin, amneziawg.AwgMixin):
    """События для интерфейса (notify(event, **data)) приходят из рабочих потоков:
    log, busy, servers, server, status, live, connections, services, service, summary, error, settings."""

    def __init__(self, app_dir: str, notify):
        self.paths = Paths(app_dir)
        self.settings = Settings(os.path.join(self.paths.data_dir, "settings.json"))
        if not self.settings.get("hwid"):
            # постоянный идентификатор этой программы для провайдера (как HWID у Happ)
            self.settings["hwid"] = secrets.token_hex(16)
        i18n.set_lang(self.settings.get("lang", "ru"))
        self._raw_notify = notify
        # журнал ошибок (data/errors.jsonl): падения кода, проблемы, итоги проверок — без ключей и адресов
        self.errors = errorlog.ErrorLog(self.paths.data_dir, scrub=self._scrub_secrets, app_dir=self.paths.app_dir)
        self._ladder_init()
        self.problems: dict[str, dict] = {}
        self._standby_at = 0.0
        self._slow_count = 0
        self._hotswap_ok = True
        self.servers: list[Server] = []
        self.sub_objs: dict[str, subscription.Subscription] = {}
        self.sub_errors: dict[str, str] = {}
        self._dns_seen: dict[str, tuple[float, str]] = {}  # имя сервера → (когда проверено, адрес из защищённого DNS)
        self.ui_clients = 1  # сколько окон программы открыто (обновляет main.py); 1 — пока не знаем
        self.xray_ver: str | None = None
        self.current: Server | None = None
        self.connected = False
        # блокировка рекламы без VPN: ядро работает без сервера (реклама блокируется, остальное напрямую)
        self.filter_on = False
        self.kill_on = False  # kill switch: VPN сломался, «через VPN» закрыто, пока он не заработает
        self._kill_at = 0.0
        self.net_profile: dict = {}  # профиль текущей сети (см. «Профили сетей»)
        self._net_sig = None
        self._filter_fail_at = 0.0
        self._ads_paused_state: bool | None = None
        self.ads_stats: dict = {"day": "", "today": 0, "top": {}, "recent": collections.deque(maxlen=100)}
        # «сайт закрыт блокировщиком»: заходы на сами сайты (example.com, www.example.com), которые попали в списки
        self._ads_site_hits: dict[str, list[float]] = {}
        self._ads_site_asked: set[str] = set()
        self._ads_ask_times: collections.deque = collections.deque(maxlen=10)
        self.ads_suspects: collections.deque = collections.deque(maxlen=20)
        self.tray_queue: collections.deque = collections.deque(maxlen=5)  # всплывающие сообщения у значка в трее
        self.ports: dict = {}
        self.geo_in_use = False
        self.proc = XrayProcess(self.paths, on_line=self._xray_line)
        self._busy = threading.Lock()
        self._conn_lock = threading.RLock()
        self.busy_text = ""
        self.stop_event = threading.Event()
        # Вторая очередь — короткие действия с VPN (подключить, отключить, сменить сервер, применить настройки).
        # Идёт параллельно с долгими задачами: пока подбирается zapret или качаются списки, VPN можно
        # включать и переключать. Само ядро запускается и останавливается под _conn_lock — по очереди.
        self._conn_busy = threading.Lock()
        self.conn_text = ""
        self.conn_stop = threading.Event()
        self._lane = threading.local()
        self.logs: collections.deque = collections.deque(maxlen=500)
        self.live: dict = {"ping": None, "proxy_down": 0.0, "proxy_up": 0.0, "direct_down": 0.0, "direct_up": 0.0,
                           "exit_ip": "", "exit_loc": "", "direct_ping": None}
        self.connections: dict[str, dict] = {}
        self._apps_off = False  # ядро не поняло правила по процессам (старая версия) — приложения без своих маршрутов
        self.hotkey_state: dict = {"key": "", "ok": False, "supported": False}  # заполняет main.py (значок в трее)
        self.last_leaks: dict | None = None
        self.vpn_until = 0.0  # «VPN на время»: когда выключить
        self._traffic_dirty = 0
        self._hist_at = 0.0
        self.just_updated = ""  # main.py: только что поставлено обновление
        self._failover_off = False  # ядро не поняло балансировщик — без запасного сервера внутри ядра
        self._failover_tag = ""
        self._host_log: collections.deque = collections.deque(maxlen=20000)  # (время, адрес, куда пошёл) — для «починить сайт»
        self.service_results: dict = {}
        self._log_pos = 0
        self._ping_failures = 0
        self._stats_prev = None
        self._monitor = threading.Thread(target=self._monitor_loop, daemon=True)
        self._closing = False
        # обход замедлений: zapret и ByeDPI
        self.dpi_paths = dpi.DpiPaths(self.paths.bin_dir, self.paths.data_dir)
        self.tun_paths = tun.TunPaths(self.paths.bin_dir, self.paths.data_dir, self.paths.xray, self.paths.legacy_xray)
        # мост sing-box для TUIC и AnyTLS (без прав администратора) и AmneziaWG (своим клиентом)
        self.bridge = singbox.Bridge(self.paths, self.tun_paths.singbox, os.path.join(self.paths.data_dir, "bridge.json"))
        tester.SINGBOX_EXE = self.tun_paths.singbox
        self.awg = amneziawg.Runner(self.paths.data_dir)
        self.awg_active: Server | None = None
        # один помощник с правами администратора на сеанс: zapret и режим TUN
        self.admin = elevated.AdminHelper(app_dir, self.paths.data_dir, {
            "winws": self.dpi_paths.winws, "singbox": self.tun_paths.singbox, "tun2proxy": self.tun_paths.tun2proxy,
            "xray": self.paths.xray, "xray_legacy": self.paths.legacy_xray})
        self.zapret = dpi.ZapretRunner(self.dpi_paths, self.admin)
        self.byedpi = dpi.ByeDpiRunner(self.dpi_paths)
        self.dpi_mode = ""  # кто сейчас ведёт YouTube и Discord: "zapret", "byedpi" или "" (VPN)
        self.dpi_errors: dict[str, str] = {}
        self.dpi_last: dict = {}
        self.dpi_supported = dpi.IS_WINDOWS  # winws работает только в Windows (в самопроверке подменяется)
        self._dpi_fail = 0
        self._dpi_watching = False
        self._auto_init()
        # режим TUN
        self.xray_normal = self.proc
        self.xray_admin = tun.ElevatedXray(
            self.admin, self.paths,
            lambda exe: "xray_legacy" if os.path.normcase(exe) == os.path.normcase(self.paths.legacy_xray) else "xray")
        self.tun_proc = tun.TunProcess(self.admin, self.tun_paths)
        self.tun_supported = tun.IS_WINDOWS  # адаптер TUN — только в Windows (в самопроверке подменяется)
        self.tun_active = ""  # движок, который сейчас работает: "xray", "singbox", "tun2proxy" или ""
        self.tun_error = ""
        self.tun_bind = ""
        self._tun_sig = None
        self._phys_ip = ""
        self._proxy_tags: list[str] = []
        self.whitelist_mode = False  # мобильный интернет пускает только на разрешённые сайты
        self.hotspot = {"on": False, "clients": 0, "via_tun": False, "error": ""}

    # ---------- служебное ----------

    def notify(self, event: str, **data) -> None:
        """События для интерфейса; тексты переводятся на выбранный язык."""
        if isinstance(data.get("text"), str) and event in ("error", "summary", "info", "busy"):
            data["text"] = i18n.tr(data["text"])
        self._raw_notify(event, **data)

    def log(self, text: str) -> None:
        # в журнале храним исходную строку, а переводим при показе — тогда после смены языка
        # старые строки тоже показываются на новом языке
        stamp = time.strftime("%H:%M:%S ")
        self.logs.append(stamp + text)
        self._raw_notify("log", text=stamp + i18n.tr(text))

    def _scrub_secrets(self, text: str) -> str:
        """Для журнала ошибок: убрать ссылки, ключи, адреса и папку пользователя."""
        from . import diagnostics
        return diagnostics.scrub(text, diagnostics.secrets_of(self))

    def errors_state(self) -> dict:
        """Журнал ошибок для окна: записи (новые сверху), куда сообщать на GitHub, где лежит файл."""
        repo = errorlog.repo_from_url(update.UPDATE_URL) or errorlog.repo_from_url(self.settings.get("github_repo", ""))
        items = [dict(e, title=i18n.tr(e["title"]), detail=i18n.tr(e.get("detail", "")), where=i18n.tr(e.get("where", "")))
                 for e in self.errors.recent(100)]
        return {"items": items, "repo": repo, "file": self.errors.path}

    def logs_view(self) -> list[str]:
        """Журнал на текущем языке интерфейса."""
        return [ln[:9] + i18n.tr(ln[9:]) for ln in list(self.logs)]

    # ---------- проблемы (жёлтый значок в интерфейсе) ----------

    def problem(self, key: str, title: str, detail: str = "", where: str = "", fix: str = "",
                level: str = "warn") -> None:
        """Программа не справляется с чем-то важным — показываем значок с объяснением."""
        old = self.problems.get(key)
        self.problems[key] = {"key": key, "title": title, "detail": str(detail)[:600], "where": where, "fix": fix,
                              "level": level, "since": old["since"] if old else time.time(),
                              "count": (old["count"] + 1) if old else 1}
        if not old:
            self.log("Проблема: " + title + (f" — {detail}" if detail else ""))
            self.errors.record("problem", title, str(detail), where=key)
        self.notify("problems")

    def resolve(self, *keys: str) -> None:
        changed = False
        for key in keys:
            if key.endswith("*"):
                for k in [k for k in self.problems if k.startswith(key[:-1])]:
                    self.problems.pop(k, None)
                    changed = True
            elif self.problems.pop(key, None):
                changed = True
        if changed:
            self.notify("problems")

    def problems_list(self) -> list[dict]:
        out = []
        for p in sorted(self.problems.values(), key=lambda x: (x["level"] != "error", x["since"])):
            out.append({k: (i18n.tr(v) if isinstance(v, str) and k in ("title", "detail", "where", "fix") else v)
                        for k, v in p.items()})
        return out

    def problem_report(self) -> str:
        """Отчёт для нейросети или разработчика: что сломалось, окружение, журнал. Без ссылок и ключей."""
        import platform
        lines = [f"VEDOMYJ VPN {APP_VERSION} — отчёт о проблемах", f"Время: {time.strftime('%Y-%m-%d %H:%M:%S')}",
                 f"Система: {platform.system()} {platform.release()} ({platform.machine()}), Python {platform.python_version()}",
                 f"Xray: {self.xray_ver or 'нет'}; совместимое ядро: {'есть' if self.paths.legacy_exists() else 'нет'}",
                 f"Подключено: {self.connected}; сервер: {self.current.name if self.current else '-'}; "
                 f"режим: {self.settings.get('mode')}; списки runetfreedom: {self.geo_in_use}",
                 f"Подписок: {len(self.settings['subscriptions'])}; серверов: {len(self.servers)}; "
                 f"рабочих: {sum(1 for s in self.servers if (s.result or {}).get('ok'))}", "", "Проблемы:"]
        if not self.problems:
            lines.append("- нет")
        for p in self.problems.values():
            lines.append(f"- [{p['level']}] {p['title']} (раз: {p['count']}, где: {p['where'] or '-'})")
            if p["detail"]:
                lines.append(f"  подробности: {p['detail']}")
            if p["fix"]:
                lines.append(f"  что делать: {p['fix']}")
        lines += ["", "Последние строки журнала:"] + list(self.logs)[-60:]
        text = "\n".join(lines)
        for meta in self.settings["subscriptions"]:  # ссылки на подписки — секрет
            text = text.replace(meta["url"], "<ссылка на подписку>")
        return text

    def _xray_line(self, line: str) -> None:
        low = line.lower()
        if "[warning]" in low or "[error]" in low or "failed" in low:
            self.log("Xray: " + line[line.find("["):] if "[" in line else "Xray: " + line)

    def is_busy(self) -> bool:
        """Идёт хоть какая-то задача (фоновая или с подключением)."""
        return self._busy.locked() or self._conn_busy.locked()

    def bg_busy(self) -> bool:
        return self._busy.locked()

    def conn_busy(self) -> bool:
        return self._conn_busy.locked()

    def _in_conn_lane(self) -> bool:
        return getattr(self._lane, "name", "") == "conn"

    def run_task(self, title: str, func, *args, lane: str = "bg") -> bool:
        """Запускает операцию в фоне. lane="conn" — действия с VPN (подключение, смена сервера, применение
        настроек): они идут параллельно с долгими задачами (lane="bg"). В каждой очереди — одна задача за раз."""
        conn = lane == "conn"
        lock = self._conn_busy if conn else self._busy
        if not lock.acquire(blocking=False):
            self.notify("error", text=f"Подожди: сейчас выполняется «{self.conn_text if conn else self.busy_text}».")
            return False

        def worker():
            self._lane.name = "conn" if conn else "bg"
            if conn:
                self.conn_text = title
                self.conn_stop.clear()
                self.notify("conn", active=True, text=title)
            else:
                self.busy_text = title
                self.stop_event.clear()
                self.notify("busy", active=True, text=title)
            try:
                func(*args)
            except Busy:
                pass
            except Cancelled:
                self.log("Остановлено.")
                self.notify("info", text="Остановлено.")
            except Exception as exc:  # показываем человеку понятную ошибку
                if errorlog.is_bug(exc):
                    self.errors.record_exc(exc, f"задача: {title}")
                self.log(f"Ошибка: {exc}")
                self.notify("error", text=str(exc))
                self.problem("task:" + title, f"Не получилось: {title}", str(exc), where=title,
                             fix="Повтори действие. Если ошибка повторяется — скопируй отчёт и пришли его.")
            else:
                self.resolve("task:" + title)
            finally:
                if conn:
                    self.conn_text = ""
                    lock.release()
                    self.notify("conn", active=False, text="")
                else:
                    self.busy_text = ""
                    lock.release()
                    self.notify("busy", active=False, text="")
                self.save()

        threading.Thread(target=worker, daemon=True).start()
        return True

    def check_stop(self) -> None:
        if (self.conn_stop if self._in_conn_lane() else self.stop_event).is_set():
            raise Cancelled()

    def progress(self, text: str) -> None:
        if self._in_conn_lane():
            self.conn_text = text
            self.notify("conn", active=True, text=text)
            return
        self.busy_text = text
        self.notify("busy", active=True, text=text)

    def stop_current(self) -> None:
        """Кнопка «Остановить»: долгая фоновая задача, а если её нет — подключение."""
        if self.bg_busy():
            self.stop_event.set()
        elif self.conn_busy():
            self.conn_stop.set()

    def save(self) -> None:
        self.settings["results"] = {s.key: s.result for s in self.servers if s.result}
        try:
            self.settings.save()
        except OSError as exc:
            self.log(f"Не удалось сохранить настройки: {exc}")

    # ---------- запуск и завершение ----------

    def startup(self) -> None:
        if xray.kill_stale(self.paths):
            self.log("Остановлен Xray, оставшийся от прошлого запуска.")
        self._install_pending_core()
        backup = self.settings.get("proxy_backup")
        port = self.settings.get("proxy_backup_port") or self.settings["http_port"]
        if sysproxy.is_ours(port):
            sysproxy.restore(backup)
            self.log("Восстановлены системные настройки прокси после прошлого аварийного закрытия.")
        self.settings["proxy_backup"] = None
        self.settings["proxy_backup_port"] = None
        self.load_cached()
        self._ads_migrate()
        self._routing_migrate()
        self.awg_restore()
        self._monitor.start()
        self._check_files()
        if not self.paths.xray_exists():
            self.log("Ядро Xray ещё не скачано — его скачает «Автонастройка» или кнопка «Обновить ядро».")
        last = None
        if self.settings.get("auto_connect_on_start") and self.servers:
            if self.settings.get("engine_pick") == "awg":
                last = None if self.awg_active else self.toggle_target()
            else:
                last = self.find(self.settings.get("last_server_key", ""))
        dpi_ready = self.dpi_supported and (
            (self.settings.get("zapret_enabled") and self.settings.get("zapret_strategy") and self.dpi_paths.zapret_installed())
            or (self.settings.get("byedpi_role") != "off" and self.settings.get("byedpi_strategy")
                and self.dpi_paths.byedpi_installed()))
        if dpi_ready or last:
            self.run_task("Подключение" if last else "Включаю обход замедлений", self._startup_task, last, bool(dpi_ready))

    def _startup_task(self, last, dpi_ready: bool) -> None:
        """При запуске: сначала обход замедлений (чтобы ядро сразу знало, куда вести YouTube), потом VPN."""
        if dpi_ready:
            self.progress("Включаю обход замедлений")
            self._apply_network_strategies()
            try:
                self.start_dpi(verify=True)
            except Exception as exc:
                self.log(f"Обход замедлений не включился: {exc}")
        if last:
            self.connect(last)

    def load_cached(self) -> None:
        """Загружает сохранённые подписки без сети и без побочных действий (так же это делает проверка программы)."""
        xray.WIPE_CONFIGS = secure.IS_WINDOWS and bool(self.settings.get("encrypt_data", True))
        if self.settings.secure_failed:
            self.problem("secure", "Подписки и пароли не расшифровались",
                         "Похоже, папку программы перенесли на другой компьютер или в другую учётную запись Windows.",
                         where="Главная → подписки",
                         fix="Добавь подписку снова. Чтобы переносить настройки, пользуйся «Поделиться → файл настроек».")
        self._migrate_old_subscription()
        os.makedirs(self._subs_dir(), exist_ok=True)
        for meta in self.settings["subscriptions"]:
            cache = self._sub_cache(meta["id"])
            if os.path.isfile(cache):
                try:
                    with open(cache, encoding="utf-8") as f:
                        self.sub_objs[meta["id"]] = subscription.parse_body(secure.decode(f.read()))
                except (OSError, secure.SecureError):
                    pass
        self._rebuild_servers()
        self.xray_ver = xray.xray_version(self.paths)

    def run_check(self) -> dict:
        """«Проверка программы» из интерфейса."""
        from . import diagnostics
        self.progress("Проверка программы")
        report = diagnostics.run(self, stop=self.stop_event, progress=lambda text: self.notify("busy", active=True, text=text))
        self.notify("check", report=report)
        self.log(f"Проверка программы: ошибок {report['errors']}, предупреждений {report['warnings']}.")
        return report

    def shutdown(self) -> None:
        self._closing = True
        self.stop_event.set()
        try:
            self.disconnect(quiet=True, keep_filter=False)
            if self.awg_active:
                self.disconnect_awg(quiet=True, restore_filter=False)  # программа закрыта — AmneziaWG тоже выключается
        finally:
            try:
                self.byedpi.stop()
                self.zapret.shutdown()
                self.admin.shutdown()
                if self.hotspot.get("on"):
                    hotspot.run("stop")  # программа закрыта — раздача без VPN никому не нужна
            except Exception:
                pass
            self.save()

    def _set_servers(self, servers: list[Server]) -> None:
        saved = dict(self.settings.get("results", {}) or {})
        saved.update({s.key: s.result for s in self.servers if s.result})
        for s in servers:
            if s.key in saved and isinstance(saved[s.key], dict):
                s.result = saved[s.key]
        self.servers = servers
        if self.current:
            same = self.find(self.current.key)
            if same:
                self.current = same
        self.notify("servers")

    def find(self, key: str) -> Server | None:
        return next((s for s in self.servers if s.key == key), None)

    def _need_xray(self) -> None:
        if not self.paths.xray_exists():
            self.progress("Скачиваю ядро Xray")
            self.update_xray()

    def ensure_legacy(self) -> None:
        """Совместимое ядро для серверов без шифрования (новые ядра их не пускают)."""
        if self.paths.legacy_exists():
            return
        self.progress("Скачиваю совместимое ядро Xray")
        version = self._fetch_any(lambda p: xray.download_legacy_xray(self.paths, proxy_port=p), "Совместимое ядро Xray")
        self.log(f"Скачано совместимое ядро Xray {version} для серверов без шифрования.")

    # ---------- подписки ----------

    def _subs_dir(self) -> str:
        return os.path.join(self.paths.data_dir, "subs")

    def _sub_cache(self, sid: str) -> str:
        return os.path.join(self._subs_dir(), f"{sid}.txt")

    def _sub_meta(self, sid: str) -> dict | None:
        return next((m for m in self.settings["subscriptions"] if m["id"] == sid), None)

    def _migrate_old_subscription(self) -> None:
        old = (self.settings.get("subscription_url") or "").strip()
        if old and not self.settings["subscriptions"]:
            sid = secrets.token_hex(3)
            self.settings["subscriptions"].append({"id": sid, "name": "", "url": old, "title": "", "usage": {},
                                                   "last_update": self.settings.get("last_sub_update", 0)})
            legacy = os.path.join(self.paths.data_dir, "subscription.txt")
            os.makedirs(self._subs_dir(), exist_ok=True)
            if os.path.isfile(legacy):
                os.replace(legacy, self._sub_cache(sid))
        self.settings["subscription_url"] = ""

    def _pins(self) -> dict:
        """Отпечатки сертификатов серверов «не проверять сертификат» — общие для движка и сборки настроек ядра."""
        pins = self.settings.setdefault("cert_pins", {})
        xray.CERT_PINS = pins
        return pins

    def _rebuild_servers(self) -> None:
        self._pins()
        servers: list[Server] = []
        for meta in self.settings["subscriptions"]:
            obj = self.sub_objs.get(meta["id"])
            if not obj:
                continue
            for s in obj.servers:
                s.sub_id = meta["id"]
                servers.append(s)
        for link in self.settings.get("manual_links", []):
            srv = parse_link(link)
            if srv:
                srv.sub_id = "manual"
                servers.append(srv)
        self._set_servers(servers)

    def sub_name(self, meta: dict) -> str:
        if meta.get("name"):
            return meta["name"]
        if meta.get("title"):
            return countries.split_flag(meta["title"])[1]
        return urlsplit(meta["url"]).hostname or "Подписка"

    def add_subscription(self, raw: str, name: str = "") -> None:
        raw = (raw or "").strip()
        if subscription.looks_like_server_link(raw):
            self.add_servers(raw)
            return
        url = subscription.normalize_url(raw)
        existing = next((m for m in self.settings["subscriptions"] if m["url"] == url), None)
        if existing:
            if name:
                existing["name"] = name
            self.update_subscription(existing["id"])
            return
        meta = {"id": secrets.token_hex(3), "name": name.strip(), "url": url, "title": "", "usage": {},
                "last_update": 0}
        self.progress("Загружаю подписку")
        self._fetch_into(meta)  # бросит понятную ошибку, если серверов нет — тогда подписку не добавляем
        self.settings["subscriptions"].append(meta)
        self._rebuild_servers()
        self.save()
        servers = [s for s in self.servers if s.sub_id == meta["id"]]
        try:
            self.test_all(servers)  # как в Happ: сразу показываем пинг (при первом запуске скачается ядро)
        except Exception as exc:
            self.log(f"Проверка пинга не удалась: {exc}")

    def _fetch_into(self, meta: dict) -> subscription.Subscription:
        proxy = self.ports.get("health") if self.connected else None
        try:
            sub = subscription.fetch(meta["url"], meta.get("user_agent") or self.settings.get("user_agent", ""),
                                     proxy_port=proxy, own_http_port=self.settings["http_port"],
                                     hwid=self.settings.get("hwid", ""), relay=self._sub_relay)
        except Exception as exc:
            self.sub_errors[meta["id"]] = str(exc)
            self.problem("sub:" + meta["id"], f"Подписка «{self.sub_name(meta)}» не обновляется", str(exc),
                         where="Главная → подписки", fix="Проверь интернет и ссылку. Подробности — на карточке подписки.")
            raise
        self.sub_errors.pop(meta["id"], None)
        self.resolve("sub:" + meta["id"])
        for w in sub.warnings:
            self.log(w)
        provider_notes = [w for w in sub.warnings if w.startswith("Провайдер:")]
        if provider_notes and not any(s.supported for s in sub.servers):
            self.sub_errors[meta["id"]] = "\n".join(provider_notes)
        os.makedirs(self._subs_dir(), exist_ok=True)
        with open(self._sub_cache(meta["id"]), "w", encoding="utf-8") as f:
            f.write(secure.encode(sub.raw) if self.settings.get("encrypt_data", True) else sub.raw)
        self.sub_objs[meta["id"]] = sub
        meta["notices"] = sub.notices
        meta["title"] = sub.title or meta.get("title", "")
        meta["usage"] = sub.usage()
        meta["last_update"] = time.time()
        if sub.user_agent and sub.user_agent != self.settings.get("user_agent"):
            meta["user_agent"] = sub.user_agent  # запоминаем, какой формат сработал
        self.settings["last_sub_update"] = time.time()
        supported = sum(1 for s in sub.servers if s.supported)
        real = sum(1 for s in sub.servers if not s.stub)
        if sub.notices and not supported:
            msg = f"«{self.sub_name(meta)}»: вместо серверов провайдер прислал сообщение: «{sub.notices[0]}»"
            self.log(msg)
            self.problem("stub:" + meta["id"], f"Провайдер не прислал серверы в «{self.sub_name(meta)}»",
                         sub.notices[0], where="Главная → подписки",
                         fix="Прочитай сообщение провайдера на карточке подписки и обнови её.")
            return sub
        self.resolve("stub:" + meta["id"])
        msg = f"«{self.sub_name(meta)}»: серверов {real}, поддерживается {supported}"
        if sub.route and sub.route != "напрямую":
            msg += f" (загружено {sub.route})"
        usage = sub.usage_text()
        self.log(msg + (f". {usage[0].upper() + usage[1:]}." if usage else "."))
        return sub

    RELAY_SERVERS = 3
    _relay_failed_at = 0.0

    def _relay_servers(self) -> list[Server]:
        """Серверы для скачивания подписки в обход блокировки: рабочие, кроме текущего; разные страны,
        и российский, если есть (сервер подписки может пускать только российские адреса)."""
        cur = self.current.key if self.connected and self.current else None
        pool = [s for s in tester.ranked(self.servers) if s.key != cur and not s.insecure and not s.stub
                and s.engine == "xray"]
        picked: list[Server] = []
        ru = next((s for s in pool if countries.detect(s.name)[0] == "RU"), None)
        if ru:
            picked.append(ru)
        seen = {countries.detect(s.name)[0] for s in picked}
        for s in pool:  # сначала разные страны
            if len(picked) >= self.RELAY_SERVERS:
                break
            cc = countries.detect(s.name)[0]
            if s not in picked and (not cc or cc not in seen):
                picked.append(s)
                seen.add(cc)
        for s in pool:
            if len(picked) >= self.RELAY_SERVERS:
                break
            if s not in picked:
                picked.append(s)
        return picked

    def _relay(self, attempt, why: str):
        """Через другие рабочие серверы на временном ядре: attempt(название, порт) → результат или None.
        Возвращает первый удачный результат или None."""
        cands = self._relay_servers()
        if not cands or not self.paths.xray_exists():
            return None
        self.progress(why)
        ports = netutil.find_free_ports(len(cands), avoid=tester.RESERVED_PORTS)
        proc = xray.XrayProcess(self.paths)
        cfg_path = os.path.join(self.paths.data_dir, "relay.json")
        try:
            proc.start(xray.build_test_config(cands, ports, None, self.xray_ver or ""), cfg_path, wait_for=ports)
        except Exception as exc:
            self.log(f"Временное ядро не запустилось: {exc}")
            return None
        try:
            for srv, port in zip(cands, ports):
                self.check_stop()
                got = attempt(f"через сервер «{srv.name}»", port)
                if got:
                    return got
        finally:
            proc.stop()
            xray.wipe(cfg_path)
        return None

    def _sub_relay(self, attempt):
        """Подписка не скачалась ни напрямую, ни через VPN: пробуем через другие серверы на временном ядре."""
        return self._relay(attempt, "Сервер подписки недоступен — пробую через другие серверы")

    def _fetch_any(self, job, what: str):
        """Скачивание своих файлов (списки, ядро, обновления) любым рабочим путём: через VPN (если подключено),
        напрямую (если DNS провайдера не знает адрес — через защищённый DNS), через другие серверы.
        job(proxy_port) возвращает результат или бросает исключение. Не вышло нигде — первая ошибка."""
        routes = [("через VPN", self.ports["health"])] if self.connected and self.ports.get("health") else []
        routes.append(("напрямую", None))
        errors: list[str] = []
        first: list[Exception] = []
        for name, port in routes:
            self.check_stop()
            try:
                return job(port)
            except (Cancelled, PermissionError):
                raise
            except Exception as exc:
                first.append(exc)
                errors.append(f"{name}: {netutil.human_error(exc)}")
        box: dict = {}

        def attempt(name, port):
            try:
                box["result"] = job(port)
                return True
            except (Cancelled, PermissionError):
                raise
            except Exception as exc:
                errors.append(f"{name}: {netutil.human_error(exc)}")
                return None
        # другие серверы не помогли только что — не запускаем временное ядро на каждый файл подряд
        if time.time() - self._relay_failed_at > 120:
            if self._relay(attempt, f"{what}: пробую через другие серверы"):
                self.log(f"{what}: скачано через другой сервер — напрямую не открывается.")
                return box.get("result")
            self._relay_failed_at = time.time()
        self.log(f"{what}: не скачалось ({'; '.join(dict.fromkeys(errors))}).")
        raise first[0]

    def update_subscription(self, sid: str | None = None) -> None:
        metas = [m for m in self.settings["subscriptions"] if sid is None or m["id"] == sid]
        if not metas:
            if sid is None:
                raise RuntimeError("Подписок пока нет — нажми «Добавить подписку».")
            raise RuntimeError("Подписка не найдена.")
        errors = []
        for meta in metas:
            self.check_stop()
            self.progress(f"Обновляю «{self.sub_name(meta)}»")
            try:
                self._fetch_into(meta)
            except Exception as exc:
                errors.append(f"«{self.sub_name(meta)}»: {exc}")
                self.log(f"Подписка «{self.sub_name(meta)}» не обновилась: {exc}")
        self._rebuild_servers()
        self.save()
        self._sub_alerts()
        if self.current and not self.find(self.current.key):
            self.log("Сервера, к которому ты подключён, больше нет в подписке — он работает до переключения.")
        if errors and len(errors) == len(metas):
            raise RuntimeError("\n".join(errors))

    def remove_subscription(self, sid: str) -> None:
        meta = self._sub_meta(sid)
        if not meta:
            return
        self.settings["subscriptions"] = [m for m in self.settings["subscriptions"] if m["id"] != sid]
        self.sub_objs.pop(sid, None)
        self.sub_errors.pop(sid, None)
        self.resolve("sub:" + sid, "stub:" + sid)
        try:
            os.remove(self._sub_cache(sid))
        except OSError:
            pass
        self._rebuild_servers()
        self.save()
        self.log(f"Подписка «{self.sub_name(meta)}» удалена.")

    def rename_subscription(self, sid: str, name: str) -> None:
        meta = self._sub_meta(sid)
        if meta:
            meta["name"] = name.strip()
            self.save()
            self.notify("servers")

    def add_servers(self, text: str) -> int:
        added, bad = 0, []
        saved = self.settings.setdefault("manual_links", [])
        try:
            lines = links.text_to_links(text)  # конфиг AmneziaWG целиком и ключи Amnezia vpn:// — тоже сюда
        except links.LinkError as exc:
            raise RuntimeError(f"Не получилось прочитать: {exc}.") from exc
        for line in lines:
            line = line.strip()
            if not line:
                continue
            srv = parse_link(line)
            if not srv:
                bad.append(line[:40])
                continue
            if line not in saved:
                saved.append(line)
                added += 1
            if not srv.supported:
                self.log(f"Сервер «{srv.name}» добавлен, но не поддерживается: {srv.note}")
        if not added and bad:
            raise RuntimeError("Не нашёл ссылок на серверы. Нужны ссылки вида vless://, vmess://, trojan://, ss://, "
                               "hysteria2://, tuic://, anytls://, ключ Amnezia vpn:// или конфиг AmneziaWG.")
        self._rebuild_servers()
        self.save()
        self.log(f"Добавлено своих серверов: {added}.")
        return added

    def remove_server(self, key: str) -> None:
        srv = self.find(key)
        if not srv or srv.sub_id != "manual":
            raise RuntimeError("Удалять можно только свои серверы. Серверы подписки обновляются вместе с ней.")
        if self.awg_active and self.awg_active.key == key:
            self.disconnect_awg()
        self.settings["manual_links"] = [x for x in self.settings.get("manual_links", []) if x.strip() != srv.link]
        self._rebuild_servers()
        self.save()

    # ---------- тесты ----------

    def _on_result(self, srv: Server) -> None:
        if srv.result and "ok" in srv.result and not srv.stub:
            ok = bool(srv.result.get("ok"))
            # при белых списках не работают все обычные серверы сразу — в историю сервера это не пишем
            if ok or not self.whitelist_mode:
                self._note_quality(srv.key, ok)
            srv.result["hour_penalty"] = self.hour_penalty(srv.key)
        self.notify("server", key=srv.key)

    # ---------- история качества серверов ----------
    # По каждому серверу — сколько раз он работал и не работал в каждый час суток. Сервер, который часто
    # не работает именно в это время (например, по вечерам), при выборе лучшего отодвигается назад.

    HIST_PENALTY = 1500  # «штраф» к оценке сервера при 100% неудач в этот час (оценка — примерно миллисекунды)

    def _note_quality(self, key: str, ok: bool, hour: int | None = None) -> None:
        hist = self.settings.setdefault("server_hist", {})
        h = time.localtime().tm_hour if hour is None else hour
        row = hist.setdefault(key, [[0, 0] for _ in range(24)])
        cell = row[h]
        cell[0 if ok else 1] += 1
        if cell[0] + cell[1] > 40:  # старое весит меньше нового
            cell[0], cell[1] = (cell[0] + 1) // 2, (cell[1] + 1) // 2
        if len(hist) > 600:
            known = {x.key for x in self.servers}
            for k in [k for k in hist if k not in known][:200]:
                hist.pop(k, None)

    def hour_penalty(self, key: str, hour: int | None = None) -> float:
        """Насколько сервер ненадёжен в этот час (и соседние): 0 — нормально, HIST_PENALTY — всегда отказывает."""
        row = (self.settings.get("server_hist") or {}).get(key)
        if not row:
            return 0.0
        h = time.localtime().tm_hour if hour is None else hour
        ok = sum(row[(h + d) % 24][0] for d in (-1, 0, 1))
        fail = sum(row[(h + d) % 24][1] for d in (-1, 0, 1))
        if ok + fail < 3:
            return 0.0
        rate = fail / (ok + fail)
        return self.HIST_PENALTY * rate if rate > 0.2 else 0.0

    def test_all(self, servers: list[Server] | None = None) -> int:
        self._need_xray()
        servers = servers if servers is not None else self.servers
        if not servers:
            raise RuntimeError("Список серверов пуст — сначала обнови подписку.")
        servers = [x for x in servers if x.engine != "awg"]  # AmneziaWG проверяется только включением
        if not servers:
            self.log("Конфиги AmneziaWG проверяются включением: выбери его и нажми большую кнопку.")
            return 0
        if certpin.fill(servers, self._pins(), refresh=True):  # сертификат сервера мог смениться — снимаем заново
            self.save()
        if singbox.bridged(servers) and not self._ensure_singbox():
            servers = [x for x in servers if x.engine != "singbox"]
            self.log("TUIC и AnyTLS сейчас не проверить: sing-box не скачался.")
            if not servers:
                return 0
        self.progress(f"Проверяю серверы ({sum(1 for s in servers if not s.stub)})")
        self._core_versions()
        self._pin_server_dns(servers)
        working = tester.test_servers(self.paths, servers, self.settings["ping_host"], self.settings["ping_path"],
                                      self._on_result, self.stop_event, self.log, ensure_core=self.ensure_legacy,
                                      mask_retry=bool(self.settings.get("mask_auto", True)),
                                      fp_retry=bool(self.settings.get("fp_auto", True)))
        self.notify("servers")
        self.check_stop()
        if self.whitelist_mode:
            for srv in servers:
                if (srv.result or {}).get("ok"):
                    srv.result["whitelist"] = True
                    self._on_result(srv)
        best = tester.ranked(self.servers, key=self._rank_key())
        msg = f"Проверка завершена: работает {working} из {len(servers)}."
        if best:
            r = best[0].result
            msg += f" Лучший: {best[0].name} (пинг {r['ping_ms']} мс)."
        self.log(msg)
        self.notify("servers")
        return working

    DNS_RECHECK = 600.0

    @staticmethod
    def _bogus_ip(ip: str) -> bool:
        """Так DNS провайдера «прячет» заблокированный адрес: 0.0.0.0, 127.x, частные сети."""
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return True
        return a.is_unspecified or a.is_loopback or a.is_private or a.is_link_local or a.is_reserved

    def _pin_server_dns(self, servers: list[Server]) -> None:
        """Имя сервера, которое DNS провайдера не находит (или подменяет на заглушку), берём из защищённого DNS:
        ядро подключится по адресу, а имя останется в TLS. Без этого такой сервер просто «не отвечает»."""
        now = time.time()
        seen = self._dns_seen
        hosts = set()
        for srv in servers:
            h = srv.address
            if not h or srv.stub or is_private_host(h):
                continue
            try:
                ipaddress.ip_address(h)
                continue  # уже адрес
            except ValueError:
                pass
            if now - seen.get(h, (0.0, ""))[0] > self.DNS_RECHECK:
                hosts.add(h)

        def check(h: str) -> tuple[str, str]:
            try:
                ips = {i[4][0] for i in socket.getaddrinfo(h, None, socket.AF_INET, socket.SOCK_STREAM)}
                if ips and not all(self._bogus_ip(ip) for ip in ips):
                    return h, ""
            except (OSError, UnicodeError):
                pass
            got = [ip for ip in netutil.doh_resolve(h) if not self._bogus_ip(ip)]
            return h, got[0] if got else ""
        if hosts:
            with ThreadPoolExecutor(max_workers=8) as pool:
                for h, ip in pool.map(check, sorted(hosts)):
                    seen[h] = (now, ip)
        fresh = 0
        for srv in servers:
            ip = seen.get(srv.address, (0.0, ""))[1] if srv.address else ""
            if ip and not srv.pinned_ip:
                fresh += 1
            srv.pinned_ip = ip
        if fresh:
            self.log(f"DNS провайдера не знает адрес серверов: {fresh}. Подключаюсь к ним по адресам из защищённого DNS.")

    def speed_top(self, count: int = 3) -> None:
        self._need_xray()
        top = tester.ranked(self.servers, key=tester.game_score)[:count]
        if not top:
            raise RuntimeError("Нет рабочих серверов — сначала нажми «Проверить все».")
        self.progress(f"Замеряю скорость {len(top)} лучших серверов")
        self._core_versions()
        tester.speed_test_servers(self.paths, top, self._on_result, stop_event=self.stop_event, log=self.log,
                                  ensure_core=self.ensure_legacy)
        self.notify("servers")
        self.check_stop()
        for s in top:
            sp = s.result.get("speed_mbps")
            self.log(f"Скорость {s.name}: {sp} Мбит/с" if sp else f"Скорость {s.name}: не удалось замерить")
        self.notify("servers")

    def speed_current(self) -> None:
        if not self.connected:
            raise RuntimeError("Сначала подключись.")
        self.progress("Замеряю скорость текущего подключения")
        r = netutil.speed_test(self.ports["health"], tester.SPEED_URLS, seconds=10)
        direct = netutil.speed_test(None, tester.SPEED_URLS, seconds=6)
        parts = [f"через VPN: {r['mbps']} Мбит/с" if r["ok"] else f"через VPN: ошибка ({r['error']})",
                 f"без VPN: {direct['mbps']} Мбит/с" if direct["ok"] else "без VPN: не удалось"]
        text = "Скорость — " + ", ".join(parts)
        if self.current and r["ok"]:
            self.current.result = dict(self.current.result or {}, speed_mbps=r["mbps"])
            self._on_result(self.current)
        self.log(text)
        self.notify("summary", text=text)

    def direct_ping(self) -> dict:
        r = netutil.http_ping(self.settings["ping_host"], self.settings["ping_path"], self._direct_http(), rounds=5)
        self.live["direct_ping"] = r["ping_ms"] if r["ok"] else None
        self.notify("live")
        return r

    def _core_versions(self) -> None:
        tester.CORE_VERSIONS.update({self.paths.xray: self.xray_ver or "", self.paths.legacy_xray: xray.LEGACY_VERSION})

    def _use_mask(self, server: Server) -> bool | int:
        """Маскировка для сервера: False, True (первый способ) или номер способа, который ему помог."""
        if not self.settings.get("mask_auto", True):
            return False
        return (server.result or {}).get("mask") or False

    def _version_for(self, exe: str) -> str:
        return xray.LEGACY_VERSION if os.path.normcase(exe) == os.path.normcase(self.paths.legacy_xray) \
            else (self.xray_ver or "")

    def _rank_key(self):
        """Как выбирать лучший сервер: по скорости и пингу или, в режиме для игр, по пингу и его ровности.
        Плюс история: сервер, который часто не работает в это время суток, отодвигается назад."""
        base = tester.game_score if self.settings.get("game_mode") else tester.score

        def key(r):
            v = base(r)
            return None if v is None else v + float((r or {}).get("hour_penalty", 0))
        return key

    def backup_server(self) -> Server | None:
        """Сервер, на который Автопереход перейдёт первым."""
        cur = self.current.key if (self.current and self.connected) else ""
        for srv in tester.ranked(self.pool(), key=self._rank_key()):
            if srv.key != cur:
                return srv
        return None

    def _backup_info(self) -> dict | None:
        srv = self.backup_server()
        if not srv:
            return None
        cc, clean = countries.detect(srv.name)
        return {"name": clean, "cc": cc, "ping": (srv.result or {}).get("ping_ms")}

    def best(self, for_games: bool = False) -> Server | None:
        lst = tester.ranked(self.pool(), key=tester.game_score if for_games else self._rank_key())
        return lst[0] if lst else None

    ENGINE_PICKS = ("auto", "xray", "hy2", "singbox", "awg")

    def pool(self) -> list[Server]:
        """Серверы выбранного движка («Движок» на главной): Авто — все, кроме AmneziaWG (его включают отдельно)."""
        pick = self.settings.get("engine_pick", "auto")
        if pick not in self.ENGINE_PICKS or pick == "auto":
            return [s for s in self.servers if s.engine != "awg"]
        return [s for s in self.servers if links.kind_of(s) == pick]

    ENGINE_NAMES = {"auto": "Авто", "xray": "Xray", "hy2": "Hysteria2", "singbox": "sing-box", "awg": "AmneziaWG"}

    def engine_state(self) -> dict:
        """«Движок» на главной: что выбрано и сколько серверов у каждого движка."""
        counts = {k: 0 for k in self.ENGINE_PICKS}
        for x in self.servers:
            if x.stub or not x.supported:
                continue
            counts[links.kind_of(x)] = counts.get(links.kind_of(x), 0) + 1
            if x.engine != "awg":
                counts["auto"] += 1
        return {"pick": self.settings.get("engine_pick", "auto"), "counts": counts,
                "singbox": os.path.isfile(self.tun_paths.singbox)}

    def toggle_target(self) -> Server | None:
        """Куда подключаться по большой кнопке: лучший сервер выбранного движка (для AmneziaWG — прошлый конфиг)."""
        pool = self.pool()
        if self.settings.get("engine_pick") == "awg":
            last = self.find(self.settings.get("last_awg_key") or "")
            return last if last in pool else (pool[0] if pool else None)
        best = self.best()
        if best:
            return best
        last = self.find(self.settings.get("last_server_key") or "")
        if last and last in pool and last.supported:
            return last
        return next((x for x in pool if x.supported and not x.stub), None)

    def set_engine_pick(self, pick: str) -> None:
        if pick not in self.ENGINE_PICKS:
            raise RuntimeError("Нет такого движка.")
        self.settings["engine_pick"] = pick
        self.save()
        self.log(f"Движок: {self.ENGINE_NAMES[pick]}.")
        self.notify("status")

    # ---------- подключение ----------

    def connect(self, server: Server) -> None:
        if server.engine == "awg":
            self.connect_awg(server)
            return
        self._need_xray()
        if not server.supported:
            raise RuntimeError(f"«{server.name}» — {server.note}.")
        if self.awg_active:
            self.disconnect_awg(quiet=True, restore_filter=False)  # два VPN сразу не нужны: AmneziaWG выключается
        if certpin.target(server) and certpin.fill([server], self._pins()):
            self.save()
        if server.engine == "singbox" and not self._ensure_singbox():
            raise RuntimeError("Для TUIC и AnyTLS нужен sing-box, а он не скачался. Проверь интернет или выбери другой сервер.")
        if server.insecure:
            self.ensure_legacy()
        self._pin_server_dns([server])
        exe = self.paths.exe_for(server)
        with self._conn_lock:
            self.progress(f"Подключаюсь к {server.name}")
            s = self.settings
            try:
                self._bring_up(server, exe)
            except XrayError as last_exc:
                self.connected = False
                self.filter_on = False  # ядро остановлено — фильтр перезапустит монитор
                self.notify("status")
                self.problem("connect", "Не удалось подключиться", str(last_exc), where=server.name,
                             fix="Выбери другой сервер или нажми «Автонастройка».", level="error")
                raise RuntimeError(f"Не удалось подключиться: {last_exc}") from last_exc
            self.filter_on = False
            self.kill_on = False
            self.connected = True
            self.current = server
            self.resolve("connect", "core_crash", "no_working", "server_down", "port_busy", "kill_switch")
            self._ping_failures = 0
            self._slow_count = 0
            self._stats_prev = None
            self._silent_since = 0.0
            self._way_saved = ""
            s["last_server_key"] = server.key
            self.save()
        mode = routing.MODES.get(s.get("mode"), "")
        geo_note = "" if self.geo_in_use else " (без списков runetfreedom — работает встроенный список)"
        self.log(f"Подключено: {server.name}. Режим: {mode}{geo_note}.")
        if self.tun_active:
            self.log(f"Режим TUN: {tun.ENGINE_NAMES[self.tun_active]} — через программу идёт весь трафик компьютера.")
        self.notify("status")
        threading.Thread(target=self._after_connect, daemon=True).start()

    def _bring_up(self, server: Server, exe: str) -> None:
        """Запуск ядра (и TUN) с этим сервером, системный прокси. Общее для VPN и «рекламы без VPN»."""
        s = self.settings
        running = self.connected or self.filter_on or self.kill_on  # порты уже наши
        self.ensure_lan_credentials()
        names = ("socks_port", "http_port") + (("lan_socks_port", "lan_http_port") if s.get("allow_lan") else ())
        for name in names:
            if not running and not netutil.is_port_free(int(s[name])):
                self.problem("port_busy", f"Порт {s[name]} занят другой программой", where="Настройки → порты",
                             fix="Закрой Happ, v2rayN и другие VPN-клиенты или поменяй порт в настройках.",
                             level="error")
                raise RuntimeError(f"Порт {s[name]} занят другой программой (возможно, Happ или v2rayN). "
                                   f"Закрой её или поменяй порт в настройках.")
        if not self.ports.get("health") or not running:
            extra = netutil.find_free_ports(4, start=21900, avoid=tester.RESERVED_PORTS)
            self.ports = {"socks": int(s["socks_port"]), "http": int(s["http_port"]),
                          "health": extra[0], "api": extra[1], "direct": extra[2], "direct_http": extra[3]}
        wait = [self.ports["socks"], self.ports["http"], self.ports["health"]]
        try:
            open(self.paths.access_log, "w").close()
        except OSError:
            pass
        self._log_pos = 0
        self._auto_live = {}  # автоправила теперь в самих настройках ядра
        if not running and not self.proc.alive() and not server.insecure:
            self._install_pending_core()
        self._start_core(server, exe, wait)
        # в режиме TUN весь трафик и так идёт через программу — системный прокси не нужен
        want_proxy = s.get("system_proxy") and not self.tun_active
        if want_proxy and not sysproxy.is_ours(self.ports["http"]):
            backup = sysproxy.enable(self.ports["http"])
            s["proxy_backup"] = backup
            s["proxy_backup_port"] = self.ports["http"]
        elif not want_proxy and s.get("proxy_backup_port"):
            sysproxy.restore(s.get("proxy_backup"))
            s["proxy_backup"] = None
            s["proxy_backup_port"] = None

    # ---------- режим TUN ----------

    def _tun_engines(self, server: Server) -> list[str]:
        """Какие движки пробовать: выбранный или, в «Авто», по очереди (сначала тот, что уже заработал)."""
        choice = self.settings.get("tun_engine", "auto")
        if choice in tun.ENGINES:
            return [choice]
        ver = xray.LEGACY_VERSION if server.insecure else (self.xray_ver or "")
        order = [e for e in tun.ENGINES if e != "xray" or tun.xray_supports_tun(ver)]
        pref = self.settings.get("tun_engine_auto")
        if pref in order:
            order.remove(pref)
            order.insert(0, pref)
        return order

    def _ensure_tun_engine(self, engine: str, exe: str, server: Server) -> None:
        proxy = self.ports.get("health") if self.connected and self.proc.alive() else None
        if engine == "xray":
            ver = xray.LEGACY_VERSION if server.insecure else (self.xray_ver or "")
            if not tun.xray_supports_tun(ver):
                raise tun.TunError("ядро Xray слишком старое для режима TUN — обнови ядро")
            self._fetch_any(lambda p: tun.ensure_wintun(self.tun_paths, os.path.dirname(exe), p), "Драйвер Wintun")
        elif engine == "singbox":
            if not os.path.isfile(self.tun_paths.singbox):
                self.progress("Скачиваю sing-box")
                ver = self._fetch_any(lambda p: tun.download_singbox(self.tun_paths, p), "sing-box")
                self.log(f"sing-box скачан: версия {ver or '?'}.")
        elif engine == "tun2proxy":
            if not os.path.isfile(self.tun_paths.tun2proxy):
                self.progress("Скачиваю tun2proxy")
                ver = self._fetch_any(lambda p: tun.download_tun2proxy(self.tun_paths, p), "tun2proxy")
                self.log(f"tun2proxy скачан: версия {ver or '?'}.")
            self._fetch_any(lambda p: tun.ensure_wintun(self.tun_paths, self.tun_paths.t2p_dir, p), "Драйвер Wintun")

    def _start_core(self, server: Server, exe: str, wait: list[int]) -> None:
        """Запуск ядра; в режиме TUN — ещё и движка TUN. Если TUN не включился ни одним движком,
        программа подключается как обычно (системный прокси) и показывает «!» с причиной."""
        s = self.settings
        engines = self._tun_engines(server) if s.get("tun_enabled") and self.tun_supported else []
        errors = []
        for engine in engines:
            try:
                self._start_with(server, exe, wait, engine)
                if s.get("tun_engine", "auto") == "auto":
                    s["tun_engine_auto"] = engine
                self.tun_error = ""
                self.resolve("tun")
                return
            except Cancelled:
                raise
            except (XrayError, RuntimeError, OSError) as exc:
                text = str(exc) or exc.__class__.__name__
                errors.append(f"{tun.ENGINE_NAMES[engine]}: {text}")
                self.log(f"Режим TUN через {tun.ENGINE_NAMES[engine]} не включился: {text}")
                if isinstance(exc, elevated.AdminError):
                    break  # без прав администратора не заработает ни один движок
        if engines:
            self.tun_error = errors[-1] if errors else ""
            self.problem("tun", "Режим TUN не включился", "; ".join(errors), where="Подключение",
                         fix="Сейчас программа работает через системный прокси. Нажми «Да», когда Windows спросит "
                             "разрешение, или выбери другой движок в списке «Подключение».")
        self._start_with(server, exe, wait, None)

    def _start_with(self, server: Server, exe: str, wait: list[int], engine: str | None) -> None:
        s = self.settings
        tun_cfg = None
        if engine:
            if not self.tun_active:
                self._phys_ip = netutil.lan_ip()  # адрес основного адаптера — до того, как маршруты уйдут в TUN
            self._ensure_tun_engine(engine, exe, server)
            self.progress(f"Включаю TUN: {tun.ENGINE_NAMES[engine]}")
            tun_cfg = {"engine": engine, "ipv6": tun.ipv6_available(), "leak": bool(s.get("leak_protection", True)),
                       "bind": tun.default_interface() if engine == "tun2proxy" else ""}
        new_proc = self.xray_admin if engine == "xray" else self.xray_normal
        if new_proc is not self.proc:
            self.proc.stop()
        if engine not in ("singbox", "tun2proxy"):
            self.tun_proc.stop()
            self._tun_sig = None
        self.proc = new_proc
        self.tun_bind = tun_cfg["bind"] if tun_cfg else ""
        use_geo = self.paths.geo_ready()
        attempts = [(use_geo, True)] + ([(True, False), (False, False)] if use_geo else [])
        variants = [tun_cfg]
        if tun_cfg and tun_cfg["ipv6"]:
            variants.append(dict(tun_cfg, ipv6=False))  # если IPv6 в системе выключен, адаптер с ним не запустится
        last_exc: Exception | None = None
        ads = self._ads_mode()
        skip = self._bridge_for(server, exe)
        for variant in variants:
            for geo, geo_ru_ip in attempts:
                retry_geo = False
                s_cfg = dict(s, mode=self.net_profile["mode"]) if self.net_profile.get("mode") else s
                for _ in range(4):  # каждая неудача может выключить одну необязательную возможность ядра
                    cfg = xray.build_run_config(server, s_cfg, self.ports, self.paths.access_log, geo, geo_ru_ip,
                                                dpi=self._dpi_route(), tun=variant, mask=self._use_mask(server),
                                                core_version=self._version_for(exe),
                                                multi=[] if server is self.FILTER else
                                                [m for m in self._multi_routes(server, exe) if m["server"].key not in skip],
                                                routes=[r for r in self._route_plan(server, exe)
                                                        if not (r.get("server") and r["server"].key in skip)], ads=ads,
                                                failover=[f for f in self._failover_for(server, exe)
                                                          if f["server"].key not in skip])
                    try:
                        self.proc.start(cfg, self.paths.run_config, wait_for=wait, exe=exe)
                        self.geo_in_use = geo
                        self._proxy_tags = [o["tag"] for o in cfg["outbounds"]
                                            if o["tag"] == "proxy" or o["tag"].endswith("@proxy")]
                        self._failover_tag = next((o["tag"] for o in cfg["outbounds"] if o["tag"] == "bk1"), "")
                        last_exc = None
                        break
                    except XrayError as exc:
                        last_exc = exc
                        low = str(exc).lower()
                        if ads == "dat" and "adblock" in low:
                            # файл списков рекламы не подошёл ядру — работаем с запасным списком и пересоберём позже
                            self.log(f"Списки рекламы не подошли ядру ({exc}). Пока работает запасной список.")
                            try:
                                os.remove(self._ads_dat)
                            except OSError:
                                pass
                            self.settings["ads_updated_at"] = 0
                            ads = "geo"
                            continue
                        if not self._apps_off and "process" in low and s.get("app_routes"):
                            # ядро не знает правил по процессам — запускаемся без маршрутов приложений
                            self._apps_off = True
                            self.log(f"Ядро не поддерживает маршруты приложений ({exc}). Обнови ядро — пока приложения идут как все.")
                            continue
                        if not self._failover_off and cfg.get("burstObservatory") \
                                and any(w in low for w in ("observatory", "balancer", "fallback")):
                            self._failover_off = True
                            self.log(f"Ядро не поддерживает мгновенное переключение ({exc}). Пока без запасного сервера внутри ядра.")
                            continue
                        retry_geo = "geo" in low or "not found" in low
                        if retry_geo:
                            self.log(f"Списки сайтов не подошли ядру ({exc}). Пробую без части правил.")
                        break
                if last_exc is None or not retry_geo:
                    break
            if not last_exc:
                tun_cfg = variant
                break
            if engine != "xray":
                break
        if last_exc:
            raise last_exc
        if engine in ("singbox", "tun2proxy"):
            sig = (engine, self.ports["socks"], tun_cfg["leak"], bool(s.get("dns_encrypted")), tun_cfg["ipv6"],
                   *self._tun_apps())
            if sig != self._tun_sig or not self.tun_proc.alive():
                try:
                    self.tun_proc.start(*sig)
                except Exception:
                    self._tun_sig = None
                    self.proc.stop()
                    raise
                self._tun_sig = sig
        was = self.tun_active
        self.tun_active = engine or ""
        if self.tun_active != was:
            self._rebind_byedpi()
            if self.hotspot.get("on"):  # раздача должна идти с того адаптера, через который сейчас интернет
                threading.Thread(target=self._hotspot_restart, daemon=True).start()

    def _bridge_for(self, server: Server, exe: str) -> set[str]:
        """Мост sing-box для серверов TUIC/AnyTLS этого подключения (основной, мультисервер, свои маршруты, запасной).
        Возвращает ключи серверов, которых в мосте нет: если мост не включился, они просто не используются."""
        extra = [] if server is self.FILTER else [m["server"] for m in self._multi_routes(server, exe)]
        extra += [r["server"] for r in self._route_plan(server, exe) if r.get("server")]
        extra += [f["server"] for f in self._failover_for(server, exe)]
        try:
            self.bridge.ensure([server] + extra)
            return set()
        except XrayError as exc:
            if getattr(server, "engine", "xray") == "singbox":
                raise XrayError(f"мост sing-box: {exc}") from exc
            skip = {x.key for x in singbox.bridged(extra)}
            self.log(f"Мост sing-box не включился ({exc}) — серверы TUIC и AnyTLS пока не используются в правилах.")
            self.bridge.ensure([server])  # остальным мост не нужен — остановится
            return skip

    def _ensure_singbox(self) -> bool:
        """sing-box для TUIC и AnyTLS: скачивается сам при первой нужде. False — скачать не вышло."""
        if os.path.isfile(self.tun_paths.singbox):
            return True
        self.progress("Скачиваю sing-box (нужен для TUIC и AnyTLS)")
        try:
            ver = self._fetch_any(lambda p: tun.download_singbox(self.tun_paths, p), "sing-box")
        except Cancelled:
            raise
        except Exception as exc:
            self.log(f"sing-box не скачался: {exc}")
            return False
        self.log(f"sing-box скачан: версия {ver or '?'}.")
        return os.path.isfile(self.tun_paths.singbox)

    def _rebind_byedpi(self) -> None:
        """Без отбора по программам (Xray TUN, tun2proxy) ByeDPI привязывается к основному адаптеру — иначе петля."""
        bind = self._phys_ip if self.tun_active in ("xray", "tun2proxy") else ""
        if bind == self.byedpi.bind_ip:
            return
        self.byedpi.bind_ip = bind
        if self.byedpi.alive():
            try:
                self.byedpi.start(self.byedpi.args, port=self.byedpi.port)
            except dpi.DpiError as exc:
                self.log(f"ByeDPI: {exc}")

    def _direct_socks(self) -> int | None:
        """Проверки «без VPN» в режиме TUN идут через служебный вход ядра — он всегда напрямую."""
        return self.ports.get("direct") if self.tun_active and self.connected else None

    def _direct_http(self) -> int | None:
        return self.ports.get("direct_http") if self.tun_active and self.connected else None

    def _failover_for(self, server: Server, exe: str) -> list[dict]:
        """Запасной сервер внутри ядра: если основной перестал отвечать, новые соединения сразу идут через него,
        без переподключения. Лучший рабочий сервер, кроме основного (по возможности — на другом адресе)."""
        if server is self.FILTER or self._failover_off or not self.settings.get("failover", True):
            return []
        main_host = (server.endpoint or "").rsplit(":", 1)[0]
        cands = [x for x in tester.ranked(self.pool(), key=self._rank_key())
                 if x.key != server.key and x.supported and not x.stub and self.paths.exe_for(x) == exe
                 and (x.result or {}).get("ok")]
        cands.sort(key=lambda x: (x.endpoint or "").rsplit(":", 1)[0] == main_host)  # сначала другой адрес
        return [{"server": cands[0], "mask": self._use_mask(cands[0])}] if cands else []

    def _tun_apps(self) -> tuple[tuple, tuple]:
        """Для sing-box: приложения напрямую и без сети (остальные выборы делает ядро Xray)."""
        direct, block = [], []
        for name, spec in sorted((self.settings.get("app_routes") or {}).items()):
            if spec.get("via") == "direct":
                direct += apps.rule_process(name)
            elif spec.get("via") == "block":
                block += apps.rule_process(name)
        return tuple(direct), tuple(block)

    def tun_state(self) -> dict:
        s = self.settings
        return {"enabled": bool(s.get("tun_enabled")), "engine": s.get("tun_engine", "auto"),
                "active": self.tun_active, "auto_pick": s.get("tun_engine_auto", ""),
                "supported": self.tun_supported, "error": i18n.tr(self.tun_error),
                "versions": {"singbox": self.tun_paths.version("singbox"),
                             "tun2proxy": self.tun_paths.version("tun2proxy")}}

    def _update_tun_engines(self, proxy) -> None:
        """Аккуратное обновление sing-box и tun2proxy вместе с ядром: только скачанные и только неработающие."""
        for engine, repo, download in (("singbox", tun.SINGBOX_REPO, tun.download_singbox),
                                       ("tun2proxy", tun.TUN2PROXY_REPO, tun.download_tun2proxy)):
            if not os.path.isfile(self.tun_paths.singbox if engine == "singbox" else self.tun_paths.tun2proxy):
                continue
            if self.tun_active == engine:
                continue  # работающий файл не заменить — обновится в следующий раз
            try:
                rel = dpi.latest_release(repo, proxy)
                tag = str(rel.get("tag_name") or "").lstrip("vV")
                if tag and tag != self.tun_paths.version(engine):
                    self.progress(f"Скачиваю {tun.ENGINE_NAMES[engine]} {tag}")
                    download(self.tun_paths, proxy, rel)
                    self.log(f"{tun.ENGINE_NAMES[engine]} обновлён: версия {tag}.")
            except Cancelled:
                raise
            except Exception as exc:
                self.log(f"Не удалось обновить {tun.ENGINE_NAMES[engine]}: {netutil.human_error(exc)}")

    def _after_connect(self) -> None:
        try:
            self._health_check()
            self._refresh_exit()
            if self.connected and not self._way_saving:
                self._way_saving = True
                self._remember_current()  # идут ли данные (для «Состояния») и запомнить способ для сети
        except Exception as exc:
            self.log(f"Проверка соединения: {exc}")

    def reconnect(self) -> None:
        """Применить новые настройки: перезапустить VPN или «рекламу без VPN» — что сейчас работает."""
        if self.connected and self.current:
            self.connect(self.current)
        elif self._filter_wanted():
            self.start_filter()
        elif self.filter_on:
            self.stop_filter()

    @property
    def core_running(self) -> bool:
        """Ядро работает: VPN, блокировка рекламы без VPN или kill switch."""
        return self.connected or self.filter_on or self.kill_on

    def kill_switch_active(self) -> bool:
        """Включён ли kill switch сейчас: сам по себе или потому что это чужая сеть (профиль сети)."""
        return bool(self.settings.get("kill_switch")) or self.net_profile.get("kill", False)

    def start_kill(self, reason: str) -> None:
        """VPN не работает, а kill switch включён: ядро без сервера, где «через VPN» — в никуда.
        Сайты, которые и так идут напрямую (российские), работают; остальное ждёт VPN. Системный прокси и TUN — на месте."""
        with self._conn_lock:
            self.progress("Закрываю интернет мимо VPN")
            server = self.current
            try:
                self._bring_up(self.KILL, self.paths.xray)
            except Exception as exc:
                # ядро не запускается совсем — системный прокси остаётся на нашем порту: браузеры тоже не уйдут мимо VPN
                self.log(f"Kill switch: ядро не запустилось ({exc}). Браузеры всё равно не пойдут мимо VPN.")
            self.connected = False
            self.filter_on = False
            self.kill_on = True
            self.current = server
        self._kill_at = time.time()
        self.problem("kill_switch", "VPN не работает — интернет мимо VPN закрыт", reason, where="Подключение",
                     fix="Программа пробует подключиться снова каждые 20 секунд. Нажми «Отключить», "
                         "чтобы открыть интернет без VPN.", level="error")
        self.log(f"Kill switch: {reason}. Сайты, которые идут через VPN, закрыты, пока VPN не заработает.")
        self.notify("status")

    def _kill_retry(self) -> None:
        """Kill switch: снова пробуем подключиться — к тому же серверу, потом к лучшему."""
        cands: list = []
        for x in (self.current, self.best()):
            if x is not None and all(x.key != y.key for y in cands):
                cands.append(x)
        for srv in cands:
            self.check_stop()
            try:
                self.connect(srv)
                self.log(f"Kill switch: VPN снова работает ({srv.name}).")
                return
            except Exception as exc:
                self.log(f"Kill switch: не подключилось ({exc}).")
        self.start_kill("сервер по-прежнему недоступен")

    def _recover(self, server: Server) -> None:
        """Ядро неожиданно остановилось: переподключаемся; не вышло — kill switch или честно отключаемся."""
        try:
            self.connect(server)
        except Cancelled:
            raise
        except Exception as exc:
            if self.kill_switch_active():
                self.start_kill(f"не удалось переподключиться: {exc}")
            else:
                self._take_down()
                raise

    def disconnect(self, quiet: bool = False, keep_filter: bool = True) -> None:
        """Отключить VPN. keep_filter — если включена «Блокировка рекламы без VPN», ядро сразу
        запускается снова без сервера (False — при обновлении ядра, смене портов и выходе)."""
        was = self.connected
        self.vpn_until = 0.0
        self._take_down()
        if was and not quiet:
            self.log("Отключено.")
        if keep_filter and not self._closing and self._filter_wanted():
            try:
                self.start_filter()
            except Exception as exc:
                self._filter_fail_at = time.time()
                self.log(f"Блокировка рекламы без VPN не включилась: {exc}")
        if not self._closing:
            self.notify("status")
            self.notify("live")

    def _take_down(self) -> None:
        with self._conn_lock:
            self.filter_on = False
            self.kill_on = False
            self.resolve("kill_switch")
            self.tun_proc.stop()
            self.proc.stop()
            self.bridge.stop()
            self._tun_sig = None
            self.connected = False
            if self.tun_active:
                self.tun_active = ""
                self._rebind_byedpi()
                self._phys_ip = ""
            if self.settings.get("proxy_backup_port") or sysproxy.is_ours(self.settings["http_port"]):
                sysproxy.restore(self.settings.get("proxy_backup"))
                self.settings["proxy_backup"] = None
                self.settings["proxy_backup_port"] = None
            try:
                os.remove(self.paths.pid_file)
            except OSError:
                pass
            self.live.update(ping=None, proxy_down=0.0, proxy_up=0.0, direct_down=0.0, direct_up=0.0,
                             exit_ip="", exit_loc="")

    def _refresh_exit(self) -> None:
        if not self.connected:
            return
        info = services.exit_info(self.ports.get("health"))
        if info["ip"]:
            self.live["exit_ip"], self.live["exit_loc"] = info["ip"], info["loc"]
            self.notify("live")

    # ---------- сервисы ----------

    def check_services(self) -> dict:
        self.progress("Проверяю сервисы")
        paths: dict = {"direct": self._direct_http()}
        if self.connected:
            paths["vpn"] = self.ports["health"]
            paths["current"] = self.ports["http"]
        else:
            paths["vpn"] = False
            paths["current"] = False
            self.log("Не подключено — сервисы проверены только напрямую. Подключись, чтобы проверить через VPN.")
        self.service_results = services.check_all(
            paths, on_result=lambda name, col, r: self.notify("service", name=name, column=col, result=r),
            stop_event=self.stop_event)
        self.notify("services")
        self.check_stop()
        if self.connected and self.settings.get("multi_enabled", True):
            self.multi_check(self.service_results)
        bad, outside = services.split_failures(self.service_results)
        for n in bad:
            detail = self.service_results[n].get("current", {}).get("detail") or ""
            if detail:
                self.log(f"{n}: {detail}.")
        if outside:
            self.log("Не отвечают даже без VPN — это не из-за программы: " + ", ".join(outside) + ".")
        if self.connected:
            self.log("Все сервисы открываются." if not bad else "Не открываются: " + ", ".join(bad) + ".")
            if bad:
                self.problem("services", "Не открываются сервисы: " + ", ".join(bad), where="Сервисы",
                             fix="Нажми «Исправить автоматически» на вкладке «Сервисы».")
            else:
                self.resolve("services")
        return self.service_results

    def autofix(self, results: dict | None = None) -> list[str]:
        """Если сервис не работает «как сейчас», но работает другим путём — добавляем правило."""
        results = results or self.service_results
        if not results or not self.connected:
            return []
        changes = []
        add_proxy, add_direct = [], []
        routes = self.settings.get("routes") or {}
        for svc in services.SERVICES:
            if f"svc:{svc['name']}" in routes:
                continue  # маршрут выбран вручную (сервер, свой прокси, обход) — не трогаем
            r = results.get(svc["name"], {})
            cur = r.get("current", {}).get("state")
            if cur not in (services.BLOCKED, services.REGION):
                continue
            if svc.get("russian"):
                if r.get("direct", {}).get("state") in (services.OK, services.SLOW):
                    add_direct += svc["domains"]
                    changes.append(f"{svc['name']} → напрямую")
            elif r.get("vpn", {}).get("state") in (services.OK, services.SLOW):
                add_proxy += svc["domains"]
                changes.append(f"{svc['name']} → через VPN")
        if add_proxy:
            self._add_to_list("proxy_list", add_proxy)
        if add_direct:
            self._add_to_list("direct_list", add_direct)
        if changes:
            self.log("Поправил маршруты: " + ", ".join(changes) + ".")
            self.notify("settings")
            self.reconnect()
        return changes

    # ---------- автоподбор для сайтов ----------
    # Новый сайт в журнале ядра → фоновая проверка → правило. Не открывается напрямую, а через VPN открывается —
    # сам уходит в VPN; через VPN закрыт для страны сервера — на другой сервер. Правило добавляется на лету
    # (API ядра), без переподключения. Ручные правила всегда главнее: сайты с ними автоподбор не трогает.
    # Приватность: сайты, которые сейчас идут через VPN, напрямую не проверяются — провайдер их не увидит.
    # В режиме «всё через VPN» сайт, который не открывается ни через один сервер, программа сама напрямую
    # не пускает и не проверяет — спрашивает человека (`_vpn_site_ask`).

    AUTO_SEEN_DAYS = 3        # проверенный и нормально работающий сайт снова проверяется не раньше
    AUTO_IGNORE_DAYS = 30     # убранное вручную автоправило не возвращается
    AUTO_MAX_PER_HOUR = 120
    AUTO_HEAVY_PER_HOUR = 15  # проверок через другие серверы (каждая — временное ядро) в час

    def _auto_init(self) -> None:
        self._auto_q: collections.deque = collections.deque(maxlen=100)
        self._auto_queued: set[str] = set()
        self._auto_event = threading.Event()
        self._auto_times: collections.deque = collections.deque(maxlen=self.AUTO_MAX_PER_HOUR)
        self._auto_pause_until = 0.0
        self._auto_live: dict[str, str] = {}   # запись → ruleTag, добавленные на лету в работающее ядро
        self._auto_api_ok = True
        self._auto_heavy: collections.deque = collections.deque(maxlen=self.AUTO_HEAVY_PER_HOUR)
        self.vpn_suspects: collections.deque = collections.deque(maxlen=20)  # «не открывается через VPN» — вопросы
        self._vpn_site_asked: set[str] = set()
        self._vpn_ask_times: collections.deque = collections.deque(maxlen=10)
        threading.Thread(target=self._auto_worker, daemon=True).start()

    def _auto_covered(self, host: str) -> bool:
        """Есть ли для сайта своё правило, маршрут сервиса или обход замедлений — тогда автоподбор не нужен."""
        s = self.settings
        if routing.user_rule(host, s):
            return True
        h = host.lower()
        for key, spec in (s.get("routes") or {}).items():
            if key.startswith("site:"):
                v = key[5:].lower()
                if h == v or h.endswith("." + v):
                    return True
            elif key.startswith("svc:"):
                svc = next((x for x in services.SERVICES if x["name"] == key[4:]), None)
                if svc and any(h == d or h.endswith("." + d) for d in svc["domains"]):
                    return True
        for d in self.dpi_domains() if self.dpi_mode else []:
            if h == d or h.endswith("." + d):
                return True
        return False

    def _auto_offer(self, host: str, outbound: str, port: int) -> None:
        """Из журнала ядра: новый адрес. Ставит его в очередь проверки, если это нужно."""
        s = self.settings
        if not s.get("auto_routes", True) or not self.connected or outbound not in ("direct", "proxy") \
                or port not in (80, 443):
            return
        h = host.lower().strip(".")
        if not h or "." not in h or routing.is_ip_entry(h) or h.endswith((".local", ".lan", ".arpa")):
            return
        entry = self._auto_entry(h)
        now = time.time()
        auto = s.get("auto_sites") or {}
        seen = s.get("auto_seen") or {}
        if entry in auto or entry in self._auto_queued:
            return
        mark = seen.get(entry)
        if mark and now - float(mark.get("at", 0)) < (self.AUTO_IGNORE_DAYS if mark.get("ignore") else self.AUTO_SEEN_DAYS) * 86400:
            return
        if self._auto_covered(h):
            return
        self._auto_queued.add(entry)
        self._auto_q.append((entry, h, outbound, 443 if port == 443 else 80))
        self._auto_event.set()

    # общие CDN и хостинги: на одном основном домене тысячи чужих сайтов — правило ставим на сам адрес
    SHARED_HOSTS = frozenset("""cloudfront.net akamaized.net akamaihd.net akamai.net edgekey.net edgesuite.net
        fastly.net fastlylb.net b-cdn.net cdn77.org azureedge.net azurefd.net amazonaws.com googleusercontent.com
        r2.dev workers.dev pages.dev github.io vercel.app netlify.app herokuapp.com firebaseapp.com web.app
        appspot.com blogspot.com wixsite.com tilda.ws ucoz.ru narod.ru""".split())

    def _auto_entry(self, host: str) -> str:
        entry = routing.site_entry(host)
        return host if entry in self.SHARED_HOSTS else entry

    def _auto_mark(self, entry: str, ignore: bool = False) -> None:
        seen = self.settings.setdefault("auto_seen", {})
        seen[entry] = {"at": time.time(), **({"ignore": True} if ignore else {})}
        if len(seen) > 3000:  # не копим бесконечно: выкидываем самые старые
            for k, _ in sorted(seen.items(), key=lambda kv: kv[1].get("at", 0))[:500]:
                seen.pop(k, None)

    def _auto_worker(self) -> None:
        while not self._closing:
            self._auto_event.wait(5)
            self._auto_event.clear()
            while self._auto_q and not self._closing:
                if not self.connected or time.time() < self._auto_pause_until:
                    self._auto_q.clear()
                    self._auto_queued.clear()
                    break
                if len(self._auto_times) >= self.AUTO_MAX_PER_HOUR and time.time() - self._auto_times[0] < 3600:
                    break  # не больше 120 проверок в час
                entry, host, outbound, port = self._auto_q.popleft()
                self._auto_times.append(time.time())
                try:
                    self._auto_probe(entry, host, outbound, port)
                except Exception as exc:  # проверка одного сайта не должна ломать остальные
                    self.log(f"Автоподбор: {entry}: {exc}")
                finally:
                    self._auto_queued.discard(entry)
                time.sleep(0.3)

    def _auto_probe(self, entry: str, host: str, outbound: str, port: int) -> None:
        url = f"{'https' if port == 443 else 'http'}://{host}/"
        good = lambda r: bool(r) and r["state"] in (services.OK, services.SLOW)  # noqa: E731
        if outbound == "direct":
            r = services.check_url(url, self._direct_http(), region_sensitive=False, timeout=6)
            if good(r):
                # открывается, но качается ли? Частая поломка: страница есть, а картинки и видео — нет
                if port == 443 and self.settings.get("auto_stall", True):
                    st = services.stall_test(host, self._direct_http())
                    if st["state"] == services.STALL_STALL:
                        sv = services.stall_test(host, self.ports["health"])
                        if sv["state"] in (services.STALL_OK, services.STALL_SMALL):
                            self._auto_add(entry, {"via": "proxy",
                                                   "why": f"напрямую {st['detail']}: картинки и видео не грузятся"})
                            return
                self._auto_mark(entry)
                return
            if not self.connected:
                return
            rv = services.check_url(url, self.ports["health"], region_sensitive=True, timeout=10)
            if not good(rv):
                self._auto_mark(entry)  # не открывается вообще — сайт лежит, правило не поможет
                return
            # напрямую не открылся, а через VPN открылся. Сначала убедимся, что у нас вообще есть интернет напрямую
            # (иначе при сбое провайдера всё подряд уехало бы в VPN)
            ctl = services.check_url("https://ya.ru/", self._direct_http(), region_sensitive=False, timeout=6)
            if not good(ctl):
                self._auto_pause_until = time.time() + 600
                self.log("Автоподбор: напрямую не открывается ничего — похоже на сбой сети, подожду 10 минут.")
                return
            self._auto_add(entry, {"via": "proxy", "why": f"напрямую: {r['detail']}"})
            return
        # сайт идёт через VPN: проверяем только через VPN (напрямую не трогаем — провайдер не должен его видеть)
        rv = services.check_url(url, self.ports["health"], region_sensitive=True, timeout=10)
        if rv["state"] == services.BLOCKED:
            # не соединилось. Если сейчас подводит сам VPN — сайт ни при чём: проверим его в другой раз
            if self._ping_failures or self.kill_on:
                return
            time.sleep(1)
            rv = services.check_url(url, self.ports["health"], region_sensitive=True, timeout=12)
        if good(rv) or rv["state"] not in (services.REGION, services.BLOCKED):
            self._auto_mark(entry)
            return
        now = time.time()
        if len(self._auto_heavy) >= self.AUTO_HEAVY_PER_HOUR and now - self._auto_heavy[0] < 3600:
            return  # другие серверы уже много раз проверяли за этот час — сайт проверится, когда откроют снова
        self._auto_heavy.append(now)
        srv = self._auto_other_server(url)
        if srv:
            self._auto_add(entry, {"via": "server", "server": srv.key, "server_name": srv.name,
                                   "why": f"через «{self.current.name if self.current else '?'}»: {rv['detail']}"})
            return
        self._auto_mark(entry)
        main_page = host in (entry, "www." + entry) and entry not in self.SHARED_HOSTS
        if self.settings.get("mode", "vpn") == "vpn" and main_page:
            self._vpn_site_ask(entry, rv["detail"])
        elif rv["state"] == services.REGION:
            self.log(f"Автоподбор: {entry} закрыт для страны сервера, а другого рабочего сервера не нашлось.")

    VPN_ASK_PER_10MIN = 3

    def _vpn_site_ask(self, site: str, detail: str) -> None:
        """Сайт не открывается ни через один сервер. Без VPN он, возможно, работает, но проверять его напрямую
        без спроса нельзя (провайдер увидит сайт) — спрашиваем: пустить напрямую?"""
        if not self.settings.get("auto_ask_direct", True) or site in self._vpn_site_asked:
            return
        now = time.time()
        if sum(1 for t in self._vpn_ask_times if now - t < 600) >= self.VPN_ASK_PER_10MIN:
            return
        self._vpn_site_asked.add(site)
        self._vpn_ask_times.append(now)
        item = {"site": site, "detail": detail, "at": now}
        self.vpn_suspects = collections.deque([x for x in self.vpn_suspects if x["site"] != site], maxlen=20)
        self.vpn_suspects.appendleft(item)
        self.log(f"Автоподбор: {site} не открывается через VPN ни через один сервер ({detail}). "
                 f"Если без VPN он работает — ответь «Напрямую» в окне программы.")
        self.notify("vpn_site", item=dict(item, detail=i18n.tr(detail)))
        lang_en = self.settings.get("lang") == "en"
        self.tray_queue.append((
            "Site doesn't open through the VPN" if lang_en else "Сайт не открывается через VPN",
            (f"{site} doesn't open through any server. Open the app to send it direct."
             if lang_en else f"{site} не открывается ни через один сервер. Открой программу, чтобы пустить его напрямую.")))

    def vpn_site_answer(self, site: str, direct: bool) -> str:
        """Ответ на «сайт не открывается через VPN»: пустить напрямую (своё правило) или оставить через VPN."""
        site = self.site_key(site, main_domain=False)
        self.vpn_suspects = collections.deque([x for x in self.vpn_suspects if x["site"] != site], maxlen=20)
        if direct:
            self.route_site(site, "direct", main_domain=False)
        else:
            self._auto_mark(site, ignore=True)  # больше не спрашивать
            self.log(f"{site}: оставил через VPN, больше не спрошу.")
            self.save()
            self.notify("settings")
        return site

    def _auto_other_server(self, url: str) -> Server | None:
        """Другой сервер (другой страны), через который сайт открывается."""
        if not self.current or not self.proc.alive():
            return None
        exe = self.proc.exe
        cur_cc = countries.detect(self.current.name)[0]
        cands = [x for x in tester.ranked(self.servers, key=self._rank_key())
                 if x.key != self.current.key and x.supported and self.paths.exe_for(x) == exe and x.engine == "xray"]
        cands.sort(key=lambda x: countries.detect(x.name)[0] == cur_cc)  # сначала другие страны
        cands = cands[:3]
        if not cands:
            return None
        ports = netutil.find_free_ports(len(cands), avoid=tester.RESERVED_PORTS)
        proc = XrayProcess(self.paths)
        try:
            proc.start(xray.build_test_config(cands, ports, None, self._version_for(exe)), os.path.join(self.paths.data_dir, "auto_test.json"),
                       wait_for=ports, exe=exe)
            for srv, p in zip(cands, ports):
                r = services.check_url(url, p, region_sensitive=True, timeout=10)
                if r["state"] in (services.OK, services.SLOW):
                    return srv
        except XrayError:
            return None
        finally:
            proc.stop()
        return None

    def _auto_add(self, entry: str, spec: dict) -> None:
        spec = dict(spec, at=time.time())
        self.settings.setdefault("auto_sites", {})[entry] = spec
        self.save()
        where = "через VPN" if spec["via"] == "proxy" else f"через сервер «{spec.get('server_name', '?')}»"
        self.log(f"Автоподбор: {entry} — {where} ({spec.get('why', '')}).")
        self.notify("info", text=f"{entry}: теперь {where}")
        self.notify("settings")
        if not self._auto_apply_live(entry, spec):
            self._auto_reconnect_soon()

    def _auto_rule(self, entry: str, tag: str) -> dict:
        domains, ips, _ = routing.split_entries(entry)
        rule = {"type": "field", "ruleTag": f"auto-{len(self._auto_live)}-{entry}"[:60], "outboundTag": tag}
        if domains:
            rule["domain"] = domains
        if ips:
            rule["ip"] = ips
        return rule

    def _auto_apply_live(self, entry: str, spec: dict) -> bool:
        """Добавить правило в работающее ядро через его API — без переподключения. False — не вышло."""
        if not self._auto_api_ok or not self.connected or not self.proc.alive() or self.conn_busy():
            return False
        exe = self.proc.exe
        tag = "proxy"
        tmp_o = os.path.join(self.paths.data_dir, "auto-outbound.json")
        tmp_r = os.path.join(self.paths.data_dir, "auto-rule.json")
        try:
            if spec["via"] == "server":
                srv = self.find(spec.get("server", ""))
                if not srv or self.paths.exe_for(srv) != exe:
                    return False
                tag = f"auto{len(self._auto_live)}"
                obs = xray.proxy_outbounds(srv, tag, self._use_mask(srv), self._version_for(exe), self.tun_bind)
                with open(tmp_o, "w", encoding="utf-8") as f:
                    json.dump({"outbounds": obs}, f, ensure_ascii=False)
                if not xray.api_command(self.paths, self.ports["api"], ["ado", tmp_o], exe=exe):
                    self._auto_api_ok = False
                    return False
            rule = self._auto_rule(entry, tag)
            with open(tmp_r, "w", encoding="utf-8") as f:
                json.dump({"routing": {"domainStrategy": "IPIfNonMatch", "rules": [rule]}}, f, ensure_ascii=False)
            if not xray.api_command(self.paths, self.ports["api"], ["adrules", "-append", tmp_r], exe=exe):
                self._auto_api_ok = False  # эта версия ядра не умеет — дальше применяем переподключением
                return False
        except OSError:
            return False
        self._auto_live[entry] = rule["ruleTag"]
        return True

    def _auto_reconnect_soon(self) -> None:
        """Правило не добавилось на лету — переподключаемся (одним разом для нескольких сайтов подряд)."""
        if getattr(self, "_auto_reconnect_pending", False):
            return
        self._auto_reconnect_pending = True

        def later():
            time.sleep(5)
            self._auto_reconnect_pending = False
            if self.connected:
                self.run_task("Применяю автоподбор", self.reconnect, lane="conn")
        threading.Thread(target=later, daemon=True).start()

    def _auto_plan(self, main: Server, exe: str, pins: dict) -> list[dict]:
        """Автоправила для конфига ядра (после рекламы, до встроенных списков)."""
        out = []
        for entry, spec in (self.settings.get("auto_sites") or {}).items():
            if self._auto_covered(entry):
                continue  # потом появилось своё правило — оно главнее
            domains, ips, _ = routing.split_entries(entry)
            item = {"domains": domains, "ips": ips, "auto": True}
            if spec.get("via") == "server":
                srv = self.find(spec.get("server", ""))
                if not srv or not srv.supported or srv.key == main.key or self.paths.exe_for(srv) != exe:
                    item["tag"] = "proxy"
                else:
                    item.update(tag=pins.setdefault(srv.key, f"pin{len(pins)}"), server=srv, mask=self._use_mask(srv))
            else:
                item["tag"] = "proxy"
            out.append(item)
        return out

    def auto_state(self) -> dict:
        s = self.settings
        items = []
        for entry, spec in sorted((s.get("auto_sites") or {}).items(), key=lambda kv: -kv[1].get("at", 0)):
            items.append({"site": entry, "via": spec.get("via"), "server": spec.get("server_name", ""),
                          "why": i18n.tr(spec.get("why", "")), "at": spec.get("at", 0)})
        return {"enabled": bool(s.get("auto_routes", True)), "items": items[:300], "total": len(items),
                "checked": len(s.get("auto_seen") or {}), "queue": len(self._auto_q)}

    def auto_forget(self, entry: str, pin: bool = False) -> None:
        """Убрать автоправило. pin=True — закрепить: сделать своим маршрутом с тем же выбором."""
        s = self.settings
        spec = (s.get("auto_sites") or {}).pop(entry, None)
        if spec is None:
            raise RuntimeError("Такого автоправила нет.")
        if pin:
            target = f"server:{spec['server']}" if spec.get("via") == "server" else "proxy"
            try:
                self.route_site(entry, target, main_domain=False)
            except RuntimeError:
                self.route_site(entry, "proxy", main_domain=False)
            self.log(f"Автоподбор: {entry} — закреплено как своё правило.")
        else:
            self._auto_mark(entry, ignore=True)  # больше сам не добавит
            self.log(f"Автоподбор: {entry} — правило убрано.")
        self.save()
        self.notify("settings")

    def auto_clear(self) -> None:
        """Начать подбор заново: убрать автоправила и забыть проверки (кроме сайтов, убранных вручную)."""
        s = self.settings
        s["auto_sites"] = {}
        s["auto_seen"] = {k: v for k, v in (s.get("auto_seen") or {}).items() if v.get("ignore")}
        self.save()
        self.log("Автоподбор: все автоправила убраны, подбор начнётся заново.")
        self.notify("settings")

    # ---------- Мультисервер ----------

    def _multi_routes(self, main: Server, exe: str) -> list[dict]:
        """Дополнительные серверы для сервисов, которые не открываются через основной."""
        s = self.settings
        if not s.get("multi_enabled", True):
            return []
        by_server: dict[str, list[str]] = {}
        manual = self._manual_services()
        for name, key in (s.get("multi_map") or {}).items():
            srv = self.find(key)
            svc = next((x for x in services.SERVICES if x["name"] == name), None)
            if not srv or not svc or not srv.supported or srv.key == main.key or self.paths.exe_for(srv) != exe \
                    or name in manual:
                continue
            by_server.setdefault(srv.key, []).extend(svc["domains"])
        return [{"tag": f"multi{i}", "server": self.find(key), "domains": doms, "mask": self._use_mask(self.find(key))}
                for i, (key, doms) in enumerate(by_server.items())]

    def multi_check(self, results: dict | None = None) -> dict:
        """Мультисервер: ищет для «сломанных» на основном сервере сервисов другой сервер, где они работают."""
        s = self.settings
        if not s.get("multi_enabled", True) or not self.connected or not self.current:
            return {}
        results = results or self.service_results or {}
        manual = self._manual_services()  # где маршрут выбран вручную, Мультисервер не вмешивается
        bad = [svc for svc in services.SERVICES if not svc.get("russian") and svc["name"] not in manual
               and results.get(svc["name"], {}).get("vpn", {}).get("state") in (services.BLOCKED, services.REGION)]
        old = dict(s.get("multi_map") or {})
        new: dict[str, str] = {}
        if bad:
            exe = self.proc.exe
            cands = [x for x in tester.ranked(self.servers, key=self._rank_key())
                     if x.key != self.current.key and self.paths.exe_for(x) == exe and x.engine != "awg"][:4]
            names = ", ".join(svc["name"] for svc in bad)
            if cands:
                self.progress(f"Мультисервер: ищу серверы для {names}")
                ports = netutil.find_free_ports(len(cands), avoid=tester.RESERVED_PORTS)
                proc = XrayProcess(self.paths)
                try:
                    proc.start(xray.build_test_config(cands, ports, None, self._version_for(exe)), self.paths.test_config,
                               wait_for=ports, exe=exe)
                    for svc in bad:
                        self.check_stop()
                        for srv, port in zip(cands, ports):
                            if services.check_service(svc, port)["state"] in (services.OK, services.SLOW):
                                new[svc["name"]] = srv.key
                                break
                except XrayError as exc:
                    self.log(f"Мультисервер: не удалось проверить другие серверы ({exc}).")
                    new = old
                finally:
                    proc.stop()
            for svc in bad:
                if svc["name"] in new:
                    srv = self.find(new[svc["name"]])
                    if old.get(svc["name"]) != new[svc["name"]]:
                        self.log(f"Мультисервер: {svc['name']} → через «{srv.name if srv else '?'}».")
                else:
                    self.log(f"Мультисервер: для {svc['name']} не нашлось рабочего сервера.")
        s["multi_map"] = new
        s["multi_checked_at"] = time.time()
        self.save()
        if new != old:
            if not new:
                self.log("Мультисервер: все сервисы снова работают через основной сервер.")
            self.reconnect()
        self.notify("status")
        return new

    def multi_state(self) -> dict:
        s = self.settings
        items = []
        for name, key in (s.get("multi_map") or {}).items():
            srv = self.find(key)
            if srv:
                cc, clean = countries.detect(srv.name)
                items.append({"service": name, "server": clean, "cc": cc, "key": key})
        return {"enabled": bool(s.get("multi_enabled", True)), "map": items, "checked_at": s.get("multi_checked_at", 0)}

    def check_site(self, raw: str) -> dict:
        """«Проверить сайт»: пробует открыть сайт напрямую, через VPN, через другие серверы и как сейчас
        и сам выбирает рабочий путь. Человек сам попросил проверить — поэтому и напрямую тоже."""
        url = (raw or "").strip()
        if not url:
            raise RuntimeError("Вставь адрес сайта, например example.com.")
        if "://" not in url:
            url = "https://" + url
        host = (urlsplit(url).hostname or "").lower()
        if "." not in host:
            raise RuntimeError("Не похоже на адрес сайта. Пример: example.com.")
        self.progress(f"Проверяю сайт {host}")
        good = lambda r: bool(r) and r["state"] in (services.OK, services.SLOW)  # noqa: E731
        entry = routing.site_entry(host)
        res: dict = {}
        action, verdict, server_name = "", "", ""
        # закрыт блокировщиком рекламы? Тогда дело не в VPN
        ads = {}
        try:
            ads = self.ads_lookup(host) if self.settings.get("block_ads") else {}
        except RuntimeError:
            ads = {}
        ads_lists = [self._ads_list_name(x["id"]) for x in ads.get("lists") or []] if ads.get("blocked") else []
        if ads.get("blocked") and not ads.get("custom") and ads_lists and [x["id"] for x in ads["lists"]] != ["threats"]:
            self.ads_allow(host)
            self.build_adblock()
            self.apply_ads()
            action = "ads"
            verdict = f"Сайт был закрыт блокировщиком рекламы (список {', '.join(f'«{n}»' for n in ads_lists)}) — разрешил его."
        paths: dict = {"direct": self._direct_http()}
        if self.connected:
            paths.update(vpn=self.ports["health"], current=self.ports["http"])
        for column, port in paths.items():
            self.check_stop()
            res[column] = services.check_url(url, port, region_sensitive=True)
        if action:
            pass
        elif ads_lists:
            verdict = (f"Сайт в списке опасных сайтов ({', '.join(ads_lists)}). Если уверен в нём — нажми «Разрешить» "
                       f"в разделе «Реклама».")
        elif not self.connected:
            verdict = ("Сайт открывается без VPN." if good(res["direct"]) else
                       "Без VPN сайт не открывается. Подключись — программа проверит его через VPN и сама настроит.")
        elif good(res["current"]):
            verdict = ("Сайт отвечает. Если в браузере он всё равно не работает (просит выключить VPN, капча по кругу), "
                       "выбери ниже, как его открывать.")
        elif good(res["vpn"]):
            self._add_to_list("proxy_list", [entry])
            action = "proxy"
            verdict = f"Сайт открывается только через VPN — добавил {entry} в «Всегда через VPN»."
        else:
            # через этот сервер не открывается: сначала другие серверы (сайт остаётся за VPN), потом напрямую
            other = self._auto_other_server(url)
            if other:
                res["other"] = {"state": services.OK, "detail": other.name, "ms": None}
                self.route_site(entry, f"server:{other.key}", main_domain=False)
                action, server_name = "server", other.name
                verdict = f"Через этот сервер сайт не открывается, а через «{other.name}» — да. Теперь {entry} идёт через него."
            elif good(res["direct"]):
                self.route_site(entry, "direct", main_domain=False)
                action = "direct"
                verdict = (f"Через VPN сайт не открывается ни через один сервер, а без VPN — открывается. "
                           f"Теперь {entry} идёт напрямую.")
            else:
                verdict = ("Сайт не открывается ни напрямую, ни через серверы подписки. Похоже, он сейчас не работает "
                           "или закрыт для этих стран.")
        if action:
            self.save()
            self.notify("settings")
            if action in ("proxy", "server", "direct"):
                self.reconnect()
            res["after"] = services.check_url(url, self.ports["http"] if self.connected else self._direct_http(),
                                              region_sensitive=True)
            verdict += " Проверил: теперь открывается." if good(res["after"]) else " Но и так пока не открывается."
        self.vpn_suspects = collections.deque([x for x in self.vpn_suspects if x["site"] != entry], maxlen=20)
        self.log(f"Проверка сайта {host}: {verdict}")
        result = {"host": host, "site": entry, "results": res, "verdict": i18n.tr(verdict), "action": action,
                  "route": self._site_choice(entry), "server": server_name}
        self.notify("site", result=result)
        return result

    def _site_choice(self, entry: str) -> str:
        """Текущий свой выбор для сайта (как в «Своих маршрутах»): auto / proxy / direct / block / server:… / …"""
        spec = (self.settings.get("routes") or {}).get(f"site:{entry}")
        if spec:
            return self._route_value(spec)
        return routing.user_rule(entry, self.settings) or "auto"

    # ---------- «Сайт работает не полностью» ----------

    REPAIR_WINDOW = 20      # адреса, к которым обращались за столько секунд до и после захода на сайт
    REPAIR_LOOKBACK = 900   # заход на сайт ищем за последние 15 минут
    REPAIR_MAX = 25

    def _related_hosts(self, site: str) -> list[tuple[str, str]]:
        """Адреса, которые загружал сайт (картинки, видео, CDN): к ним обращались вместе с ним.
        → [(адрес, куда шёл)], сначала свои поддомены, потом самые «совпадающие» по времени."""
        now = time.time()
        log = [x for x in list(self._host_log) if now - x[0] < self.REPAIR_LOOKBACK]
        mine = lambda h: h == site or h.endswith("." + site)  # noqa: E731
        hits = [t for t, h, _ in log if mine(h)]
        if not hits:
            return []
        score: dict[str, int] = {}
        route: dict[str, str] = {}
        for t, h, out in log:
            route[h] = out
            if mine(h) or any(abs(t - x) <= self.REPAIR_WINDOW for x in hits):
                score[h] = score.get(h, 0) + (1000 if mine(h) else 1)
        ranked = sorted(score, key=lambda h: -score[h])
        return [(h, route[h]) for h in ranked[:self.REPAIR_MAX]]

    def repair_site(self, raw: str) -> dict:
        """Сайт открывается, но не работает целиком (картинки, видео): проверить всё, что он загружал,
        разными путями и пустить сломанное туда, где оно работает."""
        text = (raw or "").strip()
        if "://" not in text:
            text = "https://" + text
        host = (urlsplit(text).hostname or "").lower()
        if "." not in host:
            raise RuntimeError("Не похоже на адрес сайта. Пример: example.com.")
        if not self.connected:
            raise RuntimeError("Сначала подключись к VPN: программа сравнит, как сайт работает напрямую и через VPN.")
        site = routing.site_entry(host)
        self.progress(f"Чиню сайт {site}")
        related = self._related_hosts(site)
        seen_site = bool(related)
        if not related:
            related = [(host, "")] + ([("www." + site, "")] if host == site else [])
        out, fixes, bad_others = [], 0, []
        direct_fixes = 0
        other_ports: list | None = None
        proc = None
        try:
            for h, route in related:
                self.check_stop()
                self.progress(f"Чиню сайт {site}: {h}")
                item = {"host": h, "route": route, "state": "", "detail": "", "fix": ""}
                out.append(item)
                if route in ("block", adblock.OUTBOUND):
                    item.update(state="blocked", detail="закрыт блокировщиком рекламы" if route == adblock.OUTBOUND
                                else "закрыт своим правилом «Блокировать»")
                    continue
                if routing.is_ip_entry(h):
                    item.update(state="skip")
                    continue
                direct = route == "direct" or (not route and not routing.user_rule(h, self.settings)
                                               and self._route_of(h) == "direct")
                if direct:
                    st = services.stall_test(h, self._direct_http())
                else:
                    st = services.stall_test(h, self.ports["health"])
                item.update(state=st["state"], detail=st["detail"])
                if st["state"] in (services.STALL_OK, services.STALL_SMALL):
                    continue
                entry = self._auto_entry(h)
                if self._auto_covered(h):
                    item["detail"] = (item["detail"] + "; " if item["detail"] else "") + "есть своё правило — не меняю"
                    continue  # своё правило главнее — только показываем
                if direct:
                    sv = services.stall_test(h, self.ports["health"])
                    if sv["state"] in (services.STALL_OK, services.STALL_SMALL):
                        self._auto_add(entry, {"via": "proxy", "why": f"чинил «{site}»: напрямую {st['detail'] or 'не открывается'}"})
                        item["fix"] = "proxy"
                        fixes += 1
                        continue
                # через этот сервер не работает — пробуем другие серверы
                if other_ports is None:
                    other_ports, proc = self._repair_servers()
                for srv, p in other_ports or []:
                    self.check_stop()
                    so = services.stall_test(h, p)
                    if so["state"] in (services.STALL_OK, services.STALL_SMALL):
                        self._auto_add(entry, {"via": "server", "server": srv.key, "server_name": srv.name,
                                               "why": f"чинил «{site}»: через «{self.current.name if self.current else '?'}» "
                                                      f"{st['detail'] or 'не открывается'}"})
                        item.update(fix="server", server=srv.name)
                        fixes += 1
                        break
                else:
                    if not direct:
                        # ни через один сервер не качается. Человек сам попросил починить — пробуем и без VPN
                        sd = services.stall_test(h, self._direct_http())
                        if sd["state"] in (services.STALL_OK, services.STALL_SMALL):
                            self._add_to_list("direct_list", [entry])
                            item["fix"] = "direct"
                            fixes += 1
                            direct_fixes += 1
                            continue
                    bad_others.append(h)
        finally:
            if proc:
                proc.stop()
        if direct_fixes:
            self.save()
            self.notify("settings")
            self.reconnect()
        broken = [x for x in out if x["state"] in (services.STALL_STALL, services.STALL_FAIL)]
        blocked = [x for x in out if x["state"] == "blocked"]
        if fixes:
            verdict = (f"Починил {fixes} из {len(broken)}: эти адреса теперь идут туда, где работают. Обнови страницу сайта."
                       + (" Те, что работают только без VPN, — в «Всегда напрямую»." if direct_fixes else ""))
        elif broken:
            verdict = ("Нашёл неработающие адреса, но рабочего пути для них нет ни напрямую, ни через другие серверы. "
                       "Возможно, сломан сам сайт.")
        elif blocked:
            verdict = "Все адреса качаются. Часть закрыта блокировщиком — если сайт без них не работает, разреши их."
        elif not seen_site:
            verdict = ("Сам сайт работает. Открой его в браузере (с картинками и видео) и нажми кнопку ещё раз — "
                       "тогда программа увидит все адреса, которые он загружает.")
        else:
            verdict = "Все адреса сайта работают. Если что-то всё ещё не грузится, обнови страницу с очисткой кэша (Ctrl+F5)."
        self.log(f"Починка сайта {site}: проверено {len(out)}, исправлено {fixes}.")
        result = {"site": site, "hosts": [dict(x, detail=i18n.tr(x["detail"])) for x in out], "fixed": fixes,
                  "verdict": i18n.tr(verdict), "seen": seen_site}
        self.notify("repair", result=result)
        return result

    def _route_of(self, host: str) -> str:
        """Куда сейчас идёт адрес по журналу ядра (если он там есть)."""
        c = self.connections.get(host)
        return c["route"] if c else ""

    def _repair_servers(self):
        """До трёх других серверов (сначала других стран) во временном ядре → ([(сервер, порт)], процесс)."""
        if not self.current or not self.proc.alive():
            return [], None
        exe = self.proc.exe
        cur_cc = countries.detect(self.current.name)[0]
        cands = [x for x in tester.ranked(self.servers, key=self._rank_key())
                 if x.key != self.current.key and x.supported and self.paths.exe_for(x) == exe and x.engine == "xray"]
        cands.sort(key=lambda x: countries.detect(x.name)[0] == cur_cc)
        cands = cands[:3]
        if not cands:
            return [], None
        ports = netutil.find_free_ports(len(cands), avoid=tester.RESERVED_PORTS)
        proc = XrayProcess(self.paths)
        try:
            proc.start(xray.build_test_config(cands, ports, None, self._version_for(exe)),
                       os.path.join(self.paths.data_dir, "repair_test.json"), wait_for=ports, exe=exe)
        except XrayError:
            return [], None
        return list(zip(cands, ports)), proc

    def _add_to_list(self, key: str, entries: list[str]) -> None:
        lines = [ln for ln in self.settings.get(key, "").splitlines() if ln.strip()]
        existing = {ln.strip().lower() for ln in lines}
        for e in entries:
            if e.lower() not in existing:
                lines.append(e)
                existing.add(e.lower())
        self.settings[key] = "\n".join(lines)
        # убираем из противоположных списков и своих маршрутов сайтов, чтобы правила не спорили
        for other in ("proxy_list", "direct_list", "block_list"):
            if other == key:
                continue
            kept = [ln for ln in self.settings.get(other, "").splitlines() if ln.strip().lower() not in existing]
            self.settings[other] = "\n".join(kept)
        routes = self.settings.get("routes") or {}
        for k in [k for k in routes if k.startswith("site:") and k[5:].lower() in existing]:
            routes.pop(k, None)

    def reset_site(self, host: str) -> list[str]:
        """Убирает свои правила для сайта — он снова идёт как по умолчанию."""
        removed = []
        for key, _ in routing.USER_LISTS:
            text, gone = routing.remove_host(self.settings.get(key, ""), host)
            self.settings[key] = text
            removed += gone
        routes = self.settings.get("routes") or {}
        for k in list(routes):
            if k.startswith("site:") and (k[5:] == host.lower() or
                                          routing.user_rule(host, {"proxy_list": k[5:]}) == "proxy"):
                routes.pop(k)
                removed.append(k[5:])
        if removed:
            self.save()
            self.log(f"Сброшены правила для {host}: {', '.join(removed)}.")
            self.notify("settings")
        return removed

    def reset_rules(self, key: str | None = None) -> None:
        keys = [key] if key else [k for k, _ in routing.USER_LISTS]
        for k in keys:
            self.settings[k] = ""
        if not key:  # «Сбросить все» — и свои маршруты сервисов и сайтов (свои прокси остаются)
            self.settings["routes"] = {}
        self.save()
        self.log("Свои правила сброшены." if not key else "Список правил очищен.")
        self.notify("settings")

    # ---------- свои маршруты: сервис или сайт → VPN, напрямую, обход замедления, другой сервер, свой прокси ----------

    LIST_TARGETS = {"proxy": "proxy_list", "direct": "direct_list", "block": "block_list"}

    def _check_target(self, target: str) -> dict | None:
        """Проверяет выбор маршрута. None — для auto/proxy/direct/block (они живут в списках), иначе запись routes."""
        if target in ("auto", *self.LIST_TARGETS):
            return None
        if target == "dpi":
            return {"via": "dpi"}
        if target.startswith("server:"):
            srv = self.find(target[7:])
            if not srv:
                raise RuntimeError("Сервер не найден — обнови подписку.")
            if not srv.supported:
                raise RuntimeError(f"Этот сервер не поддерживается: {srv.note}")
            return {"via": "server", "server": srv.key, "server_name": srv.name}
        if target.startswith("custom:"):
            if not self._proxy_by_id(target[7:]):
                raise RuntimeError("Прокси не найден.")
            return {"via": "custom", "proxy": target[7:]}
        raise RuntimeError("Неизвестное действие.")

    @staticmethod
    def _route_value(spec: dict) -> str:
        via = spec.get("via")
        return {"server": f"server:{spec.get('server', '')}", "custom": f"custom:{spec.get('proxy', '')}"}.get(via, via)

    def _route_label(self, target: str) -> str:
        """Подпись выбора для журнала (без адресов и паролей)."""
        if target.startswith("server:"):
            srv = self.find(target[7:])
            return f"через сервер «{countries.detect(srv.name)[1] if srv else '?'}»"
        if target.startswith("custom:"):
            p = self._proxy_by_id(target[7:])
            return f"через прокси «{self._proxy_title(p) if p else '?'}»"
        return {"proxy": "всегда через VPN", "direct": "всегда напрямую", "block": "блокируется",
                "dpi": "напрямую с обходом замедления", "auto": "как по умолчанию"}.get(target, target)

    def _drop_route(self, key: str) -> bool:
        routes = self.settings.setdefault("routes", {})
        spec = routes.pop(key, None)
        return bool(spec and spec.get("via") == "dpi")

    def set_service_route(self, name: str, target: str) -> bool:
        """Как подключаться к сервису: auto — как по умолчанию, proxy — через VPN, direct — напрямую, block,
        dpi — напрямую с обходом замедления, server:<ключ> — через другой сервер, custom:<id> — через свой прокси.
        Возвращает True, если поменялись сайты обхода замедления (нужно перезапустить zapret)."""
        svc = next((x for x in services.SERVICES if x["name"] == name), None)
        if not svc:
            raise RuntimeError("Сервис не найден.")
        spec = self._check_target(target)
        for domain in svc["domains"]:
            for key, _ in routing.USER_LISTS:
                self.settings[key] = routing.remove_host(self.settings.get(key, ""), domain)[0]
        dpi_changed = self._drop_route(f"svc:{name}")
        if target in self.LIST_TARGETS:
            self._add_to_list(self.LIST_TARGETS[target], svc["domains"])
        elif spec:
            self.settings["routes"][f"svc:{name}"] = spec
            dpi_changed = dpi_changed or spec["via"] == "dpi"
        if (self.settings.get("multi_map") or {}).pop(name, None):
            self.log(f"Мультисервер: {name} больше не подбирается сам — выбран свой маршрут.")
        self.save()
        self.log(f"{name}: {self._route_label(target)}.")
        self.notify("settings")
        return dpi_changed

    @staticmethod
    def site_key(raw: str, main_domain: bool = False) -> str:
        """Адрес сайта от пользователя → запись для правил: домен (без www) или IP.
        main_domain=True — основной домен (music.yandex.ru → yandex.ru), как для сайтов из журнала соединений."""
        text = (raw or "").strip()
        if "://" in text:
            text = urlsplit(text).hostname or ""
        text = text.split("/", 1)[0].strip()
        try:
            item = routing.normalize_entry(text)
        except ValueError:
            item = None
        if not item or not (item[0] == "ip" and not item[1].startswith("geoip:") or item[1].startswith("domain:")):
            raise RuntimeError("Не похоже на адрес сайта. Пример: example.com.")
        value = item[1][7:] if item[0] == "domain" else item[1]
        return routing.site_entry(value) if main_domain else value

    def route_site(self, host: str, target: str, main_domain: bool = True) -> tuple[str, bool]:
        """Свой маршрут для сайта (варианты — как у сервисов). Возвращает (запись, поменялся ли обход замедления).
        Правило сайта действует и на поддомены, поэтому старые правила для них убираются — последнее слово за новым."""
        entry = self.site_key(host, main_domain)
        spec = {"via": target} if target in self.LIST_TARGETS else self._check_target(target)
        dpi_changed = self._clear_site(entry)
        if spec:
            self.settings["routes"][f"site:{entry}"] = spec
            dpi_changed = dpi_changed or spec["via"] == "dpi"
        self.save()
        self.log(f"{entry}: {self._route_label(target)}.")
        self.notify("settings")
        return entry, dpi_changed

    @staticmethod
    def _covers(entry: str, value: str) -> bool:
        """Правило для entry касается value: тот же сайт или его поддомен (IP — только точное совпадение)."""
        entry, value = entry.lower(), value.lower()
        return value == entry or (not routing.is_ip_entry(entry) and value.endswith("." + entry))

    def _clear_site(self, entry: str) -> bool:
        """Убирает правила для сайта и его поддоменов из списков и своих маршрутов. True — среди них был обход замедления."""
        for key, _ in routing.USER_LISTS:
            kept = []
            for line in (self.settings.get(key) or "").splitlines():
                try:
                    item = routing.normalize_entry(line)
                except ValueError:
                    item = None
                value = item[1][7:] if item and item[1].startswith("domain:") else (item[1] if item and item[0] == "ip" else "")
                if not (value and self._covers(entry, value)):
                    kept.append(line)
            self.settings[key] = "\n".join(kept)
        routes = self.settings.setdefault("routes", {})
        dpi = False
        for k in [k for k in routes if k.startswith("site:") and self._covers(entry, k[5:])]:
            spec = routes.pop(k)
            dpi = dpi or spec.get("via") == "dpi"
        return dpi

    def apply_routes(self, dpi_changed: bool = False) -> None:
        """Применить свои маршруты: если поменялись сайты обхода и работает zapret — перезапустить его."""
        if dpi_changed and self.dpi_mode == "zapret":
            self.start_dpi()
        if self.core_running:
            self.reconnect()

    def _route_domains(self, key: str) -> tuple[list[str], list[str]]:
        if key.startswith("svc:"):
            svc = next((x for x in services.SERVICES if x["name"] == key[4:]), None)
            return ([f"domain:{d}" for d in svc["domains"]], []) if svc else ([], [])
        if key.startswith("site:"):
            domains, ips, _ = routing.split_entries([key[5:]])
            return domains, ips
        return [], []

    def _route_target(self, spec: dict, main: Server | None, exe: str, dpi_route: dict | None) -> tuple[str, str]:
        """Куда на самом деле пойдёт маршрут сейчас: (тег outbound или вид, предупреждение для интерфейса)."""
        via = spec.get("via")
        if via in self.LIST_TARGETS:  # сайт: через VPN / напрямую / блок
            return via, ""
        if via == "dpi":
            if dpi_route and dpi_route.get("mode") == "byedpi":
                return "byedpi", ""
            if dpi_route:
                return "direct", ""
            return "direct", "Обход замедления сейчас выключен — пока напрямую."
        if via == "server":
            srv = self.find(spec.get("server", ""))
            if not srv:
                return "proxy", "Этого сервера больше нет в подписке — пока через основной VPN."
            if main and srv.key == main.key:
                return "proxy", ""
            if not srv.supported:
                return "proxy", "Сервер не поддерживается — пока через основной VPN."
            if exe and self.paths.exe_for(srv) != exe:
                return "proxy", "Этому серверу нужно другое ядро — пока через основной VPN."
            return "server", ""
        if via == "custom":
            return ("custom", "") if self._proxy_by_id(spec.get("proxy", "")) else \
                ("proxy", "Прокси удалён — пока через основной VPN.")
        return "", ""

    def _route_plan(self, main: Server, exe: str) -> list[dict]:
        """Свои маршруты для конфига ядра: [{"tag", "domains", "ips", "early", "server"/"proxy"…}].
        Сайты идут раньше своих списков и сервисов, и более точный адрес — раньше общего (music.example.org
        раньше example.org), поэтому правило для поддомена не перебивается правилом для всего сайта."""
        routes = self.settings.get("routes") or {}
        dpi_route = self._dpi_route()
        plan, pins, customs = [], {}, {}

        def order(k: str):
            if not k.startswith("site:"):
                return (2, 0)
            v = k[5:]
            if routing.is_ip_entry(v):
                return (1, -int(v.split("/", 1)[1]) if "/" in v else -128)
            return (0, -v.count("."))

        items = [(k, routes[k], None) for k in sorted(routes, key=order)]
        if not self._apps_off:
            items += [(f"app:{n}", spec, n) for n, spec in sorted((self.settings.get("app_routes") or {}).items())]
        for key, spec, app in items:
            if app:
                domains, ips = [], []
                entry: dict = {"process": apps.rule_process(app), "app": True}
            else:
                domains, ips = self._route_domains(key)
                if not domains and not ips:
                    continue
                entry = {"domains": domains, "ips": ips, "early": key.startswith("site:")}
            kind, _ = self._route_target(spec, main, exe, dpi_route)
            if kind == "server":
                srv = self.find(spec["server"])
                entry.update(tag=pins.setdefault(srv.key, f"pin{len(pins)}"), server=srv, mask=self._use_mask(srv))
            elif kind == "custom":
                p = self._proxy_by_id(spec["proxy"])
                entry.update(tag=customs.setdefault(p["id"], f"custom{len(customs)}"), proxy=p,
                             block_udp="" if p.get("type") == "http" else "443")  # HTTP-прокси UDP не умеет вовсе
            elif kind in ("proxy", "direct", "byedpi", "block"):
                entry["tag"] = kind
            else:
                continue
            plan.append(entry)
        plan += self._auto_plan(main, exe, pins)
        return plan

    def _manual_services(self) -> set[str]:
        """Сервисы, для которых пользователь сам выбрал маршрут, — автоматика их не трогает."""
        s = self.settings
        names = {k[4:] for k in (s.get("routes") or {}) if k.startswith("svc:")}
        names |= {x["name"] for x in services.SERVICES if routing.user_rule(x["domains"][0], s)}
        return names

    def routes_state(self) -> dict:
        """Свои маршруты для интерфейса: выбор у сервисов и список сайтов."""
        s = self.settings
        main = self.current if self.connected else None
        exe = self.proc.exe if self.connected else ""
        dpi_route = self._dpi_route()
        svc, sites = {}, []
        # простые выборы (через VPN / напрямую / блок) лежат в списках — показываем обычные домены и IP из них
        listed: list[dict] = []
        seen: set[str] = set()
        for list_key, tag in routing.USER_LISTS:
            for line in (s.get(list_key) or "").splitlines():
                try:
                    item = routing.normalize_entry(line)
                except ValueError:
                    continue
                if not item or not (item[1].startswith("domain:") or item[0] == "ip" and not item[1].startswith("geoip:")):
                    continue
                site = item[1][7:] if item[0] == "domain" else item[1]
                if site.lower() not in seen:
                    seen.add(site.lower())
                    listed.append({"site": site, "value": tag, "warn": "", "list": True})
        for key, spec in (s.get("routes") or {}).items():
            _, warn = self._route_target(spec, main, exe, dpi_route)
            item = {"value": self._route_value(spec), "warn": i18n.tr(warn)}
            if key.startswith("svc:"):
                svc[key[4:]] = item
            else:
                sites.append(dict(item, site=key[5:]))
        own = {x["site"].lower() for x in sites}
        sites += [x for x in listed if x["site"].lower() not in own]
        return {"services": svc, "sites": sites[:300], "sites_total": len(sites),
                "proxies": [self._proxy_public(p) for p in s.get("proxies") or []]}

    # ---------- свои прокси ----------

    def _proxy_title(self, p: dict) -> str:
        """Имя прокси для журнала: своё название или номер — адрес и логин в журнал не пишем."""
        items = self.settings.get("proxies") or []
        return p.get("name") or f"№{next((i for i, x in enumerate(items) if x is p), len(items)) + 1}"

    def _proxy_public(self, p: dict) -> dict:
        out = proxies.public(p)
        if out["check"].get("error"):
            out["check"]["error"] = i18n.tr(out["check"]["error"])
        out["used"] = [k.split(":", 1)[1] for k, r in (self.settings.get("routes") or {}).items()
                       if r.get("via") == "custom" and r.get("proxy") == p["id"]]
        out["used"] += [n for n, r in (self.settings.get("app_routes") or {}).items()
                        if r.get("via") == "custom" and r.get("proxy") == p["id"]]
        return out

    def _proxy_by_id(self, pid: str) -> dict | None:
        return next((p for p in self.settings.get("proxies") or [] if p.get("id") == pid), None)

    def add_proxy(self, raw: str, name: str = "", kind: str = "auto", chain: bool = True) -> dict:
        items = self.settings.setdefault("proxies", [])
        if len(items) >= proxies.MAX:
            raise RuntimeError("Слишком много своих прокси — удали ненужные.")
        try:
            p = proxies.parse(raw, kind)
        except proxies.ProxyError as exc:
            raise RuntimeError(str(exc)) from exc
        same = next((x for x in items if (x["host"], x["port"], x.get("user", "")) == (p["host"], p["port"], p["user"])),
                    None)
        if same:
            raise RuntimeError(f"Такой прокси уже есть: «{self._proxy_title(same)}».")
        p.update(id=secrets.token_hex(3), name=" ".join(str(name or "").split())[:60], chain=bool(chain), check={})
        items.append(p)
        self.save()
        self.log(f"Добавлен свой прокси «{self._proxy_title(p)}».")
        self.notify("settings")
        return self._proxy_public(p)

    def update_proxy(self, pid: str, name: str | None = None, chain: bool | None = None) -> bool:
        """Переименовать прокси или включить/выключить «через VPN». True — надо переподключиться."""
        p = self._proxy_by_id(pid)
        if not p:
            raise RuntimeError("Прокси не найден.")
        changed = False
        if name is not None:
            p["name"] = " ".join(str(name).split())[:60]
        if chain is not None and bool(chain) != bool(p.get("chain", True)):
            p["chain"] = bool(chain)
            p["check"] = {}
            changed = True
        self.save()
        self.notify("settings")
        return changed and self._proxy_in_use(pid)

    def _proxy_in_use(self, pid: str) -> bool:
        return any(r.get("via") == "custom" and r.get("proxy") == pid
                   for r in [*(self.settings.get("routes") or {}).values(), *(self.settings.get("app_routes") or {}).values()])

    # ---------- приложения ----------

    def apps_scan(self) -> list[dict]:
        """Какие приложения сейчас ходят в сеть (для списка «Добавить приложение»)."""
        self._apps_running = apps.running(self._apps_lister)
        return self._apps_running

    _apps_lister = None  # подмена в самопроверке
    _apps_running: list = []

    def set_app_route(self, name: str, target: str, path: str = "") -> str:
        """Свой маршрут приложения: proxy / direct / block / dpi / server:… / custom:… ; auto — убрать."""
        n = apps.clean_name(name)
        if not n:
            raise RuntimeError("Не похоже на имя программы. Пример: Discord или C:/Games/game.exe.")
        routes = self.settings.setdefault("app_routes", {})
        if target == "auto":
            routes.pop(n, None)
        else:
            spec = {"via": target} if target in self.LIST_TARGETS else self._check_target(target)
            p = apps.preset_for(n)
            spec["title"] = p["title"] if p else n
            routes[n] = spec
        self.save()
        self.log(f"Приложение {n}: {self._route_label(target)}.")
        self.notify("settings")
        return n

    def apps_state(self) -> dict:
        s = self.settings
        main = self.current if self.connected else None
        exe = self.proc.exe if self.connected else ""
        dpi_route = self._dpi_route()
        tun_on = bool(s.get("tun_enabled"))
        engine = self.tun_active or (s.get("tun_engine_auto") if tun_on else "")
        items = []
        for name, spec in sorted((s.get("app_routes") or {}).items(), key=lambda kv: kv[1].get("title", kv[0]).lower()):
            _, warn = self._route_target(spec, main, exe, dpi_route)
            p = apps.preset_for(name)
            if not warn and self._apps_off:
                warn = "Ядро не поддерживает маршруты приложений — обнови ядро на странице «Обновления»."
            if not warn and p and p.get("needs_tun") and not tun_on and spec.get("via") != "dpi":
                warn = "Это приложение не слушается системного прокси: маршрут сработает, только когда включён режим TUN."
            if not warn and engine in ("singbox", "tun2proxy") and spec.get("via") not in ("direct", "block", "proxy"):
                warn = "С этим движком TUN для приложений работают только «напрямую», «через VPN» и «блок»."
            items.append({"name": name, "title": spec.get("title") or name, "value": self._route_value(spec),
                          "warn": i18n.tr(warn), "preset": bool(p and p.get("urls")),
                          "voice": bool(p and p.get("voice_udp"))})
        chosen = {x["name"] for x in items}
        running = []
        for a in self._apps_running:
            if a["name"] in chosen:
                continue
            p = apps.preset_for(a["name"])
            running.append({"name": a["name"], "title": p["title"] if p else a["name"], "conns": a["conns"],
                            "torrent": bool(p and p.get("torrent"))})
        return {"items": items, "running": running[:20], "supported": apps.IS_WINDOWS or self._apps_lister is not None,
                "off": self._apps_off, "tun": tun_on, "torrent": s.get("torrent_route", "direct"),
                "presets": [{"name": p["process"][0], "title": p["title"]} for p in apps.PRESETS]}

    def pick_app(self, name: str) -> dict:
        """«Подобрать» для известного приложения: проверяет его адреса напрямую, с обходом, через VPN и другие
        серверы и ставит лучший путь. Напрямую лучше всего (быстрее), если там всё работает."""
        n = apps.clean_name(name)
        p = apps.preset_for(n)
        if not p or not p.get("urls"):
            raise RuntimeError("Для этого приложения подбор не умеет — выбери путь сам.")
        self.progress(f"Подбираю путь для {p['title']}")
        good = lambda r: bool(r) and r["state"] in (services.OK, services.SLOW)  # noqa: E731

        def works(port) -> bool:
            for url in p["urls"]:
                self.check_stop()
                if not good(services.check_url(url, port, region_sensitive=True, timeout=8)):
                    return False
            return True
        tried, choice = [], ""
        if works(self._direct_http()):
            choice = "direct"
            tried.append("напрямую — работает")
        else:
            tried.append("напрямую — не работает")
            if self.connected and works(self.ports["health"]):
                choice = "proxy"
                tried.append("через VPN — работает")
            elif self.connected:
                tried.append("через VPN — не работает")
                ports, proc = self._repair_servers()
                try:
                    for srv, port in ports:
                        if works(port):
                            choice = f"server:{srv.key}"
                            tried.append(f"через «{srv.name}» — работает")
                            break
                finally:
                    if proc:
                        proc.stop()
        if not choice:
            choice = "proxy" if self.connected else "direct"
            verdict = "Рабочего пути не нашлось. Поставил «через VPN» — проверь, включён ли VPN и режим TUN."
        else:
            verdict = f"{p['title']}: {self._route_label(choice)}."
        self.set_app_route(n, choice)
        if p.get("needs_tun") and not self.settings.get("tun_enabled") and choice not in ("direct", "dpi"):
            verdict += " Это приложение не слушается системного прокси — включи режим TUN, чтобы маршрут сработал."
        if p.get("voice_udp") and choice not in ("direct", "dpi"):
            verdict += " Голос Discord идёт по UDP: через VPN он работает только в режиме TUN."
        self.log(f"Подбор для {p['title']}: " + "; ".join(tried) + ".")
        result = {"name": n, "choice": choice, "verdict": i18n.tr(verdict), "tried": [i18n.tr(x) for x in tried]}
        self.notify("summary", text=verdict)
        return result

    def remove_proxy(self, pid: str) -> bool:
        """Удаляет прокси. Сервисы и сайты, которые шли через него, возвращаются к «как по умолчанию»."""
        p = self._proxy_by_id(pid)
        if not p:
            return False
        title = self._proxy_title(p)
        self.settings["proxies"] = [x for x in self.settings["proxies"] if x is not p]
        routes = self.settings.get("routes") or {}
        used = [k for k, r in routes.items() if r.get("via") == "custom" and r.get("proxy") == pid]
        for k in used:
            routes.pop(k, None)
        app_routes = self.settings.get("app_routes") or {}
        for n in [n for n, r in app_routes.items() if r.get("via") == "custom" and r.get("proxy") == pid]:
            app_routes.pop(n, None)
            used.append(f"app:{n}")
        self.save()
        self.log(f"Свой прокси «{title}» удалён."
                 + (f" Как по умолчанию снова: {', '.join(k.split(':', 1)[1] for k in used)}." if used else ""))
        self.notify("settings")
        return bool(used)

    def check_proxy(self, pid: str) -> dict:
        """Проверка своего прокси: под каким IP и страной видят сайты и открывается ли TikTok.
        Если тип не был указан явно и SOCKS5 не подошёл — пробует HTTP и запоминает рабочий тип."""
        p = self._proxy_by_id(pid)
        if not p:
            raise RuntimeError("Прокси не найден.")
        title = self._proxy_title(p)
        self.progress(f"Проверяю прокси «{title}»")
        main = self.current if self.connected else None
        if main is None and p.get("chain", True):
            last = self.find(self.settings.get("last_server_key", ""))
            main = last if last and last.supported else None
        exe = self.paths.exe_for(main) if main else self.paths.xray
        if not os.path.isfile(exe):
            self._need_xray()
        kinds = [p["type"]] + ([] if p.get("type_known") else [k for k in proxies.TYPES if k != p["type"]])
        result: dict = {}
        for kind in kinds:
            self.check_stop()
            trial = dict(p, type=kind)
            port = netutil.find_free_ports(1, avoid=tester.RESERVED_PORTS)[0]
            proc = XrayProcess(self.paths)
            try:
                cfg = xray.build_proxy_test_config(trial, port, main, self._use_mask(main) if main else False,
                                                   self._version_for(exe))
                proc.start(cfg, self.paths.test_config, wait_for=[port], exe=exe)
                info = services.exit_info(port)
                result = {"ok": bool(info.get("ip")), "ip": info.get("ip", ""), "loc": info.get("loc", ""),
                          "error": info.get("error", "") if not info.get("ip") else "",
                          "at": time.time(), "chain": bool(main is not None and p.get("chain", True))}
                if result["ok"]:
                    tiktok = next((x for x in services.SERVICES if x["name"] == "TikTok"), None)
                    if tiktok:
                        r = services.check_service(tiktok, port)
                        result["tiktok"] = r.get("state", "")
            except XrayError as exc:
                result = {"ok": False, "ip": "", "loc": "", "error": str(exc), "at": time.time()}
            finally:
                proc.stop()
            if result.get("ok"):
                if kind != p["type"]:
                    self.log(f"Прокси «{title}» работает как {'HTTP' if kind == 'http' else 'SOCKS5'} — запомнил.")
                p["type"] = kind
                p["type_known"] = True
                break
        p["check"] = result
        self.save()
        if result.get("ok"):
            cc = result["loc"] or "?"
            self.log(f"Прокси «{title}»: работает, страна {cc}.")
            if self._proxy_in_use(pid) and self.connected and kinds[0] != p["type"]:
                self.reconnect()
        else:
            self.log(f"Прокси «{title}» не отвечает: {result.get('error') or 'нет ответа'}.")
        self.notify("settings")
        return self._proxy_public(p)

    # ---------- блокировка рекламы (с VPN и без него) ----------

    # «сервер» для режима без VPN: всё, что не реклама, идёт напрямую
    FILTER = Server(name="Без VPN", protocol="direct", outbound={"protocol": "freedom", "settings": {}})
    # kill switch: VPN сломался — всё, что должно идти через VPN, никуда не идёт (а не напрямую), пока он не заработает
    KILL = Server(name="Защита: VPN не работает", protocol="blackhole", outbound={"protocol": "blackhole", "settings": {}})
    ADS_LEVELS = tuple(adblock.LEVELS)

    @property
    def _ads_dat(self) -> str:
        return os.path.join(self.paths.bin_dir, adblock.DAT)

    @property
    def _ads_cache(self) -> str:
        return os.path.join(self.paths.data_dir, "adblock")

    def _ads_paused(self) -> bool:
        return float(self.settings.get("ads_pause_until") or 0) > time.time()

    def _ads_mode(self) -> str:
        """Как блокировать рекламу сейчас: dat — свои списки, geo — запасной список runetfreedom, "" — никак."""
        if not self.settings.get("block_ads") or self._ads_paused():
            return ""
        return "dat" if os.path.isfile(self._ads_dat) else "geo"

    def _filter_wanted(self) -> bool:
        s = self.settings
        return bool(s.get("block_ads") and s.get("ads_without_vpn", True) and not self._ads_paused()
                    and self.paths.xray_exists() and not self._closing
                    and not self.awg_active)  # пока работает AmneziaWG, ядро Xray не запускается совсем

    def start_filter(self) -> None:
        """Блокировка рекламы без VPN: ядро работает без сервера — реклама не загружается, остальное
        идёт напрямую (IP не меняется). Если фильтр уже работает — перезапуск с новыми настройками."""
        with self._conn_lock:
            if self.connected or self._closing:
                return
            was = self.filter_on
            self.progress("Включаю блокировку рекламы")
            try:
                self._bring_up(self.FILTER, self.paths.xray)
            except Exception:
                self.filter_on = False
                self._filter_fail_at = time.time()
                raise
            self.filter_on = True
            self._filter_fail_at = 0.0
        if not was:
            self.log("Блокировка рекламы работает без VPN: реклама не загружается, остальное идёт напрямую.")
        self.notify("status")

    def stop_filter(self, quiet: bool = False) -> None:
        if not self.filter_on:
            return
        self._take_down()
        if not quiet:
            self.log("Блокировка рекламы без VPN выключена.")
        self.notify("status")

    def apply_ads(self) -> None:
        """Применить настройки рекламы: перезапустить VPN или фильтр, включить или выключить фильтр."""
        if self.connected:
            self.reconnect()
        elif self._filter_wanted():
            self.start_filter()
        elif self.filter_on:
            self.stop_filter()

    def _ads_ids(self) -> list[str]:
        lists = self.settings.get("ads_lists") or {}
        return ["main"] + [k for k in adblock.EXTRA if lists.get(k)]

    def build_adblock(self) -> dict | None:
        """Собрать adblock.dat из скачанных списков, своих сайтов и исключений (без сети)."""
        s = self.settings
        level = s.get("ads_level", adblock.DEFAULT_LEVEL)
        if not any(os.path.isfile(os.path.join(self._ads_cache, adblock.cache_name(i, level))) for i in self._ads_ids()) \
                and not adblock.parse_user(s.get("ads_custom", "")):
            return None  # ничего не скачано — пусть работает запасной список
        args = (self._ads_cache, self._ads_dat, level, s.get("ads_lists") or {}, s.get("ads_custom", ""),
                s.get("ads_allow", ""))
        try:
            info = adblock.build(*args)
        except PermissionError:
            # Windows не даёт заменить файл, пока его держит ядро: на секунду останавливаем и запускаем снова.
            # Под _conn_lock: подключение или отключение человеком дождётся конца и не перепутается с этим
            with self._conn_lock:
                server = self.current if self.connected else None
                was_filter = self.filter_on
                self._take_down()
                try:
                    info = adblock.build(*args)
                finally:
                    if server:
                        self.connect(server)
                    elif was_filter:
                        self.start_filter()
        s["ads_info"] = info
        self.save()
        return info

    def update_adblock(self, apply: bool = True, only_missing: bool = False) -> dict:
        """Скачать списки рекламы и собрать файл для ядра. only_missing — только недостающие (сменили силу)."""
        s = self.settings
        level = s.get("ads_level", adblock.DEFAULT_LEVEL)
        proxy = self.ports.get("health") if self.connected else None
        errors, got = [], 0
        for list_id in self._ads_ids():
            self.check_stop()
            if only_missing and os.path.isfile(os.path.join(self._ads_cache, adblock.cache_name(list_id, level))):
                continue
            self.progress(f"Скачиваю списки рекламы: {self._ads_list_name(list_id)}")
            try:
                self._fetch_any(lambda p, lid=list_id: adblock.download(lid, self._ads_cache, level, p),
                                f"Списки рекламы: {self._ads_list_name(list_id)}")
                got += 1
            except Cancelled:
                raise
            except Exception as exc:
                errors.append(f"{self._ads_list_name(list_id)}: {netutil.human_error(exc)}")
        if got:
            s["ads_updated_at"] = time.time()
        info = self.build_adblock()
        if errors:
            self.log("Не все списки рекламы скачались: " + "; ".join(errors))
            if not info:
                self.problem("adblock", "Списки рекламы не скачались", "; ".join(errors), where="Блокировка рекламы",
                             fix="Пока работает запасной список. Программа попробует ещё раз позже.")
        if info:
            self.resolve("adblock")
            self.log(f"Списки рекламы готовы: блокируется {info['total']} адресов.")
        self.save()
        if apply:
            self.apply_ads()
        self.notify("settings")
        return info or {}

    @staticmethod
    def _ads_list_name(list_id: str) -> str:
        return {"main": "реклама и трекеры", "popups": "всплывающие окна", "threats": "опасные сайты",
                "ru": "российская реклама", "telemetry": "слежка Windows"}.get(list_id, list_id)

    def set_ads(self, **changes) -> tuple[bool, bool]:
        """Настройки блокировки рекламы. Возвращает (нужно скачать списки, нужно пересобрать и применить)."""
        s = self.settings
        need_download = need_apply = False
        if "enabled" in changes:
            on = bool(changes["enabled"])
            if on != bool(s.get("block_ads")):
                s["block_ads"] = on
                need_apply = True
                need_download = on and not os.path.isfile(self._ads_dat)
                self.log("Блокировка рекламы включена." if on else "Блокировка рекламы выключена.")
        if "without_vpn" in changes and bool(changes["without_vpn"]) != bool(s.get("ads_without_vpn", True)):
            s["ads_without_vpn"] = bool(changes["without_vpn"])
            need_apply = True
        if "level" in changes:
            level = str(changes["level"])
            if level not in adblock.LEVELS:
                raise RuntimeError("Неизвестная сила блокировки.")
            if level != s.get("ads_level"):
                s["ads_level"] = level
                need_download = need_apply = True
        if "lists" in changes and isinstance(changes["lists"], dict):
            lists = dict(s.get("ads_lists") or {})
            for k, v in changes["lists"].items():
                if k in adblock.EXTRA and bool(v) != bool(lists.get(k)):
                    lists[k] = bool(v)
                    need_apply = True
                    need_download = need_download or bool(v)
            s["ads_lists"] = lists
        for key in ("custom", "allow"):
            if key in changes:
                text = str(changes[key] or "")[:200000]
                if text != s.get(f"ads_{key}", ""):
                    s[f"ads_{key}"] = text
                    need_apply = True
        self.save()
        self.notify("settings")
        return need_download, need_apply

    def ads_allow(self, host: str) -> str:
        """«Разрешить» из журнала блокировок: адрес попадает в исключения."""
        entry = (adblock.parse_user(host) or {""}).pop()
        if not entry:
            raise RuntimeError("Не похоже на адрес сайта.")
        lines = [ln for ln in (self.settings.get("ads_allow") or "").splitlines() if ln.strip()]
        if entry not in adblock.parse_user("\n".join(lines)):
            lines.append(entry)
        self.settings["ads_allow"] = "\n".join(lines)
        self.ads_stats["recent"] = collections.deque((x for x in self.ads_stats["recent"] if x["host"] != entry
                                                      and not x["host"].endswith("." + entry)), maxlen=100)
        self.ads_stats["top"].pop(entry, None)
        self.save()
        self.log(f"Реклама: {entry} — в исключениях, больше не блокируется.")
        self.notify("settings")
        return entry

    def ads_lookup(self, host: str) -> dict:
        """«Проверить сайт»: почему он блокируется (какой список, свои сайты, свой список «Блокировать»)."""
        s = self.settings
        text = (host or "").strip()
        if "://" in text:
            text = urlsplit(text).hostname or ""
        try:
            r = adblock.lookup(self._ads_cache, s.get("ads_level", adblock.DEFAULT_LEVEL), s.get("ads_lists") or {},
                               s.get("ads_custom", ""), s.get("ads_allow", ""), text.split("/", 1)[0])
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc
        r.update(user_rule=routing.user_rule(r["host"], s), enabled=bool(s.get("block_ads")), mode=self._ads_mode())
        return r

    def ads_pause(self, minutes: int) -> None:
        """Пауза блокировки рекламы (0 — снять паузу)."""
        minutes = max(0, min(int(minutes), 24 * 60))
        self.settings["ads_pause_until"] = time.time() + minutes * 60 if minutes else 0
        self._ads_paused_state = bool(minutes)
        self.save()
        self.log(f"Блокировка рекламы на паузе {minutes} мин." if minutes else "Блокировка рекламы снова работает.")
        self.notify("settings")

    def _routing_migrate(self) -> None:
        """Раньше по умолчанию был «Умный» режим: через VPN только заблокированное. Из-за него сайт открывался,
        а видео и картинки с зарубежных серверов (их провайдер тормозит, но не блокирует) — нет. Один раз
        переводим на «всё через VPN, российское напрямую»; вернуть экономный режим можно на главной."""
        s = self.settings
        if s.get("routing_v2"):
            return
        s["routing_v2"] = True
        if s.get("mode") == "smart":
            s["mode"] = "vpn"
            s["ru_direct"] = True
            self.log("Маршрутизация: теперь через VPN идёт всё, кроме российских сайтов, — так сайты работают целиком "
                     "(видео, картинки). Вернуть экономный режим можно на главной.")
        self.save()

    def _ads_migrate(self) -> None:
        """Один раз после обновления программы: «Обычная» сила вместо «Сильной» и встроенная защита сайтов."""
        s = self.settings
        if s.get("ads_rev", 0) >= 2:
            return
        s["ads_rev"] = 2
        if s.get("ads_level") == "pro":
            s["ads_level"] = "normal"
            self.log("Блокировка рекламы: сила «Обычная» — она реже закрывает нужные сайты. "
                     "«Сильную» можно включить в разделе «Реклама».")
        if s.get("block_ads"):
            s["ads_updated_at"] = 0  # скачать список новой силы при первой возможности
            try:
                self.build_adblock()  # защита сайтов работает сразу, ещё до скачивания
            except Exception as exc:
                self.log(f"Списки рекламы пересоберутся позже: {exc}")
        self.save()

    ADS_ASK_WINDOW = 90  # за сколько секунд считать повторные заходы на закрытый сайт
    # «Автоматика»: выключатели, которые не требуют переподключения
    AUTO_FLAGS = ("auto_routes", "auto_stall", "auto_ask_direct", "ads_ask_sites", "cert_watch", "failover", "sub_alerts", "hotkey_enabled", "kill_switch",
                  "net_profiles", "app_update", "smart_notices", "fp_auto", "data_watch", "net_memory")

    def _ads_site_hit(self, host: str) -> None:
        """Заблокирован адрес самого сайта (не его рекламного поддомена) и к нему стучатся снова —
        похоже, человек открывает этот сайт. Спросим, не разрешить ли его."""
        site = adblock.site_name(host)
        if not self.settings.get("ads_ask_sites", True):
            return
        if not site or adblock.looks_like_ads(host) or site in self._ads_site_asked \
                or site in (self.settings.get("ads_site_ignore") or []) or self._ads_mode() != "dat":
            return
        now = time.time()
        hits = [t for t in self._ads_site_hits.get(site, []) if now - t < self.ADS_ASK_WINDOW] + [now]
        self._ads_site_hits[site] = hits
        if len(self._ads_site_hits) > 500:
            self._ads_site_hits = {k: v for k, v in self._ads_site_hits.items() if now - v[-1] < self.ADS_ASK_WINDOW}
        if len(hits) < 2:
            return
        if sum(1 for t in self._ads_ask_times if now - t < 600) >= 3:
            return  # не больше трёх вопросов за 10 минут
        self._ads_site_asked.add(site)
        self._ads_ask_times.append(now)
        threading.Thread(target=self._ads_site_suspect, args=(site, host), daemon=True).start()

    def _ads_site_suspect(self, site: str, host: str) -> None:
        try:
            r = self.ads_lookup(host)
        except Exception:
            return
        if not r.get("blocked") or r.get("custom"):
            return  # не из списков (или человек сам добавил его в «Блокировать»)
        ids = [x["id"] for x in r["lists"]]
        names = [self._ads_list_name(i) for i in ids]
        threat = ids == ["threats"]
        item = {"site": site, "host": host, "lists": names, "threat": threat, "at": time.time()}
        self.ads_suspects.appendleft(item)
        where = ", ".join(f"«{n}»" for n in names)
        self.log(f"Реклама: похоже, закрыт сам сайт {site} (список {where}). Разрешить можно в разделе «Реклама».")
        self.notify("ads_site", item=dict(item, lists=[i18n.tr(n) for n in names]))
        lang_en = self.settings.get("lang") == "en"
        self.tray_queue.append((
            "Site blocked by ad blocker" if lang_en else "Сайт закрыт блокировщиком",
            (f"{site} is on the list {', '.join(i18n.tr(n) for n in names)}. Open the app to allow it."
             if lang_en else f"{site} в списке {where}. Открой программу, чтобы разрешить.")))

    def ads_site_answer(self, site: str, allow: bool) -> str:
        """Ответ на «сайт закрыт блокировщиком»: разрешить или больше не спрашивать."""
        site = adblock.site_name(site) or site
        self.ads_suspects = collections.deque((x for x in self.ads_suspects if x["site"] != site), maxlen=20)
        if allow:
            return self.ads_allow(site)
        ignore = [x for x in (self.settings.get("ads_site_ignore") or []) if x != site][-300:]
        self.settings["ads_site_ignore"] = ignore + [site]
        self.save()
        self.log(f"Реклама: {site} остаётся закрытым, больше не спрашиваю.")
        self.notify("settings")
        return site

    def _count_ad(self, host: str) -> None:
        st = self.ads_stats
        day = time.strftime("%Y-%m-%d")
        if st["day"] != day:
            st.update(day=day, today=0, top={})
        st["today"] += 1
        st["top"][host] = st["top"].get(host, 0) + 1
        if len(st["top"]) > 3000:
            st["top"] = dict(sorted(st["top"].items(), key=lambda kv: -kv[1])[:1000])
        st["recent"].appendleft({"host": host, "time": time.strftime("%H:%M:%S")})

    def ads_state(self) -> dict:
        s = self.settings
        info = s.get("ads_info") or {}
        paused = float(s.get("ads_pause_until") or 0)
        st = self.ads_stats
        return {"enabled": bool(s.get("block_ads")), "without_vpn": bool(s.get("ads_without_vpn", True)),
                "level": s.get("ads_level", adblock.DEFAULT_LEVEL), "levels": list(adblock.LEVELS),
                "lists": {k: bool((s.get("ads_lists") or {}).get(k)) for k in adblock.EXTRA},
                "counts": info.get("lists", {}), "total": info.get("total", 0),
                "ready": os.path.isfile(self._ads_dat), "mode": self._ads_mode(),
                "updated_at": s.get("ads_updated_at", 0), "update_hours": s.get("ads_update_hours", 24),
                "paused_until": paused if paused > time.time() else 0, "filter_on": self.filter_on,
                "custom": s.get("ads_custom", ""), "allow": s.get("ads_allow", ""),
                "today": st["today"] if st["day"] == time.strftime("%Y-%m-%d") else 0,
                "top": sorted(st["top"].items(), key=lambda kv: -kv[1])[:12],
                "recent": list(st["recent"])[:40],
                "suspects": [dict(x, lists=[i18n.tr(n) for n in x["lists"]]) for x in self.ads_suspects]}

    # ---------- обновления ----------

    def update_xray(self) -> None:
        self._apps_off = False  # новое ядро могло научиться правилам по процессам
        self.progress("Скачиваю ядро Xray")
        if self.core_running:
            # работающий xray.exe заменить нельзя: качаем (через VPN, если он включён), затем на секунду отключаемся.
            # Замена — под _conn_lock: если человек в это время подключается или отключается, он подождёт секунду
            self._fetch_any(lambda p: xray.download_xray(self.paths, proxy_port=p, install=False), "Ядро Xray")
            with self._conn_lock:
                if self.connected and self.current:
                    server = self.current
                    self.disconnect(quiet=True, keep_filter=False)
                    try:
                        xray.install_pending_xray(self.paths)
                    finally:
                        self.connect(server)
                elif self.filter_on:
                    self.stop_filter(quiet=True)
                    try:
                        xray.install_pending_xray(self.paths)
                    finally:
                        self.start_filter()
                else:  # пока качали, VPN выключили — просто ставим
                    xray.install_pending_xray(self.paths)
        else:
            # ставим уже после скачивания: временное ядро (обход блокировки) держит файл, пока работает
            self._fetch_any(lambda p: xray.download_xray(self.paths, proxy_port=p, install=False), "Ядро Xray")
            xray.install_pending_xray(self.paths)
        self.xray_ver = xray.xray_version(self.paths)
        self.log(f"Ядро Xray обновлено: версия {self.xray_ver or '?'}.")
        self._check_files()
        self.notify("status")

    def update_geo(self, apply: bool = True) -> None:
        """apply=False — только скачать: новые списки начнут работать при следующем подключении,
        текущее соединение не прерывается (так обновляется автоматически)."""
        self.progress("Скачиваю списки заблокированных сайтов")
        try:
            self._fetch_any(lambda p: xray.download_geo(self.paths, proxy_port=p), "Списки сайтов")
        except PermissionError:
            with self._conn_lock:  # см. update_xray: замена файлов, которые держит ядро, — по очереди с подключением
                server = self.current if self.connected else None
                self.disconnect(quiet=True, keep_filter=False)
                xray.download_geo(self.paths)
                if server:
                    self.connect(server)
                elif self._filter_wanted():
                    self.start_filter()
        self.settings["last_geo_check"] = time.time()
        self.save()
        self.resolve("geo_old")
        if self.connected and not apply:
            self.log("Списки заблокированных сайтов обновлены — начнут работать при следующем подключении.")
        else:
            self.log("Списки заблокированных сайтов обновлены (runetfreedom).")
            if self.core_running:
                self.reconnect()
        self.notify("status")

    def update_all(self) -> None:
        errors = []
        for title, func in (("Серверы", self.update_subscription if self.settings["subscriptions"] else None),
                            ("Списки сайтов", self.update_geo), ("Ядро Xray", self.update_xray)):
            if func is None:
                continue
            try:
                func()
            except Exception as exc:
                errors.append(f"{title}: {exc}")
                self.log(f"{title}: не удалось обновить — {exc}")
        text = "Всё обновлено." if not errors else "Обновлено с ошибками: " + "; ".join(errors)
        self.notify("summary", text=text)

    # ---------- автонастройка и автопилот ----------

    def auto_setup(self) -> None:
        steps = []
        if not self.paths.xray_exists():
            self.update_xray()
        age = self.paths.geo_age_days()
        if age is None or age > 7:
            try:
                self.update_geo()
            except Exception as exc:
                self.log(f"Списки сайтов не скачались ({netutil.human_error(exc)}), использую встроенные.")
        if self.settings["subscriptions"]:
            try:
                self.update_subscription()
            except Exception as exc:
                if not self.servers:
                    raise
                self.log(f"Подписки не обновились ({exc}), беру сохранённый список.")
        elif not self.servers:
            raise RuntimeError("Сначала добавь подписку — кнопка «Добавить подписку» на главной.")
        self.check_stop()
        working = self.test_all()
        if not working:
            raise RuntimeError("Ни один сервер не отвечает. Проверь интернет или обнови подписку.")
        try:
            self.speed_top(3)
        except Cancelled:
            raise
        except Exception as exc:
            self.log(f"Замер скорости не удался: {exc}")
        self.check_stop()
        best = self.best()
        if not best:
            raise RuntimeError("Не удалось выбрать сервер.")
        self.connect(best)
        steps.append(f"сервер: {best.name}")
        r = best.result
        if r.get("ping_ms") is not None:
            steps.append(f"пинг {r['ping_ms']} мс")
        if r.get("speed_mbps"):
            steps.append(f"скорость {r['speed_mbps']} Мбит/с")
        self.check_stop()
        self.direct_ping()
        results = self.check_services()
        changes = self.autofix(results)
        if changes:
            results = self.check_services()
            steps.append("поправлены маршруты: " + ", ".join(changes))
        bad = [n for n, x in results.items() if x.get("current", {}).get("state") in (services.BLOCKED, services.REGION)]
        steps.append("все сервисы работают" if not bad else "не открываются: " + ", ".join(bad))
        dpi_step = self._auto_setup_dpi()
        if dpi_step:
            steps.append(dpi_step)
        text = "Автонастройка готова — " + "; ".join(steps) + "."
        self.log(text)
        self.notify("summary", text=text)

    # ---------- обход замедлений: zapret и ByeDPI ----------

    def dpi_domains(self) -> list[str]:
        s = self.settings
        out: list[str] = []
        if s.get("dpi_youtube", True):
            out += dpi.YOUTUBE_DOMAINS
        if s.get("dpi_discord", True):
            out += dpi.DISCORD_DOMAINS
        out += [ln.strip() for ln in (s.get("dpi_custom") or "").splitlines() if ln.strip() and not ln.startswith("#")]
        # сервисы и сайты, для которых выбрано «напрямую с обходом замедления»
        for key, spec in (s.get("routes") or {}).items():
            if spec.get("via") == "dpi":
                out += [d[7:] for d in self._route_domains(key)[0] if d.startswith("domain:")]
        return list(dict.fromkeys(out))

    def _dpi_targets(self) -> tuple[str, ...]:
        s = self.settings
        t = tuple(x for x, key in (("youtube", "dpi_youtube"), ("discord", "dpi_discord")) if s.get(key, True))
        return t or ("youtube",)

    def _dpi_route(self) -> dict | None:
        """Как ядру вести сайты обхода: напрямую (их чинит zapret) или через локальный прокси ByeDPI."""
        if self.dpi_mode == "zapret":
            return {"mode": "direct", "domains": self.dpi_domains()}
        if self.dpi_mode == "byedpi" and self.byedpi.port:
            return {"mode": "byedpi", "port": self.byedpi.port, "domains": self.dpi_domains()}
        return None

    def _set_dpi_mode(self, mode: str) -> None:
        changed = mode != self.dpi_mode
        self.dpi_mode = mode
        if changed:
            self.dpi_last = {}
            self.notify("status")
            if self.connected:
                self.reconnect()

    def _network_key(self) -> str:
        """Сеть, для которой запоминается стратегия (у разных провайдеров работают разные).
        Ключ — первые две части внешнего IP без VPN; сам адрес не сохраняется."""
        cached = getattr(self, "_net_cache", None)
        if cached and time.time() - cached[1] < 600:
            return cached[0]
        try:
            ip = services.exit_info(self._direct_http()).get("ip") or ""
        except Exception:
            ip = ""
        key = ".".join(ip.split(".")[:2]) if ip.count(".") == 3 else ""
        self._net_cache = (key, time.time())
        return key

    def _zapret_strategies(self) -> list[dict]:
        return dpi.list_strategies(self.dpi_paths.zapret_dir)

    def _zapret_by_name(self, name: str) -> dict | None:
        return next((x for x in self._zapret_strategies() if x["name"] == name), None)

    def _check_dpi_path(self, socks_port: int | None, light: bool = False) -> dict:
        checks = None
        if light:  # лёгкая фоновая проверка — меньше трафика
            checks = {"youtube": [("www.youtube.com", "/", 120_000)], "discord": [("discord.com", "/api/v9/experiments", 2_000)]}
        if socks_port is None:
            socks_port = self._direct_socks()  # в режиме TUN «напрямую» — через служебный вход ядра
        return dpi.check_targets(socks_port, targets=self._dpi_targets(), timeout=6.0 if light else 8.0, checks=checks)

    @staticmethod
    def _dpi_ok(res: dict) -> bool:
        return bool(res) and all(r.get("ok") for r in res.values())

    def _start_zapret(self, name: str) -> bool:
        strat = self._zapret_by_name(name)
        if not strat:
            self.dpi_errors["zapret"] = f"стратегия «{name}» не найдена — нажми «Подобрать лучшую»"
            return False
        dpi.add_custom_domains(self.dpi_paths.zapret_dir, self.dpi_domains())
        self.zapret.start(strat)
        self.dpi_errors.pop("zapret", None)
        return True

    def _start_byedpi(self, args: str) -> bool:
        if not args:
            return False
        self.byedpi.start(args)
        self.dpi_errors.pop("byedpi", None)
        return True

    def start_dpi(self, verify: bool = False) -> str:
        """Включает обход замедлений по настройкам: основной способ, при неудаче — запасной.
        verify=True — сразу проверить YouTube и Discord и, если основной способ не помогает, включить запасной."""
        s = self.settings
        role = s.get("byedpi_role", "backup")
        order = ["byedpi", "zapret"] if role == "main" else ["zapret", "byedpi"]
        ready = {
            "zapret": bool(s.get("zapret_enabled") and self.dpi_supported and self.dpi_paths.zapret_installed()
                           and s.get("zapret_strategy")),
            "byedpi": bool(role != "off" and self.dpi_paths.byedpi_installed() and s.get("byedpi_strategy")),
        }
        mode, fallback, checked = "", "", None
        for name in [n for n in order if ready[n]]:
            try:
                if name == "zapret":
                    self.byedpi.stop()
                    if not self._start_zapret(s["zapret_strategy"]):
                        continue
                else:
                    self.zapret.stop()
                    self._start_byedpi(s["byedpi_strategy"])
            except dpi.DpiError as exc:
                self.dpi_errors[name] = str(exc)
                self.log(f"{'Zapret' if name == 'zapret' else 'ByeDPI'}: {exc}")
                continue
            if not verify:
                mode = name
                break
            if name == "zapret":
                time.sleep(1.5)
            res = self._check_dpi_path(self.byedpi.port if name == "byedpi" else None, light=True)
            if self._dpi_ok(res):
                mode, checked = name, res
                break
            fallback = fallback or name
            self.log(f"{'Zapret' if name == 'zapret' else 'ByeDPI'} включился, но YouTube и Discord с ним не открываются.")
        if not mode and fallback:
            # ничего не помогло — возможно, просто нет интернета; оставляем основной способ, дальше разберётся Автопереход
            try:
                if fallback == "zapret":
                    self.byedpi.stop()
                    self._start_zapret(s["zapret_strategy"])
                else:
                    self.zapret.stop()
                    self._start_byedpi(s["byedpi_strategy"])
                mode = fallback
            except dpi.DpiError:
                pass
        if mode != "zapret":
            self.zapret.stop()
        if mode != "byedpi":
            self.byedpi.stop()
        if mode:
            self.log(f"Обход замедлений: работает {'zapret' if mode == 'zapret' else 'ByeDPI'}.")
            self.resolve("dpi")
        self._dpi_fail = 0
        self._set_dpi_mode(mode)
        if checked:
            self.dpi_last = {"at": time.time(), "mode": mode, **checked}
        return mode

    def stop_dpi(self) -> None:
        self.zapret.stop()
        self.byedpi.stop()
        self._set_dpi_mode("")

    def _ensure_dpi_tool(self, which: str) -> None:
        installed = self.dpi_paths.zapret_installed() if which == "zapret" else self.dpi_paths.byedpi_installed()
        if installed:
            return
        self.progress(f"Скачиваю {'zapret' if which == 'zapret' else 'ByeDPI'}")
        if which == "zapret":
            ver = self._fetch_any(lambda p: dpi.download_zapret(self.dpi_paths, p), "zapret")
        else:
            ver = self._fetch_any(lambda p: dpi.download_byedpi(self.dpi_paths, p), "ByeDPI")
        self.log(f"{'Zapret' if which == 'zapret' else 'ByeDPI'} скачан: версия {ver or '?'}.")

    def pick_zapret(self) -> dict | None:
        """Перебирает стратегии zapret и выбирает ту, с которой лучше всего работают YouTube и Discord."""
        if not self.dpi_supported:
            raise RuntimeError("Zapret работает только в Windows.")
        self._ensure_dpi_tool("zapret")
        strategies = self._zapret_strategies()
        if not strategies:
            raise RuntimeError("В сборке zapret не нашлось стратегий — обнови zapret.")
        was = self.dpi_mode
        self.zapret.stop()
        self.byedpi.stop()
        self._set_dpi_mode("")
        self.progress("Подбираю стратегию zapret: проверка без обхода")
        base = self._check_dpi_path(None)
        if self._dpi_ok(base):
            self.log("YouTube и Discord и так открываются без замедления — zapret может и не понадобиться.")
        results = []
        try:
            for i, st in enumerate(strategies, 1):
                self.check_stop()
                self.progress(f"Подбираю стратегию zapret: {i} из {len(strategies)}")
                try:
                    self._start_zapret(st["name"])
                    time.sleep(1.5)
                    res = self._check_dpi_path(None)
                except dpi.DpiAdminError as exc:
                    raise RuntimeError(str(exc)) from exc
                except dpi.DpiError as exc:
                    res = {t: {"ok": False, "kbps": 0, "detail": str(exc)} for t in self._dpi_targets()}
                finally:
                    self.zapret.stop()
                results.append({"name": st["name"], **res})
        finally:
            results.sort(key=dpi.score, reverse=True)
            if results:
                self.settings["zapret_results"] = results
                self.settings["zapret_tested_at"] = time.time()
                self.save()
                self.notify("dpi")
        best = results[0] if results and dpi.score(results[0])[0] > 0 else None
        if not best:
            self.log("Ни одна стратегия zapret не помогла — YouTube и Discord пойдут через VPN.")
            if was:
                self.start_dpi()
            return None
        self.settings["zapret_strategy"] = best["name"]
        self.settings["zapret_enabled"] = True
        self._remember_network("zapret", best["name"])
        self.save()
        self.log(f"Лучшая стратегия zapret: {best['name']}.")
        self.start_dpi()
        return best

    def pick_byedpi(self) -> dict | None:
        """Перебирает наборы параметров ByeDPI (и свой, если задан) и выбирает лучший."""
        self._ensure_dpi_tool("byedpi")
        was_zapret = self.dpi_mode == "zapret"
        self.byedpi.stop()
        candidates = [{"name": n, "args": a} for n, a in dpi.BYEDPI_STRATEGIES]
        custom = (self.settings.get("byedpi_custom") or "").strip()
        if custom:
            candidates.insert(0, {"name": "Своя стратегия", "args": custom})
        if was_zapret:
            self.zapret.stop()  # чтобы zapret не влиял на проверку
        results = []
        try:
            for i, st in enumerate(candidates, 1):
                self.check_stop()
                self.progress(f"Подбираю стратегию ByeDPI: {i} из {len(candidates)}")
                try:
                    port = self.byedpi.start(st["args"])
                    res = self._check_dpi_path(port)
                except dpi.DpiError as exc:
                    res = {t: {"ok": False, "kbps": 0, "detail": str(exc)} for t in self._dpi_targets()}
                finally:
                    self.byedpi.stop()
                results.append({"name": st["name"], "args": st["args"], **res})
        finally:
            results.sort(key=dpi.score, reverse=True)
            if results:
                self.settings["byedpi_results"] = results
                self.settings["byedpi_tested_at"] = time.time()
                self.save()
                self.notify("dpi")
        best = results[0] if results and dpi.score(results[0])[0] > 0 else None
        if best:
            self.settings["byedpi_strategy"] = best["args"]
            if self.settings.get("byedpi_role") == "off":
                self.settings["byedpi_role"] = "backup"
            self._remember_network("byedpi", best["args"])
            self.save()
            self.log(f"Лучшая стратегия ByeDPI: {best['name']} ({best['args']}).")
        else:
            self.log("Ни одна стратегия ByeDPI не помогла.")
        self.start_dpi()
        return best

    def _remember_network(self, which: str, value: str) -> None:
        key = self._network_key()
        if key:
            self.settings.setdefault("dpi_networks", {}).setdefault(key, {})[which] = value

    def _apply_network_strategies(self) -> None:
        """В другой сети (у другого провайдера) берём стратегии, подобранные для неё."""
        key = self._network_key()
        saved = (self.settings.get("dpi_networks") or {}).get(key) if key else None
        if saved:
            if saved.get("zapret"):
                self.settings["zapret_strategy"] = saved["zapret"]
            if saved.get("byedpi"):
                self.settings["byedpi_strategy"] = saved["byedpi"]

    def select_zapret(self, name: str) -> None:
        if not self._zapret_by_name(name):
            raise RuntimeError("Такой стратегии нет.")
        self.settings["zapret_strategy"] = name
        self.settings["zapret_enabled"] = True
        self._remember_network("zapret", name)
        self.save()
        self.start_dpi()

    @staticmethod
    def _clean_byedpi_args(args: str) -> str:
        args = " ".join((args or "").split())
        if not args or not args.startswith("-") or re.search(r'[\x00-\x1f"&|<>^%]', args):
            raise RuntimeError("Впиши параметры ByeDPI, например --disorder 1.")
        return args

    def select_byedpi(self, args: str) -> None:
        args = self._clean_byedpi_args(args)
        self.settings["byedpi_strategy"] = args
        if self.settings.get("byedpi_role") == "off":
            self.settings["byedpi_role"] = "backup"
        self._remember_network("byedpi", args)
        self.save()
        self.start_dpi()

    def test_byedpi_custom(self, args: str) -> dict:
        args = self._clean_byedpi_args(args)
        self._ensure_dpi_tool("byedpi")
        self.settings["byedpi_custom"] = args
        was = self.dpi_mode
        self.byedpi.stop()
        self.progress("Проверяю свою стратегию ByeDPI")
        try:
            port = self.byedpi.start(args)
            res = self._check_dpi_path(port)
        except dpi.DpiError as exc:
            res = {t: {"ok": False, "kbps": 0, "detail": str(exc)} for t in self._dpi_targets()}
        finally:
            self.byedpi.stop()
        item = {"name": "Своя стратегия", "args": args, **res}
        lst = [x for x in self.settings.get("byedpi_results", []) if x.get("args") != args] + [item]
        lst.sort(key=dpi.score, reverse=True)
        self.settings["byedpi_results"] = lst
        self.save()
        self.notify("dpi")
        ok = self._dpi_ok(res)
        self.log("Своя стратегия ByeDPI работает." if ok else "Своя стратегия ByeDPI не помогла.")
        if was:
            self.start_dpi()
        return item

    def check_dpi(self) -> dict:
        """Проверяет YouTube и Discord тем путём, которым они идут сейчас."""
        self.progress("Проверяю YouTube и Discord")
        port = self.byedpi.port if self.dpi_mode == "byedpi" else None
        res = self._check_dpi_path(port)
        self.dpi_last = {"at": time.time(), "mode": self.dpi_mode, **res}
        self.notify("dpi")
        ok = self._dpi_ok(res)
        self.log("Проверка: YouTube и Discord открываются." if ok else "Проверка: YouTube или Discord не открываются.")
        return self.dpi_last

    def set_dpi(self, values: dict) -> bool:
        """Меняет настройки обхода. Возвращает True, если нужно перезапустить обход."""
        s = self.settings
        restart = False
        for key in ("zapret_enabled", "dpi_youtube", "dpi_discord"):
            if key in values:
                s[key] = bool(values[key])
                restart = True
        if values.get("byedpi_role") in ("main", "backup", "off"):
            s["byedpi_role"] = values["byedpi_role"]
            restart = True
        if "dpi_custom" in values:
            lines = []
            for ln in str(values["dpi_custom"]).splitlines():
                try:
                    entry = routing.normalize_entry(ln)
                except ValueError:
                    continue
                if entry and entry[0] == "domain" and entry[1].startswith(("domain:", "full:")):
                    lines.append(entry[1].split(":", 1)[1])
            s["dpi_custom"] = "\n".join(dict.fromkeys(lines))
            restart = True
        self.save()
        self.notify("dpi")
        return restart

    def update_dpi(self, auto: bool = False) -> None:
        """Обновляет zapret и ByeDPI с GitHub. Сначала сверяет номер версии; качает, только если вышла новая."""
        proxy = self.ports.get("health") if self.connected else None
        self.settings["last_dpi_check"] = time.time()
        self.save()
        jobs = []
        if self.dpi_supported and (self.settings.get("zapret_enabled") or self.dpi_paths.zapret_installed()):
            jobs.append(("zapret", dpi.ZAPRET_REPO))
        if self.settings.get("byedpi_role") != "off" or self.dpi_paths.byedpi_installed():
            jobs.append(("byedpi", dpi.BYEDPI_REPO))
        errors = []
        for which, repo in jobs:
            self.check_stop()
            title = "zapret" if which == "zapret" else "ByeDPI"
            self.progress(f"Проверяю обновление {title}")
            running = (self.dpi_mode == which)
            try:
                rel = dpi.latest_release(repo, proxy)
                tag = str(rel.get("tag_name") or "").lstrip("vV")
                if tag and tag == self.dpi_paths.version(which):
                    continue
                self.progress(f"Скачиваю {title} {tag}")
                if which == "zapret":
                    self.zapret.stop()  # работающий winws.exe нельзя заменить
                    dpi.download_zapret(self.dpi_paths, proxy, rel)
                else:
                    self.byedpi.stop()
                    dpi.download_byedpi(self.dpi_paths, proxy, rel)
                self.log(f"{title} обновлён: версия {tag or '?'}.")
            except Cancelled:
                raise
            except Exception as exc:  # сеть или GitHub: в фоне — тихо в журнал, по кнопке — понятной ошибкой
                text = exc.args[0] if isinstance(exc, dpi.DpiError) and exc.args else netutil.human_error(exc)
                self.log(f"Не удалось обновить {title}: {text}")
                errors.append(f"{title}: {text}")
            finally:
                if running and self.dpi_mode == which and not (self.zapret.running_name or self.byedpi.alive()):
                    self.start_dpi()
        self.notify("dpi")
        if errors and not auto:
            raise RuntimeError("; ".join(f"Не удалось обновить {x}" for x in errors))

    def setup_dpi(self) -> str:
        """Подбирает стратегии для включённых способов, у которых их ещё нет, и включает обход."""
        text = self._auto_setup_dpi()
        if not self.dpi_mode and (self.settings.get("zapret_enabled") or self.settings.get("byedpi_role") != "off"):
            self.start_dpi(verify=True)
        return text

    def _auto_setup_dpi(self) -> str:
        """Шаг автонастройки: скачать нужное и подобрать стратегии, которых ещё нет."""
        s = self.settings
        done = []
        if not self.dpi_supported:
            return ""
        try:
            if s.get("zapret_enabled"):
                if s.get("zapret_strategy") and not self.dpi_paths.zapret_installed():
                    self._ensure_dpi_tool("zapret")  # стратегия пришла из файла настроек — проверим, что она есть
                    if not self._zapret_by_name(s["zapret_strategy"]):
                        s["zapret_strategy"] = ""
                if not s.get("zapret_strategy"):
                    best = self.pick_zapret()
                    done.append(f"zapret — {best['name']}" if best else "zapret не помог")
            if s.get("byedpi_role") != "off":
                if s.get("byedpi_strategy") and not self.dpi_paths.byedpi_installed():
                    self._ensure_dpi_tool("byedpi")
                if not s.get("byedpi_strategy"):
                    best = self.pick_byedpi()
                    done.append(f"ByeDPI — {best['name']}" if best else "ByeDPI не помог")
        except Cancelled:
            raise
        except Exception as exc:
            self.log(f"Обход замедлений не настроился: {exc}")
            done.append("обход замедлений не настроился")
        if not done and not self.dpi_mode and (s.get("zapret_strategy") or s.get("byedpi_strategy")):
            self.start_dpi()
        return ", ".join(done)

    def _dpi_watch(self) -> None:
        """Тихая проверка раз в 5 минут: если обход перестал работать — Автопереход ищет другой способ."""
        if self._dpi_watching:
            return
        self._dpi_watching = True
        try:
            if not self.dpi_mode:
                return
            alive = self.zapret.alive() if self.dpi_mode == "zapret" else self.byedpi.alive()
            port = self.byedpi.port if self.dpi_mode == "byedpi" else None
            res = self._check_dpi_path(port, light=True) if alive else {}
            ok = alive and self._dpi_ok(res)
            if res:
                self.dpi_last = {"at": time.time(), "mode": self.dpi_mode, **res}
            self._dpi_fail = 0 if ok else self._dpi_fail + 1
            if self._dpi_fail >= 2 and self.settings.get("autopilot") and not self.is_busy():
                self._dpi_fail = 0
                self.run_task("Автопереход: обход замедлений", self.dpi_failover)
        except Exception as exc:
            self.log(f"Проверка обхода замедлений: {exc}")
        finally:
            self._dpi_watching = False

    def dpi_failover(self) -> str:
        """Обход перестал работать: другая стратегия → ByeDPI → через VPN."""
        mode = self.dpi_mode
        self.log(f"Автопереход: {'zapret' if mode == 'zapret' else 'ByeDPI'} перестал справляться, ищу замену.")
        if mode == "zapret":
            current = self.settings.get("zapret_strategy")
            for item in self.settings.get("zapret_results", []):
                if item["name"] == current or dpi.score(item)[0] == 0:
                    continue
                self.check_stop()
                try:
                    self._start_zapret(item["name"])
                    time.sleep(1.5)
                    if self._dpi_ok(self._check_dpi_path(None)):
                        self.settings["zapret_strategy"] = item["name"]
                        self.save()
                        self.log(f"Автопереход: zapret работает со стратегией {item['name']}.")
                        self.notify("dpi")
                        return "zapret"
                except dpi.DpiError:
                    pass
            self.zapret.stop()
        if self.settings.get("byedpi_role") != "off" and self.dpi_paths.byedpi_installed():
            args = self.settings.get("byedpi_strategy") or ""
            tried = [args] + [x["args"] for x in self.settings.get("byedpi_results", [])
                              if x.get("args") != args and dpi.score(x)[0] > 0]
            for a in [x for x in tried if x][:4]:
                self.check_stop()
                try:
                    port = self.byedpi.start(a)
                    if self._dpi_ok(self._check_dpi_path(port)):
                        self.settings["byedpi_strategy"] = a
                        self.save()
                        self.log("Автопереход: YouTube и Discord идут через ByeDPI.")
                        self._set_dpi_mode("byedpi")
                        self.notify("dpi")
                        return "byedpi"
                except dpi.DpiError:
                    pass
            self.byedpi.stop()
        self.zapret.stop()
        self._set_dpi_mode("")
        self.problem("dpi", "Zapret и ByeDPI перестали работать", "YouTube и Discord идут через VPN.",
                     where="Обход замедлений", fix="Нажми «Подобрать лучшую стратегию» на странице Zapret.")
        self.log("Автопереход: YouTube и Discord временно идут через VPN.")
        return ""

    def dpi_state(self) -> dict:
        s = self.settings
        zres = s.get("zapret_results", [])
        bres = s.get("byedpi_results", [])
        bstrat = s.get("byedpi_strategy", "")
        bname = next((x["name"] for x in bres if x.get("args") == bstrat), "") or \
            next((n for n, a in dpi.BYEDPI_STRATEGIES if a == bstrat), "")
        tr_res = lambda lst: [dict(x, name=i18n.tr(x["name"]), **{t: dict(x[t], detail=i18n.tr(x[t].get("detail", "")))  # noqa: E731
                                                                 for t in ("youtube", "discord") if t in x})
                               for x in lst]
        return {
            "mode": self.dpi_mode, "supported": self.dpi_supported,
            "zapret": {"enabled": bool(s.get("zapret_enabled")), "installed": self.dpi_paths.zapret_installed(),
                       "version": self.dpi_paths.version("zapret"), "strategy": s.get("zapret_strategy", ""),
                       "tested_at": s.get("zapret_tested_at", 0), "results": tr_res(zres),
                       "error": i18n.tr(self.dpi_errors.get("zapret", "")),
                       "running": self.dpi_mode == "zapret"},
            "byedpi": {"role": s.get("byedpi_role", "backup"), "installed": self.dpi_paths.byedpi_installed(),
                       "version": self.dpi_paths.version("byedpi"), "strategy": bstrat, "strategy_name": i18n.tr(bname),
                       "tested_at": s.get("byedpi_tested_at", 0), "results": tr_res(bres),
                       "custom": s.get("byedpi_custom", ""), "error": i18n.tr(self.dpi_errors.get("byedpi", "")),
                       "running": self.dpi_mode == "byedpi"},
            "sites": {"youtube": bool(s.get("dpi_youtube", True)), "discord": bool(s.get("dpi_discord", True)),
                      "custom": s.get("dpi_custom", "")},
            "last": {k: (dict(v, detail=i18n.tr(v.get("detail", ""))) if isinstance(v, dict) else v)
                     for k, v in self.dpi_last.items()},
        }

    # ---------- перенос настроек и QR-коды ----------

    def export_settings(self, with_subs: bool = False, with_servers: bool = False) -> dict:
        return share.export(self.settings, with_subs, with_servers)

    def import_settings(self, parsed: dict) -> str:
        """Применяет проверенный файл настроек (share.parse). Подписки скачиваются заново."""
        s = self.settings
        dpi_keys = ("zapret_enabled", "zapret_strategy", "byedpi_role", "byedpi_strategy", "dpi_youtube",
                    "dpi_discord", "dpi_custom")
        before = tuple(s.get(k) for k in dpi_keys)
        vals = dict(parsed["settings"])
        custom = vals.pop("dpi_custom", None)
        s.update(vals)
        if custom is not None:
            self.set_dpi({"dpi_custom": custom})
        self.save()
        self.log(f"Из файла применено настроек: {len(parsed['settings'])}.")
        subs = 0
        for item in parsed["subscriptions"]:
            self.check_stop()
            try:
                self.add_subscription(item["url"], item.get("name", ""))
                subs += 1
            except Cancelled:
                raise
            except Exception as exc:  # одна плохая подписка не мешает остальным
                self.log(f"Подписка из файла не добавилась: {exc}")
        servers = 0
        if parsed["servers"]:
            try:
                servers = self.add_servers("\n".join(parsed["servers"]))
            except RuntimeError as exc:
                self.log(f"Серверы из файла не добавились: {exc}")
        if self.connected:
            self.reconnect()
        if before != tuple(s.get(k) for k in dpi_keys) and self.dpi_supported:
            self.setup_dpi()
        text = f"Настройки из файла применены. Подписок добавлено: {subs}, серверов: {servers}."
        self.log(text)
        self.notify("summary", text=i18n.tr(text))
        self.notify("status")
        return text

    def ensure_lan_credentials(self, new: bool = False) -> None:
        """Логин и пароль для доступа из сети придумываются сами: короткие, чтобы легко вписать в телефоне."""
        s = self.settings
        if s.get("allow_lan") and s.get("lan_auth", True) and (new or not s.get("lan_pass")):
            import secrets
            alphabet = "abcdefghjkmnpqrstuvwxyz23456789"  # без похожих букв и цифр
            s["lan_user"] = s.get("lan_user") or "pult"
            s["lan_pass"] = "".join(secrets.choice(alphabet) for _ in range(8))
            self.save()

    # ---------- мастер своего сервера ----------

    def vps_setup(self, host: str, port, user: str, name: str = "") -> list[str]:
        """Настраивает свой VPS через ssh и добавляет его в список. Пароль человек вводит в окне ssh сам."""
        try:
            host, port, user = vps.check_input(host, port, user)
        except vps.VpsError as exc:
            raise RuntimeError(str(exc)) from exc
        name = (name or "").strip()[:40] or i18n.tr("Свой VPS")
        script_path = os.path.join(self.paths.data_dir, "vps_install.sh")
        out_path = os.path.join(self.paths.data_dir, "vps_install.log")
        self.progress("Открываю окно для входа на сервер — введи там пароль")
        self.log("Мастер своего сервера: подключаюсь к серверу.")
        try:
            hint = i18n.tr("VEDOMYJ VPN: введи пароль от сервера и нажми Enter. Символы пароля не отображаются — "
                           "так и должно быть.")
            proc = vps.start(host, port, user, script_path, out_path, hint)
            result = vps.wait(proc, out_path, self.progress, self.stop_event.is_set)
            links = vps.make_links(host, result, name)
        except vps.VpsError as exc:
            if str(exc) == "остановлено":
                raise Cancelled() from exc
            raise RuntimeError(f"Сервер не настроился: {exc}") from exc
        finally:
            for path in (script_path, out_path):  # в ответе сервера — ключ подключения, на диске его не оставляем
                try:
                    os.remove(path)
                except OSError:
                    pass
        self._vps_entry(host, port, user, name)
        added = self.add_servers("\n".join(links))
        self.log(f"Мастер своего сервера: сервер настроен и добавлен ({added} подключения). Проверяю его.")
        mine = [s for s in self.servers if s.link in links]
        if mine:
            self.test_all(mine)
        ok = [s for s in mine if (s.result or {}).get("ok")]
        if ok:
            self.log(f"Свой сервер работает: {', '.join(s.name for s in ok)}.")
        else:
            self.log("Свой сервер настроен, но пока не отвечает. Возможно, хостинг ещё открывает порты — "
                     "проверь через пару минут. Если не заработает, провайдер мог заблокировать адрес сервера.")
        self.notify("servers")
        return links

    # ---------- свой сервер: состояние и доступ для друга ----------
    # Адрес, порт и имя для входа хранятся (зашифрованными), пароль — никогда: его вводят в окне ssh.

    VPS_FRIENDS_MAX = 20

    def _vps_entry(self, host: str, port: int, user: str, name: str = "") -> dict:
        hosts = self.settings.setdefault("vps_hosts", [])
        for h in hosts:
            if h.get("host") == host and int(h.get("port", 22)) == port and h.get("user") == user:
                if name:
                    h["name"] = name
                self.save()
                return h
        h = {"id": secrets.token_hex(4), "host": host, "port": port, "user": user,
             "name": name or i18n.tr("Свой VPS"), "friends": [], "status": {}}
        hosts.append(h)
        self.save()
        return h

    def _vps_find(self, vps_id: str) -> dict:
        h = next((h for h in self.settings.get("vps_hosts") or [] if h.get("id") == vps_id), None)
        if not h:
            raise RuntimeError("Этот сервер не найден — добавь его ещё раз.")
        return h

    def vps_view(self) -> list[dict]:
        """Свои серверы для окна программы (без ключей друзей — их отдаёт только QR-код)."""
        return [{"id": h["id"], "name": h.get("name", ""), "host": h["host"], "port": h.get("port", 22),
                 "user": h.get("user", "root"), "status": h.get("status") or {},
                 "friends": [{"id": f["id"], "name": f.get("name", ""), "ts": f.get("ts", 0)}
                             for f in h.get("friends") or []]}
                for h in self.settings.get("vps_hosts") or []]

    def _vps_run(self, h: dict, body: str, what: str) -> str:
        """Выполняет скрипт на своём сервере через окно ssh и возвращает строку PULT_RESULT."""
        script_path = os.path.join(self.paths.data_dir, "vps_task.sh")
        out_path = os.path.join(self.paths.data_dir, "vps_task.log")
        self.progress("Открываю окно для входа на сервер — введи там пароль")
        hint = i18n.tr("VEDOMYJ VPN: введи пароль от сервера и нажми Enter. Символы пароля не отображаются — "
                       "так и должно быть.")
        try:
            proc = vps.start(h["host"], int(h.get("port", 22)), h.get("user", "root"), script_path, out_path,
                             hint, body=body)
            return vps.wait(proc, out_path, self.progress, self.stop_event.is_set, timeout=300.0)
        except vps.VpsError as exc:
            if str(exc) == "остановлено":
                raise Cancelled() from exc
            raise RuntimeError(f"{what}: {exc}") from exc
        finally:
            for path in (script_path, out_path):
                try:
                    os.remove(path)
                except OSError:
                    pass

    def vps_add(self, host: str, port, user: str, name: str = "") -> dict:
        """Запомнить уже настроенный сервер (например, настроенный раньше) и сразу проверить его состояние."""
        try:
            host, port, user = vps.check_input(host, port, user)
        except vps.VpsError as exc:
            raise RuntimeError(str(exc)) from exc
        status = self._vps_status_of({"host": host, "port": port, "user": user})
        h = self._vps_entry(host, port, user, (name or "").strip()[:40])
        h["status"] = status
        self.save()
        self.notify("vps")
        return status

    def _vps_status_of(self, h: dict) -> dict:
        result = self._vps_run(h, vps.status_script(), "Состояние сервера не получено")
        try:
            status = vps.parse_status(result)
        except vps.VpsError as exc:
            raise RuntimeError(f"Состояние сервера не получено: {exc}") from exc
        status["ts"] = int(time.time())
        return status

    def vps_status(self, vps_id: str) -> dict:
        h = self._vps_find(vps_id)
        status = self._vps_status_of(h)
        h["status"] = status
        self.save()
        if status["xray"] != "active":
            self.log(f"Свой сервер «{h['name']}»: Xray не работает. Запусти мастер настройки ещё раз.")
        else:
            self.log(f"Свой сервер «{h['name']}» работает: подключений {status['conns']}, "
                     f"пользователей {status['clients']}.")
        self.notify("vps")
        return status

    def vps_friend_add(self, vps_id: str, name: str) -> dict:
        """Отдельный ключ для друга на своём сервере: его можно отозвать, не меняя свой."""
        h = self._vps_find(vps_id)
        friends = h.setdefault("friends", [])
        if len(friends) >= self.VPS_FRIENDS_MAX:
            raise RuntimeError("Слишком много ключей для друзей — сначала удали ненужные.")
        name = (name or "").strip()[:30] or i18n.tr("Друг")
        result = self._vps_run(h, vps.friend_script("add"), "Ключ для друга не создан")
        try:
            links = vps.make_links(h["host"], result, f"{h.get('name') or 'VPS'} · {name}")
        except vps.VpsError as exc:
            raise RuntimeError(f"Ключ для друга не создан: {exc}") from exc
        friend = {"id": result.split("|")[0], "name": name, "ts": int(time.time()), "links": links}
        friends.append(friend)
        self.save()
        self.log(f"Свой сервер «{h['name']}»: создан ключ для «{name}». QR-код — в разделе «Поделиться».")
        self.notify("vps", friend="friend:" + friend["id"], name=name)
        return {"id": friend["id"], "name": name}

    def vps_friend_remove(self, vps_id: str, friend_id: str) -> None:
        h = self._vps_find(vps_id)
        friend = next((f for f in h.get("friends") or [] if f["id"] == friend_id), None)
        if not friend:
            raise RuntimeError("Этот ключ уже удалён.")
        self._vps_run(h, vps.friend_script("remove", friend_id), "Ключ не удалён")
        h["friends"] = [f for f in h["friends"] if f["id"] != friend_id]
        self.save()
        self.log(f"Свой сервер «{h['name']}»: ключ «{friend.get('name', '')}» удалён — по нему больше не подключиться.")
        self.notify("vps")

    def vps_forget(self, vps_id: str) -> None:
        """Убрать сервер из списка программы (на самом сервере ничего не меняется)."""
        self._vps_find(vps_id)
        self.settings["vps_hosts"] = [h for h in self.settings["vps_hosts"] if h.get("id") != vps_id]
        self.save()
        self.notify("vps")

    def _vps_friend(self, friend_id: str) -> dict | None:
        for h in self.settings.get("vps_hosts") or []:
            for f in h.get("friends") or []:
                if f["id"] == friend_id:
                    return f
        return None

    # ---------- раздача VPN по Wi-Fi ----------

    def _hotspot_credentials(self) -> tuple[str, str]:
        s = self.settings
        if not s.get("hotspot_ssid") or not s.get("hotspot_pass"):
            alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
            s["hotspot_ssid"] = "Pult-" + "".join(secrets.choice("23456789") for _ in range(4))
            s["hotspot_pass"] = "".join(secrets.choice(alphabet) for _ in range(10))
            self.save()
        return s["hotspot_ssid"], s["hotspot_pass"]

    def hotspot_start(self) -> dict:
        ssid, password = self._hotspot_credentials()
        self.progress("Включаю раздачу Wi-Fi")
        try:
            r = hotspot.run("start", ssid, password, tun.ADAPTER if self.tun_active else "")
        except hotspot.HotspotError as exc:
            self.hotspot.update(on=False, error=str(exc))
            self.notify("status")
            raise RuntimeError(f"Раздача не включилась: {exc}") from exc
        self.hotspot.update(r, error="")
        if r["via_tun"]:
            self.log(f"Раздача Wi-Fi включена: сеть «{ssid}». Подключённые устройства идут через VPN.")
        else:
            self.log(f"Раздача Wi-Fi включена: сеть «{ssid}». Чтобы устройства шли через VPN без настроек, "
                     "включи режим TUN.")
        self.notify("status")
        return self.hotspot

    def hotspot_stop(self) -> None:
        self.progress("Выключаю раздачу Wi-Fi")
        try:
            hotspot.run("stop")
        except hotspot.HotspotError as exc:
            self.log(f"Раздача: {exc}")
        self.hotspot.update(on=False, clients=0, via_tun=False)
        self.log("Раздача Wi-Fi выключена.")
        self.notify("status")

    def _hotspot_restart(self) -> None:
        try:
            ssid, password = self._hotspot_credentials()
            r = hotspot.run("start", ssid, password, tun.ADAPTER if self.tun_active else "")
            self.hotspot.update(r, error="")
        except hotspot.HotspotError as exc:
            self.hotspot.update(on=False, error=str(exc))
            self.log(f"Раздача: {exc}")
        self.notify("status")

    def hotspot_state(self) -> dict:
        s = self.settings
        return dict(self.hotspot, ssid=s.get("hotspot_ssid", ""), password=s.get("hotspot_pass", ""),
                    supported=hotspot.IS_WINDOWS, error=i18n.tr(self.hotspot.get("error", "")))

    def share_items(self) -> list[dict]:
        """Что можно показать QR-кодом для телефона. Сами ссылки сюда не входят — только названия."""
        items = [{"id": "sub:" + m["id"], "kind": "sub", "name": self.sub_name(m)}
                 for m in self.settings["subscriptions"]]
        srv = self.current if self.connected else self.best()
        if srv and srv.link:
            items.append({"id": "srv:" + srv.key, "kind": "server", "name": countries.detect(srv.name)[1]})
        for h in self.settings.get("vps_hosts") or []:
            for f in h.get("friends") or []:
                items.append({"id": "friend:" + f["id"], "kind": "friend", "name": f.get("name", ""),
                              "server": h.get("name", "")})
        lan = netutil.lan_ip() if self.settings.get("allow_lan") else ""
        items.append({"id": "tg_lan", "kind": "telegram", "name": "Telegram", "ready": bool(lan)})
        return items

    def share_text(self, item_id: str) -> str:
        """Текст для QR-кода: ссылка на подписку, ссылка на сервер или прокси Telegram через этот компьютер."""
        if item_id.startswith("sub:"):
            meta = next((m for m in self.settings["subscriptions"] if m["id"] == item_id[4:]), None)
            if meta:
                return meta["url"]
        elif item_id.startswith("srv:"):
            srv = self.find(item_id[4:])
            if srv and srv.link:
                return srv.link
        elif item_id.startswith("friend:"):
            friend = self._vps_friend(item_id[7:])
            if friend and friend.get("links"):
                return friend["links"][0]
        elif item_id == "wifi":
            ssid, password = self._hotspot_credentials()
            return hotspot.wifi_qr_text(ssid, password)
        elif item_id == "tg_lan":
            lan = netutil.lan_ip() if self.settings.get("allow_lan") else ""
            if not lan:
                raise RuntimeError("Сначала включи «Доступ из домашней сети» в «Данных для подключения».")
            s = self.settings
            link = f"tg://socks?server={lan}&port={s['lan_socks_port']}"
            if s.get("lan_auth", True) and s.get("lan_pass"):
                link += f"&user={quote(s.get('lan_user') or 'pult')}&pass={quote(s['lan_pass'])}"
            return link
        raise RuntimeError("Нечего показать: подписка или сервер не найдены.")

    # ---------- белые списки ----------

    WL_NAME = re.compile(r"бел\w*\s*спис|white\s*-?\s*list|\bБС\b|\bWL\b", re.I)

    def is_wl_server(self, srv: Server) -> bool:
        """Сервер для белых списков: так назван в подписке или уже работал, когда они были включены."""
        return bool(self.WL_NAME.search(srv.name or "") or (srv.result or {}).get("whitelist"))

    def _check_whitelist(self) -> bool:
        if not self.settings.get("whitelist_auto", True):
            return False
        state = services.whitelist_probe(self._direct_http())
        was = self.whitelist_mode
        self.whitelist_mode = state == "whitelist"
        if self.whitelist_mode and not was:
            self.log("Похоже, включены белые списки: открываются только разрешённые сайты. "
                     "Переключаюсь на сервер, который их обходит.")
            self.problem("whitelist", "Включены белые списки", "Мобильный интернет пускает только на разрешённые сайты.",
                         where="Интернет", fix="Программа сама работает через подходящий сервер. Делать ничего не нужно.")
        elif was and not self.whitelist_mode:
            self.log("Белые списки отключились — интернет снова открыт полностью.")
            self.resolve("whitelist")
        self.notify("status")
        return self.whitelist_mode

    def _whitelist_watch(self) -> None:
        """Пока включены белые списки, раз в 5 минут смотрим, не отключились ли они; тогда возвращаемся к лучшему."""
        try:
            if self._check_whitelist() or not self.settings.get("autopilot") or self.is_busy():
                return
            self.run_task("Автопилот: возвращаюсь к лучшему серверу", self._back_to_best)
        except Exception as exc:
            self.log(f"Проверка белых списков: {exc}")

    def _back_to_best(self) -> None:
        if self.servers and self.test_all():
            best = self.best()
            if best and self.connected and (not self.current or best.key != self.current.key) and self._switch_to(best):
                self.log(f"Автопилот: переключился на {best.name}.")

    def failover(self, reason: str) -> None:
        """Текущий сервер перестал работать: лестница способов (ladder.py) — пока не пойдут данные.
        Ничего не помогло — честно показать, что работает напрямую, и попробовать снова позже (без петли)."""
        self.log(f"Автопилот: {reason}. Ищу рабочий способ.")
        current_key = self.current.key if self.current else ""
        wl = self._check_whitelist()
        if self.current:
            self.current.result = dict(self.current.result or {}, ok=False, status="перестал отвечать",
                                       error=reason, tested_at=time.time())
            self._on_result(self.current)
        if wl:  # шаг 9: при белых списках обычные серверы всё равно недоступны — сразу подходящие
            backups = [s for s in tester.ranked(self.pool(), key=self._rank_key())
                       if s.key != current_key and self.is_wl_server(s)]
            backups += [s for s in self.servers if self.is_wl_server(s) and s.supported and s.key != current_key
                        and s not in backups]
            for srv in backups[:4]:
                self.check_stop()
                if self._switch_to(srv):
                    self.log(f"Автопилот: переключился на {srv.name}.")
                    self._ladder_success(srv, "белые списки")
                    return
        if self.ladder(reason):
            return
        # всё ещё шаг 6: проверяем все серверы заново (с маскировкой и другими отпечатками) и берём лучший
        self.check_stop()
        self.ladder_step = "проверка всех серверов"
        if self.servers and self.test_all([s for s in self.servers if s.key != current_key]):
            best = self.best()
            if best and self._switch_to(best):
                self.log(f"Автопилот: переключился на {best.name}.")
                self._ladder_success(best, "другой сервер")
                return
        # серверы могли забанить — обновляем подписки и пробуем снова
        if self.settings["subscriptions"]:
            self.log("Автопилот: запасные серверы не отвечают — обновляю подписки.")
            self.ladder_step = "обновление подписок"
            try:
                self.update_subscription()
            except Cancelled:
                raise
            except Exception as exc:
                self.log(f"Автопилот: подписка не обновилась — {exc}")
            if self.servers and self.test_all():
                best = self.best()
                if best and self._switch_to(best):
                    self.log(f"Автопилот: переключился на {best.name}.")
                    self._ladder_success(best, "другой сервер")
                    return
        self._nothing_works(reason)

    def _switch_to(self, srv: Server) -> bool:
        """Переключение на другой сервер с проверкой, что через него всё работает."""
        try:
            if not (self.connected and self._hot_swap(srv)):
                self.connect(srv)
        except Exception as exc:
            self.log(f"Не удалось подключиться: {exc}")
            return False
        r = netutil.http_ping(self.settings["ping_host"], self.settings["ping_path"], self.ports.get("health"),
                              rounds=2, timeout=6)
        if r["ok"]:
            d = self._data_ok()  # пинг прошёл — а идут ли данные? («подключено, но пусто»)
            if not d["ok"]:
                self.log(f"«{srv.name}»: пинг есть, а данные не идут ({d['error']}).")
                srv.result = dict(srv.result or {}, ok=False, status="нет данных", error=d["error"],
                                  tested_at=time.time())
                self._on_result(srv)
                return False
            self.live["ping"] = r["ping_ms"]
            self._ping_failures = 0
            self.notify("live")
            return True
        srv.result = dict(srv.result or {}, ok=False, status="не отвечает", error=r["error"], tested_at=time.time())
        self._on_result(srv)
        return False

    def _hot_swap(self, srv: Server) -> bool:
        """Замена сервера на лету через API ядра — без перезапуска, соединения напрямую не рвутся.
        Если не получилось, вызывающий просто переподключится обычным способом."""
        if not self._hotswap_ok or not self.current or not srv.supported:
            return False
        if self.paths.exe_for(srv) != self.proc.exe or not self.proc.alive():
            return False  # нужно другое ядро — только перезапуск
        if "singbox" in (srv.engine, self.current.engine) or srv.engine == "awg":
            return False  # серверу через мост sing-box нужен свой вход в мосте — только перезапуск
        pinned = {r.get("server") for r in (self.settings.get("routes") or {}).values() if r.get("via") == "server"}
        if pinned & {self.current.key, srv.key}:
            return False  # к старому или новому серверу привязан свой маршрут — правила нужно пересобрать
        ver = self._version_for(self.proc.exe)
        old_tags = list(self._proxy_tags) or [o["tag"] for o in xray.tagged_outbounds(self.current, "proxy")]
        tmp = os.path.join(self.paths.data_dir, "hotswap.json")
        with open(tmp, "w", encoding="utf-8") as f:
            obs = xray.proxy_outbounds(srv, "proxy", self._use_mask(srv), ver, self.tun_bind)
            json.dump({"outbounds": obs}, f, ensure_ascii=False)
        removed = xray.api_command(self.paths, self.ports["api"], ["rmo", *old_tags], exe=self.proc.exe)
        added = removed and xray.api_command(self.paths, self.ports["api"], ["ado", tmp], exe=self.proc.exe)
        if not added:
            self._hotswap_ok = False  # эта версия ядра не умеет — дальше переподключаемся обычным способом
            return False
        self._proxy_tags = [o["tag"] for o in obs]
        with self._conn_lock:
            self.current = srv
            self.settings["last_server_key"] = srv.key
        self.resolve("server_down", "no_working")
        self.log(f"Подключено: {srv.name}. Режим: {routing.MODES.get(self.settings.get('mode'), '')}.")
        self.notify("status")
        threading.Thread(target=self._refresh_exit, daemon=True).start()
        return True

    def _standby_check(self) -> None:
        """Тихо проверяет пару запасных серверов, чтобы при сбое переключиться мгновенно."""
        if self.is_busy() or not self._busy.acquire(blocking=False):
            return
        try:
            current_key = self.current.key if self.current else ""
            backups = [s for s in tester.ranked(self.pool(), key=self._rank_key()) if s.key != current_key][:3]
            if backups:
                tester.test_servers(self.paths, backups, self.settings["ping_host"], self.settings["ping_path"],
                                    self._on_result, self.stop_event, lambda *_: None)
        except Exception:
            pass
        finally:
            self._busy.release()

    def _monitor_loop(self) -> None:
        tick = 0
        while not self._closing:
            time.sleep(1)
            tick += 1
            try:
                if self.connected:
                    self._tail_access_log()
                    # скорость в окне — раз в 2 секунды; окно закрыто — раз в 10 (каждый опрос — запуск xray.exe)
                    if tick % (2 if self.ui_clients else 10) == 0:
                        self._poll_stats()
                    if tick % 5 == 0:
                        self._health_check()
                    if tick % 300 == 0:
                        self._refresh_exit()
                    if tick % 3600 == 30:
                        self._sub_alerts()
                    if tick % 30 == 0:
                        self._check_system_proxy()
                    if self.settings.get("autopilot") and time.time() - self._standby_at > 600:
                        self._standby_at = time.time()
                        threading.Thread(target=self._standby_check, daemon=True).start()
                    if not self.proc.alive() and self.connected:
                        self.log("Ядро Xray неожиданно остановилось.")
                        self.problem("core_crash", "Ядро Xray неожиданно остановилось",
                                     "\n".join(list(self.proc.lines)[-3:]), where="Подключение",
                                     fix="Программа переподключится сама. Если повторяется — обнови ядро.")
                        if self.current and not self.conn_busy():
                            self.run_task("Переподключение", self._recover, self.current, lane="conn")
                    elif self.tun_active in ("singbox", "tun2proxy") and self.connected and not self.tun_proc.alive():
                        err = self.tun_proc.error()
                        self.log(f"Режим TUN неожиданно остановился: {err or 'без подробностей'}.")
                        self._tun_sig = None
                        if self.current and not self.is_busy():
                            self.run_task("Переподключение", self.connect, self.current)
                elif self.filter_on:
                    self._tail_access_log()
                    if tick % 30 == 0:
                        self._check_system_proxy()
                    if not self.proc.alive() and not self.is_busy():
                        self.filter_on = False
                        self.log("Ядро Xray неожиданно остановилось — снова включаю блокировку рекламы.")
                        self.notify("status")
                if self.awg_active and tick % 5 == 2:
                    self.awg_watch()
                self._ads_watch()
                self._vpn_timer()
                if tick % 15 == 3:
                    self._net_watch()
                if tick % 3600 == 90:
                    threading.Thread(target=self._clock_check, daemon=True).start()
                if tick % 21600 == 240 and self.settings.get("cert_watch", True):
                    threading.Thread(target=self._cert_watch, daemon=True).start()
                if tick % 300 == 60 and self.whitelist_mode:
                    threading.Thread(target=self._whitelist_watch, daemon=True).start()
                if tick % 300 == 150 and self.dpi_mode and not self._dpi_watching:
                    threading.Thread(target=self._dpi_watch, daemon=True).start()
                if tick % 60 == 0:
                    self._auto_update_check()
                if tick % 10800 == 7200 and self.connected and self.settings.get("multi_enabled", True) \
                        and not self.is_busy():
                    self.run_task("Мультисервер: проверяю сервисы", self.check_services)
                if tick % 3600 == 5:
                    self._check_files()
            except Exception as exc:
                self.log(f"Монитор: {exc}")
                if errorlog.is_bug(exc):
                    self.errors.record_exc(exc, "монитор")

    def _ads_watch(self) -> None:
        """Реклама без VPN должна работать, когда VPN выключен; пауза заканчивается сама."""
        paused = self._ads_paused()
        if self._ads_paused_state is None:
            self._ads_paused_state = paused
        elif paused != self._ads_paused_state and not self.is_busy():
            self._ads_paused_state = paused
            if not paused:
                self.log("Пауза закончилась — блокировка рекламы снова работает.")
            self.run_task("Применяю блокировку рекламы", self.apply_ads)
            return
        if self.kill_on and time.time() - self._kill_at > 20 and not self.conn_busy():
            self._kill_at = time.time()
            self.run_task("Переподключение", self._kill_retry, lane="conn")
            return
        if not self.connected and not self.filter_on and not self.kill_on and self._filter_wanted() and not self.is_busy() \
                and time.time() - self._filter_fail_at > 120:
            self.run_task("Включаю блокировку рекламы", self._filter_auto)

    def _filter_auto(self) -> None:
        try:
            self.start_filter()
        except Cancelled:
            raise
        except Exception as exc:
            self._filter_fail_at = time.time()
            self.log(f"Блокировка рекламы без VPN не включилась: {exc}")

    def _check_system_proxy(self) -> None:
        """Другая программа могла забрать системный прокси — тогда браузеры пойдут мимо программы."""
        if not self.settings.get("system_proxy") or not self.settings.get("proxy_backup_port") or self.tun_active:
            return
        if sysproxy.is_ours(self.ports.get("http", 0)):
            self.resolve("proxy_hijack")
        elif sysproxy.IS_WINDOWS:
            self.problem("proxy_hijack", "Системный прокси Windows перехватила другая программа",
                         "Браузеры и Telegram сейчас идут мимо программы.", where="Параметры Windows → Прокси",
                         fix="Закрой другой VPN-клиент и переподключись в программе.")

    def _check_files(self) -> None:
        age = self.paths.geo_age_days()
        if age is not None and age > 30:
            self.problem("geo_old", "Списки заблокированных сайтов устарели", f"{int(age)} дн.",
                         where="Обновления", fix="Нажми «Обновить списки».")
        if not self.paths.xray_exists():
            if self.settings.get("xray_seen"):
                # было и пропало само — почти всегда это антивирус (карантин)
                self.problem("xray_missing", "Ядро Xray пропало — похоже, его удалил антивирус", where="Обновления",
                             fix="Добавь папку программы в исключения антивируса (или верни файл из карантина) "
                                 "и нажми «Обновить ядро».", level="error")
            else:
                self.problem("xray_missing", "Ядро Xray не скачано", where="Обновления",
                             fix="Нажми «Обновить ядро» или «Автонастройка».")
        else:
            if not self.settings.get("xray_seen"):
                self.settings["xray_seen"] = True
            self.resolve("xray_missing")

    def _poll_stats(self) -> None:
        try:
            stats = xray.query_stats(self.paths, self.ports["api"], exe=self.proc.exe)
        except Exception:
            return
        now = time.monotonic()
        prev = self._stats_prev
        self._stats_prev = (now, stats)
        if not prev:
            return
        dt = max(now - prev[0], 0.1)
        not_vpn = ("direct", "block", "adblock", "api", "dns-out", "byedpi")

        def delta(tags, way):
            return sum(max(stats.get(t, {}).get(way, 0) - prev[1].get(t, {}).get(way, 0), 0) for t in tags)
        vpn_tags = [t for t in stats if t not in not_vpn]  # основной, запасной, свои серверы и прокси
        moved = {}
        for key, tags in (("proxy", vpn_tags), ("direct", ["direct"])):
            down, up = delta(tags, "downlink"), delta(tags, "uplink")
            self.live[f"{key}_down"] = down / dt
            self.live[f"{key}_up"] = up / dt
            moved[key] = down + up
        self.live["main_down"] = delta(["proxy"], "downlink") / dt  # только основной сервер (без запасного)
        if self.connected:
            self._data_watch(delta(vpn_tags, "uplink"), delta(vpn_tags, "downlink"), now)
        self._count_traffic(moved.get("proxy", 0), moved.get("direct", 0))
        self.notify("live")

    def _count_traffic(self, vpn: int, direct: int) -> None:
        """Сколько прошло через VPN и напрямую — по дням (для «Сегодня» и «За месяц»)."""
        if vpn <= 0 and direct <= 0:
            return
        days = self.settings.setdefault("traffic_days", {})
        day = days.setdefault(time.strftime("%Y-%m-%d"), {"vpn": 0, "direct": 0})
        day["vpn"] += int(vpn)
        day["direct"] += int(direct)
        if len(days) > 62:
            for k in sorted(days)[:-62]:
                days.pop(k, None)
        self._traffic_dirty += 1
        if self._traffic_dirty >= 60:  # раз в пару минут, а не при каждом опросе
            self._traffic_dirty = 0
            self.save()

    def traffic_totals(self) -> dict:
        days = self.settings.get("traffic_days") or {}
        today = days.get(time.strftime("%Y-%m-%d"), {"vpn": 0, "direct": 0})
        month = time.strftime("%Y-%m")
        m = {"vpn": 0, "direct": 0}
        for k, v in days.items():
            if k.startswith(month):
                m["vpn"] += v.get("vpn", 0)
                m["direct"] += v.get("direct", 0)
        return {"today": today, "month": m}

    BUSY_TRAFFIC = 300 * 1024  # байт/с через VPN: при такой нагрузке медленный ответ — из-за самого человека

    def _vpn_busy(self) -> bool:
        """Через VPN сейчас идёт заметный трафик (видео, загрузка)."""
        return (self.live.get("proxy_down") or 0) + (self.live.get("proxy_up") or 0) > self.BUSY_TRAFFIC

    def _health_check(self) -> None:
        r = netutil.http_ping(self.settings["ping_host"], self.settings["ping_path"], self.ports.get("health"),
                              rounds=3, timeout=6)
        busy = self._vpn_busy()
        if not r["ok"] and (self.live.get("main_down") or 0) > 50 * 1024:
            # данные через сервер идут — значит, он жив: проверка просто не пробилась сквозь загрузку
            r = dict(r, ok=True, ping_ms=None, delay_ms=None)
        if self.current and time.time() - self._hist_at > 600:  # в историю качества — раз в 10 минут
            self._hist_at = time.time()
            self._note_quality(self.current.key, bool(r["ok"]))
        if r["ok"]:
            self._ping_failures = 0
            if r["ping_ms"] is not None:
                self.live["ping"] = r["ping_ms"]
            if self.current and not self._way_saving and not self._way_saved and time.time() - self._remember_at > 300 \
                    and self.settings.get("net_memory", True) and not self.conn_busy():
                self._way_saving = True  # запомнить сервер и способ для этой сети (если данные идут), не чаще раза в 5 мин
                self._remember_at = time.time()
                threading.Thread(target=self._remember_current, daemon=True).start()
            # медленно под нагрузкой — не повод менять сервер: смена оборвала бы видео и загрузки
            self._slow_count = self._slow_count + 1 if (r["delay_ms"] or 0) > 3000 and not busy else 0
            self.resolve("server_down")
        else:
            self._ping_failures += 1
            self.live["ping"] = None
            if self._ping_failures >= 2:
                self.problem("server_down", "Сервер не отвечает", r["error"],
                             where=self.current.name if self.current else "",
                             fix="Автопилот переключит на другой сервер. Если он выключен — выбери сервер вручную.")
        self.notify("live")
        need = self._ping_failures >= 2 or self._slow_count >= 3
        if need and self.settings.get("autopilot") and not self.conn_busy() and time.time() >= self._ladder_next:
            # в очереди подключения: долгая фоновая задача (скачивание, проверка) не задерживает переход
            reason = "сервер перестал отвечать" if self._ping_failures >= 2 else "сервер стал очень медленным"
            self._ping_failures = 0
            self._slow_count = 0
            self.run_task("Автопилот: поиск рабочего сервера", self.failover, reason, lane="conn")

    # ---------- умные уведомления ----------

    def tell(self, text: str) -> None:
        """Короткое сообщение о том, что программа сделала сама: в окне — всплывающим, в фоне — у значка в трее."""
        if not self.settings.get("smart_notices", True):
            return
        self.notify("info", text=text)
        self.tray_queue.append(("VEDOMYJ VPN", i18n.tr(text) if self.settings.get("lang") == "en" else text))

    # ---------- VPN на время ----------

    def connect_for(self, minutes: int) -> None:
        """Включить VPN на время: через minutes минут программа сама его выключит."""
        minutes = max(5, min(int(minutes), 24 * 60))
        if not self.connected:
            srv = self.best() or self.find(self.settings.get("last_server_key", ""))
            if not srv:
                raise RuntimeError("Сначала добавь подписку или нажми «Автонастройка».")
            self.connect(srv)
        self.vpn_until = time.time() + minutes * 60
        self.log(f"VPN включён на {minutes} мин — потом выключится сам.")
        self.notify("status")

    def _vpn_timer(self) -> None:
        if self.vpn_until and time.time() >= self.vpn_until:
            self.vpn_until = 0.0
            if self.connected and not self.conn_busy():
                self.log("Время VPN вышло — выключаю.")
                self.tell("Время VPN вышло — VPN выключен.")
                self.run_task("Отключаюсь", self.disconnect, lane="conn")

    # ---------- обновление программы ----------

    def app_update_check(self, auto: bool = False) -> dict:
        """Есть ли новая версия программы (подписанный файл выпуска). auto — само скачать и подготовить."""
        s = self.settings
        if not update.configured():
            raise RuntimeError("Автообновление появится, когда у программы будет свой репозиторий на GitHub.")
        self.progress("Проверяю обновление программы")
        manifest = self._fetch_any(update.fetch_manifest, "Обновление программы")
        s["app_update_checked"] = time.time()
        ver = str(manifest.get("version", ""))
        info = {"version": ver, "notes": str(manifest.get("notes", ""))[:2000], "staged": False}
        if not update.newer(ver, APP_VERSION):
            s["app_update_info"] = {}
            self.save()
            self.log(f"Обновлений программы нет: {APP_VERSION} — последняя версия.")
            self.notify("settings")
            return {"version": APP_VERSION, "newer": False}
        self.log(f"Вышла новая версия программы: {ver}.")
        if auto or s.get("app_update", True):
            self.check_stop()
            self.progress(f"Скачиваю обновление {ver}")
            self._fetch_any(lambda p: update.stage(manifest, self.paths.data_dir, p), "Обновление программы")
            info["staged"] = True
            self.log(f"Обновление {ver} скачано и проверено — установится при следующем запуске программы.")
            self.tray_queue.append(("VEDOMYJ VPN", i18n.tr(f"Обновление {ver} установится при следующем запуске.")
                                    if s.get("lang") == "en" else f"Обновление {ver} установится при следующем запуске."))
        s["app_update_info"] = info
        self.save()
        self.notify("settings")
        return dict(info, newer=True)

    def _app_update_auto(self) -> None:
        try:
            self.app_update_check(auto=True)
        except Cancelled:
            raise
        except Exception as exc:
            self.log(f"Автообновление программы: {exc}")

    # ---------- проверка утечек ----------

    def leak_test(self) -> dict:
        """Видят ли сайты настоящий IP, через кого идёт DNS, не уходят ли WebRTC/UDP и IPv6 мимо VPN.
        Адреса показываются только в окне программы — в журнал и отчёты они не пишутся."""
        if not self.connected:
            raise RuntimeError("Сначала подключись к VPN — проверять нечего.")
        items: list[dict] = []

        def add(state: str, title: str, detail: str = "", fix: str = "") -> None:
            items.append({"state": state, "title": i18n.tr(title), "detail": i18n.tr(detail), "fix": i18n.tr(fix)})
        tun_on = bool(self.tun_active)
        self.progress("Проверяю утечки: IP")
        try:
            vpn = leaks.ip_info(self.ports["health"])
        except Exception as exc:
            vpn = {"ip": "", "isp": "", "country": ""}
            add("error", "Через VPN не удалось узнать адрес", netutil.human_error(exc))
        self.check_stop()
        try:
            real = leaks.ip_info(self._direct_http())
        except Exception:
            real = {"ip": "", "isp": "", "country": ""}
        if vpn["ip"]:
            if real["ip"] and vpn["ip"] == real["ip"]:
                add("error", "VPN не меняет адрес: сайты видят твой настоящий IP",
                    f"{vpn['ip']} ({vpn['country']})", "Выбери другой сервер — этот работает неправильно.")
            else:
                add("ok", "Сайты через VPN видят адрес сервера, а не твой", f"{vpn['ip']} ({vpn['country']}, {vpn['isp']})")
        if self.settings.get("mode", "vpn") == "smart" and not self.net_profile.get("mode"):
            add("info", "Обычные сайты идут напрямую и видят настоящий адрес — так устроен экономный режим",
                "Через VPN идут заблокированные и закрытые для России сайты.",
                "Нужно, чтобы через VPN шло всё, — выбери режим «Всё через VPN».")
        elif self.settings.get("ru_direct", True) and not self.net_profile.get("mode"):
            add("info", "Российские сайты идут напрямую и видят настоящий адрес",
                "Так банки, Госуслуги и магазины открываются быстрее и не просят капчу.",
                "Нужно через VPN совсем всё — выключи «Российские сайты без VPN» в настройках.")
        self.check_stop()
        self.progress("Проверяю утечки: DNS")
        if tun_on:
            try:
                d = leaks.dns_info(None)
                if real["isp"] and leaks.same_isp(real["isp"], d["geo"]):
                    add("error", "Запросы DNS идут через провайдера", d["geo"],
                        "Включи «Шифрование DNS» и «Защиту от утечек».")
                else:
                    add("ok", "DNS не идёт через провайдера", d["geo"])
            except Exception as exc:
                add("info", "DNS проверить не удалось", netutil.human_error(exc))
        else:
            add("ok", "DNS: браузеры отдают адреса сайтов программе",
                "Провайдер не видит, какие сайты открываются через VPN.")
        self.check_stop()
        self.progress("Проверяю утечки: WebRTC")
        mapped = leaks.stun_mapped()
        if not tun_on:
            if mapped and real["ip"] and mapped == real["ip"]:
                add("warn", "WebRTC в браузере может показать сайтам настоящий адрес",
                    "В режиме системного прокси звонки в браузере и WebRTC идут мимо программы.",
                    "Включи режим TUN или поставь в браузер расширение, которое отключает WebRTC.")
            else:
                add("ok", "WebRTC не показывает настоящий адрес")
        elif mapped and real["ip"] and mapped == real["ip"]:
            add("error", "Звонки и WebRTC идут мимо VPN", "", "Включи «Защиту от утечек» в «Функциях».")
        else:
            add("ok", "Звонки и WebRTC идут через VPN" if mapped else "WebRTC не показывает настоящий адрес")
        self.check_stop()
        self.progress("Проверяю утечки: IPv6")
        v6 = leaks.ipv6_address()
        if v6 and tun_on and not self.settings.get("leak_protection"):
            add("error", "IPv6 идёт мимо VPN", "", "Включи «Защиту от утечек» в «Функциях».")
        elif v6 and not tun_on:
            add("info", "IPv6 есть, но через системный прокси он не утекает", "")
        else:
            add("ok", "IPv6 не утекает")
        bad = sum(1 for x in items if x["state"] == "error")
        warn = sum(1 for x in items if x["state"] == "warn")
        self.log(f"Проверка утечек: проблем {bad}, предупреждений {warn}.")
        result = {"items": items, "errors": bad, "warnings": warn, "at": time.time()}
        self.last_leaks = result
        self.notify("leaks", result=result)
        return result

    # ---------- профили сетей ----------

    _net_runner = None  # подмена в самопроверке

    def _net_watch(self) -> None:
        """Сменилась сеть: в чужой (открытый Wi-Fi или отмеченный чужим) — VPN сам, всё через VPN, kill switch."""
        s = self.settings
        net = netprofile.current(self._net_runner)
        sig = (net.get("kind"), net.get("ssid"), net.get("open"), bool(s.get("net_profiles", True)),
               tuple(s.get("net_trusted") or []), tuple(s.get("net_untrusted") or []))
        if sig == self._net_sig and not self.net_profile.get("captive"):
            return
        first = self._net_sig is None
        kind = netprofile.classify(net, s.get("net_trusted") or [], s.get("net_untrusted") or [])
        public = kind == "public" and s.get("net_profiles", True)
        name = net.get("ssid") or ("проводная сеть" if net.get("kind") == "wired" else "")
        if public and netutil.captive_portal():
            # сеть просит войти через свою страницу: VPN и kill switch её закрыли бы — ждём входа
            if not self.net_profile.get("captive") or sig != self._net_sig:
                self.log(f"Сеть «{name}» просит войти (страница входа). Открой браузер и войди — "
                         "после этого VPN включится сам.")
                self.tray_queue.append(("VEDOMYJ VPN", i18n.tr(f"Сеть «{name}» просит войти: открой браузер.")
                                        if s.get("lang") == "en" else f"Сеть «{name}» просит войти: открой браузер."))
            self._net_sig = sig
            self.net_profile = dict(net, profile=kind, kill=False, mode="", captive=True)
            self.notify("status")
            return
        if sig == self._net_sig and self.net_profile.get("captive"):
            self.log(f"Вход в сеть «{name}» выполнен.")
        if not first and sig[:3] != (self._net_sig or (None, None, None))[:3]:
            self._net_cache = None  # другая сеть — у неё может быть другой провайдер
            self._way_saved = ""
            net_moved = True
        else:
            net_moved = False
        self._net_sig = sig
        if self.settings.get("cert_watch", True):  # новая сеть — проверим, не перехватывают ли в ней HTTPS
            threading.Thread(target=self._cert_watch, daemon=True).start()
        old_mode = self.net_profile.get("mode", "")
        self.net_profile = dict(net, profile=kind, kill=public, mode="vpn" if public else "")
        if public:
            if net.get("open"):
                self.log(f"Сеть «{name}» — чужая (открытая, без пароля): VPN включается сам, весь трафик — через VPN, "
                         "kill switch включён.")
            else:
                self.log(f"Сеть «{name}» — чужая: VPN включается сам, весь трафик — через VPN, kill switch включён.")
            self.tray_queue.append(("VEDOMYJ VPN", i18n.tr(f"Чужая сеть «{name}»: весь трафик — через VPN.")
                                    if s.get("lang") == "en" else f"Чужая сеть «{name}»: весь трафик — через VPN."))
        elif not first and name:
            self.log(f"Сеть «{name}» — своя: обычные настройки.")
        self.notify("status")
        if self.conn_busy():
            return
        if public and not self.connected and not self.kill_on and self.servers:
            srv = self.best() or self.find(s.get("last_server_key", ""))
            if srv:
                self.run_task("Подключаюсь", self.connect, srv, lane="conn")
        elif self.connected and old_mode != self.net_profile["mode"]:
            self.run_task("Применяю настройки", self.reconnect, lane="conn")
        elif net_moved:
            self._net_changed()

    # ---------- проверка сертификатов (подмена HTTPS) ----------

    def cert_check(self, quick: bool = False) -> dict:
        """Стоит ли в системе сертификат Минцифры и не подменяют ли сертификаты сайтов — напрямую и через VPN.
        quick — две контрольные площадки вместо четырёх (фоновая проверка)."""
        if not quick:
            self.progress("Проверяю сертификаты")
        vpn_port = self.ports.get("health") if self.connected else None
        res = certcheck.check(vpn_port, hosts=certcheck.PROBE_HOSTS[:2] if quick else None)
        res["time"] = time.time()
        res["acked"] = sorted(self.settings.get("cert_root_ack") or []) == sorted(res["russian_root"])
        self.cert_result = res
        if res["mitm"]:
            first = next(i for i in res["items"] if i["state"] in ("error", "warn"))
            self.problem("cert_mitm", "В этой сети подменяют сертификаты сайтов", first["title"], where="Защита",
                         fix="Включи «Всё через VPN» и kill switch. Пароли вводи только через VPN.", level="error")
        else:
            self.resolve("cert_mitm")
        if res["vpn_mitm"]:
            self.problem("cert_vpn", "Сервер VPN подменяет сертификаты сайтов", self.current.name if self.current else "",
                         where="Защита", fix="Смени сервер и не вводи пароли, пока не сменишь.", level="error")
        else:
            self.resolve("cert_vpn")
        if res["russian_root"] and not res["acked"]:
            self.problem("cert_root", "В системе стоит сертификат Минцифры", ", ".join(res["russian_root"]), where="Защита",
                         fix="Им можно подписать любой сайт. Подробнее и кнопка «Понятно» — «Настройки → Проверка сертификатов».")
        else:
            self.resolve("cert_root")
        if not quick or res["errors"] or res["warnings"]:
            self.log(f"Проверка сертификатов: ошибок {res['errors']}, предупреждений {res['warnings']}.")
        view = self.certs_view()
        self.notify("certs", result=view)
        return view

    def certs_view(self) -> dict | None:
        """Итог проверки сертификатов для окна — на языке, который выбран сейчас (хранится по-русски)."""
        res = getattr(self, "cert_result", None)
        if not res:
            return None
        return dict(res, items=[dict(i, title=i18n.tr(i["title"]), detail=i18n.tr(i["detail"]), fix=i18n.tr(i["fix"]))
                                for i in res["items"]])

    def cert_ack(self) -> None:
        """«Понятно, это я поставил» — сертификат Минцифры больше не показывается как проблема (пока не сменится)."""
        roots = list((getattr(self, "cert_result", None) or {}).get("russian_root") or certcheck.russian_roots())
        self.settings["cert_root_ack"] = sorted(roots)
        self.save()
        self.resolve("cert_root")
        if getattr(self, "cert_result", None):
            self.cert_result["acked"] = True
        self.notify("settings")

    def _cert_watch(self) -> None:
        if getattr(self, "_cert_watching", False):
            return
        self._cert_watching = True
        try:
            time.sleep(8)  # дать сети подняться
            self.cert_check(quick=True)
        except Exception as exc:
            if errorlog.is_bug(exc):
                self.errors.record_exc(exc, "проверка сертификатов")
        finally:
            self._cert_watching = False

    CLOCK_MAX_SKEW = 120  # с: VMess отказывает при расхождении больше ~2 минут, сертификаты — при сильном

    def _clock_check(self) -> None:
        """Неточные часы — частая причина «ничего не работает»: VMess и проверка сертификатов зависят от времени."""
        skew = netutil.clock_skew()
        if skew is None:
            return
        if abs(skew) > self.CLOCK_MAX_SKEW:
            mins = max(1, round(abs(skew) / 60))
            title = (f"Часы на компьютере спешат на {mins} мин" if skew > 0
                     else f"Часы на компьютере отстают на {mins} мин")
            self.problem("clock", title, "Серверы VMess и защищённые соединения не работают, если часы сбиты.",
                         where="Часы Windows",
                         fix="Параметры → Время и язык → Дата и время: включи «Установить время автоматически» "
                             "и нажми «Синхронизировать».", level="warn")
        else:
            self.resolve("clock")

    def net_mark(self, kind: str) -> str:
        """Отметить текущую сеть Wi-Fi своей или чужой."""
        ssid = self.net_profile.get("ssid", "")
        if not ssid:
            raise RuntimeError("Сейчас нет подключения к Wi-Fi — отмечать нечего.")
        s = self.settings
        trusted = [x for x in s.get("net_trusted") or [] if x != ssid]
        untrusted = [x for x in s.get("net_untrusted") or [] if x != ssid]
        (trusted if kind == "home" else untrusted).append(ssid)
        s["net_trusted"], s["net_untrusted"] = trusted[-50:], untrusted[-50:]
        self.save()
        self.log(f"Сеть «{ssid}» отмечена как своя." if kind == "home" else f"Сеть «{ssid}» отмечена как чужая.")
        self._net_watch()
        self.notify("settings")
        return ssid

    def _sub_alerts(self) -> None:
        """Подписка скоро закончится или кончается трафик — предупредить заранее (раз в день, значком и у трея)."""
        s = self.settings
        on = s.get("sub_alerts", True)
        now = time.time()
        sent = s.setdefault("sub_alerts_sent", {})
        for meta in s.get("subscriptions") or []:
            sid = meta["id"]
            u = meta.get("usage") or {}
            name = self.sub_name(meta)
            alerts: list[tuple[str, str, str, str]] = []  # (ключ, уровень, заголовок, пояснение)
            exp = u.get("expire")
            if exp:
                days = (float(exp) - now) / 86400
                if days <= 0:
                    alerts.append(("expire", "error", f"Подписка «{name}» закончилась",
                                   "Продли её у провайдера — без неё серверы перестанут работать."))
                elif days <= 3:
                    alerts.append(("expire", "warn", f"Подписка «{name}» закончится через {max(1, round(days))} дн.",
                                   "Продли её у провайдера заранее, чтобы VPN не пропал."))
            total = u.get("total") or 0
            used = (u.get("upload") or 0) + (u.get("download") or 0)
            if total > 0 and used >= total:
                alerts.append(("traffic", "error", f"В подписке «{name}» закончился трафик",
                               "Докупи трафик у провайдера или дождись нового периода."))
            elif total > 0 and used >= total * 0.9:
                alerts.append(("traffic", "warn", f"В подписке «{name}» осталось меньше 10% трафика",
                               f"Израсходовано {subscription.human_bytes(used)} из {subscription.human_bytes(total)}."))
            keys = {k for k, *_ in alerts}
            for kind in ("expire", "traffic"):
                if kind not in keys or not on:
                    self.resolve(f"sub_{kind}:{sid}")
            if not on:
                continue
            for kind, level, title, fix in alerts:
                self.problem(f"sub_{kind}:{sid}", title, "", where="Главная → подписки", fix=fix, level=level)
                mark = f"{sid}:{kind}:{level}"
                if now - float(sent.get(mark, 0)) > 86400:
                    sent[mark] = now
                    en = s.get("lang") == "en"
                    self.tray_queue.append(("VEDOMYJ VPN", i18n.tr(title) if en else title))
                    self.save()

    def _due(self, hours_key: str, last: float) -> bool:
        hours = float(self.settings.get(hours_key) or 0)
        return hours > 0 and time.time() - float(last or 0) >= hours * 3600

    def _auto_update_check(self) -> None:
        """Аккуратное автообновление: по одному делу за раз, только когда программа ничем не занята,
        и без разрыва текущего подключения."""
        if self.is_busy():
            return
        s = self.settings
        if s["subscriptions"] and self._due("auto_update_hours", s.get("last_sub_update")):
            self.run_task("Автообновление серверов", self.update_subscription)
            return
        geo_last = s.get("last_geo_check") or 0
        age = self.paths.geo_age_days()
        if age is not None:
            geo_last = max(float(geo_last), time.time() - age * 86400)
        if self._due("geo_update_hours", geo_last):
            self.run_task("Автообновление списков сайтов", self.update_geo, False)
            return
        if s.get("block_ads") and self._due("ads_update_hours", s.get("ads_updated_at")):
            # без VPN фильтр перезапускается за секунду; с VPN новые списки начнут работать при переподключении
            self.run_task("Автообновление списков рекламы", self.update_adblock, self.filter_on and not self.connected)
            return
        if s.get("app_update", True) and update.configured() and self._due("app_update_hours", s.get("app_update_checked")):
            self.run_task("Автообновление программы", self._app_update_auto)
            return
        if self.paths.xray_exists() and self._due("core_update_hours", s.get("last_core_check")):
            self.run_task("Автообновление ядра", self._auto_update_core)
            return
        if (self.dpi_paths.zapret_installed() or self.dpi_paths.byedpi_installed()) \
                and self._due("dpi_update_hours", s.get("last_dpi_check")):
            self.run_task("Автообновление zapret и ByeDPI", self.update_dpi, True)

    def _install_pending_core(self) -> None:
        """Ставит заранее скачанное новое ядро, пока оно не запущено."""
        try:
            if xray.install_pending_xray(self.paths):
                self.xray_ver = xray.xray_version(self.paths)
                self.log(f"Установлено новое ядро Xray: версия {self.xray_ver or '?'}.")
        except Exception as exc:
            self.log(f"Новое ядро пока не установлено: {exc}")

    def _auto_update_core(self) -> None:
        """Проверяет номер новой версии (маленький запрос). Архив качается, только если версия новее;
        при работающем VPN новое ядро ставится при следующем подключении или запуске."""
        self.settings["last_core_check"] = time.time()
        self.save()
        proxy = self.ports.get("health") if self.connected else None
        self._update_tun_engines(proxy)
        latest = xray.latest_xray_version(proxy)
        if not latest or not self.xray_ver or latest == self.xray_ver:
            return
        self.progress(f"Скачиваю ядро Xray {latest}")
        if self.connected:
            self._fetch_any(lambda p: xray.download_xray(self.paths, proxy_port=p, install=False), "Ядро Xray")
            self.log(f"Скачано ядро Xray {latest} — установится при следующем подключении.")
        else:
            self._fetch_any(lambda p: xray.download_xray(self.paths, proxy_port=p, install=False), "Ядро Xray")
            xray.install_pending_xray(self.paths)
            self.xray_ver = xray.xray_version(self.paths)
            self.log(f"Ядро Xray обновлено: версия {self.xray_ver or '?'}.")
        self._check_files()
        self.notify("status")

    def _tail_access_log(self) -> None:
        try:
            size = os.path.getsize(self.paths.access_log)
        except OSError:
            return
        if size < self._log_pos:
            self._log_pos = 0
        if size > 30 * 1024 * 1024:
            # журнал соединений не должен расти бесконечно
            try:
                open(self.paths.access_log, "w").close()
                self._log_pos = 0
            except OSError:
                pass
            return
        if size == self._log_pos:
            return
        with open(self.paths.access_log, "rb") as f:
            f.seek(self._log_pos)
            data = f.read(min(size - self._log_pos, 2 * 1024 * 1024))
            self._log_pos += len(data)
        changed = False
        for raw in data.decode("utf-8", "replace").splitlines():
            item = xray.parse_access_line(raw)
            if not item:
                continue
            host = item["host"]
            entry = self.connections.get(host)
            if entry is None:
                entry = self.connections[host] = {"host": host, "count": 0, "route": "", "last": "",
                                                  "port": item["port"]}
                self._auto_offer(host, item["outbound"], item["port"])  # новый адрес — автоподбор проверит его
            entry["count"] += 1
            entry["route"] = item["outbound"]
            self._host_log.append((time.time(), host, item["outbound"]))
            if item["outbound"] == adblock.OUTBOUND:
                self._count_ad(host)
                self._ads_site_hit(host)
            entry["last"] = item["time"]
            changed = True
        if len(self.connections) > 2000:
            for host, _ in sorted(self.connections.items(), key=lambda kv: kv[1]["last"])[:500]:
                self.connections.pop(host, None)
        if changed:
            self.notify("connections")

    # ---------- Happ ----------

    def happ_link(self) -> str:
        return happ.profile_link(self.settings)

    # ---------- режим ----------

    def set_mode(self, mode: str) -> None:
        if mode not in routing.MODES:
            raise RuntimeError("Неизвестный режим.")
        self.settings["mode"] = mode
        self.save()
        self.log(f"Режим: {routing.MODES[mode]}.")
        if self.connected:
            self.reconnect()
        else:
            self.notify("status")

    # ---------- состояние для интерфейса ----------

    PROTO_LABELS = {"shadowsocks": "SS", "socks": "SOCKS5", "vless": "VLESS", "vmess": "VMess", "trojan": "Trojan",
                    "hy2": "Hysteria2", "hysteria2": "Hysteria2", "mtproto": "MTProto", "happ": "Happ",
                    "tuic": "TUIC", "anytls": "AnyTLS", "amneziawg": "AmneziaWG"}

    def _busy_kind(self) -> str:
        """Что именно сейчас выполняется — чтобы интерфейс показал «Остановить» на нужной кнопке."""
        t = self.busy_text
        for word, kind in (("Проверяю всё", "health"), ("Проверка программы", "check"), ("Проверяю сайт", "site"), ("Чиню сайт", "repair"), ("Проверяю утечки", "leaks"), ("Проверяю сертификаты", "certs"), ("Проверяю обновление программы", "app_update"),
                           ("Скачиваю обновление", "app_update"), ("Автообновление программы", "app_update"), ("Подбираю путь для", "app_pick"), ("Проверяю прокси", "proxy"), ("списки рекламы", "ads"), ("блокировку рекламы", "ads"), ("Подбираю стратегию", "dpi_pick"), ("Проверяю YouTube", "dpi_check"),
                           ("Проверяю свою стратегию", "dpi_pick"), ("Включаю TUN", "connect"), ("Мультисервер", "services"), ("Включаю раздачу", "hotspot"), ("Открываю окно для входа", "vps"),
                           ("Ставлю", "vps"), ("Создаю ключи", "vps"), ("Записываю настройки сервера", "vps"),
                           ("Включаю ускорение", "vps"), ("Запускаю Xray на сервере", "vps"),
                           ("Выключаю раздачу", "hotspot"),
                           ("Включаю", "dpi"), ("Проверяю серверы", "test"), ("Замеряю скорость", "speed"), ("Проверяю сервисы", "services"),
                           ("Автонастройка", "auto"), ("Автопилот", "auto"), ("Обновляю", "update"),
                           ("Скачиваю", "update"), ("Загружаю подписку", "update"), ("Добавляю подписку", "update"),
                           ("Подключ", "connect"), ("Отключ", "connect"), ("Переподключ", "connect"),
                           ("Применяю", "connect"), ("Меняю", "connect")):
            if t.startswith(word):
                return kind
        return "other"

    @staticmethod
    def status_code(s: Server, r: dict) -> str:
        """Состояние сервера кодом — интерфейс сам подпишет его на нужном языке."""
        if s.stub:
            return "stub"
        if not s.supported:
            return "unsupported"
        if s.engine == "awg":
            return "awg"  # проверяется только включением
        if r.get("testing"):
            return "speed" if "скорост" in r.get("status", "") else "testing"
        if not r:
            return "untested"
        if r.get("ok"):
            return "unstable" if r.get("speed_ok") is False else "ok"
        status = r.get("status", "")
        if "настро" in status:
            return "config_error"
        if "ядр" in status:
            return "core_error"
        if "перестал" in status:
            return "lost"
        return "fail"

    def server_info(self, s: Server, best_key: str = "", game_key: str = "") -> dict:
        cc, clean = countries.detect(s.name)
        r = s.result or {}
        return {
            "code": self.status_code(s, r), "testing": bool(r.get("testing")),
            "key": s.key, "sub": s.sub_id, "name": clean, "cc": cc,
            "protocol": self.PROTO_LABELS.get(s.protocol, s.protocol.upper()),
            "supported": s.supported, "note": i18n.tr(s.note), "has_link": bool(s.link), "endpoint": s.endpoint,
            "mask": bool(r.get("mask")), "wl": self.is_wl_server(s), "fp": r.get("fp") or "",
            "ok": r.get("ok"), "delay": r.get("delay_ms"), "ping": r.get("ping_ms"), "jitter": r.get("jitter_ms"),
            "speed": r.get("speed_mbps"), "status": i18n.tr(r.get("status", "")), "error": i18n.tr(r.get("error", "")),
            "tested": bool(r), "best": s.key == best_key, "game": s.key == game_key,
            "insecure": s.insecure, "stub": s.stub, "kind": links.kind_of(s),
            "current": bool(self.connected and self.current and self.current.key == s.key)
            or bool(self.awg_active and self.awg_active.key == s.key),
        }

    def state(self) -> dict:
        s = self.settings
        best = self.best()
        game = self.best(for_games=True)
        best_key = best.key if best else ""
        game_key = game.key if game and game.key != best_key else ""
        servers = list(self.servers)
        subs = []
        for meta in s["subscriptions"]:
            own = [x for x in servers if x.sub_id == meta["id"]]
            usage = meta.get("usage") or {}
            subs.append({
                "id": meta["id"], "name": self.sub_name(meta), "title": meta.get("title", ""),
                "host": urlsplit(meta["url"]).hostname or "", "usage": usage,
                "usage_text": subscription.usage_text(usage), "last_update": meta.get("last_update", 0),
                "error": i18n.tr(self.sub_errors.get(meta["id"], "")), "count": sum(1 for x in own if not x.stub),
                "notices": [x.name for x in own if x.stub],
                "working": sum(1 for x in own if (x.result or {}).get("ok")),
            })
        manual = [x for x in servers if x.sub_id == "manual"]
        if manual:
            subs.append({"id": "manual", "name": i18n.tr("Мои серверы"), "title": "", "host": "", "usage": {},
                         "usage_text": "", "last_update": 0, "error": "", "count": len(manual), "notices": [],
                         "working": sum(1 for x in manual if (x.result or {}).get("ok"))})
        svc = []
        routes = self.routes_state()
        for item in services.SERVICES:
            route = routing.route_for_host(item["domains"][0], s.get("mode", "smart"), s.get("proxy_list", ""),
                                           s.get("direct_list", ""), s.get("block_list", ""), s.get("ru_direct", True))
            if self.geo_in_use and route == "direct" and not item.get("russian"):
                route = "lists"
            rule = routing.user_rule(item["domains"][0], s)
            own = routes["services"].get(item["name"]) or {}
            svc.append({"name": item["name"], "russian": bool(item.get("russian")), "route": route,
                        "rule": rule, "choice": rule or own.get("value") or "auto", "warn": "" if rule else own.get("warn", ""),
                        "results": self.service_results.get(item["name"], {})})
        return {
            "version": APP_VERSION,
            "connected": self.connected,
            "filter_on": self.filter_on,
            "kill_on": self.kill_on,
            "vpn_until": self.vpn_until,
            "traffic_totals": self.traffic_totals(),
            "app_update": {"configured": update.configured(), "auto": bool(s.get("app_update", True)),
                           "checked": s.get("app_update_checked", 0), "info": s.get("app_update_info") or {},
                           "version": APP_VERSION, "just_updated": self.just_updated},
            "pin": {"set": bool(s.get("pin_hash")), "minutes": int(s.get("pin_lock_minutes") or 0)},
            "secure": {"on": bool(s.get("encrypt_data", True)), "available": secure.available()},
            "leaks": self.last_leaks,
            "certs": self.certs_view(),
            "errors_count": len(self.errors.entries),
            "net": {"kind": self.net_profile.get("kind", ""), "ssid": self.net_profile.get("ssid", ""),
                    "open": bool(self.net_profile.get("open")), "profile": self.net_profile.get("profile", ""),
                    "enabled": bool(s.get("net_profiles", True)),
                    "trusted": list(s.get("net_trusted") or []), "untrusted": list(s.get("net_untrusted") or [])},
            "ads": self.ads_state(),
            "current": self.server_info(self.current, best_key, game_key) if self.current and self.connected else None,
            "busy": i18n.tr(self.busy_text) if self.bg_busy() else "",
            "busy_kind": self._busy_kind() if self.bg_busy() else "",
            "conn_busy": i18n.tr(self.conn_text) if self.conn_busy() else "",
            "auto": self.auto_state(),
            "vpn_suspects": [dict(x, detail=i18n.tr(x["detail"])) for x in self.vpn_suspects],
            "apps": self.apps_state(),
            "hotkey": dict(self.hotkey_state, value=s.get("hotkey", "Ctrl+Alt+V"),
                           enabled=bool(s.get("hotkey_enabled", True))),
            "problems": self.problems_list(),
            "live": dict(self.live),
            "mode": s.get("mode", "smart"), "modes": {k: i18n.tr(v) for k, v in routing.MODES.items()},
            "ru_direct": bool(s.get("ru_direct", True)), "icon": s.get("icon", "monogram"),
            "theme": s.get("theme", "dark"), "sort": s.get("sort", "ping"), "collapsed": s.get("collapsed", []),
            "lang": s.get("lang", "ru"),
            "subs": subs,
            "servers": [self.server_info(x, best_key, game_key) for x in servers],
            "best": best_key,
            "settings": {k: s.get(k) for k in ("user_agent", "ping_host", "ping_path", "socks_port", "http_port",
                                               "system_proxy", "autopilot", "allow_lan", "auto_connect_on_start",
                                               "auto_update_hours", "proxy_list", "direct_list", "block_list",
                                               "game_mode", "autostart", "geo_update_hours", "core_update_hours",
                                               "dpi_update_hours", "leak_protection", "dns_encrypted", "block_ads",
                                               "lan_socks_port", "lan_http_port", "lan_auth", "lan_user", "lan_pass",
                                               "mask_auto", "multi_enabled", "whitelist_auto", "background", "block_quic",
                                               *self.AUTO_FLAGS)},
            "lan_ip": netutil.lan_ip() if s.get("allow_lan") else "",
            "backup": self._backup_info(),
            "updates": {"xray": self.xray_ver, "xray_exists": self.paths.xray_exists(),
                        "geo_age": self.paths.geo_age_days(), "geo_ready": self.paths.geo_ready(),
                        "last_sub_update": s.get("last_sub_update", 0)},
            "geo_in_use": self.geo_in_use,
            "services": svc,
            "routes": {"sites": routes["sites"], "sites_total": routes["sites_total"], "proxies": routes["proxies"]},
            "dpi": self.dpi_state(),
            "tun": self.tun_state(),
            "multi": self.multi_state(),
            "whitelist_mode": self.whitelist_mode,
            "hotspot": self.hotspot_state(),
            "awg": self.awg_state(),
            "engine": self.engine_state(),
            "ladder": {"step": i18n.tr(self.ladder_step) if self.ladder_step else "",
                       "retry_at": self._ladder_next if self._ladder_next > time.time() else 0,
                       "what_works": self.what_works, "way": i18n.tr(ladder.way_text(self.current))
                       if self.current and self.connected else "", **self.net_memory_state(),
                       "data": dict(self.data_last, error=i18n.tr(self.data_last.get("error") or ""))
                       if self.data_last and self.connected and self.current
                       and self.data_last.get("server") == self.current.key else None,
                       "last": dict(self.ladder_last, text=i18n.tr(self.ladder_last["text"])) if self.ladder_last else None,
                       "net_known": bool(self._way_saved)},
        }

    def connections_list(self, limit: int = 500) -> list[dict]:
        items = sorted(list(self.connections.values()), key=lambda x: x["last"], reverse=True)[:limit]
        sites = [k[5:] for k in (self.settings.get("routes") or {}) if k.startswith("site:")]
        return [dict(it, rule=routing.user_rule(it["host"], self.settings)
                     or ("custom" if any(routing.user_rule(it["host"], {"proxy_list": x}) for x in sites) else ""))
                for it in items]
