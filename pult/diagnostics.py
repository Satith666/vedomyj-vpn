"""Проверка программы на этом компьютере: ядро, списки сайтов, порты, системный прокси, интернет, подписки,
серверы, сервисы и самопроверка кода. Результат — список пунктов «ок / предупреждение / ошибка» и текстовый отчёт
без ссылок и ключей (его можно отправить нейросети или разработчику)."""

from __future__ import annotations

import email.utils
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time

from . import APP_VERSION, adblock, i18n, netutil, proxies, routing, services, subscription, sysproxy, tester, xray


def T(ru: str, en: str) -> str:
    return en if i18n.lang() == "en" else ru


class Report:
    def __init__(self):
        self.items: list[dict] = []

    def add(self, level: str, title: str, detail: str = "") -> None:
        self.items.append({"level": level, "title": title, "detail": str(detail)[:400]})

    def ok(self, title, detail=""):
        self.add("ok", title, detail)

    def info(self, title, detail=""):
        """Просто сведения: не ошибка и не повод что-то менять."""
        self.add("info", title, detail)

    def warn(self, title, detail=""):
        self.add("warn", title, detail)

    def error(self, title, detail=""):
        self.add("error", title, detail)


def _minimal_config(port: int) -> dict:
    return {"log": {"loglevel": "error"},
            "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {}}],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}]}


def _geo_config(rule: dict) -> dict:
    cfg = _minimal_config(1080)
    cfg["routing"] = {"rules": [dict(rule, type="field", outboundTag="direct")]}
    return cfg


def run(e, include_selftest: bool = True, stop=None, progress=None, app_running: bool = False) -> dict:
    """e — движок программы (Engine). Ничего не сохраняет и не трогает текущее подключение."""
    r = Report()
    step = progress or (lambda text: None)

    def stopped() -> bool:
        return bool(stop and stop.is_set())

    # --- окружение ---
    step(T("Проверка программы: окружение", "Program check: environment"))
    py = sys.version_info
    (r.ok if py >= (3, 10) else r.warn)(f"Python {py.major}.{py.minor}.{py.micro}",
                                       "" if py >= (3, 10) else T("нужен Python 3.10 или новее", "Python 3.10+ is required"))
    try:
        probe = os.path.join(e.paths.data_dir, ".write_test")
        with open(probe, "w") as f:
            f.write("ok")
        os.remove(probe)
        r.ok(T("Папка программы доступна для записи", "Program folder is writable"))
    except OSError as exc:
        r.error(T("Нельзя записывать в папку программы", "Cannot write to the program folder"), exc)

    # --- ядро ---
    step(T("Проверка программы: ядро Xray", "Program check: Xray core"))
    if not e.paths.xray_exists():
        r.error(T("Ядро Xray не скачано", "Xray core is not downloaded"),
                T("Нажми «Обновить ядро» или «Автонастройка».", "Press “Update core” or “Auto setup”."))
    else:
        version = xray.xray_version(e.paths)
        port = netutil.find_free_ports(1, 42000)[0]
        ok, msg = xray.check_config(e.paths, _minimal_config(port))
        if ok and version:
            r.ok(T(f"Ядро Xray {version} работает", f"Xray core {version} works"))
        else:
            r.error(T("Ядро Xray не запускается", "Xray core does not start"), msg or version)
        if any(s.insecure for s in e.servers):
            if e.paths.legacy_exists():
                r.ok(T("Совместимое ядро для серверов без шифрования есть", "Compatible core for unencrypted servers is present"))
            else:
                r.warn(T("Нет совместимого ядра для серверов без шифрования", "No compatible core for unencrypted servers"),
                       T("Скачается само при первой проверке таких серверов.", "It downloads itself on the first check."))

    # --- списки сайтов ---
    step(T("Проверка программы: списки сайтов", "Program check: site lists"))
    age = e.paths.geo_age_days()
    if age is None:
        r.warn(T("Списки заблокированных сайтов не скачаны", "Blocked-site lists are not downloaded"),
               T("Работает встроенный список. Нажми «Обновить списки».", "The built-in list is used. Press “Update lists”."))
    else:
        (r.ok if age <= 14 else r.warn)(T(f"Списки сайтов обновлены {int(age)} дн. назад", f"Site lists updated {int(age)} days ago"))
        if e.paths.xray_exists():
            missing = []
            for rule in ({"domain": routing.GEO_PROXY_DOMAINS}, {"ip": routing.GEO_PROXY_IPS},
                         {"domain": routing.GEO_INSIDE_ONLY}, {"ip": routing.GEO_RU_IPS}):
                ok, _ = xray.check_config(e.paths, _geo_config(rule))
                if not ok:
                    missing += rule.get("domain", []) + rule.get("ip", [])
            if missing:
                r.warn(T("В списках нет категорий: ", "Lists lack categories: ") + ", ".join(missing),
                       T("Программа обойдётся без них. Обнови списки.", "The program works without them. Update the lists."))
            else:
                r.ok(T("Все категории списков на месте", "All list categories are present"))

    # --- порты и системный прокси ---
    step(T("Проверка программы: порты", "Program check: ports"))
    for key in ("socks_port", "http_port"):
        port = int(e.settings[key])
        if netutil.is_port_free(port):
            r.ok(T(f"Порт {port} свободен", f"Port {port} is free"))
        elif e.core_running or app_running:
            r.ok(T(f"Порт {port} занят самой программой", f"Port {port} is used by VEDOMYJ VPN itself"))
        else:
            r.error(T(f"Порт {port} занят другой программой", f"Port {port} is used by another program"),
                    T("Закрой Happ, v2rayN и другие VPN-клиенты или поменяй порт.", "Close other VPN clients or change the port."))
    if sysproxy.IS_WINDOWS:
        ours = sysproxy.is_ours(int(e.settings["http_port"]))
        if e.core_running and e.settings.get("system_proxy"):
            (r.ok if ours else r.warn)(T("Системный прокси Windows указывает на программу", "Windows system proxy points to VEDOMYJ VPN") if ours
                                       else T("Системный прокси Windows перехватила другая программа",
                                              "Another program took over the Windows system proxy"))
        elif ours and not (e.core_running or app_running):
            r.error(T("Системный прокси остался включённым, хотя программа не подключена",
                      "System proxy is still on while Pult is not connected"),
                    T("Запусти программу — она сама восстановит настройки.", "Start VEDOMYJ VPN — it restores the settings itself."))
        else:
            r.ok(T("Системный прокси в порядке", "System proxy is fine"))

    # --- интернет ---
    step(T("Проверка программы: интернет", "Program check: internet"))
    try:
        socket.getaddrinfo("www.google.com", 443)
        r.ok(T("DNS работает", "DNS works"))
    except OSError as exc:
        r.error(T("DNS не работает", "DNS does not work"), exc)
    ping = netutil.http_ping(e.settings["ping_host"], e.settings["ping_path"], None, rounds=3, timeout=6)
    if ping["ok"]:
        r.ok(T(f"Интернет без VPN: пинг {ping['ping_ms']} мс", f"Internet without VPN: ping {ping['ping_ms']} ms"))
    else:
        r.error(T("Интернет без VPN не отвечает", "Internet without VPN does not respond"), i18n.tr(ping["error"]))
    try:
        status, headers, _ = netutil.http_get("https://www.cloudflare.com/cdn-cgi/trace", timeout=8)
        server_time = email.utils.parsedate_to_datetime(headers.get("date", "")).timestamp() if headers.get("date") else None
        if server_time:
            skew = abs(server_time - time.time())
            (r.ok if skew < 60 else r.warn)(T(f"Часы компьютера точные (расхождение {int(skew)} с)", f"Computer clock is accurate ({int(skew)} s off)")
                                            if skew < 60 else T(f"Часы компьютера спешат или отстают на {int(skew)} с",
                                                                f"Computer clock is off by {int(skew)} s"),
                                            "" if skew < 60 else T("Серверы VMess не работают при неточных часах. Включи синхронизацию времени в Windows.",
                                                                   "VMess servers fail with a wrong clock. Turn on time sync in Windows."))
    except Exception:
        pass
    try:
        status, _, _ = netutil.http_get("https://github.com/XTLS/Xray-core/releases", timeout=10,
                                        proxy_port=e.ports.get("health") if e.connected else None)
        (r.ok if status < 400 else r.warn)(T("GitHub доступен — обновления скачиваются", "GitHub is reachable — updates download"))
    except Exception as exc:
        r.warn(T("GitHub недоступен — обновления могут не скачиваться", "GitHub is unreachable — updates may fail"),
               netutil.human_error(exc))

    # --- подписки ---
    if stopped():
        return finish(r, e)
    step(T("Проверка программы: подписки", "Program check: subscriptions"))
    if not e.settings["subscriptions"]:
        r.warn(T("Подписок нет", "No subscriptions"), T("Добавь подписку на главной.", "Add a subscription on the home screen."))
    for meta in e.settings["subscriptions"]:
        name = e.sub_name(meta)
        try:
            sub = subscription.fetch(meta["url"], meta.get("user_agent") or e.settings.get("user_agent", ""),
                                     proxy_port=e.ports.get("health") if e.connected else None,
                                     own_http_port=e.settings["http_port"], hwid=e.settings.get("hwid", ""), timeout=15)
            good = sum(1 for s in sub.servers if s.supported)
            if good:
                r.ok(T(f"Подписка «{name}»: серверов {good}", f"Subscription “{name}”: {good} servers"))
            else:
                r.warn(T(f"Подписка «{name}»: нет рабочих серверов", f"Subscription “{name}”: no usable servers"),
                       i18n.tr("; ".join(sub.notices + sub.warnings)))
        except Exception as exc:
            r.error(T(f"Подписка «{name}» не загружается", f"Subscription “{name}” does not load"), i18n.tr(str(exc)))

    # --- серверы ---
    if stopped():
        return finish(r, e)
    supported = [s for s in e.servers if s.supported and getattr(s, "engine", "xray") != "awg"]  # AmneziaWG — своим клиентом
    if e.paths.xray_exists() and supported:
        step(T("Проверка программы: серверы", "Program check: servers"))
        normal = [s for s in supported if not s.insecure and getattr(s, "engine", "xray") == "xray"]
        if normal:
            ports = netutil.find_free_ports(min(len(normal), 40), 43000)
            ok, msg = xray.check_config(e.paths, xray.build_test_config(normal[:40], ports))
            (r.ok if ok else r.warn)(T("Настройки серверов принимаются ядром", "Server settings are accepted by the core") if ok
                                     else T("Настройки части серверов не принимаются ядром", "Some server settings are rejected by the core"),
                                     "" if ok else i18n.tr(msg))
        try:
            working = tester.test_servers(e.paths, supported, e.settings["ping_host"], e.settings["ping_path"],
                                          e._on_result, stop, lambda *_: None, ensure_core=e.ensure_legacy)
            best = tester.ranked(e.servers)
            if working:
                r.ok(T(f"Работают серверы: {working} из {len(supported)}", f"Working servers: {working} of {len(supported)}"),
                     T(f"лучший: {best[0].name}, пинг {best[0].result.get('ping_ms')} мс",
                       f"best: {best[0].name}, ping {best[0].result.get('ping_ms')} ms") if best else "")
            else:
                r.error(T("Ни один сервер не отвечает", "No server responds"),
                        T("Проверь интернет и обнови подписку.", "Check your internet and update the subscription."))
        except Exception as exc:
            r.error(T("Проверка серверов не удалась", "Server check failed"), i18n.tr(str(exc)))

    # --- подключение и сервисы ---
    if stopped():
        return finish(r, e)
    if e.connected:
        step(T("Проверка программы: подключение и сервисы", "Program check: connection and services"))
        hp = netutil.http_ping(e.settings["ping_host"], e.settings["ping_path"], e.ports.get("health"), rounds=3, timeout=6)
        (r.ok if hp["ok"] else r.error)(T(f"Через VPN: пинг {hp['ping_ms']} мс", f"Via VPN: ping {hp['ping_ms']} ms") if hp["ok"]
                                        else T("Через VPN нет связи", "No connection via VPN"), "" if hp["ok"] else i18n.tr(hp["error"]))
        res = services.check_all({"direct": None, "vpn": e.ports["health"], "current": e.ports["http"]}, stop_event=stop)
        e.service_results = res
        _report_services(r, res)
    elif app_running and not netutil.is_port_free(int(e.settings["http_port"])):
        # программа уже работает в другом окне — проверяем сервисы через её подключение
        step(T("Проверка программы: сервисы через запущенную программу", "Program check: services via the running program"))
        res = services.check_all({"direct": None, "vpn": False, "current": int(e.settings["http_port"])}, stop_event=stop)
        _report_services(r, res)
    else:
        r.warn(T("Программа не подключена — сервисы через VPN не проверены", "VEDOMYJ VPN is not connected — services via VPN were not checked"),
               T("Подключись и запусти проверку ещё раз.", "Connect and run the check again."))

    # --- режим TUN ---
    if e.settings.get("tun_enabled") and not stopped():
        if getattr(e, "tun_active", ""):
            r.ok(T(f"Режим TUN работает: {e.tun_active}", f"TUN mode works: {e.tun_active}"))
        elif e.connected:
            r.warn(T("Режим TUN не включился — программа работает через системный прокси",
                     "TUN mode did not start — the program works through the system proxy"),
                   getattr(e, "tun_error", "") or T("Нажми «Да», когда Windows спросит разрешение администратора.",
                                                    "Click “Yes” when Windows asks for administrator permission."))

    # --- обход замедлений ---
    if getattr(e, "dpi_supported", False) and not stopped():
        step(T("Проверка программы: zapret и ByeDPI", "Program check: zapret and ByeDPI"))
        st = e.settings
        z_on, b_on = st.get("zapret_enabled"), st.get("byedpi_role") != "off"
        if not z_on and not b_on:
            r.ok(T("Обход замедлений выключен — YouTube и Discord идут через VPN",
                   "Throttling bypass is off — YouTube and Discord go through VPN"))
        for name, on, installed, strategy in (
                ("Zapret", z_on, e.dpi_paths.zapret_installed(), st.get("zapret_strategy")),
                ("ByeDPI", b_on, e.dpi_paths.byedpi_installed(), st.get("byedpi_strategy"))):
            if not on:
                continue
            if not installed or not strategy:
                r.warn(T(f"{name}: стратегия не подобрана", f"{name}: no strategy yet"),
                       T(f"Открой страницу {name} и нажми «Подобрать лучшую стратегию».",
                         f"Open the {name} page and click “Find the best strategy”."))
            else:
                r.ok(T(f"{name}: стратегия {strategy}", f"{name}: strategy {strategy}"))
        mode = e.dpi_mode
        if mode:
            port = e.byedpi.port if mode == "byedpi" else None
            res = e._check_dpi_path(port, light=True)
            okk = e._dpi_ok(res)
            title = "Zapret" if mode == "zapret" else "ByeDPI"
            (r.ok if okk else r.warn)(
                T(f"YouTube и Discord открываются через {title}", f"YouTube and Discord open via {title}") if okk
                else T(f"С {title} YouTube или Discord не открываются", f"YouTube or Discord doesn't open with {title}"),
                "" if okk else T("Автопереход сам попробует другой способ. Можно нажать «Подобрать лучшую стратегию».",
                                 "Auto switch will try another method. You can also click “Find the best strategy”."))

    # --- блокировка рекламы ---
    if not stopped():
        step(T("Проверка программы: блокировка рекламы", "Program check: ad blocking"))
        _check_ads(r, e, app_running)

    # --- свои маршруты и прокси ---
    if not stopped() and ((e.settings.get("routes") or {}) or (e.settings.get("proxies") or [])):
        step(T("Проверка программы: свои маршруты и прокси", "Program check: own routes and proxies"))
        _check_routes(r, e, stop)

    # --- окно программы ---
    if sys.platform == "win32":
        try:
            sys.path.insert(0, e.paths.app_dir)
            from main import browser_candidates  # type: ignore
            found = browser_candidates()
            (r.ok if found else r.warn)(T("Браузер для окна программы найден", "Browser for the program window found") if found
                                        else T("Edge/Chrome не найден — интерфейс откроется во вкладке браузера",
                                               "Edge/Chrome not found — the interface opens in a browser tab"))
        except Exception:
            pass

    # --- самопроверка кода ---
    if include_selftest and not stopped():
        step(T("Проверка программы: самопроверка кода", "Program check: code self-test"))
        r.items.extend(run_selftest(e.paths.app_dir))

    # --- активные проблемы ---
    for p in e.problems_list():
        r.warn(T("Активная проблема: ", "Active problem: ") + p["title"], p.get("detail", ""))
    return finish(r, e)


def _report_services(r, res: dict) -> None:
    bad, outside = services.split_failures(res)
    if bad:
        r.warn(T("Не открываются: ", "Not opening: ") + ", ".join(bad),
               T("На вкладке «Сервисы» нажми «Исправить автоматически».", "Press “Fix automatically” on the Services tab."))
    else:
        r.ok(T(f"Все сервисы открываются ({len(res)})", f"All services open ({len(res)})"))
    if outside:
        r.warn(T("Не отвечают даже без VPN: ", "Not answering even without VPN: ") + ", ".join(outside),
               T("Дело не в программе: сбой сайта или его защита от ботов. Проверь сайт в браузере.",
                 "Not the program's fault: the site is down or blocks bots. Check it in a browser."))


def run_selftest(app_dir: str) -> list[dict]:
    """Запускает pult.selftest отдельным процессом (он подменяет части программы заглушками)."""
    try:
        flags = 0x08000000 if sys.platform == "win32" else 0
        # вывод — строго в UTF-8: в русской Windows по умолчанию cp1251, и символ «→» в названии теста ронял вывод
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
        proc = subprocess.run([sys.executable, "-m", "pult.selftest", "--json"], cwd=app_dir, capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=240, creationflags=flags, env=env)
        lines = proc.stdout.strip().splitlines()
        if not lines:
            tail = (proc.stderr or "").strip().splitlines()
            raise RuntimeError(tail[-1] if tail else T("самопроверка ничего не вывела", "the self-test printed nothing"))
        data = json.loads(lines[-1])
    except Exception as exc:
        return [{"level": "error", "title": T("Самопроверка кода не запустилась", "Code self-test did not start"),
                 "detail": str(exc)[:300]}]
    items = []
    passed = data["total"] - data["failed"]
    if data["failed"]:
        items.append({"level": "error", "title": T(f"Самопроверка кода: ошибок {data['failed']} из {data['total']}",
                                                   f"Code self-test: {data['failed']} of {data['total']} failed"), "detail": ""})
        for res in data["results"]:
            if not res["ok"]:
                items.append({"level": "error", "title": "  " + res["name"], "detail": res.get("error", "")})
    else:
        items.append({"level": "ok", "title": T(f"Самопроверка кода: все {passed} тестов пройдены",
                                                f"Code self-test: all {passed} tests passed"), "detail": ""})
    return items


def _ago(ts: float) -> str:
    if not ts:
        return T("никогда", "never")
    m = max(0, int((time.time() - float(ts)) / 60))
    if m < 60:
        return T(f"{m} мин назад", f"{m} min ago")
    if m < 48 * 60:
        return T(f"{m // 60} ч назад", f"{m // 60} h ago")
    return T(f"{m // 1440} дн назад", f"{m // 1440} days ago")


def _check_ads(r: Report, e, app_running: bool) -> None:
    s = e.settings
    if not s.get("block_ads"):
        r.info(T("Блокировка рекламы выключена", "Ad blocking is off"))
        return
    info = s.get("ads_info") or {}
    level = s.get("ads_level", adblock.DEFAULT_LEVEL)
    ready = os.path.isfile(e._ads_dat)
    if not ready:
        r.warn(T("Списки рекламы не скачаны — работает короткий встроенный список",
                 "Ad lists are not downloaded — a short built-in list is used"),
               T("Открой «Блокировка рекламы» и нажми «Обновить списки».", "Open Ad blocking and press Update lists."))
    else:
        total = f"{int(info.get('total', 0)):,}".replace(",", " ")
        when = _ago(s.get("ads_updated_at", 0))
        r.ok(T(f"Списки рекламы: адресов — {total}, сила «{level}», обновлены {when}",
               f"Ad lists: {total} addresses, level “{level}”, updated {when}"))
        if info.get("missing"):
            r.warn(T("Не все списки рекламы скачались: ", "Not all ad lists downloaded: ") + ", ".join(info["missing"]),
                   T("Нажми «Обновить списки» ещё раз.", "Press Update lists again."))
        if e.paths.xray_exists():
            ok, msg = xray.check_config(e.paths, _geo_config({"domain": [adblock.RULE]}))
            if ok:
                r.ok(T("Ядро принимает список рекламы", "The core accepts the ad list"))
            else:
                r.warn(T("Ядро не приняло список рекламы — работает запасной список",
                         "The core rejected the ad list — the fallback list is used"), i18n.tr(msg))
    paused = float(s.get("ads_pause_until") or 0)
    if paused > time.time():
        r.info(T(f"Блокировка рекламы на паузе до {time.strftime('%H:%M', time.localtime(paused))}",
                 f"Ad blocking is paused until {time.strftime('%H:%M', time.localtime(paused))}"))
    elif not e.connected and s.get("ads_without_vpn", True) and not app_running:
        if e.filter_on:
            r.ok(T("Блокировка рекламы работает без VPN", "Ad blocking works without VPN"))
        else:
            r.info(T("Блокировка рекламы без VPN включится, когда программа запущена",
                     "Ad blocking without VPN turns on while the program is running"))
    elif e.core_running:
        r.ok(T("Блокировка рекламы работает", "Ad blocking works"))
    st = getattr(e, "ads_stats", None) or {}
    if st.get("day") == time.strftime("%Y-%m-%d") and st.get("today"):
        r.info(T(f"Сегодня заблокировано рекламы: {st['today']}", f"Ads blocked today: {st['today']}"))


def _check_routes(r: Report, e, stop) -> None:
    state = e.routes_state()
    warns = [(k, v["warn"]) for k, v in state["services"].items() if v.get("warn")]
    warns += [(x["site"], x["warn"]) for x in state["sites"] if x.get("warn")]
    total = len(e.settings.get("routes") or {})
    if total:
        if warns:
            for name, w in warns[:8]:
                r.warn(T(f"Свой маршрут «{name}»: ", f"Own route “{name}”: ") + w)
        else:
            r.ok(T(f"Свои маршруты: {total}, все в порядке", f"Own routes: {total}, all fine"))
    auto = e.auto_state()
    via_srv = sum(1 for x in auto["items"] if x.get("via") == "server")
    r.info(T(f"Автоподбор для сайтов: {'включён' if auto['enabled'] else 'выключен'}, правил {auto['total']}"
             f" (через другой сервер: {via_srv}), проверено сайтов {auto['checked']}",
             f"Auto-routing for sites: {'on' if auto['enabled'] else 'off'}, {auto['total']} rules"
             f" ({via_srv} through another server), {auto['checked']} sites checked"))
    items = e.settings.get("proxies") or []
    for p in items[:10]:
        if stop and stop.is_set():
            return
        title = e._proxy_title(p)
        used = e._proxy_in_use(p["id"])
        res = _probe_proxy(e, p) if used and e.paths.xray_exists() else dict(p.get("check") or {}, stored=True)
        where = "" if not used else T(" (используется в маршрутах)", " (used in routes)")
        if res.get("ok"):
            r.ok(T(f"Свой прокси «{title}»: работает, страна {res.get('loc') or '?'}{where}",
                   f"Own proxy “{title}”: works, country {res.get('loc') or '?'}{where}"),
                 T("по последней проверке " + _ago(res.get("at", 0)), "last checked " + _ago(res.get("at", 0)))
                 if res.get("stored") else "")
        elif res.get("error") or res.get("at"):
            (r.error if used else r.warn)(T(f"Свой прокси «{title}» не отвечает{where}", f"Own proxy “{title}” does not respond{where}"),
                                          i18n.tr(res.get("error") or ""))
        else:
            r.info(T(f"Свой прокси «{title}»: ещё не проверялся", f"Own proxy “{title}”: not checked yet"))


def _probe_proxy(e, p: dict) -> dict:
    """Короткая проверка своего прокси без сохранения результата (через VPN, если прокси так настроен)."""
    main = e.current if e.connected else None
    if main is None and p.get("chain", True):
        last = e.find(e.settings.get("last_server_key", ""))
        main = last if last and last.supported else None
    exe = e.paths.exe_for(main) if main else e.paths.xray
    port = netutil.find_free_ports(1, avoid=tester.RESERVED_PORTS)[0]
    proc = xray.XrayProcess(e.paths)
    try:
        cfg = xray.build_proxy_test_config(p, port, main, e._use_mask(main) if main else False, e._version_for(exe))
        proc.start(cfg, e.paths.test_config, wait_for=[port], exe=exe)
        got = services.exit_info(port)
        return {"ok": bool(got.get("ip")), "loc": got.get("loc", ""), "error": "" if got.get("ip") else got.get("error", ""),
                "at": time.time()}
    except Exception as exc:  # noqa: BLE001 — любая ошибка = прокси не работает
        return {"ok": False, "error": str(exc), "at": time.time()}
    finally:
        proc.stop()


def settings_summary(s: dict) -> str:
    """Настройки для отчёта: только переключатели и счётчики — без ссылок, паролей и названий."""
    def lines(key: str) -> int:
        return sum(1 for x in (s.get(key) or "").splitlines() if x.strip() and not x.strip().startswith("#"))
    parts = [f"mode={s.get('mode', 'smart')}"]
    for k in ("ru_direct", "system_proxy", "tun_enabled", "leak_protection", "dns_encrypted", "block_ads", "ads_without_vpn",
              "mask_auto", "whitelist_auto", "autopilot", "multi_enabled", "zapret_enabled", "allow_lan", "game_mode",
              "auto_connect_on_start", "autostart", "background", "auto_routes", "auto_stall", "ads_ask_sites"):
        if k in s:
            parts.append(f"{k}={'on' if s.get(k) else 'off'}")
    for k in ("tun_engine", "byedpi_role", "ads_level"):
        if s.get(k):
            parts.append(f"{k}={s.get(k)}")
    parts += [f"proxy_list={lines('proxy_list')}", f"direct_list={lines('direct_list')}", f"block_list={lines('block_list')}",
              f"routes={len(s.get('routes') or {})}", f"auto_rules={len(s.get('auto_sites') or {})}", f"app_routes={len(s.get('app_routes') or {})}",
              f"torrent={s.get('torrent_route', 'direct')}", f"own_proxies={len(s.get('proxies') or [])}",
              f"subscriptions={len(s.get('subscriptions') or [])}", f"manual_servers={len(s.get('manual_links') or [])}",
              f"lang={s.get('lang') or 'auto'}"]
    return ", ".join(parts)


_URL = re.compile(r"(?i)\b(?:https?|vless|vmess|trojan|ssr?|hysteria2?|hy2|tuic|anytls|socks5?h?|happ|wireguard|wg|awg|vpn|xrayjson)://\S+")
_UUID = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"(?i)\[?(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])\]?")
_SECRET_KEYS = {"address", "id", "password", "pass", "user", "publicKey", "shortId", "privateKey", "secretKey", "preSharedKey",
                "server", "uuid", "auth"}  # sing-box (TUIC, AnyTLS) и Hysteria2


def _walk_secrets(obj, out: set) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in _SECRET_KEYS and isinstance(v, str):
                out.add(v)
            else:
                _walk_secrets(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _walk_secrets(v, out)


def secrets_of(e) -> set:
    """Всё, что не должно попасть в отчёт: ссылки подписок, адреса и ключи серверов, логины и пароли прокси и раздачи."""
    s = e.settings
    out: set = set()
    for meta in s.get("subscriptions") or []:
        out.add(meta.get("url", ""))
    for sv in e.servers:
        out.update((sv.link, sv.address))
        _walk_secrets(sv.outbound, out)
        _walk_secrets(getattr(sv, "sb_outbound", None) or {}, out)  # TUIC, AnyTLS: uuid и пароль
        for line in (getattr(sv, "awg_conf", "") or "").splitlines():  # AmneziaWG: ключи и адреса из конфига
            k, _, v = line.partition("=")
            if k.strip() in ("PrivateKey", "PublicKey", "PresharedKey", "Endpoint", "Address"):
                out.update(x.strip() for x in v.split(","))
    for p in s.get("proxies") or []:
        out.update((p.get("host", ""), p.get("user", ""), p.get("pass", "")))
    for h in s.get("vps_hosts") or []:
        out.add(str(h.get("host", "")))
        for f in h.get("friends") or []:
            out.add(str(f.get("id", "")))
            out.update(str(x) for x in f.get("links") or [])
    for k in ("lan_user", "lan_pass", "hotspot_ssid", "hotspot_pass", "hwid", "subscription_url"):
        out.add(str(s.get(k) or ""))
    home = os.path.expanduser("~")
    if len(home) > 3:
        out.add(home)
    return {x for x in out if isinstance(x, str) and len(x) >= 4}


def scrub(text: str, secrets: set) -> str:
    """Убирает из текста секреты, ссылки, UUID и IP-адреса; папку пользователя заменяет на %USERPROFILE%."""
    home = os.path.expanduser("~")
    for sec in sorted(secrets, key=len, reverse=True):
        text = text.replace(sec, "%USERPROFILE%" if sec == home else "<скрыто>")
    text = _URL.sub("<ссылка>", text)
    text = _UUID.sub("<ключ>", text)
    text = _IPV4.sub("<адрес>", text)
    return _IPV6.sub(_v6, text)


def _v6(m: re.Match) -> str:
    """IPv6 заменяем, а время «20:10:23» и прочее похожее — нет."""
    try:
        ipaddress.IPv6Address(m.group(0).strip("[]"))
        return "<адрес>"
    except ValueError:
        return m.group(0)


def finish(r: Report, e) -> dict:
    errors = sum(1 for i in r.items if i["level"] == "error")
    warnings = sum(1 for i in r.items if i["level"] == "warn")
    marks = {"ok": "[OK]", "info": "[i]", "warn": "[!]", "error": "[ОШИБКА]" if i18n.lang() == "ru" else "[ERROR]"}
    state = T("подключено", "connected") if e.connected else T("фильтр рекламы без VPN", "ad filter without VPN") \
        if getattr(e, "filter_on", False) else T("не подключено", "not connected")
    lines = [f"VEDOMYJ VPN {APP_VERSION} — {T('проверка программы', 'program check')} {time.strftime('%Y-%m-%d %H:%M')}",
             f"{platform.system()} {platform.release()} ({platform.machine()}), Python {platform.python_version()}, "
             f"Xray {getattr(e, 'xray_ver', '') or '?'}",
             T("Состояние: ", "Status: ") + state,
             T("Настройки: ", "Settings: ") + settings_summary(e.settings),
             T(f"Ошибок: {errors}, предупреждений: {warnings}", f"Errors: {errors}, warnings: {warnings}"), ""]
    for item in r.items:
        lines.append(f"{marks.get(item['level'], '[?]')} {item['title']}" + (f" — {item['detail']}" if item["detail"] else ""))
    lines += ["", T("Последние строки журнала:", "Last log lines:")] + e.logs_view()[-60:]
    sec = secrets_of(e)
    text = scrub("\n".join(lines), sec)
    items = [dict(i, title=scrub(i["title"], sec), detail=scrub(i["detail"], sec)) for i in r.items]
    report = {"items": items, "errors": errors, "warnings": warnings, "text": text, "time": time.time()}
    if errors and getattr(e, "errors", None) is not None:  # итог с ошибками — в журнал ошибок (для заявки на GitHub)
        e.errors.record("check", f"Проверка программы: ошибок {errors}",
                        "; ".join(i["title"] for i in items if i["level"] == "error")[:1200], where="проверка программы")
    try:
        folder = os.path.join(e.paths.data_dir, "reports")
        os.makedirs(folder, exist_ok=True)
        name = time.strftime("vedomyj-check-%Y%m%d-%H%M%S.txt")
        path = os.path.join(folder, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        report["path"] = path
        report["file"] = name
        old = sorted(x for x in os.listdir(folder) if x.endswith(".txt"))
        for x in old[:-10]:  # храним последние 10 отчётов
            try:
                os.remove(os.path.join(folder, x))
            except OSError:
                pass
    except OSError:
        pass
    return report


def gh_annotation(level: str, title: str, detail: str) -> str:
    """Строка для GitHub Actions: ошибка видна прямо на странице запуска (в сводке), без открытия журнала."""
    def esc(x: str, prop: bool = False) -> str:
        x = x.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        return x.replace(":", "%3A").replace(",", "%2C") if prop else x
    return f"::{level} title={esc(title[:200], True)}::{esc(detail[:3000])}"
