"""Полная проверка VEDOMYJ VPN («Полная проверка.bat»): всё, что можно проверить на этом компьютере, — в одном отчёте.

1. Код программы — самопроверка на имитации серверов (pult.selftest).
2. Установка и настройки — ядро, списки, порты, интернет, подписки, серверы, сервисы (diagnostics.run).
3. Функции Windows — field_check.py: принимает ли ядро новые настройки, DPAPI, Wi-Fi, утечки, подпись выпусков.
4. Блокировки в этой сети — что провайдер делает прямо сейчас: подменяет ли DNS, пропускает ли UDP за границу,
   не включены ли белые списки.
5. VPN в бою — лучшие серверы под настоящей нагрузкой: идут ли данные (а не только пинг), скорость, какие отпечатки
   TLS проходят, работает ли UDP через VPN (звонки, игры).

Ничего не меняет в настройках и не трогает системный прокси: для проверки серверов запускается своё временное ядро
на свободных портах. Отчёт — data/reports/full-check-*.txt; в нём нет ссылок, ключей, адресов и названий сетей.
"""

from __future__ import annotations

import json
import os
import platform
import socket
import subprocess
import sys
import time

from . import APP_VERSION, certcheck, diagnostics, i18n, netutil, services, tester, xray
from .xray import XrayError, XrayProcess

T = diagnostics.T

# сайты, которые в России закрыты давно и у всех провайдеров: по ним видно, как провайдер блокирует
BLOCKED_PROBES = ["rutracker.org", "www.linkedin.com", "www.instagram.com", "x.com"]
# белые списки: разрешённый сайт открывается, а обычные (не заблокированные) — нет
WHITELIST_ALLOWED = "https://ya.ru"
WHITELIST_OTHERS = ["https://www.wikipedia.org", "https://www.google.com"]
UDP_DNS = [("1.1.1.1", 53), ("8.8.8.8", 53)]
# адреса для проверки «идут ли данные»: большие общие CDN, никаких личных сайтов
DATA_HOSTS = ["www.gstatic.com", "speed.cloudflare.com"]
PROBE_URL = "https://www.gstatic.com/generate_204"
FINGERPRINTS = ["chrome", "firefox", "safari", "edge", "randomized"]
TOP_SERVERS = 3
REPORTS_KEEP = 10

SECTIONS = {
    "code": ("Код программы", "Program code"),
    "install": ("Установка и настройки", "Installation and settings"),
    "windows": ("Функции Windows", "Windows features"),
    "network": ("Блокировки в этой сети", "Blocking on this network"),
    "battle": ("VPN в бою", "VPN under real load"),
}


class Collector:
    """Итоги по разделам: {"section", "level", "title", "detail"}."""

    def __init__(self, progress=None):
        self.items: list[dict] = []
        self.section = ""
        self.progress = progress or (lambda text: None)

    def start(self, key: str) -> None:
        self.section = key
        ru, en = SECTIONS[key]
        self.progress("\n" + T(ru, en))

    def add(self, level: str, title: str, detail: str = "") -> None:
        self.items.append({"section": self.section, "level": level, "title": title, "detail": detail})
        mark = {"ok": "  OK ", "info": "  i  ", "warn": "  !  ", "error": " ERR ", "skip": "  -  "}.get(level, "  ?  ")
        self.progress(f"{mark} {title}" + (f" — {detail}" if detail else ""))

    def extend(self, items: list[dict]) -> None:
        for it in items:
            self.add(it.get("level", "info"), it.get("title", ""), it.get("detail", ""))


# ---------- 1–3: то, что уже умеют проверки программы ----------

def stage_code(c: Collector, app_dir: str) -> None:
    c.start("code")
    c.progress(T("  самопроверка кода, до 3 минут…", "  code self-test, up to 3 minutes…"))
    c.extend(diagnostics.run_selftest(app_dir))


def stage_install(c: Collector, engine, app_running: bool, stop=None) -> None:
    c.start("install")
    report = diagnostics.run(engine, include_selftest=False, stop=stop,
                             progress=lambda text: c.progress("  " + text), app_running=app_running)
    c.extend(report["items"])


def stage_windows(c: Collector, app_dir: str) -> None:
    c.start("windows")
    script = os.path.join(app_dir, "field_check.py")
    if not os.path.isfile(script):
        c.add("skip", T("field_check.py не найден — проверка функций Windows пропущена",
                        "field_check.py not found — Windows feature check skipped"))
        return
    try:
        flags = 0x08000000 if sys.platform == "win32" else 0
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
        proc = subprocess.run([sys.executable, script, "--json", "--no-open"], cwd=app_dir, capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=420, creationflags=flags, env=env)
        lines = [x for x in proc.stdout.strip().splitlines() if x.startswith("{")]
        if not lines:
            tail = (proc.stderr or "").strip().splitlines()
            raise RuntimeError(tail[-1] if tail else T("проверка ничего не вывела", "the check printed nothing"))
        data = json.loads(lines[-1])
    except Exception as exc:
        c.add("error", T("Проверка функций Windows не запустилась", "Windows feature check did not start"), str(exc)[:300])
        return
    for r in data.get("results", []):
        title = (f"{r['section']}: " if r.get("section") else "") + r.get("title", "")
        c.add(r.get("level", "info"), title, r.get("detail", ""))


# ---------- 4: что делает провайдер ----------

def _system_ips(host: str) -> list[str]:
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)})
    except OSError:
        return []


def _bogus(ip: str) -> bool:
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return a.is_unspecified or a.is_loopback or a.is_private or a.is_link_local or a.is_reserved


def udp_dns(server: tuple[str, int], timeout: float = 3.0) -> bool:
    """Доходит ли UDP за границу: обычный запрос DNS к публичному серверу."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(netutil.dns_query("www.google.com"), server)
        data, _ = s.recvfrom(4096)
        return bool(netutil.dns_answers(data))
    except (OSError, ValueError):
        return False
    finally:
        s.close()


def _cert_items(c: Collector, res: dict) -> None:
    for i in res["items"]:
        detail = " ".join(x for x in (i.get("detail"), i.get("fix")) if x)
        c.add(i["state"] if i["state"] in ("ok", "info", "warn", "error") else "info", i["title"], detail)


def stage_network(c: Collector) -> None:
    c.start("network")
    # подмена DNS: провайдер отдаёт заглушку или «не знает» заблокированный сайт
    lied, unknown, checked = 0, 0, 0
    for host in BLOCKED_PROBES:
        sys_ips = _system_ips(host)
        doh = netutil.doh_resolve(host)
        if not doh:
            continue
        checked += 1
        if not sys_ips:
            unknown += 1
        elif all(_bogus(ip) for ip in sys_ips):
            lied += 1
    if not checked:
        c.add("warn", T("Защищённый DNS (DoH) недоступен", "Secure DNS (DoH) is unreachable"),
              T("Программа не сможет обойти подмену DNS у провайдера. Проверь интернет или антивирус.",
                "The program can't bypass ISP DNS tampering. Check your internet or antivirus."))
    elif lied or unknown:
        c.add("info", T(f"DNS провайдера прячет заблокированные сайты: {lied + unknown} из {checked}",
                        f"The ISP's DNS hides blocked sites: {lied + unknown} of {checked}"),
              T("Программа обходит это защищённым DNS — делать ничего не нужно.",
                "The program bypasses it with secure DNS — nothing to do."))
    else:
        c.add("ok", T("DNS провайдера не подменяет адреса", "The ISP's DNS doesn't tamper with addresses"))
    # заблокированные сайты напрямую: как именно режут (по имени сайта в TLS или по адресу)
    blocked = 0
    for host in BLOCKED_PROBES[:2]:
        r = services.check_url(f"https://{host}", None, region_sensitive=False, timeout=8)
        if r["state"] == services.BLOCKED:
            blocked += 1
    c.add("info", T(f"Заблокированные сайты напрямую не открываются: {blocked} из 2" if blocked
                    else "Заблокированные сайты открываются напрямую",
                    f"Blocked sites don't open directly: {blocked} of 2" if blocked else "Blocked sites open directly"),
          T("Так и должно быть в России — их открывает VPN.", "Expected in Russia — the VPN opens them.") if blocked else
          T("Похоже, провайдер их не блокирует или ты не в России.", "Looks like the ISP doesn't block them or you're not in Russia."))
    # UDP за границу: от него зависят Hysteria2, AmneziaWG, звонки и игры
    udp_ok = [s for s in UDP_DNS if udp_dns(s)]
    if udp_ok:
        c.add("ok", T("UDP за границу проходит", "UDP abroad passes"),
              T("Будущие UDP-способы (Hysteria2, AmneziaWG) здесь смогут работать.",
                "Future UDP methods (Hysteria2, AmneziaWG) can work here."))
    else:
        c.add("warn", T("UDP за границу не проходит", "UDP abroad is blocked"),
              T("В этой сети работает только TCP: звонки и игры — только через VPN с UDP.",
                "Only TCP works on this network: calls and games need a VPN with UDP."))
    # сертификаты: не стоит ли сертификат Минцифры и не подменяют ли HTTPS в этой сети
    _cert_items(c, certcheck.check(None))
    # белые списки
    allowed = services.check_url(WHITELIST_ALLOWED, None, region_sensitive=False, timeout=8)
    others = [services.check_url(u, None, region_sensitive=False, timeout=8) for u in WHITELIST_OTHERS]
    others_dead = all(r["state"] == services.BLOCKED for r in others)
    if allowed["state"] != services.BLOCKED and others_dead:
        c.add("error", T("Похоже, включены белые списки: открываются только разрешённые сайты",
                         "Looks like whitelists are on: only allowed sites open"),
              T("Нужен сервер «Обход белых списков» («БС») из подписки или Wi-Fi вместо мобильного интернета.",
                "You need a whitelist bypass server (“БС”) from the subscription, or Wi-Fi instead of mobile data."))
    elif allowed["state"] == services.BLOCKED and others_dead:
        c.add("error", T("Интернета напрямую нет", "No direct internet"), i18n.tr(allowed.get("detail", "")))
    else:
        c.add("ok", T("Белых списков нет — обычный интернет", "No whitelists — regular internet"))


# ---------- 5: VPN в бою ----------

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionResetError("closed")
        data += chunk
    return data


def socks_udp_dns(port: int, server: tuple[str, int] = ("1.1.1.1", 53), timeout: float = 6.0) -> bool:
    """UDP через VPN: SOCKS5 UDP ASSOCIATE к локальному ядру и запрос DNS через него."""
    tcp = udp = None
    try:
        tcp = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        tcp.sendall(b"\x05\x01\x00")
        if _recv_exact(tcp, 2) != b"\x05\x00":
            return False
        tcp.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        head = _recv_exact(tcp, 4)
        if head[1] != 0:
            return False
        if head[3] == 1:
            addr = socket.inet_ntoa(_recv_exact(tcp, 4))
        elif head[3] == 4:
            addr = socket.inet_ntop(socket.AF_INET6, _recv_exact(tcp, 16))
        else:
            addr = _recv_exact(tcp, _recv_exact(tcp, 1)[0]).decode()
        bport = int.from_bytes(_recv_exact(tcp, 2), "big")
        if addr in ("0.0.0.0", "::", ""):
            addr = "127.0.0.1"
        udp = socket.socket(socket.AF_INET6 if ":" in addr else socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(timeout)
        packet = b"\x00\x00\x00\x01" + socket.inet_aton(server[0]) + server[1].to_bytes(2, "big") + \
            netutil.dns_query("www.google.com")
        udp.sendto(packet, (addr, bport))
        data, _ = udp.recvfrom(4096)
        if len(data) < 10 or data[3] != 1:
            return False
        return bool(netutil.dns_answers(data[10:]))
    except (OSError, ValueError):
        return False
    finally:
        for s in (udp, tcp):
            if s:
                try:
                    s.close()
                except OSError:
                    pass


def _set_fingerprint(cfg: dict, tag: str, fp: str) -> bool:
    for ob in cfg["outbounds"]:
        if ob.get("tag") != tag:
            continue
        ss = ob.get("streamSettings") or {}
        done = False
        for key in ("tlsSettings", "realitySettings"):
            if isinstance(ss.get(key), dict):
                ss[key]["fingerprint"] = fp
                done = True
        return done
    return False


def _current_fp(cfg: dict, tag: str) -> str:
    for ob in cfg["outbounds"]:
        if ob.get("tag") == tag:
            ss = ob.get("streamSettings") or {}
            for key in ("tlsSettings", "realitySettings"):
                if isinstance(ss.get(key), dict):
                    return ss[key].get("fingerprint", "")
    return ""


def battle_config(servers: list, ports: list[int], fp_ports: list[int], udp_port: int, version: str) -> dict:
    """Временное ядро: по входу на каждый сервер, входы «первый сервер с другим отпечатком TLS» и SOCKS с UDP."""
    fps = FINGERPRINTS[:len(fp_ports)]
    cfg = xray.build_test_config(list(servers) + [servers[0]] * len(fps), list(ports) + list(fp_ports), None, version)
    for i, fp in enumerate(fps):
        _set_fingerprint(cfg, f"out{len(servers) + i}", fp)
    cfg["inbounds"].append({"tag": "udp0", "listen": "127.0.0.1", "port": udp_port, "protocol": "socks",
                            "settings": {"udp": True, "ip": "127.0.0.1"}})
    cfg["routing"]["rules"].append({"type": "field", "inboundTag": ["udp0"], "outboundTag": "out0"})
    return cfg


def _data_flow(port: int) -> dict:
    last = {"state": services.STALL_FAIL, "bytes": 0, "detail": "", "ms": None}
    for host in DATA_HOSTS:
        r = services.stall_test(host, proxy_port=port)
        if r["state"] in (services.STALL_OK, services.STALL_STALL):
            return r
        last = r
    return last


def stage_battle(c: Collector, engine, with_services: bool = True) -> None:
    c.start("battle")
    if not engine.paths.xray_exists():
        c.add("skip", T("Ядро Xray не скачано — боевая проверка пропущена", "Xray core not downloaded — load test skipped"))
        return
    best = [s for s in tester.ranked(engine.servers) if getattr(s, "engine", "xray") == "xray"]  # мост и AmneziaWG — отдельно
    if not best:
        c.add("error", T("Нет ни одного рабочего сервера — проверять нечего",
                         "No working servers — nothing to test"),
              T("Обнови подписку или добавь сервер.", "Update the subscription or add a server."))
        return
    exe = engine.paths.exe_for(best[0])
    top = [s for s in best if engine.paths.exe_for(s) == exe][:TOP_SERVERS]
    secure = not getattr(top[0], "insecure", False)
    fp_count = len(FINGERPRINTS) if secure and xray.fingerprint_of(top[0].outbound or {}) is not None else 0
    ports = netutil.find_free_ports(len(top) + fp_count + 1, 44000, avoid=tester.RESERVED_PORTS)
    srv_ports, fp_ports, udp_port = ports[:len(top)], ports[len(top):len(top) + fp_count], ports[-1]
    cfg = battle_config(top, srv_ports, fp_ports, udp_port, engine._version_for(exe))
    current_fp = _current_fp(cfg, "out0") or "chrome"
    proc = XrayProcess(engine.paths)
    try:
        proc.start(cfg, os.path.join(engine.paths.data_dir, "fullcheck_test.json"), wait_for=ports, exe=exe)
    except XrayError as exc:
        c.add("error", T("Временное ядро для проверки не запустилось", "The temporary core for the test did not start"),
              i18n.tr(str(exc)))
        return
    try:
        flows = []
        for srv, port in zip(top, srv_ports):
            r = _data_flow(port)
            flows.append(r["state"] == services.STALL_OK)
            kb = (r.get("bytes") or 0) // 1024
            name = srv.name
            if r["state"] == services.STALL_OK:
                c.add("ok", T(f"«{name}»: данные идут", f"“{name}”: data flows"),
                      T(f"{kb} КБ за {r.get('ms')} мс", f"{kb} KB in {r.get('ms')} ms"))
            elif r["state"] == services.STALL_STALL:
                c.add("error", T(f"«{name}»: подключается, но данные замирают после {kb} КБ",
                                 f"“{name}”: connects, but data stalls after {kb} KB"),
                      T("Так ТСПУ режет сервер по поведению. Автопереход уведёт с него, но лучше сменить сервер.",
                        "That's TSPU throttling the server by behaviour. Auto-switch will leave it; better pick another."))
            else:
                c.add("error", T(f"«{name}»: пинг есть, а данные не идут", f"“{name}”: ping works, but no data"),
                      i18n.tr(r.get("detail", "")) or T("«Подключено, но пусто» — сервер заблокирован по поведению.",
                                                         "“Connected but empty” — the server is blocked by behaviour."))
        if not flows[0]:
            c.add("skip", T("Скорость, отпечатки TLS, UDP и сервисы через лучший сервер не проверены: данные через него не идут",
                            "Speed, TLS fingerprints, UDP and services via the best server skipped: no data flows through it"))
            return
        speed = netutil.speed_test(srv_ports[0], tester.SPEED_URLS, seconds=6)
        if speed["ok"]:
            level = "ok" if speed["mbps"] >= 5 else "warn"
            c.add(level, T(f"Скорость через «{top[0].name}»: {speed['mbps']} Мбит/с",
                           f"Speed via “{top[0].name}”: {speed['mbps']} Mbit/s"),
                  "" if level == "ok" else T("Для видео в HD нужно хотя бы 5 Мбит/с.", "HD video needs at least 5 Mbit/s."))
        else:
            c.add("warn", T("Скорость через VPN не замерить", "VPN speed can't be measured"), i18n.tr(speed["error"]))
        if fp_ports:
            works, fails = [], []
            for fp, port in zip(FINGERPRINTS, fp_ports):
                r = services.check_url(PROBE_URL, port, region_sensitive=False, timeout=8)
                (works if r["state"] in (services.OK, services.SLOW) else fails).append(fp)
            if not works:
                c.add("error", T("Отпечатки TLS: через лучший сервер не проходит ни один",
                                 "TLS fingerprints: none pass through the best server"))
            elif current_fp in works or (current_fp not in FINGERPRINTS and not fails):
                c.add("ok", T(f"Отпечатки TLS: проходят {', '.join(works)}", f"TLS fingerprints: {', '.join(works)} pass"),
                      T(f"не проходят: {', '.join(fails)}", f"blocked: {', '.join(fails)}") if fails else "")
            else:
                c.add("warn", T(f"Отпечаток «{current_fp}» из ссылки режут, а {', '.join(works)} проходят",
                                f"Fingerprint “{current_fp}” from the link is blocked, but {', '.join(works)} pass"),
                      T("Помогает сменить fp в ссылке сервера (или попросить продавца подписки).",
                        "Changing fp in the server link helps (or ask the subscription seller)."))
        if socks_udp_dns(udp_port):
            c.add("ok", T("UDP через VPN работает", "UDP via VPN works"),
                  T("Звонки в Telegram и Discord, игры — через VPN.", "Telegram and Discord calls, games — via VPN."))
        else:
            c.add("warn", T("UDP через сервер не проходит", "UDP doesn't pass through the server"),
                  T("Звонки и игры через этот сервер могут не работать — попробуй другой сервер.",
                    "Calls and games via this server may fail — try another server."))
        _cert_items(c, certcheck.check(srv_ports[0], direct=False))  # не подменяет ли сертификаты сам сервер
        if with_services and not engine.connected:
            c.progress(T("  сервисы через лучший сервер…", "  services via the best server…"))
            res = services.check_all({"direct": False, "vpn": srv_ports[0], "current": False})
            bad = [name for name, cols in res.items() if (cols.get("vpn") or {}).get("state") == services.BLOCKED]
            total = len(res)
            if bad:
                c.add("warn", T(f"Через лучший сервер не открываются: {', '.join(bad)}",
                                f"Don't open via the best server: {', '.join(bad)}"),
                      T("Для них подойдёт «Свой маршрут → Через другой сервер».", "Use “Own route → Via another server” for them."))
            else:
                c.add("ok", T(f"Через лучший сервер открываются все сервисы ({total})",
                              f"All services open via the best server ({total})"))
    finally:
        proc.stop()


# ---------- запуск и отчёт ----------

def run(engine, app_dir: str, quick: bool = False, network: bool = True, app_running: bool = False,
        progress=None, stop=None) -> dict:
    c = Collector(progress)
    t0 = time.time()
    if not quick:
        stage_code(c, app_dir)
    stage_install(c, engine, app_running, stop)
    if not quick:
        stage_windows(c, app_dir)
    if network:
        stage_network(c)
    stage_battle(c, engine)
    return finish(c, engine, time.time() - t0)


def finish(c: Collector, engine, seconds: float) -> dict:
    errors = sum(1 for i in c.items if i["level"] == "error")
    warnings = sum(1 for i in c.items if i["level"] == "warn")
    marks = {"ok": "[OK]", "info": "[i]", "warn": "[!]", "skip": "[-]",
             "error": "[ОШИБКА]" if i18n.lang() == "ru" else "[ERROR]"}
    lines = [f"VEDOMYJ VPN {APP_VERSION} — {T('полная проверка', 'full check')} {time.strftime('%Y-%m-%d %H:%M')}",
             f"{platform.system()} {platform.release()} ({platform.machine()}), Python {platform.python_version()}",
             T(f"Ошибок: {errors}, предупреждений: {warnings}, заняло {round(seconds)} с",
               f"Errors: {errors}, warnings: {warnings}, took {round(seconds)} s")]
    summary = []
    for key, (ru, en) in SECTIONS.items():
        part = [i for i in c.items if i["section"] == key]
        if not part:
            continue
        e = sum(1 for i in part if i["level"] == "error")
        w = sum(1 for i in part if i["level"] == "warn")
        skipped = all(i["level"] == "skip" for i in part)
        state = T("пропущено", "skipped") if skipped else T("всё хорошо", "all good") if not e and not w else \
            T(f"ошибок {e}, предупреждений {w}", f"{e} errors, {w} warnings")
        summary.append(f"{T(ru, en)}: {state}")
        lines += ["", f"== {T(ru, en)} =="]
        lines += [f"{marks.get(i['level'], '[?]')} {i['title']}" + (f" — {i['detail']}" if i["detail"] else "") for i in part]
    lines[3:3] = [""] + summary
    secrets = diagnostics.secrets_of(engine)
    text = diagnostics.scrub("\n".join(lines), secrets)
    items = [dict(i, title=diagnostics.scrub(i["title"], secrets), detail=diagnostics.scrub(i["detail"], secrets))
             for i in c.items]
    report = {"items": items, "errors": errors, "warnings": warnings, "summary": summary, "text": text}
    if errors and getattr(engine, "errors", None) is not None:
        engine.errors.record("check", f"Полная проверка: ошибок {errors}",
                             "; ".join(i["title"] for i in items if i["level"] == "error")[:1200], where="полная проверка")
    try:
        folder = os.path.join(engine.paths.data_dir, "reports")
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, time.strftime("full-check-%Y%m%d-%H%M%S.txt"))
        with open(path, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        report["path"] = path
        old = sorted(x for x in os.listdir(folder) if x.startswith("full-check-"))
        for x in old[:-REPORTS_KEEP]:
            try:
                os.remove(os.path.join(folder, x))
            except OSError:
                pass
    except OSError:
        pass
    return report
