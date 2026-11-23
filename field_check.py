"""Проверка новых функций VEDOMYJ VPN на настоящем компьютере. Запуск: «Проверка новых функций.bat».

Самопроверка (python -m pult.selftest) гоняет программу на имитации. Здесь — то, что можно проверить только на
настоящем Windows с настоящим ядром: принимает ли ядро Xray новые настройки (приложения, торренты, мгновенное
переключение, маскировка, kill switch, реклама, TUN), добавляются ли правила на лету, работают ли DPAPI,
горячая клавиша, распознавание Wi-Fi, поиск приложений, «замирание» соединений у провайдера, проверка утечек
и подпись выпусков.

Ничего не меняет в настройках программы и не подключается к серверам. Отчёт — в data/reports/field-check-*.txt,
в нём нет ссылок, ключей, адресов и названий сетей: его можно отправить нейросети.

Ключ --ci — для проверки на GitHub (Windows в облаке): сам скачивает ядра Xray и sing-box, пропускает проверки сети
провайдера, включает и выключает настоящий туннель AmneziaWG (если клиент установлен) и завершается с кодом 1 при ошибках.
"""

import base64
import json
import os
import platform
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.parse
import urllib.request

APP_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, APP_DIR)

from pult import (APP_VERSION, apps, diagnostics, i18n, leaks, links, netprofile, netutil, secure,  # noqa: E402
                  services, settings as settingsmod, tray, tun, update, xray)
from pult import admin_helper, amneziawg, singbox, warp  # noqa: E402

IS_WINDOWS = sys.platform == "win32"
CI = "--ci" in sys.argv
RESULTS: list[dict] = []
SECTION = [""]

# поддельные серверы только для проверки настроек ядра (документационные адреса 203.0.113.x, никуда не подключаемся)
PBK = base64.urlsafe_b64encode(bytes(range(1, 33))).decode().rstrip("=")
FAKE_LINKS = [
    f"vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443?type=tcp&security=reality&pbk={PBK}"
    "&fp=chrome&sni=www.microsoft.com&sid=0123abcd&flow=xtls-rprx-vision#Check-1",
    f"vless://11111111-2222-3333-4444-666666666666@203.0.113.11:8443?type=xhttp&path=%2Fa1b2c3&security=reality"
    f"&pbk={PBK}&fp=chrome&sni=www.microsoft.com&sid=0123abcd#Check-2",
]


def T(ru: str, en: str) -> str:
    return ru if i18n.lang() == "ru" else en


def section(title: str) -> None:
    SECTION[0] = title
    print("\n" + title)


def add(level: str, title: str, detail: str = "") -> None:
    RESULTS.append({"section": SECTION[0], "level": level, "title": title, "detail": detail})
    mark = {"ok": "  OK ", "info": "  i  ", "warn": "  !  ", "error": " ERR ", "skip": "  -  "}.get(level, "  ?  ")
    print(f"{mark} {title}" + (f" — {detail}" if detail else ""), flush=True)
    if CI and level in ("error", "warn") and os.environ.get("GITHUB_ACTIONS") == "true":
        # ошибка видна прямо на странице запуска на GitHub
        print(diagnostics.gh_annotation("error" if level == "error" else "warning", title, diagnostics.scrub(detail, set())), flush=True)


def guard(title: str, func) -> None:
    """Сбой одной проверки не мешает остальным."""
    try:
        func()
    except Exception as exc:
        add("error", title, f"{exc.__class__.__name__}: {exc}"[:300])
        traceback.print_exc()


# ---------- запущена ли программа ----------

def app_info() -> dict:
    """Состояние работающей программы через её интерфейс (тот же токен, что у окна)."""
    try:
        with open(os.path.join(APP_DIR, "data", "ui.json"), encoding="utf-8") as f:
            ui = json.load(f)
        req = urllib.request.Request(f"http://127.0.0.1:{ui['port']}/api/state", headers={"X-Token": ui["token"]})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=4) as resp:
            st = json.loads(resp.read().decode("utf-8"))
        tun_st = st.get("tun") if isinstance(st.get("tun"), dict) else {}
        return {"running": True, "locked": bool(st.get("locked")), "connected": bool(st.get("connected")),
                "tun": tun_st.get("active", ""), "kill_on": bool(st.get("kill_on"))}
    except Exception:
        return {"running": False}


# ---------- ядро Xray ----------

def fake_servers():
    out = []
    for link in FAKE_LINKS:
        srv = links.parse_link(link)
        if srv is None:
            raise RuntimeError("не разобралась тестовая ссылка")
        out.append(srv)
    return out


def base_settings(**over) -> dict:
    s = json.loads(json.dumps(settingsmod.DEFAULTS))
    s.update(lan_pass="check", lan_user="check", system_proxy=False)
    s.update(over)
    return s


def check_core(paths: xray.Paths, exe: str, label: str, legacy: bool = False) -> None:
    ver = xray.xray_version(paths, exe) or ""
    if not ver:
        add("error", T(f"{label}: не запускается", f"{label}: does not start"))
        return
    add("ok", T(f"{label}: версия {ver}", f"{label}: version {ver}"))
    s1, s2 = fake_servers()
    ports = dict(zip(("socks", "http", "health", "api", "direct", "direct_http", "metrics"),
                     netutil.find_free_ports(7, start=23100)))
    access = os.path.join(paths.data_dir, "field-check-access.log")
    geo = paths.geo_ready()
    ads_dat = os.path.isfile(os.path.join(paths.bin_dir, "adblock.dat"))
    kill = None
    try:
        from pult.engine import Engine
        kill = Engine.KILL
    except Exception:
        pass
    cases = [
        (T("обычное подключение", "regular connection"), {}, {}),
        (T("маршрут приложения (Discord напрямую, игра через VPN)", "app route (Discord direct, game via VPN)"), {},
         {"routes": [{"process": apps.rule_process("Discord"), "app": True, "tag": "direct"},
                     {"process": ["VALORANT-Win64-Shipping"], "app": True, "tag": "proxy"}]}),
        (T("торренты: блок", "torrents: block"), {"torrent_route": "block"}, {}),
        (T("торренты: через VPN", "torrents: via VPN"), {"torrent_route": "proxy"}, {}),
        (T("мгновенное переключение (балансировщик и наблюдение)", "instant failover (balancer and observatory)"), {},
         {"failover": [{"server": s2, "mask": False}]}),
        (T("маскировка, способ 1", "masking, variant 1"), {}, {"mask": 1}),
        (T("маскировка, способ 2", "masking, variant 2"), {}, {"mask": 2}),
        (T("блокировка рекламы", "ad blocking"), {"block_ads": True}, {"ads": "dat" if ads_dat else "geo"}),
        (T("всё через VPN", "everything via VPN"), {"mode": "vpn"}, {}),
        (T("режим TUN (Xray)", "TUN mode (Xray)"), {},
         {"tun": {"engine": "xray", "ipv6": True, "leak": True, "bind": ""}}),
    ]
    if kill is not None:
        cases.append((T("kill switch (VPN сломался)", "kill switch (VPN broken)"), {}, {"server": kill}))
    if not ads_dat:
        add("info", T("Файла списков рекламы ещё нет — реклама проверяется запасным списком",
                      "No ad list file yet — ads are checked with the fallback list"))
    for title, s_over, kw in cases:
        server = kw.pop("server", s1)
        try:
            cfg = xray.build_run_config(server, base_settings(**s_over), ports, access, geo, True,
                                        core_version=ver, **kw)
        except Exception as exc:
            add("error", f"{label}: {title}", T("не собрались настройки: ", "settings not built: ") + str(exc)[:200])
            continue
        ok, err = xray.check_config(paths, cfg, os.path.join(paths.data_dir, "field-check-config.json"), exe=exe)
        if ok:
            add("ok", f"{label}: {title}")
        else:
            # старое (совместимое) ядро может не знать новых возможностей — программа это обходит сама
            add("info" if legacy else "error", f"{label}: {title}", err)
    try:
        os.remove(access)
    except OSError:
        pass


def check_live_rules(paths: xray.Paths) -> None:
    """Правила на лету (автоподбор для сайтов): запускаем ядро на свободных портах и добавляем правило через API."""
    ports = netutil.find_free_ports(2, start=23300)
    cfg = {"log": {"loglevel": "warning"},
           "api": {"tag": "api", "listen": f"127.0.0.1:{ports[1]}",
                   "services": ["StatsService", "HandlerService", "RoutingService"]},
           "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": ports[0], "protocol": "socks",
                         "settings": {"udp": False}}],
           "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}],
           "routing": {"rules": [{"type": "field", "domain": ["domain:example.invalid"], "outboundTag": "block"}]}}
    proc = xray.XrayProcess(paths)
    path = os.path.join(paths.data_dir, "field-check-live.json")
    try:
        proc.start(cfg, path, wait_for=[ports[0]])
    except Exception as exc:
        add("error", T("Ядро не запустилось для проверки правил на лету", "Core did not start for the live-rules check"),
            str(exc)[:200])
        return
    tmp_o = os.path.join(paths.data_dir, "field-check-ado.json")
    tmp_r = os.path.join(paths.data_dir, "field-check-rule.json")
    try:
        with open(tmp_o, "w", encoding="utf-8") as f:
            json.dump({"outbounds": [{"tag": "auto0", "protocol": "freedom"}]}, f)
        ok_o = xray.api_command(paths, ports[1], ["ado", tmp_o])
        with open(tmp_r, "w", encoding="utf-8") as f:
            json.dump({"routing": {"domainStrategy": "IPIfNonMatch", "rules": [
                {"type": "field", "ruleTag": "auto-check", "domain": ["domain:example.org"], "outboundTag": "auto0"}]}}, f)
        ok_r = xray.api_command(paths, ports[1], ["adrules", "-append", tmp_r])
        add("ok" if ok_o else "warn", T("Новый выход в работающее ядро (ado)", "New outbound into the running core (ado)"),
            "" if ok_o else T("ядро не приняло — автоподбор будет переподключаться", "core refused — auto-routing will reconnect"))
        add("ok" if ok_r else "warn", T("Новое правило в работающее ядро (adrules -append)",
                                        "New rule into the running core (adrules -append)"),
            "" if ok_r else T("ядро не приняло — автоподбор будет переподключаться", "core refused — auto-routing will reconnect"))
    finally:
        proc.stop()
        for p in (tmp_o, tmp_r, path):
            try:
                os.remove(p)
            except OSError:
                pass


def check_metrics(paths: xray.Paths) -> None:
    """Скорость без запуска xray.exe: ядро отдаёт счётчики по HTTP (/debug/vars), программа читает их
    тем же кодом, что и в работе. Трафик идёт через вход ядра к маленькому веб-серверу на этом компьютере."""
    import http.server
    import threading
    ports = netutil.find_free_ports(3, start=23400)
    body = b"x" * 200_000

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    web = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=web.serve_forever, daemon=True).start()
    cfg = {"log": {"loglevel": "warning"},
           "stats": {}, "policy": {"system": {"statsOutboundUplink": True, "statsOutboundDownlink": True}},
           "metrics": {"tag": "metrics", "listen": f"127.0.0.1:{ports[1]}"},
           "inbounds": [{"tag": "http-in", "listen": "127.0.0.1", "port": ports[0], "protocol": "http"}],
           "outbounds": [{"tag": "proxy", "protocol": "freedom"}, {"tag": "direct", "protocol": "freedom"}],
           "routing": {"rules": [{"type": "field", "inboundTag": ["http-in"], "outboundTag": "proxy"}]}}
    proc = xray.XrayProcess(paths)
    path = os.path.join(paths.data_dir, "field-check-metrics.json")
    try:
        proc.start(cfg, path, wait_for=[ports[0], ports[1]])
    except Exception as exc:
        add("error", T("Ядро не запустилось со страницей метрик", "Core did not start with the metrics page"),
            str(exc)[:200])
        web.shutdown()
        return
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler(
            {"http": f"http://127.0.0.1:{ports[0]}"}))
        got = len(opener.open(f"http://127.0.0.1:{web.server_address[1]}/", timeout=10).read())
        stats, err = {}, ""
        for _ in range(10):
            try:
                stats = xray.query_metrics(ports[1])
                if stats.get("proxy", {}).get("downlink", 0) >= len(body):
                    break
            except Exception as exc:
                err = str(exc)[:200]
            time.sleep(0.3)
        down = stats.get("proxy", {}).get("downlink", 0)
        add("ok" if down >= got > 0 else "error",
            T("Скорость без запуска xray.exe (страница метрик ядра)", "Speed without launching xray.exe (core metrics page)"),
            T(f"через ядро прошло {down} байт", f"{down} bytes went through the core") if down else (
                err or T("счётчиков трафика нет", "no traffic counters")))
    finally:
        proc.stop()
        web.shutdown()
        try:
            os.remove(path)
        except OSError:
            pass


def tun_paths(paths: xray.Paths) -> tun.TunPaths:
    return tun.TunPaths(paths.bin_dir, paths.data_dir, paths.xray, paths.legacy_xray)


def singbox_check(exe: str, cfg: dict, path: str) -> tuple[bool, str]:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    try:
        r = subprocess.run([exe, "check", "-c", path], capture_output=True, text=True, timeout=30,
                           encoding="utf-8", errors="replace", creationflags=0x08000000 if IS_WINDOWS else 0)
        out = ((r.stdout or "") + (r.stderr or "")).strip().splitlines()
        return r.returncode == 0, " ".join(out[-2:])[:300]
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def check_singbox(paths: xray.Paths) -> None:
    exe = tun_paths(paths).singbox
    if not os.path.isfile(exe):
        add("skip", T("sing-box ещё не скачан — проверится, когда включишь TUN через sing-box или подключишь TUIC",
                      "sing-box not downloaded yet — checked once TUN via sing-box or TUIC is used"))
        return
    path = os.path.join(paths.data_dir, "field-check-singbox.json")
    cfg = tun.singbox_config(23400, True, True, True, direct_apps=tuple(apps.rule_process("Discord")),
                             block_apps=("qbittorrent",))
    ok, err = singbox_check(exe, cfg, path)
    add("ok" if ok else "error", T("sing-box: правила приложений (напрямую и блок)", "sing-box: app rules (direct and block)"),
        "" if ok else err)
    bridged = [links.parse_link(x) for x in BRIDGE_LINKS]
    cfg = singbox.bridge_config([(23500 + i, s.sb_outbound) for i, s in enumerate(bridged)])
    ok, err = singbox_check(exe, cfg, path)
    add("ok" if ok else "error", T("sing-box: мост для TUIC и AnyTLS", "sing-box: bridge for TUIC and AnyTLS"),
        "" if ok else err)


# ---------- движки: Hysteria2 в ядре Xray, TUIC через мост, AmneziaWG ----------

BRIDGE_LINKS = [
    "tuic://11111111-2222-3333-4444-777777777777:check-pass@203.0.113.30:443?sni=www.example.com&alpn=h3"
    "&congestion_control=bbr#Check-TUIC",
    "anytls://check-pass@203.0.113.31:443?sni=www.example.com#Check-AnyTLS",
    # самоподписанный сертификат без отпечатка: Xray так не умеет — через мост
    "hysteria2://check-pass@203.0.113.23:443?sni=www.example.com&insecure=1&obfs=salamander&obfs-password=x#Check-Hy2-self",
    # и с перебором портов (sing-box: server_ports + hop_interval)
    "hysteria2://check-pass@203.0.113.24:443,20000-30000/?sni=www.example.com&insecure=1#Check-Hy2-hop",
]
HY2_LINKS = [
    ("Hysteria2", "hysteria2://check-pass@203.0.113.20:443?sni=www.example.com#Check-Hy2", "error"),
    (T("Hysteria2 с маскировкой Salamander", "Hysteria2 with Salamander masking"),
     "hysteria2://check-pass@203.0.113.21:8443/?sni=www.example.com&obfs=salamander&obfs-password=check-obfs"
     "#Check-Hy2-obfs", "error"),
    (T("Hysteria2 с закреплённым сертификатом", "Hysteria2 with a pinned certificate"),
     "hy2://check-pass@203.0.113.22:443?sni=www.example.com&pinSHA256=" + "ab" * 32 + "#Check-Hy2-pin", "warn"),
]


def check_engines(paths: xray.Paths, exe: str) -> None:
    ver = xray.xray_version(paths, exe) or ""
    ports = dict(zip(("socks", "http", "health", "api", "direct", "direct_http"),
                     netutil.find_free_ports(6, start=23600)))
    access = os.path.join(paths.data_dir, "field-check-access.log")
    vless = fake_servers()[0]
    for title, link, level in HY2_LINKS:
        srv = links.parse_link(link)
        cfg = xray.build_run_config(srv, base_settings(), ports, access, paths.geo_ready(), True, core_version=ver)
        ok, err = xray.check_config(paths, cfg, os.path.join(paths.data_dir, "field-check-config.json"), exe=exe)
        add("ok" if ok else level, T(f"Ядро Xray: {title}", f"Xray core: {title}"), "" if ok else err)
    hy = links.parse_link(HY2_LINKS[1][1])
    cfg = xray.build_run_config(vless, base_settings(), ports, access, paths.geo_ready(), True, core_version=ver,
                                failover=[{"server": hy, "mask": False}])
    ok, err = xray.check_config(paths, cfg, os.path.join(paths.data_dir, "field-check-config.json"), exe=exe)
    add("ok" if ok else "error", T("Ядро Xray: запасной сервер Hysteria2 внутри ядра", "Xray core: Hysteria2 as in-core backup"),
        "" if ok else err)
    cfg = xray.build_test_config([vless, hy], netutil.find_free_ports(2, start=23700))
    ok, err = xray.check_config(paths, cfg, os.path.join(paths.data_dir, "field-check-config.json"), exe=exe)
    add("ok" if ok else "error", T("Ядро Xray: проверка серверов вместе с Hysteria2", "Xray core: server test together with Hysteria2"),
        "" if ok else err)
    # «не проверять сертификат» (allowInsecure): ядро получает отпечаток сертификата вместо него
    self_signed = links.parse_link("vless://11111111-2222-3333-4444-888888888888@203.0.113.12:443?type=ws&security=tls"
                                   "&sni=www.example.com&path=%2Fws&allowInsecure=1#Check-self-signed")
    xray.CERT_PINS[self_signed.key] = "ab" * 32
    cfg = xray.build_run_config(self_signed, base_settings(), ports, access, paths.geo_ready(), True, core_version=ver)
    ok, err = xray.check_config(paths, cfg, os.path.join(paths.data_dir, "field-check-config.json"), exe=exe)
    add("ok" if ok else "error", T("Ядро Xray: сервер «не проверять сертификат» с отпечатком вместо allowInsecure",
                                   "Xray core: “skip certificate check” server with a pin instead of allowInsecure"),
        "" if ok else err)
    tuic = links.parse_link(BRIDGE_LINKS[0])
    tuic.sidecar_port = 23500
    cfg = xray.build_run_config(tuic, base_settings(), ports, access, paths.geo_ready(), True, core_version=ver)
    ok, err = xray.check_config(paths, cfg, os.path.join(paths.data_dir, "field-check-config.json"), exe=exe)
    add("ok" if ok else "error", T("Ядро Xray: сервер TUIC через мост sing-box", "Xray core: TUIC server via the sing-box bridge"),
        "" if ok else err)


def check_xray_methods(paths: xray.Paths, exe: str) -> None:
    """1.20: принимает ли настоящее ядро перебор портов Hysteria2, шум UDP, маскировку из ссылки (fm)
    и сборку для старого ядра (без них)."""
    ver = xray.xray_version(paths, exe) or ""
    ports = dict(zip(("socks", "http", "health", "api", "direct", "direct_http"),
                     netutil.find_free_ports(6, start=23800)))
    access = os.path.join(paths.data_dir, "field-check-access.log")
    fm = urllib.parse.quote(json.dumps({"tcp": [{"type": "fragment", "settings": {"packets": "tlshello",
                                                                                   "lengths": ["100-200"],
                                                                                   "delays": ["10-20"]}}]}))
    cases = [
        (T("перебор портов Hysteria2", "Hysteria2 port hopping"),
         "hysteria2://check-pass@203.0.113.40:443,20000-30000/?sni=www.example.com&obfs=salamander&obfs-password=x#Hop", 0),
        (T("шум UDP для Hysteria2", "UDP noise for Hysteria2"),
         "hysteria2://check-pass@203.0.113.41:443/?sni=www.example.com#Noise", 1),
        (T("шум UDP 2 для Hysteria2", "UDP noise 2 for Hysteria2"),
         "hysteria2://check-pass@203.0.113.41:443/?sni=www.example.com&mport=20000-21000#Noise2", 2),
        (T("маскировка из ссылки (fm)", "masking from the link (fm)"),
         f"vless://11111111-2222-3333-4444-555555555555@203.0.113.42:443?type=tcp&security=reality&pbk={PBK}"
         f"&fp=chrome&sni=www.microsoft.com&sid=0123abcd&fm={fm}#Fm", 0),
    ]
    for title, link, mask in cases:
        srv = links.parse_link(link)
        cfg = xray.build_run_config(srv, base_settings(), ports, access, paths.geo_ready(), True, mask=bool(mask),
                                    core_version=ver)
        if mask == 2:
            cfg["outbounds"] = [o for o in cfg["outbounds"] if o.get("tag") != "proxy"] + \
                xray.proxy_outbounds(srv, "proxy", 2, ver)
        ok, err = xray.check_config(paths, cfg, os.path.join(paths.data_dir, "field-check-config.json"), exe=exe)
        add("ok" if ok else "error", T(f"Ядро Xray: {title}", f"Xray core: {title}"), "" if ok else err)
    # то же для старого ядра (26.2): лишнее убирается, конфиг остаётся рабочим
    srv = links.parse_link(cases[0][1])
    cfg = xray.build_run_config(srv, base_settings(), ports, access, paths.geo_ready(), True, core_version="26.2.6")
    fmo = (cfg["outbounds"][0].get("streamSettings") or {}).get("finalmask") or {}
    add("ok" if "quicParams" not in fmo else "error",
        T("Сборка для старого ядра: без перебора портов", "Build for an old core: without port hopping"))


def check_certpin() -> None:
    """Отпечаток сертификата снимается по настоящему TLS (так программа заменяет allowInsecure)."""
    from pult import certpin
    try:
        pin = certpin.fetch("github.com", 443, "github.com", timeout=10)
        add("ok" if len(pin) == 64 else "error", T("Отпечаток сертификата сервера снимается", "Server certificate pin is taken"))
    except OSError as exc:
        add("warn", T("Отпечаток сертификата: github.com не ответил", "Certificate pin: github.com did not answer"),
            str(exc)[:200])


def _awg_conf(private: str, public: str) -> str:
    """Туннель только в документационную сеть: он не трогает настоящий интернет компьютера."""
    return "\n".join([
        "[Interface]", f"PrivateKey = {private}", "Address = 10.250.0.2/32",
        "Jc = 4", "Jmin = 40", "Jmax = 70", "S1 = 15", "S2 = 33", "H1 = 1844", "H2 = 2981", "H3 = 3110", "H4 = 4129",
        "", "[Peer]", f"PublicKey = {public}", "AllowedIPs = 10.250.0.0/24", "Endpoint = 203.0.113.40:51820"])


def check_awg(paths: xray.Paths, live: bool) -> None:
    import base64 as b64
    client = amneziawg.find_client()
    if not client:
        add("info" if not CI else "warn", T("Клиент AmneziaWG не установлен — понадобится, только если будешь включать AmneziaWG",
                                            "AmneziaWG client not installed — needed only if you turn AmneziaWG on"))
        return
    add("ok", T("Клиент AmneziaWG найден", "AmneziaWG client found"))
    conf = _awg_conf(b64.b64encode(os.urandom(32)).decode(), b64.b64encode(os.urandom(32)).decode())
    srv = links.parse_link(links.awg_link(conf, "Check"))
    add("ok" if srv and srv.engine == "awg" and not srv.note else "error",
        T("Конфиг AmneziaWG разбирается", "AmneziaWG config parses"))
    if not live:
        return
    # настоящий туннель: так же, как его включает программа (тот же помощник, те же проверки параметров)
    runner = amneziawg.Runner(paths.data_dir)
    helper = admin_helper.Helper("ci", {}, 0, paths.data_dir)
    runner.write_conf(srv.awg_conf + "\nPostUp = cmd /c exit 0")
    with open(runner.conf_path, encoding="utf-8") as f:
        add("ok" if "PostUp" not in f.read() else "error", T("Команды PostUp выкинуты из конфига", "PostUp commands removed"))
    with open(runner.conf_path, "a", encoding="utf-8") as f:
        f.write("PostUp = cmd /c exit 0\n")
    r = helper.run("awg", ["/installtunnelservice", runner.conf_path])
    add("ok" if not r.get("ok") and "PostUp" in r.get("error", "") else "error",
        T("Помощник не пускает конфиг с командами", "Helper rejects a config with commands"), r.get("error", ""))
    runner.write_conf(srv.awg_conf)
    try:
        r = helper.run("awg", ["/installtunnelservice", runner.conf_path])
        if not r.get("ok"):
            add("error", T("AmneziaWG: туннель не включился", "AmneziaWG: tunnel did not start"), r.get("error", "")[:300])
            return
        deadline = time.time() + 30
        while time.time() < deadline and not amneziawg.service_running():
            time.sleep(0.5)
        add("ok" if amneziawg.service_running() else "error",
            T("AmneziaWG: туннель включился (служба работает)", "AmneziaWG: tunnel started (service running)"))
    finally:
        r = helper.run("awg", ["/uninstalltunnelservice", amneziawg.TUNNEL])
        runner.wipe()
        deadline = time.time() + 20
        while time.time() < deadline and amneziawg.service_running():
            time.sleep(0.5)
        add("ok" if r.get("ok") and not amneziawg.service_running() and not os.path.exists(runner.conf_path) else "error",
            T("AmneziaWG: туннель выключен, файл с ключом стёрт", "AmneziaWG: tunnel removed, key file wiped"),
            r.get("error", "")[:300])


def check_warp(paths: xray.Paths, live: bool) -> None:
    """Бесплатный WARP по-настоящему: регистрация у Cloudflare и каждый набор обманок через клиент AmneziaWG.
    Туннель — только до 1.1.1.1 (не весь интернет: без «аварийного выключателя» клиента, чтобы не оборвать
    связь самой проверки); Cloudflare отвечает «warp=on», если запрос пришёл через WARP."""
    acct, last = None, ""
    for host in warp.API_HOSTS:
        try:
            acct = warp.register(warp.opener_for(None), f"https://{host}")
            break
        except warp.WarpError as exc:
            last = f"{exc.kind}: {exc}"
    if not acct:
        if CI:
            add("warn", T("WARP: Cloudflare не дал зарегистрироваться (из облака так бывает)",
                          "WARP: Cloudflare refused registration (happens from clouds)"), last[:200])
        else:
            add("info", T("WARP: напрямую регистрация не прошла — программа зарегистрирует WARP через включённый VPN",
                          "WARP: direct registration failed — the app will register WARP through a connected VPN"), last[:200])
        return None
    add("ok", T("WARP: регистрация у Cloudflare прошла", "WARP: registered with Cloudflare"))
    if not live or not amneziawg.find_client():
        return acct
    runner = amneziawg.Runner(paths.data_dir)
    helper = admin_helper.Helper("ci", {}, 0, paths.data_dir)
    passed = 0
    for i in range(len(warp.PRESETS)):
        p = warp.preset(i)
        conf = warp.build_conf(acct, p).replace("AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 1.1.1.1/32")
        conf = "\n".join(x for x in conf.splitlines() if not x.startswith("DNS ="))
        runner.write_conf(conf)
        try:
            r = helper.run("awg", ["/installtunnelservice", runner.conf_path])
            if not r.get("ok"):
                add("error", T(f"WARP {p['label']}: клиент AmneziaWG не принял конфиг",
                               f"WARP {p['label']}: AmneziaWG client rejected the config"), r.get("error", "")[:300])
                continue
            deadline = time.time() + 20
            while time.time() < deadline and not amneziawg.service_running():
                time.sleep(0.5)
            ok = False
            for _ in range(6):
                time.sleep(2)
                if warp.trace_ok(timeout=5):
                    ok = True
                    break
            passed += ok
            add("ok" if ok else "warn", T(f"WARP {p['label']} ({p['endpoint']}): " + ("трафик идёт через WARP" if ok else "трафик не пошёл"),
                                          f"WARP {p['label']} ({p['endpoint']}): " + ("traffic goes through WARP" if ok else "no traffic")))
        finally:
            helper.run("awg", ["/uninstalltunnelservice", amneziawg.TUNNEL])
            deadline = time.time() + 20
            while time.time() < deadline and amneziawg.service_running():
                time.sleep(0.5)
            runner.wipe()
    add("ok" if passed else "error", T(f"WARP: работают {passed} из {len(warp.PRESETS)} наборов обманок",
                                       f"WARP: {passed} of {len(warp.PRESETS)} decoy sets work"))
    return acct


def _trace_via(port: int, timeout: float = 10.0) -> str:
    """Ответ Cloudflare через вход HTTP ядра: on/plus — запрос пришёл через WARP, off — мимо него."""
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}", "https": f"http://127.0.0.1:{port}"}),
        urllib.request.HTTPSHandler(context=netutil.ssl_context()))
    try:
        with opener.open(urllib.request.Request(warp.TRACE_URL, headers={"User-Agent": "curl/8"}), timeout=timeout) as r:
            body = r.read(4096).decode("utf-8", "replace")
    except OSError as exc:
        return f"нет ответа: {str(exc)[:80]}"
    import re as _re
    m = _re.search(r"^warp=(\S+)", body, _re.M)
    return m.group(1) if m else "нет warp="


def _run_trace(paths: xray.Paths, cfg: dict, port: int, name: str) -> str:
    proc = xray.XrayProcess(paths)
    path = os.path.join(paths.data_dir, f"field-check-{name}.json")
    try:
        proc.start(cfg, path, wait_for=[port])
    except Exception as exc:
        return f"ядро не запустилось: {str(exc)[:160]}"
    try:
        got = ""
        for _ in range(3):
            got = _trace_via(port)
            if got in ("on", "plus"):
                break
            time.sleep(2)
        return got
    finally:
        proc.stop()
        try:
            os.remove(path)
        except OSError:
            pass


def check_warp_xray(paths: xray.Paths, acct: dict | None) -> None:
    """1.21: WARP во встроенном ядре по-настоящему — каждый набор обманок шумом Finalmask (без AmneziaWG)
    и «WARP после VPN»: WARP через другой выход (dialerProxy). Обратная проверка: цепочка в никуда — данных нет,
    значит ядро действительно ведёт WARP через цепочку, а не мимо неё."""
    if not acct:
        return
    passed, working = 0, []
    for i in range(len(warp.PRESETS)):
        p = warp.preset(i)
        conf = warp.build_conf(acct, p)
        port = netutil.find_free_ports(1, start=23900 + i * 3)[0]
        cfg = {"log": {"loglevel": "warning"},
               "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": port, "protocol": "http", "settings": {}}],
               "outbounds": [warp.xray_outbound(conf, "proxy"), {"tag": "direct", "protocol": "freedom"}],
               "routing": {"rules": [{"type": "field", "inboundTag": ["in"], "outboundTag": "proxy"}]}}
        ok, err = xray.check_config(paths, cfg, os.path.join(paths.data_dir, "field-check-warpx.json"))
        if not ok:
            add("error", T(f"WARP в ядре ({p['label']}): ядро не приняло настройки", f"WARP in the core ({p['label']}): core rejected the settings"), err)
            continue
        got = _run_trace(paths, cfg, port, "warpx")
        passed += got in ("on", "plus")
        if got in ("on", "plus"):
            working.append(p)
        add("ok" if got in ("on", "plus") else "warn",
            T(f"WARP в ядре {p['label']} ({p['endpoint']}): ", f"WARP in the core {p['label']} ({p['endpoint']}): ") + got)
    add("ok" if passed else "error", T(f"WARP во встроенном ядре: работают {passed} из {len(warp.PRESETS)} наборов обманок",
                                       f"WARP in the built-in core: {passed} of {len(warp.PRESETS)} decoy sets work"))
    # «WARP после VPN»: «VPN» — вход SOCKS этого же ядра (с UDP), WARP идёт к Cloudflare через него.
    # Наборы обманок — сработавшие выше, до трёх по очереди: сеть GitHub до отдельных адресов Cloudflare
    # иногда на минуту пропадает, это не ошибка программы.
    if not working:
        return

    def chain(conf: dict, how: str, good: bool) -> str:
        ports = netutil.find_free_ports(3, start=24000)
        ob = warp.xray_outbound(conf, "warp", noise=False)
        if how == "dialerProxy":
            ob["streamSettings"] = {"sockopt": {"dialerProxy": "proxy"}}
        else:
            ob["proxySettings"] = {"tag": "proxy"}
        cfg = {"log": {"loglevel": "warning"},
               "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": ports[0], "protocol": "http", "settings": {}},
                            {"tag": "srv-in", "listen": "127.0.0.1", "port": ports[1], "protocol": "socks",
                             "settings": {"udp": True, "ip": "127.0.0.1"}}],
               "outbounds": [ob, {"tag": "proxy", "protocol": "socks", "settings": {"servers": [
                   {"address": "127.0.0.1", "port": ports[1] if good else ports[2]}]}},
                             {"tag": "direct", "protocol": "freedom"}],
               "routing": {"rules": [{"type": "field", "inboundTag": ["in"], "outboundTag": "warp"},
                                     {"type": "field", "inboundTag": ["srv-in"], "outboundTag": "direct"}]}}
        return _run_trace(paths, cfg, ports[0], "warpchain")

    for how in ("dialerProxy", "proxySettings"):
        res = {True: "", False: ""}
        for p in working[:3] if how == "dialerProxy" else working[:1]:
            conf = warp.build_conf(acct, p)
            res[True] = chain(conf, how, True)
            if res[True] in ("on", "plus"):
                res[False] = chain(conf, how, False)
                break
        works = res[True] in ("on", "plus") and res[False] not in ("on", "plus")
        add("ok" if works else ("error" if how == "dialerProxy" else "info"),
            T(f"WARP после VPN ({how}): ", f"WARP after VPN ({how}): ")
            + (T("идёт через цепочку", "goes through the chain") if works else
               T(f"через цепочку: {res[True]}, цепочка в никуда: {res[False] or '—'}",
                 f"via chain: {res[True]}, chain to nowhere: {res[False] or '—'}")))


def check_xdns(paths: xray.Paths) -> None:
    """1.25: DNS-туннель (XDNS) на этом компьютере по-настоящему: ключ шифрования VLESS от настоящего ядра,
    служба туннеля и клиент по ссылке программы (в ссылке — публичный адрес, как у человека) на одной машине."""
    from pult import vps
    ver = xray.xray_version(paths, paths.xray) or ""
    if xray._ver(ver) < links.XDNS_MIN:
        add("info", T(f"DNS-туннель: ядро {ver or '?'} старое (нужно 26.10.21+)", f"DNS tunnel: core {ver or '?'} is old (26.10.21+ is needed)"))
        return
    out = subprocess.run([paths.xray, "vlessenc"], capture_output=True, text=True, timeout=30,
                         creationflags=xray.NO_WINDOW).stdout
    import re as _re
    encs = _re.findall(r'"encryption": *"([^"]+)"', out)
    decs = _re.findall(r'"decryption": *"([^"]+)"', out)
    i = next((k for k, e in enumerate(encs) if len(e) < 300), -1)
    if i < 0 or i >= len(decs):
        add("error", T("DNS-туннель: ядро не создало ключ шифрования VLESS", "DNS tunnel: the core did not make a VLESS key"), out[-200:])
        return
    enc, dec = encs[i], decs[i]
    domain, uid, pw = "t.vedomyj.test", "3f1c2a9e-1b2c-4d5e-8f90-1234567890ab", vps.xdns_password()
    sport, cport, rport = netutil.find_free_ports(3, start=24300)
    scfg = vps.xdns_server_config(domain, uid, pw, decryption=dec, port=sport, listen="127.0.0.1")
    # служба туннеля слушает только UDP — TCP-«маячок», чтобы дождаться, пока ядро прочитает настройки
    scfg["inbounds"].append({"tag": "ready", "listen": "127.0.0.1", "port": rport, "protocol": "socks", "settings": {}})
    link = vps.make_xdns_link(domain, uid, pw, enc, "CI", resolvers=(f"127.0.0.1:{sport}",), address="77.88.8.8")
    srv = links.parse_link(link)
    ccfg = {"log": {"loglevel": "warning"},
            "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": cport, "protocol": "http", "settings": {}}],
            "outbounds": xray.proxy_outbounds(srv, "proxy", False, ver) + [{"tag": "direct", "protocol": "freedom"}],
            "routing": {"rules": [{"type": "field", "inboundTag": ["in"], "outboundTag": "proxy"}]}}
    for name, cfg in (("server", scfg), ("client", ccfg)):
        ok, err = xray.check_config(paths, cfg, os.path.join(paths.data_dir, f"field-check-xdns-{name}.json"))
        if not ok:
            add("error", T(f"DNS-туннель: ядро не приняло настройки ({name})", f"DNS tunnel: the core rejected the settings ({name})"), err)
            return
    add("ok", T("DNS-туннель: ядро принимает настройки (публичный адрес, шифрование VLESS, xdns)",
                "DNS tunnel: the core accepts the settings (public address, VLESS encryption, xdns)"))
    procs = []
    try:
        for name, cfg, wait in (("server", scfg, [rport]), ("client", ccfg, [cport])):
            p = xray.XrayProcess(paths)
            p.start(cfg, os.path.join(paths.data_dir, f"field-check-xdns-{name}.json"), wait_for=wait)
            procs.append(p)
        time.sleep(1.5)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{cport}",
                                                                          "https": f"http://127.0.0.1:{cport}"}))
        code, t0 = 0, time.time()
        for _ in range(2):
            try:
                with opener.open("https://www.gstatic.com/generate_204", timeout=40) as r:
                    code = r.status
                break
            except OSError as exc:
                code = str(exc)[:120]
        tail = "" if code == 204 else " | " + " / ".join(
            f"{n}: " + " ; ".join(list(p.lines)[-3:])[-300:] for n, p in zip(("server", "client"), procs))
        add("ok" if code == 204 else "error", T("DNS-туннель на этом компьютере: сайт открывается через туннель",
                                                "DNS tunnel on this computer: a site opens through the tunnel"),
            f"{code}, {time.time() - t0:.1f} s{tail}")
    finally:
        for p in procs:
            p.stop()


def check_proto(paths: xray.Paths) -> None:
    """1.26: свой протокол VEDOMYJ на этом компьютере по-настоящему: ключ VLESS от ядра, служба и клиент по ссылке
    программы (sudoku «текст» + HTTP-приветствие) на одной машине."""
    from pult import dialect, vps
    ver = xray.xray_version(paths, paths.xray) or ""
    if xray._ver(ver) < dialect.PROTO_MIN:
        add("info", T(f"Свой протокол: ядро {ver or '?'} старое (нужно 26.10.21+)", f"Own protocol: core {ver or '?'} is old (26.10.21+ is needed)"))
        return
    out = subprocess.run([paths.xray, "vlessenc"], capture_output=True, text=True, timeout=30,
                         creationflags=xray.NO_WINDOW).stdout
    import re as _re
    encs = _re.findall(r'"encryption": *"([^"]+)"', out)
    decs = _re.findall(r'"decryption": *"([^"]+)"', out)
    i = next((k for k, e in enumerate(encs) if len(e) < 300), -1)
    if i < 0 or i >= len(decs):
        add("error", T("Свой протокол: ядро не создало ключ шифрования VLESS", "Own protocol: the core did not make a VLESS key"), out[-200:])
        return
    uid, pw, dial = "3f1c2a9e-1b2c-4d5e-8f90-1234567890ab", vps.xdns_password(), dialect.make()
    sport, cport = netutil.find_free_ports(2, start=24400)
    scfg = vps.proto_server_config(dial, uid, pw, decryption=decs[i], port=sport, listen="127.0.0.1")
    srv = links.parse_link(vps.make_proto_link("127.0.0.1", sport, uid, encs[i], dial, pw, "CI"))
    ccfg = {"log": {"loglevel": "warning"},
            "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": cport, "protocol": "http", "settings": {}}],
            "outbounds": xray.proxy_outbounds(srv, "proxy", False, ver) + [{"tag": "direct", "protocol": "freedom"}],
            "routing": {"rules": [{"type": "field", "inboundTag": ["in"], "outboundTag": "proxy"}]}}
    procs = []
    try:
        for name, cfg, wait in (("server", scfg, [sport]), ("client", ccfg, [cport])):
            p = xray.XrayProcess(paths)
            p.start(cfg, os.path.join(paths.data_dir, f"field-check-proto-{name}.json"), wait_for=wait)
            procs.append(p)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{cport}",
                                                                          "https": f"http://127.0.0.1:{cport}"}))
        code, t0 = 0, time.time()
        for _ in range(2):
            try:
                with opener.open("https://www.gstatic.com/generate_204", timeout=30) as r:
                    code = r.status
                break
            except OSError as exc:
                code = str(exc)[:120]
        tail = "" if code == 204 else " | " + " / ".join(
            f"{n}: " + " ; ".join(list(p.lines)[-3:])[-300:] for n, p in zip(("server", "client"), procs))
        add("ok" if code == 204 else "error", T("Свой протокол на этом компьютере: сайт открывается",
                                                "Own protocol on this computer: a site opens"), f"{code}, {time.time() - t0:.1f} s{tail}")
    except xray.XrayError as exc:
        add("error", T("Свой протокол: ядро не запустилось", "Own protocol: the core did not start"), str(exc))
    finally:
        for p in procs:
            p.stop()


def check_dht() -> None:
    """1.22: «Семья» через настоящую сеть торрентов — запись BEP 44 кладётся и читается другим клиентом."""
    from pult import dht
    keys = dht.Keys(os.urandom(32))
    salt = b"vedomyj-check/" + os.urandom(6).hex().encode()
    value = {"t": int(time.time()), "x": os.urandom(32)}
    t0 = time.time()
    try:
        n = dht.Client().put(keys.item(salt, 1, value))
    except (OSError, dht.DhtError) as exc:
        add("warn", T("Сеть торрентов: запись не легла", "Torrent network: the item was not stored"), str(exc)[:200])
        return
    if not n:
        add("warn", T("Сеть торрентов: ни один узел не принял запись (UDP закрыт?)",
                      "Torrent network: no node accepted the item (UDP closed?)"))
        return
    took = time.time() - t0
    got = None
    for i in range(6):  # сеть торрентов отвечает не сразу и не всегда одними и теми же узлами
        got = dht.Client().get(keys.public, salt)
        if got:
            break
        if i == 2:
            dht.Client().put(keys.item(salt, 1, value))  # переложить: ближайшие узлы могли смениться
        time.sleep(4)
    ok = bool(got and got[0] == 1 and got[1] == dht.bdecode(dht.bencode(value)))
    add("ok" if ok else "error", T(f"Сеть торрентов: запись легла на {n} узлов за {took:.1f} с и " + ("читается" if ok else "НЕ читается"),
                                   f"Torrent network: the item went to {n} nodes in {took:.1f} s and " + ("reads back" if ok else "does NOT read back")))


def download_cores(paths: xray.Paths) -> None:
    """Для проверки на GitHub: ядра скачиваются тем же кодом, что и в программе."""
    if not paths.xray_exists():
        ver = xray.download_xray(paths)
        add("ok", T("Ядро Xray скачано", "Xray core downloaded"), T(f"версия {ver}", f"version {ver}"))
    tp = tun_paths(paths)
    if not os.path.isfile(tp.singbox):
        ver = tun.download_singbox(tp)
        add("ok", T("sing-box скачан", "sing-box downloaded"), T(f"версия {ver}", f"version {ver}"))


# ---------- Windows ----------

def check_dpapi() -> None:
    if not secure.available():
        add("skip" if not IS_WINDOWS else "error", T("Шифрование данных (DPAPI)", "Data encryption (DPAPI)"),
            T("работает только в Windows", "Windows only"))
        return
    sample = "VEDOMYJ проверка шифрования ✓"
    enc = secure.encode(sample)
    ok = enc != sample and secure.is_encrypted(enc) and secure.decode(enc) == sample
    add("ok" if ok else "error", T("Шифрование данных (DPAPI): зашифровать и расшифровать",
                                   "Data encryption (DPAPI): encrypt and decrypt"))
    path = os.path.join(APP_DIR, "data", "settings.json")
    if not os.path.isfile(path):
        add("info", T("Файла настроек ещё нет", "No settings file yet"))
        return
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    on = raw.get("encrypt_data", True)
    sealed = isinstance(raw.get("_secure"), str) and secure.is_encrypted(raw["_secure"])
    plain = [k for k in settingsmod.SECRET_KEYS if raw.get(k)]
    if on and sealed and not plain:
        add("ok", T("Подписки и пароли в настройках лежат зашифрованными", "Subscriptions and passwords are stored encrypted"))
    elif on and plain:
        add("warn", T("Шифрование включено, но часть данных пока открыта", "Encryption is on but some data is still plain"),
            T(f"поля: {', '.join(plain)} — зашифруются при следующем сохранении настроек",
              f"fields: {', '.join(plain)} — encrypted on the next settings save"))
    elif not on:
        add("info", T("Шифрование данных выключено в настройках", "Data encryption is off in settings"))
    else:
        add("ok", T("Секретных данных в настройках пока нет", "No secret data in settings yet"))


def check_hotkey(info: dict) -> None:
    if not IS_WINDOWS:
        add("skip", T("Горячая клавиша — только в Windows", "Hotkey — Windows only"))
        return
    import ctypes
    from ctypes import wintypes as wt
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.RegisterHotKey.argtypes = [wt.HWND, ctypes.c_int, wt.UINT, wt.UINT]
    user32.UnregisterHotKey.argtypes = [wt.HWND, ctypes.c_int]
    # служебное сочетание, которое точно никем не занято: проверяем, что сама функция Windows работает
    mods, vk = tray.parse_hotkey("Ctrl+Alt+Shift+F12")
    ok = bool(user32.RegisterHotKey(None, 0x7A11, mods | tray.MOD_NOREPEAT, vk))
    if ok:
        user32.UnregisterHotKey(None, 0x7A11)
    add("ok" if ok else "error", T("Горячие клавиши Windows работают", "Windows hotkeys work"),
        "" if ok else f"RegisterHotKey: {ctypes.get_last_error()}")
    s = settingsmod.Settings(os.path.join(APP_DIR, "data", "settings.json")) \
        if os.path.isfile(os.path.join(APP_DIR, "data", "settings.json")) else {}
    combo = s.get("hotkey") or settingsmod.DEFAULTS.get("hotkey", "Ctrl+Alt+V")
    parsed = tray.parse_hotkey(combo)
    if not parsed:
        add("error", T(f"Сочетание «{combo}» не разобралось", f"Combination “{combo}” did not parse"))
        return
    free = bool(user32.RegisterHotKey(None, 0x7A12, parsed[0] | tray.MOD_NOREPEAT, parsed[1]))
    if free:
        user32.UnregisterHotKey(None, 0x7A12)
        if info.get("running"):
            add("warn", T(f"«{combo}» свободно, хотя программа запущена", f"“{combo}” is free although the program runs"),
                T("значит, программа его не заняла: проверь «Функции → Горячая клавиша»",
                  "so the program didn't take it: check Features → Hotkey"))
        else:
            add("ok", T(f"«{combo}» свободно — программа сможет его занять", f"“{combo}” is free for the program"))
    elif info.get("running"):
        add("ok", T(f"«{combo}» занято — скорее всего, самой программой (так и должно быть)",
                    f"“{combo}” is taken — most likely by the program itself (expected)"))
    else:
        add("warn", T(f"«{combo}» занято другой программой", f"“{combo}” is taken by another program"),
            T("выбери другое сочетание в «Функции → Горячая клавиша»", "pick another one in Features → Hotkey"))


def check_wifi() -> None:
    if not IS_WINDOWS:
        add("skip", T("Распознавание Wi-Fi — только в Windows", "Wi-Fi detection — Windows only"))
        return
    raw = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, timeout=10,
                         creationflags=0x08000000).stdout
    try:
        text = raw.decode("oem")
    except (LookupError, UnicodeDecodeError):
        text = raw.decode("utf-8", "replace")
    parsed = netprofile.parse_netsh(text)
    net = netprofile.current()
    if not parsed["connected"]:
        add("info", T("Сейчас не подключено к Wi-Fi (кабель, Wi-Fi выключен или его нет)",
                      "Not on Wi-Fi now (cable, Wi-Fi off or absent)"),
            T(f"строк в ответе netsh: {len(text.splitlines())}", f"netsh lines: {len(text.splitlines())}"))
        return
    kind = netprofile.classify(net, [], [])
    add("ok" if parsed["auth"] else "warn",
        T("Wi-Fi распознан", "Wi-Fi recognized"),
        T(f"название сети найдено ({len(parsed['ssid'])} симв.), защита: «{parsed['auth'] or 'не найдена'}», "
          f"открытая: {'да' if parsed['open'] else 'нет'}, профиль: {'чужая' if kind == 'public' else 'своя'}",
          f"network name found ({len(parsed['ssid'])} chars), security: “{parsed['auth'] or 'not found'}”, "
          f"open: {'yes' if parsed['open'] else 'no'}, profile: {kind}"))


def check_apps() -> None:
    if not IS_WINDOWS:
        add("skip", T("Поиск приложений — только в Windows", "App detection — Windows only"))
        return
    t0 = time.monotonic()
    found = apps.running()
    ms = int((time.monotonic() - t0) * 1000)
    with_path = sum(1 for a in found if "/" in a["path"])
    known = sorted({p["title"] for a in found for p in [apps.preset_for(a["name"])] if p})
    add("ok" if found else "warn", T("Приложения с соединениями находятся", "Apps with connections are found"),
        T(f"{len(found)} шт. (с путём к .exe — {with_path}), за {ms} мс; известные: {', '.join(known) or 'нет'}",
          f"{len(found)} (with .exe path — {with_path}), in {ms} ms; known: {', '.join(known) or 'none'}"))


# ---------- сеть и провайдер ----------

def check_direct() -> bool:
    r = netutil.http_ping("www.gstatic.com", "/generate_204", None, rounds=2, timeout=8)
    add("ok" if r["ok"] else "error", T("Интернет напрямую", "Direct internet"),
        f"{r.get('ping_ms')} {T('мс', 'ms')}" if r["ok"] else str(r.get("error", "")))
    return bool(r["ok"])


STALL_HOSTS = ["www.gstatic.com", "speed.cloudflare.com", "cdn.jsdelivr.net", "github.githubassets.com"]


def check_stall(proxy_port: int | None) -> None:
    """Замирание после ~16 КБ: так провайдеры режут часть зарубежных хостингов. Адреса — общие CDN, не личные."""
    via = T("через VPN", "via VPN") if proxy_port else T("напрямую", "direct")
    for host in STALL_HOSTS:
        r = services.stall_test(host, proxy_port=proxy_port)
        state = r["state"]
        kb = (r.get("bytes") or 0) // 1024
        if state == services.STALL_OK:
            add("ok", f"{host} {via}: {T('качается', 'downloads')}", f"{kb} {T('КБ', 'KB')}, {r.get('ms')} {T('мс', 'ms')}")
        elif state == services.STALL_STALL:
            add("warn" if not proxy_port else "error", f"{host} {via}: {T('замирает', 'stalls')}",
                f"{kb} {T('КБ', 'KB')} — {r.get('detail', '')}" + ("" if proxy_port else
                T(" (так провайдер режет этот хостинг — автоподбор уведёт такие адреса в VPN)",
                  " (the ISP throttles this host — auto-routing moves such hosts to VPN)")))
        elif state == services.STALL_SMALL:
            add("info", f"{host} {via}: {T('отдаёт мало — не проверить', 'sends little — cannot check')}", f"{kb} {T('КБ', 'KB')}")
        else:
            add("warn", f"{host} {via}: {T('не открылся', 'did not open')}", r.get("detail", ""))


def check_leaks(info: dict, http_port: int) -> None:
    """Те же проверки, что «Проверка утечек» в программе. Адреса в отчёт не пишутся — только «совпадают или нет»."""
    try:
        direct = leaks.ip_info(None)
    except Exception as exc:
        add("warn", T("Адрес напрямую не узнать (ip-api.com)", "Direct address unknown (ip-api.com)"), netutil.human_error(exc))
        return
    add("ok", T("ip-api.com отвечает напрямую", "ip-api.com answers directly"), T(f"страна {direct['country']}", f"country {direct['country']}"))
    if info.get("connected"):
        try:
            vpn = leaks.ip_info(http_port)
            same = vpn["ip"] == direct["ip"]
            mode_note = T(" (в умном режиме ip-api идёт напрямую — это нормально)", " (smart mode sends ip-api direct — normal)")
            add("info" if same else "ok", T("Адрес через прокси программы", "Address via the program's proxy"),
                T(f"{'совпадает с настоящим' + mode_note if same else 'другой, страна ' + vpn['country']}",
                  f"{'same as real' + mode_note if same else 'different, country ' + vpn['country']}"))
        except Exception as exc:
            add("warn", T("Через прокси программы адрес не узнать", "Address via the program's proxy unknown"),
                netutil.human_error(exc))
    mapped = leaks.stun_mapped()
    if mapped:
        add("ok" if mapped != direct["ip"] or not info.get("tun") else "error",
            T("WebRTC/STUN отвечает", "WebRTC/STUN answers"),
            T("адрес STUN " + ("совпадает с настоящим" if mapped == direct["ip"] else "другой"),
              "STUN address " + ("same as real" if mapped == direct["ip"] else "different")))
    else:
        add("info", T("STUN (UDP 19302) не ответил", "STUN (UDP 19302) did not answer"),
            T("UDP наружу закрыт или порт режется — это не ошибка программы", "outbound UDP closed — not a program error"))
    v6 = leaks.ipv6_address()
    add("info", "IPv6", T("есть" if v6 else "нет", "present" if v6 else "none"))
    try:
        d = leaks.dns_info(None)
        add("ok" if d.get("geo") else "info", T("Проверка DNS (edns.ip-api.com) отвечает", "DNS check (edns.ip-api.com) answers"),
            T("через провайдера" if leaks.same_isp(direct.get("isp", ""), d.get("geo", "")) else "не через провайдера",
              "via the ISP" if leaks.same_isp(direct.get("isp", ""), d.get("geo", "")) else "not via the ISP"))
    except Exception as exc:
        add("info", T("Проверка DNS не ответила", "DNS check did not answer"), netutil.human_error(exc))


def check_bypass() -> None:
    """То, чем программа обходит блокировки своих загрузок: защищённый DNS, страница входа Wi-Fi, точность часов."""
    for url, host, ip in netutil.DOH_SERVERS:
        netutil._DOH_CACHE.clear()
        saved = netutil.DOH_SERVERS
        netutil.DOH_SERVERS = [(url, host, ip)]
        try:
            t0 = time.monotonic()
            got = netutil.doh_resolve("github.com", timeout=6)
            ms = int((time.monotonic() - t0) * 1000)
        finally:
            netutil.DOH_SERVERS = saved
        add("ok" if got else "warn", T(f"Защищённый DNS {host}", f"Secure DNS {host}"),
            T(f"отвечает, {ms} мс", f"answers, {ms} ms") if got else
            T("не отвечает — программа возьмёт другой", "no answer — the program uses another one"))
    netutil._DOH_CACHE.clear()
    captive = netutil.captive_portal()
    add("warn" if captive else "ok", T("Страница входа Wi-Fi", "Wi-Fi login page"),
        T("сеть просит войти — открой браузер", "the network asks you to sign in — open the browser") if captive
        else T("нет", "none"))
    skew = netutil.clock_skew()
    if skew is None:
        add("info", T("Точность часов не проверить", "Clock accuracy can't be checked"))
    else:
        add("ok" if abs(skew) <= 120 else "error", T("Часы компьютера", "Computer clock"),
            T(f"расхождение {int(skew)} с", f"{int(skew)} s off"))


# ---------- обновление программы ----------

def check_signature() -> None:
    n, e, d = _test_key()
    manifest = {"version": "99.0.0", "notes": "проверка", "pc": {"url": "https://example.invalid/a.zip", "sha256": "0" * 64}}
    signed = update.pack(manifest, n, d)
    good = update.unpack(signed, {"n": n, "e": e})
    forged = update.unpack(dict(signed, payload=signed["payload"].replace("99.0.0", "99.0.1")), {"n": n, "e": e})
    add("ok" if good and good.get("version") == "99.0.0" and forged is None else "error",
        T("Подпись выпуска: настоящая принимается, подделка — нет", "Release signature: genuine accepted, forged rejected"))


def _is_prime(n: int) -> bool:
    import secrets as _s
    if n < 4:
        return n in (2, 3)
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(24):
        x = pow(_s.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _test_key() -> tuple[int, int, int]:
    """Небольшой ключ RSA (1024 бита) только для этой проверки — создаётся заново за секунду-две."""
    import secrets as _s
    e = 65537

    def prime() -> int:
        while True:
            c = _s.randbits(512) | (1 << 511) | 1
            if _is_prime(c):
                return c
    while True:
        p, q = prime(), prime()
        phi = (p - 1) * (q - 1)
        if p != q and phi % e:
            return p * q, e, pow(e, -1, phi)


def check_release(info: dict, http_port: int) -> None:
    if not update.configured():
        add("info", T("Автообновление ещё не настроено (нет своего репозитория) — проверится после выпуска",
                      "Auto-update not configured yet (no own repository) — checked after a release"))
        return
    try:
        manifest = update.fetch_manifest(http_port if info.get("connected") else None)
        add("ok", T("Файл выпуска скачан, подпись верна", "Release file downloaded, signature valid"),
            T(f"версия {manifest.get('version')}, у тебя {APP_VERSION}", f"version {manifest.get('version')}, yours {APP_VERSION}"))
    except Exception as exc:
        add("error", T("Файл выпуска не проверился", "Release file failed the check"), str(exc)[:200])


# ---------- отчёт ----------

MANUAL = [
    ("Горячая клавиша: нажми Ctrl+Alt+V (или своё сочетание) — VPN включится или выключится, у часов появится сообщение.",
     "Hotkey: press Ctrl+Alt+V (or yours) — the VPN toggles and a tray message appears."),
    ("Значок у часов → «Включить на 1 час»: на главной появится время, когда VPN выключится.",
     "Tray icon → “Turn on for 1 hour”: the main screen shows when the VPN turns off."),
    ("Пин-код: «Настройки → Конфиденциальность → Поставить пин-код», закрой окно, через 15 секунд открой — должно спросить пин-код.",
     "PIN: Settings → Privacy → Set PIN, close the window, reopen after 15 s — it must ask for the PIN."),
    ("Kill switch: включи в «Функции → Защита», подключись и выдерни интернет на минуту: заблокированные сайты не должны открыться напрямую.",
     "Kill switch: enable in Features → Protection, connect and drop the internet for a minute: blocked sites must not open directly."),
    ("Мгновенное переключение: в журнале при подключении нет строки «Ядро не поддерживает мгновенное переключение».",
     "Instant failover: the log has no line “core does not support instant failover” after connecting."),
    ("Приложения: «Свои правила → Приложения» → Discord «Подобрать». В режиме TUN Discord должен открываться.",
     "Apps: My rules → Apps → Discord “Pick”. In TUN mode Discord must open."),
    ("Сайт не догружается: открой такой сайт, затем «Сервисы и сайты → Проверить сайт → Сайт работает не полностью».",
     "Site loads partly: open it, then Services and sites → Check site → Site works partly."),
    ("Свой сервер: «Поделиться → Свой сервер → Проверить» — откроется окно ssh, после пароля появится состояние сервера.",
     "Own server: Share → Your own server → Check — an ssh window opens, after the password the status appears."),
    ("Проверка утечек: «Настройки → Проверка утечек» при включённом VPN — красных пунктов быть не должно.",
     "Leak test: Settings → Leak test with VPN on — no red items."),
]


def save_report(info: dict) -> str:
    errors = sum(1 for r in RESULTS if r["level"] == "error")
    warns = sum(1 for r in RESULTS if r["level"] == "warn")
    marks = {"ok": "[OK]", "info": "[i]", "warn": "[!]", "error": "[ОШИБКА]" if i18n.lang() == "ru" else "[ERROR]",
             "skip": "[-]"}
    lines = [f"VEDOMYJ VPN {APP_VERSION} — {T('проверка новых функций', 'new features check')} {time.strftime('%Y-%m-%d %H:%M')}",
             f"{platform.system()} {platform.release()} ({platform.machine()}), Python {platform.python_version()}",
             T("Программа: ", "Program: ") + (T("не запущена", "not running") if not info.get("running") else
                                               T("заперта пин-кодом", "locked with PIN") if info.get("locked") else
                                               T("подключена", "connected") if info.get("connected") else T("запущена, не подключена", "running, not connected")),
             T(f"Ошибок: {errors}, предупреждений: {warns}", f"Errors: {errors}, warnings: {warns}")]
    sec = ""
    for r in RESULTS:
        if r["section"] != sec:
            sec = r["section"]
            lines += ["", sec]
        lines.append(f"{marks.get(r['level'], '[?]')} {r['title']}" + (f" — {r['detail']}" if r["detail"] else ""))
    lines += ["", T("Проверь руками (это автоматически не проверить):", "Check by hand (cannot be automated):")]
    lines += [f"{i}. {T(ru, en)}" for i, (ru, en) in enumerate(MANUAL, 1)]
    try:  # журнал подключения: сколько раз программа сама переподключала и почему (главное для «лагает»)
        from pult import journal
        items = journal.read(os.path.join(APP_DIR, "data"))
        if items:
            lines += [""] + journal.report_lines(items, i18n.tr, n=60)
    except Exception:
        pass
    secrets = set()
    try:
        from pult.engine import Engine
        e = Engine(APP_DIR, lambda *a, **k: None)
        e.load_cached()
        secrets = diagnostics.secrets_of(e)
    except Exception:
        pass
    text = diagnostics.scrub("\n".join(lines), secrets)
    folder = os.path.join(APP_DIR, "data", "reports")
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, f"field-check-{time.strftime('%Y%m%d-%H%M%S')}.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text + "\n")
    return path


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    s_path = os.path.join(APP_DIR, "data", "settings.json")
    try:
        with open(s_path, encoding="utf-8") as f:
            lang = json.load(f).get("lang", "ru")
    except (OSError, ValueError):
        lang = "ru"
    i18n.set_lang(lang or "ru")
    print(T("Проверяю новые функции VEDOMYJ VPN на этом компьютере. Это займёт 1–3 минуты…",
            "Checking VEDOMYJ VPN new features on this computer. This takes 1–3 minutes…"))
    info = app_info()
    try:
        with open(s_path, encoding="utf-8") as f:
            http_port = int(json.load(f).get("http_port", settingsmod.DEFAULTS["http_port"]))
    except (OSError, ValueError):
        http_port = int(settingsmod.DEFAULTS["http_port"])
    paths = xray.Paths(APP_DIR)
    xray.WIPE_CONFIGS = True

    if CI:
        section(T("Скачивание ядер", "Downloading cores"))
        guard(T("Скачивание ядер", "Downloading cores"), lambda: download_cores(paths))

    section(T("Ядро Xray: принимает ли новые настройки", "Xray core: does it accept the new settings"))
    if paths.xray_exists():
        guard(T("Ядро Xray", "Xray core"), lambda: check_core(paths, paths.xray, T("Ядро", "Core")))
        guard(T("Правила на лету", "Live rules"), lambda: check_live_rules(paths))
        guard(T("Страница метрик", "Metrics page"), lambda: check_metrics(paths))
    else:
        add("warn", T("Ядро Xray ещё не скачано — запусти программу один раз", "Xray core not downloaded yet — start the program once"))
    if paths.legacy_exists():
        guard(T("Совместимое ядро", "Compatible core"),
              lambda: check_core(paths, paths.legacy_xray, T("Совместимое ядро", "Compatible core"), legacy=True))
    guard("sing-box", lambda: check_singbox(paths))

    section(T("Движки: Hysteria2, TUIC, AmneziaWG", "Engines: Hysteria2, TUIC, AmneziaWG"))
    if paths.xray_exists():
        guard(T("Движки в ядре Xray", "Engines in the Xray core"), lambda: check_engines(paths, paths.xray))
        guard(T("Способы для Xray (1.20)", "Xray methods (1.20)"), lambda: check_xray_methods(paths, paths.xray))
    guard(T("Отпечаток сертификата", "Certificate pin"), check_certpin)
    if IS_WINDOWS:
        guard("AmneziaWG", lambda: check_awg(paths, live=CI))
    guard("WARP", lambda: check_warp_xray(paths, check_warp(paths, live=CI and IS_WINDOWS)) if paths.xray_exists()
          else check_warp(paths, live=CI and IS_WINDOWS))
    if paths.xray_exists():
        guard(T("DNS-туннель", "DNS tunnel"), lambda: check_xdns(paths))
        guard(T("Свой протокол", "Own protocol"), lambda: check_proto(paths))
    guard(T("Семья: сеть торрентов", "Family: torrent network"), check_dht)

    section(T("Windows", "Windows"))
    guard("DPAPI", check_dpapi)
    guard(T("Горячая клавиша", "Hotkey"), lambda: check_hotkey(info))
    guard("Wi-Fi", check_wifi)
    guard(T("Приложения", "Apps"), check_apps)

    if CI:  # облако GitHub — не сеть провайдера, а файла выпуска у нового репозитория может ещё не быть
        guard(T("Подпись выпуска", "Release signature"), check_signature)
        errors = [r for r in RESULTS if r["level"] == "error"]
        print("\n" + T(f"Готово. Ошибок: {len(errors)}. Отчёт: ", f"Done. Errors: {len(errors)}. Report: ")
              + save_report(info))
        sys.exit(1 if errors else 0)

    section(T("Сеть и провайдер", "Network and ISP"))
    online = False
    try:
        online = check_direct()
    except Exception as exc:
        add("error", T("Интернет напрямую", "Direct internet"), str(exc)[:200])
    if online:
        guard(T("Замирание соединений", "Connection stalls"), lambda: check_stall(None))
        if info.get("connected"):
            guard(T("Замирание через VPN", "Stalls via VPN"), lambda: check_stall(http_port))
        guard(T("Утечки", "Leaks"), lambda: check_leaks(info, http_port))
    else:
        add("skip", T("Без интернета сетевые проверки пропущены", "No internet — network checks skipped"))
    # защищённый DNS проверяем и без «обычного» интернета: им программа обходит как раз DNS провайдера
    guard(T("Обход блокировок", "Bypass"), check_bypass)
    if not info.get("running"):
        add("info", T("Программа не запущена: проверки через VPN пропущены. Запусти её, подключись и проверь ещё раз.",
                      "The program isn't running: VPN checks skipped. Start it, connect and run again."))
    elif not info.get("connected"):
        add("info", T("Программа не подключена: проверки через VPN пропущены.", "The program isn't connected: VPN checks skipped."))

    section(T("Обновление программы", "Program updates"))
    guard(T("Подпись выпуска", "Release signature"), check_signature)
    guard(T("Файл выпуска", "Release file"), lambda: check_release(info, http_port))

    path = save_report(info)
    if "--json" in sys.argv:  # для «Полной проверки»: итоги одной строкой; ключи и адреса она вычищает ещё раз сама
        print(json.dumps({"path": path, "results": [dict(r, title=diagnostics.scrub(r["title"], set()),
                                                         detail=diagnostics.scrub(r["detail"], set()))
                                                    for r in RESULTS]}, ensure_ascii=False))
        return
    errors = sum(1 for r in RESULTS if r["level"] == "error")
    print("\n" + T(f"Готово. Ошибок: {errors}. Отчёт: ", f"Done. Errors: {errors}. Report: ") + path)
    print(T("В нём нет ссылок, ключей, адресов и названий сетей — его можно отправить нейросети.",
            "It has no links, keys, addresses or network names — you can send it to the AI."))
    if IS_WINDOWS and "--no-open" not in sys.argv:
        subprocess.Popen(f'explorer /select,"{path}"')


if __name__ == "__main__":
    main()
