"""Настоящая проверка подключения целиком: программа (Engine) + настоящее ядро Xray + свои серверы VLESS на этой
же машине. Ловит то, чего не видно в проверке настроек (xray -test) и в самопроверке на заглушках: ядро или движок
TUN падают через несколько секунд после подключения, «подключено», а сайты не открываются.

Серверы — настоящий Xray на 127.0.0.1: VLESS + REALITY + Vision (как у большинства подписок) и VLESS без шифрования
(запасной для «мгновенного переключения»). Ключи создаются на месте, наружу ничего не уходит.

Настройки — как у человека из отчёта: «всё через VPN», российские напрямую, системный прокси, маскировка сама,
белые списки сами, мультисервер, мгновенное переключение, без автопилота. Круги:
  proxy                — без TUN;
  tun-xray / tun-singbox / tun-tun2proxy — режим TUN каждым движком (только Windows, нужны права администратора).
В каждом круге: подключение через Engine.connect, потом ~75 секунд каждые 3 секунды запрос к сайту (в TUN — без
прокси, как браузер), живы ли ядро и движок TUN, что в «проблемах» и журнале подключения. Если круг не прошёл —
он повторяется без «мгновенного переключения» и с ядром Xray v26.10.31: так видно, кто виноват.
В конце — «Автонастройка» целиком.

Запуск: python build/e2e_live.py [--rounds proxy,tun-xray] [--seconds 75]. Код выхода 1 — если основной круг
(proxy, а на Windows ещё и TUN) не прошёл. Отчёт: e2e-report.txt рядом с программой.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.request
import uuid as uuidmod
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from pult import APP_VERSION, netutil, xray  # noqa: E402
from pult import engine as engmod  # noqa: E402

IS_WINDOWS = sys.platform == "win32"
EXE = "xray.exe" if IS_WINDOWS else "xray"
OLD_CORE = "v26.10.31"
PROBE = "http://www.gstatic.com/generate_204"
REPORT: list[str] = []
FAILS: list[str] = []


def say(text: str = "") -> None:
    print(text, flush=True)
    REPORT.append(text)


# ---------- ядро и серверы ----------

def core_dir(tag: str) -> str:
    """Папка с ядром: «latest» — то, что скачивает программа; иначе — конкретный выпуск."""
    folder = os.path.join(ROOT, "build", "e2e-cores", tag)
    if os.path.isfile(os.path.join(folder, EXE)):
        return folder
    os.makedirs(folder, exist_ok=True)
    if tag == "latest":
        repo_bin = os.path.join(ROOT, "bin")
        if os.path.isfile(os.path.join(repo_bin, EXE)):  # уже скачано проверкой на Windows (field_check.py)
            for name in os.listdir(repo_bin):
                if name == EXE or name.endswith(".dat") or name == xray.GEO_MARK:
                    shutil.copy2(os.path.join(repo_bin, name), folder)
            return folder
        url = "https://github.com/XTLS/Xray-core/releases/latest/download/" + xray.xray_zip_name()
    else:
        url = f"https://github.com/XTLS/Xray-core/releases/download/{tag}/" + xray.xray_zip_name()
    zpath = os.path.join(folder, "core.zip")
    netutil.download_file(url, zpath, timeout=120)
    with zipfile.ZipFile(zpath) as zf:
        for name in zf.namelist():
            if os.path.basename(name) in (EXE, "geosite.dat", "geoip.dat"):
                with zf.open(name) as src, open(os.path.join(folder, os.path.basename(name)), "wb") as dst:
                    dst.write(src.read())
    os.remove(zpath)
    if not IS_WINDOWS:
        os.chmod(os.path.join(folder, EXE), 0o755)
    return folder


def core_version(folder: str) -> str:
    out = subprocess.run([os.path.join(folder, EXE), "version"], capture_output=True, text=True, timeout=20).stdout
    m = re.search(r"Xray (\d+\.\d+\.\d+)", out)
    return m.group(1) if m else "?"


def x25519(folder: str) -> tuple[str, str]:
    out = subprocess.run([os.path.join(folder, EXE), "x25519"], capture_output=True, text=True, timeout=20).stdout
    priv = re.search(r"Private ?[Kk]ey:\s*(\S+)", out)
    pub = re.search(r"(?:Public ?[Kk]ey|Password(?: \(PublicKey\))?):\s*(\S+)", out)
    if not priv or not pub:
        raise RuntimeError("xray x25519: непонятный вывод")
    return priv.group(1), pub.group(1)


class Servers:
    """Два настоящих сервера Xray на 127.0.0.1 (REALITY + Vision и простой VLESS) — для одного ядра."""

    def __init__(self, folder: str, work: str):
        self.folder, self.work = folder, work
        self.procs: list[subprocess.Popen] = []
        self.uid = str(uuidmod.uuid4())
        self.sid = os.urandom(4).hex()
        self.priv, self.pub = x25519(folder)
        self.p1, self.p2 = netutil.find_free_ports(2, start=24600)

    def config(self, reality_key: str) -> dict:
        reality = {"show": False, reality_key: "www.microsoft.com:443", "serverNames": ["www.microsoft.com"],
                   "privateKey": self.priv, "shortIds": [self.sid]}
        return {"log": {"loglevel": "warning"},
                "inbounds": [
                    {"listen": "127.0.0.1", "port": self.p1, "protocol": "vless",
                     "settings": {"clients": [{"id": self.uid, "flow": "xtls-rprx-vision"}], "decryption": "none"},
                     "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": reality}},
                    {"listen": "127.0.0.1", "port": self.p2, "protocol": "vless",
                     "settings": {"clients": [{"id": self.uid}], "decryption": "none"},
                     "streamSettings": {"network": "tcp", "security": "none"}}],
                "outbounds": [{"protocol": "freedom", "tag": "out"}]}

    def start(self) -> None:
        path = os.path.join(self.work, "server.json")
        exe = os.path.join(self.folder, EXE)
        for key in ("target", "dest"):  # новое имя поля — target; старые ядра знают только dest
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.config(key), f)
            if subprocess.run([exe, "run", "-test", "-c", path], capture_output=True, timeout=20).returncode == 0:
                break
        log = open(os.path.join(self.work, "server.log"), "wb")
        self.procs.append(subprocess.Popen([exe, "run", "-c", path], stdout=log, stderr=subprocess.STDOUT,
                                           stdin=subprocess.DEVNULL))
        if not netutil.wait_ports([self.p1, self.p2], timeout=15):
            raise RuntimeError("серверы Xray не запустились: " + self.tail())

    def tail(self, n: int = 15) -> str:
        try:
            with open(os.path.join(self.work, "server.log"), encoding="utf-8", errors="replace") as f:
                return " | ".join(f.read().splitlines()[-n:])
        except OSError:
            return ""

    def links(self) -> list[str]:
        return [f"vless://{self.uid}@127.0.0.1:{self.p1}?type=tcp&security=reality&pbk={self.pub}&fp=chrome"
                f"&sni=www.microsoft.com&sid={self.sid}&flow=xtls-rprx-vision#E2E-Reality",
                f"vless://{self.uid}@127.0.0.1:{self.p2}?type=tcp&security=none#E2E-Plain"]

    def stop(self) -> None:
        for p in self.procs:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()


# ---------- программа ----------

USER_SETTINGS = dict(
    lang="ru", mode="vpn", ru_direct=True, system_proxy=True, leak_protection=True, dns_encrypted=False,
    block_ads=False, ads_without_vpn=True, mask_auto=True, whitelist_auto=True, autopilot=False, multi_enabled=True,
    zapret_enabled=False, byedpi_role="off", allow_lan=False, game_mode=False, auto_connect_on_start=False,
    autostart=False, background=True, auto_routes=True, auto_stall=True, failover=True, stall_check=True,
    warp_fallback=False, family_dht=False, collect_until=0,
)
# фоновые обновления (ядро, списки) во время проверки не нужны: ядро круга не должно смениться само
QUIET = ("last_core_check", "last_geo_check", "app_update_checked")


def make_engine(folder: str, links: list[str], tun_engine: str, failover: bool) -> tuple[engmod.Engine, str]:
    app = tempfile.mkdtemp(prefix="vedomyj-e2e-")
    os.makedirs(os.path.join(app, "bin"))
    for name in os.listdir(folder):
        if name == EXE or name.endswith(".dat") or name == xray.GEO_MARK:
            shutil.copy2(os.path.join(folder, name), os.path.join(app, "bin", name))
    for sub in ("singbox", "tun2proxy"):  # движки TUN скачиваются один раз на все круги
        src = os.path.join(ROOT, "build", "e2e-cores", sub)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(app, "bin", sub), dirs_exist_ok=True)
    events: list = []
    e = engmod.Engine(app, lambda ev, **d: events.append((ev, d)))
    socks, http = netutil.find_free_ports(2, start=25800)
    e.settings.update(USER_SETTINGS, socks_port=socks, http_port=http, manual_links=list(links),
                      tun_enabled=bool(tun_engine), tun_engine=tun_engine or "auto", failover=failover,
                      **{k: time.time() for k in QUIET})
    e.save()
    e.events = events
    return e, app


def keep_tun_engines(app: str) -> None:
    """Скачанные в круге sing-box и tun2proxy — в общую папку, чтобы следующие круги их не качали снова."""
    for sub in ("singbox", "tun2proxy"):
        src = os.path.join(app, "bin", sub)
        if os.path.isdir(src) and os.listdir(src):
            shutil.copytree(src, os.path.join(ROOT, "build", "e2e-cores", sub), dirs_exist_ok=True)


def probe(proxy_port: int | None) -> tuple[bool, str]:
    handlers = [urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"} if proxy_port else {})]
    opener = urllib.request.build_opener(*handlers)
    t0 = time.monotonic()
    try:
        with opener.open(PROBE, timeout=8) as r:
            ok = r.status in (200, 204)
            return ok, f"{r.status} за {int((time.monotonic() - t0) * 1000)} мс"
    except Exception as exc:  # noqa: BLE001 — в отчёт любую причину
        return False, f"{type(exc).__name__}: {str(exc)[:120]}"


def run_round(name: str, folder: str, links: list[str], seconds: int, failover: bool = True) -> bool:
    tun_engine = name[4:] if name.startswith("tun-") else ""
    title = f"{name} | ядро {core_version(folder)} | мгновенное переключение: {'да' if failover else 'нет'}"
    say(f"\n=== Круг: {title}")
    e, app = make_engine(folder, links, tun_engine, failover)
    ok_round = True
    try:
        e.startup()
        working = e.test_all()
        say(f"Проверка серверов: работают {working} из {len(e.servers)}")
        best = e.best()
        if not best:
            say("ОШИБКА: best() не выбрал сервер")
            return False
        e.connect(best)
        say(f"Подключено: {best.name}; TUN: {e.tun_active or 'нет'}; запасной: {e._failover_tag or 'нет'}")
        if tun_engine and e.tun_active != tun_engine:
            say(f"ОШИБКА: TUN не включился движком {tun_engine}: {e.tun_error}")
            ok_round = False
        good = bad = 0
        deaths = []
        t_end = time.monotonic() + seconds
        while time.monotonic() < t_end:
            port = None if e.tun_active else e.settings["http_port"]
            ok, detail = probe(port)
            good += ok
            bad += not ok
            core = e.proc.alive()
            tunp = e.tun_proc.alive() if e.tun_active in ("singbox", "tun2proxy") else True
            stamp = f"{seconds - int(t_end - time.monotonic()):>3} с"
            if not ok or not core or not tunp:
                say(f"  {stamp}: сайт {'да' if ok else 'НЕТ'} ({detail}); ядро {'живо' if core else 'УПАЛО'}; "
                    f"TUN {'жив' if tunp else 'УПАЛ'}; подключено {e.connected}")
            if not core or not tunp:
                deaths.append(stamp)
                lines = list(e.proc.lines)[-25:] if hasattr(e.proc, "lines") else []
                for ln in lines:
                    say("    ядро> " + ln[:300])
                if e.tun_active in ("singbox", "tun2proxy"):
                    say("    TUN> " + (e.tun_proc.error() or "без текста ошибки"))
            time.sleep(3)
        say(f"Запросы к сайту: удачных {good}, неудачных {bad}; падений: {len(deaths)}")
        probs = [f"{p['key']}: {p['title']} — {p['detail'][:200]}" for p in e.problems_list()]
        for p in probs:
            say("  проблема> " + p)
        for it in reversed(e.journal.recent(15)):
            say(f"  журнал> {it['kind']} {it['server']} ({it['who']}){': ' + it['why'] if it['why'] else ''}")
        crash = [ln for ln in e.logs if re.search(r"неожиданно|panic|fatal", ln, re.I)]
        for ln in crash[-10:]:
            say("  лог> " + ln[:300])
        if deaths or bad > max(2, (good + bad) // 5):
            ok_round = False
    except Exception as exc:  # noqa: BLE001
        say(f"ОШИБКА круга: {exc}")
        say(traceback.format_exc()[-1500:])
        ok_round = False
    finally:
        try:
            tail = [ln for ln in e.logs][-40:]
            if not ok_round:
                for ln in tail:
                    say("  лог> " + ln[:300])
            e.shutdown()
        except Exception as exc:  # noqa: BLE001
            say(f"(завершение: {exc})")
        keep_tun_engines(app)
        shutil.rmtree(app, ignore_errors=True)
    say(f"Итог круга {name}: {'ПРОШЁЛ' if ok_round else 'НЕ ПРОШЁЛ'}")
    return ok_round


def autosetup_round(folder: str, links: list[str]) -> bool:
    say("\n=== Автонастройка целиком (без TUN)")
    e, app = make_engine(folder, links, "", True)
    try:
        e.startup()
        e.settings["engine_pick"] = "awg"   # как после нажатия WARP / AmneziaWG: «Автонастройка» всё равно должна работать
        e.settings["conn_method"] = "awg"
        e.auto_setup()
        ok, detail = probe(e.settings["http_port"])
        say(f"Автонастройка: подключено {e.connected} ({e.current.name if e.current else '-'}); сайт: {detail}")
        return bool(e.connected and ok)
    except Exception as exc:  # noqa: BLE001
        say(f"ОШИБКА автонастройки: {exc}")
        for ln in list(e.logs)[-20:]:
            say("  лог> " + ln[:300])
        return False
    finally:
        try:
            e.shutdown()
        except Exception:  # noqa: BLE001
            pass
        shutil.rmtree(app, ignore_errors=True)


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = sys.argv[1:]
    seconds = int(args[args.index("--seconds") + 1]) if "--seconds" in args else 75
    rounds = args[args.index("--rounds") + 1].split(",") if "--rounds" in args else \
        (["proxy", "tun-xray", "tun-singbox", "tun-tun2proxy"] if IS_WINDOWS else ["proxy"])
    xray.WIPE_CONFIGS = False
    say(f"VEDOMYJ VPN {APP_VERSION} — настоящее подключение целиком ({sys.platform})")
    work = tempfile.mkdtemp(prefix="vedomyj-e2e-srv-")
    latest = core_dir("latest")
    srv = Servers(latest, work)
    srv.start()
    say(f"Серверы: REALITY + Vision и простой VLESS на 127.0.0.1, ядро {core_version(latest)}")
    results: dict[str, bool] = {}
    try:
        for name in rounds:
            ok = run_round(name, latest, srv.links(), seconds)
            results[name] = ok
            if ok:
                continue
            # не прошло — кто виноват: мгновенное переключение или новое ядро?
            results[name + " без мгновенного переключения"] = run_round(name, latest, srv.links(), seconds, failover=False)
            try:
                old = core_dir(OLD_CORE)
                results[f"{name} на ядре {OLD_CORE}"] = run_round(name, old, srv.links(), seconds)
            except Exception as exc:  # noqa: BLE001
                say(f"(ядро {OLD_CORE} не скачалось: {exc})")
        results["Автонастройка после WARP/AmneziaWG"] = autosetup_round(latest, srv.links())
    finally:
        srv.stop()
        say("\nСерверы: " + (srv.tail(8) or "без ошибок"))
        shutil.rmtree(work, ignore_errors=True)
    say("\n=== Итог")
    for k, v in results.items():
        say(f"{'OK  ' if v else 'FAIL'} {k}")
    with open(os.path.join(ROOT, "e2e-report.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(REPORT) + "\n")
    main_rounds = [k for k in results if k in rounds or k.startswith("Автонастройка")]
    sys.exit(0 if all(results[k] for k in main_rounds) else 1)


if __name__ == "__main__":
    main()
