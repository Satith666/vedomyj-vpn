"""Свой сервер по-настоящему (для GitHub, Ubuntu, sudo): скрипт мастера ставит Xray на эту машину, программа
подключается по своим ссылкам; потом рядом запускается мост (настройки — те же, что пишет скрипт моста) и
подключение идёт через него на «основной» сервер. Печатает [OK]/[FAIL] и выходит с ошибкой, если что-то не так.

Запуск: sudo python3 build/server_check.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from pult import links, vps  # noqa: E402

XRAY = "/usr/local/bin/xray"
ENV = dict(os.environ, XRAY_LOCATION_ASSET="/usr/local/share/xray")
URL = "https://www.gstatic.com/generate_204"
fails: list[str] = []


def ok(cond: bool, title: str, detail: str = "") -> None:
    print(("[OK]   " if cond else "[FAIL] ") + title + (f" — {detail}" if detail else ""), flush=True)
    if not cond:
        fails.append(title)


def via_proxy(port: int, url: str = URL, timeout: float = 15.0) -> int:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}",
                                                                      "https": f"http://127.0.0.1:{port}"}))
    try:
        with opener.open(url, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except OSError:
        return 0


def run_xray(cfg: dict, name: str) -> subprocess.Popen:
    path = os.path.join(tempfile.gettempdir(), f"server-check-{name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    test = subprocess.run([XRAY, "run", "-test", "-c", path], capture_output=True, text=True, env=ENV)
    ok(test.returncode == 0, f"Xray принимает настройки: {name}", (test.stdout + test.stderr).strip()[-300:] if test.returncode else "")
    proc = subprocess.Popen([XRAY, "run", "-c", path], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=ENV)
    time.sleep(2)
    return proc


def client(link: str, port: int, name: str) -> subprocess.Popen:
    srv = links.parse_link(link)
    ob = dict(srv.outbound, tag="proxy")
    return run_xray({"log": {"loglevel": "warning"},
                     "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": port, "protocol": "http", "settings": {}}],
                     "outbounds": [ob, {"tag": "direct", "protocol": "freedom"}],
                     "routing": {"rules": [{"type": "field", "inboundTag": ["in"], "outboundTag": "proxy"}]}}, name)


def sh(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, timeout=120)


def awg_client(idx: int, conf: str) -> bool:
    """Устройство в отдельном сетевом пространстве (как другой компьютер): туннель и ping сервера AmneziaWG."""
    ns, net = f"awgc{idx}", f"10.20{idx}.0"
    sh(f"ip netns add {ns}; ip link add vh{idx} type veth peer name vc{idx}; ip link set vc{idx} netns {ns}; "
       f"ip addr add {net}.1/24 dev vh{idx}; ip link set vh{idx} up; "
       f"ip netns exec {ns} ip addr add {net}.2/24 dev vc{idx}; ip netns exec {ns} ip link set vc{idx} up; "
       f"ip netns exec {ns} ip link set lo up")
    conf = conf.replace("AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 10.66.66.1/32")
    conf = "\n".join(ln for ln in conf.splitlines() if not ln.startswith("DNS ="))
    conf = __import__("re").sub(r"Endpoint = [^\n]+:", f"Endpoint = {net}.1:", conf)
    path = f"/tmp/{ns}.conf"
    with open(path, "w") as f:
        f.write(conf + "\n")
    os.chmod(path, 0o600)
    up = sh(f"ip netns exec {ns} awg-quick up {path}")
    if up.returncode:
        print(up.stdout[-500:], up.stderr[-500:])
    ping = sh(f"ip netns exec {ns} ping -c 3 -W 3 10.66.66.1")
    return ping.returncode == 0


def awg_check() -> None:
    """AmneziaWG 2.0: скрипт программы ставит его на эту машину, два устройства (компьютер и «роутер»)
    подключаются со своими ключами и видят сервер через туннель."""
    from pult import warp
    params = vps.awg_params()
    priv, pub = warp.keypair()
    out = subprocess.run(["bash", "-s"], input=vps.awg_script(pub, 45123, params), capture_output=True, text=True,
                         timeout=1500)
    res = next((ln[12:] for ln in out.stdout.splitlines() if ln.startswith("PULT_RESULT:")), "")
    err = next((ln[11:] for ln in out.stdout.splitlines() if ln.startswith("PULT_ERROR:")), "")
    ok(bool(res), "AmneziaWG 2.0 установлен скриптом программы", vps.ERRORS.get(err, err) or out.stderr[-300:])
    if not res:
        print(f"       ядро: {os.uname().release}, шаг: {err or '?'}")
        for ln in out.stdout.splitlines():
            if ln.startswith("PULT_LOG:"):
                print("       | " + ln[9:][:200])
        return
    spub, port, n = vps.parse_awg_result(res)
    conf = vps.awg_client_conf("203.0.113.1", port, spub, priv, n, params, warp.DNS_YANDEX_I1)
    ok(awg_client(1, conf), "Устройство 1 (этот компьютер) видит сервер через AmneziaWG 2.0")
    priv2, pub2 = warp.keypair()
    out = subprocess.run(["bash", "-s"], input=vps.awg_peer_script(pub2), capture_output=True, text=True, timeout=120)
    res = next((ln[12:] for ln in out.stdout.splitlines() if ln.startswith("PULT_RESULT:")), "")
    ok(bool(res), "Устройство для роутера добавлено на сервер", out.stdout[-300:])
    if res:
        spub2, port2, n2 = vps.parse_awg_result(res)
        conf2 = vps.awg_client_conf("203.0.113.1", port2, spub2, priv2, n2, params, warp.DNS_YANDEX_I1)
        ok(spub2 == spub and n2 == 3 and awg_client(2, conf2), "Устройство 2 («роутер») видит сервер со своим ключом", f"адрес {n2}")
    show = sh("awg show awg0")
    ok("peer:" in show.stdout and show.stdout.count("peer:") == 2, "На сервере два устройства", str(show.stdout.count("peer:")))


def main() -> int:
    if os.geteuid() != 0:
        print("Нужен root: sudo python3 build/server_check.py")
        return 2
    # 1. скрипт мастера — как на настоящем сервере
    out = subprocess.run(["bash", "-s"], input=vps.script(), capture_output=True, text=True, timeout=900)
    res = next((ln[12:] for ln in out.stdout.splitlines() if ln.startswith("PULT_RESULT:")), "")
    err = next((ln[11:] for ln in out.stdout.splitlines() if ln.startswith("PULT_ERROR:")), "")
    ok(bool(res), "Скрипт мастера поставил Xray и прислал ключи", err or out.stderr[-300:])
    if not res:
        return 1
    main_links = vps.make_links("127.0.0.1", res, "CI")
    procs = []
    try:
        for i, link in enumerate(main_links):
            procs.append(client(link, 20800 + i, f"клиент {i + 1}"))
            code = via_proxy(20800 + i)
            ok(code == 204, f"Подключение к своему серверу ({'TCP' if i == 0 else 'XHTTP'})", f"ответ {code}")
        # 2. мост: те же настройки, что пишет скрипт моста, — на соседних портах этой же машины
        uuid = subprocess.run([XRAY, "uuid"], capture_output=True, text=True).stdout.strip()
        keys = subprocess.run([XRAY, "x25519"], capture_output=True, text=True).stdout
        priv = next(ln.split(":", 1)[1].strip() for ln in keys.splitlines() if "private" in ln.lower())
        pub = next(ln.split(":", 1)[1].strip() for ln in keys.splitlines()
                   if ("public" in ln.lower() or "password" in ln.lower()) and "private" not in ln.lower())
        fwd = vps.parse_forward(main_links[0])
        cfg = vps.bridge_config(uuid, priv, "ab12cd34", "b1d9e", fwd, port_tcp=21443, port_xhttp=21444, listen="127.0.0.1")
        procs.append(run_xray(cfg, "мост"))
        blink = vps.make_links("127.0.0.1", f"{uuid}|{pub}|ab12cd34|b1d9e", "Мост", vps.RU_SNI)
        blink = [x.replace(":443?", ":21443?").replace(":8443?", ":21444?") for x in blink]
        for i, link in enumerate(blink):
            procs.append(client(link, 20900 + i, f"клиент моста {i + 1}"))
            code = via_proxy(20900 + i)
            ok(code == 204, f"Подключение через мост на свой сервер ({'TCP' if i == 0 else 'XHTTP'})", f"ответ {code}")
        code = via_proxy(20900, "https://ya.ru/")
        ok(code in (200, 301, 302, 403), "Российский сайт через мост открывается (напрямую с моста)", f"ответ {code}")
    finally:
        for p in procs:
            p.terminate()
    awg_check()
    print(f"\nОшибок: {len(fails)}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
