"""Окно программы с имитацией ядра — для проверки интерфейса в настоящем браузере (build/ui_check.js).

Запуск: python3 build/ui_server.py — печатает {"port": …} и держит окно 5 минут. Ядро, серверы и сеть —
имитация из самопроверки (pult/selftest.py): 150 серверов, подключено, скорость меняется.
"""

import json
import os
import shutil
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from pult import netutil  # noqa: E402
from pult import selftest as st  # noqa: E402
from pult.engine import Engine  # noqa: E402
from pult.webui import UIServer  # noqa: E402
from urllib.parse import quote  # noqa: E402


def main() -> None:
    st.install_fakes()
    app = tempfile.mkdtemp(prefix="pult-ui-")
    os.makedirs(os.path.join(app, "bin"))
    open(os.path.join(app, "bin", "xray.exe" if sys.platform == "win32" else "xray"), "w").close()
    ui = UIServer(os.path.join(ROOT, "ui"), "tok")
    e = Engine(app, ui.notify)
    ui.engine = e
    e.settings.update(ping_host=f"127.0.0.1:{st.WEB}", socks_port=netutil.find_free_ports(1, 35000)[0],
                      http_port=netutil.find_free_ports(1, 35100)[0], system_proxy=False, autopilot=True, mode="vpn")
    port = ui.start()
    e.startup()
    q = "?security=reality&pbk=K&sni=a.com&type=tcp"
    names = ["🇳🇱 Amsterdam", "🇩🇪 Frankfurt", "🇫🇮 Helsinki", "🇸🇪 Stockholm", "🇱🇻 Riga", "🇵🇱 Warsaw"]
    lines = [f"vless://7{i:07d}-1111-4111-8111-111111111111@fast{i}.example:443{q}#{quote(names[i % 6] + f' {i}')}"
             for i in range(150)]
    e.add_servers("\n".join(lines))
    while e.is_busy():
        time.sleep(0.2)
    e.test_all()
    for attempt in range(3):
        # порты выбираем прямо перед подключением: на машине проверки порт могли занять, пока шла проверка серверов
        e.settings.update(socks_port=netutil.find_free_ports(1, 35000 + attempt * 300)[0],
                          http_port=netutil.find_free_ports(1, 35100 + attempt * 300)[0])
        e.run_task("Подключение", e.connect, e.best(), lane="conn", user=True)
        for _ in range(100):
            if e.connected and not e.conn_busy():
                break
            time.sleep(0.1)
        if e.connected:
            break
        print("не подключилось: " + " | ".join(p.get("title", "") for p in e.problems_list()), file=sys.stderr, flush=True)
    print(json.dumps({"port": port, "connected": e.connected}), flush=True)
    try:
        time.sleep(float(os.environ.get("UI_SERVER_SECONDS", "300")))
    finally:
        e.shutdown()
        shutil.rmtree(app, ignore_errors=True)


if __name__ == "__main__":
    main()
