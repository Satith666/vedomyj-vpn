"""Полная проверка VEDOMYJ VPN на этом компьютере. Запуск: Проверка.bat (или python check.py).

Проверяет код (самопроверка на имитации серверов), ядро Xray, списки сайтов, порты, системный прокси,
интернет, подписки, серверы и сервисы. Ничего не меняет в настройках. Отчёт сохраняется в data/reports.
Если программа уже запущена, удобнее нажать «Проверка программы» в её настройках — тогда проверятся и сервисы через VPN.
"""

import json
import os
import sys
import urllib.request

APP_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, APP_DIR)

from pult import diagnostics, i18n  # noqa: E402
from pult.engine import Engine  # noqa: E402


def app_running() -> bool:
    try:
        with open(os.path.join(APP_DIR, "data", "ui.json"), encoding="utf-8") as f:
            info = json.load(f)
        req = urllib.request.Request(f"http://127.0.0.1:{info['port']}/api/ping", headers={"X-Token": info["token"]})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=2) as resp:
            return resp.status == 200
    except Exception:
        return False


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    engine = Engine(APP_DIR, lambda *a, **k: None)
    i18n.set_lang(engine.settings.get("lang", "ru"))
    engine.load_cached()  # без запуска фоновых задач и без изменения системных настроек
    running = app_running()
    print(diagnostics.T("Проверяю VEDOMYJ VPN… Это займёт до пары минут.", "Checking VEDOMYJ VPN… This takes up to a couple of minutes."))
    report = diagnostics.run(engine, progress=lambda text: print("  " + text), app_running=running)
    print("\n" + report["text"].split("\n\n")[0] + "\n")
    for item in report["items"]:
        mark = {"ok": "  OK ", "info": "  i  ", "warn": "  !  ", "error": " ERR "}.get(item["level"], "  ?  ")
        print(f"{mark} {item['title']}" + (f" — {item['detail']}" if item["detail"] else ""))
    if report.get("path"):
        print("\n" + diagnostics.T("Отчёт сохранён: ", "Report saved: ") + report["path"])
        print(diagnostics.T("В нём нет ссылок, ключей и адресов — перетащи этот файл в Telegram и отправь.",
                            "It has no links, keys or addresses — drag this file into Telegram and send it."))
        if sys.platform == "win32" and "--no-open" not in sys.argv:
            import subprocess
            subprocess.Popen(f'explorer /select,"{report["path"]}"')  # показать файл в Проводнике


if __name__ == "__main__":
    main()
