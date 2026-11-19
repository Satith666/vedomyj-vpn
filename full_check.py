"""Полная проверка VEDOMYJ VPN на этом компьютере. Запуск: «Полная проверка.bat» (или python full_check.py).

Проверяет всё по очереди: код программы, установку и настройки, функции Windows, блокировки в этой сети
и сам VPN под настоящей нагрузкой (идут ли данные, скорость, отпечатки TLS, UDP). Ничего не меняет в настройках
и не трогает системный прокси. Занимает 5–10 минут.

Ключи:
  --quick    без самопроверки кода и функций Windows (2–4 минуты)
  --no-net   не проверять заблокированные сайты напрямую (провайдер увидит попытки зайти на них)
  --no-open  не открывать папку с отчётом в конце
"""

import json
import os
import subprocess
import sys
import urllib.request

APP_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, APP_DIR)

from pult import fullcheck, i18n  # noqa: E402
from pult.diagnostics import T  # noqa: E402
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


def main(args: list[str]) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    engine = Engine(APP_DIR, lambda *a, **k: None)
    i18n.set_lang(engine.settings.get("lang", "ru"))
    engine.load_cached()  # без фоновых задач и без изменения системных настроек
    quick = "--quick" in args
    print(T("Полная проверка VEDOMYJ VPN. " + ("Это займёт 2–4 минуты…" if quick else "Это займёт 5–10 минут…"),
            "VEDOMYJ VPN full check. " + ("This takes 2–4 minutes…" if quick else "This takes 5–10 minutes…")))
    print(T("Настройки не меняются, системный прокси не трогается.", "Settings aren't changed, the system proxy isn't touched."))
    report = fullcheck.run(engine, APP_DIR, quick=quick, network="--no-net" not in args,
                           app_running=app_running(), progress=print)
    print("\n" + "=" * 60)
    print(T(f"Итог: ошибок {report['errors']}, предупреждений {report['warnings']}",
            f"Result: {report['errors']} errors, {report['warnings']} warnings"))
    for line in report["summary"]:
        print("  " + line)
    if report.get("path"):
        print("\n" + T("Отчёт: ", "Report: ") + report["path"])
        print(T("В нём нет ссылок, ключей и адресов — его можно отправить в Telegram или нейросети.",
                "It has no links, keys or addresses — you can send it to Telegram or an AI."))
        if sys.platform == "win32" and "--no-open" not in args:
            subprocess.Popen(f'explorer /select,"{report["path"]}"')  # показать файл в Проводнике
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
