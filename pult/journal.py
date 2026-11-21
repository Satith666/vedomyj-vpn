"""Журнал подключения: когда, что и почему программа подключила, переключила или отключила.

Нужен, чтобы понять «почему лагает»: если VPN сам переподключается, здесь видно, кто это сделал
(ты, автопилот, сторож данных, смена сети…) и по какой причине. Хранится в data/journal.jsonl,
последние 300 записей. Адресов, ключей и ссылок в нём нет — только названия серверов (их тоже
прячет отчёт, если в названии есть адрес).
"""

from __future__ import annotations

import collections
import json
import os
import threading
import time

KEEP = 300

# что произошло → короткое слово для окна и отчёта
KINDS = {
    "connect": "Подключение",
    "switch": "Смена сервера",
    "hotswap": "Смена сервера без перезапуска",
    "reconnect": "Переподключение",
    "disconnect": "Отключение",
    "fail": "Не удалось подключиться",
}


class Journal:
    def __init__(self, data_dir: str):
        self.path = os.path.join(data_dir, "journal.jsonl")
        self.items: collections.deque = collections.deque(maxlen=KEEP)
        self._lock = threading.Lock()
        self._writes = 0
        try:
            with open(self.path, encoding="utf-8") as f:
                for line in f:
                    try:
                        item = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(item, dict) and item.get("kind") in KINDS:
                        self.items.append(item)
        except OSError:
            pass

    def add(self, kind: str, server: str = "", who: str = "", why: str = "", engine: str = "") -> dict:
        item = {"t": round(time.time(), 1), "kind": kind, "server": server[:80], "who": who[:80],
                "why": why[:200], "engine": engine}
        with self._lock:
            self.items.append(item)
            self._writes += 1
            try:
                if self._writes >= 50:  # время от времени переписываем файл, чтобы он не рос
                    self._writes = 0
                    tmp = self.path + ".tmp"
                    with open(tmp, "w", encoding="utf-8") as f:
                        for it in self.items:
                            f.write(json.dumps(it, ensure_ascii=False) + "\n")
                    os.replace(tmp, self.path)
                else:
                    with open(self.path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(item, ensure_ascii=False) + "\n")
            except OSError:
                pass
        return item

    def recent(self, n: int = 50) -> list[dict]:
        with self._lock:
            return list(self.items)[-n:][::-1]

    def count(self, kinds: tuple, seconds: float, auto_only: bool = True) -> int:
        """Сколько раз за последние seconds секунд было kinds (по умолчанию — только сделанное программой сама)."""
        since = time.time() - seconds
        with self._lock:
            return sum(1 for it in self.items if it["t"] >= since and it["kind"] in kinds
                       and not (auto_only and it.get("who") == "user"))


def report_lines(items: list[dict], tr=lambda s: s, n: int = 40) -> list[str]:
    """Строки для отчёта: сводка (сколько раз программа сама переподключала) и последние записи."""
    now = time.time()
    auto = [it for it in items if it.get("who") != "user" and it.get("kind") in ("switch", "hotswap", "reconnect", "fail")]
    hour = sum(1 for it in auto if now - it["t"] < 3600)
    day = sum(1 for it in auto if now - it["t"] < 86400)
    lines = [tr("Журнал подключения") + f": {len(items)} " + tr("записей") + "; " + tr("сама программа") +
             f" — {hour} " + tr("за час") + f", {day} " + tr("за сутки")]
    for it in sorted(items, key=lambda x: x["t"], reverse=True)[:n]:
        who = tr("ты") if it.get("who") == "user" else tr(it.get("who") or "программа")
        line = time.strftime("%d.%m %H:%M:%S", time.localtime(it["t"])) + "  " + tr(KINDS.get(it["kind"], it["kind"]))
        if it.get("server"):
            line += f" — {it['server']}"
        line += f" ({who})"
        if it.get("why"):
            line += f": {tr(it['why'])}"
        lines.append(line)
    return lines


def read(data_dir: str) -> list[dict]:
    """Журнал с диска — для отчёта «Проверка новых функций», когда программа не запущена."""
    return Journal(data_dir).recent(KEEP)
