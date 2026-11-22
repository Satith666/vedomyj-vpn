"""«Сбор ошибок»: на время (от 1 до 72 часов) программа складывает в файл всё, что пошло не так.

Пишется: каждая строка журнала программы, каждая новая проблема (жёлтый «!»), раз в 5 минут — короткое
состояние (подключено ли, способ, пинг, белые списки, на каком шаге лестница). Когда время вышло или
сбор остановили, получается один отчёт data/reports/errors-<дата>.txt: сводка, проблемы, сбои кода,
журнал подключения, состояние и журнал программы. В отчёте нет ссылок, ключей, адресов серверов и IP —
их вычищает scrub (тот же, что у журнала ошибок), поэтому отчёт можно присылать как есть.

Запуск: «Сбор ошибок.bat» (python main.py --collect 24), кнопка в «Профессиональных настройках» или
действие collect_start в окне. Сбор продолжается и после перезапуска программы, пока не выйдет время.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time

FILE = "collect.jsonl"
MAX_BYTES = 8 * 1024 * 1024      # больше не пишем строки журнала — только проблемы и состояние
SNAPSHOT_EVERY = 300             # с
HOURS_MIN, HOURS_MAX = 1, 72
REPORT_LOG_LINES = 4000

# строки журнала, которые в отчёте идут в «важное»
_IMPORTANT = re.compile(r"ошибк|не удалось|не отвеча|упал|останов|не подключ|не запуст|проблем|предохранит|"
                        r"автооткат|лестниц|автопилот|белые списки|тишин|не идут|сбой|exception|error|traceback",
                        re.I)


class CollectMixin:
    """Часть Engine. Использует: settings, save, log, tell, paths, problems, errors, journal, _scrub_secrets."""

    def _collect_init(self) -> None:
        self._collect_lock = threading.Lock()
        self._collect_secrets_at = 0.0
        self._collect_scrub_cache = None
        self._collect_bytes = 0
        self._collect_events = 0
        self._collect_finishing = False

    def _collect_path(self) -> str:
        return os.path.join(self.paths.data_dir, FILE)

    def collecting(self) -> bool:
        return float(self.settings.get("collect_until") or 0) > time.time()

    def _collect_scrub(self, text: str) -> str:
        """Чистка без лишней работы: список секретов обновляется не чаще раза в 2 минуты."""
        from . import diagnostics
        now = time.time()
        if self._collect_scrub_cache is None or now - self._collect_secrets_at > 120:
            self._collect_scrub_cache = diagnostics.secrets_of(self)
            self._collect_secrets_at = now
        return diagnostics.scrub(str(text), self._collect_scrub_cache)

    def collect_start(self, hours: float = 24) -> dict:
        try:
            hours = float(hours)
        except (TypeError, ValueError):
            hours = 24.0
        hours = max(HOURS_MIN, min(HOURS_MAX, hours))
        now = time.time()
        with self._collect_lock:
            self.settings["collect_until"] = now + hours * 3600
            self.settings["collect_started"] = now
            self._collect_bytes = 0
            self._collect_events = 0
            try:
                with open(self._collect_path(), "w", encoding="utf-8") as f:
                    f.write(json.dumps({"t": now, "k": "start", "hours": hours}, ensure_ascii=False) + "\n")
            except OSError as exc:
                self.log(f"Сбор ошибок: не удалось создать файл: {exc}")
        self.save()
        self.log(f"Сбор ошибок включён на {self._hours_text(hours)}. Отчёт появится сам, когда время выйдет.")
        self.notify("status")
        return self.collect_state()

    @staticmethod
    def _hours_text(hours: float) -> str:
        h = int(round(hours))
        if h % 10 == 1 and h % 100 != 11:
            return f"{h} час"
        if h % 10 in (2, 3, 4) and h % 100 not in (12, 13, 14):
            return f"{h} часа"
        return f"{h} часов"

    def _collect_add(self, kind: str, **data) -> None:
        if not self.collecting() or self._collect_finishing:
            return
        try:
            item = {"t": round(time.time(), 1), "k": kind}
            for k, v in data.items():
                item[k] = self._collect_scrub(v) if isinstance(v, str) else v
            line = json.dumps(item, ensure_ascii=False) + "\n"
            if kind == "log" and self._collect_bytes > MAX_BYTES:
                return
            with self._collect_lock:
                with open(self._collect_path(), "a", encoding="utf-8") as f:
                    f.write(line)
                self._collect_bytes += len(line.encode("utf-8"))
                self._collect_events += 1
        except Exception:
            pass  # сбор ошибок сам не должен ничего ломать

    def _collect_snapshot(self) -> None:
        cur = getattr(self, "current", None)
        self._collect_add("state", on=bool(self.connected), awg=bool(getattr(self, "awg_active", False)),
                          server=cur.name if cur and self.connected else "",
                          method=self.settings.get("engine_pick", "auto"), mode=self.settings.get("mode", ""),
                          ping=(getattr(self, "live", None) or {}).get("ping"), wl=bool(getattr(self, "whitelist_mode", False)),
                          step=getattr(self, "ladder_step", ""), problems=len(self.problems),
                          safe=bool(getattr(self, "safe_mode", False)),
                          dpi=str(getattr(self, "dpi_mode", "") or ""), tun=str(getattr(self, "tun_active", "") or ""),
                          ads=bool(self.settings.get("block_ads")),
                          net=str((getattr(self, "net_profile", None) or {}).get("kind") or ""),
                          sysproxy=bool(self.settings.get("system_proxy")))

    def collect_tick(self, tick: int) -> None:
        until = float(self.settings.get("collect_until") or 0)
        if not until:
            return
        if time.time() >= until:
            threading.Thread(target=self.collect_finish, args=("время вышло",), daemon=True).start()
            return
        if tick % SNAPSHOT_EVERY == 7:
            self._collect_snapshot()

    def collect_stop(self) -> str:
        return self.collect_finish("остановлен вручную")

    def _collect_read(self) -> list[dict]:
        out = []
        try:
            with open(self._collect_path(), encoding="utf-8") as f:
                for line in f:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        continue
        except OSError:
            pass
        return out

    def collect_finish(self, reason: str = "время вышло") -> str:
        """Собрать отчёт из накопленного и выключить сбор. Возвращает путь к отчёту ('' — сбор не шёл)."""
        if self._collect_finishing or not self.settings.get("collect_until"):
            return ""
        self._collect_finishing = True
        try:
            started = float(self.settings.get("collect_started") or 0)
            items = self._collect_read()
            path = self._collect_report(items, started, reason)
            self.settings["collect_until"] = 0
            self.settings["collect_report"] = path
            self.save()
            try:
                os.remove(self._collect_path())
            except OSError:
                pass
            if path:
                self.log(f"Сбор ошибок закончен ({reason}). Отчёт: {os.path.basename(path)} в папке data\\reports.")
                self.tell("Сбор ошибок закончен — отчёт готов (Дополнительно → Профессиональные → «Показать файл»).")
            self.notify("status")
            return path
        finally:
            self._collect_finishing = False

    def _collect_report(self, items: list[dict], started: float, reason: str) -> str:
        from . import APP_VERSION, journal
        fmt = lambda t: time.strftime("%d.%m %H:%M:%S", time.localtime(t))  # noqa: E731
        now = time.time()
        logs = [it for it in items if it.get("k") == "log"]
        probs = [it for it in items if it.get("k") == "problem"]
        states = [it for it in items if it.get("k") == "state"]
        crashes = [e for e in self.errors.recent(300) if float(e.get("last") or 0) >= started]
        jitems = [it for it in self.journal.recent(300) if it.get("t", 0) >= started]
        auto = [it for it in jitems if it.get("who") != "user" and it.get("kind") in ("switch", "hotswap", "reconnect", "fail")]
        important = [it for it in logs if _IMPORTANT.search(it.get("text", ""))]
        hours = max(0.0, (now - started) / 3600) if started else 0.0
        lines = [f"VEDOMYJ VPN {APP_VERSION} — сбор ошибок",
                 f"С {fmt(started) if started else '?'} по {fmt(now)} ({hours:.1f} ч); закончен: {reason}.", "",
                 "Итого:",
                 f"- новых проблем (жёлтый «!»): {len(probs)}",
                 f"- сбоев кода: {sum(1 for e in crashes if e.get('kind') == 'crash')}",
                 f"- автоматических переподключений и смен сервера: {len(auto)}",
                 f"- важных строк журнала: {len(important)} из {len(logs)}", ""]
        lines.append("Проблемы (по порядку):")
        lines += [f"- {fmt(it['t'])}  {it.get('title', '')}" + (f" — {it.get('detail')}" if it.get("detail") else "")
                  for it in probs] or ["- нет"]
        lines += ["", "Журнал ошибок за это время:"]
        for e in crashes:
            lines.append(f"- [{e.get('kind')}] {e.get('title', '')} (раз: {e.get('count', 1)}, "
                         f"последний: {fmt(float(e.get('last') or 0))})")
            if e.get("detail"):
                lines.append("  " + str(e["detail"])[:500].replace("\n", "\n  "))
            if e.get("trace"):
                lines.append("  " + str(e["trace"])[-1500:].replace("\n", "\n  "))
        if not crashes:
            lines.append("- пусто")
        lines += ["", "Журнал подключения:"] + (journal.report_lines(jitems, n=200)[1:] if jitems else ["- пусто"])
        lines += ["", "Состояние каждые 5 минут:"]
        for s in states:
            lines.append(f"- {fmt(s['t'])}  {'VPN вкл' if s.get('on') else 'VPN выкл'}"
                         + (", AmneziaWG" if s.get("awg") else "")
                         + (f", {s.get('server')}" if s.get("server") else "")
                         + f", способ {s.get('method')}"
                         + (", белые списки" if s.get("wl") else "")
                         + (f", лестница: {s.get('step')}" if s.get("step") else "")
                         + (f", проблем: {s.get('problems')}" if s.get("problems") else "")
                         + (f", ускорение: {s.get('dpi')}" if s.get("dpi") else "")
                         + (f", TUN: {s.get('tun')}" if s.get("tun") else "")
                         + (", без рекламы" if s.get("ads") else "")
                         + (f", сеть: {s.get('net')}" if s.get("net") else "")
                         + (", безопасный запуск" if s.get("safe") else ""))
        if not states:
            lines.append("- нет (сбор шёл меньше 5 минут)")
        lines += ["", "Важное из журнала программы:"] + [f"{fmt(it['t'])}  {it.get('text', '')}" for it in important[-800:]]
        lines += ["", "Сейчас:", self.problem_report(), "",
                  f"Журнал программы целиком (последние {REPORT_LOG_LINES} строк):"]
        lines += [f"{fmt(it['t'])}  {it.get('text', '')}" for it in logs[-REPORT_LOG_LINES:]]
        text = self._collect_scrub("\n".join(lines))
        folder = os.path.join(self.paths.data_dir, "reports")
        try:
            os.makedirs(folder, exist_ok=True)
            path = os.path.join(folder, time.strftime("errors-%Y%m%d-%H%M.txt"))
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            return path
        except OSError as exc:
            self.log(f"Сбор ошибок: не удалось сохранить отчёт: {exc}")
            return ""

    def collect_state(self) -> dict:
        until = float(self.settings.get("collect_until") or 0)
        report = self.settings.get("collect_report") or ""
        return {"on": until > time.time(), "until": until, "left": max(0, int(until - time.time())) if until else 0,
                "events": self._collect_events, "report": os.path.basename(report) if report else "",
                "report_ok": bool(report) and os.path.isfile(report)}
