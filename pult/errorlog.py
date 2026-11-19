"""Журнал ошибок: всё, что пошло не так, — в data/errors.jsonl, чтобы починить это в следующей версии.

Что пишется:
  crash   — неожиданное исключение в коде (ошибка программиста: KeyError, NameError и т. п.) с трассировкой;
  problem — жёлтый «!» в окне (сервер упал, ядро не запустилось, подписка не загрузилась…);
  check   — итог проверки программы с ошибками.
Одинаковые записи склеиваются: растёт счётчик и время последнего раза. Хранится не больше MAX_ENTRIES записей.

В журнал не попадают ссылки, ключи, адреса серверов, IP и папка пользователя (их вычищает scrub),
поэтому записи можно выложить в заявку (Issue) на GitHub — для этого есть issue_text() и issue_url().
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import sys
import threading
import time
import traceback
import urllib.parse

from . import APP_VERSION

FILE = "errors.jsonl"
MAX_ENTRIES = 300
TRACE_LIMIT = 4000
ISSUE_BODY_LIMIT = 6000  # ссылка на новую заявку GitHub с текстом длиннее обрывается браузером

# ошибки, которые программа и так показывает человеку понятным текстом: это не баг кода, а сеть или настройки
EXPECTED = (RuntimeError, OSError, TimeoutError, ConnectionError)

_REPO = re.compile(r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")


def repo_from_url(url: str) -> str:
    """owner/repo из адреса вида https://github.com/<owner>/<repo>/releases/…; '' — не GitHub."""
    m = _REPO.search(url or "")
    if not m:
        return ""
    name = m.group(2)[:-4] if m.group(2).endswith(".git") else m.group(2)
    return f"{m.group(1)}/{name}" if name else ""


def is_bug(exc: BaseException) -> bool:
    """Неожиданное исключение (ошибка в коде), а не понятная ошибка сети или настроек."""
    return not isinstance(exc, EXPECTED)


class ErrorLog:
    def __init__(self, data_dir: str, scrub=None, app_dir: str = ""):
        self.path = os.path.join(data_dir, FILE)
        self.scrub = scrub or (lambda text: text)
        self.app_dir = app_dir
        self._lock = threading.Lock()
        self.entries: list[dict] = self._load()

    # ---------- хранение ----------

    def _load(self) -> list[dict]:
        out = []
        try:
            with open(self.path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except ValueError:
                        continue  # битая строка (например, выключили питание посреди записи) — пропускаем
                    if isinstance(item, dict) and item.get("title"):
                        out.append(item)
        except OSError:
            pass
        return out[-MAX_ENTRIES:]

    def _save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                for item in self.entries[-MAX_ENTRIES:]:
                    f.write(json.dumps(item, ensure_ascii=False) + "\n")
            os.replace(tmp, self.path)
        except OSError:
            pass  # журнал — помощник, а не причина падать

    # ---------- запись ----------

    def _clean(self, text: str) -> str:
        text = str(text or "")
        if self.app_dir:
            text = text.replace(self.app_dir, "<app>")
        try:
            return self.scrub(text)
        except Exception:
            return text

    @staticmethod
    def _signature(kind: str, where: str, title: str) -> str:
        norm = re.sub(r"\d+", "#", f"{kind}|{where}|{title}".lower())
        return hashlib.sha1(norm.encode("utf-8")).hexdigest()[:12]

    def record(self, kind: str, title: str, detail: str = "", trace: str = "", where: str = "") -> dict:
        title, detail = self._clean(title)[:300], self._clean(detail)[:1500]
        trace, where = self._clean(trace)[-TRACE_LIMIT:], self._clean(where)[:120]
        sig = self._signature(kind, where, title)
        now = time.time()
        with self._lock:
            for item in reversed(self.entries):
                if item.get("sig") == sig and item.get("version") == APP_VERSION:
                    item.update(count=int(item.get("count", 1)) + 1, last=now, detail=detail or item.get("detail", ""))
                    if trace:
                        item["trace"] = trace
                    self.entries.remove(item)
                    self.entries.append(item)  # свежие — в конце
                    self._save()
                    return item
            item = {"id": f"{sig}-{int(now)}", "sig": sig, "kind": kind, "title": title, "detail": detail,
                    "trace": trace, "where": where, "version": APP_VERSION,
                    "os": f"{platform.system()} {platform.release()}", "python": platform.python_version(),
                    "first": now, "last": now, "count": 1}
            self.entries.append(item)
            del self.entries[:-MAX_ENTRIES]
            self._save()
            return item

    def record_exc(self, exc: BaseException, where: str, kind: str = "crash") -> dict:
        trace = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        title = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
        return self.record(kind, title, "", trace, where)

    def clear(self) -> None:
        with self._lock:
            self.entries = []
            self._save()

    def recent(self, limit: int = 100) -> list[dict]:
        return list(reversed(self.entries[-limit:]))

    # ---------- заявка на GitHub ----------

    def issue_text(self, ids: list[str] | None = None, limit: int = 10) -> dict:
        """Готовая заявка: {"title", "body"} в разметке GitHub. ids — какие записи; по умолчанию последние."""
        chosen = [e for e in self.recent(MAX_ENTRIES) if not ids or e["id"] in ids][:limit]
        if not chosen:
            return {"title": "", "body": ""}
        head = chosen[0]
        title = f"[{head['version']}] {head['title']}"[:120]
        lines = [f"**Версия:** {APP_VERSION} · **Система:** {platform.system()} {platform.release()} · "
                 f"**Python:** {platform.python_version()}", "",
                 "Записи из журнала ошибок (ссылки, ключи и адреса вычищены программой):", ""]
        for e in chosen:
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(e.get("last", 0)))
            lines.append(f"### {e['title']}")
            lines.append(f"- вид: `{e['kind']}`, где: `{e.get('where') or '—'}`, раз: {e.get('count', 1)}, "
                         f"последний: {when}, версия: {e.get('version')}")
            if e.get("detail"):
                lines.append(f"- подробности: {e['detail']}")
            if e.get("trace"):
                lines += ["", "```", e["trace"].strip()[-1500:], "```"]
            lines.append("")
        lines += ["**Что я делал перед ошибкой:**", "", "<!-- опиши своими словами -->"]
        body = "\n".join(lines)
        if len(body) > ISSUE_BODY_LIMIT:
            body = body[:ISSUE_BODY_LIMIT - 40] + "\n…(обрезано, полный журнал — data/errors.jsonl)"
        return {"title": title, "body": body}

    def issue_url(self, repo: str, ids: list[str] | None = None) -> str:
        if not repo:
            return ""
        text = self.issue_text(ids)
        if not text["title"]:
            return ""
        query = urllib.parse.urlencode({"title": text["title"], "body": text["body"], "labels": "bug"})
        return f"https://github.com/{repo}/issues/new?{query}"


def install_hooks(log: ErrorLog) -> None:
    """Необработанные исключения в главном потоке и во всех фоновых — в журнал (и дальше, как обычно)."""
    old_hook = sys.excepthook

    def main_hook(tp, value, tb):
        if not issubclass(tp, KeyboardInterrupt):
            try:
                log.record_exc(value, "главный поток")
            except Exception:
                pass
        old_hook(tp, value, tb)

    old_thread_hook = threading.excepthook

    def thread_hook(args):
        if args.exc_type is not SystemExit and args.exc_value is not None:
            try:
                log.record_exc(args.exc_value, f"поток {args.thread.name if args.thread else '?'}")
            except Exception:
                pass
        old_thread_hook(args)

    sys.excepthook = main_hook
    threading.excepthook = thread_hook
