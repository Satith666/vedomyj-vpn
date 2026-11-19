"""Что нового в версии — из CHANGELOG.md. Для выпуска на GitHub и окна «Есть обновление».

python build/changelog_notes.py 1.9.0           — текст раздела (разметка GitHub)
python build/changelog_notes.py 1.9.0 --plain   — коротко, без разметки (для latest.json)
python build/changelog_notes.py 1.9.0 --check   — ошибка, если раздела для версии нет
"""

from __future__ import annotations

import os
import re
import sys

PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "CHANGELOG.md")
PLAIN_LIMIT = 900


def section(text: str, version: str) -> str:
    m = re.search(rf"^## \[?{re.escape(version)}\]?(?![\d.])[^\n]*\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    return m.group(1).strip() if m else ""


def plain(md: str, limit: int = PLAIN_LIMIT) -> str:
    lines = []
    for line in md.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line = re.sub(r"^[-*]\s+", "• ", line)
        line = re.sub(r"\*\*(.+?)\*\*|`(.+?)`", lambda m: m.group(1) or m.group(2), line)
        lines.append(line)
    out = "\n".join(lines)
    return out if len(out) <= limit else out[:limit - 1].rsplit("\n", 1)[0] + "\n…"


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        sys.exit(__doc__)
    with open(PATH, encoding="utf-8") as f:
        notes = section(f.read(), args[0])
    if "--check" in sys.argv:
        if not notes:
            sys.exit(f"В CHANGELOG.md нет раздела «## {args[0]}» — опиши, что изменилось.")
        print(f"CHANGELOG.md: раздел {args[0]} есть")
        return
    if not notes:
        notes = "Новая версия"
    sys.stdout.reconfigure(encoding="utf-8")
    print(plain(notes) if "--plain" in sys.argv else notes)


if __name__ == "__main__":
    main()
