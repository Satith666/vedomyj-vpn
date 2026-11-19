"""Страна сервера по названию: флаг-эмодзи, код или название страны."""

from __future__ import annotations

import re

NAMES = {
    "NL": ["нидерланд", "голланд", "netherlands", "holland", "amsterdam", "амстердам"],
    "DE": ["германи", "germany", "frankfurt", "франкфурт", "deutschland"],
    "FI": ["финлянд", "finland", "helsinki", "хельсинки"],
    "SE": ["швеци", "sweden", "stockholm", "стокгольм"],
    "FR": ["франци", "france", "paris", "париж"],
    "GB": ["великобритан", "англи", "united kingdom", "england", "london", "лондон", " uk "],
    "US": ["сша", "америк", "united states", "usa", "new york", "нью-йорк", "los angeles"],
    "PL": ["польш", "poland", "warsaw", "варшав"],
    "LV": ["латви", "latvia", "riga", "рига"],
    "LT": ["литв", "lithuania", "vilnius", "вильнюс"],
    "EE": ["эстони", "estonia", "tallinn", "таллин"],
    "KZ": ["казахстан", "kazakhstan", "almaty", "алматы"],
    "TR": ["турци", "turkey", "türkiye", "istanbul", "стамбул"],
    "AE": ["оаэ", "эмират", "uae", "dubai", "дубай"],
    "CH": ["швейцари", "switzerland", "zurich", "цюрих"],
    "AT": ["австри", "austria", "vienna", "вена"],
    "CZ": ["чехи", "czech", "prague", "праг"],
    "ES": ["испани", "spain", "madrid", "мадрид"],
    "IT": ["итали", "italy", "milan", "милан"],
    "JP": ["япони", "japan", "tokyo", "токио"],
    "SG": ["сингапур", "singapore"],
    "HK": ["гонконг", "hong kong"],
    "CA": ["канад", "canada", "toronto", "торонто"],
    "RU": ["росси", "russia", "москв", "moscow"],
    "AM": ["армени", "armenia", "yerevan", "ереван"],
    "GE": ["грузи", "georgia", "tbilisi", "тбилиси"],
    "RS": ["серби", "serbia", "belgrade", "белград"],
    "MD": ["молдов", "moldova", "chisinau", "кишин"],
    "BG": ["болгари", "bulgaria", "sofia", "софия"],
    "RO": ["румыни", "romania", "bucharest", "бухарест"],
    "HU": ["венгри", "hungary", "budapest", "будапешт"],
    "NO": ["норвеги", "norway", "oslo"],
    "IL": ["израил", "israel", "tel aviv"],
    "IN": ["инди", "india", "mumbai"],
    "BR": ["бразили", "brazil", "sao paulo"],
}


def split_flag(name: str) -> tuple[str, str]:
    """Возвращает (код страны или "", название без флага и прочих эмодзи)."""
    code = ""
    out = []
    chars = list(name)
    i = 0
    while i < len(chars):
        cp = ord(chars[i])
        if 0x1F1E6 <= cp <= 0x1F1FF and i + 1 < len(chars) and 0x1F1E6 <= ord(chars[i + 1]) <= 0x1F1FF:
            if not code:
                code = chr(cp - 0x1F1E6 + 65) + chr(ord(chars[i + 1]) - 0x1F1E6 + 65)
            i += 2
            continue
        if cp > 0xFFFF or cp in (0xFE0F, 0x200D, 0x20E3):
            i += 1
            continue
        out.append(chars[i])
        i += 1
    clean = re.sub(r"\s+", " ", "".join(out)).strip(" -|·•,") or name.strip()
    return code, clean


def detect(name: str) -> tuple[str, str]:
    code, clean = split_flag(name)
    if code:
        return code, clean
    low = f" {clean.lower()} "
    for cc, words in NAMES.items():
        if any(w in low for w in words):
            return cc, clean
    m = re.match(r"^\[?([A-Z]{2})\]?[\s\-_|]", clean + " ")
    if m and m.group(1) in NAMES:
        return m.group(1), clean
    return "", clean
