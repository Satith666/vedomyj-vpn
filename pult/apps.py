"""Приложения на компьютере: какие сейчас ходят в сеть и свой маршрут для каждого.

Маршрут приложения — правило ядра Xray с полем «process» (имя процесса без .exe или полный путь).
Ядро узнаёт процесс только у соединений, которые пришли с этого компьютера: через системный прокси
или через TUN. Приложения, которые не слушаются системного прокси (Discord, многие игры), попадают в ядро
только в режиме TUN.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

IS_WINDOWS = sys.platform == "win32"

# Известные приложения: как называются их процессы и чем их проверить («Подобрать»)
PRESETS: list[dict] = [
    {"id": "discord", "title": "Discord", "process": ["Discord", "DiscordPTB", "DiscordCanary"],
     "urls": ["https://discord.com/api/v9/experiments", "https://gateway.discord.gg/", "https://cdn.discordapp.com/"],
     "service": "Discord", "needs_tun": True, "voice_udp": True},
    {"id": "telegram", "title": "Telegram", "process": ["Telegram"], "service": "Telegram",
     "urls": ["https://web.telegram.org/", "https://api.telegram.org/"]},
    {"id": "steam", "title": "Steam", "process": ["steam", "steamwebhelper"], "service": "Steam",
     "urls": ["https://store.steampowered.com/", "https://steamcommunity.com/"], "needs_tun": True},
    {"id": "spotify", "title": "Spotify", "process": ["Spotify"], "service": "Spotify",
     "urls": ["https://open.spotify.com/"]},
    {"id": "whatsapp", "title": "WhatsApp", "process": ["WhatsApp"], "service": "WhatsApp",
     "urls": ["https://web.whatsapp.com/"]},
    {"id": "chrome", "title": "Google Chrome", "process": ["chrome"]},
    {"id": "edge", "title": "Microsoft Edge", "process": ["msedge"]},
    {"id": "firefox", "title": "Firefox", "process": ["firefox"]},
    {"id": "yandex", "title": "Яндекс Браузер", "process": ["browser"]},
    {"id": "opera", "title": "Opera", "process": ["opera"]},
    {"id": "zoom", "title": "Zoom", "process": ["Zoom"], "needs_tun": True},
    {"id": "battlenet", "title": "Battle.net", "process": ["Battle.net"], "needs_tun": True},
    {"id": "epic", "title": "Epic Games", "process": ["EpicGamesLauncher"], "needs_tun": True},
    {"id": "riot", "title": "Riot Client", "process": ["RiotClientServices", "RiotClientUx"], "needs_tun": True},
    {"id": "minecraft", "title": "Minecraft", "process": ["javaw", "Minecraft.Windows"], "needs_tun": True},
    # торрент-клиенты: по умолчанию напрямую — многие VPN-сервисы блокируют за торренты
    {"id": "qbittorrent", "title": "qBittorrent", "process": ["qbittorrent"], "torrent": True},
    {"id": "utorrent", "title": "uTorrent", "process": ["uTorrent", "uTorrentie"], "torrent": True},
    {"id": "bittorrent", "title": "BitTorrent", "process": ["BitTorrent"], "torrent": True},
    {"id": "transmission", "title": "Transmission", "process": ["transmission-qt", "transmission-daemon"], "torrent": True},
]

# служебные процессы Windows и сама программа — их маршрутом не управляем
SYSTEM = {"system", "idle", "svchost", "lsass", "services", "wininit", "csrss", "smss", "winlogon", "spoolsv",
          "searchhost", "searchapp", "searchindexer", "runtimebroker", "explorer", "dwm", "fontdrvhost",
          "xray", "xray_legacy", "sing-box", "tun2proxy", "tun2proxy-bin", "winws", "ciadpi", "python", "pythonw",
          "vedomyj", "vedomyjvpn", "msmpeng", "nissrv", "memory compression", "registry", "dashost", "wudfhost",
          "audiodg", "sihost", "taskhostw", "ctfmon", "conhost", "smartscreen", "securityhealthservice"}

_NAME = re.compile(r"^[\w .+\-()]{1,80}$")


def clean_name(name: str) -> str:
    """Имя процесса для правила: без пути и без .exe (ядро само убирает .exe у имён)."""
    n = os.path.basename((name or "").strip().replace("\\", "/"))
    if n.lower().endswith(".exe"):
        n = n[:-4]
    return n if _NAME.match(n) else ""


def preset_for(name: str) -> dict | None:
    low = name.lower()
    for p in PRESETS:
        if any(low == x.lower() for x in p["process"]):
            return p
    return None


def rule_process(name: str) -> list[str]:
    """Что писать в правило: имя процесса и родственные (Discord → Discord, DiscordPTB, DiscordCanary)."""
    p = preset_for(name)
    return list(p["process"]) if p else [name]


# ---------- какие приложения сейчас в сети (Windows) ----------

def _netstat_pids() -> dict[int, int]:
    """PID → число соединений (TCP с установленным соединением и UDP)."""
    flags = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW
    try:
        out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=10,
                             creationflags=flags, errors="replace").stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    counts: dict[int, int] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] not in ("TCP", "UDP"):
            continue
        if parts[0] == "TCP" and (len(parts) < 5 or parts[3] != "ESTABLISHED"):
            continue
        remote = parts[2]
        if remote.startswith(("127.", "[::1]", "0.0.0.0", "*:")):
            continue
        try:
            pid = int(parts[-1])
        except ValueError:
            continue
        if pid > 4:
            counts[pid] = counts.get(pid, 0) + 1
    return counts


def _image_path(pid: int) -> str:
    if not IS_WINDOWS:
        return ""
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = wintypes.HANDLE
    h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wintypes.DWORD(len(buf))
        if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return buf.value
        return ""
    finally:
        k32.CloseHandle(h)


def running(lister=None) -> list[dict]:
    """Приложения, у которых сейчас есть соединения: [{name, path, conns}], самые активные первыми.
    lister — подмена для самопроверки: функция без аргументов → [(pid, путь, соединений)]."""
    rows: list[tuple[int, str, int]]
    if lister is not None:
        rows = lister()
    elif IS_WINDOWS:
        rows = [(pid, _image_path(pid), n) for pid, n in _netstat_pids().items()]
    else:
        rows = []
    apps: dict[str, dict] = {}
    for _pid, path, n in rows:
        name = clean_name(path)
        if not name or name.lower() in SYSTEM:
            continue
        a = apps.setdefault(name, {"name": name, "path": path.replace("\\", "/"), "conns": 0})
        a["conns"] += n
    return sorted(apps.values(), key=lambda a: -a["conns"])
