"""Мост sing-box: протоколы, которых нет в ядре Xray (TUIC, AnyTLS), на компьютере.

Как устроено: sing-box запускается отдельным процессом без прав администратора. На каждый сервер у него свой вход
(mixed: SOCKS и HTTP) на 127.0.0.1. Ядро Xray для такого сервера получает outbound «SOCKS на 127.0.0.1:порт» —
поэтому все правила, маршруты, реклама, статистика и TUN работают как обычно. Для проверки серверов поднимается
временный мост, и замер идёт прямо через его входы.
"""

from __future__ import annotations

import json
import os

from . import netutil
from .links import Server
from .xray import Paths, XrayError, XrayProcess

RESERVED_PORTS = {10808, 10809}


def bridge_config(entries: list[tuple[int, dict]]) -> dict:
    """[(порт входа, outbound sing-box)] → настройки моста: вход in{i} → выход out{i}."""
    inbounds, outbounds, rules = [], [], []
    for i, (port, ob) in enumerate(entries):
        inbounds.append({"type": "mixed", "tag": f"in{i}", "listen": "127.0.0.1", "listen_port": int(port)})
        outbounds.append(dict(ob, tag=f"out{i}"))
        rules.append({"inbound": [f"in{i}"], "outbound": f"out{i}"})
    outbounds.append({"type": "direct", "tag": "direct"})
    return {"log": {"level": "warn"}, "inbounds": inbounds, "outbounds": outbounds, "route": {"rules": rules}}


def bridged(servers: list[Server]) -> list[Server]:
    return [s for s in servers if getattr(s, "engine", "xray") == "singbox" and s.supported]


class Bridge:
    """Мост для основного подключения: порты закреплены за серверами, пока программа работает."""

    def __init__(self, paths: Paths, exe: str, config_path: str):
        self.exe = exe
        self.config_path = config_path
        self.proc = XrayProcess(paths)
        self.ports: dict[str, int] = {}
        self.sig: tuple | None = None

    def alive(self) -> bool:
        return self.proc.alive()

    def ensure(self, servers: list[Server]) -> None:
        """Мост с этими серверами (остальные не нужны). Порты пишутся в server.sidecar_port."""
        need = bridged(servers)
        if not need:
            self.stop()
            return
        fresh = [s.key for s in need if s.key not in self.ports]
        if fresh:
            used = set(self.ports.values()) | RESERVED_PORTS
            for key, port in zip(fresh, netutil.find_free_ports(len(fresh), start=22900, avoid=used)):
                self.ports[key] = port
        for s in need:
            s.sidecar_port = self.ports[s.key]
        sig = tuple(sorted((s.key, s.sidecar_port, json.dumps(s.sb_outbound, sort_keys=True)) for s in need))
        if sig == self.sig and self.proc.alive():
            return
        if not os.path.isfile(self.exe):
            raise XrayError("нет sing-box — он скачается сам при подключении")
        cfg = bridge_config([(s.sidecar_port, s.sb_outbound) for s in need])
        self.proc.start(cfg, self.config_path, wait_for=[s.sidecar_port for s in need], exe=self.exe)
        self.sig = sig

    def stop(self) -> None:
        self.proc.stop()
        self.sig = None
