"""Блокировка рекламы «через DNS»: во всех программах компьютера и для всего дома (dnsfilter.py — сам сервер).

«Во всех программах» (Windows): DNS сетевых адаптеров с выходом в интернет ставится так: первым — 127.0.0.1
(наш фильтр), вторым — прежний DNS. Если программа закрылась с ошибкой, Windows сама спросит прежний DNS —
интернет не пропадёт. Перед изменением прежние настройки записываются в data/dns_mode.json; при выключении,
закрытии программы и при следующем запуске после сбоя они возвращаются как были. DNS меняет помощник
с правами администратора — только командой netsh и только на 127.0.0.1 или прежние адреса (admin_helper.py).

«Весь дом»: фильтр слушает ещё и адрес компьютера в домашней сети — телевизору, приставке или роутеру
достаточно указать его как DNS. Раздача Wi-Fi с компьютера берёт DNS у компьютера — и тоже без рекламы.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

from . import adblock, dnsfilter, netutil

IS_WINDOWS = sys.platform == "win32"
STATE_FILE = "dns_mode.json"

# Адаптеры с выходом в интернет: индекс, GUID, DNS (IPv4) и шлюз. Только чтение — без прав администратора.
_PS_ADAPTERS = (
    "Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq 'Up' } | "
    "ForEach-Object { [pscustomobject]@{ index = $_.InterfaceIndex; guid = [string]$_.NetAdapter.InterfaceGuid; "
    "gateway = [string]($_.IPv4DefaultGateway | Select-Object -First 1).NextHop; "
    "dns = @($_.DNSServer | Where-Object AddressFamily -eq 2 | ForEach-Object { $_.ServerAddresses }) } } | "
    "ConvertTo-Json -Compress")


def _windows_adapters() -> list[dict]:
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_ADAPTERS],
                           capture_output=True, timeout=25, creationflags=0x08000000)
        data = json.loads(r.stdout.decode("utf-8", "replace") or "[]")
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return []
    if isinstance(data, dict):
        data = [data]
    out = []
    for a in data or []:
        guid = str(a.get("guid") or "")
        static = ""
        try:  # DNS прописан вручную? Тогда вернём именно его; иначе — «автоматически» (DHCP)
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 rf"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{guid}")
            static = str(winreg.QueryValueEx(key, "NameServer")[0] or "")
            winreg.CloseKey(key)
        except OSError:
            static = ""
        dns = [str(x) for x in (a.get("dns") or []) if x]
        out.append({"index": int(a.get("index") or 0), "servers": dns, "static": bool(static.strip()),
                    "gateway": str(a.get("gateway") or "")})
    return [x for x in out if x["index"] > 0]


class DnsModeMixin:
    """Часть Engine: режим «через DNS» и «весь дом»."""

    _dns_lister = None  # подмена в самопроверке: () -> [{"index", "servers", "static", "gateway"}]
    DNS_PORT = 53

    def _dns_init(self) -> None:
        self.dnsf: dnsfilter.DnsFilter | None = None
        self.dns_error = ""
        self.dns_hosts: list[str] = []
        self.dns_system = False   # DNS адаптеров сейчас указывает на наш фильтр

    @property
    def _dns_state_path(self) -> str:
        return os.path.join(self.paths.data_dir, STATE_FILE)

    def dns_supported(self) -> bool:
        return IS_WINDOWS or self._dns_lister is not None

    def _dns_wanted(self) -> tuple[bool, bool]:
        """(во всех программах, весь дом) — с учётом того, что сама блокировка включена."""
        s = self.settings
        on = bool(s.get("block_ads")) and self.dns_supported()
        return on and bool(s.get("ads_dns_system")), on and bool(s.get("ads_dns_home"))

    def _dns_domains(self) -> set[str]:
        if self._ads_paused() or not os.path.isfile(self._ads_dat):
            return set()
        try:
            with open(self._ads_dat, "rb") as f:
                return set(adblock.decode_geosite(f.read()).get(adblock.TAG.upper(), []))
        except (OSError, ValueError, IndexError):
            return set()

    def _dns_adapters(self) -> list[dict]:
        return (self._dns_lister or _windows_adapters)()

    # ---------- включить / выключить ----------

    def dns_apply(self) -> None:
        """Привести режим «через DNS» к настройкам: включить, выключить или обновить списки."""
        system, home = self._dns_wanted()
        if not system and not home:
            self.dns_stop()
            return
        want_hosts = ["127.0.0.1"] + ([netutil.lan_ip()] if home and netutil.lan_ip() else [])
        if self.dnsf and self.dnsf.running and want_hosts == self.dns_hosts and system == self.dns_system:
            self.dnsf.set_domains(self._dns_domains())
            return
        self.dns_stop()
        self.dns_error = ""
        adapters = self._dns_adapters()  # только чтение: откуда спрашивать адреса дальше
        if not adapters:
            self.dns_error = "Не нашёл сетевых адаптеров с выходом в интернет."
            self.log("Блокировка через DNS: " + self.dns_error)
            self.notify("settings")
            return
        if system and not os.path.isfile(self._dns_state_path):  # запись осталась (не вернули) — в ней прежние
            # прежние настройки — на диск до любых изменений (при сбое вернём при следующем запуске)
            with open(self._dns_state_path, "w", encoding="utf-8") as fh:
                json.dump({"adapters": adapters, "at": time.time()}, fh)
        ups = [x for a in adapters for x in a["servers"] if x != "127.0.0.1"] + [a["gateway"] for a in adapters if a["gateway"]]
        f = dnsfilter.DnsFilter(list(dict.fromkeys(ups)), log=self.log, on_block=self._dns_blocked)
        f.set_domains(self._dns_domains())
        try:
            f.start(want_hosts, self.DNS_PORT)
        except OSError as exc:
            self.dns_error = f"Порт {self.DNS_PORT} занят другой программой ({netutil.human_error(exc)})."
            self.log("Блокировка через DNS не включилась: " + self.dns_error)
            self._dns_restore()
            self.notify("settings")
            return
        self.dnsf, self.dns_hosts = f, want_hosts
        if system:
            failed = []
            for a in adapters:
                backup = [x for x in a["servers"] if x != "127.0.0.1"][:1] or ([a["gateway"]] if a["gateway"] else [])
                r = self.admin.run("dns", ["filter", str(a["index"])] + backup)
                if not r.get("ok"):
                    failed.append(r.get("error") or "ошибка")
            if failed and len(failed) == len(adapters):
                self.dns_error = "Windows не дала поменять DNS: " + "; ".join(failed[:2])
                self.log("Блокировка через DNS: " + self.dns_error)
                f.stop()
                self.dnsf = None
                self._dns_restore()
                self.notify("settings")
                return
            self.dns_system = True
        where = ("во всех программах" if system else "") + (" и " if system and home else "") + \
                (f"для всего дома (DNS {want_hosts[1]})" if home and len(want_hosts) > 1 else "")
        self.log(f"Блокировка рекламы через DNS работает {where}.")
        self.notify("settings")

    def dns_stop(self) -> None:
        if self.dnsf:
            self.dnsf.stop()
            self.dnsf = None
            self.log("Блокировка рекламы через DNS выключена.")
        self.dns_hosts = []
        self._dns_restore()

    def _dns_restore(self) -> None:
        """Вернуть DNS адаптеров как было (по записи в data/dns_mode.json) и удалить запись."""
        path = self._dns_state_path
        if not os.path.isfile(path):
            self.dns_system = False
            return
        try:
            with open(path, encoding="utf-8") as f:
                saved = json.load(f)
        except (OSError, ValueError):
            saved = {}
        ok = True
        for a in saved.get("adapters") or []:
            idx = str(int(a.get("index") or 0))
            servers = [x for x in a.get("servers") or [] if x != "127.0.0.1"][:2]
            args = ["static", idx] + servers if a.get("static") and servers else ["dhcp", idx]
            try:
                r = self.admin.run("dns", args)
            except Exception as exc:  # помощник не запустился (отказ в правах) — попробуем при следующем запуске
                r = {"ok": False, "error": str(exc)}
            ok = ok and bool(r.get("ok"))
        if ok:
            try:
                os.remove(path)
            except OSError:
                pass
            self.dns_system = False
        else:
            self.log("Не получилось вернуть прежний DNS компьютера — попробую при следующем запуске.")

    def dns_startup(self) -> None:
        """При запуске: прошлый раз программа закрылась с включённым режимом — сначала вернуть DNS, потом включить."""
        if os.path.isfile(self._dns_state_path):
            self.log("Прошлый раз программа закрылась, не вернув DNS компьютера, — возвращаю.")
            self._dns_restore()
        if any(self._dns_wanted()):
            try:
                self.dns_apply()
            except Exception as exc:
                self.log(f"Блокировка через DNS: {exc}")

    def _dns_blocked(self, host: str) -> None:
        self._count_ad(host)  # в журнал рекламы — как и закрытое ядром

    def dns_state(self) -> dict:
        f = self.dnsf
        return {"supported": self.dns_supported(), "system": bool(self.settings.get("ads_dns_system")),
                "home": bool(self.settings.get("ads_dns_home")), "running": bool(f and f.running),
                "home_ip": self.dns_hosts[1] if len(self.dns_hosts) > 1 else "",
                "switched": self.dns_system, "error": self.dns_error,
                "stats": dict(f.stats) if f else {"queries": 0, "blocked": 0, "failed": 0}}
