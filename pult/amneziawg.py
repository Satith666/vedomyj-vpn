"""AmneziaWG на компьютере: «отдельный VPN», который запускает официальный клиент AmneziaWG для Windows.

AmneziaWG — это WireGuard с маскировкой (мусорные пакеты, случайные заголовки, сигнатуры перед рукопожатием),
поэтому его не узнаёт оборудование провайдера. Ядро Xray его не умеет, sing-box тоже, поэтому программа:
  • хранит конфиги AmneziaWG вместе со своими серверами (строкой awg://, в зашифрованных настройках);
  • включает туннель командой клиента «amneziawg.exe /installtunnelservice <файл.conf>» через помощника с правами
    администратора (в его белом списке — только этот exe из Program Files и только наш файл в папке data);
  • выключает — «/uninstalltunnelservice vedomyj» и стирает файл с закрытым ключом.
Пока работает AmneziaWG, весь трафик компьютера идёт через него: ядро Xray выключено, правила программы
(российское напрямую, реклама, свои маршруты) в этом режиме не действуют — так и пишется в окне.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time

from . import links, warp
from .links import Server

IS_WINDOWS = sys.platform == "win32"
TUNNEL = "vedomyj"
SERVICE = f"AmneziaWGTunnel${TUNNEL}"
DOWNLOAD_URL = "https://github.com/amnezia-vpn/amneziawg-windows-client/releases"


def find_client() -> str:
    """Путь к amneziawg.exe, если клиент AmneziaWG для Windows установлен; иначе ""."""
    if not IS_WINDOWS:
        return ""
    for env in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(env)
        if root:
            path = os.path.join(root, "AmneziaWG", "amneziawg.exe")
            if os.path.isfile(path):
                return path
    return ""


def _service_state(name: str) -> int | None:
    """Состояние службы через API Windows (без запуска sc.exe): 4 — работает, 1 — остановлена,
    0 — службы нет; None — API недоступно."""
    try:
        import ctypes
        from ctypes import wintypes
        adv = ctypes.WinDLL("advapi32", use_last_error=True)
        adv.OpenSCManagerW.restype = wintypes.HANDLE
        adv.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        adv.OpenServiceW.restype = wintypes.HANDLE
        adv.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
        adv.CloseServiceHandle.argtypes = [wintypes.HANDLE]

        class Status(ctypes.Structure):
            _fields_ = [(n, wintypes.DWORD) for n in ("type", "state", "accepted", "exit", "svc_exit",
                                                       "checkpoint", "wait_hint")]
        adv.QueryServiceStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(Status)]
    except (AttributeError, OSError, ImportError):
        return None
    scm = adv.OpenSCManagerW(None, None, 0x0001)  # SC_MANAGER_CONNECT — хватает обычных прав
    if not scm:
        return None
    try:
        svc = adv.OpenServiceW(scm, name, 0x0004)  # SERVICE_QUERY_STATUS
        if not svc:
            return 0 if ctypes.get_last_error() == 1060 else None  # 1060 — такой службы нет
        try:
            st = Status()
            if not adv.QueryServiceStatus(svc, ctypes.byref(st)):
                return None
            return int(st.state)
        finally:
            adv.CloseServiceHandle(svc)
    finally:
        adv.CloseServiceHandle(scm)


def service_running(name: str = SERVICE) -> bool:
    """Работает ли служба туннеля. Обычно — через API Windows (без запуска программ: монитор
    спрашивает каждые 5 секунд); если API недоступно — через «sc query»."""
    if not IS_WINDOWS:
        return False
    state = _service_state(name)
    if state is not None:
        return state == 4  # SERVICE_RUNNING
    try:
        out = subprocess.run(["sc", "query", name], capture_output=True, timeout=8,
                             creationflags=0x08000000).stdout.decode("cp866", "replace")
    except (OSError, subprocess.SubprocessError):
        return False
    return "RUNNING" in out


class Runner:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.client = find_client()
        self.folder = os.path.join(data_dir, "awg")
        self.conf_path = os.path.join(self.folder, TUNNEL + ".conf")

    def refresh(self) -> str:
        self.client = find_client()
        return self.client

    def running(self) -> bool:
        return service_running()

    def write_conf(self, conf: str) -> None:
        """Файл для клиента. Команды PreUp/PostUp выкидываются: с правами администратора они не нужны и опасны."""
        lines = [x for x in conf.strip().splitlines()
                 if x.split("=", 1)[0].strip().lower() not in ("preup", "postup", "predown", "postdown")]
        os.makedirs(self.folder, exist_ok=True)
        if os.path.islink(self.conf_path):
            os.remove(self.conf_path)
        with open(self.conf_path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")

    def wipe(self) -> None:
        try:
            if os.path.isfile(self.conf_path):
                with open(self.conf_path, "r+b") as f:
                    f.write(b"\0" * os.path.getsize(self.conf_path))
                os.remove(self.conf_path)
        except OSError:
            pass


class AwgMixin:
    """Часть движка: включить и выключить AmneziaWG, следить, что туннель жив."""

    def awg_servers(self) -> list[Server]:
        return [s for s in self.servers if s.engine == "awg"]

    def _awg_admin(self) -> None:
        if not self.awg.client and not self.awg.refresh():
            raise RuntimeError("Для AmneziaWG нужна программа AmneziaWG для Windows. Скачай её на GitHub "
                               "(«Движок → AmneziaWG → Скачать клиент»), установи и нажми снова.")

    def connect_awg(self, srv: Server) -> None:
        if srv.engine != "awg":
            raise RuntimeError("Это не конфиг AmneziaWG.")
        self._awg_admin()
        if self.connected or self.filter_on or self.kill_on:
            self.disconnect(quiet=True, keep_filter=False)  # весь трафик возьмёт AmneziaWG — ядро Xray не нужно
        self.disconnect_awg(quiet=True, restore_filter=False)  # прошлый туннель (и оставшийся от прошлого запуска) — выключить
        self.progress(f"Включаю AmneziaWG: {srv.name}")
        if warp.is_warp(srv.awg_conf):
            self._connect_warp(srv)
        else:
            self._awg_up(srv.awg_conf)
        self.awg_active = srv
        self.settings["last_awg_key"] = srv.key
        self.resolve("awg_down")
        self.resolve("warp_dead")
        self.save()
        self.log(f"Подключено через AmneziaWG: {srv.name}. Весь трафик компьютера идёт через него.")
        self.notify("status")

    def _awg_up(self, conf: str) -> None:
        """Записать конфиг и включить туннель клиентом AmneziaWG (через помощника с правами администратора)."""
        self.awg.write_conf(conf)
        r = self.admin.run("awg", ["/installtunnelservice", self.awg.conf_path])
        if not r.get("ok"):
            self.awg.wipe()
            raise RuntimeError(f"AmneziaWG не включился: {r.get('error') or 'клиент AmneziaWG вернул ошибку'}. "
                               "Можно открыть AmneziaWG и добавить туда файл конфига вручную.")
        deadline = time.time() + 12
        while time.time() < deadline and not self.awg.running():
            time.sleep(0.4)
        if not self.awg.running():
            self.admin.run("awg", ["/uninstalltunnelservice", TUNNEL])
            self.awg.wipe()
            raise RuntimeError("Туннель AmneziaWG не запустился. Проверь конфиг или открой AmneziaWG и посмотри журнал.")

    def _awg_down(self) -> None:
        """Выключить туннель (между попытками WARP): без записей в журнал и без «Без рекламы»."""
        try:
            self.admin.run("awg", ["/uninstalltunnelservice", TUNNEL])
        except Exception as exc:
            self.log(f"AmneziaWG: {exc}")
        deadline = time.time() + 6
        while time.time() < deadline and self.awg.running():
            time.sleep(0.3)
        self.awg.wipe()

    # ---------- бесплатный WARP ----------

    WARP_VERIFY_DELAYS = (1.0, 2.5, 3.5)  # когда проверять, что трафик идёт через WARP (всего ~7 с)
    WARP_HEALTH_EVERY = 60
    WARP_HEALTH_RECHECK = 10.0
    WARP_NETS_MAX = 30

    def _warp_check(self) -> bool:
        return warp.trace_ok()

    def _warp_verify(self) -> bool:
        for delay in self.WARP_VERIFY_DELAYS:
            if self.conn_stop.is_set():
                break
            time.sleep(delay)
            if self._warp_check():
                return True
        return False

    def _warp_net(self) -> str:
        """Ключ сети для памяти обманок (хеш, как у памяти способов). До включения туннеля — иначе
        провайдером оказался бы Cloudflare."""
        if not self.settings.get("net_memory", True):
            return ""
        try:
            return self._net_id(cached_only=True) or self._net_id()
        except Exception:
            return ""

    def _warp_candidates(self, srv: Server, net: str, skip: str = ""):
        """Варианты конфига по очереди: рабочий в этой сети раньше → как в конфиге → наборы обманок."""
        saved = (self.settings.get("warp_nets") or {}).get(net) if net else None
        if saved:
            yield warp.variant(srv.awg_conf, saved)
        yield srv.awg_conf
        for i in range(len(warp.PRESETS)):
            yield warp.variant(srv.awg_conf, warp.preset(i))

    @staticmethod
    def _warp_sig(conf: str) -> str:
        p = warp.current_params(conf)
        return f"{p.get('endpoint')}|{p.get('i1')}" if p else conf

    def _connect_warp(self, srv: Server, skip: str = "") -> None:
        """Включить WARP: каждый вариант обманок — туннель и проверка, что Cloudflare видит трафик через WARP.
        Не прошло — следующий вариант. Рабочий запоминается для этой сети."""
        net = self._warp_net()
        seen = {skip} if skip else set()
        total = 2 + len(warp.PRESETS)
        tried = 0
        for conf in self._warp_candidates(srv, net):
            sig = self._warp_sig(conf)
            if sig in seen:
                continue
            seen.add(sig)
            tried += 1
            self.check_stop()
            self.progress(f"WARP: пробую обманки, вариант {tried} из {total}")
            self._awg_up(conf)
            if self._warp_verify():
                self._warp_conf = conf
                p = warp.current_params(conf)
                if net and p:
                    nets = dict(self.settings.get("warp_nets") or {})
                    nets.pop(net, None)
                    nets[net] = {k: p[k] for k in ("endpoint", "jc", "jmin", "jmax", "i1")}
                    while len(nets) > self.WARP_NETS_MAX:
                        nets.pop(next(iter(nets)))
                    self.settings["warp_nets"] = nets
                if tried > 1:
                    self.log(f"WARP работает с обманками «{p.get('label', '') if p else ''}» (вариант {tried}).")
                return
            self._awg_down()
        raise RuntimeError(f"WARP не пробился в этой сети: проверил {tried} вариантов обманок. Провайдер блокирует "
                           "WARP — попробуй позже, в другой сети или используй обычный VPN-сервер.")

    def _warp_bases(self) -> list[str]:
        return [f"https://{h}" for h in warp.API_HOSTS]

    def _warp_register(self, port: int | None, base: str) -> dict:
        return warp.register(warp.opener_for(port), base)

    def create_warp(self) -> Server:
        """Зарегистрировать бесплатный WARP и сохранить его конфиг среди своих серверов (прошлый свой WARP
        заменяется). Если VPN включён — регистрация идёт через него: напрямую в России её часто блокируют."""
        routes: list = []
        if self.connected and self.ports.get("health"):
            routes.append(self.ports["health"])
        routes.append(None)
        acct, kinds = None, []
        for port in routes:
            for base in self._warp_bases():
                self.check_stop()
                self.progress("Регистрирую WARP у Cloudflare" + (" через VPN" if port else ""))
                try:
                    acct = self._warp_register(port, base)
                    break
                except warp.WarpError as exc:
                    kinds.append(exc.kind)
                    if port:
                        self.log(f"WARP: регистрация через VPN не удалась ({exc}).")
                    else:
                        self.log(f"WARP: регистрация напрямую не удалась ({exc}).")
            if acct:
                break
        if not acct:
            if "limit" in kinds:
                raise RuntimeError("Cloudflare сейчас не даёт создать WARP: слишком много регистраций с твоего "
                                   "адреса. Попробуй через полчаса.")
            if routes[0]:
                raise RuntimeError("Не получилось связаться с Cloudflare ни через VPN, ни напрямую. Попробуй позже.")
            raise RuntimeError("Не получилось связаться с Cloudflare: в твоей сети регистрацию WARP, похоже, "
                               "блокируют. Включи на минуту любой VPN-сервер и нажми снова — регистрация пройдёт "
                               "через него. Или вставь готовый конфиг WARP через «+».")
        net = self._warp_net()
        saved = (self.settings.get("warp_nets") or {}).get(net) if net else None
        conf = warp.build_conf(acct, saved or warp.preset(0))
        link = links.awg_link(conf, warp.NAME)
        old = [x for x in self.servers if x.sub_id == "manual" and x.engine == "awg" and x.name == warp.NAME]
        if self.awg_active and self.awg_active in old:
            self.disconnect_awg(quiet=True)
        drop = {x.link for x in old}
        saved_links = [x for x in self.settings.get("manual_links", []) if x.strip() not in drop]
        saved_links.append(link)
        self.settings["manual_links"] = saved_links
        self._rebuild_servers()
        srv = next((x for x in self.servers if x.link == link), None)
        if not srv:
            raise RuntimeError("Конфиг WARP не сохранился.")
        self.settings["last_awg_key"] = srv.key
        self.save()
        self.log("Создан бесплатный WARP (ключи созданы на этом компьютере).")
        self.notify("servers")
        return srv

    def warp_start(self) -> None:
        """Кнопка «Создать бесплатный WARP»: создать конфиг, выбрать способ AmneziaWG и, если клиент
        AmneziaWG установлен, сразу включить."""
        srv = self.create_warp()
        if self.method() != "awg":
            self.set_method("awg")
        if not self.awg.client and not self.awg.refresh():
            self.notify("info", text="WARP создан. Чтобы включить его, установи программу AmneziaWG и нажми большую кнопку.")
            return
        self.connect(srv)

    def awg_conf_text(self, srv: Server) -> str:
        """Конфиг для ручного переноса: у работающего WARP — с обманками, которые сейчас пробивают блокировку."""
        if self.awg_active is srv and getattr(self, "_warp_conf", ""):
            return self._warp_conf
        return srv.awg_conf

    def _warp_health(self) -> None:
        """Раз в минуту, пока работает WARP: идёт ли трафик. Два промаха подряд — подобрать другие обманки."""
        srv = self.awg_active
        if not srv or not warp.is_warp(srv.awg_conf) or getattr(self, "_warp_checking", False) or self.is_busy():
            return
        self._warp_checking = True

        def job():
            try:
                if self._warp_check():
                    return
                time.sleep(self.WARP_HEALTH_RECHECK)
                if self.awg_active is not srv or self._warp_check() or self.is_busy():
                    return
                self.log("WARP перестал пропускать трафик — подбираю другие обманки.")
                self.run_task("Чиню WARP", self._warp_repair, srv, lane="conn")
            finally:
                self._warp_checking = False
        threading.Thread(target=job, daemon=True).start()

    def _warp_repair(self, srv: Server) -> None:
        if self.awg_active is not srv:
            return
        self._lane.why = "WARP перестал пропускать трафик"
        skip = self._warp_sig(getattr(self, "_warp_conf", "") or srv.awg_conf)
        self._warp_switching = True
        try:
            self._awg_down()
            try:
                self._connect_warp(srv, skip=skip)
            except Exception as exc:
                self.awg_active = None
                self._warp_conf = ""
                self._journal("fail", srv, str(exc))
                self.problem("warp_dead", "WARP не пропускает трафик", str(exc), where="Способ → AmneziaWG",
                             fix="Попробуй позже, в другой сети или выбери обычный VPN-сервер.")
                self.notify("status")
                return
        finally:
            self._warp_switching = False
        self.save()
        self._journal("reconnect", srv)
        self.notify("status")

    def disconnect_awg(self, quiet: bool = False, restore_filter: bool = True) -> None:
        if self.awg.client and (self.awg_active or self.awg.running()):  # иначе незачем спрашивать права администратора
            try:
                self.admin.run("awg", ["/uninstalltunnelservice", TUNNEL])
            except Exception as exc:  # туннель мог уже быть выключен в самом клиенте
                self.log(f"AmneziaWG: {exc}")
        self.awg.wipe()
        was = self.awg_active
        self._warp_conf = ""
        if was and not quiet:
            self._journal("disconnect", was)
        self.awg_active = None
        if was and not quiet:
            self.log(f"AmneziaWG выключен: {was.name}.")
        if was and restore_filter and not self._closing and self._filter_wanted() and not self.connected:
            try:
                self.start_filter()  # «Без рекламы» без VPN снова работает, как до AmneziaWG
            except Exception as exc:
                self._filter_fail_at = time.time()
                self.log(f"Блокировка рекламы без VPN не включилась: {exc}")
        self.notify("status")

    def awg_watch(self) -> None:
        """Из монитора: туннель выключили в самом клиенте или он упал — сказать об этом."""
        if self.awg_active and not getattr(self, "_warp_switching", False) and not self.awg.running():
            name = self.awg_active.name
            self.awg_active = None
            self.awg.wipe()
            self.log(f"Туннель AmneziaWG «{name}» остановился.")
            self.journal.add("disconnect", name, "AmneziaWG", "туннель остановился сам или выключен в клиенте AmneziaWG",
                             "awg")
            self.problem("awg_down", "AmneziaWG остановился", name, where="Движок → AmneziaWG",
                         fix="Нажми большую кнопку, чтобы включить снова, или выбери другой движок.")
            self.notify("status")

    def awg_restore(self) -> None:
        """При запуске программы: туннель AmneziaWG, включённый раньше, ещё работает — показать это."""
        key = self.settings.get("last_awg_key") or ""
        srv = self.find(key) if key else None
        if srv and srv.engine == "awg" and self.awg.running():
            self.awg_active = srv
            self.log(f"AmneziaWG работает: {srv.name}.")

    def awg_state(self) -> dict:
        if not self.awg.client and IS_WINDOWS:
            self.awg.refresh()  # клиент могли установить, пока программа открыта (проверка — пара вызовов isfile)
        own = [x for x in self.awg_servers() if x.name == warp.NAME and x.sub_id == "manual"]
        return {"client": bool(self.awg.client), "active": self.awg_active.key if self.awg_active else "",
                "name": self.awg_active.name if self.awg_active else "", "count": len(self.awg_servers()),
                "warp": own[0].key if own else "", "download": DOWNLOAD_URL}
