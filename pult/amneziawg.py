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
import time

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
        self.awg.write_conf(srv.awg_conf)
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
        self.awg_active = srv
        self.settings["last_awg_key"] = srv.key
        self.resolve("awg_down")
        self.save()
        self.log(f"Подключено через AmneziaWG: {srv.name}. Весь трафик компьютера идёт через него.")
        self.notify("status")

    def disconnect_awg(self, quiet: bool = False, restore_filter: bool = True) -> None:
        if self.awg.client and (self.awg_active or self.awg.running()):  # иначе незачем спрашивать права администратора
            try:
                self.admin.run("awg", ["/uninstalltunnelservice", TUNNEL])
            except Exception as exc:  # туннель мог уже быть выключен в самом клиенте
                self.log(f"AmneziaWG: {exc}")
        self.awg.wipe()
        was = self.awg_active
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
        if self.awg_active and not self.awg.running():
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
        return {"client": bool(self.awg.client), "active": self.awg_active.key if self.awg_active else "",
                "name": self.awg_active.name if self.awg_active else "", "count": len(self.awg_servers()),
                "download": DOWNLOAD_URL}
