"""Значок программы у часов Windows (в области уведомлений) — для работы в фоне.

Только стандартная библиотека: Win32 API через ctypes. Значок живёт в своём потоке со своей очередью сообщений.
Меню: «Открыть», «Подключить»/«Отключить», «Выход». Двойной щелчок открывает окно.
Не в Windows ничего не делает (Tray.ok == False).
"""

from __future__ import annotations

import sys
import threading

IS_WINDOWS = sys.platform == "win32"

WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_COMMAND = 0x0111
WM_NULL = 0x0000
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONUP = 0x0205
WM_APP = 0x8000
WM_TRAY = WM_APP + 1
WM_UPDATE = WM_APP + 2

NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
NIF_MESSAGE, NIF_ICON, NIF_TIP, NIF_INFO = 0x1, 0x2, 0x4, 0x10
NIN_BALLOONUSERCLICK = 0x0405
NIIF_INFO = 0x1
MF_STRING, MF_SEPARATOR, MF_GRAYED = 0x0, 0x800, 0x1
TPM_RIGHTBUTTON, TPM_RETURNCMD, TPM_NONOTIFY = 0x2, 0x100, 0x80
IMAGE_ICON, LR_LOADFROMFILE, LR_DEFAULTSIZE = 1, 0x10, 0x40
IDI_APPLICATION = 32512

CMD_OPEN, CMD_TOGGLE, CMD_EXIT, CMD_HOUR = 1001, 1002, 1003, 1004

# горячая клавиша «включить/выключить VPN»
WM_HOTKEY = 0x0312
WM_HOTKEY_SET = WM_APP + 3
HOTKEY_ID = 0x5650
MOD_ALT, MOD_CONTROL, MOD_SHIFT, MOD_WIN, MOD_NOREPEAT = 0x1, 0x2, 0x4, 0x8, 0x4000
_MODS = {"ctrl": MOD_CONTROL, "alt": MOD_ALT, "shift": MOD_SHIFT, "win": MOD_WIN}


def parse_hotkey(text: str) -> tuple[int, int] | None:
    """«Ctrl+Alt+V» → (модификаторы, код клавиши). Нужен хотя бы один модификатор и одна буква/цифра/F1–F12."""
    parts = [p.strip().lower() for p in (text or "").replace(" ", "").split("+") if p.strip()]
    if len(parts) < 2:
        return None
    mods = 0
    for p in parts[:-1]:
        if p not in _MODS:
            return None
        mods |= _MODS[p]
    key = parts[-1]
    if len(key) == 1 and key.isalnum() and key.isascii():
        vk = ord(key.upper())
    elif key.startswith("f") and key[1:].isdigit() and 1 <= int(key[1:]) <= 12:
        vk = 0x70 + int(key[1:]) - 1
    else:
        return None
    return mods, vk


class Tray:
    """on_open(), on_toggle(), on_exit() вызываются из потока значка — они должны быть быстрыми."""

    def __init__(self, icon_path: str, on_open, on_toggle, on_exit, texts, on_hour=None):
        self.icon_path = icon_path
        self.on_open, self.on_toggle, self.on_exit = on_open, on_toggle, on_exit
        self.on_hour = on_hour  # «Включить на 1 час»
        self.texts = texts  # функция: ключ → текст на выбранном языке
        self.tip = "VEDOMYJ VPN"
        self.connected = False
        self.hwnd = None
        self.ok = False
        self._ready = threading.Event()
        self._pending_balloon: tuple[str, str] | None = None
        self.hotkey = ""          # заданная горячая клавиша («Ctrl+Alt+V»), пусто — выключена
        self.hotkey_ok = False    # удалось ли её занять (другая программа может уже держать её)
        if IS_WINDOWS:
            threading.Thread(target=self._run, name="tray", daemon=True).start()
            self._ready.wait(5)

    # ---------- снаружи ----------

    def update(self, connected: bool, tip: str) -> None:
        self.connected = connected
        self.tip = tip[:120]
        if self.ok and self.hwnd:
            self._user32.PostMessageW(self.hwnd, WM_UPDATE, 0, 0)

    def balloon(self, title: str, text: str) -> None:
        self._pending_balloon = (title[:60], text[:250])
        if self.ok and self.hwnd:
            self._user32.PostMessageW(self.hwnd, WM_UPDATE, 0, 0)

    def set_hotkey(self, text: str) -> None:
        """Занять горячую клавишу (или освободить, если text пустой). Выполняется в потоке значка."""
        self.hotkey = text or ""
        if self.ok and self.hwnd:
            self._user32.PostMessageW(self.hwnd, WM_HOTKEY_SET, 0, 0)

    def stop(self) -> None:
        if self.ok and self.hwnd:
            self._user32.PostMessageW(self.hwnd, WM_CLOSE, 0, 0)

    def _apply_hotkey(self) -> None:
        self._user32.UnregisterHotKey(self.hwnd, HOTKEY_ID)
        self.hotkey_ok = False
        parsed = parse_hotkey(self.hotkey)
        if parsed:
            mods, vk = parsed
            self.hotkey_ok = bool(self._user32.RegisterHotKey(self.hwnd, HOTKEY_ID, mods | MOD_NOREPEAT, vk))

    # ---------- поток значка ----------

    def _run(self) -> None:
        try:
            self._setup()
        except Exception:
            self.ok = False
            self._ready.set()
            return
        msg = self._wt.MSG()
        while self._user32.GetMessageW(self._ctypes.byref(msg), None, 0, 0) > 0:
            self._user32.TranslateMessage(self._ctypes.byref(msg))
            self._user32.DispatchMessageW(self._ctypes.byref(msg))

    def _setup(self) -> None:
        import ctypes
        from ctypes import wintypes as wt
        self._ctypes, self._wt = ctypes, wt
        user32, shell32, kernel32 = ctypes.windll.user32, ctypes.windll.shell32, ctypes.windll.kernel32
        self._user32, self._shell32 = user32, shell32
        LRESULT = ctypes.c_ssize_t
        WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)

        class WNDCLASSW(ctypes.Structure):
            _fields_ = [("style", wt.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int),
                        ("cbWndExtra", ctypes.c_int), ("hInstance", wt.HINSTANCE), ("hIcon", wt.HICON),
                        ("hCursor", wt.HANDLE), ("hbrBackground", wt.HBRUSH), ("lpszMenuName", wt.LPCWSTR),
                        ("lpszClassName", wt.LPCWSTR)]

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort), ("Data3", ctypes.c_ushort),
                        ("Data4", ctypes.c_ubyte * 8)]

        class NOTIFYICONDATAW(ctypes.Structure):
            _fields_ = [("cbSize", wt.DWORD), ("hWnd", wt.HWND), ("uID", wt.UINT), ("uFlags", wt.UINT),
                        ("uCallbackMessage", wt.UINT), ("hIcon", wt.HICON), ("szTip", wt.WCHAR * 128),
                        ("dwState", wt.DWORD), ("dwStateMask", wt.DWORD), ("szInfo", wt.WCHAR * 256),
                        ("uVersion", wt.UINT), ("szInfoTitle", wt.WCHAR * 64), ("dwInfoFlags", wt.DWORD),
                        ("guidItem", GUID), ("hBalloonIcon", wt.HICON)]

        self._NID = NOTIFYICONDATAW
        user32.DefWindowProcW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
        user32.DefWindowProcW.restype = LRESULT
        user32.CreateWindowExW.argtypes = [wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD, ctypes.c_int, ctypes.c_int,
                                           ctypes.c_int, ctypes.c_int, wt.HWND, wt.HMENU, wt.HINSTANCE, wt.LPVOID]
        user32.CreateWindowExW.restype = wt.HWND
        user32.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
        user32.LoadImageW.argtypes = [wt.HINSTANCE, wt.LPCWSTR, wt.UINT, ctypes.c_int, ctypes.c_int, wt.UINT]
        user32.LoadImageW.restype = wt.HANDLE
        user32.LoadIconW.argtypes = [wt.HINSTANCE, wt.LPVOID]
        user32.LoadIconW.restype = wt.HICON
        user32.CreatePopupMenu.restype = wt.HMENU
        user32.AppendMenuW.argtypes = [wt.HMENU, wt.UINT, ctypes.c_size_t, wt.LPCWSTR]
        user32.TrackPopupMenu.argtypes = [wt.HMENU, wt.UINT, ctypes.c_int, ctypes.c_int, ctypes.c_int, wt.HWND,
                                          wt.LPVOID]
        user32.DestroyMenu.argtypes = [wt.HMENU]
        user32.SetForegroundWindow.argtypes = [wt.HWND]
        user32.RegisterHotKey.argtypes = [wt.HWND, ctypes.c_int, wt.UINT, wt.UINT]
        user32.UnregisterHotKey.argtypes = [wt.HWND, ctypes.c_int]
        user32.RegisterWindowMessageW.argtypes = [wt.LPCWSTR]
        user32.RegisterWindowMessageW.restype = wt.UINT
        user32.GetMessageW.argtypes = [ctypes.POINTER(wt.MSG), wt.HWND, wt.UINT, wt.UINT]
        user32.TranslateMessage.argtypes = [ctypes.POINTER(wt.MSG)]
        user32.DispatchMessageW.argtypes = [ctypes.POINTER(wt.MSG)]
        shell32.Shell_NotifyIconW.argtypes = [wt.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
        kernel32.GetModuleHandleW.restype = wt.HMODULE

        self._taskbar_created = user32.RegisterWindowMessageW("TaskbarCreated")
        self._wndproc = WNDPROC(self._proc)  # ссылка хранится, иначе сборщик мусора её удалит
        hinst = kernel32.GetModuleHandleW(None)
        wc = WNDCLASSW()
        wc.lpfnWndProc = self._wndproc
        wc.hInstance = hinst
        wc.lpszClassName = "VedomyjVPNTray"
        user32.RegisterClassW(ctypes.byref(wc))
        self.hwnd = user32.CreateWindowExW(0, "VedomyjVPNTray", "VEDOMYJ VPN", 0, 0, 0, 0, 0, None, None, hinst, None)
        if not self.hwnd:
            raise OSError("no tray window")
        self._hicon = user32.LoadImageW(None, self.icon_path, IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE) \
            or user32.LoadIconW(None, ctypes.c_void_p(IDI_APPLICATION))
        self._notify(NIM_ADD)
        self.ok = True
        self._ready.set()

    def _nid(self, flags: int):
        nid = self._NID()
        nid.cbSize = self._ctypes.sizeof(self._NID)
        nid.hWnd = self.hwnd
        nid.uID = 1
        nid.uFlags = flags
        nid.uCallbackMessage = WM_TRAY
        nid.hIcon = self._hicon
        nid.szTip = self.tip
        return nid

    def _notify(self, action: int) -> None:
        nid = self._nid(NIF_MESSAGE | NIF_ICON | NIF_TIP)
        self._shell32.Shell_NotifyIconW(action, self._ctypes.byref(nid))

    def _show_balloon(self) -> None:
        title, text = self._pending_balloon
        self._pending_balloon = None
        nid = self._nid(NIF_INFO)
        nid.szInfoTitle = title
        nid.szInfo = text
        nid.dwInfoFlags = NIIF_INFO
        self._shell32.Shell_NotifyIconW(NIM_MODIFY, self._ctypes.byref(nid))

    def _menu(self) -> None:
        user32 = self._user32
        menu = user32.CreatePopupMenu()
        user32.AppendMenuW(menu, MF_STRING, CMD_OPEN, self.texts("tray_open"))
        user32.AppendMenuW(menu, MF_STRING, CMD_TOGGLE,
                           self.texts("tray_disconnect" if self.connected else "tray_connect"))
        if self.on_hour and not self.connected:
            user32.AppendMenuW(menu, MF_STRING, CMD_HOUR, self.texts("tray_hour"))
        user32.AppendMenuW(menu, MF_SEPARATOR, 0, None)
        user32.AppendMenuW(menu, MF_STRING, CMD_EXIT, self.texts("tray_exit"))
        pt = self._wt.POINT()
        user32.GetCursorPos(self._ctypes.byref(pt))
        user32.SetForegroundWindow(self.hwnd)
        cmd = user32.TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, self.hwnd, None)
        user32.PostMessageW(self.hwnd, WM_NULL, 0, 0)
        user32.DestroyMenu(menu)
        self._command(cmd)

    def _command(self, cmd: int) -> None:
        try:
            if cmd == CMD_OPEN:
                self.on_open()
            elif cmd == CMD_TOGGLE:
                self.on_toggle()
            elif cmd == CMD_EXIT:
                self.on_exit()
            elif cmd == CMD_HOUR and self.on_hour:
                self.on_hour()
        except Exception:
            pass

    def _proc(self, hwnd, msg, wparam, lparam):
        try:
            if msg == WM_TRAY:
                event = lparam & 0xFFFF
                if event in (WM_LBUTTONDBLCLK, NIN_BALLOONUSERCLICK):  # двойной щелчок или щелчок по сообщению
                    self._command(CMD_OPEN)
                elif event == WM_RBUTTONUP:
                    self._menu()
                return 0
            if msg == WM_HOTKEY and wparam == HOTKEY_ID:
                self._command(CMD_TOGGLE)
                return 0
            if msg == WM_HOTKEY_SET:
                self._apply_hotkey()
                return 0
            if msg == WM_UPDATE:
                self._notify(NIM_MODIFY)
                if self._pending_balloon:
                    self._show_balloon()
                return 0
            if msg == self._taskbar_created:  # Проводник перезапустился — значок нужно добавить заново
                self._notify(NIM_ADD)
                return 0
            if msg == WM_CLOSE:
                self._user32.DestroyWindow(hwnd)
                return 0
            if msg == WM_DESTROY:
                self._user32.UnregisterHotKey(hwnd, HOTKEY_ID)
                self._notify(NIM_DELETE)
                self.ok = False
                self._user32.PostQuitMessage(0)
                return 0
        except Exception:
            pass
        return self._user32.DefWindowProcW(hwnd, msg, wparam, lparam)
