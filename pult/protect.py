"""Защита: один сломанный способ обхода не ломает остальные.

1. Предохранители. Способ (другой отпечаток TLS, маскировка, а дальше и новые способы), который в этой сети
   дважды подряд не помог, когда помогло другое, пропускается: 10 минут, потом час, потом сутки. Ключ —
   хеш сети (как у памяти сетей) и вид способа. Если не сработало вообще ничего, способы не виноваты —
   такие неудачи не считаются (иначе лёгший интернет «сжёг» бы все способы).
2. Автооткат. Настройки поменяли, пока VPN работал. Через GUARD_WAIT секунд программа смотрит, идут ли
   данные. Не идут (а до изменения шли) — возвращает прежние значения и пишет, что и почему вернула.
3. Безопасный запуск. Программа дважды подряд упала, не успев проработать SAFE_OK_AFTER секунд, — следующий
   запуск идёт без необязательной автоматики (SAFE_OFF) и говорит об этом. Настройки при этом не меняются.
4. «Вернуть как было»: профессиональные настройки — значения по умолчанию.
"""

from __future__ import annotations

import json
import os
import threading
import time

from . import settings as settings_mod

FUSE_FAILS = 2                    # столько неудач подряд (когда другое помогло) — пауза
FUSE_STEPS = (600, 3600, 86400)   # с: пауза растёт — 10 минут, час, сутки
FUSES_MAX = 300
GUARD_WAIT = 40                   # с: после изменения настроек ждём, пока VPN переподключится и проверит связь
SAFE_OK_AFTER = 90                # с: программа проработала столько — запуск удачный
SAFE_CRASHES = 2                  # столько неудачных запусков подряд — следующий безопасный

# Изменение этих настроек при работающем VPN — под присмотром автоотката.
GUARDED_KEYS = ("mode", "tun_enabled", "tun_engine", "dns_encrypted", "block_quic", "mask_auto", "fp_auto",
                "failover", "multi_enabled", "game_mode", "leak_protection", "kill_switch", "ru_direct",
                "block_ads", "system_proxy", "engine_pick", "wl_priority")

# Безопасный запуск выключает на один запуск только необязательную автоматику (не VPN и не защиту).
SAFE_OFF = ("auto_routes", "multi_enabled", "fp_auto", "mask_auto", "net_profiles", "app_update")

# Профессиональные настройки: ключ → значение по умолчанию («Вернуть как было»).
PRO_KEYS = ("fuses_enabled", "guard_rollback", "safe_start", "net_memory", "autopilot", "fp_auto", "mask_auto",
            "failover", "data_watch", "whitelist_auto", "auto_routes", "auto_stall", "multi_enabled")


LABELS = {"mode": "режим маршрутизации", "tun_enabled": "режим TUN", "tun_engine": "движок TUN",
          "dns_encrypted": "шифрование DNS", "block_quic": "блокировка QUIC", "mask_auto": "маскировка",
          "fp_auto": "подбор отпечатка", "failover": "мгновенное переключение", "multi_enabled": "мультисервер",
          "game_mode": "режим для игр", "leak_protection": "защита от утечек", "kill_switch": "kill switch",
          "ru_direct": "российские сайты напрямую", "block_ads": "без рекламы", "system_proxy": "системный прокси",
          "engine_pick": "способ подключения", "wl_priority": "белые списки"}


PRO_NAMES = {"fuses_enabled": "предохранители", "guard_rollback": "автооткат", "safe_start": "безопасный запуск",
             "net_memory": "память сетей", "autopilot": "автопереход", "fp_auto": "подбор отпечатка",
             "mask_auto": "маскировка", "failover": "мгновенное переключение", "data_watch": "сторож данных",
             "whitelist_auto": "обход белых списков", "auto_routes": "автоподбор для сайтов",
             "auto_stall": "сайты, которые не догружаются", "multi_enabled": "мультисервер"}


def change_label(before: dict) -> str:
    return ", ".join(LABELS.get(k, k) for k in before) or "настройки"


def pro_defaults() -> dict:
    return {k: settings_mod.DEFAULTS[k] for k in PRO_KEYS}


class ProtectMixin:
    """Часть Engine. Использует: settings, save, log, tell, connected, conn_busy, data_flowing, _data_ok,
    _net_id, run_task, reconnect, _mono, _ping_failures, _ping_at."""

    def _protect_init(self) -> None:
        self._guard: dict | None = None
        self._guard_checking = False
        self.safe_mode = False
        self._fuse_lock = threading.Lock()

    # ---------- предохранители ----------

    def _fuses(self) -> dict:
        f = self.settings.get("fuses")
        if not isinstance(f, dict):
            f = {}
            self.settings["fuses"] = f
        return f

    def _fuse_key(self, kind: str) -> str:
        return f"{self._net_id(cached_only=True) or 'any'}|{kind}"

    def fuse_ok(self, kind: str) -> bool:
        """Можно ли сейчас пробовать способ kind в этой сети."""
        if not kind or not self.settings.get("fuses_enabled", True):
            return True
        rec = self._fuses().get(self._fuse_key(kind))
        return not rec or rec.get("until", 0) <= time.time()

    def fuse_result(self, kind: str, ok: bool) -> None:
        """Итог способа в лестнице, где что-то помогло: ok — помог он сам."""
        if not kind:
            return
        with self._fuse_lock:
            fuses = self._fuses()
            key = self._fuse_key(kind)
            rec = fuses.get(key) or {"n": 0, "level": 0, "until": 0}
            if ok:
                if key in fuses:
                    fuses.pop(key, None)
                    self.save()
                return
            rec["n"] = rec.get("n", 0) + 1
            rec["at"] = time.time()
            if rec["n"] >= FUSE_FAILS:
                level = min(rec.get("level", 0), len(FUSE_STEPS) - 1)
                rec["until"] = time.time() + FUSE_STEPS[level]
                rec["level"] = level + 1
                rec["n"] = 0
                self.log(f"Предохранитель: «{kind}» в этой сети не помогает — пропускаю его "
                         f"{self._dur(FUSE_STEPS[level])}.")
            fuses[key] = rec
            if len(fuses) > FUSES_MAX:
                for k in sorted(fuses, key=lambda k: fuses[k].get("at", 0))[:len(fuses) - FUSES_MAX]:
                    fuses.pop(k, None)
            self.save()

    @staticmethod
    def _dur(sec: float) -> str:
        if sec >= 86400:
            return "сутки"
        if sec >= 3600:
            return "час"
        return f"{int(sec // 60)} мин"

    def fuses_state(self) -> list[dict]:
        """Способы на паузе в этой сети — для «Профессиональных настроек»."""
        now = time.time()
        prefix = (self._net_id(cached_only=True) or "any") + "|"
        out = []
        for k, rec in self._fuses().items():
            if k.startswith(prefix) and rec.get("until", 0) > now:
                out.append({"kind": k[len(prefix):], "left": int(rec["until"] - now)})
        return sorted(out, key=lambda x: x["kind"])

    def fuses_clear(self) -> None:
        self.settings["fuses"] = {}
        self.save()
        self.log("Предохранители сброшены: все способы снова пробуются.")

    # ---------- автооткат изменений ----------

    def _working_now(self) -> bool:
        """VPN сейчас работает: с сервера идут данные или проверка связи недавно прошла."""
        if not self.connected:
            return False
        if self.data_flowing(60):
            return True
        return not getattr(self, "_ping_failures", 1) and self._mono() - getattr(self, "_ping_at", -1e9) < 180

    def guard_change(self, before: dict, label: str) -> None:
        """Перед изменением настроек: before — прежние значения изменённых ключей. Если VPN работал,
        через GUARD_WAIT секунд проверим, работает ли он с новыми, и при необходимости вернём как было."""
        before = {k: v for k, v in (before or {}).items() if k in GUARDED_KEYS}
        if not before or not self.settings.get("guard_rollback", True) or not self._working_now():
            return
        if self._guard:  # изменения подряд — откатывать к самому первому рабочему состоянию
            before = dict(before, **self._guard["before"])
            label = self._guard["label"] if label == self._guard["label"] else f"{self._guard['label']}, {label}"
        self._guard = {"before": before, "label": label, "at": self._mono()}

    def _guard_tick(self) -> None:
        g = self._guard
        if not g or self._guard_checking:
            return
        if not self.connected:
            self._guard = None  # VPN выключили — проверять нечего
            return
        if self.conn_busy() or self._mono() - g["at"] < GUARD_WAIT:
            return
        # доказательство — только после изменения: данные за последние 30 с или пинг, измеренный после него
        if self.data_flowing(30) or (not getattr(self, "_ping_failures", 1)
                                     and getattr(self, "_ping_at", -1e9) > g["at"]):
            self._guard = None
            self.log(f"Изменение прижилось: {g['label']} — VPN работает.")
            return
        self._guard_checking = True
        threading.Thread(target=self._guard_check, args=(g,), daemon=True).start()

    def _guard_check(self, g: dict) -> None:
        try:
            r = self._data_ok()
            if r.get("ok") or r.get("inconclusive") or self._guard is not g:
                if self._guard is g:
                    self._guard = None
                    self.log(f"Изменение прижилось: {g['label']} — VPN работает.")
                return
            self._guard = None
            changed = {k: v for k, v in g["before"].items() if self.settings.get(k) != v}
            if not changed:
                return
            self.settings.update(changed)
            self.save()
            self.log(f"Автооткат: после изменения ({g['label']}) данные через VPN перестали идти — "
                     f"вернул как было.")
            self.tell(f"Вернул настройки как было: после изменения ({g['label']}) VPN перестал работать.")
            self.notify("settings")
            self.run_task("Возвращаю настройки как было", self.reconnect, lane="conn")
        except Exception as exc:
            self.log(f"Автооткат: {exc}")
        finally:
            self._guard_checking = False

    # ---------- безопасный запуск ----------

    def _start_file(self) -> str:
        return os.path.join(self.paths.data_dir, "start.json")

    def safe_start_begin(self) -> None:
        """В начале запуска: прошлые запуски падали — этот безопасный."""
        path = self._start_file()
        try:
            with open(path, encoding="utf-8") as f:
                info = json.load(f)
        except (OSError, ValueError):
            info = {}
        fails = int(info.get("fails", 0)) + (1 if info.get("running") else 0)
        self.safe_mode = bool(self.settings.get("safe_start", True)) and fails >= SAFE_CRASHES
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"running": True, "fails": fails, "at": time.time()}, f)
        except OSError:
            pass
        if self.safe_mode:
            self.log(f"Безопасный запуск: программа {fails} раза подряд закрылась с ошибкой при запуске — "
                     "в этот раз без необязательной автоматики.")
            self.problem("safe_mode", "Безопасный запуск",
                         "Программа несколько раз подряд закрылась с ошибкой при запуске, поэтому сейчас "
                         "работает без необязательной автоматики (автоподбор сайтов, мультисервер, подбор "
                         "отпечатка и маскировки).",
                         where="Дополнительно → Профессиональные",
                         fix="Пришли отчёт: «Журнал ошибок» → «Отчёт». Следующий запуск — обычный.")

    def safe_start_ok(self) -> None:
        """Программа проработала SAFE_OK_AFTER секунд — запуск удачный, счётчик падений обнулить."""
        try:
            with open(self._start_file(), "w", encoding="utf-8") as f:
                json.dump({"running": True, "fails": 0, "at": time.time()}, f)
        except OSError:
            pass

    def safe_start_end(self) -> None:
        """Обычное закрытие программы."""
        try:
            with open(self._start_file(), "w", encoding="utf-8") as f:
                json.dump({"running": False, "fails": 0, "at": time.time()}, f)
        except OSError:
            pass

    def opt(self, key: str, default=True):
        """Настройка необязательной автоматики с учётом безопасного запуска."""
        if self.safe_mode and key in SAFE_OFF:
            return False
        return self.settings.get(key, default)

    # ---------- профессиональные настройки ----------

    def pro_state(self) -> dict:
        return {"keys": {k: self.settings.get(k, settings_mod.DEFAULTS[k]) for k in PRO_KEYS},
                "defaults": pro_defaults(), "fuses": self.fuses_state(), "safe_mode": self.safe_mode,
                "guard": bool(self._guard)}

    def pro_set(self, values: dict) -> None:
        changed = []
        for k, v in (values or {}).items():
            if k in PRO_KEYS and isinstance(v, bool) and self.settings.get(k) != v:
                self.settings[k] = v
                changed.append(k)
        if changed:
            self.save()
            self.log("Профессиональные настройки: " + ", ".join(
                f"{PRO_NAMES.get(k, k)} — {'вкл' if self.settings[k] else 'выкл'}" for k in changed) + ".")

    def pro_reset(self) -> list[str]:
        """«Вернуть как было»: профессиональные настройки — по умолчанию; предохранители сброшены."""
        changed = [k for k, v in pro_defaults().items() if self.settings.get(k) != v]
        self.settings.update(pro_defaults())
        self.settings["fuses"] = {}
        self.save()
        self.log("Профессиональные настройки возвращены как было"
                 + (f" ({', '.join(PRO_NAMES.get(k, k) for k in changed)})." if changed else "."))
        return changed
