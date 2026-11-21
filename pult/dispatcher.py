"""Диспетчер подключения: одно место, где решается, можно ли автоматике трогать VPN.

Раньше полтора десятка механизмов (автопереход, сторож данных, память сетей, белые списки, автоподбор,
мультисервер, обход замедлений, реклама…) сами переподключали VPN и не знали друг о друге. Каждое
переподключение рвёт все соединения на 1–3 секунды — отсюда «постоянно лагает». Теперь они спрашивают
диспетчер. Правила:

1. Идут данные — сервер жив, ничего не трогаем (ни смена сервера, ни «применить по-новому»).
2. Сервер меняем только после ~30 секунд подтверждённой тишины (раньше — через ~10 секунд).
3. Не чаще одной автосмены сервера за 2 минуты; если смены не помогают (сервер «моргает»),
   пауза растёт: 5, потом 10 минут. Пока связи нет совсем, пауза — 2 минуты.
4. Ты сам подключил или переключил — автоматика минуту молчит.
5. Не срочные изменения (новые правила автоподбора, карта мультисервера, обход замедлений) не рвут
   соединения: они откладываются и применяются, когда трафик затихнет.

Действия человека (кнопки окна) диспетчер не ограничивает. Восстановление после падения ядра — тоже:
связи и так нет.
"""

from __future__ import annotations

import collections
import time

SILENCE_S = 30.0          # с: сколько тишины подтверждает, что сервер правда не работает
RX_ALIVE_S = 10.0         # с: данные приходили за это время — сервер жив
SWITCH_GAP = 120.0        # с: не чаще одной автосмены сервера за это время
FLAP_GAPS = (300.0, 600.0)  # с: сервер «моргает» (2 и 3+ автосмены за 15 минут) — пауза больше
FLAP_WINDOW = 900.0       # с: за какое время считаем автосмены
DEAD_S = 90.0             # с: данных нет так долго — связи нет совсем, длинные паузы не нужны
USER_QUIET_S = 60.0       # с: после действия человека с VPN автоматика молчит
IDLE_S = 10.0             # с: трафик затих — можно применить отложенное


class DispatcherMixin:
    """Часть Engine. Использует: self._mono(), self._rx_at, self.connected, self._lane, self.log,
    self.run_task, self.conn_busy, self.reconnect."""

    def _dispatcher_init(self) -> None:
        self._auto_switches: collections.deque = collections.deque(maxlen=20)  # monotonic-время автосмен
        self._user_conn_at = -1e9   # monotonic: когда человек последний раз что-то делал с VPN
        self._deferred = ""         # отложенное «применить по-новому» (причина)
        self._deferred_at = 0.0
        self._denied_logged: dict[str, float] = {}

    # ---------- кто спрашивает ----------

    def _by_user(self) -> bool:
        """Текущую задачу начал человек (кнопкой в окне)."""
        return bool(getattr(self._lane, "user", False))

    def note_user_conn(self) -> None:
        self._user_conn_at = self._mono()

    def data_flowing(self, within: float = RX_ALIVE_S) -> bool:
        return self._mono() - self._rx_at < within

    def silent_for(self) -> float:
        """Сколько секунд с сервера ничего не приходило."""
        return self._mono() - self._rx_at

    # ---------- смена сервера, потому что он перестал работать ----------

    def switch_gap(self) -> float:
        """Сколько нужно выждать после прошлой автосмены."""
        now = self._mono()
        recent = [t for t in self._auto_switches if now - t < FLAP_WINDOW]
        if self.silent_for() >= DEAD_S or len(recent) <= 1:
            return SWITCH_GAP
        return FLAP_GAPS[min(len(recent) - 2, len(FLAP_GAPS) - 1)]

    def may_switch(self, reason: str = "") -> str:
        """Можно ли автоматике сменить сервер. "" — можно; иначе — почему нельзя (для журнала)."""
        if self._by_user() or not self.connected:
            return ""
        now = self._mono()
        if self.data_flowing():
            return "с сервера идут данные — он работает"
        if self.silent_for() < SILENCE_S:
            return f"тишина меньше {int(SILENCE_S)} с — жду подтверждения"
        if now - self._user_conn_at < USER_QUIET_S:
            return "ты только что сам подключал — автоматика ждёт минуту"
        if self._auto_switches:
            wait = self.switch_gap() - (now - self._auto_switches[-1])
            if wait > 0:
                return f"сервер недавно уже меняли — следующая смена не раньше чем через {int(wait) + 1} с"
        return ""

    def note_auto_switch(self) -> None:
        if not self._by_user():
            self._auto_switches.append(self._mono())

    def deny_note(self, what: str, why: str) -> None:
        """Отказ — в журнал программы, но не чаще раза в минуту на одно и то же."""
        key = what + "|" + why.split(" — ")[0]
        now = self._mono()
        if now - self._denied_logged.get(key, -1e9) >= 60:
            self._denied_logged[key] = now
            self.log(f"Диспетчер: не {what} — {why}.")

    # ---------- «применить по-новому», когда ничего не сломано ----------

    def may_apply(self) -> bool:
        """Не срочное переподключение: можно, только когда трафик затих и человек не трогал VPN минуту."""
        if self._by_user():
            return True
        return not self.data_flowing(IDLE_S) and self._mono() - self._user_conn_at >= USER_QUIET_S

    def defer_reconnect(self, why: str) -> None:
        if not self._deferred:
            self._deferred_at = self._mono()
            self.log(f"Применю позже, когда затихнет трафик: {why}.")
        self._deferred = why

    def _deferred_tick(self) -> None:
        """Из монитора: отложенное применяется, как только трафик затих."""
        if not self._deferred or not self.connected or self.conn_busy() or not self.may_apply():
            if self._deferred and not self.connected:
                self._deferred = ""  # VPN выключен — при следующем подключении настройки и так новые
            return
        why, self._deferred = self._deferred, ""

        def apply():
            self._lane.why = why
            self.reconnect(urgent=True)
        self.run_task("Применяю отложенные изменения", apply, lane="conn")

    def dispatcher_state(self) -> dict:
        now = self._mono()
        last = self._auto_switches[-1] if self._auto_switches else None
        return {"deferred": self._deferred, "flowing": self.data_flowing(),
                "next_switch_in": max(0, int(self.switch_gap() - (now - last))) if last is not None else 0}
