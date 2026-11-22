"""Бесплатный WARP во встроенном ядре Xray (1.21): запасной путь «Авто», «WARP после VPN» и перенос на телефон.

Как это устроено:
  • ядро Xray умеет WireGuard само, а шум Finalmask (ядро 26.3.27+) заменяет обманки AmneziaWG (warp.xray_outbound) —
    программа AmneziaWG для этого не нужна;
  • запасной путь: в «Авто» серверы не ответили ни одним способом (лестница, проверка всех, обновление подписок) —
    программа включает свой WARP (нет его — создаёт), перебирая наборы обманок, пока не пойдут данные.
    Раз в 5–30 минут проверяет серверы и сама возвращается на ожившую;
  • «WARP после VPN» — маршрут для сервиса или сайта: соединение идёт через VPN-сервер, а оттуда — через WARP.
    Сайт видит адрес Cloudflare, а не адрес VPN-сервера (полезно, когда сайт не пускает адреса VPN-серверов).
    Провайдер по-прежнему видит только VPN;
  • перенос на другое устройство — QR-код конфига для приложения AmneziaWG (с обманками, которые работают сейчас).

Приватность: ключ WARP хранится только в зашифрованных настройках (как и раньше), в журнал не попадает;
метка доступа Cloudflare не хранится (warp.register).
"""

from __future__ import annotations

import time

from . import tester, warp, xray
from .links import Server

WARP_KEY = "warp"
WARP_NAME = "WARP"
REVIVE_STEPS = (300, 600, 1200, 1800)  # с: когда снова проверить серверы, пока работает запасной WARP
FORCE_BACK_S = 1800                    # дольше получаса на WARP — возвращаемся, даже если идут данные
VARIANTS_MAX = 8


class WarpServer(Server):
    """WARP во встроенном ядре: один ключ для любых наборов обманок (меняется только адрес сервера Cloudflare)."""

    @property
    def key(self) -> str:
        return WARP_KEY


class WarpAutoMixin:
    """Часть Engine. Использует: servers, settings, paths, current, connected, method, create_warp, _warp_net,
    _switch_to, test_all, best, ranked_pool, may_apply, run_task, is_busy, progress, check_stop, log, tell,
    problem, resolve, notify, save, stop_event, _core_versions, ladder (_ladder_* поля)."""

    def _warpauto_init(self) -> None:
        self.warp_since = 0.0        # с какого времени работает запасной WARP (0 — не работает)
        self._warp_revive_at = 0.0
        self._warp_revive_n = 0

    # ---------- свой WARP ----------

    def own_warp(self) -> Server | None:
        """Свой WARP, созданный кнопкой (конфиг AmneziaWG среди своих серверов)."""
        return next((x for x in self.servers if x.engine == "awg" and x.sub_id == "manual" and x.name == warp.NAME
                     and warp.is_warp(x.awg_conf)), None)

    def warp_xray(self, params: dict | None = None, src: Server | None = None, tag: str = "proxy",
                  noise: bool = True) -> WarpServer:
        """Свой WARP как сервер для ядра Xray. params — набор обманок (адрес Cloudflare, I1, Jc…), None — из конфига."""
        src = src or self.own_warp()
        if not src:
            raise RuntimeError("Бесплатного WARP ещё нет.")
        conf = warp.variant(src.awg_conf, params) if params else src.awg_conf
        ob = warp.xray_outbound(conf, tag, noise=noise)
        host, _, port = ob["settings"]["peers"][0]["endpoint"].rpartition(":")
        return WarpServer(name=WARP_NAME, protocol="wireguard", address=host.strip("[]"),
                          port=int(port) if port.isdigit() else 0, outbound=ob, sub_id="warp",
                          note="бесплатный WARP от Cloudflare во встроенном ядре")

    def _warp_variants(self) -> list[dict | None]:
        """Наборы обманок по порядку: рабочий в этой сети, из конфига, затем остальные."""
        net = self._warp_net()
        out: list[dict | None] = []
        saved = (self.settings.get("warp_nets") or {}).get(net) if net else None
        if saved:
            out.append(saved)
        out.append(None)
        out += [warp.preset(i) for i in range(len(warp.PRESETS))]
        seen, uniq = set(), []
        src = self.own_warp()
        for p in out:
            cur = p or (warp.current_params(src.awg_conf) if src else {})
            sig = (cur.get("endpoint", ""), str(cur.get("i1", ""))[:40], cur.get("label", ""))
            if sig in seen:
                continue
            seen.add(sig)
            uniq.append(p)
        return uniq[:VARIANTS_MAX]

    def warp_pick(self) -> WarpServer | None:
        """Перебрать наборы обманок временным ядром: первый, через который идут данные. Рабочий запоминается для сети."""
        self._core_versions()
        variants = self._warp_variants()
        exe = self.paths.xray
        for i, params in enumerate(variants, 1):
            self.check_stop()
            self.progress(f"WARP: пробую обманки, вариант {i} из {len(variants)}")
            srv = self.warp_xray(params)
            r = tester.probe_data(self.paths, [srv], self.stop_event, exe=exe)[0]
            if r.get("ok"):
                p = params or warp.current_params(self.own_warp().awg_conf)
                net = self._warp_net()
                if net and p:
                    nets = dict(self.settings.get("warp_nets") or {})
                    nets[net] = {k: p[k] for k in ("endpoint", "jc", "jmin", "jmax", "i1", "label") if k in p}
                    while len(nets) > self.WARP_NETS_MAX:
                        nets.pop(next(iter(nets)))
                    self.settings["warp_nets"] = nets
                    self.save()
                self.log(f"WARP во встроенном ядре: данные идут (обманки «{(p or {}).get('label', '')}», вариант {i}).")
                return srv
        self.log(f"WARP во встроенном ядре: данные не пошли ни с одним из {len(variants)} наборов обманок.")
        return None

    # ---------- запасной путь «Авто» ----------

    def is_warp_fallback(self) -> bool:
        return bool(self.connected and self.current is not None and self.current.key == WARP_KEY and self.warp_since)

    def _warp_fallback(self, reason: str) -> bool:
        """Из failover: серверы не помогли — включить свой WARP. True — данные пошли."""
        s = self.settings
        if not s.get("warp_fallback", True) or self.method() == "awg":
            return False
        if self.is_warp_fallback():
            return False  # WARP уже был запасным и тоже перестал — честно «ничего не работает»
        self.ladder_step = "бесплатный WARP"
        if not self.own_warp():
            self.progress("Серверы не работают — создаю бесплатный WARP")
            try:
                self.create_warp()
            except Exception as exc:
                self.log(f"Запасной WARP: не получилось создать ({exc}).")
                return False
        try:
            srv = self.warp_pick()
        except Exception as exc:
            if exc.__class__.__name__ in ("Cancelled", "Busy"):
                raise
            self.log(f"Запасной WARP: {exc}")
            return False
        if not srv or not self._switch_to(srv):
            return False
        self.warp_since = time.time()
        self._warp_revive_n = 0
        self._warp_revive_at = time.time() + REVIVE_STEPS[0]
        self.ladder_last = {"at": time.time(), "ok": True, "text": "серверы не работают — временно через WARP"}
        self._ladder_fails = 0
        self._ladder_next = 0.0
        self.ladder_step = ""
        self.what_works = None
        self.resolve("no_working")
        self.problem("warp_fallback", "Серверы не работают — пока через WARP", reason, where="Главная",
                     fix="Программа сама проверяет серверы и вернётся на первый оживший. "
                         "Выключить запасной WARP можно в «Профессиональных».", level="warn")
        self.log(f"Запасной WARP: серверы не работают ({reason}) — включил бесплатный WARP.")
        self.tell("Серверы не работают — временно включил бесплатный WARP. Вернусь на сервер, как только он оживёт.")
        self.notify("status")
        return True

    def _warp_left(self) -> None:
        if self.warp_since:
            self.warp_since = 0.0
            self.resolve("warp_fallback")

    def _warp_revive_tick(self) -> None:
        """Из монитора: пора ли проверить, ожили ли серверы."""
        if not self.warp_since:
            return
        if not self.is_warp_fallback():
            self._warp_left()  # подключились иначе (сам человек или выключил) — запасной режим закончился
            return
        if time.time() < self._warp_revive_at or self.is_busy():
            return
        self._warp_revive_n += 1
        self._warp_revive_at = time.time() + REVIVE_STEPS[min(self._warp_revive_n, len(REVIVE_STEPS) - 1)]
        self.run_task("Проверяю, ожили ли серверы", self._warp_revive, lane="conn")

    def _warp_revive(self) -> None:
        if not self.is_warp_fallback():
            return
        if not self.may_apply() and time.time() - self.warp_since < FORCE_BACK_S:
            self.log("Запасной WARP: идут данные — проверю серверы позже, чтобы не оборвать загрузку.")
            return
        warp_srv = self.current
        pool = [x for x in self.pool() if x.supported and not x.stub]
        if not pool:
            return
        if not self.test_all(pool):
            self.log("Запасной WARP: серверы всё ещё не отвечают — остаюсь на WARP.")
            return
        for srv in self.ranked_pool()[:3]:
            self.check_stop()
            if self._switch_to(srv):
                self._warp_left()
                self.log(f"Сервер «{srv.name}» снова работает — ушёл с запасного WARP.")
                self.tell(f"Сервер снова работает — вернулся на «{srv.name}».")
                self.notify("status")
                return
        self.log("Запасной WARP: серверы отвечают на проверку, но данные через них не идут — остаюсь на WARP.")
        if self.current is not warp_srv and not self._switch_to(warp_srv):
            self.warp_since = 0.0  # и WARP не поднялся — дальше как обычно: сторож заметит и начнёт поиск

    # ---------- «WARP после VPN» ----------

    def warp_route_outbound(self) -> dict | None:
        """Outbound «warp» для своих маршрутов: WARP поверх основного VPN (без шума — провайдер видит только VPN)."""
        src = self.own_warp()
        if not src:
            return None
        try:
            net = self._net_id(cached_only=True) if self.settings.get("net_memory", True) else ""
        except Exception:
            net = ""
        saved = (self.settings.get("warp_nets") or {}).get(net) if net else None
        ob = self.warp_xray(saved, src, tag="warp", noise=False).outbound
        ob.pop("streamSettings", None)
        ob["streamSettings"] = {"sockopt": {"dialerProxy": "proxy"}}
        return ob

    def warp_route_set(self, kind: str, value, exact: bool = False) -> None:
        """«Через VPN и WARP» для сервиса (kind="svc") или сайтов (kind="site"): своего WARP нет — сначала создать
        (регистрация идёт через VPN, если он включён)."""
        if not self.own_warp():
            self.create_warp()
        dpi_changed = False
        if kind == "svc":
            dpi_changed = self.set_service_route(str(value), "warp")
        else:
            for h in list(value)[:200]:
                dpi_changed = self.route_site(str(h), "warp", main_domain=not exact)[1] or dpi_changed
        if self.core_running or dpi_changed:
            self.apply_routes(dpi_changed)

    # ---------- перенос на другое устройство ----------

    def warp_share_text(self) -> str:
        src = self.own_warp()
        if not src:
            raise RuntimeError("Бесплатного WARP ещё нет — создай его кнопкой «Создать бесплатный WARP».")
        conf = self.awg_conf_text(src)
        net = self._warp_net()
        saved = (self.settings.get("warp_nets") or {}).get(net) if net else None
        if saved and conf == src.awg_conf:
            conf = warp.variant(src.awg_conf, saved)  # обманки, которые работают в этой сети
        return warp.share_conf(conf)

    def warp_state(self) -> dict:
        src = self.own_warp()
        return {"own": bool(src), "fallback": self.is_warp_fallback(), "since": self.warp_since or 0,
                "next_check": max(0, int(self._warp_revive_at - time.time())) if self.warp_since else 0,
                "enabled": bool(self.settings.get("warp_fallback", True)),
                "core_ok": core_ok(self.xray_ver or "")}


def core_ok(version: str) -> bool:
    """Ядро умеет шум Finalmask (без него WireGuard в России обычно блокируют)."""
    return not version or xray._ver(version) >= xray.FM_MIN
