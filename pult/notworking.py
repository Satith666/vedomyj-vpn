"""«Не работает»: человек выбирает, что не работает (сервис из списка, программу или сайт), программа проверяет
это всеми путями сразу и ставит рабочий.

Проверка не только «открылось», но и «работает полностью»: после ответа сайта качаем до 16 КБ (`stall_test`) —
так ловится обрыв соединения после первых килобайт, когда страница открывается, а видео и картинки нет.

Пути: как сейчас → через VPN → напрямую (человек сам попросил, поэтому можно) → через другие серверы →
ускорение (если оно работает, а напрямую режется). Найденный путь становится своим маршрутом сервиса, сайта
или программы. Перед изменением запоминаются все списки маршрутов — «Отменить» возвращает их как было.

Внутри — то, что уже есть: проверка сайта (`check_site`), починка «работает не полностью» (`repair_site`),
подбор пути для программы (`pick_app`), маршруты сервисов (`set_service_route`).
"""

from __future__ import annotations

import copy
import time
from urllib.parse import urlsplit

from . import apps, i18n, services

# всё, что может поменять починка, — для «Отменить»
NW_KEYS = ("routes", "proxy_list", "direct_list", "block_list", "auto_sites", "app_routes", "ads_allow")
NW_KINDS = ("service", "app", "site")
UNDO_TTL = 24 * 3600   # отменить можно в течение суток


def _good(r: dict | None) -> bool:
    return bool(r) and r.get("state") in (services.OK, services.SLOW)


def _full(r: dict | None) -> bool:
    return bool(r) and r.get("state") in (services.STALL_OK, services.STALL_SMALL)


def service_by_name(name: str) -> dict | None:
    n = (name or "").strip().lower()
    return next((s for s in services.SERVICES if s["name"].lower() == n), None)


def service_host(svc: dict) -> str:
    """Адрес для проверки «качается ли»: первая ссылка сервиса (у YouTube — сама страница с плеером)."""
    return (urlsplit(svc["urls"][0]).hostname or svc["domains"][0]).lower()


class NotWorkingMixin:
    """Часть Engine: «Не работает» — проверить и починить сервис, программу или сайт."""

    def _nw_init(self) -> None:
        self.nw_last: dict | None = None
        self._nw_undo: dict | None = None

    # ---------- что можно выбрать ----------

    def nw_targets(self) -> dict:
        """Списки для окна «Не работает»: сервисы и программы (запущенные и знакомые)."""
        running = []
        try:
            running = self.apps_scan()
        except Exception as exc:  # список программ — не главное, окно откроется и без него
            self.log(f"Список программ: {exc}")
        seen, progs = set(), []
        for a in running:
            p = apps.preset_for(a["name"])
            if a["name"] in seen:
                continue
            seen.add(a["name"])
            progs.append({"name": a["name"], "title": p["title"] if p else a["name"], "known": bool(p and p.get("urls"))})
        for p in apps.PRESETS:
            n = p["process"][0]
            if n not in seen and p.get("urls"):
                seen.add(n)
                progs.append({"name": n, "title": p["title"], "known": True, "preset": True})
        return {"services": [{"name": s["name"], "russian": bool(s.get("russian"))} for s in services.SERVICES],
                "apps": progs[:60], "apps_supported": apps.IS_WINDOWS or self._apps_lister is not None}

    # ---------- починка ----------

    def nw_fix(self, kind: str, value: str, target: str = "") -> dict:
        if kind not in NW_KINDS:
            raise RuntimeError("Выбери, что не работает: сервис, программу или сайт.")
        value = (value or "").strip()
        if not value:
            raise RuntimeError({"service": "Выбери сервис из списка.", "app": "Выбери программу из списка.",
                                "site": "Вставь адрес сайта, например example.com."}[kind])
        before = {k: copy.deepcopy(self.settings.get(k)) for k in NW_KEYS}
        if kind == "service":
            res = self._nw_service(value)
        elif kind == "app":
            res = self._nw_app(value, target)
        else:
            res = self._nw_site(value)
        changed = any(self.settings.get(k) != before[k] for k in NW_KEYS)
        self._nw_undo = {"keys": before, "at": time.time()} if changed else None
        self.nw_last = dict(res, kind=kind, changed=changed, at=time.time())
        self.log(f"«Не работает» — {res['name']}: {res['verdict']}")
        self.notify("nw", result=self.nw_state()["last"])
        return self.nw_state()["last"]

    def nw_undo(self) -> str:
        u = self._nw_undo
        if not u or time.time() - u["at"] > UNDO_TTL:
            self._nw_undo = None
            raise RuntimeError("Отменять нечего.")
        dpi_before = {k: v for k, v in (self.settings.get("routes") or {}).items() if v.get("via") == "dpi"}
        for k, v in u["keys"].items():
            if v is None:
                self.settings.pop(k, None)
            else:
                self.settings[k] = v
        self._nw_undo = None
        dpi_after = {k: v for k, v in (self.settings.get("routes") or {}).items() if v.get("via") == "dpi"}
        self.save()
        name = (self.nw_last or {}).get("name", "")
        if self.nw_last:
            self.nw_last = dict(self.nw_last, changed=False, undone=True)
        self.log(f"«Не работает» — {name}: вернул маршруты как было.")
        self.notify("settings")
        self.apply_routes(dpi_before != dpi_after)
        self.notify("nw", result=self.nw_state()["last"])
        return name

    def nw_state(self) -> dict:
        last = self.nw_last
        out = None
        if last:
            out = {k: last.get(k) for k in ("kind", "name", "changed", "at", "undone", "route")}
            out["verdict"] = i18n.tr(last.get("verdict") or "")
            out["steps"] = [i18n.tr(x) for x in last.get("steps") or []]
            out["can_undo"] = bool(self._nw_undo) and time.time() - self._nw_undo["at"] < UNDO_TTL
        return {"last": out}

    # ---------- сервис ----------

    def _nw_try(self, svc: dict, host: str, port, label: str, steps: list) -> bool:
        """Сервис открывается этим путём и качается полностью?"""
        self.check_stop()
        r = services.check_service(svc, port)
        if not _good(r):
            steps.append(f"{label}: не открывается" + (f" ({r.get('detail')})" if r.get("detail") else ""))
            return False
        st = services.stall_test(host, port)
        if not _full(st):
            steps.append(f"{label}: открывается, но {st.get('detail') or 'не качается'}")
            return False
        steps.append(f"{label}: работает полностью")
        return True

    def _nw_service(self, name: str) -> dict:
        svc = service_by_name(name)
        if not svc:
            raise RuntimeError("Такого сервиса нет в списке.")
        name = svc["name"]
        host = service_host(svc)
        self.progress(f"Проверяю сервис {name}")
        steps: list[str] = []
        direct = self._direct_http()
        cur_port = self.ports["http"] if self.connected else direct
        if self._nw_try(svc, host, cur_port, "как сейчас", steps):
            verdict = (f"{name} открывается и качается полностью. Если не работает только в приложении — "
                       f"перезапусти его; если в браузере — обнови страницу с очисткой кэша (Ctrl+F5).")
            return {"name": name, "verdict": verdict, "steps": steps, "route": ""}
        # кандидаты по порядку: российским сервисам — напрямую первым делом, остальным — через VPN
        cands: list[tuple[str, str, object]] = []
        if self.connected:
            cands.append(("proxy", "через VPN", self.ports["health"]))
        direct_c = ("direct", "напрямую", direct)
        if svc.get("russian"):
            cands.insert(0, direct_c)
        else:
            cands.append(direct_c)
        choice, label = "", ""
        for tgt, lbl, port in cands:
            if self._nw_try(svc, host, port, lbl, steps):
                choice, label = tgt, lbl
                break
        if not choice and self.connected:
            ports, proc = self._repair_servers()
            try:
                for srv, port in ports:
                    if self._nw_try(svc, host, port, f"через «{srv.name}»", steps):
                        choice, label = f"server:{srv.key}", f"через «{srv.name}»"
                        break
            finally:
                if proc:
                    proc.stop()
        if not choice and self.dpi_mode and not svc.get("russian"):
            # напрямую открывается, но режется — ускорение (zapret или ByeDPI) как раз против этого
            if any(s.startswith("напрямую: открывается") for s in steps):
                choice, label = "dpi", "с ускорением"
        if not choice:
            verdict = (f"{name} не открывается ни как сейчас, ни через VPN, ни напрямую"
                       + (", ни через другие серверы" if self.connected else "")
                       + ". Похоже, сервис сейчас не работает или закрыт для этих стран."
                       + ("" if self.connected else " Подключись к VPN — программа проверит его и через VPN."))
            return {"name": name, "verdict": verdict, "steps": steps, "route": ""}
        dpi_changed = self.set_service_route(name, choice)
        self.save()
        self.notify("settings")
        self.apply_routes(dpi_changed)
        after_port = self.ports["http"] if self.connected else direct
        ok = self._nw_try(svc, host, after_port, "после изменения", steps)
        verdict = f"{name}: теперь {label}." + (" Проверил — работает." if ok else
                                                 " Но и так пока не работает — нажми «Отменить», если стало хуже.")
        return {"name": name, "verdict": verdict, "steps": steps, "route": choice}

    # ---------- программа ----------

    def _nw_app(self, name: str, target: str) -> dict:
        n = apps.clean_name(name)
        if not n:
            raise RuntimeError("Не похоже на имя программы. Пример: Discord или C:/Games/game.exe.")
        p = apps.preset_for(n)
        title = p["title"] if p else n
        if p and p.get("urls") and not target:
            r = self.pick_app(n)
            if self.core_running:
                self.reconnect()
            return {"name": title, "verdict": r["verdict"], "steps": r.get("tried", []), "route": r.get("choice", "")}
        if not target:
            raise RuntimeError("Эту программу проверить не получится — выбери, как её пускать: через VPN или напрямую.")
        if target not in ("proxy", "direct", "dpi", "auto"):
            raise RuntimeError("Неизвестный путь.")
        self.set_app_route(n, target)
        if self.core_running:
            self.reconnect()
        verdict = f"{title}: {self._route_label(target)}."
        if p and p.get("needs_tun") and not self.settings.get("tun_enabled") and target not in ("direct", "dpi"):
            verdict += " Эта программа не слушается системного прокси — включи режим TUN, чтобы маршрут сработал."
        elif not p and not self.settings.get("tun_enabled"):
            verdict += " Если программа не слушается системного прокси, маршрут сработает только в режиме TUN."
        return {"name": title, "verdict": verdict, "steps": [], "route": target}

    # ---------- сайт ----------

    def _nw_site(self, raw: str) -> dict:
        r = self.check_site(raw)
        steps: list[str] = []
        verdict = r["verdict"]
        if self.connected and r.get("action") != "ads":
            # открылся — проверяем, работает ли целиком (картинки, видео): всё, что сайт загружал
            rep = self.repair_site(r["host"])
            if rep.get("fixed") or any(x.get("state") in (services.STALL_STALL, services.STALL_FAIL)
                                       for x in rep.get("hosts") or []):
                verdict += " " + rep["verdict"]
            elif not rep.get("seen"):
                verdict += (" Чтобы проверить картинки и видео, открой сайт в браузере и нажми «Проверить» ещё раз.")
            steps = [f"{x['host']}: {x.get('detail') or x.get('state')}" for x in rep.get("hosts") or []][:12]
        return {"name": r["site"], "verdict": verdict, "steps": steps, "route": r.get("route", "")}
