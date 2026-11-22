"""Лестница самоподбора: программа сама спускается по способам подключения, пока данные не пойдут.

Успех — это «скачались 64 КБ» (netutil.data_check), а не «прошёл пинг»: в 2026 году пинг часто проходит, а данные нет.
Шаги (каждый — одним временным ядром, способы внутри шага проверяются параллельно):
  1. память этой сети — что работало у этого провайдера или в этой сети Wi-Fi;
  2. текущий сервер как есть (может, это был короткий сбой);
  3. другой отпечаток TLS (firefox, safari, случайный) — в мае 2026 блокировали отдельно отпечаток Chrome;
  4. маскировка (дробление первого пакета, два способа);
  5. другой вход этого же сервера (другой порт или транспорт);
  6. другие серверы — сначала из другой сети (другой подсети хостинга), потом полная проверка и обновление подписок;
  9. белые списки — серверы «БС» (если включены белые списки, с них и начинаем).
Шаги 7 (вход через CDN) и 8 (UDP: Hysteria2, AmneziaWG) появятся вместе со своими движками.
Ничего не помогло — программа не переподключается по кругу: показывает, что работает напрямую, и пробует снова
через 2, 5, 10, 20 минут.

Сработавший способ (сервер + отпечаток + маскировка) запоминается для сети: ключ — хеш вида сети, имени Wi-Fi
и первых двух чисел внешнего адреса провайдера (сами имя сети и адрес не хранятся).
Сторож данных: если через VPN уходят байты, а обратно не приходит ничего 15 секунд, это повод проверить данные,
даже когда пинг в порядке.
"""

from __future__ import annotations

import dataclasses
import hashlib
import ipaddress
import threading
import time

from . import netutil, services, tester
from .links import Server

LADDER_FPS = ("firefox", "safari", "randomized")
BACKOFF = (120, 300, 600, 1200)  # с: «ничего не работает» — следующая попытка не сразу
SILENT_S = 30.0                  # с: уходит, но не приходит — пора проверить, идут ли данные (диспетчер: 30 с тишины)
SILENT_RECHECK = 60.0            # с: не чаще раза в минуту
NET_WAYS_MAX = 40
NET_WAY_TTL = 30 * 86400        # с: память сети старше 30 дней не используется
NET_ALTS = 2                     # запасных путей на сеть
WHAT_WORKS = ("Google", "YouTube", "Telegram", "Яндекс", "VK", "Госуслуги")
PROBE_BATCH = 6


def way_copy(srv: Server, fp: str | None = None, mask=None) -> Server:
    """Копия сервера с другим способом подключения (ключ сервера тот же). fp/mask None — как есть, "" / 0 — без."""
    r = dict(srv.result or {})
    if fp is not None:
        if fp:
            r["fp"] = fp
        else:
            r.pop("fp", None)
    if mask is not None:
        if mask:
            r["mask"] = mask
        else:
            r.pop("mask", None)
    return dataclasses.replace(srv, result=r)


def way_of(srv: Server) -> dict:
    r = srv.result or {}
    m = r.get("mask") or 0
    return {"server": srv.key, "fp": r.get("fp") or "", "mask": 1 if m is True else int(m or 0)}


def host_of(srv: Server) -> str:
    return (srv.pinned_ip or srv.address or "").strip("[]").lower()


def net_group(srv: Server) -> str:
    """«Сеть» сервера для правила «сначала другой хостинг»: первые два числа адреса (подсеть хостинга)
    или, если адрес — имя, домен второго уровня. Базы ASN у программы нет, это приближение."""
    h = host_of(srv)
    try:
        ip = ipaddress.ip_address(h)
        if ip.version == 4:
            return ".".join(h.split(".")[:2])
        return ":".join(ip.exploded.split(":")[:3])
    except ValueError:
        parts = [p for p in h.split(".") if p]
        return ".".join(parts[-2:]) if parts else ""


def transport_of(srv: Server) -> str:
    """udp — Hysteria2, TUIC, mKCP, QUIC (шаг 8 «UDP-канал»); tcp — всё остальное."""
    ss = (srv.outbound or {}).get("streamSettings") or {}
    if srv.protocol in ("hysteria2", "tuic") or ss.get("network") in ("hysteria", "kcp", "mkcp", "quic"):
        return "udp"
    return "tcp"


def way_kind(srv: Server) -> str:
    """Вид способа для предохранителя: другой отпечаток TLS или маскировка; '' — обычный путь."""
    w = way_of(srv)
    if w["fp"]:
        return f"отпечаток {w['fp']}"
    if w["mask"]:
        return "маскировка" if w["mask"] == 1 else f"маскировка {w['mask']}"
    return ""


def way_text(srv: Server) -> str:
    """Как сейчас подключён сервер — коротко, для журнала и окна: «отпечаток firefox, маскировка 2»."""
    w = way_of(srv)
    parts = []
    if w["fp"]:
        parts.append(f"отпечаток {w['fp']}")
    if w["mask"]:
        parts.append("маскировка" if w["mask"] == 1 else f"маскировка {w['mask']}")
    return ", ".join(parts)


class LadderMixin:
    """Часть движка (Engine): лестница способов, память сетей, сторож данных, «что работает сейчас»."""

    def _ladder_init(self) -> None:
        self._ladder_next = 0.0      # раньше этого времени лестницу заново не начинаем (ничего не работало)
        self._ladder_fails = 0
        self._silent_since = 0.0
        self._silent_checked = 0.0
        self._way_saved = ""         # какой способ уже запомнен для текущей сети
        self._way_saving = False
        self._remember_at = 0.0
        self.what_works: dict | None = None
        self.ladder_step = ""
        self.data_last: dict | None = None    # последняя проверка «идут ли данные» через подключение
        self.ladder_last: dict | None = None  # последнее, что сделала лестница (для окна «Состояние»)

    # ---------- сеть ----------

    def _net_id(self, cached_only: bool = False) -> str:
        """Ключ сети для памяти способов: вид сети, имя Wi-Fi и подсеть провайдера — одним хешем.
        cached_only — без запроса в сеть (только если провайдер уже известен): для быстрого старта."""
        net = getattr(self, "net_profile", None) or {}
        if cached_only:
            cached = getattr(self, "_net_cache", None)
            isp = cached[0] if cached and time.time() - cached[1] < 600 else ""
            if not isp:
                return ""
        else:
            isp = self._network_key()
        kind, ssid = net.get("kind") or "", net.get("ssid") or ""
        if not (isp or ssid):
            return ""
        return hashlib.sha1(f"{kind}|{ssid}|{isp}".encode("utf-8")).hexdigest()[:12]

    def _net_way(self, cached_only: bool = False) -> dict | None:
        if not self.settings.get("net_memory", True):
            return None
        nid = self._net_id(cached_only)
        way = (self.settings.get("net_ways") or {}).get(nid) if nid else None
        if way and time.time() - float(way.get("at") or 0) > NET_WAY_TTL:
            return None  # запись старше 30 дней: сеть могла измениться — ищем заново
        return way

    @staticmethod
    def _net_alts(way: dict | None) -> list[dict]:
        """Запасные пути из памяти сети (до двух), без устаревших."""
        now = time.time()
        return [a for a in (way or {}).get("alt") or [] if isinstance(a, dict) and a.get("server")
                and now - float(a.get("at") or 0) <= NET_WAY_TTL][:NET_ALTS]

    def connect_start(self, srv: Server) -> None:
        """Большая кнопка и запуск программы: если в этой сети уже что-то работало — сразу оно
        (сервер и способ из памяти сети), без перебора; иначе — srv."""
        mem = self._net_way(cached_only=True)
        pick = self.settings.get("engine_pick", "auto")
        if mem and srv and srv.engine != "awg":
            for i, w in enumerate([mem] + self._net_alts(mem)):
                real = self.find(w.get("server", ""))
                if not (real and real in self.pool() and real.supported and not real.stub
                        and (pick == "auto" or real.engine == srv.engine)):
                    continue
                way = self._apply_way(way_copy(real, w.get("fp") or "", w.get("mask") or 0))
                if not way:
                    continue
                self._lane.why = "в этой сети работал этот сервер" if not i else "запасной путь из памяти этой сети"
                try:
                    self.connect(way)
                    return
                except Exception as exc:
                    self.log(f"{'Сервер' if not i else 'Запасной путь'} из памяти сети не подключился ({exc}).")
            self.log("Память сети не помогла — беру лучший сервер.")
        self.connect(srv)

    def _remember_way(self, srv: Server) -> None:
        """Способ сработал — запомнить его для этой сети (шаг 1 лестницы в следующий раз)."""
        if not self.settings.get("net_memory", True) or not srv:
            return
        nid = self._net_id()
        if not nid:
            return
        way = dict(way_of(srv), at=time.time())
        ways = self.settings.setdefault("net_ways", {})
        old = ways.get(nid) or {}
        # прежний рабочий путь этой сети не выбрасываем — он становится запасным (до двух запасных)
        sig = lambda w: (w.get("server"), w.get("fp") or "", w.get("mask") or 0)  # noqa: E731
        alts = []
        for a in ([{k: old.get(k) for k in ("server", "fp", "mask", "at")}] if old.get("server") else []) + self._net_alts(old):
            if sig(a) != sig(way) and sig(a) not in [sig(x) for x in alts]:
                alts.append(a)
        if alts:
            way["alt"] = alts[:NET_ALTS]
        ways[nid] = way
        if len(ways) > NET_WAYS_MAX:
            for k in sorted(ways, key=lambda k: ways[k].get("at", 0))[:len(ways) - NET_WAYS_MAX]:
                ways.pop(k, None)
        self._way_saved = f"{nid}|{way['server']}|{way['fp']}|{way['mask']}"
        if (old.get("server"), old.get("fp"), old.get("mask")) != (way["server"], way["fp"], way["mask"]):
            self.save()

    def net_memory_state(self) -> dict:
        return {"count": len(self.settings.get("net_ways") or {}), "on": self.settings.get("net_memory", True)}

    def net_memory_clear(self) -> None:
        self.settings["net_ways"] = {}
        self._way_saved = ""
        self.save()
        self.log("Память сетей очищена.")

    # ---------- проверка способов ----------

    def _data_ok(self) -> dict:
        """Идут ли данные через текущее подключение (вход health — всегда через VPN)."""
        r = netutil.data_check(self.ports.get("health"), tester.DATA_URLS, timeout=tester.DATA_TIMEOUT,
                               stop_event=self.stop_event)
        self.data_last = dict(r, at=time.time(), server=self.current.key if self.current else "")
        return r

    def data_check_now(self) -> dict:
        """Кнопка «Проверить данные» в окне «Состояние»."""
        if not self.connected:
            raise RuntimeError("Сначала подключись.")
        self.progress("Проверяю, идут ли данные")
        r = self._data_ok()
        if r.get("inconclusive"):
            self.log("Проверочные адреса для данных сейчас недоступны — проверка не показательна.")
        else:
            self.log(f"Данные через VPN: идут ({r['ms']} мс на 64 КБ)." if r["ok"] else f"Данные через VPN не идут: {r['error']}.")
        self.notify("status")
        return r

    def health_check(self) -> None:
        """«Проверить всё»: данные, сертификаты и утечки — одной кнопкой."""
        if self.connected:
            self.data_check_now()
            self.check_stop()
        self.cert_check()
        self.check_stop()
        if self.connected:
            self.leak_test()
        self.notify("status")

    def _probe(self, cands: list[tuple[str, Server]]) -> list[tuple[str, Server]]:
        """Проверить способы (подпись, копия сервера) временным ядром → те, через которые пошли данные (по порядку)."""
        cands = [(label, c) for label, c in cands if c.supported and not c.stub][:PROBE_BATCH]
        if not cands:
            return []
        self._core_versions()
        ok: dict[int, bool] = {}
        for exe, group in tester._groups(self.paths, [c for _, c in cands], self.ensure_legacy):
            for c, r in zip(group, tester.probe_data(self.paths, group, self.stop_event, exe=exe, mask=None)):
                ok[id(c)] = r["ok"]
        self.check_stop()
        return [(label, c) for label, c in cands if ok.get(id(c))]

    def _apply_way(self, cand: Server) -> Server | None:
        """Перенести способ с проверенной копии на настоящий сервер."""
        real = self.find(cand.key)
        if not real:
            return None
        w = way_of(cand)
        r = dict(real.result or {})
        r.pop("fp", None)
        r.pop("mask", None)
        if w["fp"]:
            r["fp"] = w["fp"]
        if w["mask"]:
            r["mask"] = True if w["mask"] == 1 else w["mask"]
        real.result = r
        return real

    def _ladder_step(self, title: str, cands: list[tuple[str, Server]]) -> tuple[str, Server] | None:
        if not cands:
            return None
        self.ladder_step = title
        self.progress(f"Ищу рабочий способ: {title}")
        found = self._probe(cands)
        kinds = getattr(self, "_ladder_kinds", None)
        if kinds is not None:
            ok_ids = {id(c) for _, c in found}
            for _, c in [(lb, c) for lb, c in cands if c.supported and not c.stub][:PROBE_BATCH]:
                kind = way_kind(c)
                if kind:
                    kinds[kind] = kinds.get(kind, False) or id(c) in ok_ids
        if not found:
            self.log(f"Лестница: {title} — данные не идут.")
            return None
        for label, cand in found:
            real = self._apply_way(cand)
            if real and self._switch_to(real):
                how = way_text(real)
                self.log(f"Лестница: данные пошли — {label}: {real.name}" + (f" ({how})." if how else "."))
                return label, real
        return None

    def _ladder_success(self, srv: Server, label: str) -> None:
        self.ladder_last = {"at": time.time(), "ok": True, "text": f"данные пошли — {label}: {srv.name}"}
        self._ladder_fails = 0
        self._ladder_next = 0.0
        self.ladder_step = ""
        self.what_works = None
        self.resolve("no_working")
        self._remember_way(srv)
        if label != "тот же сервер":
            self.tell(f"Сервер перестал отвечать — нашёл рабочий способ: «{srv.name}».")
        self.notify("status")

    def ladder(self, reason: str) -> bool:
        """Спуститься по лестнице способов. True — данные пошли (подключено новым способом)."""
        cur = self.current
        fp_on = bool(self.settings.get("fp_auto", True))
        mask_on = bool(self.settings.get("mask_auto", True))
        tried: set[tuple] = set()
        self._ladder_kinds = {}   # вид способа → помог ли (для предохранителей, protect.py)
        fused: set[str] = set()

        def fresh(label: str, c: Server) -> list[tuple[str, Server]]:
            w = way_of(c)
            sig = (w["server"], w["fp"], w["mask"])
            if sig in tried:
                return []
            kind = way_kind(c)
            if kind and not self.fuse_ok(kind):
                if kind not in fused:
                    fused.add(kind)
                    self.log(f"Лестница: «{kind}» в этой сети на паузе (предохранитель) — пропускаю.")
                return []
            tried.add(sig)
            return [(label, c)]

        # шаги 1–4: память сети, тот же сервер, другой отпечаток, маскировка — одним временным ядром
        first: list[tuple[str, Server]] = []
        mem = self._net_way()
        for i, w in enumerate([mem] + self._net_alts(mem) if mem else []):
            if self.find(w.get("server", "")):
                first += fresh("память этой сети" if not i else "запасной путь этой сети",
                               way_copy(self.find(w["server"]), w.get("fp") or "", w.get("mask") or 0))
        if cur:
            first += fresh("тот же сервер", way_copy(cur))
            cur_fp = tester.fp_of(cur)
            if fp_on and tester.fp_capable(cur):
                for fp in LADDER_FPS:
                    if fp != cur_fp:
                        first += fresh(f"отпечаток {fp}", way_copy(cur, fp=fp))
            cur_mask = way_of(cur)["mask"]
            if mask_on:
                for m in (1, 2):
                    if m != cur_mask:
                        first += fresh("маскировка", way_copy(cur, mask=m))
        got = self._ladder_try_many("тот же сервер и способы маскировки", first)
        if got:
            return True
        # шаг 5: другой вход этого же сервера; шаг 6: другие серверы, сначала из другой сети
        if cur:
            same = [s for s in self.servers if s.key != cur.key and s.supported and host_of(s) == host_of(cur)]
            if self._ladder_try_many("другой вход этого сервера", [x for s in same for x in fresh("другой вход", s)]):
                return True
        cur_net = net_group(cur) if cur else ""
        current_key = cur.key if cur else ""
        backups = [s for s in tester.ranked(self.pool(), key=self._rank_key()) if s.key != current_key]
        # сначала другой транспорт (UDP — Hysteria2/TUIC — если отказал TCP, и наоборот), потом другая сеть
        cur_udp = transport_of(cur) if cur else ""
        backups.sort(key=lambda s: (bool(cur_udp) and transport_of(s) == cur_udp,
                                    bool(cur_net) and net_group(s) == cur_net))  # стабильная: внутри — по рангу
        cands = [x for s in backups[:8] for x in fresh("другой сервер", s)]
        if self._ladder_try_many("другой сервер, другая сеть", cands):
            return True
        return False

    def _ladder_try_many(self, title: str, cands: list[tuple[str, Server]]) -> bool:
        for i in range(0, len(cands), PROBE_BATCH):
            self.check_stop()
            got = self._ladder_step(title, cands[i:i + PROBE_BATCH])
            if got:
                self._ladder_fuses()
                self._ladder_success(got[1], got[0])
                return True
        return False

    def _ladder_fuses(self) -> None:
        """Что-то помогло — значит, сеть жива: способы, которые в этот раз не помогли, получают неудачу,
        помогший — сброс. Если не помогло ничего, неудачи не считаются (виноват не способ)."""
        for kind, ok in (getattr(self, "_ladder_kinds", None) or {}).items():
            try:
                self.fuse_result(kind, ok)
            except Exception as exc:
                self.log(f"Предохранитель: {exc}")
        self._ladder_kinds = {}

    def _remember_current(self) -> None:
        """После подключения: данные идут — запомнить сервер и способ для этой сети."""
        try:
            srv = self.current
            if not srv or not self.connected:
                return
            if not self._data_ok()["ok"] or self.current is not srv or not self.settings.get("net_memory", True):
                return
            nid = self._net_id()
            w = way_of(srv)
            if nid and self._way_saved != f"{nid}|{w['server']}|{w['fp']}|{w['mask']}":
                self._remember_way(srv)
        finally:
            self._way_saving = False
            self.notify("status")

    # ---------- «ничего не работает» ----------

    def _direct_works(self) -> list[dict]:
        """Что открывается напрямую (Google, Telegram…) — подсказка, когда через VPN связи нет.
        Свежий результат (меньше минуты) берётся повторно, чтобы не проверять дважды подряд."""
        prev = self.what_works or {}
        if prev.get("items") and time.time() - prev.get("time", 0) < 60:
            return prev["items"]
        self.progress("Проверяю, что работает напрямую")
        names = [n for n in WHAT_WORKS if any(s["name"] == n for s in services.SERVICES)]
        found = []
        try:
            res = services.check_all({"direct": self._direct_http()},
                                     [s for s in services.SERVICES if s["name"] in names], stop_event=self.stop_event)
            for n in names:
                st = (res.get(n) or {}).get("direct", {}).get("state")
                found.append({"name": n, "ok": st in (services.OK, services.SLOW)})
        except Exception as exc:  # проверка — подсказка, а не главное
            self.log(f"Проверка «что работает напрямую»: {exc}")
        return found

    def _searching_more(self, reason: str) -> None:
        """Быстрые способы лестницы не помогли: сразу показать, что происходит и что работает напрямую,
        а глубокий поиск (проверка всех серверов, обновление подписки) продолжается — он может идти минуту."""
        found = self._direct_works()
        self.what_works = {"time": time.time(), "items": found, "retry_at": 0, "searching": True,
                           "hint": "wifi" if getattr(self, "whitelist_mode", False) else ""}
        self.problem("no_working", "Связи через VPN нет — ищу рабочий сервер", reason, where="Главная",
                     fix="Программа проверяет все серверы и обновляет подписку — это до минуты.", level="warn")
        self.notify("status")

    def _nothing_works(self, reason: str) -> None:
        """Ни один способ не помог: без бесконечных переподключений, честно показать, что работает напрямую."""
        self._ladder_fails += 1
        wait = BACKOFF[min(self._ladder_fails, len(BACKOFF)) - 1]
        self._ladder_next = time.time() + wait
        self.ladder_step = ""
        found = self._direct_works()
        works = [f["name"] for f in found if f["ok"]]
        self.ladder_last = {"at": time.time(), "ok": False, "text": "ни один способ не помог"}
        self.what_works = {"time": time.time(), "items": found, "retry_at": self._ladder_next,
                           "hint": "wifi" if getattr(self, "whitelist_mode", False) else ""}
        self.log(f"Лестница: ни один способ не помог ({reason}). Напрямую работает: "
                 f"{', '.join(works) if works else 'ничего'}. Следующая попытка через {wait // 60} мин.")
        self.problem("no_working", "Все серверы недоступны", reason, where="Главная",
                     fix="Программа не переподключается по кругу: попробует снова сама. Можно обновить подписку, "
                         "взять другой интернет (Wi-Fi вместо мобильного) или написать провайдеру VPN.",
                     level="error")
        self.notify("error", text="Все серверы недоступны. Программа попробует снова сама.")
        self.notify("status")

    def ladder_retry_now(self) -> None:
        """Кнопка «Попробовать сейчас» — не ждать паузы после «ничего не работает»."""
        self._ladder_next = 0.0
        self.failover("проверка по кнопке")

    # ---------- сторож данных ----------

    def _data_watch(self, up: int, down: int, now: float) -> None:
        """Из _poll_stats: через VPN уходят байты, а не приходит ничего — проверить, идут ли данные."""
        if up > 0 and down == 0:
            if not self._silent_since:
                self._silent_since = now
        elif down > 0:
            self._silent_since = 0.0
        if not self._silent_since or now - self._silent_since < SILENT_S:
            return
        s = self.settings
        if not (s.get("data_watch", True) and s.get("autopilot")) or self.conn_busy():
            return
        if time.time() - self._silent_checked < SILENT_RECHECK or time.time() < self._ladder_next:
            return
        self._silent_checked = time.time()
        threading.Thread(target=self._silent_verify, daemon=True).start()

    def _silent_verify(self) -> None:
        r = self._data_ok()
        if r["ok"]:
            return
        why_not = self.may_switch("данные через сервер не идут")
        if why_not:
            self.deny_note("меняю сервер", why_not)
            return
        self.log(f"Сторож данных: соединения открываются, а данные не приходят ({r['error']}).")
        if self.connected and not self.conn_busy():
            self.run_task("Автопилот: поиск рабочего сервера", self.failover, "данные через сервер не идут",
                          lane="conn")

    # ---------- смена сети ----------

    def _net_changed(self) -> None:
        """Сеть сменилась: забыть адрес провайдера и взять способ, который работал в новой сети."""
        self._net_cache = None
        self._way_saved = ""
        self._remember_at = 0.0
        if not (self.settings.get("net_memory", True) and self.connected and self.current) or self.conn_busy():
            return
        self.run_task("Сеть сменилась: беру то, что работало в ней", self._apply_net_way, lane="conn")

    def _apply_net_way(self) -> None:
        mem = self._net_way()
        cur = self.current
        if not mem or not cur or not self.connected:
            return
        if not self.may_apply():  # подключение пережило смену сети и данные идут — не трогаем (dispatcher.py)
            self.deny_note("беру способ из памяти сети", "текущее подключение работает")
            return
        srv = self.find(mem.get("server", ""))
        if not srv:
            return
        if (mem.get("server"), mem.get("fp") or "", mem.get("mask") or 0) == tuple(way_of(cur).values()):
            return
        cand = way_copy(srv, mem.get("fp") or "", mem.get("mask") or 0)
        found = self._probe([("память этой сети", cand)])
        if not found:
            self.log("В этой сети раньше работал другой способ, но сейчас он не отвечает — оставляю текущий.")
            return
        real = self._apply_way(cand)
        if real and self._switch_to(real):
            self.log(f"Сеть сменилась: в ней работал «{real.name}» — переключился.")
            self._remember_way(real)
            self.notify("status")
