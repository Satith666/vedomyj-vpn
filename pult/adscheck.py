"""«Проверить блокировку рекламы»: почему реклама проходит — простыми словами и с кнопкой «Исправить».

Проверяется по шагам:
1. Блокировка включена и не на паузе.
2. Списки скачаны (каждый включённый), собраны в файл для ядра и не устарели.
3. Программа сейчас фильтрует: работает VPN или блокировка без VPN.
4. Браузеры идут через программу: системный прокси (и он наш, его не перехватил другой VPN-клиент) или TUN;
   в TUN закрыт QUIC.
5. Известные рекламные адреса есть в собранном файле и правда не открываются через программу
   (проверка через её же вход — наружу такие запросы не уходят, если блокировка работает).
6. Напоминание: реклама в YouTube и внутри страниц приходит с адреса самого сайта — её убирает расширение.

Каждый пункт: {"level": ok/info/warn/error, "title", "detail", "fix"}; fix — что сделает кнопка «Исправить»
(окно сопоставляет его со своими действиями).
"""

from __future__ import annotations

import os
import time

from . import adblock, i18n, services, sysproxy

# известные рекламные и следящие адреса: Google, Яндекс, Mail.ru / VK, Adfox
AD_PROBES = ("pagead2.googlesyndication.com", "ad.doubleclick.net", "www.googleadservices.com",
             "www.google-analytics.com", "mc.yandex.ru", "an.yandex.ru", "ad.mail.ru", "top-fwz1.mail.ru",
             "ads.adfox.ru", "googletagmanager.com")
LIVE_PROBES = 4          # столько адресов проверяем по-настоящему, через вход программы
STALE_DAYS = 7


class AdsCheckMixin:
    """Часть Engine: проверка блокировки рекламы."""

    ads_check_last: dict | None = None

    def ads_check(self) -> dict:
        self.progress("Проверяю блокировку рекламы")
        s = self.settings
        items: list[dict] = []

        def add(level: str, title: str, detail: str = "", fix: str = "") -> None:
            items.append({"level": level, "title": title, "detail": detail, "fix": fix})

        if not s.get("block_ads"):
            add("error", "Блокировка рекламы выключена",
                "Включи её — программа будет закрывать рекламу и слежку во всех браузерах.", "ads_on")
            return self._ads_check_done(items)
        if self._ads_paused():
            until = time.strftime("%H:%M", time.localtime(float(s.get("ads_pause_until") or 0)))
            add("warn", f"Блокировка на паузе до {until}", "", "ads_resume")
        # 2. списки
        level = s.get("ads_level", adblock.DEFAULT_LEVEL)
        ids = self._ads_ids()
        missing = [i for i in ids if not os.path.isfile(adblock.cache_path(i, self._ads_cache, level))]
        info = s.get("ads_info") or {}
        if missing:
            names = ", ".join(f"«{self._ads_list_name(i)}»" for i in missing)
            title = f"Не скачались списки: {names}" if len(missing) <= 3 else f"Не скачались списки: {len(missing)} из {len(ids)}"
            add("error" if "main" in missing else "warn", title,
                "Без них часть рекламы проходит. Программа скачает их снова (через VPN, если напрямую не выходит)."
                + ("" if len(missing) <= 3 else f" Не скачались: {names}."), "ads_update")
        elif info.get("total"):
            add("ok", f"Списки скачаны: блокируется {info['total']} адресов", f"Списков: {len(ids)}.")
        if self._ads_mode() == "geo":
            add("warn", "Работает запасной список", "Свои списки ещё не собраны — запасной закрывает меньше рекламы.",
                "ads_update")
        upd = float(s.get("ads_updated_at") or 0)
        if upd and time.time() - upd > STALE_DAYS * 86400:
            add("warn", f"Списки не обновлялись {int((time.time() - upd) // 86400)} дн.",
                "Новые рекламные адреса появляются каждый день.", "ads_update")
        # 3. фильтрует ли программа сейчас
        running = bool(self.connected or self.filter_on)
        if not running:
            if s.get("ads_without_vpn", True):
                add("error", "Программа сейчас не фильтрует рекламу",
                    "VPN выключен, а блокировка без VPN не запустилась.", "ads_apply")
            else:
                add("error", "VPN выключен — реклама сейчас не блокируется",
                    "Включи «Блокировать и без VPN»: реклама будет закрываться, а остальное пойдёт напрямую.",
                    "ads_without_vpn")
        # 4. идут ли браузеры через программу
        if self.tun_active:
            add("ok", "Весь трафик компьютера идёт через программу (TUN)")
            if not s.get("block_quic"):
                add("warn", "QUIC не закрыт",
                    "Браузер может отправить часть запросов по QUIC — их адреса программа видит хуже.", "quic_on")
        elif s.get("system_proxy"):
            if running and sysproxy.IS_WINDOWS and not sysproxy.is_ours(self.ports.get("http", 0)):
                add("error", "Системный прокси занят другой программой",
                    "Похоже, его поменял другой VPN-клиент — браузеры идут мимо программы.", "ads_apply")
            else:
                add("ok", "Браузеры идут через программу (системный прокси)")
            if not (s.get("ads_dns_system") and self.dnsf and self.dns_system):
                add("info", "Программы, которые не слушают системный прокси, идут мимо",
                    "Игры и приложения. Для них включи «Во всех программах (через DNS)» ниже или режим TUN.", "dns_on")
        else:
            add("error", "Браузеры идут мимо программы",
                "Системный прокси выключен и TUN не включён — браузер не знает о программе.", "sysproxy_on")
        # 4б. блокировка через DNS (все программы и весь дом)
        if s.get("ads_dns_system") or s.get("ads_dns_home"):
            if self.dns_error:
                add("error", "Блокировка через DNS не работает", self.dns_error, "ads_apply")
            elif self.dnsf and self.dnsf.running:
                where = []
                if self.dns_system:
                    where.append("во всех программах")
                if len(self.dns_hosts) > 1:
                    where.append(f"для всего дома (DNS {self.dns_hosts[1]})")
                add("ok", "Блокировка через DNS работает " + " и ".join(where) if where else "Блокировка через DNS работает")
            else:
                add("warn", "Блокировка через DNS не запущена", "", "ads_apply")
        # 5. известные рекламные адреса: в собранном файле и по-настоящему, через вход программы
        if self._ads_mode() == "dat":
            try:
                with open(self._ads_dat, "rb") as f:
                    doms = set(adblock.decode_geosite(f.read()).get(adblock.TAG.upper(), []))
            except (OSError, ValueError, IndexError):
                doms = set()
            miss = [h for h in AD_PROBES if not adblock.is_blocked(h, doms)]
            if miss:
                add("warn", f"В списках нет {len(miss)} из {len(AD_PROBES)} известных рекламных адресов",
                    ", ".join(miss), "ads_update")
        if running and self.core_running and not self._ads_paused() and self.ports.get("http"):
            opened = []
            for h in AD_PROBES[:LIVE_PROBES]:
                self.check_stop()
                r = services.check_url(f"https://{h}/", self.ports["http"], region_sensitive=False, timeout=6)
                if r.get("state") in (services.OK, services.SLOW):
                    opened.append(h)
            if opened:
                add("error", "Рекламные адреса открываются через программу",
                    "Блокировка не применилась: " + ", ".join(opened) + ".", "ads_apply")
            else:
                add("ok", "Рекламные адреса закрыты", f"Проверил {LIVE_PROBES} адреса через программу.")
        # 6. то, что по адресам не закрыть
        add("info", "Реклама в YouTube, VK Видео и внутри страниц",
            "Она приходит с того же адреса, что и сам сайт, — по адресам её не отличить. Её убирает расширение "
            "в браузере: «Монстр».", "monster")
        return self._ads_check_done(items)

    def _ads_check_done(self, items: list[dict]) -> dict:
        res = {"items": [dict(x, title=i18n.tr(x["title"]), detail=i18n.tr(x["detail"])) for x in items],
               "errors": sum(1 for x in items if x["level"] == "error"),
               "warnings": sum(1 for x in items if x["level"] == "warn"), "at": time.time()}
        self.ads_check_last = res
        bad = res["errors"] + res["warnings"]
        self.log(f"Проверка блокировки рекламы: ошибок {res['errors']}, предупреждений {res['warnings']}."
                 if bad else "Проверка блокировки рекламы: всё в порядке.")
        self.notify("ads_check", result=res)
        return res
