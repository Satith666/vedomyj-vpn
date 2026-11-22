"""Настройки программы (data/settings.json)."""

from __future__ import annotations

import copy
import json
import os

DEFAULTS: dict = {
    "subscription_url": "",
    "user_agent": "v2rayN/7.13.8",
    "mode": "vpn",
    "ru_direct": True,
    "block_quic": True,       # в режиме TUN: QUIC мимо российских сайтов блокируется (через VPN он лагает)
    "routing_v2": False,      # переход на «всё через VPN» по умолчанию уже сделан
    "proxy_list": "",
    "direct_list": "",
    "block_list": "",
    "ping_host": "www.gstatic.com",
    "ping_path": "/generate_204",
    "socks_port": 10808,
    "http_port": 10809,
    "system_proxy": True,
    "allow_lan": False,
    # доступ из домашней сети: отдельные порты и логин с паролем, чтобы чужие в той же Wi-Fi не пользовались VPN
    "lan_socks_port": 10810, "lan_http_port": 10811, "lan_auth": True, "lan_user": "", "lan_pass": "",
    "autopilot": True,
    "auto_update_hours": 6,
    "auto_connect_on_start": False,
    "last_server_key": "",
    "proxy_backup": None,
    "proxy_backup_port": None,
    "last_sub_update": 0,
    "results": {},
    # [{"id", "name", "url", "title", "usage": {...}, "last_update", "user_agent"}]
    "subscriptions": [],
    "manual_links": [],
    "theme": "dark",
    "sort": "ping",
    "collapsed": [],
    "hwid": "",
    "lang": "ru",
    "icon": "monogram",
    "game_mode": False,
    "autostart": False,
    "geo_update_hours": 24,
    "core_update_hours": 168,
    "dpi_update_hours": 24,
    # режим TUN, защита от утечек, шифрование DNS, блокировка рекламы
    "tun_enabled": False, "tun_engine": "auto", "tun_engine_auto": "", "leak_protection": True,
    "dns_encrypted": False, "block_ads": False,
    # блокировка рекламы: сила основного списка, дополнительные списки, свои сайты, исключения, работа без VPN
    "ads_level": "normal", "ads_rev": 0, "ads_site_ignore": [], "ads_ask_sites": True, "ads_lists": {"popups": True, "threats": True, "ru": True, "telemetry": False}, "ads_custom": "", "ads_allow": "",
    "ads_without_vpn": True, "ads_pause_until": 0, "ads_update_hours": 24, "ads_updated_at": 0, "ads_info": {},
    "mask_auto": True,
    "fp_auto": True,      # лестница: подбор отпечатка TLS (firefox, safari…), если сервер не отвечает
    "data_watch": True,   # сторож данных: «уходит, но не приходит» — проверить, идут ли данные
    "net_memory": True,   # память сетей: что работало у этого провайдера или в этой сети Wi-Fi
    "net_ways": {},       # хеш сети → {"server", "fp", "mask", "at"}
    "cert_pins": {},      # ключ сервера → SHA-256 его сертификата (серверы «не проверять сертификат», см. certpin.py)
    "engine_pick": "auto",  # «Движок» на главной: auto, xray, hy2 (Hysteria2), singbox (TUIC, AnyTLS), awg (AmneziaWG)
    "last_awg_key": "",     # какой конфиг AmneziaWG был включён (чтобы показать его после перезапуска программы)
    "background": True,  # закрыл окно — программа работает дальше, значок у часов
    "background_hint_shown": False,
    "hotspot_ssid": "", "hotspot_pass": "",  # раздача VPN по Wi-Fi
    "whitelist_auto": True,  # сам замечать белые списки и переходить на подходящий сервер
    "stall_check": True,      # «16 КБ»: лучшие серверы качают 64 КБ, обрывающиеся уходят вниз (ladder.stall_check)
    "ads_dns_system": False,  # реклама «через DNS» во всех программах (DNS компьютера → наш фильтр)
    "ads_dns_home": False,    # фильтр DNS и для домашней сети (телевизор, приставка, роутер)
    "wl_priority": False,    # галочка «Белые списки» на главном: сначала серверы для их обхода
    "wl_muted": "",          # галочку сняли, когда списки замечены сами: в этой сети (хеш) сама не включается
    # свои маршруты: "svc:<сервис>" или "site:<домен>" → {"via": "server"|"custom"|"dpi"|"proxy"|"direct"|"block", …}
    # (у сервисов «через VPN / напрямую / блок» — в списках proxy_list, direct_list, block_list)
    "routes": {},
    # автоподбор для сайтов: новый сайт не открывается напрямую — сам уходит в VPN, закрыт для страны — на другой сервер
    "auto_routes": True, "auto_sites": {}, "auto_seen": {}, "auto_stall": True, "auto_ask_direct": True,
    "failover": True,  # запасной сервер внутри ядра: при сбое основного — мгновенно через него
    "app_update": True, "app_update_hours": 24, "app_update_checked": 0, "app_update_info": {},  # обновление программы
    "encrypt_data": True,  # подписки, серверы и пароли на диске — зашифрованы (Windows, только этот пользователь)
    "pin_hash": "", "pin_salt": "", "pin_lock_minutes": 0,  # пин-код на открытие окна программы
    "hotkey_enabled": True, "hotkey": "Ctrl+Alt+V",  # горячая клавиша «включить/выключить VPN»
    "server_hist": {},  # история качества серверов по часам суток: {ключ: [[работал, нет] × 24]}
    "traffic_days": {},  # трафик по дням: {"2026-11-13": {"vpn": байт, "direct": байт}}
    "smart_notices": True,  # «Сервер упал — переключился на X» и т. п. — коротким сообщением
    "kill_switch": False,  # VPN сломался — «через VPN» никуда, а не напрямую (в чужом Wi-Fi включается сам)
    # профили сетей: в чужом (открытом) Wi-Fi — VPN сам, всё через VPN и kill switch
    "net_profiles": True, "net_trusted": [], "net_untrusted": [],
    "sub_alerts": True, "sub_alerts_sent": {},  # предупреждать: подписка скоро закончится, мало трафика
    # приложения: имя процесса → маршрут ({"via": …} как у сайтов); торренты — напрямую, через VPN или блок
    "app_routes": {}, "torrent_route": "direct",
    # свои серверы (адрес, порт, имя для входа, ключи друзей) — без паролей
    "vps_hosts": [],
    # свой репозиторий на GitHub — куда «Сообщить об ошибке» открывает заявку (если адрес не вшит при сборке)
    "github_repo": "",
    # проверка сертификатов: когда последний раз смотрели системное хранилище и что нашли
    "cert_watch": True,
    # свои прокси: [{"id", "name", "type": "socks"|"http", "tls", "host", "port", "user", "pass", "chain", "check"}]
    "proxies": [],
    "multi_enabled": True, "multi_map": {}, "multi_checked_at": 0,  # Мультисервер: сервис → ключ сервера  # маскировка включается сама для серверов, которым она помогает
    # обход замедлений YouTube и Discord
    "zapret_enabled": True, "zapret_strategy": "", "zapret_results": [], "zapret_tested_at": 0,
    "byedpi_role": "backup", "byedpi_strategy": "", "byedpi_custom": "", "byedpi_results": [], "byedpi_tested_at": 0,
    "dpi_youtube": True, "dpi_discord": True, "dpi_custom": "", "dpi_networks": {}, "last_dpi_check": 0,
    "last_geo_check": 0,
    "last_core_check": 0,
    # защита (protect.py): предохранители способов, автооткат изменений, безопасный запуск
    "fuses_enabled": True, "fuses": {}, "guard_rollback": True, "safe_start": True,
    # сбор ошибок (collect.py): до какого времени собирать, когда начали, последний отчёт
    "collect_until": 0, "collect_started": 0, "collect_report": "",
}


# секреты: на диске хранятся зашифрованными (см. secure.py), если включено «encrypt_data»
SECRET_KEYS = ("subscriptions", "manual_links", "proxies", "lan_user", "lan_pass", "hotspot_pass",
               "subscription_url", "vps_hosts", "family")


class Settings(dict):
    def __init__(self, path: str):
        super().__init__(copy.deepcopy(DEFAULTS))  # глубокая копия: списки не должны быть общими
        self.path = path
        # поверх сохранённых значений на один запуск (безопасный запуск выключает необязательную автоматику);
        # на диск overlay не попадает: save() пишет настоящие значения
        self.overlay: dict = {}
        self.secure_failed = False  # секреты зашифрованы, но расшифровать не вышло (другой компьютер/пользователь)
        self._secure_raw = ""
        if os.path.isfile(path):
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    self.update({k: v for k, v in data.items() if k in DEFAULTS})
                    if isinstance(data.get("_secure"), str):
                        self._load_secure(data["_secure"])
            except (OSError, ValueError):
                pass

    def __getitem__(self, key):
        if self.overlay and key in self.overlay:
            return self.overlay[key]
        return super().__getitem__(key)

    def get(self, key, default=None):
        if self.overlay and key in self.overlay:
            return self.overlay[key]
        return super().get(key, default)

    def _load_secure(self, raw: str) -> None:
        from . import secure
        try:
            blob = json.loads(secure.decode(raw))
            self.update({k: v for k, v in blob.items() if k in SECRET_KEYS})
        except (secure.SecureError, ValueError):
            self.secure_failed = True
            self._secure_raw = raw

    def save(self) -> None:
        from . import secure
        out = dict(self)
        if self.get("encrypt_data", True) and secure.available():
            blob = {k: out.pop(k) for k in SECRET_KEYS if k in out}
            # главное — подписки, серверы и прокси (пароли раздачи программа создаёт заново сама)
            empty = all(not blob.get(k) for k in ("subscriptions", "manual_links", "proxies", "vps_hosts"))
            if self.secure_failed and empty:
                out["_secure"] = self._secure_raw  # не затираем то, что не смогли прочитать
            else:
                out["_secure"] = secure.encode(json.dumps(blob, ensure_ascii=False))
                self.secure_failed = False
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)
