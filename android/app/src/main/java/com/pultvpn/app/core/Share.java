package com.pultvpn.app.core;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Перенос настроек: тот же формат, что у программы для Windows ("pult-vpn-settings").
 * Чужой файл или QR-код — недоверенные данные: каждое значение проверяется, неизвестное пропускается.
 * Ссылки на подписки и свои серверы попадают в файл только по отдельной галочке.
 */
public final class Share {
    private Share() {
    }

    public static final String FORMAT = "pult-vpn-settings";
    static final int MAX_SUBS = 20;
    static final int MAX_SERVERS = 100;

    /** Настройки, которые понимает телефон. */
    static final List<String> BOOLS = Arrays.asList("ru_direct", "autopilot", "dns_encrypted", "block_ads",
            "mask_auto", "whitelist_auto", "ads_without_vpn", "dpi_youtube", "dpi_discord", "ads_ask_sites", "sub_alerts",
            "block_quic");
    static final List<String> TEXTS = Arrays.asList("proxy_list", "direct_list", "block_list", "ads_custom", "ads_allow",
            "dpi_custom");
    /** Настройки программы для Windows, которые на телефоне не нужны: пропускаются без предупреждения. */
    static final Set<String> WINDOWS_ONLY = new HashSet<String>(Arrays.asList("system_proxy", "game_mode",
            "auto_connect_on_start", "auto_update_hours", "geo_update_hours", "core_update_hours", "dpi_update_hours",
            "zapret_enabled", "zapret_strategy", "byedpi_role", "byedpi_strategy", "byedpi_custom", "tun_enabled", "tun_engine", "leak_protection", "multi_enabled",
            "background", "lan_auth", "ping_host", "ping_path", "auto_routes", "auto_stall", "torrent_route", "failover", "hotkey_enabled"));

    public static Map<String, Object> export(Map<String, Object> settings, boolean withSubs, boolean withServers,
                                             String appVersion) {
        Map<String, Object> s = new LinkedHashMap<String, Object>();
        s.put("mode", Json.str(settings, "mode", "vpn"));
        for (String k : BOOLS) {
            if (settings.containsKey(k)) {
                s.put(k, settings.get(k));
            }
        }
        for (String k : TEXTS) {
            String v = Json.str(settings, k);
            if (!v.isEmpty()) {
                s.put(k, v);
            }
        }
        if (!Json.str(settings, "user_agent").isEmpty()) {
            s.put("user_agent", Json.str(settings, "user_agent"));
        }
        s.put("ads_level", Json.str(settings, "ads_level", AdBlock.DEFAULT_LEVEL));
        Map<String, Object> lists = Json.map(settings, "ads_lists");
        if (lists != null) {
            s.put("ads_lists", Json.copy(lists));
        }
        Map<String, Object> data = Json.obj("format", FORMAT, "version", 1, "app", appVersion,
                "created", new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(new Date()), "settings", s);
        if (withSubs) {
            List<Object> subs = new ArrayList<Object>();
            List<Object> list = Json.list(settings, "subscriptions");
            if (list != null) {
                for (Object o : list) {
                    Map<String, Object> m = Json.map(o);
                    subs.add(Json.obj("name", Json.str(m, "name"), "url", Json.str(m, "url")));
                }
            }
            data.put("subscriptions", subs);
        }
        if (withServers) {
            List<Object> links = Json.list(settings, "manual_links");
            data.put("servers", links == null ? new ArrayList<Object>() : links);
        }
        return data;
    }

    /** Проверяет чужие настройки. Возвращает {settings, subscriptions, servers, skipped}. Ничего не меняет. */
    public static Map<String, Object> parse(Object raw) {
        Map<String, Object> data = Json.map(raw);
        if (data == null || !FORMAT.equals(Json.str(data, "format"))) {
            throw new IllegalArgumentException(Text.t("Это не файл настроек VEDOMYJ VPN.", "This is not a VEDOMYJ VPN settings file."));
        }
        Map<String, Object> in = Json.map(data, "settings");
        Map<String, Object> settings = new LinkedHashMap<String, Object>();
        List<Object> skipped = new ArrayList<Object>();
        if (in != null) {
            for (Map.Entry<String, Object> e : in.entrySet()) {
                String k = e.getKey();
                Object v = e.getValue();
                if (WINDOWS_ONLY.contains(k)) {
                    continue;
                }
                if (k.equals("mode")) {
                    if ("smart".equals(v) || "vpn".equals(v)) {
                        settings.put(k, v);
                    } else {
                        skipped.add(k);
                    }
                } else if (BOOLS.contains(k)) {
                    if (v instanceof Boolean) {
                        settings.put(k, v);
                    } else {
                        skipped.add(k);
                    }
                } else if (TEXTS.contains(k)) {
                    if (v instanceof String && ((String) v).length() <= 200000 && ((String) v).indexOf('\0') < 0) {
                        settings.put(k, v);
                    } else {
                        skipped.add(k);
                    }
                } else if (k.equals("ads_level")) {
                    if (v instanceof String && AdBlock.LEVELS.containsKey(v)) {
                        settings.put(k, v);
                    } else {
                        skipped.add(k);
                    }
                } else if (k.equals("ads_lists")) {
                    Map<String, Object> m = Json.map(v);
                    if (m != null) {
                        Map<String, Object> clean = new LinkedHashMap<String, Object>();
                        for (String id : AdBlock.EXTRA) {
                            clean.put(id, Json.bool(m, id, false));
                        }
                        settings.put(k, clean);
                    } else {
                        skipped.add(k);
                    }
                } else if (k.equals("user_agent")) {
                    if (v instanceof String && ((String) v).length() <= 200 && ((String) v).indexOf('\0') < 0) {
                        settings.put(k, v);
                    } else {
                        skipped.add(k);
                    }
                } else {
                    skipped.add(Text.shorten(k, 40));
                }
            }
        }
        List<Object> subs = new ArrayList<Object>();
        List<Object> rawSubs = Json.list(data, "subscriptions");
        if (rawSubs != null) {
            for (int i = 0; i < Math.min(MAX_SUBS, rawSubs.size()); i++) {
                Map<String, Object> m = Json.map(rawSubs.get(i));
                String url = Json.str(m, "url").trim();
                String low = url.toLowerCase();
                if (url.length() <= 4000 && (low.startsWith("http://") || low.startsWith("https://") || low.startsWith("happ://"))
                        && !low.startsWith("happ://crypt")) {
                    subs.add(Json.obj("url", url, "name", Text.shorten(Json.str(m, "name").trim(), 80)));
                } else {
                    skipped.add("subscription");
                }
            }
        }
        List<Object> servers = new ArrayList<Object>();
        List<Object> rawServers = Json.list(data, "servers");
        if (rawServers != null) {
            for (int i = 0; i < Math.min(MAX_SERVERS, rawServers.size()); i++) {
                Object o = rawServers.get(i);
                if (o instanceof String && ((String) o).contains("://") && ((String) o).length() <= 8000
                        && !((String) o).trim().contains("\n")) {
                    servers.add(((String) o).trim());
                } else {
                    skipped.add("server");
                }
            }
        }
        return Json.obj("settings", settings, "subscriptions", subs, "servers", servers, "skipped", skipped);
    }

    /** Что за текст пришёл из QR-кода или буфера обмена. */
    public static String kind(String text) {
        String t = text == null ? "" : text.trim();
        String low = t.toLowerCase();
        if (t.startsWith("{") && t.contains(FORMAT)) {
            return "settings";
        }
        if (low.startsWith("wifi:")) {
            return "wifi";
        }
        if (Subscription.looksLikeServerLink(t) || t.contains("\nvless://") || t.contains("\nvmess://")
                || t.contains("\ntrojan://") || t.contains("\nss://") || (t.contains("[Interface]") && t.contains("[Peer]"))) {
            return "servers";
        }
        if (low.startsWith("http://") || low.startsWith("https://") || low.startsWith("happ://add")
                || low.contains("://install-sub") || low.contains("://install-config") || low.startsWith("v2rayng://")) {
            return "subscription";
        }
        return "unknown";
    }
}
