package com.pultvpn.app.core;

import java.net.IDN;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/** Правила маршрутизации: что идёт через VPN, что напрямую, что блокируется. Как routing.py. */
public final class Routing {
    private Routing() {
    }

    static final List<String> PRIVATE_IPS = Arrays.asList(
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
            "100.64.0.0/10", "224.0.0.0/4", "255.255.255.255/32", "::1/128", "fc00::/7", "fe80::/10");

    /** Российские сайты: работают только напрямую (многие блокируют зарубежные IP). */
    static final List<String> RU_DIRECT_DOMAINS = Arrays.asList(
            "domain:ru", "domain:su", "domain:xn--p1ai", "domain:xn--d1acj3b", "domain:xn--80adxhks",
            "domain:moscow", "domain:tatar",
            "domain:yandex.net", "domain:yandex.com", "domain:yastatic.net", "domain:yandexcloud.net",
            "domain:vk.com", "domain:vk.me", "domain:vk.link", "domain:vkuser.net", "domain:userapi.com",
            "domain:vk-cdn.net", "domain:vkuseraudio.net", "domain:vkuservideo.net", "domain:mycdn.me",
            "domain:mradx.net", "domain:sberbank.com", "domain:ozonusercontent.com", "domain:wbstatic.net",
            "domain:wbbasket.ru", "domain:avito.st", "domain:2gis.com", "domain:max.im");

    /** Популярные сервисы, заблокированные или ограниченные в России (работает и без списков runetfreedom). */
    static final List<String> BUILTIN_PROXY_DOMAINS = Arrays.asList(
            "domain:youtube.com", "domain:youtu.be", "domain:googlevideo.com", "domain:ytimg.com", "domain:ggpht.com",
            "domain:youtube-nocookie.com", "domain:youtubei.googleapis.com", "domain:yt.be",
            "domain:discord.com", "domain:discord.gg", "domain:discordapp.com", "domain:discordapp.net",
            "domain:discord.media", "domain:discordcdn.com", "domain:discord.dev", "domain:discord.gift",
            "domain:discordstatus.com", "domain:dis.gd",
            "domain:telegram.org", "domain:t.me", "domain:telegram.me", "domain:telesco.pe", "domain:tdesktop.com",
            "domain:telegra.ph", "domain:telegram-cdn.org",
            "domain:instagram.com", "domain:cdninstagram.com", "domain:facebook.com", "domain:fbcdn.net",
            "domain:fb.com", "domain:facebook.net", "domain:whatsapp.com", "domain:whatsapp.net", "domain:wa.me",
            "domain:threads.net", "domain:threads.com",
            "domain:x.com", "domain:twitter.com", "domain:twimg.com", "domain:t.co",
            "domain:openai.com", "domain:chatgpt.com", "domain:oaistatic.com", "domain:oaiusercontent.com",
            "domain:claude.ai", "domain:claude.com", "domain:anthropic.com", "domain:gemini.google.com",
            "domain:aistudio.google.com", "domain:generativelanguage.googleapis.com", "domain:perplexity.ai",
            "domain:grok.com", "domain:x.ai", "domain:copilot.microsoft.com",
            "domain:linkedin.com", "domain:licdn.com", "domain:medium.com", "domain:soundcloud.com",
            "domain:sndcdn.com", "domain:spotify.com", "domain:scdn.co", "domain:spotifycdn.com", "domain:patreon.com",
            "domain:notion.so", "domain:canva.com", "domain:netflix.com", "domain:nflxvideo.net", "domain:signal.org",
            "domain:proton.me", "domain:protonmail.com", "domain:torproject.org", "domain:rutracker.org",
            "domain:viber.com", "domain:speedtest.net", "domain:ookla.com", "domain:roblox.com", "domain:rbxcdn.com",
            "domain:snapchat.com", "domain:twitch.tv", "domain:ttvnw.net", "domain:jtvnw.net");

    /** Сети Telegram (приложение часто подключается напрямую по IP). */
    static final List<String> BUILTIN_PROXY_IPS = Arrays.asList(
            "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.20.0/22",
            "91.108.56.0/22", "91.105.192.0/23", "95.161.64.0/20", "149.154.160.0/20", "185.76.151.0/24",
            "2001:67c:4e8::/48", "2001:b28:f23c::/47", "2001:b28:f23f::/48", "2a0a:f280::/32");

    static final String[] DOMAIN_PREFIXES = {"domain:", "full:", "regexp:", "keyword:", "geosite:", "ext:", "dotless:"};

    /** Строка из своего списка → {"domain"|"ip", значение для Xray}. null — пусто или комментарий.
     *  IllegalArgumentException — строку не удалось понять. */
    public static String[] normalizeEntry(String raw) {
        String s = raw.trim();
        if (s.isEmpty() || s.startsWith("#")) {
            return null;
        }
        if (s.contains("#")) {
            s = s.substring(0, s.indexOf('#')).trim();
        }
        String low = s.toLowerCase();
        if (low.startsWith("geoip:")) {
            return new String[]{"ip", low};
        }
        for (String p : DOMAIN_PREFIXES) {
            if (low.startsWith(p)) {
                return new String[]{"domain", low.startsWith("regexp:") ? s : low};
            }
        }
        if (s.contains("://")) {
            s = s.substring(s.indexOf("://") + 3);
            int end = s.length();
            for (char c : new char[]{'/', '?', '#'}) {
                int k = s.indexOf(c);
                if (k >= 0 && k < end) {
                    end = k;
                }
            }
            s = s.substring(0, end);
            if (s.contains("@")) {
                s = s.substring(s.lastIndexOf('@') + 1);
            }
            if (s.startsWith("[")) {
                s = s.substring(1, Math.max(1, s.indexOf(']')));
            } else if (s.indexOf(':') >= 0 && s.indexOf(':') == s.lastIndexOf(':')) {
                s = s.substring(0, s.indexOf(':'));
            }
        }
        s = s.trim();
        while (s.startsWith("/")) {
            s = s.substring(1);
        }
        while (s.endsWith("/")) {
            s = s.substring(0, s.length() - 1);
        }
        s = s.toLowerCase();
        if (s.startsWith("*.")) {
            s = s.substring(2);
        }
        if (s.startsWith("[") && s.endsWith("]")) {
            s = s.substring(1, s.length() - 1);
        }
        if (Text.isIpOrCidr(s)) {
            return new String[]{"ip", s};
        }
        if (s.startsWith("www.")) {
            s = s.substring(4);
        }
        if (s.isEmpty() || s.contains(" ") || (!s.contains(".") && !s.matches("[\\p{L}\\p{N}]+"))) {
            throw new IllegalArgumentException(raw.trim());
        }
        try {
            s = IDN.toASCII(s, IDN.ALLOW_UNASSIGNED);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(raw.trim());
        }
        return new String[]{"domain", "domain:" + s};
    }

    /** Свой список → {домены, IP, нераспознанные строки}. */
    public static List<List<String>> splitEntries(String text) {
        List<String> domains = new ArrayList<String>();
        List<String> ips = new ArrayList<String>();
        List<String> bad = new ArrayList<String>();
        for (String line : (text == null ? "" : text).split("\\r?\\n")) {
            String[] item;
            try {
                item = normalizeEntry(line);
            } catch (IllegalArgumentException e) {
                bad.add(line.trim());
                continue;
            }
            if (item == null) {
                continue;
            }
            List<String> target = item[0].equals("domain") ? domains : ips;
            if (!target.contains(item[1])) {
                target.add(item[1]);
            }
        }
        List<List<String>> out = new ArrayList<List<String>>();
        out.add(domains);
        out.add(ips);
        out.add(bad);
        return out;
    }

    public static String defaultOutbound(String mode) {
        return "vpn".equals(mode) ? "proxy" : "direct";
    }

    /** «Всё через VPN»: правила только по имени (AsIs) — ядро не спрашивает DNS провайдера про каждый сайт:
     *  быстрее, а подменённый адрес-заглушка не уводит заблокированный сайт «напрямую». Экономный — и по IP. */
    public static String domainStrategy(String mode) {
        return "vpn".equals(mode) ? "AsIs" : "IPIfNonMatch";
    }

    static final List<String> GEO_INSIDE_ONLY = Arrays.asList("geosite:ru-available-only-inside");

    /** Адреса домашней сети с именами (страница роутера и т.п.) — всегда напрямую. */
    static final List<String> LAN_DOMAINS = Arrays.asList(
            "domain:local", "domain:lan", "domain:home.arpa", "domain:internal", "domain:localdomain", "domain:box",
            "full:my.keenetic.net", "full:router.asus.com", "domain:tplinkwifi.net", "domain:tplinklogin.net",
            "domain:routerlogin.net", "full:miwifi.com", "domain:mywifiext.net", "full:speedport.ip");

    private static void add(List<Object> rules, List<String> domains, List<String> ips, String tag) {
        if (domains != null && !domains.isEmpty()) {
            rules.add(Json.obj("type", "field", "domain", new ArrayList<Object>(domains), "outboundTag", tag));
        }
        if (ips != null && !ips.isEmpty()) {
            rules.add(Json.obj("type", "field", "ip", new ArrayList<Object>(ips), "outboundTag", tag));
        }
    }

    // ---------- свои списки: какой сайт задевает строка ----------

    /** Ключи своих списков и куда они ведут. */
    public static final String[][] USER_LISTS = {{"block_list", "block"}, {"direct_list", "direct"}, {"proxy_list", "proxy"}};

    public static boolean isIpEntry(String value) {
        return Text.isIpOrCidr(value);
    }

    /** Хост из журнала → основной домен (music.yandex.ru → yandex.ru) или IP. Как routing.site_entry. */
    public static String siteEntry(String host) {
        String h = host.trim().toLowerCase();
        if (h.startsWith("[") && h.endsWith("]")) {
            h = h.substring(1, h.length() - 1);
        }
        if (Text.isIp(h)) {
            return h;
        }
        List<String> labels = new ArrayList<String>();
        for (String x : h.split("\\.")) {
            if (!x.isEmpty()) {
                labels.add(x);
            }
        }
        int n = labels.size();
        if (n <= 2) {
            return String.join(".", labels);
        }
        String second = labels.get(n - 2);
        if (labels.get(n - 1).length() == 2 && Arrays.asList("co", "com", "net", "org", "gov", "edu", "ac", "msk", "spb")
                .contains(second)) {
            return String.join(".", labels.subList(n - 3, n));
        }
        return String.join(".", labels.subList(n - 2, n));
    }

    static boolean entryMatches(String entry, String host) {
        String h = host.toLowerCase();
        while (h.endsWith(".")) {
            h = h.substring(0, h.length() - 1);
        }
        if (h.startsWith("[") && h.endsWith("]")) {
            h = h.substring(1, h.length() - 1);
        }
        if (entry.startsWith("domain:")) {
            String d = entry.substring(7);
            return h.equals(d) || h.endsWith("." + d);
        }
        if (entry.startsWith("full:")) {
            return h.equals(entry.substring(5));
        }
        if (entry.startsWith("keyword:")) {
            return h.contains(entry.substring(8));
        }
        return Text.isIp(h) && entry.equals(h);
    }

    /** Какое своё правило действует на сайт: proxy / direct / block или "". */
    public static String userRule(String host, Map<String, Object> settings) {
        for (String[] l : USER_LISTS) {
            for (String line : Json.str(settings, l[0]).split("\\r?\\n")) {
                try {
                    String[] item = normalizeEntry(line);
                    if (item != null && entryMatches(item[1], host)) {
                        return l[1];
                    }
                } catch (IllegalArgumentException ignored) {
                    // непонятная строка — пропускаем
                }
            }
        }
        return "";
    }

    /** Убирает из списка строки, которые задевают этот сайт. */
    public static String removeHost(String text, String host) {
        List<String> kept = new ArrayList<String>();
        for (String line : (text == null ? "" : text).split("\\r?\\n", -1)) {
            String[] item;
            try {
                item = normalizeEntry(line);
            } catch (IllegalArgumentException e) {
                item = null;
            }
            if (item == null || !entryMatches(item[1], host)) {
                kept.add(line);
            }
        }
        String out = String.join("\n", kept);
        while (out.startsWith("\n")) {
            out = out.substring(1);
        }
        while (out.endsWith("\n")) {
            out = out.substring(0, out.length() - 1);
        }
        return out;
    }

    /** Правила Xray без своих маршрутов, рекламы из своих списков и обхода замедлений (как раньше). */
    public static List<Object> buildRules(Map<String, Object> settings, boolean useGeo) {
        return buildRules(settings, useGeo, Json.bool(settings, "block_ads", false) && useGeo ? "geo" : "", null, null);
    }

    /**
     * Правила Xray. Порядок важен: первое совпадение побеждает. Остальное уходит в первый outbound.
     * ads: "dat" — свой файл adblock.dat, "geo" — запасной список рекламы из файлов runetfreedom, "" — нет.
     * dpiDomains — сайты «напрямую с обходом замедления» (null — обход не работает).
     * routes — свои маршруты сервисов и сайтов: [{tag, domains, ips, early, block_udp?}].
     */
    public static List<Object> buildRules(Map<String, Object> settings, boolean useGeo, String ads, List<String> dpiDomains,
                                          List<Map<String, Object>> routes) {
        List<Object> rules = new ArrayList<Object>();
        add(rules, LAN_DOMAINS, PRIVATE_IPS, "direct");
        // QUIC (UDP 443) мимо российских сайтов — блок: браузер и YouTube сразу переходят на обычное соединение.
        // Через VPN QUIC едет внутри TCP и работает заметно хуже (видео лагает)
        if (Json.bool(settings, "block_quic", true)) {
            if (Json.bool(settings, "ru_direct", true)) {
                List<Object> ru = new ArrayList<Object>(RU_DIRECT_DOMAINS);
                if (useGeo) {
                    ru.addAll(GEO_INSIDE_ONLY);
                }
                rules.add(Json.obj("type", "field", "network", "udp", "port", "443", "domain", ru, "outboundTag", "direct"));
            }
            rules.add(Json.obj("type", "field", "network", "udp", "port", "443", "outboundTag", "block"));
        }
        // свои маршруты сайтов — раньше всего остального
        addRoutes(rules, routes, true);
        for (String[] l : USER_LISTS) {
            List<List<String>> e = splitEntries(Json.str(settings, l[0]));
            add(rules, e.get(0), e.get(1), l[1]);
        }
        // свои маршруты сервисов: другой сервер, свой прокси, обход замедления
        addRoutes(rules, routes, false);
        // реклама, всплывающие окна, мошенничество — в «чёрную дыру» (свои правила выше и важнее)
        if ("dat".equals(ads)) {
            add(rules, Arrays.asList(AdBlock.RULE), null, AdBlock.OUTBOUND);
        } else if ("geo".equals(ads) && useGeo) {
            add(rules, Arrays.asList("geosite:category-ads-all"), null, AdBlock.OUTBOUND);
        }
        // обход замедлений: YouTube и Discord напрямую с дроблением, а не через VPN («Глобальный» — всё через VPN)
        if (dpiDomains != null && !dpiDomains.isEmpty() && !"vpn".equals(Json.str(settings, "mode", "vpn"))) {
            List<String> d = new ArrayList<String>();
            for (String x : dpiDomains) {
                d.add("domain:" + x);
            }
            add(rules, d, null, Dpi.OUTBOUND);
        }
        if (useGeo) {
            add(rules, GEO_INSIDE_ONLY, null, "direct");
            add(rules, Arrays.asList("geosite:ru-blocked"), Arrays.asList("geoip:ru-blocked"), "proxy");
        }
        add(rules, BUILTIN_PROXY_DOMAINS, BUILTIN_PROXY_IPS, "proxy");
        if (Json.bool(settings, "ru_direct", true)) {
            add(rules, RU_DIRECT_DOMAINS, useGeo ? Arrays.asList("geoip:ru") : null, "direct");
        }
        return rules;
    }

    @SuppressWarnings("unchecked")
    private static void addRoutes(List<Object> rules, List<Map<String, Object>> routes, boolean early) {
        if (routes == null) {
            return;
        }
        for (Map<String, Object> r : routes) {
            if (Json.bool(r, "early", false) != early) {
                continue;
            }
            List<String> domains = (List<String>) (List<?>) Json.list(r, "domains");
            List<String> ips = (List<String>) (List<?>) Json.list(r, "ips");
            if (r.containsKey("block_udp")) {
                // через свой прокси UDP не ходит или ходит плохо: QUIC (UDP 443) блокируем — приложения сразу на TCP
                Map<String, Object> udp = Json.obj("type", "field", "network", "udp", "outboundTag", "block");
                if (!Json.str(r, "block_udp").isEmpty()) {
                    udp.put("port", Json.str(r, "block_udp"));
                }
                if (domains != null && !domains.isEmpty()) {
                    Map<String, Object> x = Json.copy(udp);
                    x.put("domain", new ArrayList<Object>(domains));
                    rules.add(x);
                }
                if (ips != null && !ips.isEmpty()) {
                    Map<String, Object> x = Json.copy(udp);
                    x.put("ip", new ArrayList<Object>(ips));
                    rules.add(x);
                }
            }
            add(rules, domains, ips, Json.str(r, "tag"));
        }
    }

    /** Подсказка для интерфейса: куда пойдёт сайт по своим спискам и встроенным правилам (без гео-файлов). */
    public static String routeForHost(String host, Map<String, Object> settings) {
        String own = userRule(host, settings);
        if (!own.isEmpty()) {
            return own;
        }
        for (String e : BUILTIN_PROXY_DOMAINS) {
            if (entryMatches(e, host)) {
                return "proxy";
            }
        }
        if (Json.bool(settings, "ru_direct", true)) {
            for (String e : RU_DIRECT_DOMAINS) {
                if (entryMatches(e, host)) {
                    return "direct";
                }
            }
        }
        return defaultOutbound(Json.str(settings, "mode", "vpn"));
    }
}
