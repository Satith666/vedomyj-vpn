package com.pultvpn.app.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Настройки ядра Xray на телефоне: туннель (TUN) от Android, DNS, правила, маскировка. Как xray.py. */
public final class XrayConfig {
    private XrayConfig() {
    }

    // адреса виртуального адаптера VPN; DNS-адрес внутри той же подсети, поэтому запросы попадают в туннель
    public static final String TUN_V4 = "172.19.0.1";
    public static final int TUN_V4_PREFIX = 30;
    public static final String TUN_DNS = "172.19.0.2";
    public static final String TUN_V6 = "fdfe:dcba:9876::1";
    public static final int TUN_V6_PREFIX = 126;
    public static final int MTU = 1500;

    /** Проверка связи: этот адрес всегда идёт через VPN (отдельное правило). */
    public static final String HEALTH_HOST = "www.gstatic.com";
    public static final String HEALTH_URL = "https://www.gstatic.com/generate_204";

    static final List<String> DNS_REMOTE = Arrays.asList("1.1.1.1", "1.0.0.1");
    static final String DNS_RU = "77.88.8.8"; // Яндекс DNS
    static final List<String> RU_SUFFIXES = Arrays.asList("ru", "su", "xn--p1ai", "by", "kz", "yandex.net",
            "yastatic.net", "vk.com", "userapi.com", "mail.ru", "ok.ru", "avito.st", "wbstatic.net", "wbbasket.ru",
            "ozone.ru", "sberbank.ru");

    /** С этой версии Xray дробление TLS настраивается в finalmask, а не во freedom. */
    static final int[] FINALMASK_MIN = {26, 10, 31};

    /** Что ещё нужно для рабочей настройки, кроме сервера. */
    public static final class Options {
        public boolean useGeo;
        public boolean mask;
        public String coreVersion = "";
        public int appPort;          // вход для запросов самого приложения через VPN (с логином)
        public String appUser = "";
        public String appPass = "";
        public String shareIp = "";  // раздача: адрес точки доступа телефона ("" — выключена)
        public int shareSocksPort = 10810;
        public int shareHttpPort = 10811;
        public String shareUser = "";
        public String sharePass = "";
        public boolean tun = true;
        /** Свои маршруты: [{tag, domains, ips, early, server (Server) | proxy (Map, chain), block_udp?}]. */
        public List<Map<String, Object>> routes;
        /** Реклама: "dat" — свой файл adblock.dat, "geo" — запасной список, "" — не блокировать. */
        public String ads = "";
        /** Сайты «напрямую с обходом замедления» (null — обход не работает). */
        public List<String> dpiDomains;
        /** Способ обхода для выхода "dpi" (null — выхода нет). */
        public Dpi.Strategy dpi;
        /** Журнал соединений ядра ("" — не вести): по нему считается заблокированная реклама. */
        public String accessLog = "";
    }

    static int[] version(String text) {
        Matcher m = Pattern.compile("(\\d+)\\.(\\d+)\\.(\\d+)").matcher(text == null ? "" : text);
        if (!m.find()) {
            return new int[0];
        }
        return new int[]{Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3))};
    }

    static boolean atLeast(int[] v, int[] min) {
        if (v.length == 0) {
            return false;
        }
        for (int i = 0; i < min.length; i++) {
            if (v[i] != min[i]) {
                return v[i] > min[i];
            }
        }
        return true;
    }

    /** Outbound сервера с нужным тегом плюс вспомогательные (цепочки) с переименованными тегами. */
    /** DNS провайдера не знает адрес сервера (его так заблокировали) — подключаемся по адресу из защищённого DNS.
     *  Имя сервера остаётся там, где оно важно: в TLS (SNI) и в заголовке Host для CDN. */
    @SuppressWarnings("unchecked")
    static void pinAddress(Map<String, Object> ob, String domain, String ip) {
        Map<String, Object> st = Json.map(ob, "settings");
        if (st != null) {
            for (String k : new String[]{"vnext", "servers"}) {
                List<Object> l = Json.list(st, k);
                if (l != null) {
                    for (Object o : l) {
                        Map<String, Object> item = Json.map(o);
                        if (item != null && domain.equals(Json.str(item, "address"))) {
                            item.put("address", ip);
                        }
                    }
                }
            }
            if (domain.equals(Json.str(st, "address"))) {
                st.put("address", ip);
            }
        }
        Map<String, Object> ss = Json.map(ob, "streamSettings");
        if (ss == null) {
            return;
        }
        Map<String, Object> tls = Json.map(ss, "tlsSettings");
        if ("tls".equals(Json.str(ss, "security")) && tls != null && Json.str(tls, "serverName").isEmpty()) {
            tls.put("serverName", domain);
        }
        for (String k : new String[]{"wsSettings", "httpupgradeSettings", "xhttpSettings"}) {
            Map<String, Object> m = Json.map(ss, k);
            if (m != null && Json.str(m, "host").isEmpty()) {
                m.put("host", domain);
            }
        }
        Map<String, Object> grpc = Json.map(ss, "grpcSettings");
        if (grpc != null && Json.str(grpc, "authority").isEmpty() && "tls".equals(Json.str(ss, "security"))) {
            grpc.put("authority", domain);
        }
        Map<String, Object> h2 = Json.map(ss, "httpSettings");
        if (h2 != null && (Json.list(h2, "host") == null || Json.list(h2, "host").isEmpty())) {
            h2.put("host", Json.arr(domain));
        }
    }

    /** Ключ сервера → SHA-256 его сертификата (серверы «не проверять сертификат»; заполняет Engine). */
    public static final Map<String, String> CERT_PINS = new java.util.concurrent.ConcurrentHashMap<String, String>();

    static List<Map<String, Object>> taggedOutbounds(Server server, String tag) {
        Map<String, Object> main = Json.copy(server.outbound);
        main.put("tag", tag);
        if (server.tlsUnverified) {
            String pin = CERT_PINS.get(server.key());
            Map<String, Object> tls = Json.map(Json.map(main, "streamSettings"), "tlsSettings");
            if (pin != null && tls != null) {
                tls.put("pinnedPeerCertSha256", pin); // вместо allowInsecure: закреплённый сертификат этого сервера
            }
        }
        if (server.pinnedIp != null && !server.pinnedIp.isEmpty()) {
            pinAddress(main, server.address, server.pinnedIp);
        }
        if (server.fp != null && FINGERPRINTS.contains(server.fp)) {
            setFingerprint(main, server.fp); // отпечаток, который подобрала программа, вместо отпечатка из ссылки
        }
        Map<String, String> mapping = new LinkedHashMap<String, String>();
        List<Map<String, Object>> all = new ArrayList<Map<String, Object>>();
        all.add(main);
        for (Map<String, Object> ex0 : server.extraOutbounds) {
            Map<String, Object> ex = Json.copy(ex0);
            String old = Json.str(ex, "tag");
            String nw = tag + "~" + old;
            mapping.put(old, nw);
            ex.put("tag", nw);
            all.add(ex);
        }
        for (Map<String, Object> ob : all) {
            Map<String, Object> so = Json.map(Json.map(ob, "streamSettings"), "sockopt");
            if (so != null && mapping.containsKey(Json.str(so, "dialerProxy"))) {
                so.put("dialerProxy", mapping.get(Json.str(so, "dialerProxy")));
            }
            Map<String, Object> ps = Json.map(ob, "proxySettings");
            if (ps != null && mapping.containsKey(Json.str(ps, "tag"))) {
                ps.put("tag", mapping.get(Json.str(ps, "tag")));
            }
        }
        return all;
    }

    public static final List<String> FINGERPRINTS = java.util.Arrays.asList("chrome", "firefox", "safari", "edge", "ios",
            "android", "randomized");

    /** Отпечаток TLS outbound'а: строка (может быть пустой) или null — у сервера нет TLS/Reality. */
    public static String fingerprintOf(Map<String, Object> ob) {
        Map<String, Object> ss = Json.map(ob, "streamSettings");
        String net = Json.str(ss, "network");
        if (net.equals("hysteria") || net.equals("quic") || net.equals("kcp") || net.equals("mkcp")) {
            return null;  // QUIC (Hysteria2) и UDP: отпечаток браузера там не меняется
        }
        for (String key : new String[]{"realitySettings", "tlsSettings"}) {
            Map<String, Object> t = Json.map(ss, key);
            if (t != null) {
                return Json.str(t, "fingerprint");
            }
        }
        return null;
    }

    static boolean setFingerprint(Map<String, Object> ob, String fp) {
        Map<String, Object> ss = Json.map(ob, "streamSettings");
        boolean done = false;
        for (String key : new String[]{"realitySettings", "tlsSettings"}) {
            Map<String, Object> t = Json.map(ss, key);
            if (t != null) {
                t.put("fingerprint", fp);
                done = true;
            }
        }
        return done;
    }

    /** Временное ядро для проверки данных: вход HTTP 127.0.0.1:port → этот сервер (со своим способом). */
    public static Map<String, Object> probeConfig(Server server, boolean mask, String version, int port) {
        Map<String, Object> cfg = testConfig(server, mask, version);
        cfg.put("inbounds", Json.arr(Json.obj("tag", "in", "listen", "127.0.0.1", "port", port, "protocol", "http",
                "settings", Json.obj())));
        cfg.put("routing", Json.obj("domainStrategy", "AsIs", "rules", Json.arr(
                Json.obj("type", "field", "inboundTag", Json.arr("in"), "outboundTag", "proxy"))));
        return cfg;
    }

    /** Маскировка: первый пакет TLS режется на кусочки с паузами — ТСПУ не узнаёт сервер по нему. */
    static List<Map<String, Object>> maskOutbounds(List<Map<String, Object>> obs, String coreVersion) {
        Map<String, Object> main = obs.get(0);
        Map<String, Object> ss = Json.child(main, "streamSettings");
        String net = Json.str(ss, "network");
        if (net.equals("kcp") || net.equals("mkcp") || net.equals("quic") || net.equals("hysteria")
                || !Json.str(Json.map(ss, "sockopt"), "dialerProxy").isEmpty() || ss.containsKey("finalmask")
                || main.containsKey("proxySettings")) {
            return obs;
        }
        if (atLeast(version(coreVersion), FINALMASK_MIN)) {
            ss.put("finalmask", Json.obj("tcp", Json.arr(Json.obj("type", "fragment", "settings", Json.obj(
                    "packets", "tlshello", "lengths", Json.arr("100-200"), "delays", Json.arr("10-20"))))));
            return obs;
        }
        String tag = Json.str(main, "tag") + "~mask";
        Json.child(ss, "sockopt").put("dialerProxy", tag);
        List<Map<String, Object>> out = new ArrayList<Map<String, Object>>(obs);
        out.add(Json.obj("tag", tag, "protocol", "freedom",
                "settings", Json.obj("fragment", Json.obj("packets", "tlshello", "length", "100-200", "interval", "10-20")),
                "streamSettings", Json.obj("sockopt", Json.obj("TcpNoDelay", true))));
        return out;
    }

    /** Выходы своих маршрутов: выбранные серверы и свои прокси (каждый тег — один раз). */
    static List<Object> routeOutbounds(List<Map<String, Object>> routes, String version) {
        List<Object> out = new ArrayList<Object>();
        java.util.Set<String> seen = new java.util.HashSet<String>();
        if (routes == null) {
            return out;
        }
        for (Map<String, Object> r : routes) {
            String tag = Json.str(r, "tag");
            if (seen.contains(tag)) {
                continue;
            }
            Object srv = r.get("server");
            Object px = r.get("proxy");
            if (srv instanceof Server) {
                out.addAll(proxyOutbounds((Server) srv, tag, Json.bool(r, "mask", false), version));
            } else if (px instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> pm = (Map<String, Object>) px;
                out.add(Proxies.outbound(pm, tag, Json.bool(pm, "chain", true)));
            } else {
                continue;
            }
            seen.add(tag);
        }
        return out;
    }

    static Map<String, Object> logConfig(Options o) {
        Map<String, Object> log = Json.obj("loglevel", "warning", "dnsLog", false);
        if (o.accessLog != null && !o.accessLog.isEmpty()) {
            log.put("access", o.accessLog);
        }
        return log;
    }

    static List<Map<String, Object>> proxyOutbounds(Server server, String tag, boolean mask, String version) {
        List<Map<String, Object>> obs = taggedOutbounds(server, tag);
        return mask ? maskOutbounds(obs, version) : obs;
    }

    /** Для проверки одного сервера (замер задержки через временный экземпляр ядра). */
    public static Map<String, Object> testConfig(Server server, boolean mask, String version) {
        List<Object> outbounds = new ArrayList<Object>(proxyOutbounds(server, "proxy", mask, version));
        outbounds.add(Json.obj("tag", "direct", "protocol", "freedom"));
        return Json.obj("log", Json.obj("loglevel", "none"), "inbounds", new ArrayList<Object>(),
                "outbounds", outbounds, "routing", Json.obj("domainStrategy", "AsIs", "rules", new ArrayList<Object>()));
    }

    static Map<String, Object> sniffing() {
        return Json.obj("enabled", true, "destOverride", Json.arr("http", "tls", "quic"), "routeOnly", true);
    }

    /** Встроенный DNS ядра: российские адреса — через Яндекс напрямую, остальное — через VPN. */
    static Map<String, Object> dns(boolean encrypted, boolean useGeo) {
        List<Object> ruDomains = new ArrayList<Object>();
        for (String s : RU_SUFFIXES) {
            ruDomains.add("domain:" + s);
        }
        if (useGeo) {
            ruDomains.add("geosite:ru-available-only-inside");
        }
        List<Object> servers = new ArrayList<Object>();
        servers.add(Json.obj("address", encrypted ? "https://" + DNS_RU + "/dns-query" : DNS_RU,
                "domains", ruDomains, "skipFallback", true));
        for (String ip : DNS_REMOTE) {
            servers.add(encrypted ? "https://" + ip + "/dns-query" : ip);
        }
        return Json.obj("tag", "dns-internal", "queryStrategy", "UseIPv4", "servers", servers);
    }

    /** Рабочие настройки: туннель от Android → правила → сервер или напрямую. */
    public static Map<String, Object> runConfig(Server server, Map<String, Object> settings, Options o) {
        String mode = Json.str(settings, "mode", "vpn");
        boolean encrypted = Json.bool(settings, "dns_encrypted", false);
        List<Object> inbounds = new ArrayList<Object>();
        if (o.tun) {
            inbounds.add(Json.obj("tag", "tun-in", "protocol", "tun",
                    "settings", Json.obj("name", "xray0", "mtu", MTU), "sniffing", sniffing()));
        }
        if (o.appPort > 0) {
            // только для запросов самого приложения (подписки, списки сайтов), с логином: другие приложения
            // на телефоне не смогут через него узнать адрес сервера
            inbounds.add(Json.obj("tag", "app-in", "listen", "127.0.0.1", "port", o.appPort, "protocol", "http",
                    "settings", Json.obj("accounts", Json.arr(Json.obj("user", o.appUser, "pass", o.appPass)))));
        }
        if (!o.shareIp.isEmpty()) {
            // раздача: только на адресе точки доступа телефона, а не во всех сетях
            Map<String, Object> socks = Json.obj("udp", true);
            if (!o.sharePass.isEmpty()) {
                socks.put("auth", "password");
                socks.put("accounts", Json.arr(Json.obj("user", o.shareUser, "pass", o.sharePass)));
            }
            inbounds.add(Json.obj("tag", "share-socks", "listen", o.shareIp, "port", o.shareSocksPort,
                    "protocol", "socks", "settings", socks, "sniffing", sniffing()));
            inbounds.add(Json.obj("tag", "share-http", "listen", o.shareIp, "port", o.shareHttpPort,
                    "protocol", "http", "settings", Json.obj(), "sniffing", sniffing()));
        }
        List<Map<String, Object>> proxyObs = proxyOutbounds(server, "proxy", o.mask, o.coreVersion);
        Map<String, Object> direct = Json.obj("tag", "direct", "protocol", "freedom");
        if (encrypted) {
            // прямые соединения узнают адрес через встроенный (зашифрованный) DNS, а не через DNS провайдера
            direct.put("settings", Json.obj("domainStrategy", "UseIPv4"));
        }
        List<Object> outbounds = new ArrayList<Object>();
        // первый outbound — маршрут по умолчанию для всего, что не попало ни в одно правило
        if ("proxy".equals(Routing.defaultOutbound(mode))) {
            outbounds.addAll(proxyObs);
            outbounds.add(direct);
        } else {
            outbounds.add(direct);
            outbounds.addAll(proxyObs);
        }
        outbounds.addAll(routeOutbounds(o.routes, o.coreVersion));
        if (o.dpi != null) {
            outbounds.add(Dpi.outbound(o.dpi, Dpi.OUTBOUND, o.coreVersion));
        }
        outbounds.add(Json.obj("tag", "block", "protocol", "blackhole"));
        outbounds.add(Json.obj("tag", AdBlock.OUTBOUND, "protocol", "blackhole"));
        outbounds.add(Json.obj("tag", "dns-out", "protocol", "dns"));

        List<Object> rules = new ArrayList<Object>();
        if (o.appPort > 0) {
            rules.add(Json.obj("type", "field", "inboundTag", Json.arr("app-in"), "outboundTag", "proxy"));
        }
        rules.add(Json.obj("type", "field", "domain", Json.arr("full:" + HEALTH_HOST), "outboundTag", "proxy"));
        if (o.tun) {
            rules.add(Json.obj("type", "field", "inboundTag", Json.arr("tun-in"), "port", 53, "outboundTag", "dns-out"));
        }
        if (!"vpn".equals(mode)) {
            rules.add(Json.obj("type", "field", "inboundTag", Json.arr("dns-internal"), "ip", Json.arr(DNS_RU),
                    "outboundTag", "direct"));
        }
        rules.add(Json.obj("type", "field", "inboundTag", Json.arr("dns-internal"), "outboundTag", "proxy"));
        rules.add(Json.obj("type", "field", "ip", new ArrayList<Object>(DNS_REMOTE), "port", "53,443",
                "outboundTag", "proxy"));
        rules.addAll(Routing.buildRules(settings, o.useGeo, o.ads, o.dpi != null ? o.dpiDomains : null, o.routes));

        Map<String, Object> cfg = new LinkedHashMap<String, Object>();
        cfg.put("log", logConfig(o));
        cfg.put("stats", Json.obj());
        cfg.put("policy", Json.obj("system", Json.obj("statsOutboundUplink", true, "statsOutboundDownlink", true)));
        cfg.put("dns", dns(encrypted, o.useGeo));
        cfg.put("inbounds", inbounds);
        cfg.put("outbounds", outbounds);
        cfg.put("routing", Json.obj("domainStrategy", Routing.domainStrategy(mode), "rules", rules));
        return cfg;
    }

    /**
     * Без VPN: туннель Android → ядро → всё напрямую, кроме рекламы (в «чёрную дыру») и сайтов обхода замедлений
     * (напрямую с дроблением). Свой список «Блокировать» тоже действует. Сервер не нужен.
     */
    public static Map<String, Object> filterConfig(Map<String, Object> settings, Options o) {
        boolean encrypted = Json.bool(settings, "dns_encrypted", false);
        List<Object> inbounds = new ArrayList<Object>();
        inbounds.add(Json.obj("tag", "tun-in", "protocol", "tun", "settings", Json.obj("name", "xray0", "mtu", MTU),
                "sniffing", sniffing()));
        Map<String, Object> direct = Json.obj("tag", "direct", "protocol", "freedom");
        if (encrypted) {
            direct.put("settings", Json.obj("domainStrategy", "UseIPv4"));
        }
        List<Object> outbounds = new ArrayList<Object>();
        outbounds.add(direct);
        if (o.dpi != null) {
            outbounds.add(Dpi.outbound(o.dpi, Dpi.OUTBOUND, o.coreVersion));
        }
        outbounds.add(Json.obj("tag", "block", "protocol", "blackhole"));
        outbounds.add(Json.obj("tag", AdBlock.OUTBOUND, "protocol", "blackhole"));
        outbounds.add(Json.obj("tag", "dns-out", "protocol", "dns"));
        List<Object> rules = new ArrayList<Object>();
        rules.add(Json.obj("type", "field", "inboundTag", Json.arr("tun-in"), "port", 53, "outboundTag", "dns-out"));
        rules.add(Json.obj("type", "field", "inboundTag", Json.arr("dns-internal"), "outboundTag", "direct"));
        rules.add(Json.obj("type", "field", "ip", new ArrayList<Object>(Routing.PRIVATE_IPS), "outboundTag", "direct"));
        List<List<String>> blocked = Routing.splitEntries(Json.str(settings, "block_list"));
        if (!blocked.get(0).isEmpty()) {
            rules.add(Json.obj("type", "field", "domain", new ArrayList<Object>(blocked.get(0)), "outboundTag", "block"));
        }
        if (!blocked.get(1).isEmpty()) {
            rules.add(Json.obj("type", "field", "ip", new ArrayList<Object>(blocked.get(1)), "outboundTag", "block"));
        }
        if ("dat".equals(o.ads)) {
            rules.add(Json.obj("type", "field", "domain", Json.arr(AdBlock.RULE), "outboundTag", AdBlock.OUTBOUND));
        } else if ("geo".equals(o.ads) && o.useGeo) {
            rules.add(Json.obj("type", "field", "domain", Json.arr("geosite:category-ads-all"), "outboundTag", AdBlock.OUTBOUND));
        }
        if (o.dpi != null && o.dpiDomains != null && !o.dpiDomains.isEmpty()) {
            List<Object> d = new ArrayList<Object>();
            for (String x : o.dpiDomains) {
                d.add("domain:" + x);
            }
            rules.add(Json.obj("type", "field", "domain", d, "outboundTag", Dpi.OUTBOUND));
        }
        Map<String, Object> cfg = new LinkedHashMap<String, Object>();
        cfg.put("log", logConfig(o));
        cfg.put("dns", dns(encrypted, o.useGeo));
        cfg.put("inbounds", inbounds);
        cfg.put("outbounds", outbounds);
        cfg.put("routing", Json.obj("domainStrategy", "IPIfNonMatch", "rules", rules));
        return cfg;
    }
}
