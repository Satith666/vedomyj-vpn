package com.pultvpn.app.core;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/** Разбор ссылок серверов (vless, vmess, trojan, ss, socks, hysteria2, AmneziaWG) и JSON-конфигов. Как links.py.
 *  TUIC и AnyTLS разбираются, но на телефоне не работают (на компьютере их ведёт мост sing-box). */
public final class Links {
    private Links() {
    }

    public static final class LinkError extends Exception {
        public LinkError(String msg) {
            super(msg);
        }
    }

    static final List<String> PROXY_PROTOCOLS = Arrays.asList("vless", "vmess", "trojan", "shadowsocks", "socks",
            "http", "wireguard", "hysteria");

    static String unsupported(String scheme) {
        switch (scheme) {
            case "hysteria":
                return Text.t("Hysteria первой версии не поддерживается — нужен Hysteria2",
                        "Hysteria version 1 is not supported — Hysteria2 is needed");
            case "wireguard":
            case "wg":
                return Text.t("обычный WireGuard в России блокируют — нужен AmneziaWG",
                        "plain WireGuard is blocked in Russia — AmneziaWG is needed");
            case "tg":
                return Text.t("MTProto-прокси работает только в Telegram", "MTProto proxies only work in Telegram");
            case "ssr":
                return Text.t("ShadowsocksR не поддерживается ядром Xray", "ShadowsocksR is not supported by Xray");
            default:
                return null;
        }
    }

    static final Set<String> STUB_HOSTS = new HashSet<String>(Arrays.asList(
            "0.0.0.0", "::", "127.0.0.1", "::1", "localhost", "example.com", "0.0.0.1"));
    static final String[] STUB_WORDS = {"hwid", "включите", "обновите", "устройств", "истек", "истёк", "закончил",
            "продлите", "не поддерж", "приложени", "оплатите", "заблокирован", "лимит", "subscription expired",
            "update app", "enable hwid"};
    static final String ZERO_UUID = "00000000-0000-0000-0000-000000000000";

    static String providerMessage() {
        return Text.t("это не сервер, а сообщение провайдера", "this is a provider message, not a server");
    }

    /** Помечает заглушки провайдера и серверы без шифрования. */
    /** Ядра Xray с 1 июня 2026 не принимают allowInsecure («не проверять сертификат»): настройки с ним не запускаются.
     *  Убирает его; true — проверку просили отключить, а отпечатка сертификата нет. Как links.drop_allow_insecure. */
    public static boolean dropAllowInsecure(Map<String, Object> ob) {
        Map<String, Object> tls = Json.map(Json.map(ob, "streamSettings"), "tlsSettings");
        if (tls == null || !tls.containsKey("allowInsecure")) {
            return false;
        }
        Object v = tls.remove("allowInsecure");
        boolean asked = v instanceof Boolean ? (Boolean) v : v instanceof Number ? ((Number) v).doubleValue() != 0
                : v != null && !String.valueOf(v).isEmpty();
        return asked && Json.str(tls, "pinnedPeerCertSha256").isEmpty();
    }

    static Server markFlags(Server srv) {
        boolean unverified = dropAllowInsecure(srv.outbound);
        for (Map<String, Object> ex : srv.extraOutbounds) {
            dropAllowInsecure(ex);
        }
        if (unverified && "xray".equals(srv.engine)) {
            srv.tlsUnverified = true;
            if ("hysteria".equals(Json.str(Json.map(srv.outbound, "streamSettings"), "network"))) {
                // самоподписанный сертификат без отпечатка: по QUIC его заранее не снять, а sing-box на телефоне нет
                srv.engine = "singbox";
                srv.supported = false;
                srv.note = Text.t("самоподписанный сертификат без отпечатка (pinSHA256) — на телефоне так нельзя, "
                        + "работает в программе для компьютера", "self-signed certificate without a pin (pinSHA256) — "
                        + "not possible on the phone, works in the desktop app");
            }
        }
        String host = srv.address.replace("[", "").replace("]", "").toLowerCase();
        String uid = "";
        Map<String, Object> st = Json.map(srv.outbound, "settings");
        List<Object> vnext = Json.list(st, "vnext");
        Map<String, Object> user = null;
        if (vnext != null && !vnext.isEmpty()) {
            List<Object> users = Json.list(Json.map(vnext.get(0)), "users");
            if (users != null && !users.isEmpty()) {
                user = Json.map(users.get(0));
                uid = Json.str(user, "id");
            }
        }
        boolean main = Arrays.asList("vless", "vmess", "trojan", "shadowsocks", "socks").contains(srv.protocol);
        if (main && (STUB_HOSTS.contains(host) || srv.port == 0 || srv.port == 1 || ZERO_UUID.equals(uid))) {
            srv.stub = true;
            srv.supported = false;
            srv.note = providerMessage();
            return srv;
        }
        if (srv.supported && ("vless".equals(srv.protocol) || "trojan".equals(srv.protocol))) {
            String security = Json.str(Json.map(srv.outbound, "streamSettings"), "security", "none").toLowerCase();
            if (security.isEmpty()) {
                security = "none";
            }
            String encryption = "none";
            if (user != null) {
                encryption = Json.str(user, "encryption", "none").toLowerCase();
            } else if ("vless".equals(srv.protocol)) {
                encryption = Json.str(st, "encryption", "none").toLowerCase();
            }
            if (encryption.isEmpty()) {
                encryption = "none";
            }
            if ("none".equals(security) && "none".equals(encryption) && !Text.isPrivateHost(host)) {
                String low = srv.name.toLowerCase();
                for (String w : STUB_WORDS) {
                    if (low.contains(w)) {
                        srv.stub = true;
                        srv.supported = false;
                        srv.note = providerMessage();
                        return srv;
                    }
                }
                srv.insecure = true;
                srv.note = Text.t("сервер без шифрования (без TLS/Reality) — ядро Xray на телефоне его не запустит",
                        "server without encryption (no TLS/Reality) — the Xray core on the phone won't run it");
            }
        }
        return srv;
    }

    // ---------- вспомогательное ----------

    /** Параметры ссылки. Плюс не превращается в пробел. Повторный ключ не перезаписывает первый. */
    static Map<String, String> parseQuery(String query) {
        Map<String, String> p = new LinkedHashMap<String, String>();
        if (query == null || query.isEmpty()) {
            return p;
        }
        for (String part : query.split("&")) {
            if (part.isEmpty()) {
                continue;
            }
            String k;
            String v;
            int eq = part.indexOf('=');
            if (eq >= 0) {
                k = part.substring(0, eq);
                v = part.substring(eq + 1);
            } else {
                k = part;
                v = "";
            }
            k = Text.unquote(k).trim();
            if (!k.isEmpty() && !p.containsKey(k)) {
                p.put(k, Text.unquote(v).trim());
            }
        }
        return p;
    }

    static Object[] splitHostPort(String hostport) throws LinkError {
        String hp = hostport.trim();
        while (hp.endsWith("/")) {
            hp = hp.substring(0, hp.length() - 1);
        }
        String host;
        String portS;
        if (hp.startsWith("[")) {
            int end = hp.indexOf(']');
            if (end < 0) {
                throw new LinkError(Text.t("неверный IPv6-адрес", "invalid IPv6 address"));
            }
            host = hp.substring(1, end);
            String rest = hp.substring(end + 1);
            if (!rest.startsWith(":")) {
                throw new LinkError(Text.t("не указан порт", "no port"));
            }
            portS = rest.substring(1);
        } else {
            int c = hp.lastIndexOf(':');
            if (c < 0) {
                throw new LinkError(Text.t("не указан порт", "no port"));
            }
            host = hp.substring(0, c);
            portS = hp.substring(c + 1);
        }
        int port;
        try {
            port = Integer.parseInt(portS.trim());
        } catch (NumberFormatException e) {
            throw new LinkError(Text.t("неверный порт", "invalid port"));
        }
        if (host.isEmpty() || port <= 0 || port >= 65536) {
            throw new LinkError(Text.t("неверный адрес или порт", "invalid address or port"));
        }
        return new Object[]{host, port};
    }

    private static String first(String... values) {
        for (String v : values) {
            if (v != null && !v.isEmpty()) {
                return v;
            }
        }
        return "";
    }

    private static boolean truthy(String v) {
        String s = v == null ? "" : v.trim().toLowerCase();
        return s.equals("1") || s.equals("true") || s.equals("yes") || s.equals("on");
    }

    private static String g(Map<String, String> p, String k) {
        String v = p.get(k);
        return v == null ? "" : v;
    }

    private static List<Object> csv(String s) {
        List<Object> out = new ArrayList<Object>();
        for (String x : s.split(",")) {
            if (!x.trim().isEmpty()) {
                out.add(x.trim());
            }
        }
        return out;
    }

    // ---------- транспорт и шифрование ----------

    static Map<String, Object> buildStream(Map<String, String> p, String address, String defaultSecurity)
            throws LinkError {
        String net = first(g(p, "type"), g(p, "net"), "tcp").trim().toLowerCase();
        if (net.equals("raw")) {
            net = "tcp";
        }
        if (net.equals("splithttp")) {
            net = "xhttp";
        }
        String security = first(g(p, "security"), defaultSecurity, "none").trim().toLowerCase();
        if (security.isEmpty() || security.equals("0") || security.equals("false")) {
            security = "none";
        }
        String host = g(p, "host");
        String path = g(p, "path");
        Map<String, Object> ss = Json.obj("network", net, "security", security);

        switch (net) {
            case "tcp":
                if ("http".equalsIgnoreCase(g(p, "headerType"))) {
                    List<Object> hosts = csv(host);
                    Map<String, Object> request = Json.obj("path", Json.arr(path.isEmpty() ? "/" : path));
                    if (!hosts.isEmpty()) {
                        request.put("headers", Json.obj("Host", hosts));
                    }
                    ss.put("tcpSettings", Json.obj("header", Json.obj("type", "http", "request", request)));
                }
                break;
            case "ws": {
                Map<String, Object> ws = Json.obj("path", path.isEmpty() ? "/" : path);
                if (!host.isEmpty()) {
                    ws.put("host", host);
                }
                ss.put("wsSettings", ws);
                break;
            }
            case "grpc": {
                Map<String, Object> grpc = Json.obj("serviceName", first(g(p, "serviceName"), path),
                        "multiMode", "multi".equals(g(p, "mode")));
                if (!g(p, "authority").isEmpty()) {
                    grpc.put("authority", g(p, "authority"));
                }
                ss.put("grpcSettings", grpc);
                break;
            }
            case "httpupgrade": {
                Map<String, Object> hu = Json.obj("path", path.isEmpty() ? "/" : path);
                if (!host.isEmpty()) {
                    hu.put("host", host);
                }
                ss.put("httpupgradeSettings", hu);
                break;
            }
            case "xhttp": {
                Map<String, Object> xs = Json.obj("path", path.isEmpty() ? "/" : path);
                if (!host.isEmpty()) {
                    xs.put("host", host);
                }
                if (!g(p, "mode").isEmpty()) {
                    xs.put("mode", g(p, "mode"));
                }
                if (!g(p, "extra").isEmpty()) {
                    try {
                        xs.put("extra", Json.parse(g(p, "extra")));
                    } catch (IllegalArgumentException ignored) {
                        // повреждённые дополнительные параметры просто пропускаем
                    }
                }
                ss.put("xhttpSettings", xs);
                break;
            }
            case "kcp": {
                Map<String, Object> kcp = Json.obj("header", Json.obj("type", first(g(p, "headerType"), "none")));
                if (!g(p, "seed").isEmpty()) {
                    kcp.put("seed", g(p, "seed"));
                }
                ss.put("kcpSettings", kcp);
                break;
            }
            case "http":
            case "h2": {
                ss.put("network", "http");
                Map<String, Object> h2 = Json.obj("path", path.isEmpty() ? "/" : path);
                List<Object> hosts = csv(host);
                if (!hosts.isEmpty()) {
                    h2.put("host", hosts);
                }
                ss.put("httpSettings", h2);
                break;
            }
            default:
                throw new LinkError(Text.t("транспорт «" + net + "» не поддерживается",
                        "transport \"" + net + "\" is not supported"));
        }

        String sni = first(g(p, "sni"), g(p, "peer"), g(p, "serverName"));
        String fp = first(g(p, "fp"), g(p, "fingerprint"));
        if (security.equals("tls")) {
            String firstHost = host.isEmpty() ? address : host.split(",")[0].trim();
            Map<String, Object> tls = Json.obj("serverName", sni.isEmpty() ? firstHost : sni,
                    "fingerprint", fp.isEmpty() ? "chrome" : fp);
            if (!g(p, "alpn").isEmpty()) {
                tls.put("alpn", csv(g(p, "alpn")));
            }
            if (truthy(g(p, "allowInsecure")) || truthy(g(p, "insecure"))) {
                tls.put("allowInsecure", true);
            }
            if (!g(p, "ech").isEmpty()) {
                tls.put("echConfigList", g(p, "ech"));
            }
            if (!g(p, "pcs").isEmpty()) {
                tls.put("pinnedPeerCertSha256", g(p, "pcs"));
            }
            ss.put("tlsSettings", tls);
        } else if (security.equals("reality")) {
            String pbk = first(g(p, "pbk"), g(p, "publicKey"), g(p, "password"));
            if (pbk.isEmpty()) {
                throw new LinkError(Text.t("нет публичного ключа Reality (pbk)", "no Reality public key (pbk)"));
            }
            Map<String, Object> rs = Json.obj("serverName", sni, "fingerprint", fp.isEmpty() ? "chrome" : fp,
                    "publicKey", pbk, "shortId", g(p, "sid"), "spiderX", first(g(p, "spx"), "/"));
            if (!g(p, "pqv").isEmpty()) {
                rs.put("mldsa65Verify", g(p, "pqv"));
            }
            ss.put("realitySettings", rs);
        } else if (!security.equals("none")) {
            throw new LinkError(Text.t("шифрование «" + security + "» не поддерживается",
                    "security \"" + security + "\" is not supported"));
        }
        Map<String, Object> fm = parseFm(first(g(p, "fm"), g(p, "finalmask")));
        if (!fm.isEmpty()) {
            ss.put("finalmask", fm); // своя маскировка сервера (Finalmask, Xray 26.3.27+), как links.py
        }
        return ss;
    }

    // ---------- Finalmask (fm в ссылках) и перебор портов Hysteria2 — как links.py ----------

    static final List<String> FM_TCP = Arrays.asList("fragment", "header-custom", "sudoku");
    static final List<String> FM_UDP = Arrays.asList("header-custom", "noise", "salamander", "sudoku", "mkcp-legacy", "realm", "udphop");

    @SuppressWarnings("unchecked")
    static Map<String, Object> cleanFinalmask(Object v) {
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        if (!(v instanceof Map)) {
            return out;
        }
        Map<String, Object> obj = (Map<String, Object>) v;
        for (String key : new String[]{"tcp", "udp"}) {
            List<String> allowed = key.equals("tcp") ? FM_TCP : FM_UDP;
            List<Object> layers = new ArrayList<Object>();
            Object list = obj.get(key);
            if (list instanceof List) {
                for (Object item : (List<Object>) list) {
                    if (item instanceof Map && allowed.contains(Json.str((Map<String, Object>) item, "type"))
                            && ((Map<String, Object>) item).get("type") instanceof String) {
                        Map<String, Object> layer = Json.obj("type", ((Map<String, Object>) item).get("type"));
                        Object st = ((Map<String, Object>) item).get("settings");
                        if (st instanceof Map) {
                            layer.put("settings", st);
                        }
                        layers.add(layer);
                    }
                }
            }
            if (!layers.isEmpty()) {
                out.put(key, new ArrayList<Object>(layers.subList(0, Math.min(8, layers.size()))));
            }
        }
        Object qp = obj.get("quicParams");
        if (qp instanceof Map && !((Map<String, Object>) qp).isEmpty()) {
            Map<String, Object> q = new LinkedHashMap<String, Object>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) qp).entrySet()) {
                Object x = e.getValue();
                if (x instanceof String || x instanceof Number || x instanceof Boolean || x instanceof Map) {
                    q.put(e.getKey(), x);
                }
            }
            out.put("quicParams", q);
        }
        return out;
    }

    static Map<String, Object> parseFm(String value) {
        if (value == null || value.isEmpty() || value.length() > 8192) {
            return new LinkedHashMap<String, Object>();
        }
        try {
            return cleanFinalmask(Json.parse(value));
        } catch (RuntimeException e) {
            return new LinkedHashMap<String, Object>();
        }
    }

    static final java.util.regex.Pattern PORTS = java.util.regex.Pattern.compile("^\\d{1,5}(-\\d{1,5})?(,\\d{1,5}(-\\d{1,5})?)*$");

    /** Порты для перебора («20000-50000», «443,8443,10000-20000») или "". */
    static String portsSpec(String value) {
        String v = value == null ? "" : value.replace(" ", "");
        if (v.isEmpty() || !PORTS.matcher(v).matches()) {
            return "";
        }
        for (String part : v.split(",")) {
            String[] ab = part.split("-", 2);
            int lo = Integer.parseInt(ab[0]);
            int hi = ab.length > 1 ? Integer.parseInt(ab[1]) : lo;
            if (lo < 1 || hi > 65535 || lo > hi) {
                return "";
            }
        }
        return v;
    }

    // ---------- протоколы ----------

    /** {userinfo, hostport, query, name} для ссылок вида scheme://user@host:port/path?q#name (как urlsplit). */
    static String[] splitLink(String link) throws LinkError {
        String rest = link.substring(link.indexOf("://") + 3);
        String frag = "";
        int hash = rest.indexOf('#');
        if (hash >= 0) {
            frag = rest.substring(hash + 1);
            rest = rest.substring(0, hash);
        }
        String query = "";
        int q = rest.indexOf('?');
        if (q >= 0) {
            query = rest.substring(q + 1);
            rest = rest.substring(0, q);
        }
        int slash = rest.indexOf('/');
        String netloc = slash >= 0 ? rest.substring(0, slash) : rest;
        int at = netloc.lastIndexOf('@');
        if (at < 0) {
            throw new LinkError(Text.t("нет данных пользователя в ссылке", "no user info in the link"));
        }
        return new String[]{Text.unquote(netloc.substring(0, at)), netloc.substring(at + 1), query,
                Text.unquote(frag)};
    }

    static Server parseVless(String link) throws LinkError {
        String[] sp = splitLink(link);
        Object[] hp = splitHostPort(sp[1]);
        String host = (String) hp[0];
        int port = (Integer) hp[1];
        Map<String, String> p = parseQuery(sp[2]);
        Map<String, Object> user = Json.obj("id", sp[0], "encryption", first(g(p, "encryption"), "none"));
        if (!g(p, "flow").isEmpty()) {
            user.put("flow", g(p, "flow"));
        }
        Server s = new Server();
        s.outbound = Json.obj("protocol", "vless",
                "settings", Json.obj("vnext", Json.arr(Json.obj("address", host, "port", port, "users", Json.arr(user)))),
                "streamSettings", buildStream(p, host, "none"));
        s.name = sp[3].isEmpty() ? "VLESS " + host : sp[3];
        s.protocol = "vless";
        s.address = host;
        s.port = port;
        s.link = link;
        return s;
    }

    static Server parseTrojan(String link) throws LinkError {
        String[] sp = splitLink(link);
        Object[] hp = splitHostPort(sp[1]);
        String host = (String) hp[0];
        int port = (Integer) hp[1];
        Map<String, String> p = parseQuery(sp[2]);
        Map<String, Object> server = Json.obj("address", host, "port", port, "password", sp[0]);
        if (!g(p, "flow").isEmpty()) {
            server.put("flow", g(p, "flow"));
        }
        Server s = new Server();
        s.outbound = Json.obj("protocol", "trojan", "settings", Json.obj("servers", Json.arr(server)),
                "streamSettings", buildStream(p, host, "tls"));
        s.name = sp[3].isEmpty() ? "Trojan " + host : sp[3];
        s.protocol = "trojan";
        s.address = host;
        s.port = port;
        s.link = link;
        return s;
    }

    static Server parseVmess(String link) throws LinkError {
        String body = link.substring("vmess://".length());
        String nameHint = "";
        int hash = body.indexOf('#');
        if (hash >= 0) {
            nameHint = Text.unquote(body.substring(hash + 1));
            body = body.substring(0, hash);
        }
        int qm = body.indexOf('?');
        String text = Text.b64text(qm >= 0 ? body.substring(0, qm) : body);
        if (text != null && text.trim().startsWith("{")) {
            Map<String, Object> v;
            try {
                v = Json.parseObject(text);
            } catch (IllegalArgumentException e) {
                throw new LinkError(Text.t("повреждённая vmess-ссылка", "damaged vmess link"));
            }
            String host = Json.str(v, "add").trim();
            int port;
            try {
                port = Integer.parseInt(Json.str(v, "port", "0").trim());
            } catch (NumberFormatException e) {
                throw new LinkError(Text.t("неверный порт", "invalid port"));
            }
            if (host.isEmpty() || port == 0) {
                throw new LinkError(Text.t("нет адреса сервера", "no server address"));
            }
            String net = first(Json.str(v, "net"), "tcp");
            String tls = Json.str(v, "tls").toLowerCase();
            Map<String, String> p = new LinkedHashMap<String, String>();
            p.put("type", net);
            p.put("headerType", Json.str(v, "type"));
            p.put("host", Json.str(v, "host"));
            p.put("path", Json.str(v, "path"));
            p.put("security", tls.equals("tls") || tls.equals("reality") ? tls : "none");
            p.put("sni", Json.str(v, "sni"));
            p.put("alpn", Json.str(v, "alpn"));
            p.put("fp", Json.str(v, "fp"));
            p.put("pbk", Json.str(v, "pbk"));
            p.put("sid", Json.str(v, "sid"));
            p.put("allowInsecure", first(Json.str(v, "allowInsecure"), Json.str(v, "skip-cert-verify")));
            if (net.equals("grpc")) {
                p.put("serviceName", p.get("path"));
                p.put("mode", Json.str(v, "type"));
            }
            Server s = new Server();
            s.outbound = Json.obj("protocol", "vmess",
                    "settings", Json.obj("vnext", Json.arr(Json.obj("address", host, "port", port, "users",
                            Json.arr(Json.obj("id", Json.str(v, "id"), "security", first(Json.str(v, "scy"), "auto")))))),
                    "streamSettings", buildStream(p, host, "none"));
            s.name = first(Json.str(v, "ps"), nameHint, "VMess " + host);
            s.protocol = "vmess";
            s.address = host;
            s.port = port;
            s.link = link;
            return s;
        }
        String[] sp = splitLink(link);
        Object[] hp = splitHostPort(sp[1]);
        String host = (String) hp[0];
        int port = (Integer) hp[1];
        Map<String, String> p = parseQuery(sp[2]);
        Server s = new Server();
        s.outbound = Json.obj("protocol", "vmess",
                "settings", Json.obj("vnext", Json.arr(Json.obj("address", host, "port", port, "users",
                        Json.arr(Json.obj("id", sp[0], "security", first(g(p, "encryption"), "auto")))))),
                "streamSettings", buildStream(p, host, "none"));
        s.name = sp[3].isEmpty() ? "VMess " + host : sp[3];
        s.protocol = "vmess";
        s.address = host;
        s.port = port;
        s.link = link;
        return s;
    }

    static Server parseSs(String link) throws LinkError {
        String body = link.substring("ss://".length());
        String name = "";
        int hash = body.indexOf('#');
        if (hash >= 0) {
            name = Text.unquote(body.substring(hash + 1));
            body = body.substring(0, hash);
        }
        String query = "";
        int qm = body.indexOf('?');
        if (qm >= 0) {
            query = body.substring(qm + 1);
            body = body.substring(0, qm);
        }
        Map<String, String> p = parseQuery(query);
        if (!g(p, "plugin").isEmpty()) {
            throw new LinkError(Text.t("плагины Shadowsocks не поддерживаются", "Shadowsocks plugins are not supported"));
        }
        while (body.endsWith("/")) {
            body = body.substring(0, body.length() - 1);
        }
        String method;
        String password;
        String hostport;
        int at = body.lastIndexOf('@');
        if (at >= 0) {
            String userinfo = body.substring(0, at);
            hostport = body.substring(at + 1);
            String plain = Text.unquote(userinfo);
            String cred = plain;
            if (!plain.contains(":")) {
                cred = Text.b64text(userinfo);
                if (cred == null || !cred.contains(":")) {
                    throw new LinkError(Text.t("не удалось прочитать метод и пароль", "cannot read method and password"));
                }
            }
            int c = cred.indexOf(':');
            method = cred.substring(0, c);
            password = cred.substring(c + 1);
        } else {
            String decoded = Text.b64text(body);
            if (decoded == null || !decoded.contains("@")) {
                throw new LinkError(Text.t("повреждённая ss-ссылка", "damaged ss link"));
            }
            int a = decoded.lastIndexOf('@');
            String cred = decoded.substring(0, a);
            hostport = decoded.substring(a + 1);
            int c = cred.indexOf(':');
            if (c < 0) {
                throw new LinkError(Text.t("не удалось прочитать метод и пароль", "cannot read method and password"));
            }
            method = cred.substring(0, c);
            password = cred.substring(c + 1);
        }
        Object[] hp = splitHostPort(hostport);
        String host = (String) hp[0];
        int port = (Integer) hp[1];
        Server s = new Server();
        s.outbound = Json.obj("protocol", "shadowsocks", "settings", Json.obj("servers", Json.arr(
                Json.obj("address", host, "port", port, "method", method, "password", password))));
        s.name = name.isEmpty() ? "Shadowsocks " + host : name;
        s.protocol = "shadowsocks";
        s.address = host;
        s.port = port;
        s.link = link;
        return s;
    }

    static Server parseSocks(String link) throws LinkError {
        String rest = link.substring(link.indexOf("://") + 3);
        String name = "";
        int hash = rest.indexOf('#');
        if (hash >= 0) {
            name = Text.unquote(rest.substring(hash + 1));
            rest = rest.substring(0, hash);
        }
        int qm = rest.indexOf('?');
        if (qm >= 0) {
            rest = rest.substring(0, qm);
        }
        while (rest.endsWith("/")) {
            rest = rest.substring(0, rest.length() - 1);
        }
        String user = "";
        String password = "";
        String hostport = rest;
        int at = rest.lastIndexOf('@');
        if (at >= 0) {
            String userinfo = rest.substring(0, at);
            hostport = rest.substring(at + 1);
            String plain = Text.unquote(userinfo);
            if (plain.contains(":")) {
                user = plain.substring(0, plain.indexOf(':'));
                password = plain.substring(plain.indexOf(':') + 1);
            } else {
                String decoded = Text.b64text(userinfo);
                if (decoded != null && decoded.contains(":")) {
                    user = decoded.substring(0, decoded.indexOf(':'));
                    password = decoded.substring(decoded.indexOf(':') + 1);
                } else {
                    user = plain;
                }
            }
        }
        Object[] hp = splitHostPort(hostport);
        String host = (String) hp[0];
        int port = (Integer) hp[1];
        Map<String, Object> srv = Json.obj("address", host, "port", port);
        if (!user.isEmpty()) {
            srv.put("users", Json.arr(Json.obj("user", user, "pass", password)));
        }
        Server s = new Server();
        s.outbound = Json.obj("protocol", "socks", "settings", Json.obj("servers", Json.arr(srv)));
        s.name = name.isEmpty() ? "SOCKS5 " + host : name;
        s.protocol = "socks";
        s.address = host;
        s.port = port;
        s.link = link;
        return s;
    }

    // ---------- Hysteria2 (в ядре Xray), TUIC и AnyTLS (только на компьютере), AmneziaWG ----------

    /** {netloc, query, fragment} — как urlsplit в Python. */
    static String[] urlParts(String link) {
        String rest = link.substring(link.indexOf("://") + 3);
        String frag = "";
        int hash = rest.indexOf('#');
        if (hash >= 0) {
            frag = rest.substring(hash + 1);
            rest = rest.substring(0, hash);
        }
        String query = "";
        int q = rest.indexOf('?');
        if (q >= 0) {
            query = rest.substring(q + 1);
            rest = rest.substring(0, q);
        }
        int slash = rest.indexOf('/');
        return new String[]{slash >= 0 ? rest.substring(0, slash) : rest, query, frag};
    }

    static Map<String, Object> tlsParams(Map<String, String> p, String host, List<Object> alpnDefault) {
        String sni = first(g(p, "sni"), g(p, "peer"), g(p, "serverName"));
        Map<String, Object> tls = Json.obj("serverName", sni.isEmpty() ? host : sni);
        List<Object> alpn = csv(g(p, "alpn"));
        if (alpn.isEmpty() && alpnDefault != null) {
            alpn = alpnDefault;
        }
        if (!alpn.isEmpty()) {
            tls.put("alpn", alpn);
        }
        if (truthy(g(p, "insecure")) || truthy(g(p, "allowInsecure")) || truthy(g(p, "allow_insecure"))) {
            tls.put("allowInsecure", true);
        }
        String pin = first(g(p, "pinSHA256"), g(p, "pcs"));
        if (!pin.isEmpty()) {
            tls.put("pinnedPeerCertSha256", pin);
        }
        return tls;
    }

    /** hysteria2://пароль@адрес:порт/?sni=…&obfs=salamander&obfs-password=…#имя → Xray (protocol hysteria, Xray 26.2+). */
    static Server parseHysteria2(String link) throws LinkError {
        String[] u = urlParts(link);
        String name = Text.unquote(u[2]);
        String netloc = u[0];
        String auth = "";
        int at = netloc.lastIndexOf('@');
        if (at >= 0) {
            auth = Text.unquote(netloc.substring(0, at));
            netloc = netloc.substring(at + 1);
        }
        String hop = "";
        java.util.regex.Matcher mh = java.util.regex.Pattern
                .compile("^(.*):(\\d{1,5}(?:-\\d{1,5})?(?:,\\d{1,5}(?:-\\d{1,5})?)+|\\d{1,5}-\\d{1,5})$").matcher(netloc);
        if (mh.matches() && !netloc.endsWith("]")) { // несколько портов прямо в адресе: первый — основной
            hop = portsSpec(mh.group(2));
            java.util.regex.Matcher first = java.util.regex.Pattern.compile("^\\d+").matcher(mh.group(2));
            first.find();
            netloc = mh.group(1) + ":" + first.group();
        }
        Object[] hp = splitHostPort(netloc.matches(".*:\\d+") ? netloc : netloc + ":443");
        String host = (String) hp[0];
        int port = (Integer) hp[1];
        Map<String, String> p = parseQuery(u[1]);
        String hopQ = portsSpec(first(g(p, "mport"), g(p, "ports")));
        if (!hopQ.isEmpty()) {
            hop = hopQ;
        }
        Map<String, Object> ss = Json.obj("network", "hysteria", "hysteriaSettings", Json.obj("version", 2, "auth", auth),
                "security", "tls", "tlsSettings", tlsParams(p, host, Json.arr("h3")));
        String obfs = g(p, "obfs").toLowerCase();
        if (!obfs.isEmpty() && !obfs.equals("salamander")) {
            throw new LinkError(Text.t("маскировка «" + obfs + "» не поддерживается", "masking \"" + obfs + "\" is not supported"));
        }
        Map<String, Object> fm = parseFm(g(p, "fm"));
        if (!obfs.isEmpty()) {
            List<Object> udp = Json.arr(Json.obj("type", "salamander", "settings", Json.obj("password", g(p, "obfs-password"))));
            Object old = fm.get("udp");
            if (old instanceof List) {
                for (Object x : (List<?>) old) {
                    if (!"salamander".equals(Json.str(Json.map(x), "type"))) {
                        udp.add(x);
                    }
                }
            }
            fm.put("udp", udp);
        }
        if (!hop.isEmpty()) {
            int interval = 30;
            try {
                String iv = first(g(p, "mportHopInt"), g(p, "hop_interval"));
                if (!iv.isEmpty()) {
                    interval = Math.max(5, Math.min(Integer.parseInt(iv), 600));
                }
            } catch (NumberFormatException e) {
                interval = 30;
            }
            Map<String, Object> qp = Json.map(fm, "quicParams");
            if (qp == null) {
                qp = new LinkedHashMap<String, Object>();
                fm.put("quicParams", qp);
            }
            qp.put("udpHop", Json.obj("ports", hop, "interval", interval));
        }
        if (!fm.isEmpty()) {
            ss.put("finalmask", fm);
        }
        Server s = new Server();
        s.name = name.isEmpty() ? "Hysteria2 " + host : name;
        s.protocol = "hysteria2";
        s.address = host;
        s.port = port;
        s.outbound = Json.obj("tag", "proxy", "protocol", "hysteria", "settings",
                Json.obj("version", 2, "address", host, "port", port), "streamSettings", ss);
        s.link = link;
        return s;
    }

    /** TUIC и AnyTLS: адрес и имя для списка, но на телефоне не подключаются (нет sing-box). */
    static Server parseDesktopOnly(String link, String scheme) throws LinkError {
        String[] sp = splitLink(link);
        Object[] hp = splitHostPort(sp[1]);
        String host = (String) hp[0];
        boolean tuic = scheme.equals("tuic");
        if (tuic && sp[0].split(":", 2)[0].isEmpty()) {
            throw new LinkError(Text.t("нет UUID", "no UUID"));
        }
        Server s = new Server();
        s.name = sp[3].isEmpty() ? (tuic ? "TUIC " : "AnyTLS ") + host : sp[3];
        s.protocol = scheme;
        s.address = host;
        s.port = (Integer) hp[1];
        s.link = link;
        s.engine = "singbox";
        s.supported = false;
        s.note = Text.t("TUIC и AnyTLS работают только в программе для компьютера (через sing-box)",
                "TUIC and AnyTLS work only in the desktop app (via sing-box)");
        return s;
    }

    static final String[] AWG_KEYS = {"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
            "I1", "I2", "I3", "I4", "I5"};
    private static final Pattern SECTION = Pattern.compile("\\[(\\w+)\\]");

    /** [Interface]/[Peer] → {interface, peer}. Без ключей или адреса — ошибка. */
    static Map<String, Map<String, String>> awgParseConf(String text) throws LinkError {
        Map<String, Map<String, String>> out = new LinkedHashMap<String, Map<String, String>>();
        out.put("interface", new LinkedHashMap<String, String>());
        out.put("peer", new LinkedHashMap<String, String>());
        String sect = "";
        for (String raw : (text == null ? "" : text).split("\r\n|\r|\n")) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) {
                continue;
            }
            Matcher m = SECTION.matcher(line);
            if (m.matches()) {
                sect = m.group(1).toLowerCase();
                continue;
            }
            int eq = line.indexOf('=');
            if (eq >= 0 && out.containsKey(sect)) {
                String k = line.substring(0, eq).trim();
                if (!out.get(sect).containsKey(k)) {
                    out.get(sect).put(k, line.substring(eq + 1).trim());
                }
            }
        }
        Map<String, String> i = out.get("interface");
        Map<String, String> p = out.get("peer");
        if (empty(i.get("PrivateKey")) || empty(p.get("PublicKey")) || empty(p.get("Endpoint"))) {
            throw new LinkError(Text.t("в конфиге AmneziaWG нет ключей или адреса сервера",
                    "the AmneziaWG config has no keys or server address"));
        }
        return out;
    }

    private static boolean empty(String v) {
        return v == null || v.isEmpty();
    }

    /** Конфиг AmneziaWG → одна строка awg://… (так он хранится вместе с другими своими серверами). */
    public static String awgLink(String conf, String name) throws LinkError {
        awgParseConf(conf);
        String body = Base64.getUrlEncoder().withoutPadding().encodeToString(conf.trim().getBytes(StandardCharsets.UTF_8));
        return "awg://" + body + (name == null || name.isEmpty() ? "" : "#" + Text.quote(name));
    }

    /** Текст конфига из строки awg://. */
    public static String awgConfOf(String link) throws LinkError {
        String rest = link.substring("awg://".length());
        int hash = rest.indexOf('#');
        String conf = Text.b64text(hash >= 0 ? rest.substring(0, hash) : rest);
        if (conf == null) {
            throw new LinkError(Text.t("ссылка AmneziaWG повреждена", "the AmneziaWG link is damaged"));
        }
        return conf;
    }

    static Server parseAwg(String link) throws LinkError {
        String conf = awgConfOf(link);
        Map<String, Map<String, String>> c = awgParseConf(conf);
        Object[] hp = splitHostPort(c.get("peer").get("Endpoint"));
        int hash = link.indexOf('#');
        String name = hash >= 0 ? Text.unquote(link.substring(hash + 1)) : "";
        int obf = 0;
        for (String k : AWG_KEYS) {
            String v = c.get("interface").get(k);
            if (v != null && !v.isEmpty() && !v.equals("0")) {
                obf++;
            }
        }
        Server s = new Server();
        s.name = name.isEmpty() ? "AmneziaWG " + hp[0] : name;
        s.protocol = "amneziawg";
        s.address = (String) hp[0];
        s.port = (Integer) hp[1];
        s.link = link;
        s.engine = "awg";
        s.awgConf = conf;
        s.note = obf > 0 ? "" : Text.t("без маскировки AmneziaWG это обычный WireGuard — в России его блокируют",
                "without masking AmneziaWG is plain WireGuard — it is blocked in Russia");
        return s;
    }

    static Server parseXrayJson(String link) throws LinkError {
        String text = Text.b64text(link.substring("xrayjson://".length()));
        if (text == null) {
            throw new LinkError(Text.t("в настройках Xray нет сервера", "the Xray settings have no server"));
        }
        List<Server> found = serversFromJson(Json.parse(text));
        if (found.isEmpty()) {
            throw new LinkError(Text.t("в настройках Xray нет сервера", "the Xray settings have no server"));
        }
        Server s = found.get(0);
        s.link = link;
        s.source = "link";
        return s;
    }

    /** Ключ AmneziaVPN vpn://… → [вид, текст]: «awg» — конфиг AmneziaWG, «xray» — JSON Xray, «name» — название. */
    public static List<String[]> amneziaKeyConfigs(String key) throws LinkError {
        byte[] data = Text.b64decode(key.trim().substring("vpn://".length()));
        if (data == null) {
            throw new LinkError(Text.t("ключ Amnezia не читается", "the Amnezia key cannot be read"));
        }
        byte[] plain = inflate(data, 4);
        if (plain == null) {
            plain = inflate(data, 0);
        }
        Object root;
        try {
            root = Json.parse(new String(plain != null ? plain : data, StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            throw new LinkError(Text.t("ключ Amnezia не читается", "the Amnezia key cannot be read"));
        }
        List<String[]> found = new ArrayList<String[]>();
        walkKey(root, 0, found);
        String name = root instanceof Map ? Json.str(Json.map(root), "description") : "";
        if (!name.isEmpty()) {
            found.add(new String[]{"name", name});
        }
        return found;
    }

    private static byte[] inflate(byte[] data, int offset) {
        if (data.length <= offset) {
            return null;
        }
        Inflater inf = new Inflater();
        inf.setInput(data, offset, data.length - offset);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        try {
            while (!inf.finished()) {
                int n = inf.inflate(buf);
                if (n == 0 && (inf.needsInput() || inf.needsDictionary())) {
                    return null;
                }
                out.write(buf, 0, n);
                if (out.size() > 4 * 1024 * 1024) {
                    return null;
                }
            }
            return out.toByteArray();
        } catch (DataFormatException e) {
            return null;
        } finally {
            inf.end();
        }
    }

    private static void walkKey(Object x, int depth, List<String[]> found) {
        if (depth > 8 || x == null) {
            return;
        }
        if (x instanceof Map) {
            Map<String, Object> m = Json.map(x);
            if (m.get("outbounds") instanceof List) {
                found.add(new String[]{"xray", Json.write(m)});
                return;
            }
            for (Object v : m.values()) {
                walkKey(v, depth + 1, found);
            }
        } else if (x instanceof List) {
            for (Object v : Json.list(x)) {
                walkKey(v, depth + 1, found);
            }
        } else if (x instanceof String) {
            String str = (String) x;
            if (str.trim().startsWith("{")) {  // last_config — JSON строкой; внутри него уже сам конфиг
                try {
                    walkKey(Json.parse(str), depth + 1, found);
                    return;
                } catch (RuntimeException ignored) {
                    // не JSON — смотрим как на текст
                }
            }
            if (str.contains("[Interface]") && str.contains("[Peer]")) {
                found.add(new String[]{"awg", str});
            }
        }
    }

    private static final Pattern CONF_NAME = Pattern.compile("^#\\s*(?:Name\\s*=\\s*)?(.+)$", Pattern.MULTILINE);

    /** Вставленный текст → строки-ссылки: конфиг AmneziaWG целиком — в awg://, ключ vpn:// — в awg:// и ссылки Xray. */
    public static List<String> textToLinks(String text) throws LinkError {
        String t = text == null ? "" : text.trim();
        List<String> out = new ArrayList<String>();
        if (t.contains("[Interface]") && t.contains("[Peer]")) {
            Matcher m = CONF_NAME.matcher(t);
            String name = m.find() ? m.group(1).trim() : "";
            out.add(awgLink(t, name.length() > 60 ? name.substring(0, 60) : name));
            return out;
        }
        for (String raw : t.split("\\s+")) {
            String line = raw.trim();
            if (line.toLowerCase().startsWith("vpn://")) {
                List<String[]> items = amneziaKeyConfigs(line);
                String name = "";
                for (String[] it : items) {
                    if (it[0].equals("name")) {
                        name = it[1];
                    }
                }
                boolean any = false;
                for (String[] it : items) {
                    if (it[0].equals("awg")) {
                        out.add(awgLink(it[1], name));
                        any = true;
                    } else if (it[0].equals("xray")) {
                        for (Server srv : serversFromJson(Json.parse(it[1]))) {
                            List<Object> obs = new ArrayList<Object>();
                            obs.add(srv.outbound);
                            obs.addAll(srv.extraOutbounds);
                            String body = Json.write(Json.obj("remarks", name.isEmpty() ? srv.name : name, "outbounds", obs));
                            out.add("xrayjson://" + Base64.getUrlEncoder().withoutPadding()
                                    .encodeToString(body.getBytes(StandardCharsets.UTF_8)));
                            any = true;
                        }
                    }
                }
                if (!any) {
                    throw new LinkError(Text.t("в ключе Amnezia нет ни AmneziaWG, ни Xray",
                            "the Amnezia key has neither AmneziaWG nor Xray"));
                }
            } else if (!line.isEmpty()) {
                out.add(line);
            }
        }
        return out;
    }

    /** Движок сервера: xray, hy2 (Hysteria2 в ядре Xray), singbox (TUIC/AnyTLS — только компьютер), awg. */
    public static String kindOf(Server s) {
        if ("awg".equals(s.engine)) {
            return "awg";
        }
        if ("hysteria2".equals(s.protocol) || "hy2".equals(s.protocol) || "hysteria".equals(s.protocol)) {
            return "hy2";
        }
        return "singbox".equals(s.engine) ? "singbox" : "xray";
    }

    private static String nameOf(String line, String scheme) {
        int hash = line.indexOf('#');
        return hash >= 0 ? Text.unquote(line.substring(hash + 1)) : scheme.toUpperCase();
    }

    private static Server unsupportedServer(String name, String protocol, String link, String note) {
        Server s = new Server();
        s.name = name;
        s.protocol = protocol;
        s.link = link;
        s.supported = false;
        s.note = note;
        return s;
    }

    /** Разбирает одну строку. null — строка не является ссылкой на сервер. */
    public static Server parseLink(String raw) {
        String line = raw == null ? "" : raw.trim();
        int sep = line.indexOf("://");
        if (sep <= 0) {
            return null;
        }
        String scheme = line.substring(0, sep).toLowerCase();
        if (scheme.equals("happ")) {
            if (line.toLowerCase().startsWith("happ://crypt")) {
                return unsupportedServer(Text.t("Зашифрованная ссылка Happ", "Encrypted Happ link"), "happ", line,
                        Text.t("Провайдер зашифровал ссылку только для Happ.", "The provider encrypted the link for Happ only."));
            }
            return null;
        }
        if ((scheme.equals("http") || scheme.equals("https")) && line.contains("t.me/proxy")) {
            return unsupportedServer(Text.t("MTProto-прокси", "MTProto proxy"), "mtproto", line, unsupported("tg"));
        }
        String note = unsupported(scheme);
        if (note != null) {
            return unsupportedServer(nameOf(line, scheme), scheme, line, note);
        }
        try {
            Server s;
            switch (scheme) {
                case "vless":
                    s = parseVless(line);
                    break;
                case "vmess":
                    s = parseVmess(line);
                    break;
                case "trojan":
                    s = parseTrojan(line);
                    break;
                case "ss":
                    s = parseSs(line);
                    break;
                case "socks":
                case "socks5":
                    s = parseSocks(line);
                    break;
                case "hysteria2":
                case "hy2":
                    s = parseHysteria2(line);
                    break;
                case "tuic":
                case "anytls":
                    s = parseDesktopOnly(line, scheme);
                    break;
                case "awg":
                    s = parseAwg(line);
                    break;
                case "xrayjson":
                    s = parseXrayJson(line);
                    break;
                default:
                    return null;
            }
            return markFlags(s);
        } catch (LinkError e) {
            return unsupportedServer(nameOf(line, scheme), scheme, line, e.getMessage());
        } catch (RuntimeException e) {
            return unsupportedServer(nameOf(line, scheme), scheme, line,
                    Text.t("не удалось разобрать: ", "cannot parse: ") + e.getMessage());
        }
    }

    // ---------- JSON-конфиги ----------

    private static Object[] outboundEndpoint(Map<String, Object> ob) {
        Map<String, Object> st = Json.map(ob, "settings");
        for (String key : new String[]{"vnext", "servers", "peers"}) {
            List<Object> lst = Json.list(st, key);
            if (lst != null && !lst.isEmpty()) {
                Map<String, Object> item = Json.map(lst.get(0));
                String addr = first(Json.str(item, "address"), Json.str(item, "endpoint"));
                long port = Json.num(item, "port", 0);
                if (port == 0 && addr.indexOf(':') >= 0 && addr.indexOf(':') == addr.lastIndexOf(':')) {
                    try {
                        port = Long.parseLong(addr.substring(addr.indexOf(':') + 1));
                    } catch (NumberFormatException ignored) {
                        port = 0;
                    }
                    addr = addr.substring(0, addr.indexOf(':'));
                }
                return new Object[]{addr, (int) port};
            }
        }
        return new Object[]{Json.str(st, "address"), (int) Json.num(st, "port", 0)};
    }

    private static List<String> referencedTags(Map<String, Object> ob) {
        List<String> tags = new ArrayList<String>();
        Map<String, Object> so = Json.map(Json.map(ob, "streamSettings"), "sockopt");
        if (!Json.str(so, "dialerProxy").isEmpty()) {
            tags.add(Json.str(so, "dialerProxy"));
        }
        Map<String, Object> ps = Json.map(ob, "proxySettings");
        if (!Json.str(ps, "tag").isEmpty()) {
            tags.add(Json.str(ps, "tag"));
        }
        return tags;
    }

    public static List<Server> serversFromJson(Object data) {
        List<Object> configs = data instanceof List ? Json.list(data) : Json.arr(data);
        List<Server> result = new ArrayList<Server>();
        int i = 0;
        for (Object c : configs) {
            i++;
            Map<String, Object> cfg = Json.map(c);
            if (cfg == null) {
                continue;
            }
            List<Map<String, Object>> outbounds = new ArrayList<Map<String, Object>>();
            List<Object> raw = Json.list(cfg, "outbounds");
            if (raw != null) {
                for (Object o : raw) {
                    if (o instanceof Map) {
                        outbounds.add(Json.map(o));
                    }
                }
            }
            Map<String, Map<String, Object>> byTag = new LinkedHashMap<String, Map<String, Object>>();
            List<Map<String, Object>> proxies = new ArrayList<Map<String, Object>>();
            for (Map<String, Object> o : outbounds) {
                if (!Json.str(o, "tag").isEmpty()) {
                    byTag.put(Json.str(o, "tag"), o);
                }
                if (PROXY_PROTOCOLS.contains(Json.str(o, "protocol"))) {
                    proxies.add(o);
                }
            }
            if (proxies.isEmpty()) {
                continue;
            }
            Map<String, Object> main = proxies.contains(byTag.get("proxy")) ? byTag.get("proxy") : proxies.get(0);
            List<Map<String, Object>> extras = new ArrayList<Map<String, Object>>();
            List<String> queue = new ArrayList<String>(referencedTags(main));
            Set<String> seen = new HashSet<String>();
            while (!queue.isEmpty()) {
                String tag = queue.remove(0);
                if (seen.contains(tag) || !byTag.containsKey(tag)) {
                    continue;
                }
                seen.add(tag);
                extras.add(Json.copy(byTag.get(tag)));
                queue.addAll(referencedTags(byTag.get(tag)));
            }
            Object[] ep = outboundEndpoint(main);
            Server s = new Server();
            s.name = first(Json.str(cfg, "remarks"), Text.t("JSON-сервер ", "JSON server ") + i);
            s.protocol = Json.str(main, "protocol");
            s.address = (String) ep[0];
            s.port = (Integer) ep[1];
            s.outbound = Json.copy(main);
            s.extraOutbounds = extras;
            s.source = "json";
            result.add(markFlags(s));
        }
        return result;
    }
}
