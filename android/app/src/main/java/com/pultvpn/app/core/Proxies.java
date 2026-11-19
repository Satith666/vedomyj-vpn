package com.pultvpn.app.core;

import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Свои прокси (SOCKS5 и HTTP) для отдельных сервисов и сайтов — например, резидентный прокси для TikTok. Как proxies.py.
 * Логин и пароль прокси — секрет: в журнал, отчёты, интерфейс и файл переноса настроек они не попадают.
 */
public final class Proxies {
    private Proxies() {
    }

    public static final int MAX = 30;

    public static final class ProxyError extends Exception {
        public ProxyError(String msg) {
            super(msg);
        }
    }

    private static final Pattern HOST = Pattern.compile(
            "^(?=.{1,253}$)[a-z0-9_]([a-z0-9_-]{0,62}[a-z0-9_])?(\\.[a-z0-9_]([a-z0-9_-]{0,62}[a-z0-9_])?)*$");
    private static final Pattern SCHEME = Pattern.compile("^([A-Za-z][A-Za-z0-9+.-]*)://");

    private static String host(String value) throws ProxyError {
        String h = value == null ? "" : value.trim();
        if (h.startsWith("[") && h.endsWith("]")) {
            h = h.substring(1, h.length() - 1);
        }
        h = h.toLowerCase();
        if (Text.isIpOrCidr(h) && !h.contains("/")) {
            return h;
        }
        if (!HOST.matcher(h).matches() || !h.contains(".")) {
            throw new ProxyError(Text.t("Не похоже на адрес прокси. Пример: socks5://логин:пароль@1.2.3.4:1080",
                    "This doesn't look like a proxy address. Example: socks5://login:password@1.2.3.4:1080"));
        }
        return h;
    }

    private static int port(String value) throws ProxyError {
        int p;
        try {
            p = Integer.parseInt(value == null ? "" : value.trim());
        } catch (NumberFormatException e) {
            p = 0;
        }
        if (p < 1 || p > 65535) {
            throw new ProxyError(Text.t("Порт прокси — число от 1 до 65535.", "The proxy port is a number from 1 to 65535."));
        }
        return p;
    }

    private static boolean digits(String s) {
        return !s.isEmpty() && s.matches("\\d+");
    }

    /** Без схемы: user:pass@host:port, host:port:user:pass, user:pass:host:port, host:port. → {host, port, user, pass} */
    private static String[] splitPlain(String s) throws ProxyError {
        if (s.contains("@")) {
            int at = s.lastIndexOf('@');
            String cred = s.substring(0, at);
            String hp = s.substring(at + 1);
            int c = cred.indexOf(':');
            String user = c >= 0 ? cred.substring(0, c) : cred;
            String pw = c >= 0 ? cred.substring(c + 1) : "";
            String host;
            String port;
            if (hp.startsWith("[")) {
                int e = hp.indexOf("]:");
                host = e > 0 ? hp.substring(1, e) : hp.substring(1);
                port = e > 0 ? hp.substring(e + 2) : "";
            } else {
                int k = hp.lastIndexOf(':');
                host = k >= 0 ? hp.substring(0, k) : hp;
                port = k >= 0 ? hp.substring(k + 1) : "";
            }
            return new String[]{host, port, user, pw};
        }
        if (s.startsWith("[")) { // [IPv6]:port[:user:pass]
            int e = s.indexOf("]:");
            if (e < 0) {
                throw new ProxyError(formatError());
            }
            String host = s.substring(1, e);
            String rest = s.substring(e + 2);
            String[] p = rest.split(":", 3);
            return new String[]{host, p[0], p.length > 1 ? p[1] : "", p.length > 2 ? p[2] : ""};
        }
        String[] parts = s.split(":", -1);
        if (parts.length == 2) {
            return new String[]{parts[0], parts[1], "", ""};
        }
        if (parts.length >= 4) {
            if (digits(parts[1])) { // host:port:user:pass (пароль может содержать «:»)
                StringBuilder pw = new StringBuilder(parts[3]);
                for (int i = 4; i < parts.length; i++) {
                    pw.append(':').append(parts[i]);
                }
                return new String[]{parts[0], parts[1], parts[2], pw.toString()};
            }
            if (parts.length == 4 && digits(parts[3])) { // user:pass:host:port
                return new String[]{parts[2], parts[3], parts[0], parts[1]};
            }
        }
        throw new ProxyError(formatError());
    }

    private static String formatError() {
        return Text.t("Не понял формат прокси. Подходит: socks5://логин:пароль@адрес:порт, "
                        + "http://логин:пароль@адрес:порт или адрес:порт:логин:пароль.",
                "Unknown proxy format. Use socks5://login:password@host:port, http://login:password@host:port "
                        + "or host:port:login:password.");
    }

    private static String decode(String s) {
        try {
            return URLDecoder.decode(s.replace("+", "%2B"), "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    /**
     * Строка от продавца прокси → {type, tls, host, port, user, pass, type_known}.
     * kind — тип из списка (auto — по схеме ссылки; без схемы сначала пробуется SOCKS5).
     */
    public static Map<String, Object> parse(String raw, String kind) throws ProxyError {
        String s = raw == null ? "" : raw.trim();
        if (s.isEmpty()) {
            throw new ProxyError(Text.t("Вставь адрес прокси, например socks5://логин:пароль@1.2.3.4:1080.",
                    "Paste a proxy address, for example socks5://login:password@1.2.3.4:1080."));
        }
        if (s.length() > 600 || s.matches("(?s).*[\\s\\x00-\\x1f].*")) {
            throw new ProxyError(Text.t("В адресе прокси не должно быть пробелов и переносов строк.",
                    "The proxy address must not contain spaces or line breaks."));
        }
        String typ = "";
        boolean tls = false;
        String[] hpup;
        Matcher m = SCHEME.matcher(s);
        if (m.find()) {
            String scheme = m.group(1).toLowerCase();
            if (scheme.equals("socks") || scheme.equals("socks5") || scheme.equals("socks5h")) {
                typ = "socks";
            } else if (scheme.equals("http") || scheme.equals("https")) {
                typ = "http";
                tls = scheme.equals("https");
            } else if (scheme.matches("vless|vmess|trojan|ss|hy2|hysteria2|tuic")) {
                throw new ProxyError(Text.t("Это ссылка на VPN-сервер, а не прокси. Добавь её как сервер — "
                                + "потом её можно выбрать в списке «Через сервер».",
                        "This is a VPN server link, not a proxy. Add it as a server — then pick it in “Via server”."));
            } else {
                throw new ProxyError(Text.t("Поддерживаются прокси SOCKS5 и HTTP.", "SOCKS5 and HTTP proxies are supported."));
            }
            String rest = s.substring(m.end());
            for (char c : new char[]{'/', '?', '#'}) {
                int k = rest.indexOf(c);
                if (k >= 0) {
                    rest = rest.substring(0, k);
                }
            }
            int colons = rest.length() - rest.replace(":", "").length();
            if (rest.contains("@") || rest.startsWith("[") || colons <= 1) {
                hpup = splitPlain(rest);
                hpup[2] = decode(hpup[2]);
                hpup[3] = decode(hpup[3]);
            } else { // socks5://host:port:user:pass — так тоже иногда выдают
                hpup = splitPlain(rest);
            }
        } else {
            hpup = splitPlain(s);
        }
        if (hpup[1] == null || hpup[1].isEmpty()) {
            throw new ProxyError(Text.t("В адресе прокси нет порта. Пример: 1.2.3.4:1080.", "The proxy address has no port. Example: 1.2.3.4:1080."));
        }
        if (hpup[2].length() > 200 || hpup[3].length() > 200) {
            throw new ProxyError(Text.t("Слишком длинный логин или пароль.", "The login or password is too long."));
        }
        boolean known = !typ.isEmpty() || "socks".equals(kind) || "http".equals(kind);
        if (typ.isEmpty()) {
            typ = "http".equals(kind) ? "http" : "socks";
        }
        return Json.obj("type", typ, "tls", tls, "host", host(hpup[0]), "port", (long) port(hpup[1]), "user", hpup[2],
                "pass", hpup[3], "type_known", known);
    }

    /** Короткая подпись без логина и пароля: «SOCKS5 1.2.3.4:1080». */
    public static String label(Map<String, Object> p) {
        String kind = Json.bool(p, "tls", false) ? "HTTPS" : "http".equals(Json.str(p, "type")) ? "HTTP" : "SOCKS5";
        String h = Json.str(p, "host");
        return kind + " " + (h.contains(":") ? "[" + h + "]" : h) + ":" + Json.num(p, "port", 0);
    }

    /** Что можно показать в интерфейсе: без логина и пароля. */
    public static Map<String, Object> publicView(Map<String, Object> p) {
        Map<String, Object> check = Json.map(p, "check");
        return Json.obj("id", Json.str(p, "id"), "name", Json.str(p, "name"), "label", label(p),
                "type", Json.str(p, "type", "socks"), "auth", !Json.str(p, "user").isEmpty(),
                "chain", Json.bool(p, "chain", true), "check", check == null ? Json.obj() : Json.copy(check));
    }

    /** Свой прокси как outbound ядра. chain — подключаться к прокси через основной VPN (outbound "proxy"). */
    public static Map<String, Object> outbound(Map<String, Object> p, String tag, boolean chain) {
        Map<String, Object> server = Json.obj("address", Json.str(p, "host"), "port", Json.num(p, "port", 0));
        if (!Json.str(p, "user").isEmpty()) {
            server.put("users", Json.arr(Json.obj("user", Json.str(p, "user"), "pass", Json.str(p, "pass"))));
        }
        boolean http = "http".equals(Json.str(p, "type"));
        Map<String, Object> ob = Json.obj("tag", tag, "protocol", http ? "http" : "socks", "settings",
                Json.obj("servers", Json.arr(server)));
        Map<String, Object> ss = Json.obj();
        if (http && Json.bool(p, "tls", false)) {
            ss.put("security", "tls");
            ss.put("tlsSettings", Json.obj("serverName", Json.str(p, "host")));
        }
        if (chain) {
            ss.put("sockopt", Json.obj("dialerProxy", "proxy"));
        }
        if (!ss.isEmpty()) {
            ob.put("streamSettings", ss);
        }
        return ob;
    }

    /** Проверка своего прокси: вход HTTP → прокси (через основной сервер, если main не null). */
    public static Map<String, Object> testConfig(Map<String, Object> p, int port, Server main, boolean mask, String version) {
        List<Object> outbounds = new ArrayList<Object>();
        outbounds.add(outbound(p, "out", main != null));
        if (main != null) {
            outbounds.addAll(XrayConfig.proxyOutbounds(main, "proxy", mask, version));
        }
        outbounds.add(Json.obj("tag", "direct", "protocol", "freedom"));
        return Json.obj("log", Json.obj("loglevel", "none"),
                "inbounds", Json.arr(Json.obj("tag", "in", "listen", "127.0.0.1", "port", port, "protocol", "http",
                        "settings", Json.obj())),
                "outbounds", outbounds,
                "routing", Json.obj("domainStrategy", "AsIs", "rules", Json.arr(
                        Json.obj("type", "field", "inboundTag", Json.arr("in"), "outboundTag", "out"))));
    }

    /** Ответ Cloudflare trace → {ip, loc}. */
    public static Map<String, Object> parseTrace(String body) {
        String ip = "";
        String loc = "";
        for (String line : body.split("\n")) {
            if (line.startsWith("ip=")) {
                ip = line.substring(3).trim();
            } else if (line.startsWith("loc=")) {
                loc = line.substring(4).trim().toUpperCase();
            }
        }
        return Json.obj("ip", ip, "loc", loc);
    }

    /** Адреса для проверки (в самопроверке — локальные). */
    public static String TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace";
    public static String TIKTOK_URL = "https://www.tiktok.com/";
}
