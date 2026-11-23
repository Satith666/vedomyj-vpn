package com.pultvpn.app.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Свой протокол VEDOMYJ (1.26, эксперимент) — как pult/dialect.py: шифрование VLESS Encryption ядра Xray,
 * вид трафика — свой «диалект» у каждого сервера (HTTP-приветствие и дальше sudoku «текст» с паддингом).
 * Порядок обращений к генератору случайных чисел тот же, что на ПК, — сверка Dump vproto.
 */
public final class Dialect {
    private Dialect() {
    }

    public static final int[] PROTO_MIN = {26, 10, 21};
    public static final String LABEL = "VEDOMYJ";
    public static final String NAME = "Свой протокол";
    public static final int[] PORTS = {80, 8080, 8880, 2052, 2082, 2086, 2095};

    static final String[] SYL = {"ba", "ve", "do", "mi", "ra", "lo", "ki", "su", "ne", "to", "za", "pe", "ri", "mo", "la",
            "ny", "te", "vi", "go", "sa", "ku", "re", "na", "bo"};
    static final String[] SUB = {"cdn", "static", "img", "media", "api", "files", "assets", "content"};
    static final String[] TLD = {"ru", "net", "com", "io", "su", "org"};
    static final String[] WORDS = {"api", "static", "feed", "media", "assets", "sync", "update", "content", "files", "img",
            "data", "v1", "v2", "v3", "stream", "news", "lib", "events", "chunk", "pkg"};
    static final String[] PARAMS = {"lang", "v", "id", "t", "ref", "page", "s", "rev"};
    static final String[] UA = {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Safari/605.1.15",
            "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36"};
    static final String[] SERVERS = {"nginx", "nginx/1.24.0", "nginx/1.26.3", "openresty", "Apache"};
    static final String[] CTYPES = {"application/octet-stream", "text/plain; charset=utf-8", "application/json",
            "text/html; charset=utf-8"};
    static final String HEX = "0123456789abcdef";

    static final String[][] RX = {
            {"path", "/[a-z0-9/]{1,60}"},
            {"query", "[a-z]{1,8}=[0-9a-f]{1,16}"},
            {"host", "[a-z0-9]{1,12}\\.[a-z]{2,12}\\.[a-z]{2,4}"},
            {"ua", "[A-Za-z0-9 ()/.,;:_-]{10,160}"},
            {"server", "[A-Za-z0-9/._-]{2,24}"},
            {"ctype", "[a-z/+.-]{3,40}(; charset=utf-8)?"},
    };

    /** Случайный диалект сервера (rnd == null — надёжный генератор). */
    public static Map<String, Object> make(Warp.Rnd rnd) {
        final Warp.Rnd r = rnd != null ? rnd : Warp.SECURE;
        StringBuilder word = new StringBuilder();
        int n = 3 + r.next(2); // 3–4 слога: не похоже на настоящие короткие домены
        for (int i = 0; i < n; i++) {
            word.append(SYL[r.next(SYL.length)]);
        }
        StringBuilder path = new StringBuilder();
        n = 1 + r.next(3);
        for (int i = 0; i < n; i++) {
            path.append("/").append(WORDS[r.next(WORDS.length)]);
        }
        StringBuilder query = new StringBuilder(PARAMS[r.next(PARAMS.length)]).append('=');
        n = 4 + r.next(9);
        for (int i = 0; i < n; i++) {
            query.append(HEX.charAt(r.next(HEX.length())));
        }
        int padMin = 1 + r.next(8);
        Map<String, Object> d = new LinkedHashMap<String, Object>();
        d.put("path", path.toString());
        d.put("query", query.toString());
        String sub = SUB[r.next(SUB.length)];
        d.put("host", sub + "." + word + "." + TLD[r.next(TLD.length)]);
        d.put("ua", UA[r.next(UA.length)]);
        d.put("server", SERVERS[r.next(SERVERS.length)]);
        d.put("ctype", CTYPES[r.next(CTYPES.length)]);
        d.put("padMin", (long) padMin);
        d.put("padMax", (long) (padMin + 4 + r.next(15)));
        return d;
    }

    /** Диалект попадает в скрипт сервера и настройки ядра: только известные поля и безопасные знаки. */
    public static Map<String, Object> check(Map<String, Object> d) {
        if (d == null) {
            throw new IllegalArgumentException("dialect");
        }
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        for (String[] kv : RX) {
            Object v = d.get(kv[0]);
            if (!(v instanceof String) || !((String) v).matches(kv[1])) {
                throw new IllegalArgumentException("dialect: " + kv[0]);
            }
            out.put(kv[0], v);
        }
        Object lo = d.get("padMin"), hi = d.get("padMax");
        if (!(lo instanceof Number) || !(hi instanceof Number) || lo instanceof Double || hi instanceof Double) {
            throw new IllegalArgumentException("dialect: padding");
        }
        long a = ((Number) lo).longValue(), b = ((Number) hi).longValue();
        if (a < 0 || a > b || b > 40) {
            throw new IllegalArgumentException("dialect: padding");
        }
        out.put("padMin", a);
        out.put("padMax", b);
        return out;
    }

    public static String request(Map<String, Object> d) {
        return "GET " + d.get("path") + "?" + d.get("query") + " HTTP/1.1\r\nHost: " + d.get("host") + "\r\nUser-Agent: "
                + d.get("ua") + "\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\n\r\n";
    }

    public static String response(Map<String, Object> d) {
        return "HTTP/1.1 200 OK\r\nServer: " + d.get("server") + "\r\nContent-Type: " + d.get("ctype")
                + "\r\nCache-Control: no-store\r\nConnection: keep-alive\r\n\r\n";
    }

    /** Finalmask протокола: внутри — sudoku «текст» с паддингом, снаружи — HTTP-приветствие. */
    public static Map<String, Object> mask(Map<String, Object> dial, String password) {
        Map<String, Object> d = check(dial);
        return Json.obj("tcp", Json.arr(
                Json.obj("type", "sudoku", "settings", Json.obj("password", password, "ascii", "prefer_ascii",
                        "paddingMin", d.get("padMin"), "paddingMax", d.get("padMax"))),
                Json.obj("type", "header-custom", "settings", Json.obj(
                        "clients", Json.arr(Json.arr(Json.obj("delay", 0L, "type", "str", "packet", request(d)))),
                        "servers", Json.arr(Json.arr(Json.obj("delay", 0L, "type", "str", "packet", response(d))))))));
    }

    public static boolean isVprotoSs(Map<String, Object> ss) {
        List<Object> tcp = Json.list(Json.map(ss, "finalmask"), "tcp");
        List<String> types = new ArrayList<String>();
        for (Object x : tcp == null ? new ArrayList<Object>() : tcp) {
            Map<String, Object> m = Json.map(x);
            if (m != null && m.get("type") instanceof String) {
                types.add((String) m.get("type"));
            }
        }
        return types.contains("sudoku") && types.contains("header-custom");
    }

    /** Сервер говорит на своём протоколе (sudoku + HTTP-приветствие поверх голого TCP). */
    public static boolean isVproto(Server s) {
        return s != null && isVprotoSs(Json.map(s.outbound, "streamSettings"));
    }
}
