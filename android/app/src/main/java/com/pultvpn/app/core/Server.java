package com.pultvpn.app.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/** Сервер из подписки или ссылки: готовый outbound для Xray и результаты проверки. */
public final class Server {
    public String name = "";
    public String protocol = "";
    public String address = "";
    public int port;
    public Map<String, Object> outbound = new LinkedHashMap<String, Object>();
    public List<Map<String, Object>> extraOutbounds = new ArrayList<Map<String, Object>>();
    public String link = "";
    public boolean supported = true;
    public String note = "";
    public String source = "link"; // link | json
    public String subId = "";       // "" — добавлен вручную
    public boolean insecure;        // без TLS/Reality: новые ядра Xray такие запрещают
    public boolean stub;            // не сервер, а сообщение провайдера
    public String pinnedIp = "";    // DNS провайдера не знает имя сервера — адрес из защищённого DNS (на ключ не влияет)
    public String engine = "xray";  // xray; awg — AmneziaWG (своё приложение); singbox — TUIC/AnyTLS (только компьютер)
    public String awgConf = "";     // конфиг AmneziaWG (берётся из ссылки awg://, отдельно не хранится)

    // результаты проверки
    public long pingMs = -1;        // -1 — не проверяли или не отвечает
    public boolean ok;
    public boolean mask;            // работает только с маскировкой (дробление TLS)
    public String fp = "";          // отпечаток TLS, который подобрала программа ("" — как в ссылке)
    public boolean whitelist;       // доказано, что работает при «белых списках»
    public String error = "";
    public long testedAt;
    public int fails;               // подряд неудач во время работы

    /** Похоже на сервер для обхода «белых списков» (по названию). */
    public static final Pattern WL_NAME = Pattern.compile(
            "бел\\p{L}*\\s*спис|white\\s*-?\\s*list|(?<![\\p{L}\\p{N}])(?:БС|WL)(?![\\p{L}\\p{N}])",
            Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);

    public String key() {
        String raw = link.isEmpty() ? Json.canonical(outbound) : link;
        return Text.sha1hex(subId + "|" + raw).substring(0, 12);
    }

    public String endpoint() {
        if (address.isEmpty()) {
            return "";
        }
        return (address.contains(":") ? "[" + address + "]" : address) + ":" + port;
    }

    /** Годится для подключения ядром Xray прямо в приложении (AmneziaWG передаётся в своё приложение). */
    public boolean usable() {
        return supported && !stub && !insecure && "xray".equals(engine);
    }

    public boolean isWl() {
        return whitelist || WL_NAME.matcher(name).find();
    }

    /** Оценка: меньше — лучше. null — сервер не годится. */
    public Double score() {
        if (!usable() || !ok || pingMs < 0) {
            return null;
        }
        return (double) pingMs + (mask ? 15.0 : 0.0);
    }

    /** Копия с другим способом подключения (ключ тот же) — чтобы проверить способ, не трогая сам сервер. */
    public Server withWay(String fp, boolean mask) {
        Server c = new Server();
        c.name = name;
        c.protocol = protocol;
        c.address = address;
        c.port = port;
        c.outbound = outbound;
        c.extraOutbounds = extraOutbounds;
        c.link = link;
        c.supported = supported;
        c.note = note;
        c.source = source;
        c.subId = subId;
        c.insecure = insecure;
        c.stub = stub;
        c.pinnedIp = pinnedIp;
        c.engine = engine;
        c.awgConf = awgConf;
        c.pingMs = pingMs;
        c.ok = ok;
        c.whitelist = whitelist;
        c.fp = fp == null ? "" : fp;
        c.mask = mask;
        return c;
    }

    // ---------- хранение ----------

    public Map<String, Object> toJson() {
        Map<String, Object> m = Json.obj("name", name, "protocol", protocol, "address", address, "port", port,
                "outbound", outbound, "link", link, "supported", supported, "note", note, "source", source,
                "sub", subId, "insecure", insecure, "stub", stub,
                "ping", pingMs, "ok", ok, "mask", mask, "wl", whitelist, "error", error, "tested", testedAt);
        if (!fp.isEmpty()) {
            m.put("fp", fp);
        }
        if (!extraOutbounds.isEmpty()) {
            m.put("extra", extraOutbounds);
        }
        return m;
    }

    @SuppressWarnings("unchecked")
    public static Server fromJson(Map<String, Object> m) {
        Server s = new Server();
        s.name = Json.str(m, "name");
        s.protocol = Json.str(m, "protocol");
        s.address = Json.str(m, "address");
        s.port = (int) Json.num(m, "port", 0);
        Map<String, Object> ob = Json.map(m, "outbound");
        s.outbound = ob != null ? ob : new LinkedHashMap<String, Object>();
        List<Object> extra = Json.list(m, "extra");
        if (extra != null) {
            for (Object o : extra) {
                if (o instanceof Map) {
                    s.extraOutbounds.add((Map<String, Object>) o);
                }
            }
        }
        s.link = Json.str(m, "link");
        s.supported = Json.bool(m, "supported", true);
        s.note = Json.str(m, "note");
        s.source = Json.str(m, "source", "link");
        s.subId = Json.str(m, "sub");
        s.insecure = Json.bool(m, "insecure", false);
        s.stub = Json.bool(m, "stub", false);
        s.pingMs = Json.num(m, "ping", -1);
        s.ok = Json.bool(m, "ok", false);
        s.mask = Json.bool(m, "mask", false);
        s.fp = Json.str(m, "fp");
        s.whitelist = Json.bool(m, "wl", false);
        s.error = Json.str(m, "error");
        s.testedAt = Json.num(m, "tested", 0);
        if ("amneziawg".equals(s.protocol)) {
            s.engine = "awg";  // ключ AmneziaWG — только в ссылке awg:// (её же хранят свои серверы)
            try {
                s.awgConf = Links.awgConfOf(s.link);
            } catch (Links.LinkError e) {
                s.supported = false;
                s.note = e.getMessage();
            }
        } else if ("tuic".equals(s.protocol) || "anytls".equals(s.protocol)) {
            s.engine = "singbox";
        }
        return s;
    }
}
