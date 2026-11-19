package com.pultvpn.app.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Обход замедлений YouTube и Discord без VPN и без root. zapret на Android без root не работает, поэтому
 * сайты идут напрямую через ядро Xray, которое «дробит» начало защищённого соединения на мелкие кусочки с паузами
 * (тот же приём, что у ByeDPI): оборудование провайдера не узнаёт по нему сайт и не замедляет его.
 * Разные провайдеры ловят по-разному, поэтому есть несколько способов — программа сама подбирает рабочий.
 */
public final class Dpi {
    private Dpi() {
    }

    public static final class Strategy {
        public final String id;
        public final String ru;
        public final String en;
        final String packets;
        final String length;
        final String interval;

        Strategy(String id, String ru, String en, String packets, String length, String interval) {
            this.id = id;
            this.ru = ru;
            this.en = en;
            this.packets = packets;
            this.length = length;
            this.interval = interval;
        }

        public String title() {
            return Text.t(ru, en);
        }
    }

    public static final List<Strategy> STRATEGIES = Collections.unmodifiableList(Arrays.asList(
            new Strategy("tls_100", "Дробление приветствия TLS", "TLS hello fragments", "tlshello", "100-200", "10-20"),
            new Strategy("tls_10", "Мелкое дробление TLS", "Small TLS fragments", "tlshello", "10-30", "5-10"),
            new Strategy("tls_1", "Очень мелкое дробление TLS", "Tiny TLS fragments", "tlshello", "1-5", "1-3"),
            new Strategy("tls_slow", "Дробление TLS с паузами", "TLS fragments with pauses", "tlshello", "50-100", "30-50"),
            new Strategy("first_1", "Дробление первого пакета", "First packet fragments", "1-1", "1-3", "1-2"),
            new Strategy("first_3", "Дробление первых пакетов", "First packets fragments", "1-3", "5-10", "5-10")));

    public static final String OUTBOUND = "dpi";

    public static Strategy find(String id) {
        for (Strategy s : STRATEGIES) {
            if (s.id.equals(id)) {
                return s;
            }
        }
        return null;
    }

    /** Выход «напрямую с дроблением». С новых версий ядра дробление задаётся в finalmask. */
    public static Map<String, Object> outbound(Strategy s, String tag, String coreVersion) {
        Map<String, Object> ob = Json.obj("tag", tag, "protocol", "freedom");
        if (XrayConfig.atLeast(XrayConfig.version(coreVersion), XrayConfig.FINALMASK_MIN)) {
            ob.put("settings", Json.obj());
            ob.put("streamSettings", Json.obj("sockopt", Json.obj("TcpNoDelay", true), "finalmask",
                    Json.obj("tcp", Json.arr(Json.obj("type", "fragment", "settings", Json.obj("packets", s.packets,
                            "lengths", Json.arr(s.length), "delays", Json.arr(s.interval)))))));
        } else {
            ob.put("settings", Json.obj("fragment", Json.obj("packets", s.packets, "length", s.length, "interval", s.interval)));
            ob.put("streamSettings", Json.obj("sockopt", Json.obj("TcpNoDelay", true)));
        }
        return ob;
    }

    /** Временное ядро для проверки: вход HTTP 127.0.0.1:port → этот выход. */
    public static Map<String, Object> testConfig(Map<String, Object> out, int port) {
        Map<String, Object> ob = Json.copy(out);
        ob.put("tag", "out");
        return Json.obj("log", Json.obj("loglevel", "none"),
                "inbounds", Json.arr(Json.obj("tag", "in", "listen", "127.0.0.1", "port", port, "protocol", "http",
                        "settings", Json.obj())),
                "outbounds", Json.arr(ob),
                "routing", Json.obj("domainStrategy", "AsIs", "rules", Json.arr(
                        Json.obj("type", "field", "inboundTag", Json.arr("in"), "outboundTag", "out"))));
    }

    /**
     * Что проверяем: адрес и сколько байт нужно скачать. Замедление видно по тому, что страница качается медленно
     * или обрывается; блокировка — по обрыву соединения. В самопроверке подменяется на локальные адреса.
     */
    public static Map<String, String[][]> CHECKS = checks();

    private static Map<String, String[][]> checks() {
        Map<String, String[][]> m = new LinkedHashMap<String, String[][]>();
        m.put("youtube", new String[][]{{"https://www.youtube.com/", "300000"}, {"https://redirector.googlevideo.com/report_mapping", "1"}});
        m.put("discord", new String[][]{{"https://discord.com/api/v9/experiments", "1"}, {"https://gateway.discord.gg/", "0"}});
        return m;
    }

    /** Медленнее этого (кбит/с) большая страница — «замедлено». */
    public static final long MIN_KBPS = 1500;

    /** Открываются ли сервисы через вход 127.0.0.1:proxyPort: {"youtube": {ok, kbps, detail}, …}. */
    public static Map<String, Object> check(int proxyPort, List<String> targets, int timeoutMs) {
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        for (String t : targets) {
            String[][] list = CHECKS.get(t);
            if (list == null) {
                continue;
            }
            boolean ok = true;
            long kbps = -1;
            String detail = "";
            for (String[] c : list) {
                int need = Integer.parseInt(c[1]);
                try {
                    Http.Response r = Http.probe(c[0], null, timeoutMs, proxyPort, Math.max(need, 1));
                    if (r.status <= 0) {
                        ok = false;
                        detail = Text.t("нет ответа", "no answer");
                    } else if (need > 1000) {
                        long got = r.body.length;
                        long speed = r.ms > 0 ? got * 8 / r.ms : got * 8; // кбит/с
                        kbps = speed;
                        if (got < Math.min(need, 50000)) {
                            ok = false;
                            detail = Text.t("страница не докачалась", "the page did not finish loading");
                        } else if (speed < MIN_KBPS) {
                            ok = false;
                            detail = Text.t("замедлено: ", "throttled: ") + speed + Text.t(" кбит/с", " kbit/s");
                        }
                    }
                } catch (Exception e) {
                    ok = false;
                    detail = Http.human(e);
                }
                if (!ok) {
                    break;
                }
            }
            out.put(t, Json.obj("ok", ok, "kbps", kbps, "detail", detail));
        }
        return out;
    }

    public static boolean allOk(Map<String, Object> res) {
        if (res == null || res.isEmpty()) {
            return false;
        }
        for (Object v : res.values()) {
            if (!Json.bool(Json.map(v), "ok", false)) {
                return false;
            }
        }
        return true;
    }

    /** Что проверять: YouTube и/или Discord по настройкам (хотя бы YouTube). */
    public static List<String> targets(Map<String, Object> settings) {
        List<String> t = new ArrayList<String>();
        if (Json.bool(settings, "dpi_youtube", true)) {
            t.add("youtube");
        }
        if (Json.bool(settings, "dpi_discord", true)) {
            t.add("discord");
        }
        if (t.isEmpty()) {
            t.add("youtube");
        }
        return t;
    }

    /** Адреса, которые идут напрямую с обходом замедления (YouTube, Discord и свои). */
    public static List<String> domains(Map<String, Object> settings) {
        Set<String> out = new LinkedHashSet<String>();
        if (Json.bool(settings, "dpi_youtube", true)) {
            out.addAll(Services.YOUTUBE_DOMAINS);
        }
        if (Json.bool(settings, "dpi_discord", true)) {
            out.addAll(Services.DISCORD_DOMAINS);
        }
        List<List<String>> own = Routing.splitEntries(Json.str(settings, "dpi_custom"));
        for (String d : own.get(0)) {
            if (d.startsWith("domain:")) {
                out.add(d.substring(7));
            }
        }
        return new ArrayList<String>(out);
    }
}
