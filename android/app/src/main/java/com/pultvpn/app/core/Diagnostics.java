package com.pultvpn.app.core;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * «Проверка программы» на телефоне: пункты «ок / предупреждение / ошибка» и текстовый отчёт.
 * В отчёте нет ссылок подписок, ключей, адресов серверов и IP — его можно спокойно отправить нейросети.
 * Сама проверка (порядок шагов) — в Engine.checkFlow(), здесь — пункты, самопроверка логики и очистка текста.
 */
public final class Diagnostics {
    public final List<Map<String, Object>> items = new ArrayList<Map<String, Object>>();

    /** Сайты для проверки напрямую и через VPN. */
    public static String[][] SITES = {
            {"Google", "https://www.google.com/generate_204"},
            {"YouTube", "https://www.youtube.com/"},
            {"Telegram", "https://web.telegram.org/"},
            {"Instagram", "https://www.instagram.com/"},
            {"TikTok", "https://www.tiktok.com/"},
            {"ChatGPT", "https://chatgpt.com/"},
            {"Discord", "https://discord.com/"},
            {"VK", "https://vk.com/"},
            {"Госуслуги", "https://www.gosuslugi.ru/"},
    };

    public void add(String level, String ru, String en, String detail) {
        items.add(Json.obj("level", level, "title", Text.t(ru, en),
                "detail", detail == null ? "" : Text.shorten(detail, 400)));
    }

    public void ok(String ru, String en, String detail) {
        add("ok", ru, en, detail);
    }

    /** Просто сведения: не ошибка и не повод что-то менять. */
    public void info(String ru, String en, String detail) {
        add("info", ru, en, detail);
    }

    public void warn(String ru, String en, String detail) {
        add("warn", ru, en, detail);
    }

    public void error(String ru, String en, String detail) {
        add("error", ru, en, detail);
    }

    /** Кнопка исправления у последнего пункта (battery, notifications, data_saver, vpn). */
    public void fix(String what) {
        if (!items.isEmpty()) {
            items.get(items.size() - 1).put("fix", what);
        }
    }

    public int count(String level) {
        int n = 0;
        for (Map<String, Object> i : items) {
            if (level.equals(Json.str(i, "level"))) {
                n++;
            }
        }
        return n;
    }

    static String msg(Throwable e) {
        return e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
    }

    /** Простейшая проверка ядра: выход в интернет напрямую, без сервера. */
    public static Map<String, Object> directConfig() {
        return Json.obj("log", Json.obj("loglevel", "warning"),
                "outbounds", Json.arr(Json.obj("tag", "direct", "protocol", "freedom")));
    }

    // ---------- самопроверка логики на этом телефоне ----------

    private interface Check {
        void run() throws Exception;
    }

    /**
     * Быстрые проверки того, что приложение правильно разбирает ссылки и подписки, строит правила и настройки ядра
     * и переносит настройки. Ловят отличия Android от обычной Java (так уже было с регулярными выражениями).
     */
    public void selfTest(final Map<String, Object> settings, final String coreVersion, final String appVersion) {
        final String uuid = "11111111-2222-3333-4444-555555555555";
        final String[] links = {
                "vless://" + uuid + "@a.example.com:443?security=reality&sni=www.microsoft.com&fp=chrome"
                        + "&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=6ba85179e30d4fc2&type=tcp"
                        + "&flow=xtls-rprx-vision#%F0%9F%87%B3%F0%9F%87%B1%20VLESS",
                "trojan://secret@c.example.com:443?sni=c.example.com&type=tcp#Trojan",
                "vless://" + uuid + "@b.example.com:443?security=tls&sni=b.example.com&type=ws&path=%2Fws#WS",
        };
        final Map<String, String> failed = new LinkedHashMap<String, String>();
        final int[] passed = {0};
        Map<String, Check> checks = new LinkedHashMap<String, Check>();
        checks.put("ссылки серверов", new Check() {
            @Override
            public void run() {
                for (String l : links) {
                    Server s = Links.parseLink(l);
                    if (s == null || !s.supported) {
                        throw new IllegalStateException("не разобралась: " + l.substring(0, l.indexOf(':')));
                    }
                }
                if (!Links.parseLink(links[0]).name.contains("VLESS")) {
                    throw new IllegalStateException("название сервера разобрано неверно");
                }
            }
        });
        checks.put("подписка", new Check() {
            @Override
            public void run() throws Exception {
                StringBuilder b = new StringBuilder();
                for (String l : links) {
                    b.append(l).append('\n');
                }
                Subscription sub = Subscription.parseBody(Text.b64encode(b.toString().getBytes(StandardCharsets.UTF_8)));
                if (sub.servers.size() != links.length) {
                    throw new IllegalStateException("серверов " + sub.servers.size() + " вместо " + links.length);
                }
            }
        });
        checks.put("правила", new Check() {
            @Override
            public void run() {
                Map<String, Object> s = new HashMap<String, Object>(settings);
                s.put("proxy_list", "example.org\n1.2.3.0/24\ngeosite:youtube");
                List<Object> rules = Routing.buildRules(s, false);
                if (rules.isEmpty() || !Json.write(rules).contains("example.org")) {
                    throw new IllegalStateException("свои правила не попали в настройки");
                }
            }
        });
        checks.put("настройки ядра", new Check() {
            @Override
            public void run() {
                XrayConfig.Options o = new XrayConfig.Options();
                o.coreVersion = coreVersion;
                o.appPort = 30001;
                o.appUser = "u";
                o.appPass = "p";
                String cfg = Json.write(XrayConfig.runConfig(Links.parseLink(links[0]), settings, o));
                Map<String, Object> back = Json.parseObject(cfg);
                String text = Json.write(back);
                if (!text.contains("tun-in") || !text.contains("\"proxy\"") || !text.contains("reality")) {
                    throw new IllegalStateException("в настройках ядра нет туннеля или сервера");
                }
            }
        });
        checks.put("JSON", new Check() {
            @Override
            public void run() {
                String tricky = "Привет \"мир\" \\ / \n\t 🇷🇺 \u0001";
                Map<String, Object> back = Json.parseObject(Json.write(Json.obj("t", tricky)));
                if (!tricky.equals(Json.str(back, "t"))) {
                    throw new IllegalStateException("текст после записи и чтения изменился");
                }
            }
        });
        checks.put("перенос настроек", new Check() {
            @Override
            public void run() {
                String text = Json.write(Share.export(settings, false, false, appVersion));
                Map<String, Object> got = Share.parse(Json.parse(text));
                if (!Json.str(Json.map(got, "settings"), "mode", "vpn").equals(Json.str(settings, "mode", "vpn"))) {
                    throw new IllegalStateException("режим не перенёсся");
                }
            }
        });
        checks.put("белые списки по названию", new Check() {
            @Override
            public void run() {
                if (!Server.WL_NAME.matcher("🇷🇺 Белые списки · Москва").find() || !Server.WL_NAME.matcher("БС Мегафон").find()
                        || Server.WL_NAME.matcher("🇺🇸 Обсерватория").find()) {
                    throw new IllegalStateException("неверно узнаёт серверы для белых списков");
                }
            }
        });
        checks.put("свой сервер", new Check() {
            @Override
            public void run() {
                if (!Vps.script().contains("xray")) {
                    throw new IllegalStateException("пустой скрипт установки");
                }
            }
        });
        for (Map.Entry<String, Check> c : checks.entrySet()) {
            try {
                c.getValue().run();
                passed[0]++;
            } catch (Throwable e) {
                failed.put(c.getKey(), msg(e));
            }
        }
        if (failed.isEmpty()) {
            ok("Самопроверка логики: все " + passed[0] + " проверок пройдены",
                    "Logic self-test: all " + passed[0] + " checks passed", "");
        } else {
            for (Map.Entry<String, String> f : failed.entrySet()) {
                error("Самопроверка логики: " + f.getKey(), "Logic self-test: " + f.getKey(), f.getValue());
            }
        }
    }

    // ---------- отчёт ----------

    private static final Pattern URL = Pattern.compile("(?i)\\b(?:https?|vless|vmess|trojan|ss|hysteria2|hy2|tuic|happ)://\\S+");
    private static final Pattern UUID = Pattern.compile("(?i)\\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b");
    private static final Pattern IPV4 = Pattern.compile("(?<![\\d.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![\\d.])");
    private static final Pattern IPV6 = Pattern.compile("(?i)\\[?(?<![\\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\\w:])\\]?");

    /** Убирает из текста секреты (адреса серверов, пароли), ссылки, UUID и IP-адреса. */
    public static String scrub(String text, Collection<String> secrets) {
        String out = text;
        for (String s : secrets) {
            if (s != null && s.length() >= 4) {
                out = out.replace(s, "<скрыто>");
            }
        }
        out = URL.matcher(out).replaceAll("<ссылка>");
        out = UUID.matcher(out).replaceAll("<ключ>");
        out = IPV4.matcher(out).replaceAll("<адрес>");
        java.util.regex.Matcher m = IPV6.matcher(out);
        StringBuffer b = new StringBuffer();
        while (m.find()) {
            String c = m.group().replace("[", "").replace("]", "");
            int colons = c.length() - c.replace(":", "").length();
            // IPv6: есть «::» или 7 двоеточий; время «20:10:23» не трогаем
            boolean v6 = (c.contains("::") && c.replace(":", "").length() > 0) || colons == 7;
            m.appendReplacement(b, java.util.regex.Matcher.quoteReplacement(v6 ? "<адрес>" : m.group()));
        }
        m.appendTail(b);
        return b.toString();
    }

    public String text(String header, List<String> log, Collection<String> secrets) {
        StringBuilder b = new StringBuilder(header);
        b.append(Text.t("Ошибок: ", "Errors: ")).append(count("error")).append(Text.t(", предупреждений: ", ", warnings: "))
                .append(count("warn")).append("\n\n");
        for (Map<String, Object> i : items) {
            String level = Json.str(i, "level");
            String mark = "ok".equals(level) ? "[OK]" : "info".equals(level) ? "[i]" : "warn".equals(level) ? "[!]"
                    : Text.t("[ОШИБКА]", "[ERROR]");
            b.append(mark).append(' ').append(Json.str(i, "title"));
            if (!Json.str(i, "detail").isEmpty()) {
                b.append(" — ").append(Json.str(i, "detail"));
            }
            b.append('\n');
        }
        b.append('\n').append(Text.t("Журнал (последние строки):", "Log (last lines):")).append('\n');
        int from = Math.max(0, log.size() - 80);
        for (String l : log.subList(from, log.size())) {
            b.append(l).append('\n');
        }
        return scrub(b.toString(), secrets);
    }
}
