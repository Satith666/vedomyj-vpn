package com.pultvpn.app.core;

import java.io.IOException;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Загрузка и разбор подписки. Как subscription.py. */
public final class Subscription {
    public static final String[] USER_AGENTS = {"v2rayNG/1.10.5", "Happ/2.0.0", "v2rayN/7.13.8", "Streisand/1.6.40",
            "v2rayTun/2.5"};
    static final String[] SERVER_SCHEMES = {"vless://", "vmess://", "trojan://", "ss://", "socks://", "socks5://",
            "hy2://", "hysteria2://", "tuic://", "anytls://", "wireguard://", "awg://", "vpn://", "xrayjson://"};
    static final Pattern LINK_RE = Pattern.compile(
            "(?:vless|vmess|trojan|ss|socks5?|hy2|hysteria2|tuic|anytls)://[^\\s\"'<>`]+", Pattern.CASE_INSENSITIVE);

    public static final class SubError extends Exception {
        public SubError(String msg) {
            super(msg);
        }
    }

    public List<Server> servers = new ArrayList<Server>();
    public String title = "";
    public long upload = -1;
    public long download = -1;
    public long total = -1;
    public long expire = -1;
    public long fetchedAt;
    public String raw = "";
    public String userAgent = "";
    public String route = "";
    public List<String> warnings = new ArrayList<String>();

    public Map<String, Object> usage() {
        return Json.obj("upload", upload, "download", download, "total", total, "expire", expire);
    }

    public static String usageText(Map<String, Object> u) {
        List<String> parts = new ArrayList<String>();
        long up = Json.num(u, "upload", -1);
        long down = Json.num(u, "download", -1);
        long total = Json.num(u, "total", -1);
        long expire = Json.num(u, "expire", -1);
        if (up >= 0 || down >= 0) {
            long used = Math.max(up, 0) + Math.max(down, 0);
            parts.add(total > 0 ? Text.t("трафик: " + human(used) + " из " + human(total),
                    "traffic: " + human(used) + " of " + human(total)) : Text.t("трафик: ", "traffic: ") + human(used));
        }
        if (expire > 0) {
            long days = Math.max(0, (expire - System.currentTimeMillis() / 1000) / 86400);
            String date = new SimpleDateFormat("dd.MM.yyyy", Locale.US).format(new Date(expire * 1000));
            parts.add(Text.t("до " + date + " (осталось " + days + " дн.)", "until " + date + " (" + days + " days left)"));
        }
        return String.join(", ", parts);
    }

    public static String human(double n) {
        String[] units = "en".equals(Text.lang) ? new String[]{"B", "KB", "MB", "GB", "TB"}
                : new String[]{"Б", "КБ", "МБ", "ГБ", "ТБ"};
        for (int i = 0; i < units.length; i++) {
            if (Math.abs(n) < 1024 || i == units.length - 1) {
                return i == 0 ? ((long) n) + " " + units[i] : String.format(Locale.US, "%.1f %s", n, units[i]);
            }
            n /= 1024;
        }
        return "";
    }

    private void parseUserinfo(String value) {
        for (String part : value.split(";")) {
            int eq = part.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String k = part.substring(0, eq).trim().toLowerCase();
            long num;
            try {
                num = (long) Double.parseDouble(part.substring(eq + 1).trim());
            } catch (NumberFormatException e) {
                continue;
            }
            if (k.equals("upload")) {
                upload = num;
            } else if (k.equals("download")) {
                download = num;
            } else if (k.equals("total")) {
                total = num;
            } else if (k.equals("expire")) {
                expire = num > 0 ? num : -1;
            }
        }
    }

    static String decodeTitle(String value) {
        String v = value.trim();
        if (v.toLowerCase().startsWith("base64:")) {
            String t = Text.b64text(v.substring(7));
            return t == null ? "" : t;
        }
        return v;
    }

    // ---------- что вставил человек ----------

    public static boolean looksLikeServerLink(String text) {
        String low = text.trim().toLowerCase();
        for (String s : SERVER_SCHEMES) {
            if (low.startsWith(s)) {
                return true;
            }
        }
        return false;
    }

    /** Достаёт адрес подписки из того, что вставил человек: https://…, happ://add/…, v2rayng://install-sub?url=… */
    public static String normalizeUrl(String raw) throws SubError {
        String s = raw == null ? "" : raw.trim();
        while (!s.isEmpty() && "\"'<> \t\r\n".indexOf(s.charAt(0)) >= 0) {
            s = s.substring(1);
        }
        while (!s.isEmpty() && "\"'<> \t\r\n".indexOf(s.charAt(s.length() - 1)) >= 0) {
            s = s.substring(0, s.length() - 1);
        }
        String low = s.toLowerCase();
        if (s.isEmpty()) {
            throw new SubError(Text.t("Вставь ссылку на подписку.", "Paste a subscription link."));
        }
        if (low.startsWith("happ://crypt")) {
            throw new SubError(Text.t(
                    "Это зашифрованная ссылка Happ: открыть её может только сам Happ. Попроси у провайдера обычную ссылку "
                            + "на подписку, которая начинается с https:// — обычно она есть в личном кабинете или в боте.",
                    "This is an encrypted Happ link: only Happ can open it. Ask your provider for a regular subscription "
                            + "link starting with https:// — it is usually in the account page or the bot."));
        }
        if (looksLikeServerLink(s)) {
            throw new SubError(Text.t("Это ссылка на один сервер, а не на подписку. Добавь её кнопкой «Добавить сервер».",
                    "This is a link to a single server, not a subscription. Use \"Add server\"."));
        }
        Matcher m = Pattern.compile("https?://[^\\s\"'<>]+", Pattern.CASE_INSENSITIVE).matcher(s);
        if (m.find()) {
            return m.group();
        }
        m = Pattern.compile("https?%3a%2f%2f[^\\s\"'<>&]+", Pattern.CASE_INSENSITIVE).matcher(s);
        if (m.find()) {
            return Text.unquote(m.group());
        }
        String tail = s.substring(s.lastIndexOf('/') + 1);
        tail = tail.split("#", 2)[0].split("\\?", 2)[0];
        String decoded = tail.length() > 12 ? Text.b64text(tail) : null;
        if (decoded != null && decoded.trim().toLowerCase().matches("https?://.*")) {
            return decoded.trim();
        }
        throw new SubError(Text.t("Не похоже на ссылку подписки: она должна начинаться с https://.",
                "This doesn't look like a subscription link: it should start with https://."));
    }

    // ---------- разбор ответа ----------

    public static Subscription parseBody(String text) {
        Subscription sub = new Subscription();
        String stripped = text.trim();
        if (stripped.startsWith("﻿")) {
            stripped = stripped.substring(1);
        }
        sub.raw = stripped;
        if (stripped.startsWith("[") || stripped.startsWith("{")) {
            try {
                sub.servers = Links.serversFromJson(Json.parse(stripped));
                return sub;
            } catch (IllegalArgumentException ignored) {
                // не JSON — читаем как текст
            }
        }
        if (!stripped.contains("://")) {
            String decoded = Text.b64text(stripped);
            if (decoded != null && !decoded.trim().isEmpty()) {
                stripped = decoded.trim();
                sub.raw = stripped;
                if (stripped.startsWith("[") || stripped.startsWith("{")) {
                    try {
                        sub.servers = Links.serversFromJson(Json.parse(stripped));
                        return sub;
                    } catch (IllegalArgumentException ignored) {
                        // дальше — построчно
                    }
                }
            }
        }
        for (String line : stripped.split("\\r?\\n")) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            Server s = Links.parseLink(line);
            if (s != null) {
                sub.servers.add(s);
            }
        }
        if (sub.servers.isEmpty()) {
            // ссылки могут быть внутри HTML-страницы или текста с мусором
            Set<String> seen = new LinkedHashSet<String>();
            Matcher m = LINK_RE.matcher(stripped.replace("&amp;", "&"));
            while (m.find()) {
                String link = m.group().replaceAll("[.,;)]+$", "");
                if (seen.add(link)) {
                    Server s = Links.parseLink(link);
                    if (s != null) {
                        sub.servers.add(s);
                    }
                }
            }
        }
        return sub;
    }

    /** Короткое описание ответа, в котором не нашлось рабочих серверов. */
    static String describe(String text, Subscription sub) {
        String t = text.trim();
        String low = t.substring(0, Math.min(400, t.length())).toLowerCase();
        if (!sub.servers.isEmpty()) {
            List<String> stubs = new ArrayList<String>();
            boolean happ = false;
            boolean insecure = false;
            Set<String> protos = new LinkedHashSet<String>();
            for (Server s : sub.servers) {
                if (s.stub) {
                    stubs.add(s.name);
                }
                happ |= "happ".equals(s.protocol);
                insecure |= s.insecure;
                protos.add(s.protocol);
            }
            if (!stubs.isEmpty() && stubs.size() == sub.servers.size()) {
                return Text.t("вместо серверов пришло сообщение провайдера: «", "the provider sent a message instead of servers: \"")
                        + String.join(Text.t("», «", "\", \""), stubs.subList(0, Math.min(3, stubs.size())))
                        + Text.t("»", "\"");
            }
            if (happ) {
                return Text.t("ссылки на серверы зашифрованы только для Happ", "server links are encrypted for Happ only");
            }
            if (insecure) {
                return Text.t("серверы без шифрования (без TLS/Reality)", "servers without encryption (no TLS/Reality)");
            }
            return Text.t("серверы есть, но не поддерживаются: ", "there are servers, but they are not supported: ")
                    + String.join(", ", protos);
        }
        if (t.isEmpty()) {
            return Text.t("пустой ответ", "empty answer");
        }
        if (low.startsWith("<")) {
            String page = (t.length() > 20000 ? t.substring(0, 20000) : t).toLowerCase();
            for (String m : BLOCK_PAGE_MARKS) {
                if (page.contains(m)) {
                    return blockPageNote();
                }
            }
            return Text.t("пришла веб-страница вместо списка серверов", "a web page came instead of a server list");
        }
        if (low.contains("proxies:") || low.contains("proxy-groups:")) {
            return Text.t("формат Clash (YAML) — не подходит", "Clash (YAML) format — not suitable");
        }
        if ((t.startsWith("{") || t.startsWith("[")) && t.contains("\"outbounds\"") && t.contains("\"type\"")) {
            return Text.t("формат sing-box — не подходит", "sing-box format — not suitable");
        }
        return Text.t("непонятный формат ответа", "unknown answer format");
    }

    static String hwidNote(Map<String, String> headers) {
        if ("true".equalsIgnoreCase(headers.get("x-hwid-max-devices-reached"))
                || "true".equalsIgnoreCase(headers.get("x-hwid-limit"))) {
            return Text.t("достигнут лимит устройств в подписке — удали лишнее устройство в боте или личном кабинете "
                            + "провайдера и обнови подписку",
                    "the subscription device limit is reached — remove a device in the provider's bot or account and refresh");
        }
        if ("true".equalsIgnoreCase(headers.get("x-hwid-not-supported"))) {
            return Text.t("провайдер требует идентификатор устройства", "the provider requires a device ID");
        }
        return "";
    }

    /** Заголовки устройства, как у Happ и v2RayTun: многие панели без них отдают заглушку. */
    public static Map<String, String> deviceHeaders(String hwid, String osVersion) {
        Map<String, String> h = new LinkedHashMap<String, String>();
        if (hwid == null || hwid.isEmpty()) {
            return h;
        }
        h.put("x-hwid", hwid);
        h.put("x-device-os", "Android");
        h.put("x-ver-os", osVersion == null || osVersion.isEmpty() ? "14" : osVersion);
        h.put("x-device-model", "VedomyjVPN");
        return h;
    }

    /** Скачать подписку через другие серверы (временное ядро): для каждого сервера вызвать attempt.tryPort. */
    public interface Relay {
        Subscription run(Attempt attempt);
    }

    public interface Attempt {
        /** Подписка с серверами или null. */
        Subscription tryPort(String routeName, int port);
    }

    /** Заголовки, которые ставит панель подписки (Remnawave, Marzban, 3x-ui…): ответ точно от провайдера VPN. */
    static final String[] PROVIDER_HEADERS = {"subscription-userinfo", "profile-title", "profile-update-interval",
            "profile-web-page-url", "support-url", "announce", "x-hwid-limit", "x-hwid-max-devices-reached",
            "x-hwid-not-supported"};
    /** Признаки страницы-заглушки провайдера интернета («доступ ограничен по решению…»). */
    static final String[] BLOCK_PAGE_MARKS = {"роскомнадзор", "rkn.gov.ru", "eais.rkn", "warning.rt.ru", "доступ ограничен",
            "доступ к ресурсу ограничен", "ресурс заблокирован", "сайт заблокирован", "единый реестр", "blocked by", "blocklist"};

    static String blockPageNote() {
        return Text.t("провайдер интернета показал страницу блокировки", "the internet provider showed a block page");
    }

    public static String routeDoh() {
        return Text.t("напрямую через защищённый DNS", "direct via secure DNS");
    }

    public static String blockedHint() {
        return Text.t("Похоже, провайдер интернета блокирует адрес подписки. Если не поможет и VPN — попроси у провайдера VPN "
                        + "запасную ссылку (зеркало) и добавь её.",
                "Looks like your internet provider blocks the subscription address. If the VPN doesn't help either, ask your "
                        + "VPN provider for a backup link (mirror) and add it.");
    }

    /** Скачивает подписку, перебирая способы и User-Agent, пока не найдёт нормальные серверы.
     *  vpnPort — HTTP-вход ядра, если VPN уже включён (0 — нет). */
    public static Subscription fetch(String rawUrl, String userAgent, int vpnPort, Map<String, String> device,
                                     int timeoutMs) throws SubError {
        return fetch(rawUrl, userAgent, vpnPort, device, timeoutMs, null);
    }

    /** Способы по очереди: напрямую; если DNS провайдера не знает адрес — по адресу из защищённого DNS; через VPN;
     *  relay — через другие серверы. */
    public static Subscription fetch(String rawUrl, String userAgent, int vpnPort, final Map<String, String> device,
                                     final int timeoutMs, Relay relay) throws SubError {
        final String url = normalizeUrl(rawUrl);
        final String host;
        try {
            host = new URL(url).getHost();
        } catch (IOException e) {
            throw new SubError(Text.t("Неверная ссылка подписки.", "Invalid subscription link."));
        }
        final List<String> agents = new ArrayList<String>();
        if (userAgent != null && !userAgent.isEmpty()) {
            agents.add(userAgent);
        }
        for (String ua : USER_AGENTS) {
            if (!agents.contains(ua)) {
                agents.add(ua);
            }
        }
        final List<String> notes = new ArrayList<String>();
        final Fetch f = new Fetch(url, agents, device, notes);
        String direct = Text.t("напрямую", "direct");
        Subscription sub = f.attempt(direct, 0, null, null, timeoutMs);
        if (sub != null) {
            return sub;
        }
        List<String> doh = new ArrayList<String>();
        if (f.dnsFailed && !f.answered) {
            // DNS провайдера не знает адрес (часто так блокируют) — спрашиваем защищённый DNS и идём по адресу
            doh = Http.dohResolve(host, 6000);
            if (!doh.isEmpty()) {
                sub = f.attempt(routeDoh(), 0, host, doh.get(0), Math.min(timeoutMs, 12000));
                if (sub != null) {
                    return sub;
                }
            } else {
                notes.add(Text.t("защищённый DNS: адрес тоже не найден", "secure DNS: address not found either"));
            }
        }
        if (!f.answered && vpnPort > 0) {
            sub = f.attempt(Text.t("через VPN", "via VPN"), vpnPort, null, null, timeoutMs);
            if (sub != null) {
                return sub;
            }
        }
        if (!f.answered && relay != null) {
            sub = relay.run(new Attempt() {
                @Override
                public Subscription tryPort(String routeName, int port) {
                    return f.attempt(routeName, port, null, null, Math.min(timeoutMs, 15000));
                }
            });
            if (sub != null) {
                return sub;
            }
        }
        if (f.best != null && !f.best.servers.isEmpty()) {
            f.best.warnings.add(Text.t("В подписке нет серверов, которые работают на телефоне: ",
                    "The subscription has no servers that work on the phone: ") + describe(f.best.raw, f.best) + ".");
            return f.best;
        }
        List<String> unique = new ArrayList<String>(new LinkedHashSet<String>(notes));
        StringBuilder b = new StringBuilder(Text.t("Не удалось получить серверы с ", "Could not get servers from ") + host + ".");
        for (int i = 0; i < Math.min(8, unique.size()); i++) {
            b.append("\n• ").append(unique.get(i));
        }
        boolean blockPage = false;
        for (String n : unique) {
            blockPage |= n.contains(blockPageNote());
        }
        if (((f.dnsFailed && !doh.isEmpty()) || blockPage) && !f.answered) {
            b.append("\n").append(blockedHint());
        }
        throw new SubError(b.toString());
    }

    /** Одна попытка одним способом (все User-Agent). */
    private static final class Fetch {
        final String url;
        final List<String> agents;
        final Map<String, String> device;
        final List<String> notes;
        boolean answered;
        boolean dnsFailed;
        Subscription best;
        int[] bestQ = {-1, -1, -1};

        Fetch(String url, List<String> agents, Map<String, String> device, List<String> notes) {
            this.url = url;
            this.agents = agents;
            this.device = device;
            this.notes = notes;
        }

        synchronized Subscription attempt(String routeName, int port, String pinHost, String pinIp, int timeoutMs) {
            for (String ua : agents) {
                String label = ua.split("/")[0];
                Http.Response r;
                Map<String, String> headers = new LinkedHashMap<String, String>(device);
                headers.put("User-Agent", ua);
                headers.put("Accept", "*/*");
                try {
                    r = pinIp != null ? Http.getPinned(url, headers, timeoutMs, pinHost, pinIp)
                            : Http.get(url, headers, timeoutMs, port);
                } catch (IOException e) {
                    if (port == 0 && pinIp == null && e instanceof java.net.UnknownHostException) {
                        dnsFailed = true;
                    }
                    notes.add(routeName + ": " + Http.human(e));
                    return null; // сеть не пускает — другие User-Agent тут не помогут
                }
                String hw = hwidNote(r.headers);
                boolean provider = false;
                for (String ph : PROVIDER_HEADERS) {
                    provider |= r.headers.containsKey(ph);
                }
                if (r.status >= 400) {
                    // ответ с заголовками подписки — это сам провайдер; без них — может быть провайдер интернета
                    // или запрет для страны: тогда пробуем другие пути
                    answered |= provider;
                    notes.add(routeName + ", " + Text.t("как ", "as ") + label + ": "
                            + Text.t("сервер ответил кодом ", "server answered with code ") + r.status
                            + (hw.isEmpty() ? "" : " (" + hw + ")"));
                    continue;
                }
                String text = r.text();
                Subscription sub = parseBody(text);
                // страница блокировки провайдера интернета или чужая страница — не ответ подписки, ищем дальше
                answered |= provider || !sub.servers.isEmpty();
                if (r.headers.containsKey("subscription-userinfo")) {
                    sub.parseUserinfo(r.headers.get("subscription-userinfo"));
                }
                if (r.headers.containsKey("profile-title")) {
                    sub.title = decodeTitle(r.headers.get("profile-title"));
                }
                sub.fetchedAt = System.currentTimeMillis();
                sub.userAgent = ua;
                sub.route = routeName;
                if (!hw.isEmpty()) {
                    sub.warnings.add(Text.t("Провайдер: ", "Provider: ") + hw + ".");
                }
                int good = 0;
                int usable = 0;
                for (Server s : sub.servers) {
                    if (s.usable()) {
                        good++;
                    }
                    if (s.supported) {
                        usable++;
                    }
                }
                if (good > 0) {
                    return sub;
                }
                notes.add(routeName + ", " + Text.t("как ", "as ") + label + ": " + describe(text, sub)
                        + (hw.isEmpty() ? "" : " (" + hw + ")"));
                int[] q = {good, usable, sub.servers.size()};
                if (compare(q, bestQ) > 0) {
                    best = sub;
                    bestQ = q;
                }
            }
            return null;
        }
    }

    private static int compare(int[] a, int[] b) {
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return a[i] > b[i] ? 1 : -1;
            }
        }
        return 0;
    }
}
