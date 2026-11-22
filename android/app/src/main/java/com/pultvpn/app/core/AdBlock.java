package com.pultvpn.app.core;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Блокировка рекламы: списки фильтров, свои сайты, исключения и сборка файла для ядра. Как adblock.py.
 * Списки скачиваются в files/adblock/, собираются в files/assets/adblock.dat (формат geosite) и подключаются
 * правилом «ext:adblock.dat:ads». Блокировка — по адресам сайтов (как у AdGuard DNS и Blokada): реклама с того же
 * адреса, что и сам сайт (YouTube, VK Видео), так не убирается.
 */
public final class AdBlock {
    private AdBlock() {
    }

    public static final String TAG = "ads";
    public static final String DAT = "adblock.dat";
    public static final String RULE = "ext:" + DAT + ":" + TAG;
    public static final String OUTBOUND = "adblock"; // отдельный «чёрный ящик», чтобы в журнале отличать рекламу

    static final String[] HAGEZI = {"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/%s-onlydomains.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/%s-onlydomains.txt"};
    static final String[] ADGUARD_RU = {"https://filters.adtidy.org/extension/ublock/filters/1.txt",
            "https://filters.adtidy.org/windows/filters/1.txt"};

    /** Сила основного списка: HaGeZi Light / Normal / Pro / Pro++. */
    public static final Map<String, String> LEVELS = levels();
    public static final String DEFAULT_LEVEL = "normal";
    /** Дополнительные списки: всплывающие окна, мошенничество, российские рекламные сети и списки «Монстра»
     *  (как adblock.py: EasyList, uBlock, RU AdList, EasyPrivacy, Peter Lowe, URLhaus). */
    public static final List<String> EXTRA = Collections.unmodifiableList(Arrays.asList("popups", "threats", "ru",
            "easylist", "ubo", "ruadlist", "easyprivacy", "ubo_privacy", "pgl", "ru_counters", "urlhaus", "ubo_badware"));
    /** Группы «Монстра»: одна галочка — несколько списков. */
    public static final Map<String, List<String>> GROUPS = groups();
    /** Галочки в окне и их значения по умолчанию (новые списки работают сразу). */
    public static final List<String> TOGGLES = Collections.unmodifiableList(Arrays.asList("popups", "threats", "ru",
            "m_ads", "m_privacy", "m_malware"));
    static final List<String> THREATS = Arrays.asList("threats", "urlhaus", "ubo_badware", "m_malware");

    static final String[] UBO = {"https://ublockorigin.github.io/uAssetsCDN/%s", "https://ublockorigin.pages.dev/%s",
            "https://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/%s", "https://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/%s"};
    static final String[] RUAD = {"https://raw.githubusercontent.com/easylist/ruadlist/master/%s",
            "https://cdn.jsdelivr.net/gh/easylist/ruadlist@master/%s"};

    private static Map<String, List<String>> groups() {
        Map<String, List<String>> m = new LinkedHashMap<String, List<String>>();
        m.put("m_ads", Arrays.asList("easylist", "ubo", "ruadlist"));
        m.put("m_privacy", Arrays.asList("easyprivacy", "ubo_privacy", "pgl", "ru_counters"));
        m.put("m_malware", Arrays.asList("urlhaus", "ubo_badware"));
        return Collections.unmodifiableMap(m);
    }

    static boolean grouped(String id) {
        for (List<String> ids : GROUPS.values()) {
            if (ids.contains(id)) {
                return true;
            }
        }
        return false;
    }

    /** Включена ли галочка (ключа нет — по умолчанию: всё, кроме слежки Windows, включено). */
    public static boolean listOn(Map<String, Object> lists, String key) {
        Object v = lists == null ? null : lists.get(key);
        return v instanceof Boolean ? (Boolean) v : TOGGLES.contains(key);
    }

    /** Какие списки качать и собирать: основной, отдельные и списки включённых групп. */
    public static List<String> listIds(Map<String, Object> lists) {
        List<String> out = new ArrayList<String>();
        out.add("main");
        for (String k : EXTRA) {
            if (!grouped(k) && listOn(lists, k)) {
                out.add(k);
            }
        }
        for (Map.Entry<String, List<String>> g : GROUPS.entrySet()) {
            if (listOn(lists, g.getKey())) {
                out.addAll(g.getValue());
            }
        }
        return out;
    }

    /** Адрес только в списках опасных сайтов — сам не разрешаем. */
    public static boolean onlyThreats(List<String> ids) {
        if (ids.isEmpty()) {
            return false;
        }
        for (String i : ids) {
            if (!THREATS.contains(i)) {
                return false;
            }
        }
        return true;
    }

    private static List<String> mirrors(String[] bases, String path, String official) {
        List<String> out = new ArrayList<String>();
        for (String b : bases) {
            out.add(String.format(b, path));
        }
        if (official != null) {
            out.add(official);
        }
        return out;
    }

    /** Адреса списков (в самопроверке подменяются на локальные). */
    public interface Urls {
        List<String> of(String listId, String level);
    }

    public static Urls URLS = new Urls() {
        @Override
        public List<String> of(String listId, String level) {
            List<String> out = new ArrayList<String>();
            if (listId.equals("ru")) {
                out.addAll(Arrays.asList(ADGUARD_RU));
                return out;
            }
            switch (listId) {
                case "easylist": return mirrors(UBO, "thirdparties/easylist.txt", "https://easylist.to/easylist/easylist.txt");
                case "ubo": return mirrors(UBO, "filters/filters.min.txt", null);
                case "ruadlist": return mirrors(RUAD, "RuAdList-uBO.txt", null);
                case "easyprivacy": return mirrors(UBO, "thirdparties/easyprivacy.txt", "https://easylist.to/easylist/easyprivacy.txt");
                case "ubo_privacy": return mirrors(UBO, "filters/privacy.min.txt", null);
                case "pgl": return Arrays.asList("https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=1&mimetype=plaintext",
                        "https://ublockorigin.github.io/uAssets/thirdparties/pgl.yoyo.org/as/serverlist");
                case "ru_counters": return mirrors(RUAD, "cntblock.txt", null);
                case "urlhaus": return Arrays.asList("https://malware-filter.gitlab.io/urlhaus-filter/urlhaus-filter-online.txt",
                        "https://curbengh.github.io/urlhaus-filter/urlhaus-filter-online.txt",
                        "https://malware-filter.pages.dev/urlhaus-filter-online.txt");
                case "ubo_badware": return mirrors(UBO, "filters/badware.min.txt", null);
                default: break;
            }
            String name = listId.equals("main") ? levelName(level) : listId.equals("popups") ? "popupads" : "tif.mini";
            for (String u : HAGEZI) {
                out.add(String.format(u, name));
            }
            return out;
        }
    };

    private static Map<String, String> levels() {
        Map<String, String> m = new LinkedHashMap<String, String>();
        m.put("light", "light");
        m.put("normal", "multi");
        m.put("pro", "pro");
        m.put("pro_plus", "pro.plus");
        return Collections.unmodifiableMap(m);
    }

    static String levelName(String level) {
        String n = LEVELS.get(level);
        return n == null ? LEVELS.get(DEFAULT_LEVEL) : n;
    }

    public static String cacheName(String listId, String level) {
        return listId.equals("main") ? "main-" + levelName(level) + ".txt" : listId + ".txt";
    }

    public static String format(String listId) {
        if (listId.equals("ru")) {
            return "adblock";
        }
        return grouped(listId) && !listId.equals("pgl") ? "abp" : "domains";
    }

    private static final Pattern DOMAIN = Pattern.compile(
            "^(?=.{4,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\\.)+[a-z0-9-]{2,63}$");
    private static final Pattern ADBLOCK = Pattern.compile("^\\|\\|([a-z0-9._-]+)\\^(\\$important)?$");
    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");
    private static final Pattern ABP = Pattern.compile("^(@@)?\\|\\|([a-z0-9._-]+)\\^(?:\\$(.*))?$");
    static final Set<String> ABP_WIDE = new HashSet<String>(Arrays.asList("important", "all", "document", "doc", "popup"));
    static final Set<String> ABP_THIRD = new HashSet<String>(Arrays.asList("third-party", "3p"));
    static final Set<String> ABP_EXC = new HashSet<String>(Arrays.asList("important", "all", "document", "doc", "third-party",
            "3p", "~third-party", "1p", "first-party"));

    /** Разбор списков фильтров по строке: помнит раздел сборного списка (как parse_abp в adblock.py). */
    static final class Abp {
        boolean thirdOk;

        /** → {"b"|"a", домен} или null. b — блокировать, a — исключение из самого списка. */
        String[] line(String raw) {
            String line = raw.trim();
            if (line.isEmpty()) {
                return null;
            }
            if (line.charAt(0) == '!') {
                if (line.startsWith("! *** ")) {
                    String name = line.toLowerCase();
                    thirdOk = name.contains("adservers") || name.contains("trackingservers");
                }
                return null;
            }
            if (line.charAt(0) == '[' || line.indexOf('#') >= 0) {
                return null;
            }
            Matcher m = ABP.matcher(line.toLowerCase());
            if (!m.matches()) {
                return null;
            }
            String d = clean(m.group(2));
            if (d.isEmpty() || IPV4.matcher(d).matches()) {
                return null;
            }
            Set<String> opts = new HashSet<String>();
            if (m.group(3) != null) {
                for (String o : m.group(3).split(",")) {
                    opts.add(o.trim());
                }
            }
            if (m.group(1) != null) {
                return ABP_EXC.containsAll(opts) ? new String[]{"a", d} : null;
            }
            boolean wide = ABP_WIDE.containsAll(opts);
            if (!wide && thirdOk) {
                Set<String> rest = new HashSet<String>(opts);
                rest.removeAll(ABP_WIDE);
                wide = ABP_THIRD.containsAll(rest);
            }
            return wide ? new String[]{"b", d} : null;
        }
    }

    /** Список фильтров → [адреса, исключения]. */
    public static List<Set<String>> parseAbp(String text) {
        Set<String> block = new HashSet<String>();
        Set<String> allow = new HashSet<String>();
        Abp st = new Abp();
        for (String l : text.split("\\r?\\n")) {
            String[] r = st.line(l);
            if (r != null) {
                (r[0].equals("b") ? block : allow).add(r[1]);
            }
        }
        return Arrays.asList(block, allow);
    }

    static String clean(String value) {
        String v = value.trim().toLowerCase();
        while (v.endsWith(".")) {
            v = v.substring(0, v.length() - 1);
        }
        if (v.startsWith("*.")) {
            v = v.substring(2);
        }
        return DOMAIN.matcher(v).matches() ? v : "";
    }

    /** Одна строка списка → домен ("" — не домен). */
    static String parseLine(String raw, String fmt) {
        String line = raw.trim();
        if (line.isEmpty() || line.charAt(0) == '#' || line.charAt(0) == '!' || line.startsWith("[")) {
            return "";
        }
        if (fmt.equals("adblock") || line.startsWith("||")) {
            Matcher m = ADBLOCK.matcher(line.toLowerCase());
            return m.matches() ? clean(m.group(1)) : "";
        }
        String[] parts = line.split("\\s+");
        int i = 0;
        if (parts.length >= 2 && (parts[0].equals("0.0.0.0") || parts[0].equals("127.0.0.1") || parts[0].equals("::")
                || parts[0].equals("::1"))) {
            i = 1;
        }
        String d = parts[i];
        int hash = d.indexOf('#');
        return clean(hash >= 0 ? d.substring(0, hash) : d);
    }

    /** Текст списка → домены. domains — по одному в строке (можно «0.0.0.0 домен» и «*.домен»),
     *  adblock — только правила вида ||домен^ без условий. */
    public static Set<String> parse(String text, String fmt) {
        if (fmt.equals("abp")) {
            return parseAbp(text).get(0);
        }
        Set<String> out = new HashSet<String>();
        for (String line : text.split("\\r?\\n")) {
            String d = parseLine(line, fmt);
            if (!d.isEmpty()) {
                out.add(d);
            }
        }
        return out;
    }

    static void parseFile(File f, String fmt, Set<String> out) throws IOException {
        parseFile(f, fmt, out, null);
    }

    /** allow — куда сложить исключения самого списка (только для списков фильтров), null — не нужно. */
    static void parseFile(File f, String fmt, Set<String> out, Set<String> allow) throws IOException {
        BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8), 65536);
        Abp st = fmt.equals("abp") ? new Abp() : null;
        try {
            String line;
            while ((line = r.readLine()) != null) {
                if (st != null) {
                    String[] x = st.line(line);
                    if (x != null && x[0].equals("b")) {
                        out.add(x[1]);
                    } else if (x != null && allow != null) {
                        allow.add(x[1]);
                    }
                    continue;
                }
                String d = parseLine(line, fmt);
                if (!d.isEmpty()) {
                    out.add(d);
                }
            }
        } finally {
            r.close();
        }
    }

    /** Свои сайты или исключения из поля ввода: адреса, ссылки, *.домен, ||домен^. */
    public static Set<String> parseUser(String text) {
        Set<String> out = new HashSet<String>();
        for (String raw : (text == null ? "" : text).split("\\r?\\n")) {
            String line = raw;
            int hash = line.indexOf('#');
            if (hash >= 0) {
                line = line.substring(0, hash);
            }
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }
            if (line.contains("://")) {
                line = line.substring(line.indexOf("://") + 3);
            }
            int slash = line.indexOf('/');
            if (slash >= 0) {
                line = line.substring(0, slash);
            }
            int colon = line.indexOf(':');
            if (colon >= 0) {
                line = line.substring(0, colon);
            }
            if (line.startsWith("||")) {
                line = line.substring(2);
                while (line.endsWith("^")) {
                    line = line.substring(0, line.length() - 1);
                }
            }
            String d = clean(line);
            if (!d.isEmpty()) {
                out.add(d);
            }
        }
        return out;
    }

    static List<String> parents(String domain) {
        List<String> out = new ArrayList<String>();
        int i = domain.indexOf('.');
        while (i >= 0) {
            String rest = domain.substring(i + 1);
            if (rest.indexOf('.') < 0) {
                break; // сам верхний уровень (com, ru) — не «родитель»
            }
            out.add(rest);
            i = domain.indexOf('.', i + 1);
        }
        return out;
    }

    private static boolean anyParentIn(String d, Set<String> set) {
        int i = d.indexOf('.');
        while (i >= 0) {
            String rest = d.substring(i + 1);
            if (rest.indexOf('.') < 0) {
                return false;
            }
            if (set.contains(rest)) {
                return true;
            }
            i = d.indexOf('.', i + 1);
        }
        return false;
    }

    /** Убирает поддомены, если в списке уже есть сам сайт (правило ядра действует на поддомены). */
    public static List<String> minimize(Set<String> domains) {
        List<String> out = new ArrayList<String>();
        for (String d : domains) {
            if (!anyParentIn(d, domains)) {
                out.add(d);
            }
        }
        Collections.sort(out);
        return out;
    }

    /** Исключения: сайт из исключений, его поддомены и «родители» не блокируются. */
    public static Set<String> applyAllow(Set<String> domains, Set<String> allow) {
        if (allow.isEmpty()) {
            return domains;
        }
        Set<String> out = new HashSet<String>();
        for (String d : domains) {
            if (!allow.contains(d) && !anyParentIn(d, allow)) {
                out.add(d);
            }
        }
        for (String a : allow) {
            out.removeAll(parents(a)); // запись example.com заблокировала бы и исключение cdn.example.com
        }
        return out;
    }

    // ---------- встроенная защита: блокировщик не закрывает сами сайты (как в программе для ПК) ----------

    /** Сайт и все его поддомены не блокируются никогда (картинки и файлы, мессенджеры, банки, госуслуги, разработка). */
    public static final Set<String> SAFE_TREE = new HashSet<String>(Arrays.asList(
            "0x0.st", "alfabank.ru", "bitbucket.org", "catbox.moe", "cdnjs.cloudflare.com", "discord.com",
            "discord.gg", "discord.media", "discordapp.com", "discordapp.net", "discordcdn.com", "dropbox.com",
            "dropboxusercontent.com", "epicgames.com", "esia.gosuslugi.ru", "files.fm", "gazprombank.ru", "github.com",
            "github.io", "githubassets.com", "githubusercontent.com", "gitlab.com", "gofile.io", "gosuslugi.ru",
            "i.imgur.com", "ibb.co", "iili.io", "imgbb.com", "imgur.com", "jsdelivr.net", "litter.catbox.moe",
            "mega.io", "mega.nz", "mironline.ru", "mos.ru", "mtsbank.ru", "nalog.gov.ru", "npmjs.com", "npmjs.org",
            "nspk.ru", "online.sberbank.ru", "open.ru", "paypal.com", "pfr.gov.ru", "pixeldrain.com", "pochtabank.ru",
            "postimages.org", "postimg.cc", "psbank.ru", "pypi.org", "pythonhosted.org", "qiwi.com", "raiffeisen.ru",
            "riotgames.com", "rshb.ru", "sber.ru", "sberbank.ru", "sfr.gov.ru", "signal.org", "sovcombank.ru",
            "steamcommunity.com", "steamcontent.com", "steampowered.com", "steamstatic.com", "stripe.com", "t.me",
            "tbank.ru", "tdesktop.com", "telegra.ph", "telegram.me", "telegram.org", "telesco.pe", "tinkoff.ru",
            "unpkg.com", "vtb.ru", "whatsapp.com", "whatsapp.net", "yoomoney.ru"));
    /** Сами сайты (адрес и www) не блокируются, а их рекламные поддомены — как обычно. */
    public static final Set<String> SAFE_SITES = new HashSet<String>(Arrays.asList(
            "2gis.ru", "aliexpress.com", "aliexpress.ru", "amazon.com", "anthropic.com", "apple.com", "artstation.com",
            "auto.ru", "avito.ru", "bing.com", "chatgpt.com", "cian.ru", "claude.ai", "deepseek.com", "deviantart.com",
            "drom.ru", "dtf.ru", "dzen.ru", "ebay.com", "facebook.com", "gemini.google.com", "google.com", "google.ru",
            "habr.com", "hh.ru", "icloud.com", "instagram.com", "ivi.ru", "kinopoisk.ru", "kion.ru", "kommersant.ru",
            "lenta.ru", "linkedin.com", "live.com", "mail.ru", "market.yandex.ru", "medium.com", "microsoft.com",
            "netflix.com", "office.com", "ok.ru", "okko.tv", "openai.com", "outlook.com", "ozon.ru", "perplexity.ai",
            "pikabu.ru", "pinterest.com", "pixiv.net", "quora.com", "rbc.ru", "reddit.com", "ria.ru", "rutube.ru",
            "soundcloud.com", "spotify.com", "stackoverflow.com", "tiktok.com", "tumblr.com", "twitch.tv",
            "twitter.com", "vc.ru", "vk.com", "vk.ru", "vkvideo.ru", "wb.ru", "wikimedia.org", "wikipedia.org",
            "wildberries.ru", "x.com", "ya.ru", "yandex.com", "yandex.ru", "youtu.be", "youtube.com"));
    /** Названия рекламных и следящих адресов — о таких «сайт закрыт» не спрашиваем. */
    static final Pattern AD_NAME = Pattern.compile("(^|[.\\-])(ads?|adv|adverts?|advertising|adserv(er|ice)s?|adsystem|banners?|track(er|ers|ing)?|pixels?|metrics?|analytics?|stats?|counters?|telemetry|beacons?|pop(up|under|ads?)s?|clicks?|clicktrack|promos?|affiliates?|tagmanager|doubleclick|syndication)([.\\-]|\\d|$)|doubleclick|googlesyndication|googletagmanager|google-analytics|googleadservices|adservice|taboola|outbrain|criteo|adfox|adriver|mgid|hotjar|scorecardresearch|quantserve|adnxs|rubiconproject|pubmatic|openx|smartadserver|moatads|exoclick|propeller|adsterra|clickadu|popads|popcash|juicyads|trafficjunky|yandexadexchange|adhigh|admitad|getintent|buzzoola|segmento|relap|smi2|24smi|marketgid|lentainform|adskeeper|appsflyer|branch\\.io|onesignal|pushwoosh|sendpulse|amplitude|mixpanel|segment\\.(io|com)|newrelic|nr-data|sentry|bugsnag|crashlytics");

    /** Убирает из списка защищённые сайты (и записи-«родители», которые закрыли бы их целиком). */
    public static Set<String> protect(Set<String> domains) {
        Set<String> shield = new HashSet<String>(SAFE_TREE);
        for (String d : SAFE_SITES) {
            shield.add(d);
            shield.add("www." + d);
        }
        Set<String> out = new HashSet<String>();
        for (String d : domains) {
            if (!shield.contains(d) && !anyParentIn(d, SAFE_TREE)) {
                out.add(d);
            }
        }
        for (String h : shield) {
            out.removeAll(parents(h));
        }
        return out;
    }

    /** "tree" — защищён вместе с поддоменами, "site" — защищён сам сайт, "" — не защищён. */
    public static String protectedKind(String host) {
        String h = host.toLowerCase(Locale.ROOT);
        if (SAFE_TREE.contains(h) || anyParentIn(h, SAFE_TREE)) {
            return "tree";
        }
        if (SAFE_SITES.contains(h) || (h.startsWith("www.") && SAFE_SITES.contains(h.substring(4)))) {
            return "site";
        }
        return "";
    }

    /** Основной адрес сайта, если host — это сам сайт (example.com или www.example.com), иначе "". */
    public static String siteName(String host) {
        String h = host.toLowerCase(Locale.ROOT);
        while (h.endsWith(".")) {
            h = h.substring(0, h.length() - 1);
        }
        String base = h.startsWith("www.") ? h.substring(4) : h;
        String[] parts = base.split("\\.");
        if (parts.length < 2 || !DOMAIN.matcher(base).matches()) {
            return "";
        }
        List<String> shortSld = Arrays.asList("co", "com", "net", "org", "gov", "edu", "ac", "msk", "spb");
        if (parts.length == 2 || (parts.length == 3 && parts[2].length() == 2 && shortSld.contains(parts[1]))) {
            return base;
        }
        return "";
    }

    public static boolean looksLikeAds(String host) {
        return AD_NAME.matcher(host.toLowerCase(Locale.ROOT)).find();
    }

    public static boolean isBlocked(String host, Set<String> domains) {
        String h = host.toLowerCase();
        while (h.endsWith(".")) {
            h = h.substring(0, h.length() - 1);
        }
        return domains.contains(h) || anyParentIn(h, domains);
    }

    // ---------- файл для ядра (формат geosite: GeoSiteList → GeoSite → Domain) ----------

    static int varintLen(long n) {
        int len = 1;
        while ((n >>>= 7) != 0) {
            len++;
        }
        return len;
    }

    static void varint(OutputStream o, long n) throws IOException {
        while (true) {
            int b = (int) (n & 0x7F);
            n >>>= 7;
            if (n != 0) {
                o.write(b | 0x80);
            } else {
                o.write(b);
                return;
            }
        }
    }

    /** Пишет GeoSiteList с одной категорией. Тип домена 2 (Domain) — сам сайт и все его поддомены. */
    public static void encodeGeosite(String tag, List<String> domains, OutputStream out) throws IOException {
        byte[] code = tag.toUpperCase().getBytes(StandardCharsets.UTF_8);
        long site = 1 + varintLen(code.length) + code.length;
        for (String d : domains) {
            int dl = d.getBytes(StandardCharsets.UTF_8).length;
            long inner = 2 + 1 + varintLen(dl) + dl;
            site += 1 + varintLen(inner) + inner;
        }
        out.write(1 << 3 | 2);
        varint(out, site);
        out.write(1 << 3 | 2);
        varint(out, code.length);
        out.write(code);
        for (String d : domains) {
            byte[] db = d.getBytes(StandardCharsets.UTF_8);
            long inner = 2 + 1 + varintLen(db.length) + db.length;
            out.write(2 << 3 | 2);
            varint(out, inner);
            out.write(0x08);
            out.write(0x02);
            out.write(2 << 3 | 2);
            varint(out, db.length);
            out.write(db);
        }
    }

    public static byte[] encodeGeosite(String tag, List<String> domains) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        try {
            encodeGeosite(tag, domains, b);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return b.toByteArray();
    }

    private static long[] readVarint(byte[] buf, int i) {
        long n = 0;
        int shift = 0;
        while (true) {
            int b = buf[i++] & 0xff;
            n |= (long) (b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                return new long[]{n, i};
            }
            shift += 7;
        }
    }

    /** Обратное чтение (для самопроверки): {категория → домены}. */
    public static Map<String, List<String>> decodeGeosite(byte[] data) {
        Map<String, List<String>> out = new LinkedHashMap<String, List<String>>();
        int i = 0;
        while (i < data.length) {
            long[] k = readVarint(data, i);
            long[] l = readVarint(data, (int) k[1]);
            int start = (int) l[1];
            int end = start + (int) l[0];
            if ((k[0] >> 3) == 1) {
                String code = "";
                List<String> doms = new ArrayList<String>();
                int j = start;
                while (j < end) {
                    long[] k2 = readVarint(data, j);
                    long[] l2 = readVarint(data, (int) k2[1]);
                    int s2 = (int) l2[1];
                    int e2 = s2 + (int) l2[0];
                    if ((k2[0] >> 3) == 1) {
                        code = new String(data, s2, e2 - s2, StandardCharsets.UTF_8);
                    } else if ((k2[0] >> 3) == 2) {
                        int m = s2;
                        while (m < e2) {
                            long[] k3 = readVarint(data, m);
                            if ((k3[0] & 7) == 0) {
                                m = (int) readVarint(data, (int) k3[1])[1];
                                continue;
                            }
                            long[] l3 = readVarint(data, (int) k3[1]);
                            int s3 = (int) l3[1];
                            if ((k3[0] >> 3) == 2) {
                                doms.add(new String(data, s3, (int) l3[0], StandardCharsets.UTF_8));
                            }
                            m = s3 + (int) l3[0];
                        }
                    }
                    j = e2;
                }
                out.put(code, doms);
            }
            i = end;
        }
        return out;
    }

    // ---------- скачивание и сборка ----------

    /** Скачивает список (с запасным адресом). Возвращает число адресов в нём. */
    public static int download(String listId, String level, File cacheDir, int proxyPort, int timeoutMs) throws IOException {
        cacheDir.mkdirs();
        File dest = new File(cacheDir, cacheName(listId, level));
        File tmp = new File(cacheDir, dest.getName() + ".new");
        int prev = 0;
        if (dest.isFile()) {
            Set<String> old = new HashSet<String>();
            parseFile(dest, format(listId), old);
            prev = old.size();
        }
        IOException last = null;
        for (String url : URLS.of(listId, level)) {
            try {
                Http.downloadTo(url, tmp, timeoutMs, proxyPort, 64L * 1024 * 1024);
                Set<String> got = new HashSet<String>();
                parseFile(tmp, format(listId), got);
                if (got.size() < 50) {
                    throw new IOException(Text.t("в скачанном списке почти нет адресов", "the downloaded list is almost empty"));
                }
                if (prev >= 1000 && got.size() < prev * 0.4) { // обрезанный ответ или подмена: старая копия лучше
                    throw new IOException(Text.t("список скачался не целиком (" + got.size() + " адресов вместо " + prev + ")",
                            "the list didn't download fully (" + got.size() + " addresses instead of " + prev + ")"));
                }
                dest.delete();
                if (!tmp.renameTo(dest)) {
                    throw new IOException(Text.t("не удалось сохранить список", "could not save the list"));
                }
                return got.size();
            } catch (IOException e) {
                last = e;
                tmp.delete();
            }
        }
        throw last != null ? last : new IOException(Text.t("список не скачался", "the list did not download"));
    }

    /**
     * Почему сайт блокируется: в каких скачанных списках он (или его «родитель») есть, есть ли он в своих сайтах
     * и в исключениях. Списки читаются построчно, без загрузки в память. → {lists: [{id, match}], custom, allowed}
     */
    public static Map<String, Object> lookup(File cacheDir, String level, Map<String, Object> lists, String custom, String allow,
                                             String host) throws IOException {
        String h = clean(host);
        if (h.isEmpty()) {
            throw new IOException(Text.t("Не похоже на адрес сайта. Пример: example.com.", "This doesn't look like a site address."));
        }
        Set<String> cand = new HashSet<String>();
        cand.add(h);
        cand.addAll(parents(h));
        List<Object> found = new ArrayList<Object>();
        for (String id : listIds(lists)) {
            File f = cacheFile(id, level, cacheDir);
            if (!f.isFile()) {
                continue;
            }
            Abp st = format(id).equals("abp") ? new Abp() : null;
            BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8), 65536);
            try {
                String line;
                while ((line = r.readLine()) != null) {
                    String d;
                    if (st != null) {
                        String[] x = st.line(line);
                        d = x != null && x[0].equals("b") ? x[1] : "";
                    } else {
                        d = parseLine(line, format(id));
                    }
                    if (!d.isEmpty() && cand.contains(d)) {
                        found.add(Json.obj("id", id, "match", d));
                        break;
                    }
                }
            } finally {
                r.close();
            }
        }
        String ownMatch = "";
        for (String d : parseUser(custom)) {
            if (cand.contains(d)) {
                ownMatch = d;
            }
        }
        Set<String> al = parseUser(allow);
        boolean allowed = al.contains(h) || anyParentIn(h, al);
        boolean safe = !protectedKind(h).isEmpty() && ownMatch.isEmpty(); // свой «Блокировать» главнее защиты
        return Json.obj("host", h, "lists", found, "custom", ownMatch, "allowed", allowed, "protected", safe,
                "blocked", !allowed && !safe && (!found.isEmpty() || !ownMatch.isEmpty()));
    }

    /** Файл списка в кэше; основного списка нужной силы ещё нет — пока берём ближайший скачанный, мягкий первым. */
    static File cacheFile(String listId, String level, File cacheDir) {
        File f = new File(cacheDir, cacheName(listId, level));
        if (!listId.equals("main") || f.length() > 0) {
            return f;
        }
        for (String other : new String[]{"normal", "light", "pro", "pro_plus"}) {
            File alt = new File(cacheDir, cacheName("main", other));
            if (alt.length() > 0) {
                return alt;
            }
        }
        return f;
    }

    public static boolean cached(String listId, String level, File cacheDir) {
        return new File(cacheDir, cacheName(listId, level)).length() > 0;
    }

    /** Собирает adblock.dat из скачанных списков, своих сайтов и исключений.
     *  Возвращает {total, lists: {id: число}, missing: [id…], built_at}. */
    public static Map<String, Object> build(File cacheDir, File out, String level, Map<String, Object> lists,
                                            String custom, String allow) throws IOException {
        Map<String, Object> counts = new LinkedHashMap<String, Object>();
        List<Object> missing = new ArrayList<Object>();
        Set<String> domains = new HashSet<String>();
        Set<String> excepts = new HashSet<String>();
        for (String id : listIds(lists)) {
            File f = cacheFile(id, level, cacheDir);
            Set<String> got = new HashSet<String>();
            if (f.isFile()) {
                parseFile(f, format(id), got, excepts);
            }
            if (got.isEmpty()) {
                missing.add(id);
            }
            counts.put(id, (long) got.size());
            domains.addAll(got);
        }
        for (Map.Entry<String, List<String>> g : GROUPS.entrySet()) { // число адресов группы — для окна
            if (listOn(lists, g.getKey())) {
                long n = 0;
                for (String id : g.getValue()) {
                    Object c = counts.get(id);
                    n += c instanceof Long ? (Long) c : 0L;
                }
                counts.put(g.getKey(), n);
            }
        }
        Set<String> own = parseUser(custom);
        excepts.removeAll(own);
        domains = applyAllow(domains, excepts); // исключения самих списков (@@||…^), кроме своих сайтов
        domains = protect(domains); // свои сайты из «Блокировать» главнее встроенной защиты
        counts.put("custom", (long) own.size());
        domains.addAll(own);
        List<String> fin = minimize(applyAllow(domains, parseUser(allow)));
        domains = null; // освободить память до записи
        if (fin.isEmpty()) {
            fin = Collections.singletonList("example.invalid"); // пустая категория ядру не нравится
        }
        out.getParentFile().mkdirs();
        File tmp = new File(out.getPath() + ".part");
        OutputStream o = new BufferedOutputStream(new FileOutputStream(tmp), 65536);
        try {
            encodeGeosite(TAG, fin, o);
        } finally {
            o.close();
        }
        out.delete();
        if (!tmp.renameTo(out)) {
            tmp.delete();
            throw new IOException(Text.t("не удалось сохранить список рекламы", "could not save the ad list"));
        }
        return Json.obj("total", (long) fin.size(), "lists", counts, "missing", missing, "built_at", System.currentTimeMillis());
    }
}
