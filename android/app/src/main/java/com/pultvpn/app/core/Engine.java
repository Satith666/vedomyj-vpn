package com.pultvpn.app.core;

import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Мозг приложения: подписки, проверка серверов, подключение к лучшему, Автопереход, белые списки, раздача.
 * Всё, что зависит от Android, спрятано за интерфейсом Platform — поэтому логику можно проверить на обычной Java.
 */
public final class Engine {

    /** То, что даёт телефон. */
    public interface Platform {
        File dataDir();

        String deviceId();

        String osVersion();

        String systemLang();

        String appVersion();

        /** Задержка через временный экземпляр ядра с этими настройками, мс. Ошибка — исключение. */
        long testDelay(String configJson, String url) throws Exception;

        /** Включить VPN или перезапустить ядро с новыми настройками. Ждёт, пока ядро запустится. */
        void startVpn(String configJson, List<String> excludedApps) throws Exception;

        void stopVpn();

        boolean vpnAlive();

        /** Задержка через работающее ядро (по его правилам), мс. */
        long coreDelay(String url) throws Exception;

        /** Временное ядро без туннеля (вход HTTP на 127.0.0.1) — для проверок обхода и своих прокси. close() — остановить. */
        java.io.Closeable startTestCore(String configJson) throws Exception;

        String coreVersion();

        /** Адрес точки доступа или USB-модема телефона ("" — нет). */
        String hotspotIp();

        /** SSH: выполнить скрипт на сервере, вывод — построчно. */
        void sshRun(String host, int port, String user, String password, String script, LineSink out, Stop stop)
                throws Exception;

        /** Состояние изменилось: обновить уведомление и т.п. */
        void changed();
    }

    /** Необязательно: сколько байт приложение (а значит, весь трафик через туннель) скачало и отправило. */
    public interface Traffic {
        long[] trafficBytes();
    }

    /** Необязательно: какая сеть сейчас (для профилей сетей). → {kind: wifi|cell|other, open: открытый Wi-Fi}. */
    public interface NetInfo {
        Map<String, Object> netInfo();
    }

    private volatile boolean netPublic;
    private String netSig = "";

    /** Профили сетей: в открытом Wi-Fi весь трафик — через VPN; VPN выключен — напомнить уведомлением. */
    public void netWatch() {
        if (!(p instanceof NetInfo)) {
            return;
        }
        Map<String, Object> n;
        try {
            n = ((NetInfo) p).netInfo();
        } catch (RuntimeException e) {
            return;
        }
        boolean captive = Json.bool(n, "captive", false);
        // пока сеть просит войти через свою страницу, «всё через VPN» закрыло бы её — ждём входа
        boolean pub = Json.bool(settings, "net_profiles", true) && "wifi".equals(Json.str(n, "kind"))
                && Json.bool(n, "open", false) && !captive;
        String sig = Json.str(n, "kind") + ":" + pub + ":" + captive;
        if (sig.equals(netSig)) {
            return;
        }
        boolean first = netSig.isEmpty();
        netSig = sig;
        if (!first && !captive) {
            certWatch(); // новая сеть — не подменяет ли она сертификаты
        }
        boolean was = netPublic;
        netPublic = pub;
        if (captive) {
            log("Сеть Wi-Fi просит войти (страница входа). Войди — после этого весь трафик пойдёт через VPN.",
                    "The Wi-Fi network asks you to sign in (a login page). Sign in — after that all traffic goes through the VPN.");
        }
        if (pub) {
            log("Открытый Wi-Fi без пароля: весь трафик — через VPN.", "Open Wi-Fi without a password: all traffic goes through the VPN.");
            if (!isOn() && p instanceof Notices) {
                try {
                    ((Notices) p).notice(Text.t("Открытый Wi-Fi", "Open Wi-Fi"),
                            Text.t("Сеть без пароля: включи VPN, чтобы никто в ней не видел твой трафик.",
                                    "A network without a password: turn the VPN on so nobody there sees your traffic."));
                } catch (RuntimeException ignored) {
                    // уведомление — не главное
                }
            }
        }
        if (was != pub && isOn()) {
            applyCore();
        } else if (!first) {
            netChanged();
        }
        changed();
    }

    /** Необязательно: шифрование секретов на диске (Android Keystore). Строка ↔ строка (base64). */
    public interface Crypto {
        String seal(String plain) throws Exception;

        String open(String sealed) throws Exception;
    }

    static final String SECURE_PREFIX = "VDMSEC1:";
    static final String[] SECRET_KEYS = {"subscriptions", "proxies", "share_pass", "share_user", "vps_hosts", "family"};
    private boolean secureFailed;
    private String secureRaw = "";

    private boolean encrypting() {
        return p instanceof Crypto && Json.bool(settings, "encrypt_data", true);
    }

    String sealText(String text) {
        if (!encrypting()) {
            return text;
        }
        try {
            return SECURE_PREFIX + ((Crypto) p).seal(text);
        } catch (Exception e) {
            return text; // ключ недоступен — лучше сохранить как есть, чем потерять
        }
    }

    String openText(String text) throws Exception {
        if (!text.startsWith(SECURE_PREFIX)) {
            return text;
        }
        if (!(p instanceof Crypto)) {
            throw new Exception("no crypto");
        }
        return ((Crypto) p).open(text.substring(SECURE_PREFIX.length()));
    }

    /** Необязательно: заметное уведомление (например, «сайт закрыт блокировщиком — разрешить?»). */
    public interface Notices {
        void notice(String title, String text);
    }

    /** Необязательно: сертификаты центров сертификации на телефоне (DER). user — поставленные человеком или приложениями. */
    public interface CertStore {
        List<byte[]> caCerts(boolean user);
    }

    /** Необязательно: сведения о телефоне для «Проверки программы» (разрешения, батарея, другой VPN…). */
    public interface DeviceInfo {
        Map<String, Object> deviceInfo();
    }

    public interface LineSink {
        void line(String s);
    }

    public interface Stop {
        boolean stopped();
    }

    /** Задача остановлена кнопкой «Стоп». */
    public static final class Cancelled extends RuntimeException {
        public Cancelled() {
            super("cancelled");
        }
    }

    /** Ошибка, которую нужно показать человеку как есть. */
    public static final class UserError extends RuntimeException {
        public UserError(String msg) {
            super(msg);
        }
    }

    public static final String GEO_BASE = "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/";
    // запасные адреса тех же файлов (ветка release): GitHub в России иногда открывается не целиком
    public static String[] GEO_MIRRORS = {"https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/",
            "https://cdn.jsdelivr.net/gh/runetfreedom/russia-v2ray-rules-dat@release/"};
    public static String GEO_MAIN = GEO_BASE;

    static List<String> geoUrls() {
        List<String> out = new ArrayList<String>();
        out.add(GEO_MAIN);
        out.addAll(Arrays.asList(GEO_MIRRORS));
        return out;
    }
    /** Сайты для проверки «белых списков» (в самопроверке подменяются на локальные). */
    public static String[] WL_ALLOWED = {"https://ya.ru/", "https://vk.com/", "https://www.gosuslugi.ru/"};
    public static String[] WL_FOREIGN = {"https://www.google.com/generate_204", "https://cp.cloudflare.com/generate_204",
            "https://www.wikipedia.org/"};
    static final int TEST_THREADS = 6;
    static final long TICK_MS = 5000;

    private final Platform p;
    private final Object lock = new Object();
    public final OverlayMap settings;
    private final File settingsFile;
    private final File serversFile;
    private final List<Server> servers = new ArrayList<Server>();

    private Server current;
    private String status = "off"; // off | connecting | on
    /**
     * Две очереди задач. «Подключение» — короткие действия с VPN: подключить, отключить, сменить сервер, применить
     * настройки. «Фон» — долгие: проверка серверов, подписки, списки, подбор обхода, проверка программы.
     * Они идут параллельно: пока в фоне что-то качается или подбирается, VPN можно включать и переключать.
     * Фоновая задача сама ядро не трогает — просит очередь подключения (applyCore).
     */
    static final class Lane {
        final ExecutorService exec = Executors.newSingleThreadExecutor();
        String title = "";
        String kind = "";
        volatile boolean stop;
        String task = "";   // название задачи (title меняется по ходу) — для журнала подключения
        boolean user;       // задачу начал человек (кнопкой, виджетом, плиткой), а не автоматика
        String why = "";    // причина (например, «сервер перестал отвечать») — для журнала подключения
    }

    /** Журнал подключения: кто и почему подключал, переключал и отключал VPN. */
    private final Journal journal;
    private volatile long userUntil;
    private long pingAt; // когда последний раз измерена задержка (монитор)

    // ---------- диспетчер подключения (то же, что pult/dispatcher.py) ----------
    // Идут данные — ничего не трогаем; сервер меняем после 30 с тишины; не чаще раза в 2 минуты (сервер
    // «моргает» — 5, потом 10 минут; связи нет совсем — 2 минуты); после твоего действия — минута тишины.
    public static long SILENCE_MS = 30000L;
    public static long SWITCH_GAP_MS = 120000L;
    static final long[] FLAP_GAPS_MS = {300000L, 600000L};
    static final long FLAP_WINDOW_MS = 900000L;
    static final long DEAD_MS = 90000L;
    public static long USER_QUIET_MS = 60000L;
    static final long RX_ALIVE_MS = 10000L;
    public volatile long rxAt;     // когда с сервера последний раз приходили данные
    public volatile long userConnAt; // когда человек последний раз что-то делал с VPN
    private final java.util.ArrayDeque<Long> autoSwitches = new java.util.ArrayDeque<Long>();
    private final Map<String, Long> deniedLogged = new java.util.HashMap<String, Long>();

    private boolean byUser() {
        Lane l = laneOf.get();
        return l != null && l.user;
    }

    boolean dataFlowing() {
        return System.currentTimeMillis() - rxAt < RX_ALIVE_MS;
    }

    synchronized long switchGap() {
        long now = System.currentTimeMillis();
        int recent = 0;
        for (Long t : autoSwitches) {
            if (now - t < FLAP_WINDOW_MS) {
                recent++;
            }
        }
        if (now - rxAt >= DEAD_MS || recent <= 1) {
            return SWITCH_GAP_MS;
        }
        return FLAP_GAPS_MS[Math.min(recent - 2, FLAP_GAPS_MS.length - 1)];
    }

    /** Можно ли автоматике сменить сервер: "" — можно, иначе — почему нельзя. */
    public String maySwitch() {
        if (byUser() || !isOn()) {
            return "";
        }
        long now = System.currentTimeMillis();
        if (dataFlowing()) {
            return Text.t("с сервера идут данные — он работает", "data is coming from the server — it works");
        }
        if (now - rxAt < SILENCE_MS) {
            return Text.t("тишина меньше 30 с — жду подтверждения", "silence under 30 s — waiting for confirmation");
        }
        if (now - userConnAt < USER_QUIET_MS) {
            return Text.t("ты только что сам подключал — автоматика ждёт минуту", "you just connected yourself — automation waits a minute");
        }
        Long last;
        synchronized (this) {
            last = autoSwitches.peekLast();
        }
        if (last != null && now - last < switchGap()) {
            return Text.t("сервер недавно уже меняли", "the server was switched recently");
        }
        return "";
    }

    private synchronized void noteAutoSwitch() {
        if (!byUser()) {
            autoSwitches.addLast(System.currentTimeMillis());
            while (autoSwitches.size() > 20) {
                autoSwitches.removeFirst();
            }
        }
    }

    private void denyNote(String why) {
        long now = System.currentTimeMillis();
        String key = why.split(" — ")[0];
        Long at = deniedLogged.get(key);
        if (at == null || now - at >= 60000L) {
            deniedLogged.put(key, now);
            log("Диспетчер: не меняю сервер — " + why + ".", "Dispatcher: not switching — " + why + ".");
        }
    }

    /** Следующую задачу начал человек (вызывать прямо перед действием). */
    public void markUser() {
        userUntil = System.currentTimeMillis() + 3000;
    }

    public Journal journal() {
        return journal;
    }

    private void journal(String kind, Server s, String why) {
        Lane l = laneOf.get();
        String who = l == null ? "" : l.user ? "user" : l.task;
        String reason = why == null || why.isEmpty() ? (l == null ? "" : l.why) : why;
        try {
            journal.add(kind, s == null ? "" : s.name, who, reason, s == null ? "" : (s.engine == null || s.engine.isEmpty() ? "xray" : s.engine));
        } catch (Exception ignored) {
            // журнал — помощник
        }
    }

    private void journalWhy(String why) {
        Lane l = laneOf.get();
        if (l != null) {
            l.why = why;
        }
    }

    private final Lane conn = new Lane();
    private final Lane bg = new Lane();
    private final ThreadLocal<Lane> laneOf = new ThreadLocal<Lane>();
    private volatile boolean pendingApply; // настройки поменялись, пока очередь подключения была занята
    private final ExecutorService pool = Executors.newFixedThreadPool(TEST_THREADS);
    private ScheduledExecutorService timer;
    private final LinkedList<String> log = new LinkedList<String>();
    private final Map<String, Map<String, Object>> problems = new LinkedHashMap<String, Map<String, Object>>();
    private Map<String, Object> message = Json.obj("id", 0L, "text", "", "kind", "");
    private long messageId;

    private boolean whitelistMode;
    private long lastTestAt;
    private long lastSubUpdate;
    private int healthFails;
    private long liveDelay = -1;
    private long tick;
    private final Random rnd = new Random();

    // раздача
    private boolean shareOn;
    private String shareIp = "";
    private String hotspotSsid = "";
    private String hotspotPass = "";
    private String hotspotKind = ""; // local — точка доступа приложения, system — обычная точка доступа телефона
    private int shareFails;
    private long lastShareFix;

    // вход для запросов самого приложения через VPN (подписки, если напрямую не открываются)
    private int appPort;
    private final String appUser = "pult-" + Text.randomWord(6);
    private final String appPass = Text.randomWord(20);

    // последняя «Проверка программы»
    private Map<String, Object> lastCheck;

    // журнал ошибок (errors.jsonl) — для заявок на GitHub
    private final ErrorLog errors;
    // последняя проверка сертификатов
    private volatile Map<String, Object> lastCerts;
    private final java.util.concurrent.atomic.AtomicBoolean certWatching = new java.util.concurrent.atomic.AtomicBoolean();

    public Engine(Platform platform) {
        this.p = platform;
        File dir = platform.dataDir();
        dir.mkdirs();
        settingsFile = new File(dir, "settings.json");
        serversFile = new File(dir, "servers.json");
        settings = new OverlayMap(Store.loadSettings(settingsFile));
        XrayConfig.CERT_PINS.clear();
        loadPins();
        errors = new ErrorLog(dir, platform.appVersion(), "Android " + platform.osVersion(), new ErrorLog.Scrubber() {
            @Override
            public String scrub(String text) {
                return scrubSecrets(text);
            }
        });
        journal = new Journal(dir, new ErrorLog.Scrubber() {
            @Override
            public String scrub(String text) {
                return scrubSecrets(text);
            }
        });
        Object sec = settings.remove("_secure");
        if (sec instanceof String) {
            try {
                Map<String, Object> blob = Json.parseObject(openText((String) sec));
                for (String k : SECRET_KEYS) {
                    if (blob.containsKey(k)) {
                        settings.put(k, blob.get(k));
                    }
                }
            } catch (Exception e) {
                secureFailed = true; // другой телефон или ключ потерян — подписки добавят заново
                secureRaw = (String) sec;
            }
        }
        String lang = Json.str(settings, "lang");
        Text.lang = lang.isEmpty() ? ("ru".equals(platform.systemLang()) ? "ru" : "en") : lang;
        if (Json.str(settings, "hwid").isEmpty()) {
            settings.put("hwid", Text.sha256hex("pultvpn|" + platform.deviceId()).substring(0, 16));
        }
        if (Json.str(settings, "share_pass").isEmpty()) {
            settings.put("share_pass", Text.randomWord(8));
        }
        if (Json.num(settings, "ads_rev", 0) < 2) {
            // встроенная защита сайтов в списках рекламы: пересобрать при первой возможности
            settings.put("ads_rev", 2L);
            if (Json.bool(settings, "block_ads", false)) {
                settings.put("ads_updated_at", 0L);
            }
        }
        if (!Json.bool(settings, "routing_v2", false)) {
            // Раньше по умолчанию был «умный» режим: сайт открывался, а видео и картинки с зарубежных серверов
            // (их провайдер тормозит, но не блокирует) — нет. Один раз переводим на «всё через VPN, российское напрямую».
            settings.put("routing_v2", true);
            if ("smart".equals(Json.str(settings, "mode", "vpn"))) {
                settings.put("mode", "vpn");
                settings.put("ru_direct", true);
                log("Маршрутизация: теперь через VPN идёт всё, кроме российских сайтов, — так сайты работают целиком "
                        + "(видео, картинки). Вернуть экономный режим можно на главной.",
                        "Routing: everything except Russian sites now goes through the VPN so sites work fully "
                        + "(videos, pictures). You can switch back to economy mode on the home screen.");
            }
        }
        loadServers();
        if (secureFailed) {
            problem("secure", Text.t("Подписки не расшифровались", "Subscriptions could not be decrypted"),
                    Text.t("Похоже, данные перенесли с другого телефона. Добавь подписку снова или перенеси настройки через QR-код.",
                            "Looks like the data came from another phone. Add the subscription again or transfer settings by QR code."));
        }
        saveSettings();
    }

    /** Запуск фоновых проверок. */
    public void start() {
        synchronized (lock) {
            if (timer != null) {
                return;
            }
            timer = Executors.newSingleThreadScheduledExecutor();
        }
        safeStartBegin(); // два падения подряд при запуске — этот запуск без необязательной автоматики
        timer.scheduleWithFixedDelay(new Runnable() {
            @Override
            public void run() {
                try {
                    monitor();
                } catch (Throwable e) {
                    log("Сбой фоновой проверки: " + e, "Background check failed: " + e);
                    recordBug(e, "монитор");
                }
            }
        }, TICK_MS, TICK_MS, TimeUnit.MILLISECONDS);
    }

    public void shutdown() {
        if (timer != null) {
            timer.shutdownNow();
        }
        conn.exec.shutdownNow();
        bg.exec.shutdownNow();
        pool.shutdownNow();
    }

    /** Всё, что нельзя показывать в отчётах и журнале ошибок: ссылки подписок, серверы, пароли, свои прокси. */
    List<String> reportSecrets() {
        List<String> secrets = new ArrayList<String>();
        synchronized (lock) {
            for (Map<String, Object> sb : subs()) {
                secrets.add(Json.str(sb, "url"));
            }
            for (Server sv : servers) {
                secrets.add(sv.link);
                secrets.add(sv.address);
            }
            secrets.add(Json.str(settings, "share_pass"));
            secrets.add(Json.str(settings, "share_user"));
            secrets.add(Json.str(settings, "hwid"));
            for (Map<String, Object> px : proxyList()) {
                secrets.add(Json.str(px, "host"));
                secrets.add(Json.str(px, "user"));
                secrets.add(Json.str(px, "pass"));
            }
            for (Object o : vlist(settings, "vps_hosts")) {
                secrets.add(Json.str(Json.map(o), "host"));
            }
        }
        secrets.add(appPass);
        secrets.add(appUser);
        try {
            secrets.add(p.deviceId());
        } catch (RuntimeException ignored) {
            // нет — и ладно
        }
        return secrets;
    }

    String scrubSecrets(String text) {
        String out = text == null ? "" : text;
        String dir = p.dataDir().getAbsolutePath();
        if (dir.length() > 3) {
            out = out.replace(dir, "<app>");
        }
        return Diagnostics.scrub(out, reportSecrets());
    }

    // ---------- защита: предохранители, автооткат, безопасный запуск (как protect.py) ----------

    static final int FUSE_FAILS = 2;
    static final long[] FUSE_STEPS = {600_000L, 3_600_000L, 86_400_000L};
    public static long GUARD_WAIT_MS = 40_000L; // самопроверка укорачивает
    static final long SAFE_OK_MS = 90_000L;
    static final String[] SAFE_OFF = {"fp_auto", "mask_auto", "net_profiles", "app_update"};
    static final String[] GUARDED_KEYS = {"mode", "ru_direct", "block_quic", "dns_encrypted", "block_ads", "mask_auto",
            "fp_auto", "engine_pick", "wl_priority"};
    /** Профессиональные настройки и их значения по умолчанию («Вернуть как было»). */
    static final String[] PRO_KEYS = {"fuses_enabled", "guard_rollback", "safe_start", "net_memory", "autopilot", "fp_auto",
            "mask_auto", "data_watch", "whitelist_auto"};
    private final Object fuseLock = new Object();
    private Map<String, Boolean> ladderKinds;
    private volatile Map<String, Object> guard;
    private volatile boolean guardChecking;
    public volatile boolean safeMode;
    private final long startedAt = System.currentTimeMillis();

    /** Вид способа для предохранителя: другой отпечаток TLS или маскировка; "" — обычный путь. */
    static String wayKind(Server c) {
        if (c.fp != null && !c.fp.isEmpty()) {
            return "отпечаток " + c.fp;
        }
        return c.mask ? "маскировка" : "";
    }

    static String wayKindEn(String kind) {
        return kind.startsWith("отпечаток ") ? "fingerprint " + kind.substring(10) : "маскировка".equals(kind) ? "masking" : kind;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> fuses() {
        Object v = settings.get("fuses");
        if (!(v instanceof Map)) {
            v = new LinkedHashMap<String, Object>();
            settings.put("fuses", v);
        }
        return (Map<String, Object>) v;
    }

    private String fuseKey(String kind) {
        String id = netId();
        return (id.isEmpty() ? "any" : id) + "|" + kind;
    }

    public boolean fuseOk(String kind) {
        if (kind == null || kind.isEmpty() || !Json.bool(settings, "fuses_enabled", true)) {
            return true;
        }
        synchronized (fuseLock) {
            Map<String, Object> rec = Json.map(fuses(), fuseKey(kind));
            return rec == null || Json.num(rec, "until", 0) <= System.currentTimeMillis();
        }
    }

    public void fuseResult(String kind, boolean ok) {
        if (kind == null || kind.isEmpty()) {
            return;
        }
        String msgRu = null;
        String msgEn = null;
        synchronized (fuseLock) {
            Map<String, Object> all = fuses();
            String key = fuseKey(kind);
            if (ok) {
                if (all.remove(key) == null) {
                    return;
                }
            } else {
                Map<String, Object> rec = Json.map(all, key);
                if (rec == null) {
                    rec = Json.obj("n", 0L, "level", 0L, "until", 0L);
                }
                long n = Json.num(rec, "n", 0) + 1;
                long level = Json.num(rec, "level", 0);
                rec.put("at", System.currentTimeMillis());
                if (n >= FUSE_FAILS) {
                    int i = (int) Math.min(level, FUSE_STEPS.length - 1);
                    rec.put("until", System.currentTimeMillis() + FUSE_STEPS[i]);
                    rec.put("level", level + 1);
                    n = 0;
                    String[] dur = i == 0 ? new String[]{"10 мин", "10 min"} : i == 1 ? new String[]{"час", "an hour"} : new String[]{"сутки", "a day"};
                    msgRu = "Предохранитель: «" + kind + "» в этой сети не помогает — пропускаю его " + dur[0] + ".";
                    msgEn = "Fuse: “" + wayKindEn(kind) + "” doesn't help on this network — skipping it for " + dur[1] + ".";
                }
                rec.put("n", n);
                all.put(key, rec);
                while (all.size() > 300) {
                    all.remove(all.keySet().iterator().next());
                }
            }
        }
        if (msgRu != null) {
            log(msgRu, msgEn);
        }
        saveSettings();
    }

    public List<Object> fusesState() {
        List<Object> out = new ArrayList<Object>();
        String id = netId();
        String prefix = (id.isEmpty() ? "any" : id) + "|";
        long now = System.currentTimeMillis();
        synchronized (fuseLock) {
            for (Map.Entry<String, Object> e : fuses().entrySet()) {
                long until = Json.num(Json.map(e.getValue()), "until", 0);
                if (e.getKey().startsWith(prefix) && until > now) {
                    String kind = e.getKey().substring(prefix.length());
                    out.add(Json.obj("kind", Text.t(kind, wayKindEn(kind)), "left", (until - now) / 1000));
                }
            }
        }
        return out;
    }

    public void fusesClear() {
        synchronized (fuseLock) {
            settings.put("fuses", new LinkedHashMap<String, Object>());
        }
        saveSettings();
        log("Предохранители сброшены: все способы снова пробуются.", "Fuses reset: all methods are tried again.");
        changed();
    }

    /** Что-то в лестнице помогло — не помогшие способы получают неудачу, помогший — сброс. */
    private void ladderFuses() {
        Map<String, Boolean> k = ladderKinds;
        ladderKinds = null;
        if (k == null) {
            return;
        }
        for (Map.Entry<String, Boolean> e : k.entrySet()) {
            fuseResult(e.getKey(), e.getValue());
        }
    }

    private boolean workingNow() {
        if (!isOn()) {
            return false;
        }
        if (dataFlowing()) {
            return true;
        }
        synchronized (lock) {
            return healthFails == 0 && System.currentTimeMillis() - pingAt < 180_000L;
        }
    }

    /** Перед изменением настроек: если VPN работал, через 40 с проверим, работает ли он с новыми. */
    public void guardChange(Map<String, Object> before, String labelRu, String labelEn) {
        Map<String, Object> keep = new LinkedHashMap<String, Object>();
        for (String k : GUARDED_KEYS) {
            if (before.containsKey(k)) {
                keep.put(k, before.get(k));
            }
        }
        if (keep.isEmpty() || !Json.bool(settings, "guard_rollback", true) || !workingNow()) {
            return;
        }
        Map<String, Object> g = guard;
        if (g != null) {
            Map<String, Object> first = Json.map(g, "before");
            if (first != null) {
                keep.putAll(first);
            }
        }
        guard = Json.obj("before", keep, "ru", labelRu, "en", labelEn, "at", System.currentTimeMillis());
    }

    private void guardTick() {
        final Map<String, Object> g = guard;
        if (g == null || guardChecking) {
            return;
        }
        if (!isOn()) {
            guard = null;
            return;
        }
        long at = Json.num(g, "at", 0);
        if (connBusy() || System.currentTimeMillis() - at < GUARD_WAIT_MS) {
            return;
        }
        boolean fresh;
        synchronized (lock) {
            fresh = healthFails == 0 && pingAt > at;
        }
        if (dataFlowing() || fresh) {
            guard = null;
            log("Изменение прижилось: " + Json.str(g, "ru") + " — VPN работает.",
                    "The change took: " + Json.str(g, "en") + " — the VPN works.");
            return;
        }
        guardChecking = true;
        pool.submit(new Runnable() {
            @Override
            public void run() {
                try {
                    long d = -1;
                    try {
                        d = p.coreDelay(XrayConfig.HEALTH_URL);
                    } catch (Exception ignored) {
                        d = -1;
                    }
                    if (guard != g) {
                        return;
                    }
                    guard = null;
                    if (d > 0) {
                        log("Изменение прижилось: " + Json.str(g, "ru") + " — VPN работает.",
                                "The change took: " + Json.str(g, "en") + " — the VPN works.");
                        return;
                    }
                    Map<String, Object> before = Json.map(g, "before");
                    boolean changedAny = false;
                    synchronized (lock) {
                        for (Map.Entry<String, Object> e : before.entrySet()) {
                            Object now = settings.get(e.getKey());
                            if (now == null ? e.getValue() != null : !now.equals(e.getValue())) {
                                settings.put(e.getKey(), e.getValue());
                                changedAny = true;
                            }
                        }
                    }
                    if (!changedAny) {
                        return;
                    }
                    saveSettings();
                    log("Автооткат: после изменения (" + Json.str(g, "ru") + ") данные через VPN перестали идти — вернул как было.",
                            "Auto rollback: after the change (" + Json.str(g, "en") + ") data stopped flowing through the VPN — put it back.");
                    say(Text.t("Вернул настройки как было: после изменения (" + Json.str(g, "ru") + ") VPN перестал работать.",
                            "Put the settings back: after the change (" + Json.str(g, "en") + ") the VPN stopped working."), "info");
                    applyCore();
                    changed();
                } finally {
                    guardChecking = false;
                }
            }
        });
    }

    private File startFile() {
        return new File(p.dataDir(), "start.json");
    }

    /** При создании движка: два падения подряд в первые 90 с после запуска — этот запуск безопасный. */
    private void safeStartBegin() {
        long crashes = 0;
        try {
            if (startFile().isFile()) {
                crashes = Json.num(Json.parseObject(Store.read(startFile())), "crashes", 0);
            }
        } catch (Exception ignored) {
            crashes = 0;
        }
        safeMode = Json.bool(settings, "safe_start", true) && crashes >= 2;
        if (safeMode) {
            for (String k : SAFE_OFF) {
                settings.overlay.put(k, false);
            }
            log("Безопасный запуск: приложение " + crashes + " раза подряд закрылось с ошибкой при запуске — в этот раз без необязательной автоматики.",
                    "Safe start: the app crashed " + crashes + " times in a row while starting — this time without optional automation.");
            problem("safe_mode", Text.t("Безопасный запуск", "Safe start"),
                    Text.t("Приложение несколько раз подряд закрылось с ошибкой при запуске, поэтому сейчас работает без необязательной автоматики. Следующий запуск — обычный.",
                            "The app crashed several times in a row while starting, so it now runs without optional automation. The next start is normal."));
        }
    }

    /** Из обработчика падений: упало в первые 90 с — считаем; позже — это не падение при запуске. */
    public void noteCrash() {
        if (System.currentTimeMillis() - startedAt > SAFE_OK_MS) {
            return;
        }
        long crashes = 0;
        try {
            if (startFile().isFile()) {
                crashes = Json.num(Json.parseObject(Store.read(startFile())), "crashes", 0);
            }
        } catch (Exception ignored) {
            crashes = 0;
        }
        try {
            Store.write(startFile(), Json.write(Json.obj("crashes", crashes + 1, "at", System.currentTimeMillis())));
        } catch (Exception ignored) {
            // не вышло — не страшно
        }
    }

    private void safeStartOk() {
        try {
            Store.write(startFile(), Json.write(Json.obj("crashes", 0L, "at", System.currentTimeMillis())));
        } catch (Exception ignored) {
            // не вышло — не страшно
        }
    }

    public Map<String, Object> proState() {
        Map<String, Object> keys = new LinkedHashMap<String, Object>();
        Map<String, Object> defs = Store.defaults();
        Map<String, Object> d = new LinkedHashMap<String, Object>();
        for (String k : PRO_KEYS) {
            keys.put(k, Json.bool(settings, k, Json.bool(defs, k, true)));
            d.put(k, Json.bool(defs, k, true));
        }
        return Json.obj("keys", keys, "defaults", d, "fuses", fusesState(), "safe_mode", safeMode, "guard", guard != null);
    }

    public List<Object> proReset() {
        Map<String, Object> defs = Store.defaults();
        Map<String, Object> vals = new LinkedHashMap<String, Object>();
        List<Object> changedKeys = new ArrayList<Object>();
        for (String k : PRO_KEYS) {
            boolean def = Json.bool(defs, k, true);
            if (Json.bool(settings, k, def) != def) {
                changedKeys.add(k);
            }
            vals.put(k, def);
        }
        synchronized (fuseLock) {
            settings.put("fuses", new LinkedHashMap<String, Object>());
        }
        setSettings(vals);
        log("Профессиональные настройки возвращены как было.", "Advanced settings reset to defaults.");
        return changedKeys;
    }

    // ---------- сбор ошибок (как collect.py) ----------

    private final Object collectLock = new Object();
    private volatile int collectEvents;
    private volatile long collectBytes;
    private volatile boolean collectFinishing;

    private File collectFile() {
        return new File(p.dataDir(), "collect.jsonl");
    }

    public boolean collecting() {
        return Json.num(settings, "collect_until", 0) > System.currentTimeMillis();
    }

    public Map<String, Object> collectStart(double hours) {
        if (!(hours >= 1)) {
            hours = hours > 0 ? 1 : 24;
        }
        hours = Math.min(72, hours);
        long now = System.currentTimeMillis();
        synchronized (collectLock) {
            settings.put("collect_until", now + (long) (hours * 3_600_000L));
            settings.put("collect_started", now);
            collectEvents = 0;
            collectBytes = 0;
            try {
                Store.write(collectFile(), Json.write(Json.obj("t", now, "k", "start", "hours", hours)) + "\n");
            } catch (Exception e) {
                log("Сбор ошибок: не удалось создать файл: " + e.getMessage(), "Error collection: couldn't create the file: " + e.getMessage());
            }
        }
        saveSettings();
        long h = Math.round(hours);
        log("Сбор ошибок включён на " + h + " ч. Отчёт появится сам, когда время выйдет.",
                "Error collection is on for " + h + " h. The report appears by itself when the time is up.");
        collectSnapshot();
        changed();
        return collectState();
    }

    private void collectAdd(String kind, Map<String, Object> data) {
        if (collectFinishing || !collecting()) {
            return;
        }
        try {
            Map<String, Object> item = new LinkedHashMap<String, Object>();
            item.put("t", System.currentTimeMillis());
            item.put("k", kind);
            for (Map.Entry<String, Object> e : data.entrySet()) {
                Object v = e.getValue();
                item.put(e.getKey(), v instanceof String ? scrubSecrets((String) v) : v);
            }
            String line = Json.write(item) + "\n";
            if ("log".equals(kind) && collectBytes > 8L * 1024 * 1024) {
                return;
            }
            synchronized (collectLock) {
                Store.append(collectFile(), line.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                collectBytes += line.length();
                collectEvents++;
            }
        } catch (Exception ignored) {
            // сбор ошибок сам ничего не ломает
        }
    }

    private void collectSnapshot() {
        Server cur;
        synchronized (lock) {
            cur = current;
        }
        boolean on = isOn();
        collectAdd("state", Json.obj("on", on, "server", on && cur != null ? cur.name : "",
                "method", Json.str(settings, "engine_pick", "auto"), "mode", Json.str(settings, "mode"),
                "ping", liveDelay, "wl", whitelistMode, "step", ladderStep, "problems", problems.size(),
                "safe", safeMode, "ads", Json.bool(settings, "block_ads", false), "filter", filterOn()));
    }

    private void collectTick() {
        long until = Json.num(settings, "collect_until", 0);
        if (until <= 0) {
            return;
        }
        if (System.currentTimeMillis() >= until) {
            pool.submit(new Runnable() {
                @Override
                public void run() {
                    collectFinish(Text.t("время вышло", "time is up"));
                }
            });
            return;
        }
        if (tick % 60 == 7) {
            collectSnapshot();
        }
    }

    public String collectStop() {
        return collectFinish(Text.t("остановлен вручную", "stopped by hand"));
    }

    private List<Map<String, Object>> collectRead() {
        List<Map<String, Object>> out = new ArrayList<Map<String, Object>>();
        try {
            for (String line : Store.read(collectFile()).split("\n")) {
                if (!line.trim().isEmpty()) {
                    try {
                        out.add(Json.parseObject(line));
                    } catch (Exception ignored) {
                        // испорченная строка
                    }
                }
            }
        } catch (Exception ignored) {
            // файла нет
        }
        return out;
    }

    public String collectFinish(String reason) {
        if (collectFinishing || Json.num(settings, "collect_until", 0) <= 0) {
            return "";
        }
        collectFinishing = true;
        try {
            long started = Json.num(settings, "collect_started", 0);
            String path = collectReport(collectRead(), started, reason);
            settings.put("collect_until", 0L);
            settings.put("collect_report", path);
            saveSettings();
            collectFile().delete();
            if (!path.isEmpty()) {
                log("Сбор ошибок закончен (" + reason + "). Отчёт готов: Настройки → Профессиональные.",
                        "Error collection finished (" + reason + "). The report is ready: Settings → Advanced.");
                say(Text.t("Сбор ошибок закончен — отчёт готов (Настройки → Профессиональные).",
                        "Error collection finished — the report is ready (Settings → Advanced)."), "info");
            }
            changed();
            return path;
        } finally {
            collectFinishing = false;
        }
    }

    private String collectReport(List<Map<String, Object>> items, long started, String reason) {
        SimpleDateFormat fmt = new SimpleDateFormat("dd.MM HH:mm:ss", Locale.US);
        long now = System.currentTimeMillis();
        List<Map<String, Object>> logs = new ArrayList<Map<String, Object>>();
        List<Map<String, Object>> probs = new ArrayList<Map<String, Object>>();
        List<Map<String, Object>> states = new ArrayList<Map<String, Object>>();
        for (Map<String, Object> it : items) {
            String k = Json.str(it, "k");
            if ("log".equals(k)) {
                logs.add(it);
            } else if ("problem".equals(k)) {
                probs.add(it);
            } else if ("state".equals(k)) {
                states.add(it);
            }
        }
        StringBuilder b = new StringBuilder();
        b.append("VEDOMYJ VPN для Android ").append(p.appVersion()).append(" — сбор ошибок\n");
        b.append("С ").append(started > 0 ? fmt.format(new Date(started)) : "?").append(" по ").append(fmt.format(new Date(now)))
                .append(String.format(Locale.US, " (%.1f ч); закончен: ", started > 0 ? (now - started) / 3_600_000.0 : 0.0))
                .append(reason).append(".\n\n");
        int crashes = 0;
        List<Map<String, Object>> errs = new ArrayList<Map<String, Object>>();
        for (Map<String, Object> e : errors.recent(300)) {
            if (Json.num(e, "last", 0) * 1000L >= started) {
                errs.add(e);
                if ("crash".equals(Json.str(e, "kind"))) {
                    crashes++;
                }
            }
        }
        b.append("Итого:\n- новых проблем: ").append(probs.size()).append("\n- сбоев кода: ").append(crashes)
                .append("\n- строк журнала: ").append(logs.size()).append("\n\nПроблемы (по порядку):\n");
        if (probs.isEmpty()) {
            b.append("- нет\n");
        }
        for (Map<String, Object> it : probs) {
            b.append("- ").append(fmt.format(new Date(Json.num(it, "t", 0)))).append("  ").append(Json.str(it, "title"));
            if (!Json.str(it, "detail").isEmpty()) {
                b.append(" — ").append(Json.str(it, "detail"));
            }
            b.append('\n');
        }
        b.append("\nЖурнал ошибок за это время:\n");
        if (errs.isEmpty()) {
            b.append("- пусто\n");
        }
        for (Map<String, Object> e : errs) {
            b.append("- [").append(Json.str(e, "kind")).append("] ").append(Json.str(e, "title"))
                    .append(" (раз: ").append(Json.num(e, "count", 1)).append(")\n");
            String tr = Json.str(e, "trace");
            if (!tr.isEmpty()) {
                b.append("  ").append(tr.length() > 1500 ? tr.substring(tr.length() - 1500) : tr).append('\n');
            }
        }
        b.append("\nСостояние каждые 5 минут:\n");
        for (Map<String, Object> st : states) {
            b.append("- ").append(fmt.format(new Date(Json.num(st, "t", 0)))).append("  ")
                    .append(Json.bool(st, "on", false) ? "VPN вкл" : "VPN выкл");
            if (!Json.str(st, "server").isEmpty()) {
                b.append(", ").append(Json.str(st, "server"));
            }
            b.append(", способ ").append(Json.str(st, "method"));
            if (Json.bool(st, "wl", false)) {
                b.append(", белые списки");
            }
            if (!Json.str(st, "step").isEmpty()) {
                b.append(", лестница: ").append(Json.str(st, "step"));
            }
            if (Json.bool(st, "filter", false)) {
                b.append(", защита без VPN");
            }
            if (Json.bool(st, "safe", false)) {
                b.append(", безопасный запуск");
            }
            b.append('\n');
        }
        b.append("\nСейчас:\n").append(report()).append("\nЖурнал программы за время сбора:\n");
        int from = Math.max(0, logs.size() - 4000);
        for (int i = from; i < logs.size(); i++) {
            Map<String, Object> it = logs.get(i);
            b.append(fmt.format(new Date(Json.num(it, "t", 0)))).append("  ").append(Json.str(it, "text")).append('\n');
        }
        String text = scrubSecrets(b.toString());
        try {
            File dir = new File(p.dataDir(), "reports");
            dir.mkdirs();
            File f = new File(dir, "errors-" + new SimpleDateFormat("yyyyMMdd-HHmm", Locale.US).format(new Date(now)) + ".txt");
            Store.write(f, text);
            return f.getAbsolutePath();
        } catch (Exception e) {
            log("Сбор ошибок: не удалось сохранить отчёт: " + e.getMessage(), "Error collection: couldn't save the report: " + e.getMessage());
            return "";
        }
    }

    public Map<String, Object> collectState() {
        long until = Json.num(settings, "collect_until", 0);
        String rep = Json.str(settings, "collect_report");
        long now = System.currentTimeMillis();
        return Json.obj("on", until > now, "until", until, "left", until > now ? (until - now) / 1000 : 0L,
                "events", (long) collectEvents, "report", rep.isEmpty() ? "" : new File(rep).getName(),
                "report_ok", !rep.isEmpty() && new File(rep).isFile());
    }

    public String collectText() throws IOException {
        String rep = Json.str(settings, "collect_report");
        if (rep.isEmpty() || !new File(rep).isFile()) {
            throw new IOException(Text.t("Отчёта пока нет.", "No report yet."));
        }
        return Store.read(new File(rep));
    }

    // ---------- «Белые списки» (галочка на главном) и «Не работает» (как notworking.py) ----------

    /** Ключ сети без запросов в интернет (для галочки «Белые списки»). */
    String netIdCached() {
        String kind = "";
        if (p instanceof NetInfo) {
            try {
                kind = Json.str(((NetInfo) p).netInfo(), "kind");
            } catch (RuntimeException ignored) {
                kind = "";
            }
        }
        String isp = ispKey;
        return isp.isEmpty() && kind.isEmpty() ? "any" : Text.sha1hex(kind + "|" + isp).substring(0, 12);
    }

    /** Сначала серверы для белых списков: галочка или списки замечены сами (если галочку не сняли в этой сети). */
    public boolean wlFirst() {
        if (Json.bool(settings, "wl_priority", false)) {
            return true;
        }
        if (!whitelistMode) {
            return false;
        }
        String muted = Json.str(settings, "wl_muted");
        return muted.isEmpty() || !muted.equals(netIdCached());
    }

    public Map<String, Object> wlState() {
        int n = 0;
        synchronized (lock) {
            for (Server s : servers) {
                if (s.usable() && s.isWl()) {
                    n++;
                }
            }
        }
        boolean on = wlFirst();
        return Json.obj("on", on, "manual", Json.bool(settings, "wl_priority", false), "auto", whitelistMode,
                "muted", whitelistMode && !on, "servers", (long) n);
    }

    public boolean wlSet(boolean on) {
        Map<String, Object> before = Json.obj("wl_priority", Json.bool(settings, "wl_priority", false));
        synchronized (lock) {
            settings.put("wl_priority", on);
            settings.put("wl_muted", !on && whitelistMode ? netIdCached() : "");
        }
        saveSettings();
        if (on) {
            log("Белые списки: сначала серверы для их обхода.", "Whitelists: whitelist bypass servers first.");
        } else {
            log("Белые списки: обычный выбор серверов." + (whitelistMode ? " Пока не сменится сеть, сама галочка не включится." : ""),
                    "Whitelists: regular server choice." + (whitelistMode ? " Until the network changes, the box won't turn on by itself." : ""));
        }
        changed();
        Server cur = current;
        if (!isOn() || cur == null || !"auto".equals(method()) || !Json.str(settings, "selected").isEmpty()) {
            return false;
        }
        List<Server> r = ranked();
        final Server best = r.isEmpty() ? null : r.get(0);
        if (best == null || best == cur || (!on && best.isWl())) {
            return false;
        }
        guardChange(before, "белые списки", "whitelists");
        return runTask(Text.t("Переключаю сервер", "Switching server"), "connect", new Runnable() {
            @Override
            public void run() {
                if (best != current && !startWith(best)) {
                    failover();
                }
            }
        });
    }

    static final String[] NW_KEYS = {"routes", "proxy_list", "direct_list", "block_list", "excluded_apps"};
    static final long NW_UNDO_MS = 24 * 3600_000L;
    private volatile Map<String, Object> nwLast;
    private volatile Map<String, Object> nwUndo;

    /** Приложения, про которые известно, какой это сервис: тогда проверяется сам сервис. */
    static final String[][] NW_APPS = {
            {"com.google.android.youtube", "YouTube"}, {"com.discord", "Discord"}, {"org.telegram.messenger", "Telegram"},
            {"org.telegram.messenger.web", "Telegram"}, {"com.whatsapp", "WhatsApp"}, {"com.instagram.android", "Instagram"},
            {"com.zhiliaoapp.musically", "TikTok"}, {"com.ss.android.ugc.trill", "TikTok"}, {"com.facebook.katana", "Facebook"},
            {"com.twitter.android", "X (Twitter)"}, {"com.openai.chatgpt", "ChatGPT"}, {"com.anthropic.claude", "Claude"},
            {"tv.twitch.android.app", "Twitch"}, {"com.spotify.music", "Spotify"}, {"com.valvesoftware.android.steam.community", "Steam"},
            {"ru.sberbankmobile", "Сбербанк"}, {"com.idamob.tinkoff.android", "Т-Банк"}, {"com.vkontakte.android", "VK"},
            {"ru.ozon.app.android", "Ozon"}, {"com.wildberries.ru", "Wildberries"}, {"ru.yandex.searchplugin", "Яндекс"},
            {"ru.rostel", "Госуслуги"}};

    static String nwServiceOfApp(String pkg) {
        for (String[] x : NW_APPS) {
            if (x[0].equals(pkg)) {
                return x[1];
            }
        }
        return "";
    }

    public Map<String, Object> nwTargets() {
        List<Object> svc = new ArrayList<Object>();
        for (Services.Service x : Services.ALL) {
            svc.add(Json.obj("name", x.name, "russian", x.russian));
        }
        Map<String, Object> known = new LinkedHashMap<String, Object>();
        for (String[] x : NW_APPS) {
            known.put(x[0], x[1]);
        }
        return Json.obj("services", svc, "known_apps", known);
    }

    public Map<String, Object> nwState() {
        Map<String, Object> last = nwLast;
        if (last == null) {
            return Json.obj("last", null);
        }
        Map<String, Object> out = new LinkedHashMap<String, Object>(last);
        Map<String, Object> u = nwUndo;
        out.put("can_undo", u != null && System.currentTimeMillis() - Json.num(u, "at", 0) < NW_UNDO_MS);
        return Json.obj("last", out);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> nwSnapshot() {
        Map<String, Object> keys = new LinkedHashMap<String, Object>();
        synchronized (lock) {
            for (String k : NW_KEYS) {
                Object v = settings.get(k);
                keys.put(k, v == null ? null : Json.parse(Json.write(v)));
            }
        }
        return keys;
    }

    private boolean nwSame(Map<String, Object> before) {
        Map<String, Object> now = nwSnapshot();
        return Json.write(now).equals(Json.write(before));
    }

    public boolean nwFix(final String kind, final String value, final String target) {
        final String v = value == null ? "" : value.trim();
        if (!"service".equals(kind) && !"app".equals(kind) && !"site".equals(kind)) {
            throw new UserError(Text.t("Выбери, что не работает: сервис, приложение или сайт.",
                    "Choose what doesn't work: a service, an app or a site."));
        }
        if (v.isEmpty()) {
            throw new UserError("site".equals(kind) ? Text.t("Вставь адрес сайта, например example.com.", "Paste a site address, for example example.com.")
                    : Text.t("Выбери из списка, что не работает.", "Choose from the list what doesn't work."));
        }
        final String svcName = "service".equals(kind) ? v : "app".equals(kind) ? nwServiceOfApp(v) : "";
        if ("service".equals(kind) && Services.find(v) == null) {
            throw new UserError(Text.t("Такого сервиса нет в списке.", "There is no such service in the list."));
        }
        if ("app".equals(kind) && svcName.isEmpty() && !"direct".equals(target) && !"proxy".equals(target)) {
            throw new UserError(Text.t("Это приложение проверить не получится — выбери, как его пускать: через VPN или без VPN.",
                    "This app can't be checked — choose how to route it: via VPN or without VPN."));
        }
        if ("app".equals(kind) && !v.matches("[A-Za-z0-9_.]{1,200}")) {
            throw new UserError(Text.t("Не похоже на приложение.", "This doesn't look like an app."));
        }
        if ("site".equals(kind)) {
            if (!isOn()) {
                throw new UserError(Text.t("Сначала включи VPN: приложение сравнит, как сайт работает напрямую и через VPN.",
                        "Turn the VPN on first: the app compares how the site works directly and through the VPN."));
            }
            if (!siteKey(v, false).contains(".")) {
                throw new UserError(Text.t("Не похоже на адрес сайта. Пример: example.com.", "This doesn't look like a site address."));
            }
        }
        return runTask(Text.t("Проверяю", "Checking"), "nw", new Runnable() {
            @Override
            public void run() {
                Map<String, Object> before = nwSnapshot();
                Map<String, Object> res;
                if (!svcName.isEmpty()) {
                    res = nwServiceFlow(Services.find(svcName));
                } else if ("app".equals(kind)) {
                    res = nwAppRoute(v, target);
                } else {
                    String host = siteKey(v, false).replaceFirst("^domain:", "");
                    repairFlow(host);
                    Map<String, Object> rep = lastRepair;
                    List<Object> steps = new ArrayList<Object>();
                    for (Object o : Json.list(rep, "hosts")) {
                        Map<String, Object> h = Json.map(o);
                        String d = Json.str(h, "detail");
                        steps.add(Json.str(h, "host") + ": " + (d.isEmpty() ? Json.str(h, "state") : d));
                    }
                    res = Json.obj("name", Json.str(rep, "site"), "verdict", Json.str(rep, "verdict"), "steps", steps, "route", "");
                }
                boolean changedNow = !nwSame(before);
                nwUndo = changedNow ? Json.obj("keys", before, "at", System.currentTimeMillis()) : null;
                Map<String, Object> last = new LinkedHashMap<String, Object>(res);
                last.put("kind", kind);
                last.put("changed", changedNow);
                last.put("at", System.currentTimeMillis());
                nwLast = last;
                log("«Не работает» — " + Json.str(res, "name") + ": " + Json.str(res, "verdict"),
                        "“Not working” — " + Json.str(res, "name") + ": " + Json.str(res, "verdict"));
                changed();
            }
        });
    }

    public boolean nwUndo() {
        final Map<String, Object> u = nwUndo;
        if (u == null || System.currentTimeMillis() - Json.num(u, "at", 0) > NW_UNDO_MS) {
            nwUndo = null;
            throw new UserError(Text.t("Отменять нечего.", "Nothing to undo."));
        }
        return runTask(Text.t("Возвращаю маршруты как было", "Putting routes back as they were"), "nw", new Runnable() {
            @Override
            public void run() {
                Map<String, Object> keys = Json.map(u, "keys");
                synchronized (lock) {
                    for (Map.Entry<String, Object> e : keys.entrySet()) {
                        if (e.getValue() == null) {
                            settings.remove(e.getKey());
                        } else {
                            settings.put(e.getKey(), e.getValue());
                        }
                    }
                }
                nwUndo = null;
                saveSettings();
                Map<String, Object> last = nwLast;
                String name = last == null ? "" : Json.str(last, "name");
                if (last != null) {
                    Map<String, Object> l2 = new LinkedHashMap<String, Object>(last);
                    l2.put("changed", false);
                    l2.put("undone", true);
                    nwLast = l2;
                }
                log("«Не работает» — " + name + ": вернул маршруты как было.", "“Not working” — " + name + ": routes are back as they were.");
                if (isOn()) {
                    applyCore();
                }
                changed();
            }
        });
    }

    private static boolean nwFull(Map<String, Object> st) {
        String s = Json.str(st, "state");
        return "ok".equals(s) || "small".equals(s);
    }

    /** Проверить сервис одним путём: port 0 — напрямую, иначе вход HTTP (VPN как сейчас или временное ядро). */
    private boolean nwTry(String host, int port, String ru, String en, List<Object> steps) {
        checkStop();
        Map<String, Object> st = STALL.test(host, port);
        String state = Json.str(st, "state");
        String d = Json.str(st, "detail");
        if (nwFull(st)) {
            steps.add(Text.t(ru + ": работает полностью", en + ": works fully"));
            return true;
        }
        steps.add("stall".equals(state) ? Text.t(ru + ": открывается, но " + d, en + ": opens, but " + d)
                : Text.t(ru + ": не открывается", en + ": doesn't open") + (d.isEmpty() ? "" : " (" + d + ")"));
        return false;
    }

    /** Временное ядро через этот сервер → проверка. */
    private boolean nwTryServer(Server x, String host, String ru, String en, List<Object> steps) {
        int port = freePort();
        java.io.Closeable core = null;
        try {
            core = p.startTestCore(Json.write(serverTestConfig(x, port)));
            return nwTry(host, port, ru, en, steps);
        } catch (Cancelled c) {
            throw c;
        } catch (Exception e) {
            steps.add(Text.t(ru + ": не запустился", en + ": didn't start"));
            return false;
        } finally {
            if (core != null) {
                try {
                    core.close();
                } catch (Exception ignored) {
                    // уже остановлено
                }
            }
        }
    }

    Map<String, Object> nwServiceFlow(Services.Service svc) {
        String host = Services.checkHost(svc);
        List<Object> steps = new ArrayList<Object>();
        progress(Text.t("Проверяю сервис " + svc.name, "Checking the service " + svc.name));
        boolean on = isOn();
        if (nwTry(host, on ? appPort : 0, "как сейчас", "as now", steps)) {
            return Json.obj("name", svc.name, "verdict", Text.t(svc.name + " открывается и качается полностью. Если не работает только в приложении — "
                    + "закрой его и открой снова.", svc.name + " opens and downloads fully. If it fails only in the app, close and reopen the app."),
                    "steps", steps, "route", "");
        }
        Server cur = current;
        String choice = "";
        String ru = "", en = "";
        if (svc.russian && nwTry(host, 0, "без VPN", "without VPN", steps)) {
            choice = "direct";
            ru = "без VPN";
            en = "without VPN";
        }
        if (choice.isEmpty() && on && cur != null && !svc.russian && nwTryServer(cur, host, "через VPN", "via VPN", steps)) {
            choice = "proxy";
            ru = "через VPN";
            en = "via VPN";
        }
        if (choice.isEmpty() && !svc.russian && nwTry(host, 0, "без VPN", "without VPN", steps)) {
            choice = "direct";
            ru = "без VPN";
            en = "without VPN";
        }
        if (choice.isEmpty() && on) {
            int n = 0;
            for (Server x : ranked()) {
                if (x == cur || n >= 3) {
                    continue;
                }
                n++;
                if (nwTryServer(x, host, "через «" + x.name + "»", "via “" + x.name + "”", steps)) {
                    choice = "server:" + x.key();
                    ru = "через «" + x.name + "»";
                    en = "via “" + x.name + "”";
                    break;
                }
            }
        }
        if (choice.isEmpty()) {
            return Json.obj("name", svc.name, "verdict", Text.t(svc.name + " не открывается ни как сейчас, ни через VPN, ни без VPN"
                    + (on ? ", ни через другие серверы" : "") + ". Похоже, сервис сейчас не работает или закрыт для этих стран."
                    + (on ? "" : " Включи VPN — приложение проверит его и через VPN."),
                    svc.name + " doesn't open as now, via VPN or without VPN" + (on ? ", nor via other servers" : "")
                            + ". The service seems to be down or closed for these countries."
                            + (on ? "" : " Turn the VPN on — the app will check it via the VPN too.")),
                    "steps", steps, "route", "");
        }
        setServiceRoute(svc.name, choice);
        boolean ok = nwTry(host, isOn() ? appPort : 0, "после изменения", "after the change", steps);
        return Json.obj("name", svc.name, "verdict", Text.t(svc.name + ": теперь " + ru + "." + (ok ? " Проверил — работает."
                        : " Но и так пока не работает — нажми «Отменить», если стало хуже."),
                svc.name + ": now " + en + "." + (ok ? " Checked — it works." : " But it doesn't work this way either yet — press “Undo” if it got worse.")),
                "steps", steps, "route", choice);
    }

    private Map<String, Object> nwAppRoute(String pkg, String target) {
        List<Object> ex = new ArrayList<Object>();
        List<Object> cur = Json.list(settings, "excluded_apps");
        if (cur != null) {
            ex.addAll(cur);
        }
        ex.remove(pkg);
        if ("direct".equals(target)) {
            ex.add(pkg);
        }
        setSettings(Json.obj("excluded_apps", ex));
        return Json.obj("name", pkg, "verdict", "direct".equals(target)
                        ? Text.t("Приложение теперь работает без VPN.", "The app now works without VPN.")
                        : Text.t("Приложение теперь работает через VPN.", "The app now works via VPN."),
                "steps", new ArrayList<Object>(), "route", target);
    }


    // ---------- журнал, сообщения, проблемы ----------

    public void log(String ru, String en) {
        String line = new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date()) + "  " + Text.t(ru, en);
        synchronized (lock) {
            log.add(line);
            while (log.size() > 300) {
                log.removeFirst();
            }
        }
        if (settings != null && Json.num(settings, "collect_until", 0) > 0) {
            collectAdd("log", Json.obj("text", ru));
        }
    }

    private void say(String text, String kind) {
        synchronized (lock) {
            messageId++;
            message = Json.obj("id", messageId, "text", text, "kind", kind);
        }
    }

    private void problem(String key, String title, String detail) {
        boolean fresh;
        synchronized (lock) {
            Map<String, Object> old = problems.get(key);
            fresh = old == null || !title.equals(Json.str(old, "title"));
            problems.put(key, Json.obj("key", key, "title", title, "detail", detail));
        }
        if (fresh && errors != null) {
            errors.record("problem", title, detail, "", key);
        }
        if (fresh) {
            collectAdd("problem", Json.obj("key", key, "title", title, "detail", detail == null ? "" : detail));
        }
    }

    /** Неожиданная ошибка в коде — в журнал ошибок (с трассировкой), чтобы починить в следующей версии. */
    public void recordBug(Throwable e, String where) {
        if (errors != null && ErrorLog.isBug(e)) {
            try {
                errors.recordExc(e, where);
            } catch (RuntimeException ignored) {
                // журнал — помощник
            }
        }
    }

    public ErrorLog errors() {
        return errors;
    }

    private void resolve(String key) {
        synchronized (lock) {
            problems.remove(key);
        }
    }

    private void changed() {
        try {
            p.changed();
        } catch (Exception ignored) {
            // интерфейс не обязан быть открыт
        }
    }

    // ---------- хранение ----------

    private void loadServers() {
        if (!serversFile.isFile()) {
            return;
        }
        try {
            List<Object> raw = Json.list(Json.parse(openText(Store.read(serversFile))));
            if (raw != null) {
                for (Object o : raw) {
                    Map<String, Object> m = Json.map(o);
                    if (m != null) {
                        servers.add(Server.fromJson(m));
                    }
                }
            }
        } catch (Exception e) {
            serversFile.renameTo(new File(serversFile.getPath() + ".broken"));
        }
    }

    @SuppressWarnings("unchecked")
    public void saveSettings() {
        synchronized (lock) {
            try {
                Map<String, Object> out = settings;
                if (encrypting()) {
                    out = new LinkedHashMap<String, Object>(settings);
                    Map<String, Object> blob = new LinkedHashMap<String, Object>();
                    boolean empty = true;
                    for (String k : SECRET_KEYS) {
                        if (out.containsKey(k)) {
                            Object v = out.remove(k);
                            blob.put(k, v);
                            if (k.equals("subscriptions") || k.equals("proxies") || k.equals("vps_hosts")) { // пароль раздачи создаётся заново сам
                                empty &= v == null || (v instanceof List && ((List<Object>) v).isEmpty());
                            }
                        }
                    }
                    if (secureFailed && empty) {
                        out.put("_secure", secureRaw); // не затираем то, что не смогли прочитать
                    } else {
                        String sealed = sealText(Json.write(blob));
                        if (sealed.startsWith(SECURE_PREFIX)) {
                            out.put("_secure", sealed);
                            secureFailed = false;
                        } else {
                            out = settings;
                        }
                    }
                }
                Store.writeText(settingsFile, Json.write(out));
            } catch (Exception e) {
                log("Не удалось сохранить настройки: " + e.getMessage(), "Could not save settings: " + e.getMessage());
            }
        }
    }

    private void saveServers() {
        synchronized (lock) {
            List<Object> out = new ArrayList<Object>();
            for (Server s : servers) {
                out.add(s.toJson());
            }
            try {
                Store.writeText(serversFile, sealText(Json.write(out)));
            } catch (Exception e) {
                log("Не удалось сохранить серверы: " + e.getMessage(), "Could not save servers: " + e.getMessage());
            }
        }
    }

    // ---------- задачи ----------

    /** Идёт хоть какая-то задача. */
    public boolean busy() {
        synchronized (lock) {
            return !conn.title.isEmpty() || !bg.title.isEmpty();
        }
    }

    /** Подключение, отключение или смена сервера прямо сейчас. */
    public boolean connBusy() {
        synchronized (lock) {
            return !conn.title.isEmpty();
        }
    }

    /** Долгая фоновая задача. */
    public boolean bgBusy() {
        synchronized (lock) {
            return !bg.title.isEmpty();
        }
    }

    private Lane laneFor(String kind) {
        return "connect".equals(kind) || "filter".equals(kind) ? conn : bg;
    }

    private Lane here() {
        Lane l = laneOf.get();
        return l != null ? l : bg;
    }

    /** Задача в своей очереди (подключение или фон). false — в этой очереди уже что-то идёт. */
    public boolean runTask(final String title, String kind, final Runnable job) {
        final Lane lane = laneFor(kind);
        synchronized (lock) {
            if (!lane.title.isEmpty()) {
                return false;
            }
            lane.title = title;
            lane.kind = kind;
            lane.stop = false;
            lane.task = title;
            lane.user = System.currentTimeMillis() < userUntil;
            lane.why = "";
            userUntil = 0;
            if (lane.user && lane == conn) {
                userConnAt = System.currentTimeMillis(); // человек сам что-то делает с VPN — автоматика ждёт минуту
            }
        }
        changed();
        lane.exec.submit(new Runnable() {
            @Override
            public void run() {
                laneOf.set(lane);
                try {
                    job.run();
                } catch (Cancelled c) {
                    log("Остановлено.", "Stopped.");
                } catch (UserError e) {
                    log(e.getMessage(), e.getMessage());
                    say(e.getMessage(), "error");
                } catch (Throwable e) {
                    String m = e.getMessage() == null ? e.toString() : e.getMessage();
                    log("Ошибка: " + m, "Error: " + m);
                    say(Text.t("Ошибка: ", "Error: ") + m, "error");
                    recordBug(e, "задача: " + title);
                } finally {
                    synchronized (lock) {
                        lane.title = "";
                        lane.kind = "";
                    }
                    saveServers();
                    saveSettings();
                    changed();
                    if (lane == conn && pendingApply) {
                        pendingApply = false;
                        applyCore(); // пока подключались, настройки поменялись — применить их
                    }
                }
            }
        });
        return true;
    }

    private void progress(String title) {
        Lane l = laneOf.get();
        if (l == null) {
            return; // не из задачи (например, из самопроверки) — показывать нечего
        }
        synchronized (lock) {
            l.title = title;
        }
        changed();
    }

    /** «Стоп» — остановить долгую фоновую задачу (VPN не трогается). */
    public void stopTask() {
        bg.stop = true;
    }

    private void checkStop() {
        if (here().stop) {
            throw new Cancelled();
        }
    }

    private void sleep(long ms) {
        long end = System.currentTimeMillis() + ms;
        while (System.currentTimeMillis() < end) {
            checkStop();
            try {
                Thread.sleep(Math.min(200, Math.max(1, end - System.currentTimeMillis())));
            } catch (InterruptedException e) {
                throw new Cancelled();
            }
        }
    }

    // ---------- подписки ----------

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> subs() {
        List<Object> l = Json.list(settings, "subscriptions");
        if (l == null) {
            l = new ArrayList<Object>();
            settings.put("subscriptions", l);
        }
        List<Map<String, Object>> out = new ArrayList<Map<String, Object>>();
        for (Object o : l) {
            if (o instanceof Map) {
                out.add((Map<String, Object>) o);
            }
        }
        return out;
    }

    private Map<String, Object> sub(String id) {
        for (Map<String, Object> s : subs()) {
            if (id.equals(Json.str(s, "id"))) {
                return s;
            }
        }
        return null;
    }

    /** Добавить подписку и сразу её загрузить и проверить серверы. */
    public String addSubscription(String raw, String name) throws Subscription.SubError {
        String url = Subscription.normalizeUrl(raw);
        String id = Text.sha1hex(url).substring(0, 8);
        synchronized (lock) {
            if (sub(id) != null) {
                throw new Subscription.SubError(Text.t("Эта подписка уже добавлена.", "This subscription is already added."));
            }
            Json.list(settings, "subscriptions").add(Json.obj("id", id, "url", url,
                    "name", name == null ? "" : Text.shorten(name.trim(), 80), "title", "", "usage", Json.obj(),
                    "error", "", "fetched", 0L, "count", 0L));
        }
        saveSettings();
        log("Добавлена подписка.", "Subscription added.");
        final String fid = id;
        runTask(Text.t("Загружаю подписку", "Loading the subscription"), "update", new Runnable() {
            @Override
            public void run() {
                refreshOne(fid);
                testServers(false);
            }
        });
        return id;
    }

    public void removeSubscription(String id) {
        synchronized (lock) {
            Map<String, Object> s = sub(id);
            if (s != null) {
                Json.list(settings, "subscriptions").remove(s);
            }
            List<Server> keep = new ArrayList<Server>();
            for (Server srv : servers) {
                if (!id.equals(srv.subId)) {
                    keep.add(srv);
                }
            }
            servers.clear();
            servers.addAll(keep);
        }
        saveSettings();
        saveServers();
        changed();
    }

    static final int RELAY_SERVERS = 3;

    /** Страна по флагу в имени сервера ("" — неизвестно). */
    public static String flagOf(String name) {
        if (name == null) {
            return "";
        }
        int i = 0;
        while (i < name.length()) {
            int cp = name.codePointAt(i);
            int n = Character.charCount(cp);
            if (cp >= 0x1F1E6 && cp <= 0x1F1FF && i + n < name.length()) {
                int cp2 = name.codePointAt(i + n);
                if (cp2 >= 0x1F1E6 && cp2 <= 0x1F1FF) {
                    return "" + (char) ('A' + cp - 0x1F1E6) + (char) ('A' + cp2 - 0x1F1E6);
                }
            }
            i += n;
        }
        return "";
    }

    public static boolean isRu(String name) {
        String low = name == null ? "" : name.toLowerCase();
        return "RU".equals(flagOf(name)) || low.contains("росси") || low.contains("russia") || low.contains("москв")
                || low.contains("moscow");
    }

    /** Серверы для скачивания подписки в обход блокировки: рабочие, кроме текущего; разные страны и российский,
     *  если есть (сервер подписки может пускать только российские адреса). */
    public List<Server> relayServers() {
        String cur = "on".equals(status) && current != null ? current.key() : null;
        List<Server> pool = new ArrayList<Server>();
        for (Server x : ranked()) {
            if (cur == null || !x.key().equals(cur)) {
                pool.add(x);
            }
        }
        List<Server> picked = new ArrayList<Server>();
        Set<String> seen = new HashSet<String>();
        for (Server x : pool) {
            if (isRu(x.name)) {
                picked.add(x);
                seen.add("RU");
                break;
            }
        }
        for (Server x : pool) {
            if (picked.size() >= RELAY_SERVERS) {
                break;
            }
            String cc = isRu(x.name) ? "RU" : flagOf(x.name);
            if (!picked.contains(x) && (cc.isEmpty() || !seen.contains(cc))) {
                picked.add(x);
                seen.add(cc);
            }
        }
        for (Server x : pool) {
            if (picked.size() >= RELAY_SERVERS) {
                break;
            }
            if (!picked.contains(x)) {
                picked.add(x);
            }
        }
        return picked;
    }

    /** Подписка не скачалась ни напрямую, ни через VPN: пробуем через другие серверы на временном ядре. */
    private Subscription.Relay subRelay() {
        return new Subscription.Relay() {
            @Override
            public Subscription run(Subscription.Attempt attempt) {
                List<Server> cands = relayServers();
                if (cands.isEmpty()) {
                    return null;
                }
                progress(Text.t("Сервер подписки недоступен — пробую через другие серверы",
                        "The subscription server is unreachable — trying via other servers"));
                for (Server x : cands) {
                    checkStop();
                    int port = freePort();
                    java.io.Closeable core = null;
                    try {
                        core = p.startTestCore(Json.write(serverTestConfig(x, port)));
                        Subscription sub = attempt.tryPort(Text.t("через сервер «", "via server “") + x.name
                                + Text.t("»", "”"), port);
                        if (sub != null) {
                            return sub;
                        }
                    } catch (Cancelled c) {
                        throw c;
                    } catch (Exception ignored) {
                        // этот сервер не запустился — следующий
                    } finally {
                        if (core != null) {
                            try {
                                core.close();
                            } catch (Exception ignored) {
                                // уже остановлено
                            }
                        }
                    }
                }
                return null;
            }
        };
    }

    // ---------- имя сервера заблокировано в DNS провайдера ----------
    static final long DNS_RECHECK_MS = 600000L;
    private final Map<String, Object[]> dnsSeen = new java.util.concurrent.ConcurrentHashMap<String, Object[]>();

    /** Так DNS провайдера «прячет» заблокированный адрес: 0.0.0.0, 127.x, частные сети. */
    static boolean bogusIp(java.net.InetAddress a) {
        return a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isSiteLocalAddress() || a.isLinkLocalAddress();
    }

    static boolean isIpLiteral(String h) {
        return h.matches("[0-9.]+") || h.contains(":");
    }

    /** Имя сервера, которое DNS провайдера не находит (или подменяет на заглушку), берём из защищённого DNS:
     *  ядро подключится по адресу, а имя останется в TLS. Без этого такой сервер просто «не отвечает». */
    void pinServerDns(List<Server> list) {
        final long now = System.currentTimeMillis();
        Set<String> hosts = new java.util.TreeSet<String>();
        for (Server x : list) {
            String h = x.address;
            Object[] seen = h == null ? null : dnsSeen.get(h);
            if (h != null && !h.isEmpty() && !x.stub && !isIpLiteral(h) && !h.endsWith(".local") && !h.endsWith(".lan")
                    && (seen == null || now - (Long) seen[0] > DNS_RECHECK_MS)) {
                hosts.add(h);
            }
        }
        List<Future<?>> fs = new ArrayList<Future<?>>();
        for (final String h : hosts) {
            fs.add(pool.submit(new Runnable() {
                @Override
                public void run() {
                    String ip = "";
                    boolean fine = false;
                    try {
                        for (java.net.InetAddress a : java.net.InetAddress.getAllByName(h)) {
                            fine |= !bogusIp(a);
                        }
                    } catch (Exception ignored) {
                        // DNS провайдера не знает имя
                    }
                    if (!fine) {
                        for (String got : Http.dohResolve(h, 6000)) {
                            try {
                                if (!bogusIp(java.net.InetAddress.getByName(got))) {
                                    ip = got;
                                    break;
                                }
                            } catch (Exception ignored) {
                                // не адрес
                            }
                        }
                    }
                    dnsSeen.put(h, new Object[]{now, ip});
                }
            }));
        }
        waitAll(fs);
        int fresh = 0;
        for (Server x : list) {
            Object[] seen = x.address == null ? null : dnsSeen.get(x.address);
            String ip = seen == null ? "" : (String) seen[1];
            if (!ip.isEmpty() && (x.pinnedIp == null || x.pinnedIp.isEmpty())) {
                fresh++;
            }
            x.pinnedIp = ip;
        }
        if (fresh > 0) {
            log("DNS провайдера не знает адрес серверов: " + fresh + ". Подключаюсь к ним по адресам из защищённого DNS.",
                    "The provider's DNS doesn't know the address of " + fresh + " servers. Connecting via addresses from secure DNS.");
        }
    }

    /** Скачивание одним путём: port 0 — напрямую, иначе через вход ядра. */
    public interface PortJob {
        void run(int port) throws Exception;
    }

    private volatile long relayFailedAt;

    /** Свои загрузки (списки, обновления) любым рабочим путём: напрямую (если DNS провайдера не знает адрес — через
     *  защищённый DNS), через VPN, через другие серверы на временном ядре. errs — что не вышло (для журнала). */
    boolean downloadAny(PortJob job, String whatRu, String whatEn, List<String> errs) {
        int[] routes = isOn() ? new int[]{0, appPort} : new int[]{0};
        for (int route : routes) {
            checkStop();
            try {
                job.run(route);
                return true;
            } catch (Cancelled c) {
                throw c;
            } catch (UserError u) {
                throw u;
            } catch (Exception e) {
                errs.add((route == 0 ? Text.t("напрямую", "direct") : Text.t("через VPN", "via VPN")) + ": " + Http.human(e));
            }
        }
        // другие серверы не помогли только что — не запускаем временное ядро на каждый файл подряд
        if (System.currentTimeMillis() - relayFailedAt < 120000L) {
            return false;
        }
        List<Server> cands = relayServers();
        if (!cands.isEmpty()) {
            progress(Text.t(whatRu + ": пробую через другие серверы", whatEn + ": trying via other servers"));
        }
        for (Server x : cands) {
            checkStop();
            int port = freePort();
            java.io.Closeable core = null;
            try {
                core = p.startTestCore(Json.write(serverTestConfig(x, port)));
                job.run(port);
                log(whatRu + ": скачано через другой сервер — напрямую не открывается.",
                        whatEn + ": downloaded via another server — it doesn't open directly.");
                return true;
            } catch (Cancelled c) {
                throw c;
            } catch (UserError u) {
                throw u;
            } catch (Exception e) {
                errs.add(Text.t("через сервер «", "via server “") + x.name + Text.t("»", "”") + ": " + Http.human(e));
            } finally {
                if (core != null) {
                    try {
                        core.close();
                    } catch (Exception ignored) {
                        // уже остановлено
                    }
                }
            }
        }
        relayFailedAt = System.currentTimeMillis();
        return false;
    }

    private Map<String, String> device() {
        return Subscription.deviceHeaders(Json.str(settings, "hwid"), p.osVersion());
    }

    /** Загрузка одной подписки. Результаты прежних проверок для тех же серверов сохраняются. */
    boolean refreshOne(String id) {
        Map<String, Object> s = sub(id);
        if (s == null) {
            return false;
        }
        String url = Json.str(s, "url");
        int vpn = "on".equals(status) ? appPort : 0;
        try {
            Subscription sub = Subscription.fetch(url, Json.str(settings, "user_agent"), vpn, device(), 20000, subRelay());
            synchronized (lock) {
                Map<String, Server> old = new HashMap<String, Server>();
                List<Server> keep = new ArrayList<Server>();
                for (Server srv : servers) {
                    if (id.equals(srv.subId)) {
                        old.put(srv.key(), srv);
                    } else {
                        keep.add(srv);
                    }
                }
                Set<String> seen = new HashSet<String>();
                for (Server srv : keep) {
                    seen.add(srv.key());
                }
                for (Server srv : sub.servers) {
                    srv.subId = id;
                    if (!seen.add(srv.key())) {
                        continue; // тот же сервер второй раз (повтор в подписке): иначе «подключён» горит у всех копий
                    }
                    Server prev = old.get(srv.key());
                    if (prev != null) {
                        srv.pingMs = prev.pingMs;
                        srv.ok = prev.ok;
                        srv.mask = prev.mask;
                        srv.whitelist = prev.whitelist;
                        srv.testedAt = prev.testedAt;
                    }
                    keep.add(srv);
                }
                servers.clear();
                servers.addAll(keep);
                s.put("title", sub.title);
                s.put("usage", sub.usage());
                s.put("error", sub.warnings.isEmpty() ? "" : String.join(" ", sub.warnings));
                s.put("fetched", System.currentTimeMillis());
                s.put("count", (long) sub.servers.size());
            }
            resolve("sub_" + id);
            subAlerts();
            String title = sub.title.isEmpty() ? Json.str(s, "name") : sub.title;
            boolean other = sub.route != null && !sub.route.isEmpty() && !sub.route.equals(Text.t("напрямую", "direct"));
            log("Подписка " + (title.isEmpty() ? "" : "«" + title + "» ") + "загружена: серверов — " + sub.servers.size()
                            + (other ? " (загружено " + sub.route + ")" : "") + ".",
                    "Subscription " + (title.isEmpty() ? "" : "\"" + title + "\" ") + "loaded: " + sub.servers.size()
                            + " servers" + (other ? " (loaded " + sub.route + ")" : "") + ".");
            for (String w : sub.warnings) {
                log(w, w);
            }
            saveServers();
            saveSettings();
            changed();
            return true;
        } catch (Subscription.SubError e) {
            synchronized (lock) {
                s.put("error", e.getMessage());
            }
            problem("sub_" + id, Text.t("Подписка не обновляется", "The subscription does not update"), e.getMessage());
            log(e.getMessage(), e.getMessage());
            say(e.getMessage(), "error");
            return false;
        }
    }

    public void refreshSubscriptions(final boolean thenTest) {
        runTask(Text.t("Обновляю подписки", "Updating subscriptions"), "update", new Runnable() {
            @Override
            public void run() {
                refreshAll();
                if (thenTest) {
                    testServers(false);
                }
            }
        });
    }

    private void refreshAll() {
        for (Map<String, Object> s : subs()) {
            checkStop();
            refreshOne(Json.str(s, "id"));
        }
        lastSubUpdate = System.currentTimeMillis();
    }

    // ---------- свои серверы ----------

    @SuppressWarnings("unchecked")
    private List<Object> manualLinks() {
        List<Object> l = Json.list(settings, "manual_links");
        if (l == null) {
            l = new ArrayList<Object>();
            settings.put("manual_links", l);
        }
        return l;
    }

    /** Добавить серверы из текста со ссылками (без проверки). Возвращает, сколько добавлено. */
    private int addServersQuiet(String text) {
        int added = 0;
        synchronized (lock) {
            List<Object> links = manualLinks();
            List<String> lines;
            try {
                lines = Links.textToLinks(text);  // конфиг AmneziaWG целиком и ключи Amnezia vpn:// — тоже сюда
            } catch (Links.LinkError e) {
                throw new UserError(Text.t("Не получилось прочитать: ", "Could not read it: ") + e.getMessage() + ".");
            }
            for (String line : lines) {
                Server s = Links.parseLink(line);
                if (s == null || links.contains(s.link)) {
                    continue;
                }
                links.add(s.link);
                servers.add(s);
                added++;
            }
        }
        if (added > 0) {
            saveSettings();
            saveServers();
            log("Добавлено серверов: " + added + ".", "Servers added: " + added + ".");
        }
        changed();
        return added;
    }

    /** Добавить серверы и сразу их проверить. */
    public int addServers(String text) {
        int added = addServersQuiet(text);
        if (added > 0) {
            runTask(Text.t("Проверяю серверы", "Testing servers"), "test", new Runnable() {
                @Override
                public void run() {
                    testServers(false);
                }
            });
        }
        return added;
    }

    public void removeServer(String key) {
        synchronized (lock) {
            Server found = find(key);
            if (found == null) {
                return;
            }
            servers.remove(found);
            if (found.subId.isEmpty()) {
                manualLinks().remove(found.link);
            }
            if (key.equals(Json.str(settings, "selected"))) {
                settings.put("selected", "");
            }
        }
        saveSettings();
        saveServers();
        changed();
    }

    public Server find(String key) {
        synchronized (lock) {
            for (Server s : servers) {
                if (s.key().equals(key)) {
                    return s;
                }
            }
            return null;
        }
    }

    // ---------- проверка серверов ----------

    private boolean geoReady() {
        File a = new File(p.dataDir(), "assets");
        return new File(a, "geosite.dat").length() > 100000 && new File(a, "geoip.dat").length() > 10000;
    }

    private long testOne(Server s, boolean mask) {
        try {
            String cfg = Json.write(XrayConfig.testConfig(s, mask, p.coreVersion()));
            long d = p.testDelay(cfg, XrayConfig.HEALTH_URL);
            return d > 0 ? d : -1;
        } catch (Exception e) {
            String m = e.getMessage() == null ? "" : e.getMessage();
            synchronized (lock) {
                s.error = Text.shorten(m, 200);
            }
            return -1;
        }
    }

    /** Проверяет серверы параллельно. onlyKeys — только эти (null — все рабочие). */
    // ---------- отпечатки сертификатов вместо allowInsecure (как certpin.py) ----------

    /** Как снимать отпечаток (в тестах — подмена без сети). */
    public interface PinSource {
        String pin(String host, int port, String sni) throws Exception;
    }

    public static volatile PinSource PINS = new PinSource() {
        @Override
        public String pin(String host, int port, String sni) throws Exception {
            return Certs.pinOf(host, port, sni, 8000);
        }
    };

    /** {адрес, порт, SNI} сервера с TLS поверх TCP, которому нужен отпечаток; null — снимать нечего. */
    static Object[] pinTarget(Server s) {
        if (!s.tlsUnverified || !"xray".equals(s.engine)) {
            return null;
        }
        Map<String, Object> ss = Json.map(s.outbound, "streamSettings");
        String net = Json.str(ss, "network");
        if (!"tls".equalsIgnoreCase(Json.str(ss, "security")) || net.equals("hysteria") || net.equals("kcp")
                || net.equals("mkcp") || net.equals("quic")) {
            return null;
        }
        String host = s.pinnedIp != null && !s.pinnedIp.isEmpty() ? s.pinnedIp : s.address;
        if (host == null || host.isEmpty() || s.port <= 0) {
            return null;
        }
        String sni = Json.str(Json.map(ss, "tlsSettings"), "serverName");
        return new Object[]{host.replace("[", "").replace("]", ""), s.port, sni.isEmpty() ? s.address : sni};
    }

    /** Снимает отпечатки параллельно (не дольше ~10 с на всё); refresh — и тем, что уже известны. */
    int fillPins(List<Server> list, boolean refresh) {
        Map<String, Object> store = Json.child(settings, "cert_pins");
        List<Thread> threads = new ArrayList<Thread>();
        final Map<String, String> got = new java.util.concurrent.ConcurrentHashMap<String, String>();
        for (final Server s : list) {
            final Object[] t = pinTarget(s);
            final String key = s.key();
            if (t == null || (!refresh && XrayConfig.CERT_PINS.containsKey(key))) {
                continue;
            }
            Thread th = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        String pin = PINS.pin((String) t[0], (Integer) t[1], (String) t[2]);
                        if (pin != null && pin.matches("[0-9a-f]{64}")) {
                            got.put(key, pin);
                        }
                    } catch (Exception ignored) {
                        // не ответил — остаётся прежний отпечаток (или никакого)
                    }
                }
            });
            th.setDaemon(true);
            th.start();
            threads.add(th);
            if (threads.size() >= 64) {
                break;
            }
        }
        long deadline = System.currentTimeMillis() + 10000;
        for (Thread th : threads) {
            try {
                th.join(Math.max(1, deadline - System.currentTimeMillis()));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        if (!got.isEmpty()) {
            synchronized (lock) {
                XrayConfig.CERT_PINS.putAll(got);
                store.putAll(got);
            }
            saveSettings();
        }
        return got.size();
    }

    void loadPins() {
        Map<String, Object> store = Json.child(settings, "cert_pins");
        for (Map.Entry<String, Object> en : store.entrySet()) {
            if (en.getValue() instanceof String) {
                XrayConfig.CERT_PINS.put(en.getKey(), (String) en.getValue());
            }
        }
    }

    void testList(List<Server> list) {
        if (list.isEmpty()) {
            return;
        }
        fillPins(list, false); // «не проверять сертификат»: ядро так не умеет — отпечатки, которых ещё нет
        final Lane lane = here();
        List<Future<?>> fs = new ArrayList<Future<?>>();
        for (final Server s : list) {
            fs.add(pool.submit(new Runnable() {
                @Override
                public void run() {
                    if (lane.stop) {
                        return;
                    }
                    long d = testOne(s, false);
                    synchronized (lock) {
                        s.pingMs = d;
                        s.ok = d > 0;
                        s.mask = false;
                        s.testedAt = System.currentTimeMillis();
                        if (s.ok) {
                            s.error = "";
                        }
                    }
                    changed();
                }
            }));
        }
        waitAll(fs);
        checkStop();
        if (!Json.bool(settings, "mask_auto", true)) {
            return;
        }
        // маскировка: серверы, которые не ответили, пробуем ещё раз с дроблением TLS
        List<Server> failed = new ArrayList<Server>();
        for (Server s : list) {
            if (!s.ok) {
                failed.add(s);
            }
        }
        if (failed.isEmpty()) {
            return;
        }
        fs.clear();
        for (final Server s : failed) {
            fs.add(pool.submit(new Runnable() {
                @Override
                public void run() {
                    if (lane.stop) {
                        return;
                    }
                    long d = testOne(s, true);
                    if (d > 0) {
                        synchronized (lock) {
                            s.pingMs = d;
                            s.ok = true;
                            s.mask = true;
                            s.error = "";
                        }
                        changed();
                    }
                }
            }));
        }
        waitAll(fs);
        int helped = 0;
        for (Server s : failed) {
            if (s.ok) {
                helped++;
            }
        }
        if (helped > 0) {
            log("Маскировка помогла серверам: " + helped + ".", "Masking helped servers: " + helped + ".");
        }
        fpRetry(list, lane);
    }

    /** Другой отпечаток TLS: серверы, которые не ответили и с маскировкой, пробуем как Firefox и Safari. */
    private void fpRetry(List<Server> list, final Lane lane) {
        if (!Json.bool(settings, "fp_auto", true)) {
            return;
        }
        final List<Server> failed = new ArrayList<Server>();
        for (Server s : list) {
            if (!s.ok && XrayConfig.fingerprintOf(s.outbound) != null) {
                failed.add(s);
            }
        }
        int helped = 0;
        for (final String fp : FP_RETRY) {
            List<Future<?>> fs = new ArrayList<Future<?>>();
            for (final Server s : failed) {
                if (s.ok || fp.equals(fpOf(s))) {
                    continue;
                }
                fs.add(pool.submit(new Runnable() {
                    @Override
                    public void run() {
                        if (lane.stop) {
                            return;
                        }
                        long d = testOne(s.withWay(fp, false), false);
                        if (d > 0) {
                            synchronized (lock) {
                                s.pingMs = d;
                                s.ok = true;
                                s.mask = false;
                                s.fp = fp;
                                s.error = "";
                            }
                            changed();
                        }
                    }
                }));
            }
            waitAll(fs);
        }
        for (Server s : failed) {
            helped += s.ok ? 1 : 0;
        }
        if (helped > 0) {
            log("Другой отпечаток TLS помог серверам: " + helped + ".", "Another TLS fingerprint helped servers: " + helped + ".");
        }
    }

    static final String[] FP_RETRY = {"firefox", "safari"};

    /** С каким отпечатком сервер подключается сейчас: подобранный программой или из ссылки. */
    static String fpOf(Server s) {
        if (s.fp != null && !s.fp.isEmpty()) {
            return s.fp;
        }
        String f = XrayConfig.fingerprintOf(s.outbound);
        return f == null || f.isEmpty() ? "chrome" : f;
    }

    private void waitAll(List<Future<?>> fs) {
        for (Future<?> f : fs) {
            while (true) {
                try {
                    f.get(500, TimeUnit.MILLISECONDS);
                    break;
                } catch (java.util.concurrent.TimeoutException e) {
                    if (here().stop) {
                        for (Future<?> x : fs) {
                            x.cancel(true);
                        }
                        throw new Cancelled();
                    }
                } catch (Exception e) {
                    break;
                }
            }
        }
    }

    /** Проверить все рабочие серверы. */
    void testServers(boolean quiet) {
        List<Server> list = new ArrayList<Server>();
        synchronized (lock) {
            for (Server s : servers) {
                if (s.usable()) {
                    list.add(s);
                }
            }
        }
        if (list.isEmpty()) {
            if (!quiet) {
                say(Text.t("Нет серверов для проверки — добавь подписку.", "No servers to test — add a subscription."), "error");
            }
            return;
        }
        progress(Text.t("Проверяю серверы", "Testing servers") + " (" + list.size() + ")");
        pinServerDns(list);
        fillPins(list, true); // сертификат сервера мог смениться — снимаем заново
        testList(list);
        lastTestAt = System.currentTimeMillis();
        int ok = 0;
        for (Server s : list) {
            if (s.ok) {
                ok++;
            }
        }
        log("Проверено серверов: " + list.size() + ", работают: " + ok + ".",
                "Servers tested: " + list.size() + ", working: " + ok + ".");
        if (ok == 0) {
            problem("servers", Text.t("Ни один сервер не отвечает", "No server answers"),
                    Text.t("Проверь интернет. Если интернет есть, а серверы молчат — возможно, провайдер их блокирует "
                                    + "или включены «белые списки».",
                            "Check the internet. If it works but servers are silent, the provider may block them "
                                    + "or whitelists may be active."));
        } else {
            resolve("servers");
        }
        saveServers();
    }

    public void testServersTask() {
        runTask(Text.t("Проверяю серверы", "Testing servers"), "test", new Runnable() {
            @Override
            public void run() {
                testServers(false);
            }
        });
    }

    /** Лучшие по порядку: выбранный вручную, затем по задержке; при белых списках — сначала серверы для них. */
    List<Server> ranked() {
        List<Server> good = new ArrayList<Server>();
        synchronized (lock) {
            for (Server s : servers) {
                if (s.score() != null && inPool(s)) {
                    good.add(s);
                }
            }
        }
        final boolean wlFirst = wlFirst();
        Collections.sort(good, new Comparator<Server>() {
            @Override
            public int compare(Server a, Server b) {
                if (wlFirst && a.isWl() != b.isWl()) {
                    return a.isWl() ? -1 : 1;
                }
                return Double.compare(a.score(), b.score());
            }
        });
        String sel = Json.str(settings, "selected");
        if (!sel.isEmpty()) {
            for (int i = 0; i < good.size(); i++) {
                if (good.get(i).key().equals(sel)) {
                    good.add(0, good.remove(i));
                    break;
                }
            }
        }
        return good;
    }

    // ---------- подключение ----------

    public String status() {
        synchronized (lock) {
            return status;
        }
    }

    public boolean isOn() {
        return "on".equals(status());
    }

    private XrayConfig.Options options(Server s) {
        XrayConfig.Options o = new XrayConfig.Options();
        o.useGeo = geoReady();
        o.mask = s.mask;
        o.coreVersion = p.coreVersion();
        o.appPort = appPort;
        o.appUser = appUser;
        o.appPass = appPass;
        if (shareOn && !shareIp.isEmpty()) {
            o.shareIp = shareIp;
            o.shareSocksPort = (int) Json.num(settings, "share_socks_port", 10810);
            o.shareHttpPort = (int) Json.num(settings, "share_http_port", 10811);
            o.shareUser = Json.str(settings, "share_user", "pult");
            o.sharePass = Json.str(settings, "share_pass");
        }
        o.routes = routePlan(s);
        o.ads = adsMode();
        if (dpiActive()) {
            o.dpiDomains = Dpi.domains(settings);
            if (Json.bool(settings, "discord_via_vpn", true)) {
                // VPN включён — Discord (и его голос) идёт через VPN, а не через обход замедлений (как на ПК)
                o.dpiDomains.removeAll(Services.DISCORD_DOMAINS);
            }
        }
        if (dpiActive() || planUsesDpi(o.routes)) {
            o.dpi = dpiStrategy();
        }
        o.accessLog = accessLog().getAbsolutePath(); // и для рекламы, и для «сайт работает не полностью»
        return o;
    }

    @SuppressWarnings("unchecked")
    private List<String> excludedApps() {
        List<String> out = new ArrayList<String>();
        List<Object> l = Json.list(settings, "excluded_apps");
        if (l != null) {
            for (Object o : l) {
                if (o instanceof String) {
                    out.add((String) o);
                }
            }
        }
        return out;
    }

    /** Запустить VPN с этим сервером и убедиться, что связь есть. */
    boolean startWith(Server s) {
        checkStop();
        progress(Text.t("Подключаюсь: ", "Connecting: ") + Text.shorten(s.name, 40));
        pinServerDns(Collections.singletonList(s));
        fillPins(Collections.singletonList(s), false);
        appPort = 30000 + rnd.nextInt(9000);
        Http.setProxyAuth(appPort, appUser, appPass);
        String cfg;
        synchronized (lock) {
            Map<String, Object> eff = settings;
            if (netPublic) { // открытый Wi-Fi: весь трафик — через VPN
                eff = new LinkedHashMap<String, Object>(settings);
                eff.put("mode", "vpn");
            }
            cfg = Json.write(XrayConfig.runConfig(s, eff, options(s)));
        }
        resetAccessLog();
        try {
            p.startVpn(cfg, excludedApps());
        } catch (Cancelled c) {
            throw c;
        } catch (Exception e) {
            String m = e.getMessage() == null ? e.toString() : e.getMessage();
            log("Ядро не запустилось с сервером «" + s.name + "»: " + m,
                    "The core did not start with \"" + s.name + "\": " + m);
            journal("fail", s, m);
            if (m.toLowerCase().contains("permission") || m.contains("VPN_PERMISSION")) {
                throw new UserError(Text.t("Нет разрешения на VPN. Нажми «Подключить» ещё раз и разреши.",
                        "No VPN permission. Tap Connect again and allow it."));
            }
            return false;
        }
        for (int attempt = 0; attempt < 3; attempt++) {
            checkStop();
            try {
                long d = p.coreDelay(XrayConfig.HEALTH_URL);
                if (d > 0) {
                    Server prev;
                    synchronized (lock) {
                        prev = "on".equals(status) ? current : null;
                        current = s;
                        status = "on";
                        healthFails = 0;
                        liveDelay = d;
                        s.fails = 0;
                        filterOn = false;
                    }
                    journal(prev == null ? "connect" : prev.key().equals(s.key()) ? "reconnect" : "switch", s, "");
                    settings.put("was_on", true);
                    resolve("connect");
                    waySaved = "";
                    rememberAt = 0;
                    log("Подключено: «" + s.name + "», задержка " + d + " мс.",
                            "Connected: \"" + s.name + "\", delay " + d + " ms.");
                    changed();
                    return true;
                }
            } catch (Exception ignored) {
                // ещё попытка
            }
            sleep(1000);
        }
        log("Сервер «" + s.name + "» не пропускает трафик.", "Server \"" + s.name + "\" passes no traffic.");
        journal("fail", s, Text.t("сервер не пропускает трафик", "the server passes no traffic"));
        synchronized (lock) {
            s.ok = false;
            s.pingMs = -1;
        }
        return false;
    }

    /** Подключиться к лучшему серверу. */
    public boolean connect() {
        return runTask(Text.t("Подключаюсь", "Connecting"), "connect", new Runnable() {
            @Override
            public void run() {
                connectFlow();
            }
        });
    }

    void connectFlow() {
        synchronized (lock) {
            status = "connecting";
        }
        changed();
        try {
            boolean any;
            synchronized (lock) {
                any = !servers.isEmpty();
            }
            if (!any && !subs().isEmpty()) {
                refreshAll();
            }
            boolean inPick = false;
            synchronized (lock) {
                any = false;
                for (Server s : servers) {
                    any |= s.usable();
                    inPick |= inPool(s);
                }
            }
            if (!any) {
                throw new UserError(Text.t("Нет серверов. Добавь подписку или ссылку на сервер.",
                        "No servers. Add a subscription or a server link."));
            }
            if (!inPick) {
                throw new UserError(Text.t("Для выбранного движка нет серверов. Добавь их или выбери движок «Авто».",
                        "The chosen engine has no servers. Add some or pick the “Auto” engine."));
            }
            // быстрый старт: в этой сети уже что-то работало — сразу оно, без проверки всех серверов
            if (tryNetMemory()) {
                return;
            }
            boolean stale = System.currentTimeMillis() - lastTestAt > 30 * 60 * 1000L;
            if (!ranked().isEmpty() && stale && tryCandidates(ranked(), 2)) {
                // проверка старая, но лучший по ней сервер работает — остальные проверим уже в фоне
                pool.submit(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            testServers(false);
                        } catch (RuntimeException ignored) {
                            // фоновая проверка — помощник
                        }
                    }
                });
                return;
            }
            if (ranked().isEmpty() || stale) {
                testServers(true);
            }
            if (tryCandidates(ranked(), 5)) {
                return;
            }
            if (Json.bool(settings, "whitelist_auto", true) && checkWhitelist()) {
                if (tryWhitelist()) {
                    return;
                }
            }
            failConnect();
        } catch (RuntimeException e) {
            synchronized (lock) {
                if (!"on".equals(status)) {
                    status = "off";
                }
            }
            if (!(e instanceof Cancelled) && !"on".equals(status())) {
                p.stopVpn();
            }
            if (e instanceof Cancelled) {
                p.stopVpn();
                synchronized (lock) {
                    status = "off";
                    current = null;
                }
            }
            throw e;
        }
    }

    private boolean tryCandidates(List<Server> list, int max) {
        int n = 0;
        for (Server s : list) {
            if (n++ >= max) {
                break;
            }
            if (startWith(s)) {
                if (s.isWl() && !whitelistMode && Json.bool(settings, "whitelist_auto", true)) {
                    // работает только сервер для белых списков — проверить, не включены ли они,
                    // чтобы вернуться на обычный сервер, когда списки снимут
                    checkWhitelist();
                }
                return true;
            }
        }
        return false;
    }

    private void failConnect() {
        p.stopVpn();
        synchronized (lock) {
            status = "off";
            current = null;
        }
        settings.put("was_on", false);
        String detail = Text.t("Ни один сервер не пропустил трафик. Проверь интернет, обнови подписку или попробуй позже.",
                "No server passed traffic. Check the internet, refresh the subscription or try later.");
        problem("connect", Text.t("Не удалось подключиться", "Could not connect"), detail);
        throw new UserError(detail);
    }

    public void disconnect() {
        conn.stop = true; // прервать подключение, если оно идёт
        vpnUntil = 0;
        boolean wasVpn;
        synchronized (lock) {
            wasVpn = !"off".equals(status);
            if (wasVpn && current != null) {
                Lane l = laneOf.get();
                String who = l != null ? (l.user ? "user" : l.task) : System.currentTimeMillis() < userUntil ? "user" : "";
                journal.add("disconnect", current.name, who, l == null ? "" : l.why, current.engine);
            }
            status = "off";
            current = null;
            liveDelay = -1;
        }
        settings.put("was_on", false);
        saveSettings();
        if (!wasVpn && filterOn()) {
            // «Выключить» в уведомлении, когда работает защита без VPN
            filterStopByUser();
            return;
        }
        if (filterWanted()) {
            // VPN выключен, но реклама блокируется и без него — тот же туннель переключается на защиту без VPN
            applyCore();
        } else {
            p.stopVpn();
            synchronized (lock) {
                filterOn = false;
            }
        }
        log("VPN выключен.", "VPN is off.");
        changed();
    }

    /** VPN выключила система (другой VPN, «Отключить» в настройках). */
    public void onRevoked() {
        synchronized (lock) {
            if (filterOn && "off".equals(status)) {
                filterOn = false;
                filterBlocked = true;
            }
            if ("off".equals(status)) {
                return;
            }
            status = "off";
            current = null;
        }
        settings.put("was_on", false);
        saveSettings();
        log("VPN выключен системой (возможно, включился другой VPN).", "VPN was turned off by the system (maybe another VPN started).");
        changed();
    }

    /** Выбрать сервер вручную ("" — автоматически). Если VPN включён — переключиться сразу. */
    // ---------- способ на главном экране (как на ПК): Авто / VPN-сервер / AmneziaWG / Без VPN ----------

    public static final List<String> METHODS = Collections.unmodifiableList(Arrays.asList("auto", "server", "awg", "off"));

    public String method() {
        String m = Json.str(settings, "conn_method");
        if (METHODS.contains(m)) {
            return m;
        }
        if ("awg".equals(Json.str(settings, "engine_pick", "auto"))) {
            return "awg";
        }
        return Json.str(settings, "selected").isEmpty() ? "auto" : "server";
    }

    /** Сменить способ. Подключение меняет окно: «Без VPN» — защита без VPN (нужно разрешение Android). */
    public void setMethod(String m) {
        if (!METHODS.contains(m)) {
            throw new UserError(Text.t("Нет такого способа.", "No such mode."));
        }
        int awgCount = 0;
        int plain = 0;
        synchronized (lock) {
            for (Server s : servers) {
                if ("awg".equals(s.engine)) {
                    awgCount++;
                } else if (s.usable()) {
                    plain++;
                }
            }
        }
        if ("awg".equals(m) && awgCount == 0) {
            throw new UserError(Text.t("Сначала добавь конфиг AmneziaWG: «+» → вставь текст .conf или ключ vpn://.",
                    "Add an AmneziaWG config first: “+” → paste the .conf text or a vpn:// key."));
        }
        if ("server".equals(m) && plain == 0) {
            throw new UserError(Text.t("Сначала добавь подписку или ссылку на сервер.", "Add a subscription or a server link first."));
        }
        settings.put("conn_method", m);
        if ("auto".equals(m) || "server".equals(m)) {
            settings.put("autopilot", "auto".equals(m));
            if ("awg".equals(Json.str(settings, "engine_pick", "auto"))) {
                settings.put("engine_pick", "auto");
            }
            if ("auto".equals(m)) {
                settings.put("selected", "");
            } else if (Json.str(settings, "selected").isEmpty()) {
                Server cur;
                synchronized (lock) {
                    cur = current;
                }
                List<Server> r = ranked();
                Server pick = cur != null ? cur : r.isEmpty() ? null : r.get(0);
                settings.put("selected", pick == null ? "" : pick.key());
            }
        } else if ("awg".equals(m)) {
            settings.put("engine_pick", "awg");
        } else {
            settings.put("dpi_enabled", true);
            settings.put("dpi_without_vpn", true); // «Без VPN» — ускорение YouTube и Discord без VPN
        }
        saveSettings();
        int i = METHODS.indexOf(m);
        log("Способ: " + new String[]{"Авто", "VPN-сервер", "AmneziaWG", "Без VPN"}[i] + ".",
                "Mode: " + new String[]{"Auto", "VPN server", "AmneziaWG", "Without VPN"}[i] + ".");
        changed();
    }

    public void select(final String key) {
        settings.put("selected", key == null ? "" : key);
        settings.put("conn_method", key == null || key.isEmpty() ? "auto" : "server"); // выбор в списке — это способ
        settings.put("autopilot", key == null || key.isEmpty());
        saveSettings();
        if (isOn()) {
            runTask(Text.t("Переключаю сервер", "Switching server"), "connect", new Runnable() {
                @Override
                public void run() {
                    Server s = key == null || key.isEmpty() ? null : find(key);
                    if (s == null) {
                        List<Server> r = ranked();
                        s = r.isEmpty() ? null : r.get(0);
                    }
                    if (s != null && s != current && !startWith(s)) {
                        failover();
                    }
                }
            });
        }
        changed();
    }

    /** Перезапуск ядра с теми же настройками (после смены настроек). */
    public void restartIfOn() {
        if (!isOn()) {
            return;
        }
        runTask(Text.t("Применяю настройки", "Applying settings"), "connect", new Runnable() {
            @Override
            public void run() {
                Server s;
                synchronized (lock) {
                    s = current;
                }
                if (s == null || !startWith(s)) {
                    failover();
                }
            }
        });
    }

    // ---------- Автопереход ----------

    /**
     * Текущий сервер перестал отвечать: лестница способов (как ladder.py на компьютере) — память сети, тот же
     * сервер, другой отпечаток TLS, маскировка, другой вход, другие серверы (сначала из другой сети), белые списки.
     * Успех — «скачались 64 КБ», а не пинг. Ничего не помогло — «что работает напрямую» и пауза, без петли.
     */
    void failover() {
        String whyNot = maySwitch();
        if (!whyNot.isEmpty()) {
            denyNote(whyNot);
            return;
        }
        noteAutoSwitch();
        progress(Text.t("Ищу рабочий способ", "Looking for a working way"));
        // белые списки (шаг 9): если они включены, обычные серверы всё равно недоступны — сразу подходящие
        boolean wlNow = Json.bool(settings, "whitelist_auto", true) && checkWhitelist();
        if ((wlNow || wlFirst()) && tryWhitelist()) {
            Server cur;
            synchronized (lock) {
                cur = current;
            }
            ladderSuccess(cur, Text.t("белые списки", "whitelists"));
            return;
        }
        if (ladder()) {
            return;
        }
        // все серверы заново (с маскировкой и другими отпечатками) и лучший из них
        Server cur;
        synchronized (lock) {
            cur = current;
        }
        ladderStep = Text.t("проверка всех серверов", "checking all servers");
        testServers(true);
        List<Server> ok = new ArrayList<Server>();
        for (Server s : ranked()) {
            if (s != cur) {
                ok.add(s);
            }
        }
        if (tryCandidates(ok, 3)) {
            Server now;
            synchronized (lock) {
                now = current;
            }
            ladderSuccess(now, Text.t("другой сервер", "another server"));
            return;
        }
        nothingWorks();
        synchronized (lock) {
            if (current != null) {
                current.fails++;
            }
        }
    }

    // ---------- лестница самоподбора ----------

    static final String[] LADDER_FPS = {"firefox", "safari", "randomized"};
    static final long[] LADDER_BACKOFF = {120000L, 300000L, 600000L, 1200000L};
    static final int DATA_NEED = 64 * 1024;
    /** «Идут ли данные»: первые 64 КБ одного из этих файлов. В самопроверке — местный адрес. */
    public static String DATA_URL = "https://speed.cloudflare.com/__down?bytes=262144";
    public static String[] DATA_URLS_MORE = {"http://cachefly.cachefly.net/1mb.test", "https://proof.ovh.net/files/1Mb.dat"};
    public static int DATA_TIMEOUT_MS = 8000;
    /** «Что работает напрямую», когда не работает ничего. */
    public static String[][] WHAT_WORKS = {
            {"Google", "https://www.google.com/generate_204"}, {"YouTube", "https://www.youtube.com/generate_204"},
            {"Telegram", "https://web.telegram.org/"}, {"Яндекс", "https://ya.ru/"}, {"VK", "https://vk.com/"},
            {"Госуслуги", "https://www.gosuslugi.ru/"}};
    static final int NET_WAYS_MAX = 40;
    public static long SILENT_MS = 30000L;
    private volatile long ladderNext;
    private int ladderFails;
    private volatile String ladderStep = "";
    private volatile Map<String, Object> whatWorks;
    private volatile String ispKey = "";
    private volatile long ispAt;
    private volatile String waySaved = "";
    private volatile long rememberAt;
    private long silentSince;
    private long silentChecked;
    private long lastRx = -1;
    private long lastTx = -1;

    /** Скачались ли через этот вход 64 КБ (вход HTTP: временное ядро или вход приложения в VPN). */
    static boolean dataOk(int port) {
        return Json.bool(dataCheck(port), "ok", false);
    }

    /**
     * {ok, ms, error} — проверка «идут ли данные» через вход HTTP. Если все адреса ответили ошибкой HTTP (403, 404…),
     * данные через туннель всё же ходят, просто адреса недоступны: ok с пометкой inconclusive — сервер не бракуется.
     */
    public static Map<String, Object> dataCheck(int port) {
        List<String> urls = new ArrayList<String>();
        urls.add(DATA_URL);
        urls.addAll(java.util.Arrays.asList(DATA_URLS_MORE));
        String last = "";
        int httpErrors = 0;
        int broken = 0;
        boolean stalled = false;
        for (String url : urls) {
            long t0 = System.currentTimeMillis();
            try {
                Http.Response r = Http.probe(url, null, DATA_TIMEOUT_MS, port, DATA_NEED);
                int got = r.body == null ? 0 : r.body.length;
                if (r.status >= 400) {
                    httpErrors++;
                    last = Text.t("код ", "code ") + r.status;
                    continue;
                }
                if (r.status == 200 && got >= DATA_NEED) {
                    return Json.obj("ok", true, "ms", System.currentTimeMillis() - t0, "error", "");
                }
                if (got > 0) {
                    stalled = true;
                    last = Text.t("данные замерли после " + Math.max(1, got / 1024) + " КБ",
                            "data froze after " + Math.max(1, got / 1024) + " KB");
                } else {
                    last = Text.t("данные не идут", "no data flows");
                }
            } catch (Exception e) {
                last = Http.human(e);
            }
            if (++broken >= 2) {
                break; // два адреса подряд не качаются — дело в подключении, а не в адресах
            }
        }
        if (httpErrors > 0 && !stalled) {
            return Json.obj("ok", true, "ms", null, "error", "", "inconclusive", true);
        }
        return Json.obj("ok", false, "ms", null, "error", last);
    }

    private volatile Map<String, Object> dataLast;
    private volatile Map<String, Object> ladderLast;

    /** Данные через текущее подключение (вход приложения в VPN) — с запоминанием для окна «Состояние». */
    Map<String, Object> dataNow() {
        Server cur;
        synchronized (lock) {
            cur = current;
        }
        Map<String, Object> r = dataCheck(appPort);
        r.put("at", System.currentTimeMillis());
        r.put("server", cur == null ? "" : cur.key());
        dataLast = r;
        changed();
        return r;
    }

    public boolean dataCheckTask() {
        if (!isOn()) {
            throw new UserError(Text.t("Сначала включи VPN.", "Turn the VPN on first."));
        }
        return runTask(Text.t("Проверяю, идут ли данные", "Checking whether data flows"), "data", new Runnable() {
            @Override
            public void run() {
                Map<String, Object> r = dataNow();
                boolean ok = Json.bool(r, "ok", false);
                log(ok ? "Данные через VPN: идут (" + Json.num(r, "ms", 0) + " мс на 64 КБ)." : "Данные через VPN не идут: " + Json.str(r, "error") + ".",
                        ok ? "Data through the VPN: flows (" + Json.num(r, "ms", 0) + " ms per 64 KB)." : "No data flows through the VPN: " + Json.str(r, "error") + ".");
                say(ok ? Text.t("Данные идут", "Data flows") : Text.t("Данные не идут", "No data flows"), ok ? "ok" : "error");
            }
        });
    }

    /** «Проверить всё»: данные, сертификаты, утечки. */
    public boolean healthCheck() {
        return runTask(Text.t("Проверяю всё", "Checking everything"), "health", new Runnable() {
            @Override
            public void run() {
                if (isOn()) {
                    dataNow();
                    checkStop();
                }
                progress(Text.t("Проверяю сертификаты", "Checking certificates"));
                certFlow(false);
                checkStop();
                if (isOn()) {
                    progress(Text.t("Проверяю утечки", "Testing for leaks"));
                    leakFlow();
                }
            }
        });
    }

    /** Первые две части внешнего адреса без VPN (провайдер) — на 10 минут. Сам адрес не хранится. */
    String ispPrefix() {
        long now = System.currentTimeMillis();
        if (now - ispAt < 600000L) {
            return ispKey;
        }
        String key = "";
        try {
            Http.Response r = Http.probe(Proxies.TRACE_URL, null, 8000, 0, 4096);
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("(?m)^ip=(\\d+)\\.(\\d+)\\.\\d+\\.\\d+").matcher(r.text());
            if (m.find()) {
                key = m.group(1) + "." + m.group(2);
            }
        } catch (Exception ignored) {
            // нет — значит, память сети по одному виду сети
        }
        ispKey = key;
        ispAt = now;
        return key;
    }

    /** Ключ сети для памяти способов: вид сети и подсеть провайдера — одним хешем. */
    public String netId() {
        String kind = "";
        if (p instanceof NetInfo) {
            try {
                kind = Json.str(((NetInfo) p).netInfo(), "kind");
            } catch (RuntimeException ignored) {
                kind = "";
            }
        }
        String isp = ispPrefix();
        if (isp.isEmpty() && kind.isEmpty()) {
            return "";
        }
        return Text.sha1hex(kind + "|" + isp).substring(0, 12);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> netWays() {
        Object v = settings.get("net_ways");
        if (!(v instanceof Map)) {
            v = new LinkedHashMap<String, Object>();
            settings.put("net_ways", v);
        }
        return (Map<String, Object>) v;
    }

    static final long NET_WAY_TTL = 30L * 86_400_000L; // память сети старше 30 дней не используется
    static final int NET_ALTS = 2;                     // запасных путей на сеть

    public Map<String, Object> netWay() {
        if (!Json.bool(settings, "net_memory", true)) {
            return null;
        }
        String id = netId();
        synchronized (lock) {
            Map<String, Object> w = id.isEmpty() ? null : Json.map(netWays(), id);
            if (w != null && System.currentTimeMillis() - Json.num(w, "at", 0) > NET_WAY_TTL) {
                return null;
            }
            return w;
        }
    }

    /** Запасные пути из памяти сети (до двух), без устаревших. */
    public static List<Map<String, Object>> netAlts(Map<String, Object> way) {
        List<Map<String, Object>> out = new ArrayList<Map<String, Object>>();
        List<Object> alts = way == null ? null : Json.list(way.get("alt"));
        if (alts == null) {
            return out;
        }
        long now = System.currentTimeMillis();
        for (Object a : alts) {
            Map<String, Object> m = Json.map(a);
            if (m != null && !Json.str(m, "server").isEmpty() && now - Json.num(m, "at", 0) <= NET_WAY_TTL && out.size() < NET_ALTS) {
                out.add(m);
            }
        }
        return out;
    }

    private static String waySig(Map<String, Object> w) {
        return Json.str(w, "server") + "|" + Json.str(w, "fp") + "|" + Json.bool(w, "mask", false);
    }

    public void rememberWay(Server s) {
        if (s == null || !Json.bool(settings, "net_memory", true)) {
            return;
        }
        String id = netId();
        if (id.isEmpty()) {
            return;
        }
        synchronized (lock) {
            Map<String, Object> ways = netWays();
            Map<String, Object> way = Json.obj("server", s.key(), "fp", s.fp == null ? "" : s.fp, "mask", s.mask,
                    "at", System.currentTimeMillis());
            // прежний рабочий путь этой сети не выбрасываем — он становится запасным (до двух запасных)
            Map<String, Object> old = Json.map(ways, id);
            List<Object> alts = new ArrayList<Object>();
            java.util.Set<String> seen = new java.util.HashSet<String>();
            seen.add(waySig(way));
            List<Map<String, Object>> prev = new ArrayList<Map<String, Object>>();
            if (old != null && !Json.str(old, "server").isEmpty()) {
                prev.add(Json.obj("server", Json.str(old, "server"), "fp", Json.str(old, "fp"),
                        "mask", Json.bool(old, "mask", false), "at", Json.num(old, "at", 0)));
                prev.addAll(netAlts(old));
            }
            for (Map<String, Object> a : prev) {
                if (seen.add(waySig(a)) && alts.size() < NET_ALTS) {
                    alts.add(a);
                }
            }
            if (!alts.isEmpty()) {
                way.put("alt", alts);
            }
            ways.put(id, way);
            while (ways.size() > NET_WAYS_MAX) {
                String oldest = null;
                long at = Long.MAX_VALUE;
                for (Map.Entry<String, Object> e : ways.entrySet()) {
                    long a = Json.num(Json.map(e.getValue()), "at", 0);
                    if (a < at) {
                        at = a;
                        oldest = e.getKey();
                    }
                }
                ways.remove(oldest);
            }
            waySaved = id + "|" + s.key() + "|" + s.fp + "|" + s.mask;
        }
        saveSettings();
    }

    public void netMemoryClear() {
        synchronized (lock) {
            settings.put("net_ways", new LinkedHashMap<String, Object>());
            waySaved = "";
        }
        saveSettings();
        log("Память сетей очищена.", "Network memory cleared.");
        changed();
    }

    /** «отпечаток firefox, маскировка» — как сейчас подключён сервер. */
    static String wayText(Server s) {
        if (s == null) {
            return "";
        }
        StringBuilder b = new StringBuilder();
        if (s.fp != null && !s.fp.isEmpty()) {
            b.append(Text.t("отпечаток ", "fingerprint ")).append(s.fp);
        }
        if (s.mask) {
            b.append(b.length() == 0 ? "" : ", ").append(Text.t("маскировка", "masking"));
        }
        return b.toString();
    }

    /** udp — Hysteria2, mKCP, QUIC; tcp — всё остальное (лестница сначала пробует другой транспорт). */
    public static String transportOf(Server s) {
        String net = Json.str(Json.map(s.outbound, "streamSettings"), "network");
        if ("hysteria2".equals(s.protocol) || "tuic".equals(s.protocol) || net.equals("hysteria") || net.equals("kcp")
                || net.equals("mkcp") || net.equals("quic")) {
            return "udp";
        }
        return "tcp";
    }

    // ---------- «Движок»: какие серверы использовать ----------

    public static final List<String> ENGINE_PICKS = java.util.Arrays.asList("auto", "xray", "hy2", "awg");

    /** Сервер выбранного движка. «Авто» и «AmneziaWG» (он включается в своём приложении) — все, что работают здесь. */
    boolean inPool(Server s) {
        if (!s.usable()) {
            return false;
        }
        String pick = Json.str(settings, "engine_pick", "auto");
        return !(pick.equals("xray") || pick.equals("hy2")) || Links.kindOf(s).equals(pick);
    }

    public void setEnginePick(String pick) {
        if (!ENGINE_PICKS.contains(pick)) {
            throw new UserError(Text.t("Нет такого движка.", "No such engine."));
        }
        settings.put("engine_pick", pick);
        saveSettings();
        log("Движок: " + pick + ".", "Engine: " + pick + ".");
        changed();
    }

    Map<String, Object> engineState() {
        Map<String, Object> counts = Json.obj("auto", 0, "xray", 0, "hy2", 0, "singbox", 0, "awg", 0);
        synchronized (lock) {
            for (Server s : servers) {
                if (s.stub || !s.supported && !"singbox".equals(s.engine)) {
                    continue;  // TUIC/AnyTLS считаются: подсказка, что они работают на компьютере
                }
                String k = Links.kindOf(s);
                counts.put(k, ((Integer) counts.get(k)) + 1);
                if (s.usable()) {
                    counts.put("auto", ((Integer) counts.get("auto")) + 1);
                }
            }
        }
        return Json.obj("pick", Json.str(settings, "engine_pick", "auto"), "counts", counts);
    }

    // ---------- Семья: настраивать VPN родителей на расстоянии (формат — Family.java, как pult/family.py) ----------

    @SuppressWarnings("unchecked")
    private Map<String, Object> fam() {
        Map<String, Object> f = Json.map(settings, "family");
        if (f == null) {
            f = new LinkedHashMap<String, Object>();
            settings.put("family", f);
        }
        if (!(f.get("me") instanceof String)) {
            f.put("me", "");
        }
        for (String k : new String[]{"helpers", "devices"}) {
            if (!(f.get(k) instanceof List)) {
                f.put(k, new ArrayList<Object>());
            }
        }
        return f;
    }

    private List<Map<String, Object>> famList(String role) {
        List<Map<String, Object>> out = new ArrayList<Map<String, Object>>();
        for (Object o : Json.list(fam(), role)) {
            Map<String, Object> m = Json.map(o);
            if (m != null) {
                out.add(m);
            }
        }
        return out;
    }

    /** {role, entry} или null. */
    private Object[] famFind(String pair) {
        for (String role : new String[]{"helpers", "devices"}) {
            for (Map<String, Object> x : famList(role)) {
                if (pair.equals(Json.str(x, "pair"))) {
                    return new Object[]{role, x};
                }
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> opsOf(Object o) {
        List<Map<String, Object>> out = new ArrayList<Map<String, Object>>();
        List<Object> l = Json.list(o);
        if (l != null) {
            for (Object x : l) {
                if (x instanceof Map) {
                    out.add((Map<String, Object>) x);
                }
            }
        }
        return out;
    }

    /** Для окна — без секретов. */
    public Map<String, Object> familyState() {
        synchronized (lock) {
            List<Object> helpers = new ArrayList<Object>();
            for (Map<String, Object> h : famList("helpers")) {
                Map<String, Object> pend = Json.map(h, "pending");
                helpers.add(Json.obj("pair", Json.str(h, "pair"), "name", Json.str(h, "name"), "mode", Json.str(h, "mode", "ask"),
                        "since", Json.num(h, "since", 0), "reply", Json.str(h, "reply"),
                        "pending", pend == null ? null : Json.obj("summary", Family.summary(opsOf(pend.get("ops"))), "at", Json.num(pend, "at", 0))));
            }
            List<Object> devices = new ArrayList<Object>();
            for (Map<String, Object> d : famList("devices")) {
                List<Object> sent = Json.list(d, "sent");
                List<Object> last = new ArrayList<Object>();
                if (sent != null) {
                    for (Object o : sent.subList(Math.max(0, sent.size() - 10), sent.size())) {
                        Map<String, Object> x = new LinkedHashMap<String, Object>(Json.map(o));
                        x.put("summary", Family.summary(opsOf(x.get("ops"))));
                        x.remove("ops");
                        last.add(x);
                    }
                }
                Object snap = d.get("snap");
                devices.add(Json.obj("pair", Json.str(d, "pair"), "name", Json.str(d, "name"), "since", Json.num(d, "since", 0),
                        "snap", snap, "snap_at", Json.num(d, "snap_at", 0), "sent", last,
                        "invite", snap == null ? Json.str(d, "invite") : ""));
            }
            return Json.obj("me", Json.str(fam(), "me"), "helpers", helpers, "devices", devices);
        }
    }

    public void familySetMe(String name) {
        synchronized (lock) {
            fam().put("me", Text.shorten(name == null ? "" : name.trim(), 40));
        }
        saveSettings();
        changed();
    }

    public Map<String, Object> familyInvite(String device) {
        String dev = Text.shorten(device == null ? "" : device.trim(), 40);
        if (dev.isEmpty()) {
            dev = Text.t("Устройство", "Device");
        }
        byte[] secret = Family.newSecret();
        String invite;
        synchronized (lock) {
            String me = Json.str(fam(), "me");
            if (me.isEmpty()) {
                throw new Family.FamilyError(Text.t("Сначала напиши, как тебя подписать (например, «Сын»).", "First type how to sign you (for example, “Son”)."));
            }
            if (famList("devices").size() >= 20) {
                throw new Family.FamilyError(Text.t("В семье уже 20 устройств — убери ненужные.", "The family already has 20 devices — remove the ones you don't need."));
            }
            invite = Family.makeInvite(me, dev, secret);
            Json.list(fam(), "devices").add(Json.obj("pair", Family.pairId(secret), "name", dev, "secret", Family.b64u(secret),
                    "since", System.currentTimeMillis() / 1000, "seq_in", 0L, "seq_out", 0L, "snap", null, "snap_at", 0L,
                    "sent", new ArrayList<Object>(), "invite", invite));
        }
        saveSettings();
        log("Семья: приглашение для «" + dev + "» готово.", "Family: the invitation for “" + dev + "” is ready.");
        changed();
        return Json.obj("pair", Family.pairId(secret), "text", invite);
    }

    /** Приглашение или посылка: посылку от помощника в режиме «спрашивать» только запоминает, в режиме
     *  «применять сразу» — применяет. */
    public Map<String, Object> familyReceive(String text) {
        String tx = text == null ? "" : text.length() > 200000 ? text.substring(0, 200000) : text;
        Map<String, Object> inv = Family.parseInvite(tx);
        if (inv != null) {
            String pair = Family.pairId((byte[]) inv.get("secret"));
            Object[] f = famFind(pair);
            if (f != null && "devices".equals(f[0])) {
                throw new Family.FamilyError(Text.t("Это твоё же приглашение — его нужно отправить тому, кого подключаешь.",
                        "This is your own invitation — send it to the person you are connecting."));
            }
            return Json.obj("kind", "invite", "helper", inv.get("helper"), "device", inv.get("device"), "pair", pair, "known", f != null);
        }
        Map<String, Object> pk = Family.peek(tx);
        if (pk == null) {
            throw new Family.FamilyError(Text.t("Здесь нет приглашения или посылки «Семьи».", "There is no Family invitation or package here."));
        }
        String pair = Json.str(pk, "pair");
        int direction = (int) Json.num(pk, "direction", 0);
        long seq = Json.num(pk, "seq", 0);
        Object[] f = famFind(pair);
        if (f == null || (direction == Family.TO_DEVICE) != "helpers".equals(f[0])) {
            throw new Family.FamilyError(Text.t("Эта посылка не для этого устройства (или его убрали из семьи).",
                    "This package is not for this device (or it was removed from the family)."));
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> ent = (Map<String, Object>) f[1];
        Map<String, Object> payload = Family.open(Family.unb64u(Json.str(ent, "secret")), (byte[]) pk.get("raw"));
        if (seq <= Json.num(ent, "seq_in", 0)) {
            return Json.obj("kind", "old", "name", Json.str(ent, "name"));
        }
        if (Json.num(payload, "exp", 0) < System.currentTimeMillis() / 1000) {
            throw new Family.FamilyError(Text.t("Посылка устарела (ей больше недели) — попроси прислать заново.",
                    "The package is outdated (older than a week) — ask to send it again."));
        }
        if (direction == Family.TO_HELPER) {
            ent.put("seq_in", seq);
            return famReport(ent, payload);
        }
        List<Map<String, Object>> ops = Family.checkOps(payload.get("ops"));
        boolean auto;
        synchronized (lock) {
            ent.put("seq_in", seq);
            ent.put("pending", Json.obj("ops", new ArrayList<Object>(ops), "at", Json.num(payload, "at", 0), "seq", seq));
            ent.put("reply", "");
            auto = "auto".equals(Json.str(ent, "mode"));
        }
        saveSettings();
        log("Семья: " + Json.str(ent, "name") + " прислал(а) настройки — изменений: " + ops.size() + ".",
                "Family: " + Json.str(ent, "name") + " sent settings — changes: " + ops.size() + ".");
        if (auto) {
            familyApplyTask(pair);
        }
        changed();
        return Json.obj("kind", "packet", "pair", pair, "from", Json.str(ent, "name"), "summary", Family.summary(ops), "auto", auto);
    }

    public Map<String, Object> familyAccept(String text, String mode) {
        Map<String, Object> inv = Family.parseInvite(text);
        if (inv == null) {
            throw new Family.FamilyError(Text.t("Здесь нет приглашения «Семьи».", "There is no Family invitation here."));
        }
        byte[] secret = (byte[]) inv.get("secret");
        String pair = Family.pairId(secret);
        Map<String, Object> ent = Json.obj("pair", pair, "name", inv.get("helper"), "secret", Family.b64u(secret),
                "mode", "auto".equals(mode) ? "auto" : "ask", "since", System.currentTimeMillis() / 1000, "seq_in", 0L, "seq_out", 0L,
                "pending", null, "reply", "", "device", inv.get("device"));
        synchronized (lock) {
            List<Object> l = Json.list(fam(), "helpers");
            for (Map<String, Object> h : famList("helpers")) {
                if (pair.equals(Json.str(h, "pair"))) {
                    l.remove(h);
                }
            }
            l.add(ent);
        }
        log("Семья: «" + inv.get("helper") + "» теперь может настраивать VPN на этом устройстве.",
                "Family: “" + inv.get("helper") + "” can now set up the VPN on this device.");
        ent.put("reply", famReply(ent, Json.arr(Json.obj("op", "hello", "ok", true)), false));
        saveSettings();
        changed();
        return Json.obj("pair", pair, "reply", Json.str(ent, "reply"));
    }

    public void familySetMode(String pair, String mode) {
        Object[] f = famFind(pair);
        if (f == null || !"helpers".equals(f[0])) {
            throw new Family.FamilyError(Text.t("Помощник не найден.", "Helper not found."));
        }
        Json.map(f[1]).put("mode", "auto".equals(mode) ? "auto" : "ask");
        saveSettings();
        changed();
    }

    public void familyRemove(String pair) {
        Object[] f = famFind(pair);
        if (f == null) {
            return;
        }
        Map<String, Object> ent = Json.map(f[1]);
        synchronized (lock) {
            Json.list(fam(), (String) f[0]).remove(ent);
        }
        saveSettings();
        String n = Json.str(ent, "name");
        if ("devices".equals(f[0])) {
            log("Семья: «" + n + "» убран(а) из семьи.", "Family: “" + n + "” was removed from the family.");
        } else {
            log("Семья: «" + n + "» больше не может настраивать VPN на этом устройстве.", "Family: “" + n + "” can no longer set up the VPN on this device.");
        }
        changed();
    }

    public String familySend(String pair, Object rawOps) {
        Object[] f = famFind(pair);
        if (f == null || !"devices".equals(f[0])) {
            throw new Family.FamilyError(Text.t("Устройство не найдено.", "Device not found."));
        }
        Map<String, Object> ent = Json.map(f[1]);
        List<Map<String, Object>> ops = Family.checkOps(rawOps);
        long now = System.currentTimeMillis() / 1000;
        String text;
        synchronized (lock) {
            long seq = Json.num(ent, "seq_out", 0) + 1;
            ent.put("seq_out", seq);
            text = Family.seal(Family.unb64u(Json.str(ent, "secret")), Family.TO_DEVICE, seq,
                    Json.obj("t", "cmd", "at", now, "exp", now + Family.TTL, "from", Json.str(fam(), "me"), "ops", new ArrayList<Object>(ops)), null);
            List<Object> sent = Json.list(ent, "sent");
            if (sent == null) {
                sent = new ArrayList<Object>();
                ent.put("sent", sent);
            }
            sent.add(Json.obj("seq", seq, "at", now, "ops", new ArrayList<Object>(ops), "state", "sent"));
            while (sent.size() > 20) {
                sent.remove(0);
            }
        }
        saveSettings();
        log("Семья: посылка для «" + Json.str(ent, "name") + "» готова — изменений: " + ops.size() + ".",
                "Family: the package for “" + Json.str(ent, "name") + "” is ready — changes: " + ops.size() + ".");
        changed();
        return text;
    }

    public String familyDecline(String pair) {
        Object[] f = famFind(pair);
        if (f == null || !"helpers".equals(f[0]) || Json.map(Json.map(f[1]), "pending") == null) {
            throw new Family.FamilyError(Text.t("Нечего отклонять.", "Nothing to decline."));
        }
        Map<String, Object> ent = Json.map(f[1]);
        ent.put("pending", null);
        ent.put("reply", famReply(ent, Json.arr(Json.obj("op", "declined", "ok", false)), true));
        saveSettings();
        changed();
        return Json.str(ent, "reply");
    }

    public String familyReportText(String pair) {
        Object[] f = famFind(pair);
        if (f == null || !"helpers".equals(f[0])) {
            throw new Family.FamilyError(Text.t("Помощник не найден.", "Helper not found."));
        }
        Map<String, Object> ent = Json.map(f[1]);
        ent.put("reply", famReply(ent, new ArrayList<Object>(), false));
        saveSettings();
        return Json.str(ent, "reply");
    }

    public boolean familyApplyTask(final String pair) {
        Object[] f = famFind(pair);
        final String name = f == null ? "" : Json.str(Json.map(f[1]), "name");
        return runTask(Text.t("Семья: применяю настройки от «" + name + "»", "Family: applying settings from “" + name + "”"), "update",
                new Runnable() {
                    @Override
                    public void run() {
                        familyApply(pair);
                    }
                });
    }

    /** Применить посылку (из задачи), потом — ответ помощнику со снимком и итогом. */
    public void familyApply(String pair) {
        Object[] f = famFind(pair);
        Map<String, Object> ent = f == null ? null : Json.map(f[1]);
        Map<String, Object> pending = ent == null ? null : Json.map(ent, "pending");
        if (ent == null || !"helpers".equals(f[0]) || pending == null) {
            throw new Family.FamilyError(Text.t("Нечего устанавливать.", "Nothing to install."));
        }
        ent.put("pending", null);
        Lane lane = laneOf.get();
        if (lane != null) {
            lane.why = "настройки от «" + Json.str(ent, "name") + "» (Семья)";
        }
        boolean wasOn = isOn();
        boolean reconnect = false;
        List<Object> results = new ArrayList<Object>();
        List<String> refresh = new ArrayList<String>();
        for (Map<String, Object> op : opsOf(pending.get("ops"))) {
            checkStop();
            try {
                reconnect |= famApplyOp(op, refresh);
                results.add(Json.obj("op", Json.str(op, "op"), "ok", true));
            } catch (RuntimeException e) {
                String m = e.getMessage() == null ? e.toString() : e.getMessage();
                results.add(Json.obj("op", Json.str(op, "op"), "ok", false, "error", Text.shorten(m, 200)));
                log("Семья: «" + Json.str(op, "op") + "» не получилось: " + m, "Family: “" + Json.str(op, "op") + "” failed: " + m);
            }
        }
        for (String id : refresh) { // новые подписки — загрузить и проверить здесь же, в этой задаче
            refreshOne(id);
        }
        if (!refresh.isEmpty()) {
            testServers(false);
        }
        int ok = 0;
        for (Object r : results) {
            ok += Json.bool(Json.map(r), "ok", false) ? 1 : 0;
        }
        log("Семья: применено " + ok + " из " + results.size() + " изменений от «" + Json.str(ent, "name") + "».",
                "Family: applied " + ok + " of " + results.size() + " changes from “" + Json.str(ent, "name") + "”.");
        if (reconnect && wasOn) {
            if (isOn()) {
                pendingApply = true; // ядро перезапустится после задачи с новыми настройками
            } else {
                connect();
            }
        }
        ent.put("applied_seq", Json.num(pending, "seq", 0));
        ent.put("reply", famReply(ent, results, false));
        saveSettings();
        say(Text.t("Настройки от «" + Json.str(ent, "name") + "» установлены: " + ok + " из " + results.size() + ".",
                "Settings from “" + Json.str(ent, "name") + "” are installed: " + ok + " of " + results.size() + "."), "ok");
        changed();
    }

    /** Одно изменение. true — нужно переподключить VPN. */
    private boolean famApplyOp(Map<String, Object> op, List<String> refresh) {
        String kind = Json.str(op, "op");
        switch (kind) {
            case "sub_add": {
                String url;
                try {
                    url = Subscription.normalizeUrl(Json.str(op, "url"));
                } catch (Subscription.SubError e) {
                    throw new UserError(e.getMessage());
                }
                String id = Text.sha1hex(url).substring(0, 8);
                synchronized (lock) {
                    if (sub(id) == null) {
                        Json.list(settings, "subscriptions").add(Json.obj("id", id, "url", url,
                                "name", Text.shorten(Json.str(op, "name").trim(), 80), "title", "", "usage", Json.obj(),
                                "error", "", "fetched", 0L, "count", 0L));
                    }
                }
                saveSettings();
                refresh.add(id);
                return true;
            }
            case "sub_remove": {
                String found = null;
                for (Map<String, Object> m : subs()) {
                    if (Json.str(m, "id").equals(Json.str(op, "id")) || (!Json.str(op, "url").isEmpty() && Json.str(m, "url").equals(Json.str(op, "url")))) {
                        found = Json.str(m, "id");
                    }
                }
                if (found == null) {
                    throw new UserError(Text.t("подписки уже нет", "the subscription is already gone"));
                }
                removeSubscription(found);
                return true;
            }
            case "sub_update":
                for (Map<String, Object> m : subs()) {
                    refresh.add(Json.str(m, "id"));
                }
                return true;
            case "servers_add":
                addServersQuiet(Json.str(op, "text"));
                return true;
            case "server_remove": {
                Server found = null;
                synchronized (lock) {
                    for (Server x : servers) {
                        if (x.subId.isEmpty() && Family.serverId(x.link).equals(Json.str(op, "id"))) {
                            found = x;
                        }
                    }
                }
                if (found == null) {
                    throw new UserError(Text.t("сервера уже нет", "the server is already gone"));
                }
                removeServer(found.key());
                return true;
            }
            case "method": {
                String m = Json.str(op, "method");
                setMethod(m);
                if ("off".equals(m) && isOn()) {
                    disconnect();
                }
                return !"off".equals(m);
            }
            case "set": {
                Map<String, Object> vals = Json.map(op, "values");
                boolean again = false;
                if (vals.containsKey("block_ads")) {
                    setAds(Json.obj("block_ads", vals.get("block_ads")));
                }
                if (vals.containsKey("dns_encrypted")) {
                    setSettings(Json.obj("dns_encrypted", vals.get("dns_encrypted")));
                    again = true;
                }
                if (vals.containsKey("accel")) {
                    setDpi(Json.obj("dpi_enabled", vals.get("accel")));
                }
                return again;
            }
            case "reconnect":
                return true;
            case "warp_create":
                createWarp();
                return false;
            default:
                return false; // report — ответ и так придёт со снимком
        }
    }

    private Map<String, Object> famSnapshot() {
        List<Object> subsOut = new ArrayList<Object>();
        List<Object> manual = new ArrayList<Object>();
        String status;
        String server;
        synchronized (lock) {
            for (Map<String, Object> m : subs()) {
                int n = 0;
                for (Server x : servers) {
                    if (Json.str(m, "id").equals(x.subId)) {
                        n++;
                    }
                }
                String name = Json.str(m, "name").isEmpty() ? Json.str(m, "title") : Json.str(m, "name");
                subsOut.add(Json.obj("id", Json.str(m, "id"), "name", name, "url", Json.str(m, "url"), "n", n,
                        "err", !Json.str(m, "error").isEmpty()));
            }
            for (Server x : servers) {
                if (x.subId.isEmpty() && manual.size() < 60) {
                    manual.add(Json.obj("id", Family.serverId(x.link), "name", x.name, "kind", "awg".equals(x.engine) ? "awg" : "server"));
                }
            }
            status = "on".equals(status()) ? "on" : "off";
            server = current != null && "on".equals(status) ? current.name : "";
        }
        List<Object> probs = new ArrayList<Object>();
        synchronized (lock) {
            for (Map<String, Object> p : problems.values()) {
                if (probs.size() < 6) {
                    probs.add(Json.str(p, "title"));
                }
            }
        }
        return Json.obj("app", "android", "ver", p.appVersion(), "status", status, "server", server, "method", method(),
                "subs", subsOut, "manual", manual,
                "set", Json.obj("block_ads", Json.bool(settings, "block_ads", false), "dns_encrypted", Json.bool(settings, "dns_encrypted", false),
                        "accel", Json.bool(settings, "dpi_enabled", true)),
                "accel_ok", true, "problems", probs);
    }

    private String famReply(Map<String, Object> ent, List<Object> results, boolean declined) {
        long now = System.currentTimeMillis() / 1000;
        long seq;
        synchronized (lock) {
            seq = Json.num(ent, "seq_out", 0) + 1;
            ent.put("seq_out", seq);
        }
        return Family.seal(Family.unb64u(Json.str(ent, "secret")), Family.TO_HELPER, seq,
                Json.obj("t", "report", "at", now, "exp", now + Family.TTL, "snap", famSnapshot(), "results", results,
                        "applied", Json.num(ent, "applied_seq", 0), "declined", declined, "device", Json.str(ent, "device")), null);
    }

    private Map<String, Object> famReport(Map<String, Object> ent, Map<String, Object> payload) {
        Map<String, Object> snap = Json.map(payload, "snap");
        synchronized (lock) {
            if (snap != null) {
                ent.put("snap", snap);
                ent.put("snap_at", Json.num(payload, "at", System.currentTimeMillis() / 1000));
                ent.put("invite", "");
            }
            List<Object> results = Json.list(payload, "results");
            List<Object> sent = Json.list(ent, "sent");
            boolean hello = false;
            if (results != null) {
                for (Object r : results) {
                    hello |= "hello".equals(Json.str(Json.map(r), "op"));
                }
            }
            if (sent != null && !sent.isEmpty() && results != null && !results.isEmpty() && !hello) {
                Map<String, Object> last = Json.map(sent.get(sent.size() - 1));
                if (Json.bool(payload, "declined", false)) {
                    last.put("state", "declined");
                } else {
                    List<Object> errs = new ArrayList<Object>();
                    for (Object r : results) {
                        if (!Json.bool(Json.map(r), "ok", false)) {
                            errs.add(Text.shorten(Json.str(Json.map(r), "error"), 200));
                        }
                    }
                    last.put("state", errs.isEmpty() ? "applied" : errs.size() == results.size() ? "failed" : "partial");
                    last.put("errors", errs);
                }
            }
        }
        saveSettings();
        log("Семья: пришло состояние «" + Json.str(ent, "name") + "».", "Family: the state of “" + Json.str(ent, "name") + "” arrived.");
        changed();
        return Json.obj("kind", "report", "pair", Json.str(ent, "pair"), "name", Json.str(ent, "name"));
    }

    // ---------- бесплатный WARP ----------

    /** Куда регистрировать WARP (самопроверка подставляет свою имитацию Cloudflare). */
    public static String[] WARP_BASES = null;

    private String[] warpBases() {
        if (WARP_BASES != null) {
            return WARP_BASES;
        }
        String[] out = new String[Warp.API_HOSTS.length];
        for (int i = 0; i < out.length; i++) {
            out[i] = "https://" + Warp.API_HOSTS[i];
        }
        return out;
    }

    /** Свой WARP (созданный кнопкой), если есть. */
    public Server ownWarp() {
        synchronized (lock) {
            for (Server s : servers) {
                if ("awg".equals(s.engine) && s.subId.isEmpty() && Warp.NAME.equals(s.name)) {
                    return s;
                }
            }
        }
        return null;
    }

    /** Кнопка «Создать бесплатный WARP»: регистрация (через VPN, если он включён, иначе напрямую) — в фоне. */
    public boolean warpCreateTask() {
        return runTask(Text.t("Создаю бесплатный WARP", "Creating a free WARP"), "update", new Runnable() {
            @Override
            public void run() {
                createWarp();
                setMethod("awg");
                say(Text.t("WARP создан. Сохрани файл конфига и импортируй его в AmneziaWG.",
                        "WARP is created. Save the config file and import it into AmneziaWG."), "ok");
            }
        });
    }

    public Server createWarp() {
        List<Integer> routes = new ArrayList<Integer>();
        if (isOn() && appPort > 0) {
            routes.add(appPort);
        }
        routes.add(0);
        Map<String, Object> acct = null;
        java.util.Set<String> kinds = new java.util.HashSet<String>();
        for (int port : routes) {
            for (String base : warpBases()) {
                checkStop();
                progress(port > 0 ? Text.t("Регистрирую WARP у Cloudflare через VPN", "Registering WARP with Cloudflare through the VPN")
                        : Text.t("Регистрирую WARP у Cloudflare", "Registering WARP with Cloudflare"));
                try {
                    acct = Warp.register(base, port, "Android", null);
                    break;
                } catch (Warp.WarpError e) {
                    kinds.add(e.kind);
                    log((port > 0 ? "WARP: регистрация через VPN не удалась (" : "WARP: регистрация напрямую не удалась (") + e.getMessage() + ").",
                            (port > 0 ? "WARP: registration through the VPN failed (" : "WARP: direct registration failed (") + e.getMessage() + ").");
                }
            }
            if (acct != null) {
                break;
            }
        }
        if (acct == null) {
            if (kinds.contains("limit")) {
                throw new UserError(Text.t("Cloudflare сейчас не даёт создать WARP: слишком много регистраций с твоего адреса. Попробуй через полчаса.",
                        "Cloudflare will not create a WARP right now: too many registrations from your address. Try again in half an hour."));
            }
            if (routes.size() > 1) {
                throw new UserError(Text.t("Не получилось связаться с Cloudflare ни через VPN, ни напрямую. Попробуй позже.",
                        "Could not reach Cloudflare either through the VPN or directly. Try again later."));
            }
            throw new UserError(Text.t("Не получилось связаться с Cloudflare: в твоей сети регистрацию WARP, похоже, блокируют. "
                            + "Включи на минуту любой VPN-сервер и нажми снова — регистрация пройдёт через него. Или вставь готовый конфиг WARP через «+».",
                    "Could not reach Cloudflare: WARP registration seems to be blocked in your network. Turn on any VPN server for a minute "
                            + "and press again — registration will go through it. Or paste a ready WARP config with “+”."));
        }
        String conf = Warp.buildConf(acct, Warp.preset((int) Json.num(settings, "warp_preset", 0)));
        Server srv;
        try {
            srv = Links.parseLink(Links.awgLink(conf, Warp.NAME));
        } catch (Links.LinkError e) {
            throw new UserError(Text.t("Конфиг WARP не сохранился.", "The WARP config was not saved."));
        }
        synchronized (lock) {
            Server old = ownWarp();
            if (old != null) {
                servers.remove(old);
                manualLinks().remove(old.link);
            }
            servers.add(srv);
            manualLinks().add(srv.link);
            settings.put("last_awg_key", srv.key());
        }
        saveSettings();
        saveServers();
        log("Создан бесплатный WARP (ключи созданы на этом телефоне).", "A free WARP was created (the keys were made on this phone).");
        changed();
        return srv;
    }

    /** «Другие обманки»: тот же WARP со следующим набором обманок (на телефоне туннель включает AmneziaWG,
     *  поэтому выбирает человек: не подключилось — следующий набор, файл заново в AmneziaWG). */
    public Map<String, Object> warpNext(String key) {
        Server s = find(key);
        if (s == null || !"awg".equals(s.engine) || !Warp.isWarp(s.awgConf) || !s.subId.isEmpty()) {
            throw new UserError(Text.t("Это не свой конфиг WARP.", "This is not your own WARP config."));
        }
        int idx = (int) Json.num(settings, "warp_preset", 0) + 1;
        Map<String, Object> p = Warp.preset(idx);
        Server fresh;
        try {
            fresh = Links.parseLink(Links.awgLink(Warp.variant(s.awgConf, p), s.name));
        } catch (Links.LinkError e) {
            throw new UserError(Text.t("Конфиг WARP не сохранился.", "The WARP config was not saved."));
        }
        synchronized (lock) {
            int at = servers.indexOf(s);
            servers.set(at < 0 ? 0 : at, fresh);
            List<Object> l = manualLinks();
            int li = l.indexOf(s.link);
            if (li >= 0) {
                l.set(li, fresh.link);
            } else {
                l.add(fresh.link);
            }
            settings.put("warp_preset", (long) (idx % Warp.PRESETS.length));
            settings.put("last_awg_key", fresh.key());
        }
        saveSettings();
        saveServers();
        log("WARP: другие обманки — «" + Json.str(p, "label") + "».", "WARP: other decoys — “" + Json.str(p, "label") + "”.");
        changed();
        Map<String, Object> info = awgInfo(fresh.key());
        info.put("label", Json.str(p, "label"));
        return info;
    }

    /** Конфиг AmneziaWG — в приложение AmneziaWG (на телефоне его включает оно само). */
    public Map<String, Object> awgInfo(String key) {
        Server s = key == null || key.isEmpty() ? null : find(key);
        if (s == null) {
            synchronized (lock) {
                String last = Json.str(settings, "last_awg_key");
                for (Server x : servers) {
                    if ("awg".equals(x.engine) && (s == null || x.key().equals(last))) {
                        s = x;
                    }
                }
            }
        }
        if (s == null || !"awg".equals(s.engine)) {
            throw new UserError(Text.t("Добавь конфиг AmneziaWG: «+» → вставь текст файла .conf или ключ vpn://.",
                    "Add an AmneziaWG config: “+” → paste the .conf file text or a vpn:// key."));
        }
        settings.put("last_awg_key", s.key());
        saveSettings();
        String file = s.name.replaceAll("[^A-Za-z0-9_-]+", "_").replaceAll("^_+|_+$", "");
        return Json.obj("key", s.key(), "name", s.name, "conf", s.awgConf, "note", s.note, "warp", Warp.isWarp(s.awgConf) && s.subId.isEmpty(),
                "file", (file.isEmpty() ? "vedomyj" : file.length() > 32 ? file.substring(0, 32) : file) + ".conf");
    }

    private static String netGroup(Server s) {
        String h = (s.pinnedIp != null && !s.pinnedIp.isEmpty() ? s.pinnedIp : s.address).toLowerCase(Locale.ROOT);
        if (h.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
            String[] parts = h.split("\\.");
            return parts[0] + "." + parts[1];
        }
        String[] parts = h.split("\\.");
        return parts.length >= 2 ? parts[parts.length - 2] + "." + parts[parts.length - 1] : h;
    }

    private static String hostOf(Server s) {
        return (s.pinnedIp != null && !s.pinnedIp.isEmpty() ? s.pinnedIp : s.address).toLowerCase(Locale.ROOT);
    }

    /** Проверить способы временными ядрами параллельно → те, через которые пошли данные (в порядке списка). */
    private List<Object[]> probeWays(final List<Object[]> cands) {
        final boolean[] ok = new boolean[cands.size()];
        final Lane lane = here();
        List<Future<?>> fs = new ArrayList<Future<?>>();
        for (int i = 0; i < cands.size(); i++) {
            final int k = i;
            final Server c = (Server) cands.get(i)[1];
            fs.add(pool.submit(new Runnable() {
                @Override
                public void run() {
                    if (lane.stop) {
                        return;
                    }
                    java.io.Closeable core = null;
                    try {
                        int port = freePort();
                        core = p.startTestCore(Json.write(XrayConfig.probeConfig(c, c.mask, p.coreVersion(), port)));
                        ok[k] = dataOk(port);
                    } catch (Exception e) {
                        ok[k] = false;
                    } finally {
                        if (core != null) {
                            try {
                                core.close();
                            } catch (Exception ignored) {
                                // уже остановлено
                            }
                        }
                    }
                }
            }));
        }
        waitAll(fs);
        checkStop();
        List<Object[]> out = new ArrayList<Object[]>();
        for (int i = 0; i < cands.size(); i++) {
            if (ok[i]) {
                out.add(cands.get(i));
            }
        }
        return out;
    }

    private void addWay(List<Object[]> to, java.util.Set<String> tried, String[] label, Server c) {
        String sig = c.key() + "|" + (c.fp == null ? "" : c.fp) + "|" + c.mask;
        if (tried.contains(sig)) {
            return;
        }
        String kind = wayKind(c);
        if (!kind.isEmpty() && !fuseOk(kind)) {
            if (tried.add("fuse|" + kind)) {
                log("Лестница: «" + kind + "» в этой сети на паузе (предохранитель) — пропускаю.",
                        "Ladder: “" + wayKindEn(kind) + "” is paused on this network (fuse) — skipping.");
            }
            return;
        }
        tried.add(sig);
        to.add(new Object[]{label, c});
    }

    /** Проверить группу способов (по 6), первый рабочий — подключить. */
    private boolean tryWays(String[] title, List<Object[]> cands) {
        for (int i = 0; i < cands.size(); i += 6) {
            checkStop();
            List<Object[]> batch = cands.subList(i, Math.min(cands.size(), i + 6));
            ladderStep = Text.t(title[0], title[1]);
            progress(Text.t("Ищу рабочий способ: ", "Looking for a working way: ") + ladderStep);
            List<Object[]> good = probeWays(batch);
            Map<String, Boolean> kinds = ladderKinds;
            if (kinds != null) {
                for (Object[] w : batch) {
                    String kind = wayKind((Server) w[1]);
                    if (!kind.isEmpty()) {
                        boolean ok = false;
                        for (Object[] g : good) {
                            ok |= g[1] == w[1];
                        }
                        kinds.put(kind, Boolean.TRUE.equals(kinds.get(kind)) || ok);
                    }
                }
            }
            if (good.isEmpty()) {
                log("Лестница: " + title[0] + " — данные не идут.", "Ladder: " + title[1] + " — no data flows.");
                continue;
            }
            for (Object[] got : good) {
                Server cand = (Server) got[1];
                String[] label = (String[]) got[0];
                Server real = find(cand.key());
                if (real == null) {
                    continue;
                }
                synchronized (lock) {
                    real.fp = cand.fp == null ? "" : cand.fp;
                    real.mask = cand.mask;
                }
                if (startWith(real)) {
                    ladderFuses();
                    String how = wayText(real);
                    log("Лестница: данные пошли — " + label[0] + ": " + real.name + (how.isEmpty() ? "." : " (" + how + ")."),
                            "Ladder: data flows — " + label[1] + ": " + real.name + (how.isEmpty() ? "." : " (" + how + ")."));
                    ladderSuccess(real, Text.t(label[0], label[1]));
                    return true;
                }
            }
        }
        return false;
    }

    private void ladderSuccess(Server s, String label) {
        ladderLast = Json.obj("at", System.currentTimeMillis(), "ok", true,
                "text", Text.t("данные пошли — ", "data flows — ") + label + (s == null ? "" : ": " + s.name));
        ladderFails = 0;
        ladderNext = 0;
        ladderStep = "";
        whatWorks = null;
        resolve("connect");
        rememberWay(s);
        changed();
    }

    /** Спуститься по лестнице способов. true — данные пошли. */
    boolean ladder() {
        Server cur;
        synchronized (lock) {
            cur = current;
        }
        boolean fpOn = Json.bool(settings, "fp_auto", true);
        boolean maskOn = Json.bool(settings, "mask_auto", true);
        java.util.Set<String> tried = new java.util.HashSet<String>();
        ladderKinds = new LinkedHashMap<String, Boolean>();
        List<Object[]> first = new ArrayList<Object[]>();
        Map<String, Object> mem = netWay();
        if (mem != null) {
            List<Map<String, Object>> ways = new ArrayList<Map<String, Object>>();
            ways.add(mem);
            ways.addAll(netAlts(mem));
            for (int i = 0; i < ways.size(); i++) {
                Map<String, Object> w = ways.get(i);
                Server ms = find(Json.str(w, "server"));
                if (ms != null && ms.usable()) {
                    addWay(first, tried, i == 0 ? new String[]{"память этой сети", "this network's memory"}
                                    : new String[]{"запасной путь этой сети", "this network's backup route"},
                            ms.withWay(Json.str(w, "fp"), Json.bool(w, "mask", false)));
                }
            }
        }
        if (cur != null) {
            addWay(first, tried, new String[]{"тот же сервер", "the same server"}, cur.withWay(cur.fp, cur.mask));
            if (fpOn && XrayConfig.fingerprintOf(cur.outbound) != null) {
                for (String fp : LADDER_FPS) {
                    if (!fp.equals(fpOf(cur))) {
                        addWay(first, tried, new String[]{"отпечаток " + fp, "fingerprint " + fp}, cur.withWay(fp, cur.mask));
                    }
                }
            }
            if (maskOn && !cur.mask) {
                addWay(first, tried, new String[]{"маскировка", "masking"}, cur.withWay(cur.fp, true));
            }
        }
        if (tryWays(new String[]{"тот же сервер и способы маскировки", "the same server and masking ways"}, first)) {
            return true;
        }
        if (cur != null) {
            List<Object[]> same = new ArrayList<Object[]>();
            synchronized (lock) {
                for (Server s : servers) {
                    if (s != cur && inPool(s) && hostOf(s).equals(hostOf(cur))) {
                        addWay(same, tried, new String[]{"другой вход", "another entry"}, s.withWay(s.fp, s.mask));
                    }
                }
            }
            if (tryWays(new String[]{"другой вход этого сервера", "another entry of this server"}, same)) {
                return true;
            }
        }
        final String curNet = cur == null ? "" : netGroup(cur);
        List<Server> backups = new ArrayList<Server>();
        for (Server s : ranked()) {
            if (s != cur) {
                backups.add(s);
            }
        }
        if (backups.size() < 8) {
            synchronized (lock) {
                for (Server s : servers) {
                    if (inPool(s) && s != cur && !backups.contains(s)) {
                        backups.add(s);
                    }
                }
            }
        }
        // стабильная сортировка: сначала другой транспорт (TCP ↔ UDP/QUIC), потом другая сеть, внутри — как были
        final String curTr = cur == null ? "" : transportOf(cur);
        List<Server> other = new ArrayList<Server>(backups);
        Collections.sort(other, new Comparator<Server>() {
            @Override
            public int compare(Server a, Server b) {
                int ta = !curTr.isEmpty() && transportOf(a).equals(curTr) ? 1 : 0;
                int tb = !curTr.isEmpty() && transportOf(b).equals(curTr) ? 1 : 0;
                if (ta != tb) {
                    return ta - tb;
                }
                int na = !curNet.isEmpty() && netGroup(a).equals(curNet) ? 1 : 0;
                int nb = !curNet.isEmpty() && netGroup(b).equals(curNet) ? 1 : 0;
                return na - nb;
            }
        });
        List<Object[]> rest = new ArrayList<Object[]>();
        for (Server s : other.subList(0, Math.min(8, other.size()))) {
            addWay(rest, tried, new String[]{"другой сервер", "another server"}, s.withWay(s.fp, s.mask));
        }
        return tryWays(new String[]{"другой сервер, другая сеть", "another server, another network"}, rest);
    }

    /** Ничего не помогло: что открывается напрямую и пауза перед следующей попыткой (2, 5, 10, 20 минут). */
    public void nothingWorks() {
        ladderFails++;
        long wait = LADDER_BACKOFF[Math.min(ladderFails, LADDER_BACKOFF.length) - 1];
        ladderNext = System.currentTimeMillis() + wait;
        ladderStep = "";
        progress(Text.t("Проверяю, что работает напрямую", "Checking what works directly"));
        final boolean[] ok = new boolean[WHAT_WORKS.length];
        List<Future<?>> fs = new ArrayList<Future<?>>();
        for (int i = 0; i < WHAT_WORKS.length; i++) {
            final int k = i;
            fs.add(pool.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        Http.Response r = Http.probe(WHAT_WORKS[k][1], null, 6000, 0, 4096);
                        ok[k] = r.status > 0 && r.status < 500;
                    } catch (Exception e) {
                        ok[k] = false;
                    }
                }
            }));
        }
        waitAll(fs);
        List<Object> items = new ArrayList<Object>();
        StringBuilder works = new StringBuilder();
        for (int i = 0; i < WHAT_WORKS.length; i++) {
            items.add(Json.obj("name", WHAT_WORKS[i][0], "ok", ok[i]));
            if (ok[i]) {
                works.append(works.length() == 0 ? "" : ", ").append(WHAT_WORKS[i][0]);
            }
        }
        ladderLast = Json.obj("at", System.currentTimeMillis(), "ok", false,
                "text", Text.t("ни один способ не помог", "no way helped"));
        whatWorks = Json.obj("time", System.currentTimeMillis(), "items", items, "retry_at", ladderNext,
                "hint", whitelistMode ? "wifi" : "");
        long mins = wait / 60000L;
        log("Лестница: ни один способ не помог. Напрямую работает: " + (works.length() == 0 ? "ничего" : works)
                        + ". Следующая попытка через " + mins + " мин.",
                "Ladder: no way helped. Works directly: " + (works.length() == 0 ? "nothing" : works)
                        + ". Next try in " + mins + " min.");
        problem("connect", Text.t("Нет связи через VPN", "No connection through VPN"),
                Text.t("Ни один сервер и способ не помог. Программа не переподключается по кругу и попробует снова через "
                                + mins + " мин. Можно взять другой интернет (Wi-Fi вместо мобильного) или обновить подписку.",
                        "No server or way helped. The app doesn't reconnect in circles and will try again in " + mins
                                + " min. You can use another internet (Wi-Fi instead of mobile) or refresh the subscription."));
        changed();
    }

    /** Кнопка «Попробовать сейчас». */
    public boolean ladderRetry() {
        return runTask(Text.t("Ищу рабочий способ", "Looking for a working way"), "connect", new Runnable() {
            @Override
            public void run() {
                ladderNext = 0;
                failover();
            }
        });
    }

    /** Сторож данных (из монитора): трафик через туннель уходит, а обратно не приходит 15 секунд. */
    private void dataWatch(boolean on, long now) {
        if (!on || !(p instanceof Traffic)) {
            lastRx = -1;
            silentSince = 0;
            return;
        }
        long[] t;
        try {
            t = ((Traffic) p).trafficBytes();
        } catch (RuntimeException e) {
            return;
        }
        if (lastRx >= 0) {
            long dRx = t[0] - lastRx;
            long dTx = t[1] - lastTx;
            if (dTx > 0 && dRx <= 0) {
                if (silentSince == 0) {
                    silentSince = now;
                }
            } else if (dRx > 0) {
                silentSince = 0;
            }
            if (dRx > 2048) {
                rxAt = now; // с сервера пришли данные — он жив (диспетчер)
            }
        }
        lastRx = t[0];
        lastTx = t[1];
        if (silentSince == 0 || now - silentSince < SILENT_MS || !Json.bool(settings, "data_watch", true)
                || !Json.bool(settings, "autopilot", true) || now - silentChecked < 60000L || now < ladderNext
                || connBusy()) {
            return;
        }
        silentChecked = now;
        final int port = appPort;
        pool.submit(new Runnable() {
            @Override
            public void run() {
                if (dataOk(port)) {
                    return;
                }
                log("Сторож данных: соединения открываются, а данные не приходят.",
                        "Data watch: connections open, but no data comes back.");
                if (isOn() && !connBusy()) {
                    runTask(Text.t("Переключаю сервер", "Switching server"), "connect", new Runnable() {
                        @Override
                        public void run() {
                            journalWhy(Text.t("данные через сервер не идут", "no data comes through the server"));
                            failover();
                        }
                    });
                }
            }
        });
    }

    /** Сеть сменилась: взять способ, который работал в ней. */
    void netChanged() {
        ispAt = 0;
        waySaved = "";
        rememberAt = 0;
        if (!isOn() || !Json.bool(settings, "net_memory", true) || connBusy()) {
            return;
        }
        runTask(Text.t("Сеть сменилась: беру то, что работало в ней", "Network changed: using what worked on it"), "connect",
                new Runnable() {
                    @Override
                    public void run() {
                        applyNetWay();
                    }
                });
    }

    void applyNetWay() {
        Map<String, Object> mem = netWay();
        Server cur;
        synchronized (lock) {
            cur = current;
        }
        if (mem == null || cur == null || !isOn()) {
            return;
        }
        if (dataFlowing() && !byUser()) {
            return; // подключение пережило смену сети и данные идут — не трогаем (диспетчер)
        }
        Server s = find(Json.str(mem, "server"));
        if (s == null || !s.usable()) {
            return;
        }
        String fp = Json.str(mem, "fp");
        boolean mask = Json.bool(mem, "mask", false);
        if (s == cur && fp.equals(cur.fp == null ? "" : cur.fp) && mask == cur.mask) {
            return;
        }
        List<Object[]> one = new ArrayList<Object[]>();
        one.add(new Object[]{new String[]{"память этой сети", "this network's memory"}, s.withWay(fp, mask)});
        if (probeWays(one).isEmpty()) {
            log("В этой сети раньше работал другой способ, но сейчас он не отвечает — оставляю текущий.",
                    "Another way used to work on this network, but it doesn't respond now — keeping the current one.");
            return;
        }
        synchronized (lock) {
            s.fp = fp;
            s.mask = mask;
        }
        if (startWith(s)) {
            log("Сеть сменилась: в ней работал «" + s.name + "» — переключился.",
                    "Network changed: \"" + s.name + "\" worked on it — switched.");
            rememberWay(s);
        } else if (cur != s) {
            startWith(cur);
        }
    }

    /** Подключиться способом из памяти этой сети (провайдер уже известен — без запроса в сеть). */
    private boolean tryNetMemory() {
        if (!Json.bool(settings, "net_memory", true) || System.currentTimeMillis() - ispAt >= 600000L) {
            return false;
        }
        Map<String, Object> mem = netWay();
        if (mem == null) {
            return false;
        }
        List<Map<String, Object>> ways = new ArrayList<Map<String, Object>>();
        ways.add(mem);
        ways.addAll(netAlts(mem));
        for (int i = 0; i < ways.size(); i++) {
            Map<String, Object> w = ways.get(i);
            Server s = find(Json.str(w, "server"));
            if (s == null || !s.usable() || !inPool(s)) {
                continue;
            }
            synchronized (lock) {
                s.fp = Json.str(w, "fp");
                s.mask = Json.bool(w, "mask", false);
            }
            journalWhy(i == 0 ? Text.t("в этой сети работал этот сервер", "this server worked in this network")
                    : Text.t("запасной путь из памяти этой сети", "a backup route from this network's memory"));
            if (startWith(s)) {
                return true;
            }
            log((i == 0 ? "Сервер" : "Запасной путь") + " из памяти сети не подключился.",
                    (i == 0 ? "The server" : "The backup route") + " from network memory didn't connect.");
        }
        return false;
    }

    /** После подключения: данные идут — запомнить сервер и способ для этой сети. */
    private void rememberCurrent() {
        Server s;
        synchronized (lock) {
            s = current;
        }
        if (s == null) {
            return;
        }
        if (!Json.bool(dataNow(), "ok", false) || !Json.bool(settings, "net_memory", true) || s != current) {
            return;
        }
        String id = netId();
        if (!id.isEmpty() && !waySaved.equals(id + "|" + s.key() + "|" + s.fp + "|" + s.mask)) {
            rememberWay(s);
        }
    }

    // ---------- белые списки ----------

    /** «whitelist» — открываются только разрешённые российские сайты; «open» — интернет открыт; «offline». */
    String whitelistProbe() {
        final String[] urls = new String[WL_ALLOWED.length + WL_FOREIGN.length];
        System.arraycopy(WL_ALLOWED, 0, urls, 0, WL_ALLOWED.length);
        System.arraycopy(WL_FOREIGN, 0, urls, WL_ALLOWED.length, WL_FOREIGN.length);
        final boolean[] ok = new boolean[urls.length];
        List<Future<?>> fs = new ArrayList<Future<?>>();
        for (int i = 0; i < urls.length; i++) {
            final int k = i;
            fs.add(pool.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        Map<String, String> h = new HashMap<String, String>();
                        h.put("User-Agent", "Mozilla/5.0 (Linux; Android 14) VedomyjVPN");
                        Http.Response r = Http.request(urls[k], h, 6000, 0, 0);
                        ok[k] = r.status > 0 && r.status < 500;
                    } catch (Exception e) {
                        ok[k] = false;
                    }
                }
            }));
        }
        for (Future<?> f : fs) {
            try {
                f.get(15, TimeUnit.SECONDS);
            } catch (Exception ignored) {
                // считаем как «не открылось»
            }
        }
        boolean allowed = false;
        boolean foreign = false;
        for (int i = 0; i < urls.length; i++) {
            if (i < WL_ALLOWED.length) {
                allowed |= ok[i];
            } else {
                foreign |= ok[i];
            }
        }
        if (foreign) {
            return "open";
        }
        return allowed ? "whitelist" : "offline";
    }

    /** true — включены белые списки. */
    boolean checkWhitelist() {
        String state = whitelistProbe();
        boolean wl = "whitelist".equals(state);
        if (wl != whitelistMode) {
            whitelistMode = wl;
            if (wl) {
                log("Похоже, включены «белые списки»: открываются только разрешённые российские сайты. "
                                + "Пробую серверы для обхода белых списков.",
                        "Whitelists seem active: only allowed Russian sites open. Trying whitelist servers.");
            } else {
                log("Белые списки больше не действуют.", "Whitelists are no longer active.");
            }
        }
        return wl;
    }

    private boolean tryWhitelist() {
        List<Server> wl = new ArrayList<Server>();
        synchronized (lock) {
            for (Server s : servers) {
                if (inPool(s) && s.isWl() && s != current) {
                    wl.add(s);
                }
            }
        }
        if (wl.isEmpty()) {
            problem("whitelist", Text.t("Включены белые списки", "Whitelists are active"),
                    Text.t("Обычные серверы сейчас не работают. Нужен сервер для обхода белых списков — "
                                    + "спроси у провайдера подписки (в названии обычно «белые списки» или «БС»).",
                            "Regular servers don't work now. You need a whitelist bypass server — ask your provider "
                                    + "(usually named \"white list\" or \"WL\")."));
            return false;
        }
        testList(wl);
        List<Server> ok = new ArrayList<Server>();
        for (Server s : ranked()) {
            if (wl.contains(s)) {
                ok.add(s);
            }
        }
        for (Server s : ok) {
            if (startWith(s)) {
                synchronized (lock) {
                    s.whitelist = true;
                }
                resolve("whitelist");
                return true;
            }
        }
        return false;
    }

    // ---------- фоновые проверки ----------

    /** Фоновая проверка (раз в 5 секунд). */
    public void monitor() {
        tick++;
        long now = System.currentTimeMillis();
        guardTick();
        collectTick();
        if (tick == SAFE_OK_MS / TICK_MS) {
            safeStartOk();
        }
        boolean on = isOn();
        if (connBusy()) {
            return; // ядро как раз перезапускается — это не сбой
        }
        if (on || filterOn()) {
            changed(); // скорость в уведомлении
        }
        if (on && !p.vpnAlive()) {
            onRevoked();
            return;
        }
        if (vpnUntil > 0 && now >= vpnUntil) {
            vpnUntil = 0;
            if (on) {
                log("Время VPN вышло — выключаю.", "VPN time is up — turning it off.");
                if (p instanceof Notices) {
                    ((Notices) p).notice("VEDOMYJ VPN", Text.t("Время VPN вышло — VPN выключен.", "VPN time is up — the VPN is off."));
                }
                disconnect();
                return;
            }
        }
        if (monitorExtras(on, now)) {
            return;
        }
        dataWatch(on, now);
        // Автопереход: связь проверяется раз в 20 секунд (после неудачи — сразу ещё раз, через 5 секунд).
        // Пока с сервера идут данные, он жив — лишних запросов не делаем (пинг на экране — раз в минуту).
        boolean flowing = dataFlowing();
        boolean due = healthFails > 0 || (tick % 4 == 0 && (!flowing || now - pingAt > 60000L));
        if (on && due) {
            long d = -1;
            try {
                d = p.coreDelay(XrayConfig.HEALTH_URL);
            } catch (Exception ignored) {
                d = -1;
            }
            synchronized (lock) {
                if (d > 0) {
                    healthFails = 0;
                    liveDelay = d;
                    pingAt = now;
                    resolve("connect");
                } else {
                    healthFails++;
                    liveDelay = -1;
                }
            }
            changed();
            // идёт видео или загрузка — проверка могла не пробиться сквозь неё: даём серверу больше попыток,
            // смена сервера оборвала бы всё, что сейчас качается
            int need = speedDown > 200 * 1024 ? 4 : 2;
            if (healthFails >= need && dataFlowing()) {
                synchronized (lock) {
                    healthFails = 0; // проверка не прошла, а данные с сервера идут — он работает
                }
            }
            String whyNot = healthFails >= need && Json.bool(settings, "autopilot", true) && now >= ladderNext ? maySwitch() : "";
            if (!whyNot.isEmpty()) {
                denyNote(whyNot); // например, тишина ещё меньше 30 с — перепроверка в следующий раз
                return;
            }
            if (d > 0 && waySaved.isEmpty() && now - rememberAt > 300000L) {
                rememberAt = now; // не чаще раза в 5 минут, пока не запомнили
                pool.submit(new Runnable() {
                    @Override
                    public void run() {
                        rememberCurrent();
                    }
                });
            }
            if (healthFails >= need && Json.bool(settings, "autopilot", true) && now < ladderNext) {
                synchronized (lock) {
                    healthFails = 0; // пауза после «ничего не работает»: без петли
                }
            } else if (healthFails >= need && Json.bool(settings, "autopilot", true)) {
                Server cur;
                synchronized (lock) {
                    cur = current;
                    healthFails = 0;
                }
                log("Сервер «" + (cur == null ? "" : cur.name) + "» перестал отвечать — ищу другой.",
                        "Server \"" + (cur == null ? "" : cur.name) + "\" stopped answering — looking for another.");
                runTask(Text.t("Переключаю сервер", "Switching server"), "connect", new Runnable() {
                    @Override
                    public void run() {
                        journalWhy(Text.t("сервер перестал отвечать", "the server stopped answering"));
                        failover();
                    }
                });
                return;
            }
        }
        // раздача: адрес точки доступа сменился — ядро слушает новый адрес
        if (on && shareOn && tick % 2 == 0) {
            String ip = p.hotspotIp();
            if (!ip.equals(shareIp)) {
                shareIp = ip;
                log(ip.isEmpty() ? "Точка доступа выключена — раздача ждёт её." : "Раздаю на адресе " + ip + ".",
                        ip.isEmpty() ? "Hotspot is off — sharing waits for it." : "Sharing on " + ip + ".");
                restartIfOn();
                return;
            }
        }
        // раздача перестала отвечать (точку доступа пересоздали, ядро потеряло адрес) — перезапустить ядро
        if (on && shareOn && !shareIp.isEmpty() && tick % 6 == 3) {
            int socks = (int) Json.num(settings, "share_socks_port", 10810);
            if (PORTS.open(shareIp, socks, 1500, null)) {
                shareFails = 0;
            } else if (++shareFails >= 2 && now - lastShareFix > 5 * 60000L) {
                shareFails = 0;
                lastShareFix = now;
                log("Раздача перестала отвечать — перезапускаю ядро.", "Sharing stopped responding — restarting the core.");
                restartIfOn();
                return;
            }
        }
        // белые списки закончились — вернуться на лучший обычный сервер (раз в 5 минут)
        if (on && whitelistMode && tick % 60 == 30) {
            final Server cur = current;
            if (cur != null && cur.isWl() && "open".equals(whitelistProbe())) {
                whitelistMode = false;
                log("Белые списки больше не действуют — возвращаюсь на лучший сервер.",
                        "Whitelists are over — going back to the best server.");
                runTask(Text.t("Переключаю сервер", "Switching server"), "connect", new Runnable() {
                    @Override
                    public void run() {
                        testServers(true);
                        List<Server> r = ranked();
                        if (!r.isEmpty() && r.get(0) != cur && !startWith(r.get(0))) {
                            startWith(cur);
                        }
                    }
                });
                return;
            }
        }
        if (bgBusy()) {
            return; // остальное — фоновые задачи; одна уже идёт, дождёмся её
        }
        if (monitorLate(on, now)) {
            return;
        }
        // подписки: раз в несколько часов
        long hours = Json.num(settings, "auto_update_hours", 12);
        if (hours > 0 && !subs().isEmpty() && lastSubUpdate == 0) {
            lastSubUpdate = now - hours * 3600000L + 120000L; // первое обновление — через 2 минуты после запуска
        }
        if (hours > 0 && !subs().isEmpty() && now - lastSubUpdate > hours * 3600000L) {
            lastSubUpdate = now;
            runTask(Text.t("Обновляю подписки", "Updating subscriptions"), "update", new Runnable() {
                @Override
                public void run() {
                    refreshAll();
                }
            });
            return;
        }
        // списки сайтов: раз в неделю
        long geo = Json.num(settings, "geo_updated", 0);
        if (now - geo > 7L * 24 * 3600000L && tick > 6) {
            settings.put("geo_updated", now - 6L * 24 * 3600000L); // при неудаче — снова через сутки
            runTask(Text.t("Обновляю списки сайтов", "Updating site lists"), "update", new Runnable() {
                @Override
                public void run() {
                    updateGeo();
                }
            });
            return;
        }
        // раз в час перепроверить серверы и перейти на заметно лучший
        if (on && now - lastTestAt > 3600000L && Json.bool(settings, "autopilot", true)) {
            runTask(Text.t("Проверяю серверы", "Testing servers"), "test", new Runnable() {
                @Override
                public void run() {
                    backToBest();
                }
            });
        }
    }

    void backToBest() {
        if (dataFlowing() && !byUser()) {
            return; // текущий сервер работает — к «лучшему» вернёмся, когда затихнет трафик
        }
        testServers(true);
        final Server cur;
        synchronized (lock) {
            cur = current;
        }
        if (cur == null || !Json.str(settings, "selected").isEmpty()) {
            return;
        }
        List<Server> r = ranked();
        if (r.isEmpty() || r.get(0) == cur) {
            return;
        }
        final Server best = r.get(0);
        Double bs = best.score();
        Double cs = cur.score();
        if (bs != null && (cs == null || (cs >= 150 && bs < cs * 0.6))) {
            log("Нашёлся сервер заметно быстрее — переключаюсь на «" + best.name + "».",
                    "Found a much faster server — switching to \"" + best.name + "\".");
            runTask(Text.t("Переключаю сервер", "Switching server"), "connect", new Runnable() {
                @Override
                public void run() {
                    if (isOn() && current == cur && !startWith(best)) {
                        startWith(cur);
                    }
                }
            });
        }
    }

    /** Списки заблокированных и российских сайтов (runetfreedom). */
    /** Обновить списки сайтов сейчас. */
    public void updateGeoNow() {
        runTask(Text.t("Обновляю списки сайтов", "Updating site lists"), "update", new Runnable() {
            @Override
            public void run() {
                updateGeo();
            }
        });
    }

    void updateGeo() {
        File dir = new File(p.dataDir(), "assets");
        dir.mkdirs();
        String[][] files = {{"geosite.dat", "100000"}, {"geoip.dat", "10000"}};
        for (final String[] f : files) {
            checkStop();
            final File tmp = new File(dir, f[0] + ".new");
            List<String> errs = new ArrayList<String>();
            // напрямую, через VPN, через другие серверы; на каждом пути — основной адрес и запасные.
            // Файл большой (десятки МБ) — качается сразу на диск, не в память
            boolean ok = downloadAny(new PortJob() {
                @Override
                public void run(int route) throws Exception {
                    IOException last = null;
                    for (String base : geoUrls()) {
                        try {
                            long size = Http.downloadTo(base + f[0], tmp, 120000, route, 400L * 1024 * 1024);
                            if (size < Long.parseLong(f[1])) {
                                throw new IOException(Text.t("файл пустой", "the file is empty"));
                            }
                            return;
                        } catch (IOException e) {
                            last = e;
                        }
                    }
                    throw last == null ? new IOException("no url") : last;
                }
            }, "Списки сайтов", "Site lists", errs);
            if (!ok) {
                tmp.delete();
                String err = errs.isEmpty() ? "" : String.join("; ", new LinkedHashSet<String>(errs));
                log("Не удалось скачать списки сайтов (" + f[0] + "): " + err, "Could not download site lists (" + f[0] + "): " + err);
                return;
            }
        }
        // оба файла скачались — заменяем вместе, чтобы ядро не получило новый geosite со старым geoip
        for (String[] f : files) {
            File dst = new File(dir, f[0]);
            File tmp = new File(dir, f[0] + ".new");
            dst.delete();
            if (!tmp.renameTo(dst)) {
                log("Не удалось сохранить списки сайтов.", "Could not save site lists.");
                return;
            }
        }
        settings.put("geo_updated", System.currentTimeMillis());
        log("Списки сайтов обновлены.", "Site lists updated.");
    }

    // ---------- раздача ----------

    /** Включить или выключить раздачу. ssid/pass — точка доступа приложения (если она есть). */
    public void setShare(boolean on, String kind, String ssid, String pass) {
        synchronized (lock) {
            shareOn = on;
            hotspotKind = on ? kind : "";
            hotspotSsid = on && ssid != null ? ssid : "";
            hotspotPass = on && pass != null ? pass : "";
            shareIp = on ? p.hotspotIp() : "";
        }
        log(on ? "Раздача включена." : "Раздача выключена.", on ? "Sharing is on." : "Sharing is off.");
        if (on && !isOn()) {
            connect();
        } else {
            restartIfOn();
        }
        changed();
    }

    public void newSharePassword() {
        settings.put("share_pass", Text.randomWord(8));
        saveSettings();
        if (shareOn) {
            restartIfOn();
        }
        changed();
    }

    // ---------- настройки ----------

    static final String[] BOOL_KEYS = {"ru_direct", "autopilot", "dns_encrypted", "block_ads", "mask_auto",
            "whitelist_auto", "ads_ask_sites", "sub_alerts", "encrypt_data", "app_lock", "net_profiles", "app_update", "block_quic", "cert_watch", "fp_auto",
            "data_watch", "net_memory", "fuses_enabled", "guard_rollback", "safe_start"};
    static final String[] RESTART_KEYS = {"mode", "ru_direct", "block_quic", "dns_encrypted", "block_ads", "proxy_list",
            "direct_list", "block_list", "excluded_apps"};

    static String guardLabel(Map<String, Object> keys, boolean en) {
        StringBuilder b = new StringBuilder();
        for (String k : keys.keySet()) {
            String ru;
            String eng;
            switch (k) {
                case "mode": ru = "режим маршрутизации"; eng = "routing mode"; break;
                case "ru_direct": ru = "российские сайты напрямую"; eng = "Russian sites direct"; break;
                case "block_quic": ru = "блокировка QUIC"; eng = "QUIC blocking"; break;
                case "dns_encrypted": ru = "шифрование DNS"; eng = "DNS encryption"; break;
                case "block_ads": ru = "без рекламы"; eng = "no ads"; break;
                case "mask_auto": ru = "маскировка"; eng = "masking"; break;
                case "fp_auto": ru = "подбор отпечатка"; eng = "fingerprint picking"; break;
                case "engine_pick": ru = "способ подключения"; eng = "connection method"; break;
                case "wl_priority": ru = "белые списки"; eng = "whitelists"; break;
                default: ru = k; eng = k;
            }
            b.append(b.length() > 0 ? ", " : "").append(en ? eng : ru);
        }
        return b.toString();
    }

    /** Сохранить настройки из интерфейса. Неизвестные и неверные значения пропускаются. */
    public void setSettings(Map<String, Object> in) {
        boolean restart = false;
        Map<String, Object> guardBefore = new LinkedHashMap<String, Object>();
        synchronized (lock) {
            for (String k : GUARDED_KEYS) {
                if (in.containsKey(k) && in.get(k) != null && !in.get(k).equals(settings.get(k))) {
                    guardBefore.put(k, settings.get(k));
                }
            }
        }
        if (in.containsKey("block_ads")) {
            // реклама — отдельно: при включении нужно скачать списки
            Map<String, Object> rest = new LinkedHashMap<String, Object>(in);
            setAds(Json.obj("block_ads", rest.remove("block_ads")));
            in = rest;
        }
        synchronized (lock) {
            for (Map.Entry<String, Object> e : in.entrySet()) {
                String k = e.getKey();
                Object v = e.getValue();
                Object old = settings.get(k);
                boolean ok = false;
                if (k.equals("mode")) {
                    ok = "smart".equals(v) || "vpn".equals(v);
                } else if (k.equals("theme")) {
                    ok = "auto".equals(v) || "dark".equals(v) || "light".equals(v);
                } else if (k.equals("lang")) {
                    ok = "ru".equals(v) || "en".equals(v);
                    if (ok) {
                        Text.lang = (String) v;
                    }
                } else if (k.equals("proxy_list") || k.equals("direct_list") || k.equals("block_list")
                        || k.equals("user_agent")) {
                    ok = v instanceof String && ((String) v).length() <= 200000;
                } else if (k.equals("excluded_apps")) {
                    List<Object> l = Json.list(v);
                    ok = l != null && l.size() <= 500;
                    if (ok) {
                        for (Object x : l) {
                            ok &= x instanceof String && ((String) x).matches("[A-Za-z0-9_.]{1,200}");
                        }
                    }
                } else if (k.equals("auto_update_hours")) {
                    ok = v instanceof Number && ((Number) v).longValue() >= 0 && ((Number) v).longValue() <= 24 * 30;
                } else if (k.equals("hint_shown")) {
                    ok = v instanceof Boolean;
                } else {
                    for (String b : BOOL_KEYS) {
                        if (b.equals(k)) {
                            ok = v instanceof Boolean;
                        }
                    }
                }
                if (!ok) {
                    continue;
                }
                settings.put(k, v);
                for (String r : RESTART_KEYS) {
                    if (r.equals(k) && (old == null ? v != null : !old.equals(v))) {
                        restart = true;
                    }
                }
            }
        }
        saveSettings();
        if (in.containsKey("encrypt_data")) {
            saveServers(); // серверы тоже перезаписать: зашифровать или наоборот
        }
        if (Boolean.FALSE.equals(in.get("fp_auto"))) {
            boolean had = false;
            synchronized (lock) { // подобранные отпечатки больше не нужны — как в ссылке
                for (Server sv : servers) {
                    had |= sv == current && !sv.fp.isEmpty();
                    sv.fp = "";
                }
            }
            saveServers();
            restart |= had;
        }
        if (restart) {
            if (!guardBefore.isEmpty() && isOn()) {
                guardChange(guardBefore, guardLabel(guardBefore, false), guardLabel(guardBefore, true));
            }
            applyCore();
        }
        changed();
    }

    // ---------- перенос настроек ----------

    public String exportSettings(boolean withSubs, boolean withServers) {
        synchronized (lock) {
            return Json.write(Share.export(settings, withSubs, withServers, p.appVersion()));
        }
    }

    /** Что внутри текста из QR-кода, файла или буфера обмена (ничего не меняет). */
    public Map<String, Object> importPreview(String text) {
        if (text != null && text.contains("vedomyj-family://")) {
            return Json.obj("kind", "family"); // приглашение или посылка «Семьи» — открывается в «Семье»
        }
        String kind = Share.kind(text);
        Map<String, Object> out = Json.obj("kind", kind);
        if (kind.equals("settings")) {
            Map<String, Object> parsed = Share.parse(Json.parse(text.trim()));
            out.put("settings", Json.map(parsed, "settings").size());
            out.put("subscriptions", Json.list(parsed, "subscriptions").size());
            out.put("servers", Json.list(parsed, "servers").size());
            out.put("skipped", Json.list(parsed, "skipped").size());
        } else if (kind.equals("servers")) {
            int n = 0;
            try {
                for (String line : Links.textToLinks(text)) {
                    if (Links.parseLink(line) != null) {
                        n++;
                    }
                }
            } catch (Links.LinkError e) {
                out.put("kind", "unknown");
                out.put("error", e.getMessage());
            }
            out.put("servers", n);
        } else if (kind.equals("subscription")) {
            try {
                out.put("url_ok", !Subscription.normalizeUrl(text).isEmpty());
            } catch (Subscription.SubError e) {
                out.put("kind", "unknown");
                out.put("error", e.getMessage());
            }
        }
        return out;
    }

    /** Применить текст из QR-кода, файла или буфера обмена. */
    public String importApply(String text) throws Exception {
        String kind = Share.kind(text);
        if (kind.equals("subscription")) {
            addSubscription(text, "");
            return Text.t("Подписка добавлена.", "Subscription added.");
        }
        if (kind.equals("servers")) {
            int n = addServers(text);
            return n > 0 ? Text.t("Добавлено серверов: " + n + ".", "Servers added: " + n + ".")
                    : Text.t("Эти серверы уже есть.", "These servers are already added.");
        }
        if (!kind.equals("settings")) {
            throw new UserError(Text.t("Не понял, что это. Нужна ссылка на подписку, ссылка на сервер или настройки VEDOMYJ VPN.",
                    "Not recognized. A subscription link, a server link or VEDOMYJ VPN settings are needed."));
        }
        Map<String, Object> parsed = Share.parse(Json.parse(text.trim()));
        Map<String, Object> all = new LinkedHashMap<String, Object>(Json.map(parsed, "settings"));
        Map<String, Object> ads = new LinkedHashMap<String, Object>();
        Map<String, Object> dpi = new LinkedHashMap<String, Object>();
        for (String k : new ArrayList<String>(all.keySet())) {
            if (k.equals("block_ads") || k.startsWith("ads_")) {
                ads.put(k, all.remove(k));
            } else if (k.startsWith("dpi_")) {
                dpi.put(k, all.remove(k));
            }
        }
        setSettings(all);
        if (!ads.isEmpty()) {
            setAds(ads);
        }
        if (!dpi.isEmpty()) {
            setDpi(dpi);
        }
        int subsAdded = 0;
        for (Object o : Json.list(parsed, "subscriptions")) {
            Map<String, Object> m = Json.map(o);
            try {
                String url = Subscription.normalizeUrl(Json.str(m, "url"));
                String id = Text.sha1hex(url).substring(0, 8);
                synchronized (lock) {
                    if (sub(id) == null) {
                        Json.list(settings, "subscriptions").add(Json.obj("id", id, "url", url,
                                "name", Json.str(m, "name"), "title", "", "usage", Json.obj(), "error", "",
                                "fetched", 0L, "count", 0L));
                        subsAdded++;
                    }
                }
            } catch (Subscription.SubError ignored) {
                // неверную подписку пропускаем
            }
        }
        StringBuilder links = new StringBuilder();
        for (Object o : Json.list(parsed, "servers")) {
            links.append(o).append('\n');
        }
        int serversAdded = links.length() > 0 ? addServersQuiet(links.toString()) : 0;
        saveSettings();
        if (subsAdded > 0 || serversAdded > 0) {
            // одной задачей: загрузить новые подписки и проверить все серверы
            refreshSubscriptions(true);
        }
        return Text.t("Настройки применены. Подписок добавлено: " + subsAdded + ", серверов: " + serversAdded + ".",
                "Settings applied. Subscriptions added: " + subsAdded + ", servers: " + serversAdded + ".");
    }

    // ---------- свой сервер ----------

    public void vpsSetup(final String host, final String port, final String user, final String password,
                         final String name) throws Vps.VpsError {
        final Object[] in = Vps.checkInput(host, port, user);
        if (password == null || password.isEmpty()) {
            throw new Vps.VpsError(Text.t("Впиши пароль от сервера (он в письме хостинга).",
                    "Enter the server password (it is in the hosting email)."));
        }
        final String label = name == null || name.trim().isEmpty() ? Text.t("Мой сервер", "My server") : name.trim();
        boolean started = runTask(Text.t("Подключаюсь к серверу", "Connecting to the server"), "vps", new Runnable() {
            @Override
            public void run() {
                final Vps.Progress pr = new Vps.Progress();
                try {
                    p.sshRun((String) in[0], (Integer) in[1], (String) in[2], password, Vps.script(), new LineSink() {
                        @Override
                        public void line(String s) {
                            if (pr.feed(s)) {
                                progress(Vps.step(pr.step));
                                log(Vps.step(pr.step), Vps.step(pr.step));
                            }
                        }
                    }, new Stop() {
                        @Override
                        public boolean stopped() {
                            return bg.stop;
                        }
                    });
                } catch (Cancelled c) {
                    throw c;
                } catch (Exception e) {
                    if (pr.error.isEmpty() && pr.result.isEmpty()) {
                        String m = e.getMessage() == null ? e.toString() : e.getMessage();
                        String low = m.toLowerCase();
                        if (low.contains("auth")) {
                            throw new UserError(Text.t("Сервер не принял пароль — проверь пароль и имя пользователя.",
                                    "The server rejected the password — check the password and the user name."));
                        }
                        if (pr.step.isEmpty()) {
                            throw new UserError(Text.t("Не удалось войти на сервер: ", "Could not log in to the server: ")
                                    + Text.shorten(m, 200));
                        }
                        throw new UserError(Text.t("Связь с сервером оборвалась во время установки — попробуй ещё раз.",
                                "The connection broke during installation — try again."));
                    }
                }
                checkStop();
                if (!pr.error.isEmpty()) {
                    throw new UserError(Text.t("Сервер не настроен: ", "The server is not set up: ") + Vps.error(pr.error));
                }
                if (pr.result.isEmpty()) {
                    throw new UserError(Text.t("Сервер не прислал результат — попробуй ещё раз.",
                            "The server sent no result — try again."));
                }
                List<String> links;
                try {
                    links = Vps.makeLinks((String) in[0], pr.result, label);
                } catch (Vps.VpsError e) {
                    throw new UserError(e.getMessage());
                }
                StringBuilder b = new StringBuilder();
                for (String l : links) {
                    b.append(l).append('\n');
                }
                int n;
                synchronized (lock) {
                    n = 0;
                    List<Object> ml = manualLinks();
                    for (String l : links) {
                        Server s = Links.parseLink(l);
                        if (s != null && !ml.contains(s.link)) {
                            ml.add(s.link);
                            servers.add(s);
                            n++;
                        }
                    }
                }
                vpsEntry((String) in[0], (Integer) in[1], (String) in[2], label);
                log("Свой сервер готов, добавлено входов: " + n + ".", "Your server is ready, entries added: " + n + ".");
                say(Text.t("Свой сервер готов и добавлен в список.", "Your server is ready and added to the list."), "ok");
                saveSettings();
                List<Server> mine = new ArrayList<Server>();
                synchronized (lock) {
                    for (Server s : servers) {
                        for (String l : links) {
                            if (l.equals(s.link)) {
                                mine.add(s);
                            }
                        }
                    }
                }
                progress(Text.t("Проверяю свой сервер", "Testing your server"));
                testList(mine);
            }
        });
        if (!started) {
            throw new Vps.VpsError(Text.t("Подожди, пока закончится текущая задача.", "Wait until the current task finishes."));
        }
    }

    // ---------- свой сервер: состояние и ключи для друзей ----------
    // Адрес, порт и имя для входа хранятся (зашифрованными), пароль — никогда: его вводят для каждого действия.

    static final int VPS_FRIENDS_MAX = 20;

    private static List<Object> vlist(Map<String, Object> m, String key) {
        List<Object> l = Json.list(m, key);
        return l == null ? new ArrayList<Object>() : l;
    }

    @SuppressWarnings("unchecked")
    private List<Object> vpsHosts() {
        Object v = settings.get("vps_hosts");
        if (!(v instanceof List)) {
            v = new ArrayList<Object>();
            settings.put("vps_hosts", v);
        }
        return (List<Object>) v;
    }

    private Map<String, Object> vpsEntry(String host, int port, String user, String name) {
        synchronized (lock) {
            for (Object o : vpsHosts()) {
                Map<String, Object> h = Json.map(o);
                if (h != null && host.equals(Json.str(h, "host")) && port == (int) Json.num(h, "port", 22)
                        && user.equals(Json.str(h, "user"))) {
                    if (name != null && !name.isEmpty()) {
                        h.put("name", name);
                    }
                    saveSettings();
                    return h;
                }
            }
            Map<String, Object> h = Json.obj("id", Text.randomWord(8), "host", host, "port", (long) port, "user", user,
                    "name", name == null || name.isEmpty() ? Text.t("Мой сервер", "My server") : name,
                    "friends", new ArrayList<Object>(), "status", new LinkedHashMap<String, Object>());
            vpsHosts().add(h);
            saveSettings();
            return h;
        }
    }

    private Map<String, Object> vpsFind(String id) {
        synchronized (lock) {
            for (Object o : vpsHosts()) {
                Map<String, Object> h = Json.map(o);
                if (h != null && id.equals(Json.str(h, "id"))) {
                    return h;
                }
            }
        }
        throw new UserError(Text.t("Этот сервер не найден — добавь его ещё раз.", "This server was not found — add it again."));
    }

    /** Свои серверы для экрана (ключи друзей сюда не входят — их отдаёт только QR-код). */
    public List<Object> vpsView() {
        List<Object> out = new ArrayList<Object>();
        synchronized (lock) {
            for (Object o : vpsHosts()) {
                Map<String, Object> h = Json.map(o);
                if (h == null) {
                    continue;
                }
                List<Object> fr = new ArrayList<Object>();
                for (Object f : vlist(h, "friends")) {
                    Map<String, Object> fm = Json.map(f);
                    fr.add(Json.obj("id", Json.str(fm, "id"), "name", Json.str(fm, "name"), "ts", Json.num(fm, "ts", 0)));
                }
                Map<String, Object> st = Json.map(h, "status");
                out.add(Json.obj("id", Json.str(h, "id"), "name", Json.str(h, "name"), "host", Json.str(h, "host"),
                        "status", st == null ? new LinkedHashMap<String, Object>() : st, "friends", fr));
            }
        }
        return out;
    }

    public String vpsFriendLink(String friendId) {
        synchronized (lock) {
            for (Object o : vpsHosts()) {
                for (Object f : vlist(Json.map(o), "friends")) {
                    Map<String, Object> fm = Json.map(f);
                    if (friendId.equals(Json.str(fm, "id")) && !vlist(fm, "links").isEmpty()) {
                        return String.valueOf(vlist(fm, "links").get(0));
                    }
                }
            }
        }
        throw new UserError(Text.t("Этот ключ уже удалён.", "This key is already deleted."));
    }

    /** Выполняет скрипт на своём сервере и возвращает строку PULT_RESULT. */
    private String vpsRun(Map<String, Object> h, String password, String body, String whatRu, String whatEn) {
        final Vps.Progress pr = new Vps.Progress();
        progress(Text.t("Подключаюсь к серверу", "Connecting to the server"));
        try {
            p.sshRun(Json.str(h, "host"), (int) Json.num(h, "port", 22), Json.str(h, "user"), password, body, new LineSink() {
                @Override
                public void line(String s) {
                    pr.feed(s);
                }
            }, new Stop() {
                @Override
                public boolean stopped() {
                    return bg.stop;
                }
            });
        } catch (Cancelled c) {
            throw c;
        } catch (Exception e) {
            if (pr.error.isEmpty() && pr.result.isEmpty()) {
                String m = e.getMessage() == null ? e.toString() : e.getMessage();
                if (m.toLowerCase().contains("auth")) {
                    throw new UserError(Text.t("Сервер не принял пароль — проверь пароль и имя пользователя.",
                            "The server rejected the password — check the password and the user name."));
                }
                throw new UserError(Text.t("Не удалось войти на сервер: ", "Could not log in to the server: ")
                        + Text.shorten(m, 200));
            }
        }
        checkStop();
        if (!pr.error.isEmpty()) {
            throw new UserError(Text.t(whatRu, whatEn) + ": " + Vps.error(pr.error));
        }
        if (pr.result.isEmpty()) {
            throw new UserError(Text.t("Сервер не прислал результат — попробуй ещё раз.", "The server sent no result — try again."));
        }
        return pr.result;
    }

    private Map<String, Object> vpsStatusOf(Map<String, Object> h, String password) {
        String result = vpsRun(h, password, Vps.statusScript(), "Состояние сервера не получено", "Could not get the server status");
        Map<String, Object> st;
        try {
            st = Vps.parseStatus(result);
        } catch (Vps.VpsError e) {
            throw new UserError(Text.t("Состояние сервера не получено: ", "Could not get the server status: ") + e.getMessage());
        }
        st.put("ts", System.currentTimeMillis() / 1000);
        return st;
    }

    private static void needPassword(String password) throws Vps.VpsError {
        if (password == null || password.isEmpty()) {
            throw new Vps.VpsError(Text.t("Впиши пароль от сервера (он в письме хостинга).",
                    "Enter the server password (it is in the hosting email)."));
        }
    }

    private void vpsTask(String titleRu, String titleEn, Runnable job) throws Vps.VpsError {
        if (!runTask(Text.t(titleRu, titleEn), "vps", job)) {
            throw new Vps.VpsError(Text.t("Подожди, пока закончится текущая задача.", "Wait until the current task finishes."));
        }
    }

    /** Запомнить уже настроенный сервер (например, настроенный раньше) и сразу проверить его состояние. */
    public void vpsAdd(String host, String port, String user, final String password, final String name) throws Vps.VpsError {
        final Object[] in = Vps.checkInput(host, port, user);
        needPassword(password);
        vpsTask("Свой сервер: проверка", "Own server: checking", new Runnable() {
            @Override
            public void run() {
                Map<String, Object> probe = Json.obj("host", in[0], "port", (long) (Integer) in[1], "user", in[2]);
                Map<String, Object> st = vpsStatusOf(probe, password);
                String label = name == null ? "" : name.trim();
                Map<String, Object> h = vpsEntry((String) in[0], (Integer) in[1], (String) in[2],
                        label.length() > 40 ? label.substring(0, 40) : label);
                synchronized (lock) {
                    h.put("status", st);
                }
                saveSettings();
                say(Text.t("Свой сервер добавлен.", "Your server is added."), "ok");
            }
        });
    }

    public void vpsStatus(final String id, final String password) throws Vps.VpsError {
        final Map<String, Object> h = vpsFind(id);
        needPassword(password);
        vpsTask("Свой сервер: проверка", "Own server: checking", new Runnable() {
            @Override
            public void run() {
                Map<String, Object> st = vpsStatusOf(h, password);
                synchronized (lock) {
                    h.put("status", st);
                }
                saveSettings();
                String name = Json.str(h, "name");
                if (!"active".equals(st.get("xray"))) {
                    log("Свой сервер «" + name + "»: Xray не работает. Запусти мастер настройки ещё раз.",
                            "Own server “" + name + "”: Xray is not running. Run the setup wizard again.");
                    say(Text.t("На сервере не работает Xray.", "Xray is not running on the server."), "error");
                } else {
                    log("Свой сервер «" + name + "» работает: подключений " + st.get("conns") + ", пользователей " + st.get("clients") + ".",
                            "Own server “" + name + "” works: " + st.get("conns") + " connections, " + st.get("clients") + " users.");
                    say(Text.t("Сервер работает.", "The server works."), "ok");
                }
            }
        });
    }

    /** Отдельный ключ для друга на своём сервере: его можно отозвать, не меняя свой. */
    public void vpsFriendAdd(final String id, final String password, final String friendName) throws Vps.VpsError {
        final Map<String, Object> h = vpsFind(id);
        needPassword(password);
        if (vlist(h, "friends").size() >= VPS_FRIENDS_MAX) {
            throw new Vps.VpsError(Text.t("Слишком много ключей для друзей — сначала удали ненужные.",
                    "Too many keys for friends — delete the ones you don't need first."));
        }
        String n = friendName == null ? "" : friendName.trim();
        final String name = n.isEmpty() ? Text.t("Друг", "Friend") : (n.length() > 30 ? n.substring(0, 30) : n);
        final String body = Vps.friendScript("add", "");
        vpsTask("Свой сервер: ключ для друга", "Own server: key for a friend", new Runnable() {
            @Override
            public void run() {
                String result = vpsRun(h, password, body, "Ключ для друга не создан", "The key for a friend was not created");
                List<String> links;
                String srv = Json.str(h, "name");
                try {
                    links = Vps.makeLinks(Json.str(h, "host"), result, (srv.isEmpty() ? "VPS" : srv) + " · " + name);
                } catch (Vps.VpsError e) {
                    throw new UserError(Text.t("Ключ для друга не создан: ", "The key for a friend was not created: ") + e.getMessage());
                }
                String fid = result.split("\\|", -1)[0];
                synchronized (lock) {
                    List<Object> fl = new ArrayList<Object>(links);
                    Object fr = h.get("friends");
                    if (!(fr instanceof List)) {
                        fr = new ArrayList<Object>();
                        h.put("friends", fr);
                    }
                    @SuppressWarnings("unchecked")
                    List<Object> friends = (List<Object>) fr;
                    friends.add(Json.obj("id", fid, "name", name, "ts", System.currentTimeMillis() / 1000, "links", fl));
                }
                saveSettings();
                lastVpsFriend = Json.obj("id", fid, "name", name);
                log("Свой сервер «" + srv + "»: создан ключ для «" + name + "».", "Own server “" + srv + "”: a key for “" + name + "” was created.");
                say(Text.t("Ключ для «" + name + "» готов — покажи другу QR-код.", "The key for “" + name + "” is ready — show your friend the QR code."), "ok");
            }
        });
    }

    public void vpsFriendRemove(final String id, final String password, final String friendId) throws Vps.VpsError {
        final Map<String, Object> h = vpsFind(id);
        needPassword(password);
        final String body = Vps.friendScript("remove", friendId);
        vpsTask("Свой сервер: удаляю ключ", "Own server: deleting a key", new Runnable() {
            @Override
            public void run() {
                vpsRun(h, password, body, "Ключ не удалён", "The key was not deleted");
                String name = "";
                synchronized (lock) {
                    Iterator<Object> it = vlist(h, "friends").iterator();
                    while (it.hasNext()) {
                        Map<String, Object> fm = Json.map(it.next());
                        if (friendId.equals(Json.str(fm, "id"))) {
                            name = Json.str(fm, "name");
                            it.remove();
                        }
                    }
                }
                saveSettings();
                String srv = Json.str(h, "name");
                log("Свой сервер «" + srv + "»: ключ «" + name + "» удалён — по нему больше не подключиться.",
                        "Own server “" + srv + "”: the key “" + name + "” was deleted — it can no longer connect.");
                say(Text.t("Ключ удалён.", "The key is deleted."), "ok");
            }
        });
    }

    /** Убрать сервер из списка (на самом сервере ничего не меняется). */
    public void vpsForget(String id) {
        vpsFind(id);
        synchronized (lock) {
            Iterator<Object> it = vpsHosts().iterator();
            while (it.hasNext()) {
                if (id.equals(Json.str(Json.map(it.next()), "id"))) {
                    it.remove();
                }
            }
        }
        saveSettings();
        changed();
    }

    private Map<String, Object> lastVpsFriend;

    /** Новые функции, которые на имитации не проверить: ключ телефона, блокировка, подпись обновлений, Wi-Fi, замирание. */
    private void checkProtection(Diagnostics d, Map<String, Object> dev, Map<String, Object> s, boolean on) {
        if (p instanceof Crypto) {
            try {
                String sample = "VEDOMYJ ✓ " + System.currentTimeMillis();
                if (sample.equals(((Crypto) p).open(((Crypto) p).seal(sample)))) {
                    d.ok("Шифрование ключом телефона работает", "Encryption with the phone key works",
                            Json.bool(s, "encrypt_data", true) ? Text.t("подписки хранятся зашифрованными", "subscriptions are stored encrypted")
                                    : Text.t("шифрование выключено в настройках", "encryption is off in settings"));
                } else {
                    d.error("Шифрование ключом телефона не сходится", "Encryption with the phone key does not round-trip", "");
                }
            } catch (Exception e) {
                d.error("Шифрование ключом телефона не работает", "Encryption with the phone key does not work", Diagnostics.msg(e));
            }
        }
        if (secureFailed) {
            d.warn("Сохранённые подписки не расшифровались", "Saved subscriptions could not be decrypted",
                    Text.t("Так бывает после переноса на другой телефон. Добавь подписки заново.",
                            "This happens after moving to another phone. Add the subscriptions again."));
        }
        if (Json.bool(s, "app_lock", false) && dev.containsKey("keyguard_secure") && !Json.bool(dev, "keyguard_secure", true)) {
            d.warn("Блокировка приложения не сработает", "App lock will not work",
                    Text.t("На телефоне нет блокировки экрана (отпечаток, PIN или графический ключ).",
                            "The phone has no screen lock (fingerprint, PIN or pattern)."));
        } else if (Json.bool(s, "app_lock", false)) {
            d.ok("Блокировка приложения включена", "App lock is on", "");
        }
        if (Update.selfCheck()) {
            d.ok("Проверка подписи обновлений работает", "Update signature check works", "");
        } else {
            d.error("Проверка подписи обновлений не работает", "Update signature check does not work",
                    Text.t("Обновления приложения ставиться не будут — пришли этот отчёт.", "App updates will not install — send this report."));
        }
        if (Json.bool(s, "app_update", true) && dev.containsKey("install_allowed") && !Json.bool(dev, "install_allowed", true)) {
            d.info("Установка обновлений ещё не разрешена", "Installing updates is not allowed yet",
                    Text.t("Android спросит разрешение при первом обновлении — разреши.", "Android will ask on the first update — allow it."));
        }
        if (p instanceof NetInfo) {
            Map<String, Object> ni = ((NetInfo) p).netInfo();
            String kind = Json.str(ni, "kind");
            if ("wifi".equals(kind)) {
                boolean open = Json.bool(ni, "open", false);
                d.ok(open ? "Wi-Fi без пароля распознан" : "Wi-Fi с паролем распознан",
                        open ? "Open Wi-Fi recognized" : "Password Wi-Fi recognized",
                        open ? Text.t("в такой сети всё идёт через VPN", "everything goes via VPN on such a network") : "");
            } else {
                d.info("Сейчас не Wi-Fi", "Not on Wi-Fi now", "cell".equals(kind) ? Text.t("мобильный интернет", "mobile data") : "");
            }
        }
        // защищённый DNS (им программа обходит блокировку адресов подписок, списков и серверов) и часы
        List<String> doh = Http.dohResolve("github.com", 6000);
        if (doh.isEmpty()) {
            d.warn("Защищённый DNS не отвечает", "Secure DNS doesn't answer",
                    Text.t("Если провайдер заблокирует адрес подписки в своём DNS, обойти это напрямую не выйдет — только через VPN.",
                            "If the provider blocks the subscription address in its DNS, only the VPN can get around it."));
        } else {
            d.ok("Защищённый DNS отвечает", "Secure DNS answers", "");
        }
        Long skew = clockSkew();
        if (skew != null) {
            if (Math.abs(skew) > CLOCK_MAX_SKEW_MS) {
                d.error("Часы на телефоне неточные", "The phone clock is wrong", Text.t("расхождение ", "off by ") + (skew / 1000)
                        + Text.t(" с — включи «Дата и время → Автоматически»", " s — turn on “Date & time → Automatic”"));
            } else {
                d.ok("Часы на телефоне точные", "The phone clock is accurate", Text.t("расхождение ", "off by ") + (skew / 1000)
                        + Text.t(" с", " s"));
            }
        }
        // замирание после ~16 КБ: так провайдеры режут часть зарубежных хостингов (общие адреса CDN, не личные)
        String[] hosts = {"speed.cloudflare.com", "cdn.jsdelivr.net"};
        for (String h : hosts) {
            checkStop();
            Map<String, Object> st = STALL.test(h, 0);
            String state = Json.str(st, "state");
            long kb = Json.num(st, "bytes", 0) / 1024;
            if ("stall".equals(state)) {
                Map<String, Object> sv = on ? STALL.test(h, appPort) : null;
                boolean vpnOk = sv != null && "ok".equals(Json.str(sv, "state"));
                d.info(h + Text.t(": провайдер режет (замирает после ", ": the ISP throttles it (stalls after ") + kb + Text.t(" КБ)", " KB)"),
                        h + ": the ISP throttles it (stalls after " + kb + " KB)",
                        sv == null ? Text.t("автоподбор уведёт такие адреса в VPN", "auto-routing moves such hosts to VPN")
                                : vpnOk ? Text.t("через VPN качается нормально", "downloads fine via VPN")
                                : Text.t("через VPN тоже не качается: ", "does not download via VPN either: ") + Json.str(sv, "state"));
            } else if ("ok".equals(state)) {
                d.ok(h + Text.t(": напрямую качается", ": downloads directly"), h + ": downloads directly", kb + Text.t(" КБ", " KB"));
            } else {
                d.info(h + Text.t(": напрямую не проверить", ": cannot check directly"), h + ": cannot check directly",
                        Json.str(st, "detail"));
            }
        }
    }

    // ---------- VPN на время ----------
    private volatile long vpnUntil;

    /** Выключить VPN через minutes минут (повторное нажатие продлевает: «ещё час»). 0 — отменить. */
    public void vpnFor(int minutes) {
        if (minutes <= 0) {
            vpnUntil = 0;
        } else {
            long base = Math.max(System.currentTimeMillis(), vpnUntil);
            vpnUntil = Math.min(base + minutes * 60000L, System.currentTimeMillis() + 24 * 3600000L);
            log("VPN выключится сам в " + new SimpleDateFormat("HH:mm", Locale.US).format(new Date(vpnUntil)) + ".",
                    "The VPN turns off by itself at " + new SimpleDateFormat("HH:mm", Locale.US).format(new Date(vpnUntil)) + ".");
        }
        changed();
    }

    public long vpnUntil() {
        return vpnUntil;
    }

    // ---------- состояние для интерфейса ----------

    public Map<String, Object> state() {
        synchronized (lock) {
            Map<String, Object> st = new LinkedHashMap<String, Object>();
            st.put("version", p.appVersion());
            st.put("core", p.coreVersion());
            st.put("lang", Text.lang);
            st.put("status", status);
            Lane shown = !conn.title.isEmpty() ? conn : bg;
            st.put("busy", Json.obj("title", shown.title, "kind", shown.kind));
            st.put("task", Json.obj("title", bg.title, "kind", bg.kind));   // долгая фоновая задача
            st.put("conn", Json.obj("title", conn.title, "kind", conn.kind)); // подключение / смена сервера
            st.put("message", message);
            st.put("whitelist", whitelistMode);
            st.put("wl", wlState());
            st.put("nw", nwState());
            st.put("pro", proState());
            st.put("collect", collectState());
            st.put("geo", geoReady());
            st.put("delay", liveDelay);
            Server cur = current;
            st.put("server", cur == null ? null : brief(cur));
            String sel = Json.str(settings, "selected");
            List<Object> list = new ArrayList<Object>();
            Map<String, String> subNames = new HashMap<String, String>();
            for (Map<String, Object> s : subs()) {
                String t = Json.str(s, "title");
                subNames.put(Json.str(s, "id"), t.isEmpty() ? Json.str(s, "name") : t);
            }
            List<Server> sorted = new ArrayList<Server>(servers);
            Collections.sort(sorted, new Comparator<Server>() {
                @Override
                public int compare(Server a, Server b) {
                    Double x = a.score();
                    Double y = b.score();
                    if (x != null && y != null) {
                        return Double.compare(x, y);
                    }
                    if (x != null || y != null) {
                        return x != null ? -1 : 1;
                    }
                    return Boolean.compare(!a.usable(), !b.usable());
                }
            });
            for (Server s : sorted) {
                Map<String, Object> b = brief(s);
                b.put("sub", subNames.containsKey(s.subId) ? subNames.get(s.subId) : "");
                b.put("selected", s.key().equals(sel));
                b.put("current", s == cur);
                list.add(b);
            }
            st.put("servers", list);
            st.put("engine", engineState());
            List<Object> subsOut = new ArrayList<Object>();
            for (Map<String, Object> s : subs()) {
                subsOut.add(Json.obj("id", Json.str(s, "id"), "name", Json.str(s, "name"), "title", Json.str(s, "title"),
                        "usage", Subscription.usageText(Json.map(s, "usage")), "error", Json.str(s, "error"),
                        "count", Json.num(s, "count", 0), "fetched", Json.num(s, "fetched", 0)));
            }
            st.put("subs", subsOut);
            Map<String, Object> set = new LinkedHashMap<String, Object>();
            for (String k : new String[]{"mode", "theme", "ru_direct", "autopilot", "dns_encrypted", "block_ads",
                    "mask_auto", "whitelist_auto", "proxy_list", "direct_list", "block_list", "user_agent",
                    "excluded_apps", "selected", "auto_update_hours", "hint_shown", "ads_ask_sites", "sub_alerts",
                    "encrypt_data", "app_lock", "net_profiles", "block_quic", "cert_watch", "fp_auto", "data_watch",
                    "net_memory", "fuses_enabled", "guard_rollback", "safe_start"}) {
                set.put(k, settings.get(k));
            }
            st.put("settings", set);
            st.put("problems", new ArrayList<Object>(problems.values()));
            st.put("check", lastCheck == null ? null : Json.obj("time", lastCheck.get("time"),
                    "errors", lastCheck.get("errors"), "warnings", lastCheck.get("warnings"), "items", lastCheck.get("items"),
                    "file", lastCheck.get("file")));
            st.put("filter_on", filterOn);
            st.put("speed", liveSpeed());
            st.put("speed_test", lastSpeedTest);
            st.put("repair", lastRepair);
            st.put("vps", vpsView());
            st.put("vpn_until", vpnUntil);
            st.put("vps_friend_new", lastVpsFriend);
            st.put("net_public", netPublic);
            st.put("leaks", lastLeaks);
            st.put("certs", lastCerts);
            Map<String, Object> dl = dataLast;
            boolean dataFresh = dl != null && "on".equals(status) && current != null && current.key().equals(Json.str(dl, "server"));
            st.put("ladder", Json.obj("step", ladderStep, "retry_at", ladderNext > System.currentTimeMillis() ? ladderNext : 0L,
                    "what_works", whatWorks, "way", "on".equals(status) ? wayText(current) : "",
                    "count", (long) netWays().size(), "data", dataFresh ? dl : null, "last", ladderLast,
                    "net_known", !waySaved.isEmpty()));
            st.put("errors_count", errors.size());
            st.put("journal", journal.state());
            st.put("method", method());
            st.put("family", familyState());
            Server ownWarp = ownWarp();
            st.put("warp", ownWarp == null ? "" : ownWarp.key());
            st.put("app_update", Json.obj("configured", Update.configured(), "state", appUpdate,
                    "auto", Json.bool(settings, "app_update", true)));
            st.put("ads", adsState());
            st.put("dpi", dpiState());
            st.put("routes", routesState());
            st.put("share", Json.obj("on", shareOn, "ip", shareIp, "kind", hotspotKind,
                    "socks", Json.num(settings, "share_socks_port", 10810), "http", Json.num(settings, "share_http_port", 10811),
                    "user", Json.str(settings, "share_user", "pult"), "pass", Json.str(settings, "share_pass"),
                    "ssid", hotspotSsid, "wifi_pass", hotspotPass));
            return st;
        }
    }

    private Map<String, Object> brief(Server s) {
        return Json.obj("key", s.key(), "name", s.name, "protocol", s.protocol, "ping", s.pingMs, "ok", s.ok,
                "usable", s.usable(), "note", s.note, "mask", s.mask, "wl", s.isWl(), "manual", s.subId.isEmpty(),
                "tested", s.testedAt, "kind", Links.kindOf(s));
    }

    public List<String> logLines() {
        synchronized (lock) {
            return new ArrayList<String>(log);
        }
    }

    // ---------- проверка программы ----------

    /** «Проверка программы»: всё, что можно проверить на этом телефоне, и отчёт-файл для нейросети. */
    public boolean runCheck() {
        return runTask(Text.t("Проверка программы", "Program check"), "check", new Runnable() {
            @Override
            public void run() {
                checkFlow();
            }
        });
    }

    /** Текст последней проверки (для «Сохранить», «Отправить», «Скопировать»). */
    public String checkText() {
        synchronized (lock) {
            return lastCheck == null ? "" : Json.str(lastCheck, "text");
        }
    }

    private static String ago(long ts) {
        if (ts <= 0) {
            return Text.t("никогда", "never");
        }
        long min = Math.max(0, (System.currentTimeMillis() - ts) / 60000);
        if (min < 60) {
            return Text.t(min + " мин назад", min + " min ago");
        }
        if (min < 48 * 60) {
            return Text.t(min / 60 + " ч назад", min / 60 + " h ago");
        }
        return Text.t(min / 1440 + " дн назад", min / 1440 + " days ago");
    }

    private static String statusWord(String st) {
        if ("on".equals(st)) {
            return Text.t("подключён", "connected");
        }
        if ("off".equals(st)) {
            return Text.t("выключен", "off");
        }
        return st;
    }

    private static int lines(Map<String, Object> s, String key) {
        int n = 0;
        for (String l : Json.str(s, key).split("\n")) {
            if (!l.trim().isEmpty() && !l.trim().startsWith("#")) {
                n++;
            }
        }
        return n;
    }

    /** Настройки для отчёта: только переключатели и счётчики, без ссылок, паролей и названий. */
    static String settingsSummary(Map<String, Object> s) {
        StringBuilder b = new StringBuilder();
        b.append("mode=").append(Json.str(s, "mode", "vpn"));
        for (String k : new String[]{"ru_direct", "block_quic", "autopilot", "dns_encrypted", "block_ads", "mask_auto", "whitelist_auto",
                "ads_without_vpn", "dpi_enabled", "dpi_youtube", "dpi_discord", "dpi_without_vpn"}) {
            b.append(", ").append(k).append('=').append(Json.bool(s, k, false) ? "on" : "off");
        }
        b.append(", auto_update_hours=").append(Json.num(s, "auto_update_hours", 12));
        b.append(", proxy_list=").append(lines(s, "proxy_list"));
        b.append(", direct_list=").append(lines(s, "direct_list"));
        b.append(", block_list=").append(lines(s, "block_list"));
        List<Object> ex = Json.list(s, "excluded_apps");
        b.append(", excluded_apps=").append(ex == null ? 0 : ex.size());
        List<Object> subs = Json.list(s, "subscriptions");
        b.append(", subscriptions=").append(subs == null ? 0 : subs.size());
        List<Object> manual = Json.list(s, "manual_links");
        b.append(", manual_servers=").append(manual == null ? 0 : manual.size());
        b.append(", ads_level=").append(Json.str(s, "ads_level", AdBlock.DEFAULT_LEVEL));
        b.append(", dpi_strategy=").append(Json.str(s, "dpi_strategy").isEmpty() ? "none" : Json.str(s, "dpi_strategy"));
        Map<String, Object> rts = Json.map(s, "routes");
        b.append(", routes=").append(rts == null ? 0 : rts.size());
        List<Object> pxs = Json.list(s, "proxies");
        b.append(", own_proxies=").append(pxs == null ? 0 : pxs.size());
        b.append(", own_user_agent=").append(Json.str(s, "user_agent").isEmpty() ? "no" : "yes");
        b.append(", lang=").append(Json.str(s, "lang").isEmpty() ? "auto" : Json.str(s, "lang"));
        return b.toString();
    }

    /** Проверка «слушает ли адрес»: в самопроверке подменяется (там нет настоящей точки доступа). */
    public interface PortProbe {
        boolean open(String ip, int port, int timeoutMs, StringBuilder err);
    }

    public static PortProbe PORTS = new PortProbe() {
        @Override
        public boolean open(String ip, int port, int timeoutMs, StringBuilder err) {
            java.net.Socket sock = new java.net.Socket(java.net.Proxy.NO_PROXY);
            try {
                sock.connect(new java.net.InetSocketAddress(ip, port), timeoutMs);
                return true;
            } catch (Exception e) {
                if (err != null) {
                    err.append(Http.human(e));
                }
                return false;
            } finally {
                try {
                    sock.close();
                } catch (Exception ignored) {
                    // не важно
                }
            }
        }
    };

    /** "" — оба входа раздачи отвечают, иначе что не так. */
    private static String shareProblem(String ip, int socks, int http) {
        StringBuilder e1 = new StringBuilder();
        StringBuilder e2 = new StringBuilder();
        boolean s = PORTS.open(ip, socks, 2000, e1);
        boolean h = PORTS.open(ip, http, 2000, e2);
        if (s && h) {
            return "";
        }
        return (s ? "" : "SOCKS " + socks + ": " + e1) + (!s && !h ? "; " : "") + (h ? "" : "HTTP " + http + ": " + e2);
    }

    /** Имя адаптера, у которого этот адрес (из сведений о телефоне). */
    private static String ifaceOf(Map<String, Object> dev, String ip) {
        Map<String, Object> ifs = Json.map(dev, "ifaces");
        if (ifs != null) {
            for (Map.Entry<String, Object> e : ifs.entrySet()) {
                if (String.valueOf(e.getValue()).contains(ip)) {
                    return e.getKey();
                }
            }
        }
        return "?";
    }

    /** Код ответа сайта → ok / region (403, 451) / fail, и почему не открылся. */
    private static String[] siteState(String url, int proxyPort) {
        try {
            Map<String, String> h = new HashMap<String, String>();
            h.put("User-Agent", Http.UA);
            // большая страница — не ошибка: достаточно, что сайт начал её отдавать
            Http.Response r = Http.probe(url, h, 9000, proxyPort, 64 * 1024);
            if (r.status == 403 || r.status == 451) {
                return new String[]{"region", "HTTP " + r.status};
            }
            return r.status > 0 && r.status < 500 ? new String[]{"ok", ""} : new String[]{"fail", "HTTP " + r.status};
        } catch (Exception e) {
            return new String[]{"fail", Http.human(e)};
        }
    }

    void checkFlow() {
        Diagnostics d = new Diagnostics();
        Map<String, Object> dev = p instanceof DeviceInfo ? ((DeviceInfo) p).deviceInfo() : new LinkedHashMap<String, Object>();
        boolean on = isOn();

        // --- телефон ---
        progress(Text.t("Проверка программы: телефон", "Program check: phone"));
        String core = p.coreVersion();
        if (core == null || core.isEmpty()) {
            d.error("Ядро Xray не загрузилось", "The Xray core did not load", "");
        } else {
            d.ok("Ядро: " + core, "Core: " + core, "");
        }
        if (dev.containsKey("vpn_permission") && !Json.bool(dev, "vpn_permission", true)) {
            d.warn("Нет разрешения на VPN", "No VPN permission",
                    Text.t("При подключении Android спросит его — нажми «ОК».", "Android will ask when you connect — tap OK."));
        }
        if (dev.containsKey("notifications") && !Json.bool(dev, "notifications", true)) {
            d.warn("Уведомления выключены", "Notifications are off",
                    Text.t("Не видно, работает ли VPN, а Android охотнее закрывает его в фоне. Включи уведомления для VEDOMYJ VPN.",
                            "You can't see whether VPN works, and Android closes it in the background more often. Turn notifications on."));
            d.fix("notifications");
        }
        if (Json.bool(dev, "battery_restricted", false)) {
            d.warn("Android экономит батарею за счёт VEDOMYJ VPN", "Android restricts VEDOMYJ VPN to save battery",
                    Text.t("VPN может отключаться в фоне. Нажми «Снять ограничение» и разреши. На realme, OPPO, Xiaomi и Huawei "
                                    + "ещё разреши «Автозапуск» и «Работу в фоне» в настройках приложения.",
                            "VPN may stop in the background. Tap “Remove restriction” and allow it. On realme, OPPO, Xiaomi and Huawei "
                                    + "also allow Autostart and Background activity in the app settings."));
            d.fix("battery");
        } else if (dev.containsKey("battery_restricted")) {
            d.ok("Батарея: без ограничений для VEDOMYJ VPN", "Battery: unrestricted for VEDOMYJ VPN", "");
        }
        if (Json.bool(dev, "data_saver", false)) {
            d.warn("Включена экономия трафика", "Data Saver is on",
                    Text.t("Фоновая работа приложений ограничена — VPN может работать с перебоями.",
                            "Background work is limited — VPN may be unstable."));
            d.fix("data_saver");
        }
        if (!on && Json.bool(dev, "other_vpn", false)) {
            d.warn("Сейчас работает другое VPN-приложение", "Another VPN app is active",
                    Text.t("Android разрешает только один VPN: при подключении он будет выключен.",
                            "Android allows only one VPN: it will be turned off when you connect."));
        }
        String pdns = Json.str(dev, "private_dns");
        if (!pdns.isEmpty() && !"off".equals(pdns) && !"opportunistic".equals(pdns)) {
            d.ok("Частный DNS: " + pdns, "Private DNS: " + pdns,
                    Text.t("Работает вместе с VPN, менять не нужно.", "Works together with VPN, no need to change."));
        }
        long free = Json.num(dev, "free_mb", -1);
        if (free >= 0 && free < 200) {
            d.warn("Мало места на телефоне: " + free + " МБ", "Low storage: " + free + " MB",
                    Text.t("Списки сайтов и обновления могут не сохраниться.", "Site lists and updates may fail to save."));
        }

        // --- логика приложения ---
        progress(Text.t("Проверка программы: логика приложения", "Program check: app logic"));
        Map<String, Object> settingsCopy;
        synchronized (lock) {
            settingsCopy = new LinkedHashMap<String, Object>(settings);
        }
        d.selfTest(settingsCopy, core == null ? "" : core, p.appVersion());
        checkStop();

        // --- ядро и интернет ---
        progress(Text.t("Проверка программы: ядро и интернет", "Program check: core and internet"));
        try {
            long ms = p.testDelay(Json.write(Diagnostics.directConfig()), XrayConfig.HEALTH_URL);
            d.ok("Ядро запускается и выходит в интернет: " + ms + " мс", "The core starts and reaches the internet: " + ms + " ms", "");
        } catch (Exception e) {
            d.error("Ядро не запускается или нет интернета", "The core does not start or there is no internet", Diagnostics.msg(e));
        }
        if (geoReady()) {
            d.ok("Списки заблокированных сайтов на месте", "Block lists are in place", "");
        } else {
            d.warn("Списки заблокированных сайтов не скачаны", "Block lists are not downloaded",
                    Text.t("Пока работает встроенный список. Они скачаются сами при подключении.",
                            "The built-in list works for now. They download by themselves when you connect."));
        }
        String net = whitelistProbe();
        if ("open".equals(net)) {
            d.ok("Интернет работает без ограничений", "Internet works without restrictions", "");
        } else if ("whitelist".equals(net)) {
            d.warn("Похоже, включены «белые списки»", "Whitelists seem active",
                    Text.t("Открываются только разрешённые российские сайты. Нужен сервер для обхода белых списков.",
                            "Only allowed Russian sites open. A whitelist bypass server is needed."));
        } else {
            d.error("Нет интернета", "No internet", Text.t("Проверь Wi-Fi или мобильные данные.", "Check Wi-Fi or mobile data."));
        }
        checkStop();

        // --- подписки и серверы ---
        progress(Text.t("Проверка программы: подписки и серверы", "Program check: subscriptions and servers"));
        List<Map<String, Object>> subList = subs();
        for (Map<String, Object> sb : subList) {
            String title = Json.str(sb, "title").isEmpty() ? Json.str(sb, "name") : Json.str(sb, "title");
            String err = Json.str(sb, "error");
            if (!err.isEmpty()) {
                d.warn("Подписка «" + title + "»: " + err, "Subscription “" + title + "”: " + err, "");
            } else {
                d.ok("Подписка «" + title + "»: серверов " + Json.num(sb, "count", 0) + ", обновлена " + ago(Json.num(sb, "fetched", 0)),
                        "Subscription “" + title + "”: " + Json.num(sb, "count", 0) + " servers, updated " + ago(Json.num(sb, "fetched", 0)), "");
            }
        }
        int usable = 0;
        synchronized (lock) {
            for (Server sv : servers) {
                if (sv.usable()) {
                    usable++;
                }
            }
        }
        if (usable == 0) {
            d.error("Нет серверов", "No servers", Text.t("Добавь подписку или ссылку на сервер.", "Add a subscription or a server link."));
        } else {
            testServers(true);
            List<Server> best = ranked();
            Map<String, Integer> errs = new LinkedHashMap<String, Integer>();
            synchronized (lock) {
                for (Server sv : servers) {
                    if (sv.usable() && !sv.ok && !sv.error.isEmpty()) {
                        String k = sv.protocol + ": " + Text.shorten(sv.error, 120);
                        errs.put(k, errs.containsKey(k) ? errs.get(k) + 1 : 1);
                    }
                }
            }
            StringBuilder why = new StringBuilder();
            int shown = 0;
            for (Map.Entry<String, Integer> en : errs.entrySet()) {
                if (shown++ >= 3) {
                    break;
                }
                why.append(shown > 1 ? "; " : "").append(en.getKey()).append(en.getValue() > 1 ? " (×" + en.getValue() + ")" : "");
            }
            if (best.isEmpty()) {
                d.error("Ни один сервер не отвечает", "No server responds", why.toString());
            } else {
                Server b = best.get(0);
                d.ok("Работают серверы: " + best.size() + " из " + usable, "Working servers: " + best.size() + " of " + usable,
                        Text.t("лучший: " + b.name + ", пинг " + b.pingMs + " мс", "best: " + b.name + ", ping " + b.pingMs + " ms"));
                if (best.size() < usable && why.length() > 0) {
                    d.info("Почему не отвечают остальные", "Why the others don't respond", why.toString());
                }
            }
        }
        checkStop();

        // --- VPN и сайты ---
        progress(Text.t("Проверка программы: сайты напрямую и через VPN", "Program check: sites directly and via VPN"));
        final int vpnPort = isOn() ? appPort : 0;
        final String[][] direct = new String[Diagnostics.SITES.length][];
        final String[][] viaVpn = new String[Diagnostics.SITES.length][];
        List<Future<?>> fs = new ArrayList<Future<?>>();
        for (int i = 0; i < Diagnostics.SITES.length; i++) {
            final int k = i;
            fs.add(pool.submit(new Runnable() {
                @Override
                public void run() {
                    direct[k] = siteState(Diagnostics.SITES[k][1], 0);
                    viaVpn[k] = vpnPort > 0 ? siteState(Diagnostics.SITES[k][1], vpnPort) : new String[]{"", ""};
                }
            }));
        }
        waitAll(fs);
        List<String> dirBad = new ArrayList<String>();
        List<String> vpnBad = new ArrayList<String>();
        List<String> vpnRegion = new ArrayList<String>();
        Map<String, Integer> vpnWhy = new LinkedHashMap<String, Integer>();
        for (int i = 0; i < Diagnostics.SITES.length; i++) {
            String name = Diagnostics.SITES[i][0];
            if (!"ok".equals(direct[i][0])) {
                dirBad.add(name);
            }
            if ("fail".equals(viaVpn[i][0])) {
                vpnBad.add(name);
                Integer n = vpnWhy.get(viaVpn[i][1]);
                vpnWhy.put(viaVpn[i][1], n == null ? 1 : n + 1);
            } else if ("region".equals(viaVpn[i][0])) {
                vpnRegion.add(name);
            }
        }
        StringBuilder vpnWhyText = new StringBuilder();
        for (Map.Entry<String, Integer> en : vpnWhy.entrySet()) {
            vpnWhyText.append(vpnWhyText.length() > 0 ? "; " : "").append(en.getKey())
                    .append(en.getValue() > 1 ? " (×" + en.getValue() + ")" : "");
        }
        if (dirBad.isEmpty()) {
            d.ok("Напрямую открываются все проверенные сайты", "All checked sites open directly", "");
        } else {
            d.info("Напрямую не открываются: " + String.join(", ", dirBad), "Not opening directly: " + String.join(", ", dirBad),
                    Text.t("Это обычно блокировки провайдера — для них и нужен VPN.",
                            "Usually the provider's blocks — that's what VPN is for."));
        }
        if (vpnPort > 0) {
            try {
                long ms = p.coreDelay(XrayConfig.HEALTH_URL);
                d.ok("VPN работает: пинг " + ms + " мс", "VPN works: ping " + ms + " ms", "");
            } catch (Exception e) {
                d.error("VPN включён, но интернет через него не идёт", "VPN is on but the internet doesn't go through it",
                        Diagnostics.msg(e));
            }
            if (vpnBad.isEmpty() && vpnRegion.isEmpty()) {
                d.ok("Через VPN открываются все проверенные сайты (" + Diagnostics.SITES.length + ")",
                        "All checked sites open via VPN (" + Diagnostics.SITES.length + ")", "");
            }
            if (!vpnBad.isEmpty()) {
                d.error("Через VPN не открываются: " + String.join(", ", vpnBad), "Not opening via VPN: " + String.join(", ", vpnBad),
                        vpnWhyText + ". " + Text.t("Попробуй другой сервер или включи «Маскировку».", "Try another server or turn on Masking."));
            }
            if (!vpnRegion.isEmpty()) {
                d.warn("Закрыты для страны сервера: " + String.join(", ", vpnRegion), "Closed for the server's country: "
                        + String.join(", ", vpnRegion), Text.t("Нужен сервер другой страны.", "A server in another country is needed."));
            }
        } else {
            d.warn("VPN выключен — сайты через VPN не проверены", "VPN is off — sites via VPN were not checked",
                    Text.t("Включи VPN и запусти проверку ещё раз.", "Turn VPN on and run the check again."));
        }

        // --- раздача ---
        boolean share;
        String ip;
        synchronized (lock) {
            share = shareOn;
            ip = shareIp;
        }
        if (share) {
            if (ip.isEmpty()) {
                d.warn("Раздача включена, но точки доступа нет", "Sharing is on but there is no hotspot",
                        Text.t("Включи точку доступа или USB-модем.", "Turn on the hotspot or USB tethering."));
            } else if (on) {
                int socks = (int) Json.num(settingsCopy, "share_socks_port", 10810);
                int http = (int) Json.num(settingsCopy, "share_http_port", 10811);
                String where = Text.t("адаптер ", "adapter ") + ifaceOf(dev, ip) + ", " + Text.t("сеть ", "network ")
                        + (hotspotKind.equals("local") ? Text.t("приложения", "of the app") : Text.t("телефона", "of the phone"));
                String err = shareProblem(ip, socks, http);
                if (err.isEmpty()) {
                    d.ok("Раздача работает: другие устройства могут подключиться", "Sharing works: other devices can connect", where);
                } else {
                    // ядро могло не успеть занять адрес новой точки доступа — перезапуск обычно помогает.
                    // Перезапуск — в очереди подключения; проверка ждёт его
                    applyCore();
                    long end = System.currentTimeMillis() + 25000;
                    sleep(300);
                    while ((connBusy() || pendingApply) && System.currentTimeMillis() < end) {
                        sleep(200);
                    }
                    String after = isOn() ? shareProblem(ip, socks, http) : err;
                    if (after.isEmpty()) {
                        d.warn("Раздача не отвечала — заработала после перезапуска ядра", "Sharing did not respond — works after restarting the core",
                                err + "; " + where);
                    } else {
                        d.error("Раздача не отвечает", "Sharing does not respond", after + "; " + where
                                + Text.t(". Выключи и включи раздачу; если не поможет — пришли этот отчёт.",
                                ". Turn sharing off and on; if it doesn't help, send this report."));
                    }
                }
            }
        }

        // --- защита, обновления, замирание соединений ---
        progress(Text.t("Проверка программы: защита и обновления", "Program check: protection and updates"));
        checkProtection(d, dev, settingsCopy, on);
        checkStop();

        // --- блокировка рекламы ---
        progress(Text.t("Проверка программы: реклама, обход замедлений, свои маршруты", "Program check: ads, bypass, own routes"));
        Map<String, Object> ads = adsState();
        if (!Json.bool(ads, "enabled", false)) {
            d.info("Блокировка рекламы выключена", "Ad blocking is off", "");
        } else {
            if (Json.bool(ads, "ready", false)) {
                d.ok("Списки рекламы: адресов — " + Json.num(ads, "total", 0) + ", обновлены " + ago(Json.num(ads, "updated_at", 0)),
                        "Ad lists: " + Json.num(ads, "total", 0) + " addresses, updated " + ago(Json.num(ads, "updated_at", 0)), "");
            } else {
                d.warn("Списки рекламы не скачаны", "Ad lists are not downloaded",
                        Text.t("Открой «Блокировка рекламы» и нажми «Обновить списки».", "Open Ad blocking and tap Update lists."));
            }
            if (!Json.list(ads, "missing").isEmpty()) {
                d.warn("Не все списки рекламы скачались: " + Json.list(ads, "missing"), "Not all ad lists downloaded: "
                        + Json.list(ads, "missing"), "");
            }
            if (Json.num(ads, "paused_until", 0) > 0) {
                d.info("Блокировка рекламы на паузе", "Ad blocking is paused", "");
            } else if (on) {
                d.ok("Реклама блокируется вместе с VPN", "Ads are blocked together with VPN", "");
            } else if (Json.bool(ads, "filter_on", false)) {
                d.ok("Реклама блокируется без VPN", "Ads are blocked without VPN", "");
            } else if (Json.bool(ads, "without_vpn", true)) {
                d.warn("Блокировка без VPN сейчас не работает", "Blocking without VPN is not working now",
                        Json.bool(ads, "need_permission", false) ? Text.t("Нет разрешения на VPN — нажми «Включить блокировку без VPN».",
                                "No VPN permission — tap “Turn on blocking without VPN”.")
                                : Text.t("Её выключили вручную или туннель занял другой VPN.", "It was turned off or another VPN took the tunnel."));
            }
            if (Json.num(ads, "today", 0) > 0) {
                d.info("Сегодня заблокировано рекламы: " + Json.num(ads, "today", 0), "Ads blocked today: " + Json.num(ads, "today", 0), "");
            }
        }

        // --- обход замедлений ---
        if (!Json.bool(settingsCopy, "dpi_enabled", true)) {
            d.info("Обход замедлений выключен — YouTube и Discord через VPN", "Throttling bypass is off — YouTube and Discord via VPN", "");
        } else {
            Dpi.Strategy st = Dpi.find(Json.str(settingsCopy, "dpi_strategy"));
            Map<String, Object> res = dpiTest(st != null ? st : Dpi.STRATEGIES.get(0), 8000);
            StringBuilder why = new StringBuilder();
            for (Map.Entry<String, Object> en : res.entrySet()) {
                Map<String, Object> r = Json.map(en.getValue());
                why.append(why.length() > 0 ? "; " : "").append(en.getKey()).append(": ")
                        .append(Json.bool(r, "ok", false) ? (Json.num(r, "kbps", -1) > 0 ? Json.num(r, "kbps", -1) + " kbit/s" : "ok")
                                : Json.str(r, "detail"));
            }
            String name = st == null ? Text.t("стандартный", "standard") : st.title();
            if (Dpi.allOk(res)) {
                d.ok("Обход замедлений работает: " + name, "Throttling bypass works: " + name, why.toString());
            } else if (Json.num(settingsCopy, "dpi_tested_at", 0) == 0) {
                d.info("Обход замедлений ещё не подбирался", "The throttling bypass has not been tuned yet", why.toString());
            } else {
                d.info("Обход замедлений не помогает у этого провайдера — YouTube и Discord через VPN",
                        "The throttling bypass doesn't help with this ISP — YouTube and Discord via VPN", why.toString());
            }
        }
        checkStop();

        // --- свои маршруты и прокси ---
        Map<String, Object> rs = routesState();
        int own = 0;
        for (Object o : Json.list(rs, "services")) {
            Map<String, Object> m = Json.map(o);
            if (!"auto".equals(Json.str(m, "choice"))) {
                own++;
            }
            if (!Json.str(m, "warn").isEmpty()) {
                d.warn("Свой маршрут «" + Json.str(m, "name") + "»: " + Json.str(m, "warn"),
                        "Own route “" + Json.str(m, "name") + "”: " + Json.str(m, "warn"), "");
            }
        }
        for (Object o : Json.list(rs, "sites")) {
            Map<String, Object> m = Json.map(o);
            own++;
            if (!Json.str(m, "warn").isEmpty()) {
                d.warn("Свой маршрут «" + Json.str(m, "site") + "»: " + Json.str(m, "warn"),
                        "Own route “" + Json.str(m, "site") + "”: " + Json.str(m, "warn"), "");
            }
        }
        if (own > 0) {
            d.info("Своих маршрутов: " + own, "Own routes: " + own, "");
        }
        for (Object o : Json.list(rs, "proxies")) {
            Map<String, Object> m = Json.map(o);
            Map<String, Object> c = Json.map(m, "check");
            boolean used = !Json.list(m, "used").isEmpty();
            String t = Json.str(m, "title");
            if (c == null || Json.num(c, "at", 0) == 0) {
                d.info("Свой прокси «" + t + "»: ещё не проверялся", "Own proxy “" + t + "”: not checked yet", "");
            } else if (Json.bool(c, "ok", false)) {
                d.ok("Свой прокси «" + t + "»: работает, страна " + Json.str(c, "loc"), "Own proxy “" + t + "”: works, country "
                        + Json.str(c, "loc"), Text.t("проверен ", "checked ") + ago(Json.num(c, "at", 0)));
            } else if (used) {
                d.error("Свой прокси «" + t + "» не отвечает, а через него идут сервисы", "Own proxy “" + t + "” does not answer but services use it",
                        Json.str(c, "error"));
            } else {
                d.warn("Свой прокси «" + t + "» не отвечает", "Own proxy “" + t + "” does not answer", Json.str(c, "error"));
            }
        }
        checkStop();

        // --- сертификаты ---
        progress(Text.t("Проверяю сертификаты", "Checking certificates"));
        try {
            Map<String, Object> cr = certCompute(true);
            for (Object o : vlist(cr, "items")) {
                Map<String, Object> i = Json.map(o);
                String st = Json.str(i, "state");
                String title = Json.str(i, "title");
                String detail = (Json.str(i, "detail") + " " + Json.str(i, "fix")).trim();
                d.add("ok".equals(st) || "info".equals(st) || "warn".equals(st) ? st : "error", title, title, detail);
            }
        } catch (RuntimeException e) {
            d.warn("Сертификаты не проверились", "Certificates were not checked", Http.human(e));
            recordBug(e, "проверка сертификатов");
        }
        checkStop();

        // --- активные проблемы ---
        synchronized (lock) {
            for (Map<String, Object> pr : problems.values()) {
                d.warn("Сейчас: " + Json.str(pr, "title"), "Now: " + Json.str(pr, "title"), Json.str(pr, "detail"));
            }
        }

        // --- отчёт ---
        String model = Json.str(dev, "model");
        String header = "VEDOMYJ VPN для Android " + p.appVersion() + " — " + Text.t("проверка программы", "program check") + " "
                + new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(new Date()) + "\n"
                + "Android " + p.osVersion() + (model.isEmpty() ? "" : ", " + model)
                + (Json.str(dev, "abi").isEmpty() ? "" : " (" + Json.str(dev, "abi") + ")") + "\n"
                + Text.t("VPN: ", "VPN: ") + statusWord(status())
                + Text.t(", белые списки: ", ", whitelists: ") + (whitelistMode ? Text.t("включены", "on") : Text.t("нет", "no")) + "\n"
                + Text.t("Настройки: ", "Settings: ") + settingsSummary(settingsCopy) + "\n";
        String text = d.text(header, logLines(), reportSecrets());
        File dir = new File(p.dataDir(), "reports");
        dir.mkdirs();
        String name = "vedomyj-check-" + new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(new Date()) + ".txt";
        try {
            Store.write(new File(dir, name), text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            File[] old = dir.listFiles();
            if (old != null && old.length > 10) {
                java.util.Arrays.sort(old);
                for (int i = 0; i < old.length - 10; i++) {
                    old[i].delete();
                }
            }
        } catch (Exception e) {
            name = "";
        }
        int errors = d.count("error");
        int warnings = d.count("warn");
        synchronized (lock) {
            lastCheck = Json.obj("time", System.currentTimeMillis(), "errors", errors, "warnings", warnings,
                    "items", d.items, "text", text, "file", name);
        }
        if (errors > 0) {
            StringBuilder bad = new StringBuilder();
            for (Map<String, Object> i : d.items) {
                if ("error".equals(Json.str(i, "level"))) {
                    bad.append(bad.length() == 0 ? "" : "; ").append(Json.str(i, "title"));
                }
            }
            this.errors.record("check", "Проверка программы: ошибок " + errors,
                    bad.length() > 1200 ? bad.substring(0, 1200) : bad.toString(), "", "проверка программы");
        }
        log("Проверка программы: ошибок " + errors + ", предупреждений " + warnings + ".",
                "Program check: " + errors + " errors, " + warnings + " warnings.");
        say(Text.t("Проверка готова: ошибок " + errors + ", предупреждений " + warnings,
                "Check done: " + errors + " errors, " + warnings + " warnings"), errors > 0 ? "error" : "ok");
    }

    /** Отчёт для нейросети: без ссылок, ключей и адресов серверов. */
    public String report() {
        StringBuilder b = new StringBuilder();
        b.append("VEDOMYJ VPN для Android ").append(p.appVersion()).append('\n');
        b.append("Android ").append(p.osVersion()).append(", ядро: ").append(p.coreVersion()).append('\n');
        synchronized (lock) {
            int usable = 0;
            int ok = 0;
            for (Server s : servers) {
                if (s.usable()) {
                    usable++;
                }
                if (s.ok) {
                    ok++;
                }
            }
            b.append("Состояние: ").append(status).append(", подписок: ").append(subs().size())
                    .append(", серверов: ").append(servers.size()).append(" (годных ").append(usable)
                    .append(", отвечают ").append(ok).append(")\n");
            b.append("Режим: ").append(Json.str(settings, "mode")).append(", белые списки: ").append(whitelistMode)
                    .append(", списки сайтов: ").append(geoReady()).append(", раздача: ").append(shareOn).append('\n');
            for (Map<String, Object> pr : problems.values()) {
                b.append("Проблема: ").append(Json.str(pr, "title")).append(" — ").append(Json.str(pr, "detail")).append('\n');
            }
            b.append('\n').append(journal.reportText(40));
            b.append("\nЖурнал:\n");
            for (String l : log) {
                b.append(l).append('\n');
            }
        }
        return b.toString();
    }

    /** Был ли VPN включён перед тем, как приложение закрыли (для «Постоянного VPN» и перезапуска). */
    public boolean wasOn() {
        return Json.bool(settings, "was_on", false);
    }

    // =====================================================================================================
    // ---------- свои маршруты: сервис или сайт → VPN, напрямую, обход замедления, другой сервер, свой прокси ----------

    static final String[] LIST_TARGETS = {"proxy", "direct", "block"};

    static String listKey(String target) {
        return "proxy".equals(target) ? "proxy_list" : "direct".equals(target) ? "direct_list" : "block".equals(target) ? "block_list" : "";
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> routes() {
        Map<String, Object> r = Json.map(settings, "routes");
        if (r == null) {
            r = new LinkedHashMap<String, Object>();
            settings.put("routes", r);
        }
        return r;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> proxyList() {
        List<Object> l = Json.list(settings, "proxies");
        if (l == null) {
            l = new ArrayList<Object>();
            settings.put("proxies", l);
        }
        List<Map<String, Object>> out = new ArrayList<Map<String, Object>>();
        for (Object o : l) {
            if (o instanceof Map) {
                out.add((Map<String, Object>) o);
            }
        }
        return out;
    }

    private Map<String, Object> proxyById(String id) {
        for (Map<String, Object> p0 : proxyList()) {
            if (Json.str(p0, "id").equals(id)) {
                return p0;
            }
        }
        return null;
    }

    /** Имя прокси для журнала: своё название или номер — адрес и логин в журнал не пишем. */
    private String proxyTitle(Map<String, Object> px) {
        if (px == null) {
            return "?";
        }
        if (!Json.str(px, "name").isEmpty()) {
            return Json.str(px, "name");
        }
        List<Map<String, Object>> l = proxyList();
        return "№" + (l.indexOf(px) + 1);
    }

    /** Проверяет выбор маршрута. null — для auto/proxy/direct/block (они живут в списках), иначе запись routes. */
    private Map<String, Object> checkTarget(String target) {
        if ("auto".equals(target) || !listKey(target).isEmpty()) {
            return null;
        }
        if ("dpi".equals(target)) {
            return Json.obj("via", "dpi");
        }
        if (target.startsWith("server:")) {
            Server s = find(target.substring(7));
            if (s == null) {
                throw new UserError(Text.t("Сервер не найден — обнови подписку.", "Server not found — refresh the subscription."));
            }
            if (!s.usable()) {
                throw new UserError(Text.t("Этот сервер не поддерживается: ", "This server is not supported: ") + s.note);
            }
            return Json.obj("via", "server", "server", s.key(), "server_name", s.name);
        }
        if (target.startsWith("custom:")) {
            if (proxyById(target.substring(7)) == null) {
                throw new UserError(Text.t("Прокси не найден.", "Proxy not found."));
            }
            return Json.obj("via", "custom", "proxy", target.substring(7));
        }
        throw new UserError(Text.t("Неизвестное действие.", "Unknown action."));
    }

    static String routeValue(Map<String, Object> spec) {
        String via = Json.str(spec, "via");
        if ("server".equals(via)) {
            return "server:" + Json.str(spec, "server");
        }
        if ("custom".equals(via)) {
            return "custom:" + Json.str(spec, "proxy");
        }
        return via;
    }

    /** Подпись выбора для журнала (без адресов и паролей). */
    private String routeLabel(String target) {
        if (target.startsWith("server:")) {
            Server s = find(target.substring(7));
            return Text.t("через сервер «", "via server “") + (s == null ? "?" : s.name) + Text.t("»", "”");
        }
        if (target.startsWith("custom:")) {
            return Text.t("через прокси «", "via proxy “") + proxyTitle(proxyById(target.substring(7))) + Text.t("»", "”");
        }
        if ("proxy".equals(target)) {
            return Text.t("всегда через VPN", "always via VPN");
        }
        if ("direct".equals(target)) {
            return Text.t("всегда напрямую", "always direct");
        }
        if ("block".equals(target)) {
            return Text.t("блокируется", "blocked");
        }
        if ("dpi".equals(target)) {
            return Text.t("напрямую с обходом замедления", "direct with throttling bypass");
        }
        return Text.t("как по умолчанию", "as by default");
    }

    private void addToList(String key, List<String> entries) {
        String text = Json.str(settings, key);
        StringBuilder b = new StringBuilder(text);
        for (String e : entries) {
            if (!Routing.userRule(e, Json.obj(key, b.toString())).isEmpty()) {
                continue;
            }
            if (b.length() > 0 && b.charAt(b.length() - 1) != '\n') {
                b.append('\n');
            }
            b.append(e);
        }
        settings.put(key, b.toString());
    }

    /** Как подключаться к сервису: auto, proxy, direct, block, dpi, server:<ключ>, custom:<id>. */
    public void setServiceRoute(String name, String target) {
        Services.Service svc = Services.find(name);
        if (svc == null) {
            throw new UserError(Text.t("Сервис не найден.", "Service not found."));
        }
        synchronized (lock) {
            Map<String, Object> spec = checkTarget(target);
            for (String d : svc.domains) {
                for (String[] l : Routing.USER_LISTS) {
                    settings.put(l[0], Routing.removeHost(Json.str(settings, l[0]), d));
                }
            }
            routes().remove("svc:" + name);
            if (!listKey(target).isEmpty()) {
                addToList(listKey(target), svc.domains);
            } else if (spec != null) {
                routes().put("svc:" + name, spec);
            }
        }
        saveSettings();
        log(name + ": " + routeLabel(target) + ".", name + ": " + routeLabel(target) + ".");
        applyCore();
        changed();
    }

    /** Адрес сайта от человека → запись для правил: домен (без www) или IP. mainDomain — основной домен. */
    public static String siteKey(String raw, boolean mainDomain) {
        String text = raw == null ? "" : raw.trim();
        if (text.contains("://")) {
            text = text.substring(text.indexOf("://") + 3);
        }
        int slash = text.indexOf('/');
        if (slash >= 0) {
            text = text.substring(0, slash);
        }
        String[] item;
        try {
            item = Routing.normalizeEntry(text);
        } catch (IllegalArgumentException e) {
            item = null;
        }
        if (item == null || !(("ip".equals(item[0]) && !item[1].startsWith("geoip:")) || item[1].startsWith("domain:"))) {
            throw new UserError(Text.t("Не похоже на адрес сайта. Пример: example.com.",
                    "This doesn't look like a site address. Example: example.com."));
        }
        String value = "domain".equals(item[0]) ? item[1].substring(7) : item[1];
        return mainDomain ? Routing.siteEntry(value) : value;
    }

    static boolean covers(String entry, String value) {
        String e = entry.toLowerCase();
        String v = value.toLowerCase();
        return v.equals(e) || (!Routing.isIpEntry(e) && v.endsWith("." + e));
    }

    /** Убирает правила для сайта и его поддоменов из списков и своих маршрутов. */
    private void clearSite(String entry) {
        for (String[] l : Routing.USER_LISTS) {
            List<String> kept = new ArrayList<String>();
            for (String line : Json.str(settings, l[0]).split("\\r?\\n", -1)) {
                String[] item;
                try {
                    item = Routing.normalizeEntry(line);
                } catch (IllegalArgumentException e) {
                    item = null;
                }
                String value = item == null ? "" : item[1].startsWith("domain:") ? item[1].substring(7)
                        : "ip".equals(item[0]) ? item[1] : "";
                if (value.isEmpty() || !covers(entry, value)) {
                    kept.add(line);
                }
            }
            settings.put(l[0], String.join("\n", kept).trim());
        }
        for (String k : new ArrayList<String>(routes().keySet())) {
            if (k.startsWith("site:") && covers(entry, k.substring(5))) {
                routes().remove(k);
            }
        }
    }

    /** Свой маршрут для сайта (варианты — как у сервисов). Правило действует и на поддомены. Возвращает запись. */
    public String routeSite(String host, String target, boolean mainDomain) {
        String entry = siteKey(host, mainDomain);
        synchronized (lock) {
            Map<String, Object> spec = !listKey(target).isEmpty() ? Json.obj("via", target) : checkTarget(target);
            clearSite(entry);
            if (spec != null) {
                routes().put("site:" + entry, spec);
            }
        }
        saveSettings();
        log(entry + ": " + routeLabel(target) + ".", entry + ": " + routeLabel(target) + ".");
        applyCore();
        changed();
        return entry;
    }

    private static List<String> routeDomains(String key, List<String> ips) {
        List<String> domains = new ArrayList<String>();
        if (key.startsWith("svc:")) {
            Services.Service svc = Services.find(key.substring(4));
            if (svc != null) {
                for (String d : svc.domains) {
                    domains.add("domain:" + d);
                }
            }
        } else if (key.startsWith("site:")) {
            List<List<String>> e = Routing.splitEntries(key.substring(5));
            domains.addAll(e.get(0));
            ips.addAll(e.get(1));
        }
        return domains;
    }

    /** Куда на самом деле пойдёт маршрут сейчас: {вид, предупреждение для интерфейса}. */
    private String[] routeTarget(Map<String, Object> spec, Server main) {
        String via = Json.str(spec, "via");
        if (!listKey(via).isEmpty()) {
            return new String[]{via, ""};
        }
        if ("dpi".equals(via)) {
            return new String[]{"dpi", dpiActive() ? "" : Text.t("Способ обхода ещё не подобран или не работает — пробую стандартный.",
                    "No working bypass method yet — trying the standard one.")};
        }
        if ("server".equals(via)) {
            Server s = find(Json.str(spec, "server"));
            if (s == null) {
                return new String[]{"proxy", Text.t("Этого сервера больше нет в подписке — пока через основной VPN.",
                        "This server is gone from the subscription — using the main VPN for now.")};
            }
            if (main != null && s.key().equals(main.key())) {
                return new String[]{"proxy", ""};
            }
            if (!s.usable()) {
                return new String[]{"proxy", Text.t("Сервер не поддерживается — пока через основной VPN.",
                        "The server is not supported — using the main VPN for now.")};
            }
            return new String[]{"server", ""};
        }
        if ("custom".equals(via)) {
            return proxyById(Json.str(spec, "proxy")) != null ? new String[]{"custom", ""}
                    : new String[]{"proxy", Text.t("Прокси удалён — пока через основной VPN.", "The proxy was removed — using the main VPN for now.")};
        }
        return new String[]{"", ""};
    }

    /** Свои маршруты для настроек ядра. Сайты — раньше списков и сервисов, точный адрес — раньше общего. */
    List<Map<String, Object>> routePlan(Server main) {
        List<String> keys = new ArrayList<String>(routes().keySet());
        Collections.sort(keys, new Comparator<String>() {
            private int[] order(String k) {
                if (!k.startsWith("site:")) {
                    return new int[]{2, 0};
                }
                String v = k.substring(5);
                if (Routing.isIpEntry(v)) {
                    return new int[]{1, v.contains("/") ? -Integer.parseInt(v.substring(v.indexOf('/') + 1)) : -128};
                }
                return new int[]{0, -(v.length() - v.replace(".", "").length())};
            }

            @Override
            public int compare(String a, String b) {
                int[] x = order(a);
                int[] y = order(b);
                return x[0] != y[0] ? Integer.compare(x[0], y[0]) : Integer.compare(x[1], y[1]);
            }
        });
        List<Map<String, Object>> plan = new ArrayList<Map<String, Object>>();
        Map<String, String> pins = new LinkedHashMap<String, String>();
        Map<String, String> customs = new LinkedHashMap<String, String>();
        for (String key : keys) {
            Map<String, Object> spec = Json.map(routes().get(key));
            if (spec == null) {
                continue;
            }
            List<String> ips = new ArrayList<String>();
            List<String> domains = routeDomains(key, ips);
            if (domains.isEmpty() && ips.isEmpty()) {
                continue;
            }
            String kind = routeTarget(spec, main)[0];
            Map<String, Object> entry = Json.obj("domains", new ArrayList<Object>(domains), "ips", new ArrayList<Object>(ips),
                    "early", key.startsWith("site:"));
            if ("server".equals(kind)) {
                Server s = find(Json.str(spec, "server"));
                if (!pins.containsKey(s.key())) {
                    pins.put(s.key(), "pin" + pins.size());
                }
                entry.put("tag", pins.get(s.key()));
                entry.put("server", s);
                entry.put("mask", s.mask);
            } else if ("custom".equals(kind)) {
                Map<String, Object> px = proxyById(Json.str(spec, "proxy"));
                String id = Json.str(px, "id");
                if (!customs.containsKey(id)) {
                    customs.put(id, "custom" + customs.size());
                }
                entry.put("tag", customs.get(id));
                entry.put("proxy", px);
                entry.put("block_udp", "http".equals(Json.str(px, "type")) ? "" : "443"); // HTTP-прокси UDP не умеет
            } else if ("dpi".equals(kind)) {
                entry.put("tag", Dpi.OUTBOUND);
            } else if (!kind.isEmpty()) {
                entry.put("tag", kind);
            } else {
                continue;
            }
            plan.add(entry);
        }
        return plan;
    }

    private boolean planUsesDpi(List<Map<String, Object>> plan) {
        for (Map<String, Object> r : plan) {
            if (Dpi.OUTBOUND.equals(Json.str(r, "tag"))) {
                return true;
            }
        }
        return false;
    }

    /** Свои маршруты для интерфейса: выбор у сервисов, список сайтов и свои прокси. */
    public Map<String, Object> routesState() {
        synchronized (lock) {
            Server main = current;
            List<Object> services = new ArrayList<Object>();
            for (Services.Service svc : Services.ALL) {
                String rule = Routing.userRule(svc.domains.get(0), settings);
                Map<String, Object> spec = Json.map(routes().get("svc:" + svc.name));
                String warn = spec == null ? "" : routeTarget(spec, main)[1];
                services.add(Json.obj("name", svc.name, "russian", svc.russian,
                        "choice", !rule.isEmpty() ? rule : spec != null ? routeValue(spec) : "auto", "warn", warn));
            }
            List<Object> sites = new ArrayList<Object>();
            java.util.Set<String> own = new java.util.HashSet<String>();
            for (Map.Entry<String, Object> e : routes().entrySet()) {
                if (!e.getKey().startsWith("site:")) {
                    continue;
                }
                Map<String, Object> spec = Json.map(e.getValue());
                String site = e.getKey().substring(5);
                own.add(site.toLowerCase());
                sites.add(Json.obj("site", site, "value", routeValue(spec), "warn", routeTarget(spec, main)[1]));
            }
            // простые выборы (через VPN / напрямую / блок) лежат в списках — показываем обычные домены и IP из них
            for (String[] l : Routing.USER_LISTS) {
                for (String line : Json.str(settings, l[0]).split("\\r?\\n")) {
                    String[] item;
                    try {
                        item = Routing.normalizeEntry(line);
                    } catch (IllegalArgumentException ex) {
                        continue;
                    }
                    if (item == null || !(item[1].startsWith("domain:") || ("ip".equals(item[0]) && !item[1].startsWith("geoip:")))) {
                        continue;
                    }
                    String site = item[1].startsWith("domain:") ? item[1].substring(7) : item[1];
                    if (own.add(site.toLowerCase())) {
                        sites.add(Json.obj("site", site, "value", l[1], "warn", "", "list", true));
                    }
                }
            }
            List<Object> prox = new ArrayList<Object>();
            for (Map<String, Object> px : proxyList()) {
                Map<String, Object> pub = Proxies.publicView(px);
                List<Object> used = new ArrayList<Object>();
                for (Map.Entry<String, Object> e : routes().entrySet()) {
                    Map<String, Object> spec = Json.map(e.getValue());
                    if ("custom".equals(Json.str(spec, "via")) && Json.str(px, "id").equals(Json.str(spec, "proxy"))) {
                        used.add(e.getKey().substring(e.getKey().indexOf(':') + 1));
                    }
                }
                pub.put("used", used);
                pub.put("title", proxyTitle(px));
                prox.add(pub);
            }
            return Json.obj("services", services, "sites", sites.size() > 300 ? new ArrayList<Object>(sites.subList(0, 300)) : sites,
                    "sites_total", sites.size(), "proxies", prox);
        }
    }

    // ---------- свои прокси ----------

    public Map<String, Object> addProxy(String raw, String name, String kind, boolean chain) {
        Map<String, Object> px;
        try {
            px = Proxies.parse(raw, kind);
        } catch (Proxies.ProxyError e) {
            throw new UserError(e.getMessage());
        }
        synchronized (lock) {
            if (proxyList().size() >= Proxies.MAX) {
                throw new UserError(Text.t("Слишком много своих прокси — удали ненужные.", "Too many proxies — remove unused ones."));
            }
            for (Map<String, Object> x : proxyList()) {
                if (Json.str(x, "host").equals(Json.str(px, "host")) && Json.num(x, "port", 0) == Json.num(px, "port", 0)
                        && Json.str(x, "user").equals(Json.str(px, "user"))) {
                    throw new UserError(Text.t("Такой прокси уже есть: «", "This proxy already exists: “") + proxyTitle(x) + Text.t("».", "”."));
                }
            }
            px.put("id", Text.randomWord(6));
            px.put("name", Text.shorten(name == null ? "" : name.trim().replaceAll("\\s+", " "), 60));
            px.put("chain", chain);
            px.put("check", Json.obj());
            Json.list(settings, "proxies").add(px);
        }
        saveSettings();
        log("Добавлен свой прокси «" + proxyTitle(px) + "».", "Own proxy “" + proxyTitle(px) + "” added.");
        changed();
        return Proxies.publicView(px);
    }

    public void updateProxy(String id, String name, Boolean chain) {
        boolean restart = false;
        synchronized (lock) {
            Map<String, Object> px = proxyById(id);
            if (px == null) {
                throw new UserError(Text.t("Прокси не найден.", "Proxy not found."));
            }
            if (name != null) {
                px.put("name", Text.shorten(name.trim().replaceAll("\\s+", " "), 60));
            }
            if (chain != null && chain != Json.bool(px, "chain", true)) {
                px.put("chain", chain);
                px.put("check", Json.obj());
                restart = proxyInUse(id);
            }
        }
        saveSettings();
        if (restart) {
            applyCore();
        }
        changed();
    }

    private boolean proxyInUse(String id) {
        for (Object v : routes().values()) {
            Map<String, Object> spec = Json.map(v);
            if ("custom".equals(Json.str(spec, "via")) && id.equals(Json.str(spec, "proxy"))) {
                return true;
            }
        }
        return false;
    }

    /** Удаляет прокси. Сервисы и сайты, которые шли через него, возвращаются к «как по умолчанию». */
    public void removeProxy(String id) {
        String title;
        boolean used;
        synchronized (lock) {
            Map<String, Object> px = proxyById(id);
            if (px == null) {
                throw new UserError(Text.t("Прокси не найден.", "Proxy not found."));
            }
            title = proxyTitle(px);
            used = proxyInUse(id);
            for (String k : new ArrayList<String>(routes().keySet())) {
                Map<String, Object> spec = Json.map(routes().get(k));
                if ("custom".equals(Json.str(spec, "via")) && id.equals(Json.str(spec, "proxy"))) {
                    routes().remove(k);
                }
            }
            Json.list(settings, "proxies").remove(px);
        }
        saveSettings();
        log("Свой прокси «" + title + "» удалён.", "Own proxy “" + title + "” removed.");
        if (used) {
            applyCore();
        }
        changed();
    }

    /** Свободный порт на 127.0.0.1 для временного ядра. */
    static int freePort() {
        try {
            java.net.ServerSocket s = new java.net.ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"));
            int port = s.getLocalPort();
            s.close();
            return port;
        } catch (Exception e) {
            return 20000 + new Random().nextInt(9000);
        }
    }

    /** Проверка своего прокси: под каким IP и страной видят сайты и открывается ли TikTok. */
    public boolean checkProxy(final String id) {
        final Map<String, Object> px;
        synchronized (lock) {
            px = proxyById(id);
        }
        if (px == null) {
            throw new UserError(Text.t("Прокси не найден.", "Proxy not found."));
        }
        return runTask(Text.t("Проверяю прокси «", "Checking proxy “") + proxyTitle(px) + Text.t("»", "”"), "proxy", new Runnable() {
            @Override
            public void run() {
                checkProxyFlow(px);
            }
        });
    }

    void checkProxyFlow(Map<String, Object> px) {
        String title = proxyTitle(px);
        Server main = null;
        if (Json.bool(px, "chain", true)) {
            synchronized (lock) {
                main = current;
            }
            if (main == null) {
                List<Server> r = ranked();
                main = r.isEmpty() ? null : r.get(0);
            }
        }
        List<String> kinds = new ArrayList<String>();
        kinds.add(Json.str(px, "type", "socks"));
        if (!Json.bool(px, "type_known", false)) {
            kinds.add("socks".equals(kinds.get(0)) ? "http" : "socks");
        }
        Map<String, Object> result = Json.obj();
        for (String kind : kinds) {
            checkStop();
            Map<String, Object> trial = Json.copy(px);
            trial.put("type", kind);
            int port = freePort();
            java.io.Closeable core = null;
            try {
                core = p.startTestCore(Json.write(Proxies.testConfig(trial, port, main, main != null && main.mask, p.coreVersion())));
                Http.Response r = Http.probe(Proxies.TRACE_URL, null, 12000, port, 4096);
                Map<String, Object> info = Proxies.parseTrace(r.text());
                boolean ok = !Json.str(info, "ip").isEmpty();
                result = Json.obj("ok", ok, "ip", Json.str(info, "ip"), "loc", Json.str(info, "loc"),
                        "error", ok ? "" : Text.t("прокси не пропускает трафик", "the proxy passes no traffic"),
                        "at", System.currentTimeMillis(), "chain", main != null);
                if (ok) {
                    result.put("tiktok", siteState(Proxies.TIKTOK_URL, port)[0]);
                }
            } catch (Cancelled c) {
                throw c;
            } catch (Exception e) {
                result = Json.obj("ok", false, "ip", "", "loc", "", "error", Http.human(e), "at", System.currentTimeMillis(),
                        "chain", main != null);
            } finally {
                if (core != null) {
                    try {
                        core.close();
                    } catch (Exception ignored) {
                        // ядро уже остановлено
                    }
                }
            }
            if (Json.bool(result, "ok", false)) {
                boolean changedType = !kind.equals(Json.str(px, "type"));
                synchronized (lock) {
                    px.put("type", kind);
                    px.put("type_known", true);
                }
                if (changedType) {
                    log("Прокси «" + title + "» работает как " + ("http".equals(kind) ? "HTTP" : "SOCKS5") + " — запомнил.",
                            "Proxy “" + title + "” works as " + ("http".equals(kind) ? "HTTP" : "SOCKS5") + " — saved.");
                    if (proxyInUse(Json.str(px, "id"))) {
                        applyCore();
                    }
                }
                break;
            }
        }
        synchronized (lock) {
            px.put("check", result);
        }
        saveSettings();
        if (Json.bool(result, "ok", false)) {
            String cc = Json.str(result, "loc").isEmpty() ? "?" : Json.str(result, "loc");
            log("Прокси «" + title + "»: работает, страна " + cc + ".", "Proxy “" + title + "”: works, country " + cc + ".");
            say(Text.t("Прокси «" + title + "» работает, страна " + cc, "Proxy “" + title + "” works, country " + cc), "ok");
        } else {
            log("Прокси «" + title + "» не отвечает: " + Json.str(result, "error"), "Proxy “" + title + "” does not answer: "
                    + Json.str(result, "error"));
            say(Text.t("Прокси «" + title + "» не отвечает: ", "Proxy “" + title + "” does not answer: ") + Json.str(result, "error"), "error");
        }
    }

    // =====================================================================================================
    // ---------- обход замедлений YouTube и Discord ----------

    private long lastDpiCheck;
    private int dpiFails;

    /** Обход проверен и работает. */
    boolean dpiActive() {
        return Json.bool(settings, "dpi_enabled", true) && Json.bool(settings, "dpi_ok", false)
                && Dpi.find(Json.str(settings, "dpi_strategy")) != null;
    }

    /** Способ для выхода "dpi": подобранный, а если его нет — стандартный. */
    Dpi.Strategy dpiStrategy() {
        Dpi.Strategy s = Dpi.find(Json.str(settings, "dpi_strategy"));
        return s != null ? s : Dpi.STRATEGIES.get(0);
    }

    /** Проверить способ обхода через временное ядро. */
    Map<String, Object> dpiTest(Dpi.Strategy s, int timeoutMs) {
        int port = freePort();
        java.io.Closeable core = null;
        try {
            core = p.startTestCore(Json.write(Dpi.testConfig(Dpi.outbound(s, "out", p.coreVersion()), port)));
            return Dpi.check(port, Dpi.targets(settings), timeoutMs);
        } catch (Cancelled c) {
            throw c;
        } catch (Exception e) {
            Map<String, Object> out = new LinkedHashMap<String, Object>();
            for (String t : Dpi.targets(settings)) {
                out.put(t, Json.obj("ok", false, "kbps", -1L, "detail", Http.human(e)));
            }
            return out;
        } finally {
            if (core != null) {
                try {
                    core.close();
                } catch (Exception ignored) {
                    // уже остановлено
                }
            }
        }
    }

    /** Подобрать способ обхода: проверяет все, берёт самый быстрый из рабочих. */
    public boolean dpiPick() {
        return runTask(Text.t("Подбираю обход замедления", "Finding a throttling bypass"), "dpi", new Runnable() {
            @Override
            public void run() {
                dpiPickFlow(false);
            }
        });
    }

    void dpiPickFlow(boolean quiet) {
        List<Object> results = new ArrayList<Object>();
        Dpi.Strategy best = null;
        long bestKbps = -1;
        int i = 0;
        for (Dpi.Strategy s : Dpi.STRATEGIES) {
            checkStop();
            i++;
            progress(Text.t("Подбираю обход замедления: ", "Finding a throttling bypass: ") + i + Text.t(" из ", " of ")
                    + Dpi.STRATEGIES.size());
            Map<String, Object> res = dpiTest(s, 8000);
            boolean ok = Dpi.allOk(res);
            long kbps = Json.num(Json.map(res, "youtube"), "kbps", -1);
            StringBuilder why = new StringBuilder();
            for (Map.Entry<String, Object> e : res.entrySet()) {
                Map<String, Object> r = Json.map(e.getValue());
                if (!Json.bool(r, "ok", false)) {
                    why.append(why.length() > 0 ? "; " : "").append("youtube".equals(e.getKey()) ? "YouTube" : "Discord")
                            .append(": ").append(Json.str(r, "detail"));
                }
            }
            results.add(Json.obj("id", s.id, "ok", ok, "kbps", kbps, "detail", why.toString()));
            if (ok && (best == null || kbps > bestKbps)) {
                best = s;
                bestKbps = kbps;
            }
        }
        boolean was = dpiActive();
        String old = Json.str(settings, "dpi_strategy");
        synchronized (lock) {
            settings.put("dpi_results", results);
            settings.put("dpi_tested_at", System.currentTimeMillis());
            settings.put("dpi_ok", best != null);
            if (best != null) {
                settings.put("dpi_strategy", best.id);
            }
        }
        lastDpiCheck = System.currentTimeMillis();
        dpiFails = 0;
        saveSettings();
        if (best != null) {
            log("Обход замедления: работает «" + best.ru + "»" + (bestKbps > 0 ? ", " + bestKbps + " кбит/с" : "") + ".",
                    "Throttling bypass: “" + best.en + "” works" + (bestKbps > 0 ? ", " + bestKbps + " kbit/s" : "") + ".");
            if (!quiet) {
                say(Text.t("Обход замедления работает: ", "Throttling bypass works: ") + best.title(), "ok");
            }
        } else {
            log("Обход замедления: ни один способ не помог — YouTube и Discord идут через VPN.",
                    "Throttling bypass: no method helped — YouTube and Discord go through VPN.");
            if (!quiet) {
                say(Text.t("Ни один способ обхода не помог — YouTube и Discord пойдут через VPN.",
                        "No bypass method helped — YouTube and Discord will go through VPN."), "error");
            }
        }
        if (was != dpiActive() || !old.equals(Json.str(settings, "dpi_strategy"))) {
            applyCore();
        }
    }

    /** Лёгкая проверка текущего способа (раз в полчаса). Перестал работать — сайты возвращаются в VPN. */
    public void dpiCheckFlow() {
        Map<String, Object> res = dpiTest(dpiStrategy(), 8000);
        lastDpiCheck = System.currentTimeMillis();
        if (Dpi.allOk(res)) {
            dpiFails = 0;
            return;
        }
        if (++dpiFails < 2) {
            return;
        }
        dpiFails = 0;
        synchronized (lock) {
            settings.put("dpi_ok", false);
        }
        saveSettings();
        log("Обход замедления перестал работать — YouTube и Discord снова через VPN. Подберу другой способ.",
                "The throttling bypass stopped working — YouTube and Discord go through VPN again. Will find another method.");
        dpiPickFlow(true);
        if (!dpiActive()) {
            applyCore();
        }
    }

    /** Настройки обхода из интерфейса. */
    public void setDpi(Map<String, Object> in) {
        boolean recheck = false;
        boolean apply = false;
        synchronized (lock) {
            for (String k : new String[]{"dpi_enabled", "dpi_youtube", "dpi_discord", "dpi_without_vpn"}) {
                if (in.get(k) instanceof Boolean && !in.get(k).equals(settings.get(k))) {
                    settings.put(k, in.get(k));
                    apply = true;
                    recheck |= !"dpi_without_vpn".equals(k) && !"dpi_enabled".equals(k);
                }
            }
            Object custom = in.get("dpi_custom");
            if (custom instanceof String && ((String) custom).length() <= 20000 && !custom.equals(settings.get("dpi_custom"))) {
                settings.put("dpi_custom", custom);
                apply = true;
            }
            Object strat = in.get("dpi_strategy");
            if (strat instanceof String && Dpi.find((String) strat) != null && !strat.equals(settings.get("dpi_strategy"))) {
                settings.put("dpi_strategy", strat);
                settings.put("dpi_ok", false);
                recheck = true;
            }
            if (Boolean.TRUE.equals(in.get("dpi_enabled")) || Boolean.TRUE.equals(in.get("dpi_without_vpn"))) {
                filterBlocked = false;
            }
        }
        saveSettings();
        if (recheck && Json.bool(settings, "dpi_enabled", true)) {
            final Dpi.Strategy chosen = Dpi.find(Json.str(in, "dpi_strategy"));
            runTask(Text.t("Проверяю обход замедления", "Checking the throttling bypass"), "dpi", new Runnable() {
                @Override
                public void run() {
                    if (chosen != null) {
                        boolean ok = Dpi.allOk(dpiTest(chosen, 8000));
                        synchronized (lock) {
                            settings.put("dpi_ok", ok);
                            settings.put("dpi_tested_at", System.currentTimeMillis());
                        }
                        log(ok ? "Выбранный способ обхода работает." : "Выбранный способ обхода не помог.",
                                ok ? "The chosen bypass method works." : "The chosen bypass method did not help.");
                        say(ok ? Text.t("Способ работает", "The method works") : Text.t("Этот способ не помог — попробуй «Подобрать».",
                                "This method did not help — try “Find”."), ok ? "ok" : "error");
                        applyCore();
                    } else {
                        dpiPickFlow(true);
                        applyCore();
                    }
                }
            });
        } else if (apply) {
            applyCore();
        }
        changed();
    }

    public Map<String, Object> dpiState() {
        synchronized (lock) {
            List<Object> strategies = new ArrayList<Object>();
            for (Dpi.Strategy s : Dpi.STRATEGIES) {
                strategies.add(Json.obj("id", s.id, "title", s.title()));
            }
            return Json.obj("enabled", Json.bool(settings, "dpi_enabled", true), "youtube", Json.bool(settings, "dpi_youtube", true),
                    "discord", Json.bool(settings, "dpi_discord", true), "custom", Json.str(settings, "dpi_custom"),
                    "without_vpn", Json.bool(settings, "dpi_without_vpn", false), "strategy", Json.str(settings, "dpi_strategy"),
                    "ok", Json.bool(settings, "dpi_ok", false), "active", dpiActive(),
                    "tested_at", Json.num(settings, "dpi_tested_at", 0), "results", Json.list(settings, "dpi_results"),
                    "strategies", strategies, "routes", dpiRoutesUsed());
        }
    }

    private boolean dpiRoutesUsed() {
        for (Object v : routes().values()) {
            if ("dpi".equals(Json.str(Json.map(v), "via"))) {
                return true;
            }
        }
        return false;
    }

    // =====================================================================================================
    // ---------- блокировка рекламы и защита без VPN ----------

    private boolean filterOn;       // ядро работает без сервера: реклама блокируется, остальное напрямую
    private boolean filterBlocked;  // не включать само: туннель забрал другой VPN, нет разрешения или выключили вручную
    private boolean filterNoPermission;
    private long accessOffset;
    private final Map<String, Object> adsStats = Json.obj("day", "", "today", 0L, "top", new LinkedHashMap<String, Object>(),
            "recent", new ArrayList<Object>());
    // «сайт закрыт блокировщиком»: повторные заходы на сам сайт (example.com, www.example.com), попавший в списки
    private final Map<String, List<Long>> adsSiteHits = new HashMap<String, List<Long>>();
    private final Set<String> adsSiteAsked = new HashSet<String>();
    private final List<Long> adsAskTimes = new ArrayList<Long>();
    private final List<Object> adsSuspects = new ArrayList<Object>();
    static final long ADS_ASK_WINDOW = 90000;

    static String adsListName(String id) {
        if ("main".equals(id)) {
            return Text.t("реклама и трекеры", "ads and trackers");
        }
        if ("popups".equals(id)) {
            return Text.t("всплывающие окна", "pop-ups");
        }
        if ("threats".equals(id)) {
            return Text.t("опасные сайты", "dangerous sites");
        }
        return "ru".equals(id) ? Text.t("российская реклама", "Russian ads") : id;
    }

    /** Заблокирован адрес самого сайта, и к нему стучатся снова — похоже, его открывают. Спросим, разрешить ли. */
    void adsSiteHit(String host) {
        final String site = AdBlock.siteName(host);
        if (!Json.bool(settings, "ads_ask_sites", true) || site.isEmpty() || AdBlock.looksLikeAds(host) || !"dat".equals(adsMode())) {
            return;
        }
        final String h = host;
        long now = System.currentTimeMillis();
        synchronized (lock) {
            if (adsSiteAsked.contains(site) || Json.list(settings, "ads_site_ignore").contains(site)) {
                return;
            }
            List<Long> hits = adsSiteHits.get(site);
            if (hits == null) {
                hits = new ArrayList<Long>();
                adsSiteHits.put(site, hits);
            }
            for (java.util.Iterator<Long> it = hits.iterator(); it.hasNext(); ) {
                if (now - it.next() >= ADS_ASK_WINDOW) {
                    it.remove();
                }
            }
            hits.add(now);
            if (adsSiteHits.size() > 300) {
                adsSiteHits.clear();
            }
            if (hits.size() < 2) {
                return;
            }
            int recent = 0;
            for (long t : adsAskTimes) {
                if (now - t < 600000) {
                    recent++;
                }
            }
            if (recent >= 3) {
                return; // не больше трёх вопросов за 10 минут
            }
            adsSiteAsked.add(site);
            adsAskTimes.add(now);
            while (adsAskTimes.size() > 10) {
                adsAskTimes.remove(0);
            }
        }
        pool.submit(new Runnable() {
            @Override
            public void run() {
                adsSiteSuspect(site, h);
            }
        });
    }

    @SuppressWarnings("unchecked")
    void adsSiteSuspect(String site, String host) {
        Map<String, Object> r;
        try {
            r = adsLookup(host);
        } catch (RuntimeException e) {
            return;
        }
        if (!Json.bool(r, "blocked", false) || !Json.str(r, "custom").isEmpty()) {
            return;
        }
        List<Object> names = new ArrayList<Object>();
        List<String> ids = new ArrayList<String>();
        for (Object o : Json.list(r, "lists")) {
            String id = Json.str((Map<String, Object>) o, "id");
            ids.add(id);
            names.add(adsListName(id));
        }
        boolean threat = ids.size() == 1 && "threats".equals(ids.get(0));
        StringBuilder where = new StringBuilder();
        for (Object n : names) {
            where.append(where.length() == 0 ? "" : ", ").append('«').append(n).append('»');
        }
        synchronized (lock) {
            adsSuspects.add(0, Json.obj("site", site, "host", host, "lists", names, "threat", threat,
                    "at", System.currentTimeMillis()));
            while (adsSuspects.size() > 20) {
                adsSuspects.remove(adsSuspects.size() - 1);
            }
        }
        log("Реклама: похоже, закрыт сам сайт " + site + " (список " + where + ").",
                "Ads: looks like the site " + site + " itself is blocked (list " + where + ").");
        if (p instanceof Notices) {
            try {
                ((Notices) p).notice(Text.t("Сайт закрыт блокировщиком", "Site blocked by ad blocker"),
                        threat ? Text.t(site + " в списке опасных сайтов. Разрешить можно в разделе «Реклама».",
                                site + " is on the dangerous sites list. You can allow it in the Ads section.")
                                : Text.t(site + " в списке " + where + ". Открой «Рекламу», чтобы разрешить.",
                                site + " is on the list " + where + ". Open Ads to allow it."));
            } catch (RuntimeException ignored) {
                // уведомление — не главное
            }
        }
        changed();
    }

    /** Ответ на «сайт закрыт блокировщиком»: разрешить сайт целиком или больше не спрашивать. */
    @SuppressWarnings("unchecked")
    public String adsSiteAnswer(String raw, boolean allow) {
        String site = AdBlock.siteName(raw == null ? "" : raw.trim());
        if (site.isEmpty()) {
            site = siteKey(raw, false);
        }
        synchronized (lock) {
            for (java.util.Iterator<Object> it = adsSuspects.iterator(); it.hasNext(); ) {
                if (site.equals(Json.str((Map<String, Object>) it.next(), "site"))) {
                    it.remove();
                }
            }
        }
        if (allow) {
            adsAllow(site);
            return site;
        }
        synchronized (lock) {
            List<Object> ignore = new ArrayList<Object>(Json.list(settings, "ads_site_ignore"));
            ignore.remove(site);
            ignore.add(site);
            while (ignore.size() > 300) {
                ignore.remove(0);
            }
            settings.put("ads_site_ignore", ignore);
        }
        saveSettings();
        log("Реклама: " + site + " остаётся закрытым, больше не спрашиваю.", "Ads: " + site + " stays blocked, won't ask again.");
        changed();
        return site;
    }

    File adsDir() {
        return new File(p.dataDir(), "adblock");
    }

    File adsDat() {
        return new File(new File(p.dataDir(), "assets"), AdBlock.DAT);
    }

    File accessLog() {
        return new File(p.dataDir(), "access.log");
    }

    boolean adsPaused() {
        return Json.num(settings, "ads_pause_until", 0) > System.currentTimeMillis();
    }

    /** Как ядру блокировать рекламу сейчас: dat — свои списки, geo — запасной список, "" — не блокировать. */
    String adsMode() {
        if (!Json.bool(settings, "block_ads", false) || adsPaused()) {
            return "";
        }
        if (adsDat().length() > 16) {
            return "dat";
        }
        return geoReady() ? "geo" : "";
    }

    /** Нужна ли защита без VPN: реклама и/или обход замедлений, пока VPN выключен. */
    public boolean filterWanted() {
        if (isOn() || filterBlocked) {
            return false;
        }
        boolean ads = Json.bool(settings, "block_ads", false) && Json.bool(settings, "ads_without_vpn", true) && !adsPaused()
                && !adsMode().isEmpty();
        boolean dpi = Json.bool(settings, "dpi_without_vpn", false) && dpiActive();
        return ads || dpi;
    }

    public boolean filterOn() {
        synchronized (lock) {
            return filterOn;
        }
    }

    private XrayConfig.Options filterOptions() {
        XrayConfig.Options o = new XrayConfig.Options();
        o.useGeo = geoReady();
        o.coreVersion = p.coreVersion();
        o.tun = true;
        o.ads = Json.bool(settings, "ads_without_vpn", true) ? adsMode() : "";
        if (Json.bool(settings, "dpi_without_vpn", false) && dpiActive()) {
            o.dpi = dpiStrategy();
            o.dpiDomains = Dpi.domains(settings);
        }
        o.accessLog = o.ads.isEmpty() ? "" : accessLog().getAbsolutePath();
        return o;
    }

    private void resetAccessLog() {
        try {
            new java.io.RandomAccessFile(accessLog(), "rw").setLength(0);
        } catch (Exception ignored) {
            // нет файла — не важно
        }
        accessOffset = 0;
    }

    /** Включить (или перенастроить) защиту без VPN. Вызывается из задачи или фоновой проверки. */
    void startFilterNow() {
        XrayConfig.Options o = filterOptions();
        String cfg = Json.write(XrayConfig.filterConfig(settings, o));
        resetAccessLog();
        boolean was = filterOn();
        try {
            p.startVpn(cfg, excludedApps());
        } catch (Cancelled c) {
            throw c;
        } catch (Exception e) {
            String m = e.getMessage() == null ? e.toString() : e.getMessage();
            synchronized (lock) {
                filterOn = false;
                filterBlocked = true;
                filterNoPermission = m.contains("VPN_PERMISSION") || m.toLowerCase().contains("permission");
            }
            log("Защита без VPN не включилась: " + (filterNoPermission ? "нет разрешения на VPN" : m),
                    "Protection without VPN did not start: " + (filterNoPermission ? "no VPN permission" : m));
            changed();
            return;
        }
        synchronized (lock) {
            filterOn = true;
            filterNoPermission = false;
        }
        if (!was) {
            String what = !o.ads.isEmpty() && o.dpi != null ? Text.t("реклама блокируется, YouTube и Discord — с обходом замедления",
                    "ads are blocked, YouTube and Discord use the throttling bypass")
                    : !o.ads.isEmpty() ? Text.t("реклама блокируется", "ads are blocked")
                    : Text.t("YouTube и Discord — с обходом замедления", "YouTube and Discord use the throttling bypass");
            log("Защита без VPN включена: " + what + ".", "Protection without VPN is on: " + what + ".");
        }
        changed();
    }

    void stopFilterNow() {
        boolean was;
        synchronized (lock) {
            was = filterOn;
            filterOn = false;
        }
        if (was && !isOn()) {
            p.stopVpn();
            log("Защита без VPN выключена.", "Protection without VPN is off.");
        }
        changed();
    }

    /** Включить защиту без VPN по кнопке (после разрешения VPN). */
    public boolean filterStart() {
        synchronized (lock) {
            filterBlocked = false;
            filterNoPermission = false;
        }
        if (!filterWanted()) {
            return false;
        }
        return runTask(Text.t("Включаю защиту без VPN", "Turning on protection without VPN"), "filter", new Runnable() {
            @Override
            public void run() {
                startFilterNow();
            }
        });
    }

    /** Выключить защиту без VPN до следующего включения вручную (кнопка в уведомлении). */
    public void filterStopByUser() {
        synchronized (lock) {
            filterBlocked = true;
        }
        stopFilterNow();
    }

    /**
     * Применить настройки к работающему ядру: VPN — перезапуск, без VPN — включить, перенастроить или выключить
     * защиту без VPN. Всегда в очереди подключения; если она занята — сразу после текущего действия.
     */
    public void applyCore() {
        if (connBusy()) {
            pendingApply = true;
            return;
        }
        boolean started;
        if (isOn()) {
            started = runTask(Text.t("Применяю настройки", "Applying settings"), "connect", new Runnable() {
                @Override
                public void run() {
                    Server s;
                    synchronized (lock) {
                        s = current;
                    }
                    if (isOn() && s != null && !startWith(s)) {
                        failover();
                    }
                }
            });
        } else if (filterWanted()) {
            started = runTask(Text.t("Включаю защиту без VPN", "Turning on protection without VPN"), "filter", new Runnable() {
                @Override
                public void run() {
                    if (!isOn() && filterWanted()) {
                        startFilterNow();
                    }
                }
            });
        } else if (filterOn()) {
            started = runTask(Text.t("Выключаю защиту без VPN", "Turning off protection without VPN"), "filter", new Runnable() {
                @Override
                public void run() {
                    if (!isOn()) {
                        stopFilterNow();
                    }
                }
            });
        } else {
            return;
        }
        if (!started) {
            pendingApply = true; // очередь заняли между проверкой и запуском
        }
    }

    static final String[] ADS_KEYS = {"block_ads", "ads_level", "ads_lists", "ads_custom", "ads_allow", "ads_without_vpn",
            "ads_update_hours"};

    /** Настройки блокировки рекламы. Возвращает {download: нужно ли качать списки, filter: нужна ли защита без VPN}. */
    public Map<String, Object> setAds(Map<String, Object> in) {
        boolean download = false;
        boolean rebuild = false;
        boolean apply = false;
        synchronized (lock) {
            for (String k : ADS_KEYS) {
                if (!in.containsKey(k)) {
                    continue;
                }
                Object v = in.get(k);
                Object old = settings.get(k);
                boolean ok;
                if ("block_ads".equals(k) || "ads_without_vpn".equals(k)) {
                    ok = v instanceof Boolean;
                } else if ("ads_level".equals(k)) {
                    ok = v instanceof String && AdBlock.LEVELS.containsKey(v);
                } else if ("ads_lists".equals(k)) {
                    Map<String, Object> m = Json.map(v);
                    ok = m != null;
                    if (ok) {
                        Map<String, Object> clean = new LinkedHashMap<String, Object>();
                        for (String id : AdBlock.EXTRA) {
                            clean.put(id, Json.bool(m, id, false));
                        }
                        v = clean;
                    }
                } else if ("ads_update_hours".equals(k)) {
                    ok = v instanceof Number && ((Number) v).longValue() >= 0 && ((Number) v).longValue() <= 24 * 30;
                    if (ok) {
                        v = ((Number) v).longValue();
                    }
                } else {
                    ok = v instanceof String && ((String) v).length() <= 200000 && ((String) v).indexOf('\0') < 0;
                }
                if (!ok || v.equals(old)) {
                    continue;
                }
                settings.put(k, v);
                if ("block_ads".equals(k)) {
                    apply = true;
                    if (Boolean.TRUE.equals(v)) {
                        filterBlocked = false;
                        download = !AdBlock.cached("main", Json.str(settings, "ads_level", AdBlock.DEFAULT_LEVEL), adsDir());
                        rebuild = !download && adsDat().length() <= 16;
                    }
                } else if ("ads_level".equals(k) || "ads_lists".equals(k)) {
                    download = true;
                } else if ("ads_custom".equals(k) || "ads_allow".equals(k)) {
                    rebuild = true;
                } else if ("ads_without_vpn".equals(k)) {
                    apply = true;
                    if (Boolean.TRUE.equals(v)) {
                        filterBlocked = false;
                    }
                }
            }
        }
        saveSettings();
        boolean enabled = Json.bool(settings, "block_ads", false);
        if (enabled && download) {
            updateAdblock(true);
        } else if (enabled && rebuild) {
            runTask(Text.t("Собираю список рекламы", "Building the ad list"), "ads", new Runnable() {
                @Override
                public void run() {
                    buildAdblock();
                    applyCore();
                }
            });
        } else if (apply) {
            applyCore();
        }
        changed();
        return Json.obj("download", download, "filter", !isOn() && Json.bool(settings, "block_ads", false)
                && Json.bool(settings, "ads_without_vpn", true));
    }

    /** Скачать списки рекламы и собрать файл для ядра. onlyMissing — только недостающие. */
    public boolean updateAdblock(final boolean onlyMissing) {
        return runTask(Text.t("Скачиваю списки рекламы", "Downloading ad lists"), "ads", new Runnable() {
            @Override
            public void run() {
                updateAdblockFlow(onlyMissing);
                applyCore();
            }
        });
    }

    void updateAdblockFlow(boolean onlyMissing) {
        String level = Json.str(settings, "ads_level", AdBlock.DEFAULT_LEVEL);
        List<String> ids = new ArrayList<String>();
        ids.add("main");
        Map<String, Object> lists = Json.map(settings, "ads_lists");
        for (String id : AdBlock.EXTRA) {
            if (lists != null && Json.bool(lists, id, false)) {
                ids.add(id);
            }
        }
        List<String> failed = new ArrayList<String>();
        for (final String id : ids) {
            checkStop();
            if (onlyMissing && AdBlock.cached(id, level, adsDir())) {
                continue;
            }
            // напрямую, через VPN, через другие серверы (GitHub и jsDelivr в России иногда не открываются)
            final String lvl = level;
            List<String> errs = new ArrayList<String>();
            boolean ok = downloadAny(new PortJob() {
                @Override
                public void run(int route) throws Exception {
                    AdBlock.download(id, lvl, adsDir(), route, 60000);
                }
            }, "Списки рекламы", "Ad lists", errs);
            if (!ok) {
                failed.add(id + " (" + (errs.isEmpty() ? "" : errs.get(errs.size() - 1)) + ")");
            }
        }
        if (!failed.isEmpty()) {
            log("Не все списки рекламы скачались: " + String.join(", ", failed), "Not all ad lists downloaded: " + String.join(", ", failed));
        }
        settings.put("ads_updated_at", System.currentTimeMillis());
        buildAdblock();
    }

    void buildAdblock() {
        progress(Text.t("Собираю список рекламы", "Building the ad list"));
        try {
            Map<String, Object> info = AdBlock.build(adsDir(), adsDat(), Json.str(settings, "ads_level", AdBlock.DEFAULT_LEVEL),
                    Json.map(settings, "ads_lists"), Json.str(settings, "ads_custom"), Json.str(settings, "ads_allow"));
            synchronized (lock) {
                settings.put("ads_info", info);
            }
            log("Список рекламы готов: адресов — " + Json.num(info, "total", 0) + ".",
                    "The ad list is ready: " + Json.num(info, "total", 0) + " addresses.");
        } catch (Exception e) {
            log("Не удалось собрать список рекламы: " + Http.human(e), "Could not build the ad list: " + Http.human(e));
        }
        saveSettings();
    }

    /** Разрешить сайт (из журнала): в исключения и пересобрать список. */
    public void adsAllow(String host) {
        final String entry = siteKey(host, false);
        synchronized (lock) {
            if (AdBlock.parseUser(Json.str(settings, "ads_allow")).contains(entry)) {
                return;
            }
            String allow = Json.str(settings, "ads_allow");
            settings.put("ads_allow", (allow.isEmpty() || allow.endsWith("\n") ? allow : allow + "\n") + entry);
            // запись из «своих сайтов» тоже убираем — иначе исключение не сработает
            List<String> kept = new ArrayList<String>();
            for (String line : Json.str(settings, "ads_custom").split("\\r?\\n")) {
                if (!AdBlock.parseUser(line).contains(entry)) {
                    kept.add(line);
                }
            }
            settings.put("ads_custom", String.join("\n", kept).trim());
        }
        saveSettings();
        log(entry + ": реклама на нём больше не блокируется.", entry + ": ads are no longer blocked there.");
        runTask(Text.t("Собираю список рекламы", "Building the ad list"), "ads", new Runnable() {
            @Override
            public void run() {
                buildAdblock();
                applyCore();
            }
        });
        changed();
    }

    /** «Проверить сайт»: почему он блокируется (какой список, свои правила) или что не блокируется. */
    public Map<String, Object> adsLookup(String host) {
        String entry = siteKey(host, false);
        Map<String, Object> r;
        try {
            r = AdBlock.lookup(adsDir(), Json.str(settings, "ads_level", AdBlock.DEFAULT_LEVEL), Json.map(settings, "ads_lists"),
                    Json.str(settings, "ads_custom"), Json.str(settings, "ads_allow"), entry);
        } catch (java.io.IOException e) {
            throw new UserError(e.getMessage());
        }
        r.put("user_rule", Routing.userRule(entry, settings));
        r.put("enabled", Json.bool(settings, "block_ads", false));
        r.put("mode", adsMode());
        return r;
    }

    /** Пауза блокировки рекламы на minutes минут (0 — снять паузу). */
    public void adsPause(long minutes) {
        synchronized (lock) {
            settings.put("ads_pause_until", minutes > 0 ? System.currentTimeMillis() + minutes * 60000L : 0L);
            if (minutes <= 0) {
                filterBlocked = false;
            }
        }
        saveSettings();
        log(minutes > 0 ? "Блокировка рекламы на паузе: " + minutes + " мин." : "Блокировка рекламы снова работает.",
                minutes > 0 ? "Ad blocking paused for " + minutes + " min." : "Ad blocking works again.");
        applyCore();
        changed();
    }

    private static final java.util.regex.Pattern ACCESS = java.util.regex.Pattern.compile(
            "accepted (?:tcp|udp):(\\S+?):\\d+ .*adblock\\]");
    /** Любое соединение из журнала ядра: адрес и куда пошёл (для «сайт работает не полностью»). */
    private static final java.util.regex.Pattern ACCESS_ALL = java.util.regex.Pattern.compile(
            "accepted (?:tcp|udp):(\\S+?):(\\d+) \\[\\S+ (?:->|>>) (\\S+)\\]");
    /** (время, адрес, куда пошёл) — недавние соединения. */
    private final java.util.ArrayDeque<Object[]> hostLog = new java.util.ArrayDeque<Object[]>();

    /** Новые строки журнала ядра → счётчик заблокированной рекламы (сегодня, частые адреса, последние). */
    @SuppressWarnings("unchecked")
    void tailAccessLog() {
        File f = accessLog();
        long len = f.length();
        if (len < accessOffset) {
            accessOffset = 0;
        }
        if (len == accessOffset) {
            return;
        }
        try {
            java.io.RandomAccessFile raf = new java.io.RandomAccessFile(f, "r");
            byte[] buf;
            try {
                raf.seek(accessOffset);
                buf = new byte[(int) Math.min(len - accessOffset, 1024 * 1024)];
                raf.readFully(buf);
            } finally {
                raf.close();
            }
            String text = new String(buf, java.nio.charset.StandardCharsets.UTF_8);
            int lastNl = text.lastIndexOf('\n');
            if (lastNl < 0) {
                return;
            }
            accessOffset += text.substring(0, lastNl + 1).getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
            String day = new SimpleDateFormat("yyyy-MM-dd", Locale.US).format(new Date());
            String time = new SimpleDateFormat("HH:mm", Locale.US).format(new Date());
            List<String> blockedSites = new ArrayList<String>();
            synchronized (lock) {
                if (!day.equals(adsStats.get("day"))) {
                    adsStats.put("day", day);
                    adsStats.put("today", 0L);
                    adsStats.put("top", new LinkedHashMap<String, Object>());
                }
                Map<String, Object> top = (Map<String, Object>) adsStats.get("top");
                List<Object> recent = (List<Object>) adsStats.get("recent");
                java.util.regex.Matcher m = ACCESS.matcher(text.substring(0, lastNl));
                while (m.find()) {
                    String host = m.group(1);
                    if (host.startsWith("[") && host.endsWith("]")) {
                        host = host.substring(1, host.length() - 1);
                    }
                    if (blockedSites.size() < 50 && !AdBlock.siteName(host).isEmpty()) {
                        blockedSites.add(host);
                    }
                    adsStats.put("today", Json.num(adsStats, "today", 0) + 1);
                    top.put(host, Json.num(top, host, 0) + 1);
                    if (top.size() > 400) {
                        top.remove(top.keySet().iterator().next());
                    }
                    recent.add(0, Json.obj("host", host, "time", time));
                    while (recent.size() > 40) {
                        recent.remove(recent.size() - 1);
                    }
                }
            }
            java.util.regex.Matcher all = ACCESS_ALL.matcher(text.substring(0, lastNl));
            long nowMs = System.currentTimeMillis();
            synchronized (hostLog) {
                while (all.find()) {
                    String host = all.group(1);
                    if (host.startsWith("[") && host.endsWith("]")) {
                        host = host.substring(1, host.length() - 1);
                    }
                    hostLog.addLast(new Object[]{nowMs, host, all.group(3)});
                    if (hostLog.size() > 5000) {
                        hostLog.removeFirst();
                    }
                }
            }
            for (String host : blockedSites) {
                adsSiteHit(host);
            }
            if (accessOffset > 2L * 1024 * 1024) {
                resetAccessLog(); // журнал нужен только для счётчика — не даём ему расти
            }
        } catch (Exception ignored) {
            // журнала ещё нет
        }
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> adsState() {
        synchronized (lock) {
            Map<String, Object> info = Json.map(settings, "ads_info");
            Map<String, Object> lists = Json.map(settings, "ads_lists");
            Map<String, Object> on = new LinkedHashMap<String, Object>();
            for (String id : AdBlock.EXTRA) {
                on.put(id, lists != null && Json.bool(lists, id, false));
            }
            List<Map.Entry<String, Object>> top = new ArrayList<Map.Entry<String, Object>>(((Map<String, Object>) adsStats.get("top")).entrySet());
            Collections.sort(top, new Comparator<Map.Entry<String, Object>>() {
                @Override
                public int compare(Map.Entry<String, Object> a, Map.Entry<String, Object> b) {
                    return Long.compare(((Number) b.getValue()).longValue(), ((Number) a.getValue()).longValue());
                }
            });
            List<Object> topOut = new ArrayList<Object>();
            for (Map.Entry<String, Object> e : top.subList(0, Math.min(12, top.size()))) {
                topOut.add(Json.obj("host", e.getKey(), "n", e.getValue(), "domain", !Text.isIp(e.getKey())));
            }
            long pause = Json.num(settings, "ads_pause_until", 0);
            String today = new SimpleDateFormat("yyyy-MM-dd", Locale.US).format(new Date());
            return Json.obj("enabled", Json.bool(settings, "block_ads", false),
                    "without_vpn", Json.bool(settings, "ads_without_vpn", true),
                    "level", Json.str(settings, "ads_level", AdBlock.DEFAULT_LEVEL), "lists", on,
                    "counts", info == null ? Json.obj() : Json.map(info, "lists"), "total", info == null ? 0L : Json.num(info, "total", 0),
                    "missing", info == null ? new ArrayList<Object>() : Json.list(info, "missing"),
                    "ready", adsDat().length() > 16, "mode", adsMode(), "updated_at", Json.num(settings, "ads_updated_at", 0),
                    "update_hours", Json.num(settings, "ads_update_hours", 24),
                    "paused_until", pause > System.currentTimeMillis() ? pause : 0L, "filter_on", filterOn,
                    "filter_blocked", filterBlocked, "need_permission", filterNoPermission,
                    "custom", Json.str(settings, "ads_custom"), "allow", Json.str(settings, "ads_allow"),
                    "today", today.equals(adsStats.get("day")) ? Json.num(adsStats, "today", 0) : 0L,
                    "top", topOut, "recent", new ArrayList<Object>((List<Object>) adsStats.get("recent")),
                    "suspects", new ArrayList<Object>(adsSuspects));
        }
    }

    /** Реже и не так срочно: обновление списков рекламы, подбор и проверка обхода замедлений. */
    // ---------- точность часов ----------
    public static String CLOCK_URL = "http://connectivitycheck.gstatic.com/generate_204";
    static final long CLOCK_MAX_SKEW_MS = 120000L; // VMess отказывает при расхождении больше ~2 минут
    private volatile long lastClockCheck;

    /** На сколько миллисекунд часы телефона расходятся с точным временем (заголовок Date). null — не узнали. */
    public static Long clockSkew() {
        try {
            long t0 = System.currentTimeMillis();
            Http.Response r = Http.request(CLOCK_URL, null, 6000, 0, 0);
            String date = r.headers.get("date");
            if (date == null) {
                return null;
            }
            SimpleDateFormat f = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);
            f.setTimeZone(java.util.TimeZone.getTimeZone("GMT"));
            long server = f.parse(date).getTime();
            return (t0 + System.currentTimeMillis()) / 2 - server;
        } catch (Exception e) {
            return null;
        }
    }

    /** Неточные часы — частая причина «ничего не работает»: VMess и проверка сертификатов зависят от времени. */
    public void clockCheck(Long skew) {
        if (skew == null) {
            return;
        }
        if (Math.abs(skew) > CLOCK_MAX_SKEW_MS) {
            long mins = Math.max(1, Math.round(Math.abs(skew) / 60000.0));
            problem("clock", skew > 0 ? Text.t("Часы на телефоне спешат на " + mins + " мин", "The phone clock is " + mins + " min fast")
                            : Text.t("Часы на телефоне отстают на " + mins + " мин", "The phone clock is " + mins + " min slow"),
                    Text.t("Серверы VMess и защищённые соединения не работают, если часы сбиты. Настройки → Дата и время → "
                                    + "«Автоматически».",
                            "VMess servers and secure connections don't work with a wrong clock. Settings → Date & time → "
                                    + "“Automatic”."));
        } else {
            resolve("clock");
        }
    }

    private boolean monitorLate(boolean on, long now) {
        if (tick > 6 && now - lastClockCheck > 6 * 3600000L) {
            lastClockCheck = now;
            pool.submit(new Runnable() {
                @Override
                public void run() {
                    clockCheck(clockSkew());
                }
            });
        }
        if (Update.configured() && Json.bool(settings, "app_update", true) && tick > 24 && !bgBusy()
                && now - Json.num(settings, "app_update_checked", 0) > 24 * 3600000L) {
            settings.put("app_update_checked", now);
            runTask(Text.t("Проверяю обновление", "Checking for an update"), "app_update", new Runnable() {
                @Override
                public void run() {
                    try {
                        appUpdateFlow();
                    } catch (UserError e) {
                        log("Автообновление: " + e.getMessage(), "Auto-update: " + e.getMessage());
                    }
                }
            });
            return true;
        }
        boolean filter = filterOn();
        // списки рекламы: раз в несколько часов (через минуту после запуска — не сразу)
        long hours = Json.num(settings, "ads_update_hours", 24);
        if (Json.bool(settings, "block_ads", false) && hours > 0 && tick > 12
                && now - Json.num(settings, "ads_updated_at", 0) > hours * 3600000L) {
            settings.put("ads_updated_at", now - Math.max(0, hours - 1) * 3600000L); // при неудаче — снова через час
            updateAdblock(false);
            return true;
        }
        // обход замедлений: подобрать (если ещё не) и проверять раз в полчаса
        if (Json.bool(settings, "dpi_enabled", true) && (on || filter) && tick > 12) {
            long tested = Json.num(settings, "dpi_tested_at", 0);
            // ещё ни разу не подбирали — подобрать; не работает — пробовать снова не чаще раза в 6 часов
            if (tested == 0 || (!Json.bool(settings, "dpi_ok", false) && now - tested > 6 * 3600000L)) {
                settings.put("dpi_tested_at", now); // не чаще раза в 6 часов, даже если подбор прервут
                runTask(Text.t("Подбираю обход замедления", "Finding a throttling bypass"), "dpi", new Runnable() {
                    @Override
                    public void run() {
                        dpiPickFlow(true);
                    }
                });
                return true;
            }
            if (dpiActive() && now - lastDpiCheck > 30 * 60000L) {
                lastDpiCheck = now;
                runTask(Text.t("Проверяю обход замедления", "Checking the throttling bypass"), "dpi", new Runnable() {
                    @Override
                    public void run() {
                        dpiCheckFlow();
                    }
                });
                return true;
            }
        }
        return false;
    }

    /** Фоновая работа рекламы и обхода: журнал, конец паузы, защита без VPN. */
    /** Подписка скоро закончится или кончается трафик — предупредить заранее (уведомление не чаще раза в день). */
    @SuppressWarnings("unchecked")
    public void subAlerts() {
        boolean onOff = Json.bool(settings, "sub_alerts", true);
        long now = System.currentTimeMillis();
        Map<String, Object> sent = Json.map(settings, "sub_alerts_sent");
        if (sent == null) {
            sent = new LinkedHashMap<String, Object>();
            settings.put("sub_alerts_sent", sent);
        }
        boolean save = false;
        for (Map<String, Object> m : subs()) {
            String id = Json.str(m, "id");
            String name = Json.str(m, "title").isEmpty() ? Json.str(m, "name") : Json.str(m, "title");
            Map<String, Object> u = Json.map(m, "usage");
            List<String[]> alerts = new ArrayList<String[]>(); // вид, заголовок
            long exp = u == null ? -1 : Json.num(u, "expire", -1);
            if (exp > 0) {
                double days = (exp * 1000.0 - now) / 86400000.0;
                if (days <= 0) {
                    alerts.add(new String[]{"expire", Text.t("Подписка «" + name + "» закончилась", "Subscription “" + name + "” has expired")});
                } else if (days <= 3) {
                    long d = Math.max(1, Math.round(days));
                    alerts.add(new String[]{"expire", Text.t("Подписка «" + name + "» закончится через " + d + " дн.",
                            "Subscription “" + name + "” expires in " + d + " d")});
                }
            }
            long total = u == null ? 0 : Json.num(u, "total", 0);
            long used = u == null ? 0 : Json.num(u, "upload", 0) + Json.num(u, "download", 0);
            if (total > 0 && used >= total) {
                alerts.add(new String[]{"traffic", Text.t("В подписке «" + name + "» закончился трафик", "Subscription “" + name + "” is out of traffic")});
            } else if (total > 0 && used >= total * 0.9) {
                alerts.add(new String[]{"traffic", Text.t("В подписке «" + name + "» осталось меньше 10% трафика",
                        "Subscription “" + name + "” has less than 10% traffic left")});
            }
            for (String kind : new String[]{"expire", "traffic"}) {
                boolean has = false;
                for (String[] a : alerts) {
                    has |= a[0].equals(kind);
                }
                if (!has || !onOff) {
                    resolve("subalert_" + kind + "_" + id);
                }
            }
            if (!onOff) {
                continue;
            }
            for (String[] a : alerts) {
                problem("subalert_" + a[0] + "_" + id, a[1], a[0].equals("expire")
                        ? Text.t("Продли её у провайдера заранее, чтобы VPN не пропал.", "Renew it with the provider in advance so the VPN doesn't stop.")
                        : Text.t("Докупи трафик у провайдера или дождись нового периода.", "Buy more traffic from the provider or wait for the new period."));
                String mark = id + ":" + a[0] + ":" + a[1].hashCode();
                if (now - Json.num(sent, mark, 0) > 86400000L) {
                    sent.put(mark, now);
                    save = true;
                    if (p instanceof Notices) {
                        try {
                            ((Notices) p).notice("VEDOMYJ VPN", a[1]);
                        } catch (RuntimeException ignored) {
                            // уведомление — не главное
                        }
                    }
                }
            }
        }
        if (save) {
            saveSettings();
        }
    }

    private boolean monitorExtras(boolean on, long now) {
        tailAccessLog();
        if (tick % 720 == 6) {
            subAlerts(); // раз в час (и вскоре после запуска)
        }
        if (tick % 60 == 2) {
            netWatch(); // раз в 5 минут для подстраховки: обычно смену сети сообщает сам Android (PultVpnService)
        }
        if (tick % 4320 == 120) {
            certWatch(); // раз в 6 часов (и через 10 минут после запуска)
        }
        boolean filter = filterOn();
        if (filter && !p.vpnAlive()) {
            synchronized (lock) {
                filterOn = false;
                filterBlocked = true; // туннель забрал другой VPN — не воюем за него
            }
            log("Защиту без VPN выключила система (возможно, включился другой VPN).",
                    "Protection without VPN was turned off by the system (maybe another VPN started).");
            changed();
            return false;
        }
        long pause = Json.num(settings, "ads_pause_until", 0);
        if (pause > 0 && pause <= now) {
            settings.put("ads_pause_until", 0L);
            saveSettings();
            log("Пауза закончилась — реклама снова блокируется.", "The pause is over — ads are blocked again.");
            applyCore();
            return true;
        }
        if (!on) {
            boolean want = filterWanted();
            if (want != filter) {
                applyCore();
                return true;
            }
        }
        return false;
    }


    // =====================================================================================================
    // ---------- скорость: сейчас и замер ----------

    /** Откуда качать для замера (как у программы для Windows). В самопроверке подменяется. */
    public static String[] SPEED_URLS = {"https://speed.cloudflare.com/__down?bytes=60000000",
            "http://cachefly.cachefly.net/100mb.test", "https://proof.ovh.net/files/100Mb.dat"};

    private long speedAt;
    private long speedRx = -1;
    private long speedTx = -1;
    private double speedDown;
    private double speedUp;
    private Map<String, Object> lastSpeedTest;

    /** Текущая скорость через туннель, байт/с (сглаженная). Вызывается при каждом опросе состояния. */
    private Map<String, Object> liveSpeed() {
        if (!(p instanceof Traffic) || (!"on".equals(status) && !filterOn)) {
            speedRx = -1;
            speedDown = 0;
            speedUp = 0;
            return Json.obj("down", 0L, "up", 0L);
        }
        long now = System.currentTimeMillis();
        if (speedRx >= 0 && now - speedAt < 700) {
            return Json.obj("down", (long) speedDown, "up", (long) speedUp);
        }
        long[] b;
        try {
            b = ((Traffic) p).trafficBytes();
        } catch (Exception e) {
            return Json.obj("down", 0L, "up", 0L);
        }
        if (b == null || b.length < 2 || b[0] < 0) {
            return Json.obj("down", 0L, "up", 0L);
        }
        if (speedRx >= 0 && now > speedAt) {
            double sec = (now - speedAt) / 1000.0;
            double d = Math.max(0, (b[0] - speedRx) / sec);
            double u = Math.max(0, (b[1] - speedTx) / sec);
            // сглаживание: цифры не прыгают каждую секунду, но быстро догоняют
            speedDown = speedDown <= 0 ? d : speedDown * 0.35 + d * 0.65;
            speedUp = speedUp <= 0 ? u : speedUp * 0.35 + u * 0.65;
        }
        speedRx = b[0];
        speedTx = b[1];
        speedAt = now;
        return Json.obj("down", (long) speedDown, "up", (long) speedUp);
    }

    /** Строка для уведомления: «↓ 1,2 МБ/с ↑ 40 КБ/с» ("" — нечего показать). */
    public static String speedText(long down, long up) {
        if (down < 1024 && up < 1024) {
            return "";
        }
        return "↓ " + rate(down) + " ↑ " + rate(up);
    }

    static String rate(long bps) {
        if (bps >= 1024 * 1024) {
            return String.format(Locale.US, "%.1f", bps / 1048576.0).replace('.', ',') + Text.t(" МБ/с", " MB/s");
        }
        return Math.max(0, bps / 1024) + Text.t(" КБ/с", " KB/s");
    }

    /** Замер скорости: несколько секунд качаем большой файл (через VPN, если он включён). */
    // ---------- «Сайт работает не полностью» (как в программе для ПК) ----------

    /** Проверка «качается ли» (в самопроверке подменяется). proxyPort 0 — напрямую. */
    public interface Staller {
        Map<String, Object> test(String host, int proxyPort);
    }

    public static Staller STALL = new Staller() {
        @Override
        public Map<String, Object> test(String host, int proxyPort) {
            return Http.stallTest(host, proxyPort, 443, 4000, 14000, Http.STALL_TARGET);
        }
    };

    static final long REPAIR_WINDOW = 20000, REPAIR_LOOKBACK = 900000;
    static final int REPAIR_MAX = 20;
    private volatile Map<String, Object> lastRepair;

    /** Адреса, которые загружал сайт: к ним обращались вместе с ним. → [[адрес, куда шёл]]. */
    List<String[]> relatedHosts(String site) {
        long now = System.currentTimeMillis();
        List<Object[]> log = new ArrayList<Object[]>();
        synchronized (hostLog) {
            for (Object[] x : hostLog) {
                if (now - (Long) x[0] < REPAIR_LOOKBACK) {
                    log.add(x);
                }
            }
        }
        List<Long> hits = new ArrayList<Long>();
        for (Object[] x : log) {
            String h = (String) x[1];
            if (h.equals(site) || h.endsWith("." + site)) {
                hits.add((Long) x[0]);
            }
        }
        if (hits.isEmpty()) {
            return new ArrayList<String[]>();
        }
        final Map<String, Integer> score = new LinkedHashMap<String, Integer>();
        Map<String, String> route = new HashMap<String, String>();
        for (Object[] x : log) {
            String h = (String) x[1];
            long t = (Long) x[0];
            route.put(h, (String) x[2]);
            boolean mine = h.equals(site) || h.endsWith("." + site);
            boolean near = mine;
            for (long hit : hits) {
                if (Math.abs(t - hit) <= REPAIR_WINDOW) {
                    near = true;
                    break;
                }
            }
            if (near) {
                score.put(h, (score.containsKey(h) ? score.get(h) : 0) + (mine ? 1000 : 1));
            }
        }
        List<String> ranked = new ArrayList<String>(score.keySet());
        Collections.sort(ranked, new Comparator<String>() {
            @Override
            public int compare(String a, String b) {
                return score.get(b) - score.get(a);
            }
        });
        List<String[]> out = new ArrayList<String[]>();
        for (String h : ranked.subList(0, Math.min(REPAIR_MAX, ranked.size()))) {
            out.add(new String[]{h, route.get(h)});
        }
        return out;
    }

    /** Временное ядро: вход HTTP на 127.0.0.1:port → этот сервер. */
    Map<String, Object> serverTestConfig(Server x, int port) {
        List<Object> outbounds = new ArrayList<Object>(XrayConfig.proxyOutbounds(x, "proxy", x.mask, p.coreVersion()));
        outbounds.add(Json.obj("tag", "direct", "protocol", "freedom"));
        return Json.obj("log", Json.obj("loglevel", "none"),
                "inbounds", Json.arr(Json.obj("tag", "in", "listen", "127.0.0.1", "port", port, "protocol", "http",
                        "settings", Json.obj())),
                "outbounds", outbounds,
                "routing", Json.obj("domainStrategy", "AsIs", "rules", Json.arr(
                        Json.obj("type", "field", "inboundTag", Json.arr("in"), "outboundTag", "proxy"))));
    }

    /** Для самопроверки: записать соединение в недавние. */
    public void noteHost(long at, String host, String route) {
        synchronized (hostLog) {
            hostLog.addLast(new Object[]{at, host, route});
        }
    }

    public boolean repairSite(final String raw) {
        if (!isOn()) {
            throw new UserError(Text.t("Сначала включи VPN: программа сравнит, как сайт работает напрямую и через VPN.",
                    "Turn the VPN on first: the app compares how the site works directly and through the VPN."));
        }
        final String host = siteKey(raw, false).replaceFirst("^domain:", "");
        if (!host.contains(".")) {
            throw new UserError(Text.t("Не похоже на адрес сайта. Пример: example.com.", "This doesn't look like a site address."));
        }
        lastRepair = null;
        return runTask(Text.t("Чиню сайт", "Fixing site"), "repair", new Runnable() {
            @Override
            public void run() {
                repairFlow(host);
            }
        });
    }

    @SuppressWarnings("unchecked")
    void repairFlow(String host) {
        String site = siteKey(host, true).replaceFirst("^domain:", "");
        List<String[]> related = relatedHosts(site);
        boolean seen = !related.isEmpty();
        if (!seen) {
            related.add(new String[]{host, ""});
        }
        int vpn = appPort;
        List<Object> items = new ArrayList<Object>();
        int fixes = 0;
        int broken = 0;
        int blocked = 0;
        List<Server> others = null;
        Map<String, Object> newRoutes = new LinkedHashMap<String, Object>();
        for (String[] hr : related) {
            checkStop();
            String h = hr[0];
            String route = hr[1] == null ? "" : hr[1];
            progress(Text.t("Чиню сайт " + site + ": " + h, "Fixing site " + site + ": " + h));
            Map<String, Object> item = Json.obj("host", h, "route", route, "state", "", "detail", "", "fix", "");
            items.add(item);
            if ("block".equals(route) || AdBlock.OUTBOUND.equals(route)) {
                item.put("state", "blocked");
                item.put("detail", AdBlock.OUTBOUND.equals(route) ? Text.t("закрыт блокировщиком рекламы", "blocked by the ad blocker")
                        : Text.t("закрыт своим правилом «Блокировать»", "blocked by your own Block rule"));
                blocked++;
                continue;
            }
            if (Text.isIp(h)) {
                item.put("state", "skip");
                continue;
            }
            boolean direct = "direct".equals(route) || (route.isEmpty() && "direct".equals(Routing.routeForHost(h, settings)));
            Map<String, Object> st = STALL.test(h, direct ? 0 : vpn);
            item.put("state", Json.str(st, "state"));
            item.put("detail", Json.str(st, "detail"));
            String state = Json.str(st, "state");
            if ("ok".equals(state) || "small".equals(state)) {
                continue;
            }
            broken++;
            if (!Routing.userRule(h, settings).isEmpty()) {
                item.put("detail", Json.str(item, "detail") + Text.t("; есть своё правило — не меняю", "; you have your own rule — not changing it"));
                continue;
            }
            String entry = siteKey(h, true).replaceFirst("^domain:", "");
            if (direct) {
                Map<String, Object> sv = STALL.test(h, vpn);
                if ("ok".equals(Json.str(sv, "state")) || "small".equals(Json.str(sv, "state"))) {
                    newRoutes.put("site:" + entry, Json.obj("via", "proxy"));
                    item.put("fix", "proxy");
                    fixes++;
                    continue;
                }
            }
            if (others == null) {
                others = new ArrayList<Server>();
                for (Server x : ranked()) {
                    if (current == null || !x.key().equals(current.key())) {
                        others.add(x);
                    }
                    if (others.size() >= 3) {
                        break;
                    }
                }
            }
            for (Server x : others) {
                checkStop();
                int port = freePort();
                java.io.Closeable core = null;
                try {
                    core = p.startTestCore(Json.write(serverTestConfig(x, port)));
                    Map<String, Object> so = STALL.test(h, port);
                    if ("ok".equals(Json.str(so, "state")) || "small".equals(Json.str(so, "state"))) {
                        newRoutes.put("site:" + entry, Json.obj("via", "server", "server", x.key(), "server_name", x.name));
                        item.put("fix", "server");
                        item.put("server", x.name);
                        fixes++;
                        break;
                    }
                } catch (Cancelled c) {
                    throw c;
                } catch (Exception ignored) {
                    // этот сервер не запустился — следующий
                } finally {
                    if (core != null) {
                        try {
                            core.close();
                        } catch (Exception ignored) {
                            // уже остановлено
                        }
                    }
                }
            }
            if (Json.str(item, "fix").isEmpty() && !direct) {
                // ни через один сервер не качается. Человек сам попросил починить — пробуем и без VPN
                Map<String, Object> sd = STALL.test(h, 0);
                if ("ok".equals(Json.str(sd, "state")) || "small".equals(Json.str(sd, "state"))) {
                    newRoutes.put("site:" + entry, Json.obj("via", "direct"));
                    item.put("fix", "direct");
                    fixes++;
                }
            }
        }
        if (!newRoutes.isEmpty()) {
            synchronized (lock) {
                for (Map.Entry<String, Object> e : newRoutes.entrySet()) {
                    clearSite(e.getKey().substring(5));
                    routes().put(e.getKey(), e.getValue());
                }
            }
            saveSettings();
            applyCore();
        }
        String verdict;
        if (fixes > 0) {
            verdict = Text.t("Починил " + fixes + " из " + broken + ": эти адреса теперь идут туда, где работают (они в «Своих маршрутах»). Обнови страницу сайта.",
                    "Fixed " + fixes + " of " + broken + ": these addresses now go where they work (see Own routes). Reload the site page.");
        } else if (broken > 0) {
            verdict = Text.t("Нашёл неработающие адреса, но рабочего пути для них нет ни напрямую, ни через другие серверы. Возможно, сломан сам сайт.",
                    "Found broken addresses, but no working path for them — neither direct nor through other servers. The site itself may be broken.");
        } else if (blocked > 0) {
            verdict = Text.t("Все адреса качаются. Часть закрыта блокировщиком — если сайт без них не работает, разреши их в «Рекламе».",
                    "All addresses download fine. Some are blocked by the ad blocker — if the site doesn't work without them, allow them in Ads.");
        } else if (!seen) {
            verdict = Text.t("Сам сайт работает. Открой его в браузере (с картинками и видео) и нажми кнопку ещё раз — тогда программа увидит все адреса, которые он загружает.",
                    "The site itself works. Open it in the browser (with pictures and videos) and press the button again — then the app sees every address it loads.");
        } else {
            verdict = Text.t("Все адреса сайта работают.", "All the site's addresses work.");
        }
        log("Починка сайта " + site + ": проверено " + items.size() + ", исправлено " + fixes + ".",
                "Site fix " + site + ": " + items.size() + " checked, " + fixes + " fixed.");
        lastRepair = Json.obj("site", site, "hosts", items, "fixed", (long) fixes, "verdict", verdict, "seen", seen,
                "at", System.currentTimeMillis());
        changed();
    }

    // ---------- обновление приложения ----------

    private volatile Map<String, Object> appUpdate;

    public File updateApk() {
        return new File(new File(p.dataDir(), "update"), "update.apk");
    }

    public boolean appUpdateCheck() {
        if (!Update.configured()) {
            throw new UserError(Text.t("Автообновление появится, когда у программы будет свой репозиторий на GitHub.",
                    "Auto-update appears once the app has its own GitHub repository."));
        }
        return runTask(Text.t("Проверяю обновление", "Checking for an update"), "app_update", new Runnable() {
            @Override
            public void run() {
                appUpdateFlow();
            }
        });
    }

    void appUpdateFlow() {
        @SuppressWarnings("unchecked")
        final Map<String, Object>[] box = new Map[1];
        final int[] status = {0};
        List<String> errs = new ArrayList<String>();
        boolean got = downloadAny(new PortJob() {
            @Override
            public void run(int route) throws Exception {
                Http.Response r = Http.requestOwn(Update.URL, null, 20000, route, 256 * 1024);
                status[0] = r.status;
                if (r.status != 200) {
                    throw new IOException(Text.t("сервер ответил кодом ", "server answered with code ") + r.status);
                }
                box[0] = Update.unpack(Json.parseObject(r.text()), Update.PUBLIC_N, Update.PUBLIC_E);
            }
        }, "Обновление приложения", "App update", errs);
        if (!got) {
            throw new UserError(Text.t("Файл выпуска не скачался: ", "The release file didn't download: ")
                    + (errs.isEmpty() ? "" : errs.get(0)));
        }
        Map<String, Object> m = box[0];
        if (m == null) {
            throw new UserError(Text.t("Подпись выпуска не сходится — обновление не будет установлено.",
                    "The release signature doesn't match — the update won't be installed."));
        }
        settings.put("app_update_checked", System.currentTimeMillis());
        Map<String, Object> apk = Json.map(m, "android");
        String ver = apk != null && !Json.str(apk, "version").isEmpty() ? Json.str(apk, "version") : Json.str(m, "version");
        if (!Update.newer(ver, p.appVersion()) || apk == null) {
            appUpdate = Json.obj("version", p.appVersion(), "newer", false);
            log("Обновлений нет: " + p.appVersion() + " — последняя версия.", "No updates: " + p.appVersion() + " is the latest.");
            changed();
            return;
        }
        String url = Json.str(apk, "url");
        String want = Json.str(apk, "sha256").toLowerCase(Locale.ROOT);
        if (!url.startsWith("https://") && !url.startsWith("http://127.0.0.1")) {
            throw new UserError(Text.t("В файле выпуска нет приложения для телефона.", "The release has no phone app."));
        }
        final File dest = updateApk();
        dest.getParentFile().mkdirs();
        progress(Text.t("Скачиваю обновление " + ver, "Downloading update " + ver));
        final String apkUrl = url;
        List<String> apkErrs = new ArrayList<String>();
        boolean apkOk = downloadAny(new PortJob() {
            @Override
            public void run(int route) throws Exception {
                Http.downloadTo(apkUrl, dest, 60000, route, 200L * 1024 * 1024);
            }
        }, "Обновление приложения", "App update", apkErrs);
        if (!apkOk) {
            dest.delete();
            throw new UserError(Text.t("Обновление не скачалось: ", "The update didn't download: ")
                    + (apkErrs.isEmpty() ? "" : apkErrs.get(0)));
        }
        try {
            if (!Update.sha256(dest).equals(want)) {
                dest.delete();
                throw new UserError(Text.t("Обновление повреждено (не совпала контрольная сумма).", "The update is damaged (checksum mismatch)."));
            }
        } catch (UserError e) {
            throw e;
        } catch (Exception e) {
            dest.delete();
            throw new UserError(Text.t("Обновление не скачалось: ", "The update didn't download: ") + Http.human(e));
        }
        appUpdate = Json.obj("version", ver, "newer", true, "ready", true, "notes", Json.str(m, "notes"));
        log("Обновление " + ver + " скачано и проверено — нажми «Установить».", "Update " + ver + " is downloaded and verified — tap Install.");
        if (p instanceof Notices) {
            try {
                ((Notices) p).notice("VEDOMYJ VPN", Text.t("Готово обновление " + ver + " — открой приложение, чтобы установить.",
                        "Update " + ver + " is ready — open the app to install."));
            } catch (RuntimeException ignored) {
                // уведомление — не главное
            }
        }
        saveSettings();
        changed();
    }

    // ---------- проверка сертификатов ----------

    /** Контрольные сайты, сертификаты телефона — без записи в состояние. quick — два сайта вместо четырёх. */
    Map<String, Object> certCompute(boolean quick) {
        int vpnPort = isOn() ? appPort : 0;
        List<String> roots = null;
        List<String> users = null;
        if (p instanceof CertStore) {
            try {
                List<String> r = new ArrayList<String>();
                List<String> u = new ArrayList<String>();
                for (boolean user : new boolean[]{false, true}) {
                    List<byte[]> list = ((CertStore) p).caCerts(user);
                    for (byte[] der : list == null ? new ArrayList<byte[]>() : list) {
                        List<String> rn = Certs.russianNames(der);
                        for (String n : rn) {
                            if (!r.contains(n)) {
                                r.add(n);
                            }
                        }
                        String name = Certs.certName(der);
                        if (user && rn.isEmpty() && !u.contains(name)) {
                            u.add(name);
                        }
                    }
                }
                roots = r;
                users = u;
            } catch (RuntimeException e) {
                roots = null; // хранилище не прочиталось — про него ничего не говорим
            }
        }
        String[] hosts = quick ? new String[]{Certs.PROBE_HOSTS[0], Certs.PROBE_HOSTS[1]} : null;
        return Certs.check(vpnPort, hosts, roots, users, null, true);
    }

    private static List<String> strList(Map<String, Object> m, String key) {
        List<String> out = new ArrayList<String>();
        for (Object o : vlist(m, key)) {
            out.add(String.valueOf(o));
        }
        Collections.sort(out);
        return out;
    }

    /** Проверить и показать: проблемы «!», уведомление (если нашлась подмена в фоне), запись в журнал. */
    Map<String, Object> certFlow(boolean quick) {
        Map<String, Object> res = certCompute(quick);
        res.put("time", System.currentTimeMillis());
        List<String> roots = strList(res, "russian_root");
        boolean acked = !roots.isEmpty() && roots.equals(strList(settings, "cert_root_ack"));
        res.put("acked", acked);
        lastCerts = res;
        boolean was;
        synchronized (lock) {
            was = problems.containsKey("cert_mitm") || problems.containsKey("cert_vpn");
        }
        String first = "";
        for (Object o : vlist(res, "items")) {
            String st = Json.str(Json.map(o), "state");
            if (first.isEmpty() && ("error".equals(st) || "warn".equals(st))) {
                first = Json.str(Json.map(o), "title");
            }
        }
        boolean mitm = Json.bool(res, "mitm", false);
        boolean vpnMitm = Json.bool(res, "vpn_mitm", false);
        if (mitm) {
            problem("cert_mitm", Text.t("В этой сети подменяют сертификаты сайтов", "Website certificates are substituted in this network"),
                    first + ". " + Text.t("Включи «Всё через VPN». Пароли вводи только через VPN.",
                            "Turn on “Everything through VPN”. Enter passwords only through the VPN."));
        } else {
            resolve("cert_mitm");
        }
        if (vpnMitm) {
            Server cur = current;
            problem("cert_vpn", Text.t("Сервер VPN подменяет сертификаты сайтов", "The VPN server substitutes website certificates"),
                    (cur == null ? "" : cur.name + ". ") + Text.t("Смени сервер и не вводи пароли, пока не сменишь.",
                            "Switch the server and don't enter passwords until you do."));
        } else {
            resolve("cert_vpn");
        }
        if (!roots.isEmpty() && !acked) {
            problem("cert_root", Text.t("На телефоне стоит сертификат Минцифры", "A Russian Ministry certificate is installed on the phone"),
                    Text.t("Им можно подписать любой сайт. Подробнее и кнопка «Понятно» — «Проверка программы».",
                            "It can sign any website. Details and the “Got it” button — “Program check”."));
        } else {
            resolve("cert_root");
        }
        long errs = Json.num(res, "errors", 0);
        long warns = Json.num(res, "warnings", 0);
        if (!quick || errs > 0 || warns > 0) {
            log("Проверка сертификатов: ошибок " + errs + ", предупреждений " + warns + ".",
                    "Certificate check: " + errs + " errors, " + warns + " warnings.");
        }
        if (quick && (mitm || vpnMitm) && !was && p instanceof Notices) {
            try {
                ((Notices) p).notice(Text.t("Подмена сертификатов", "Certificate substitution"),
                        vpnMitm ? Text.t("Сервер VPN подменяет защищённые соединения. Смени сервер.",
                                "The VPN server substitutes secure connections. Switch the server.")
                                : Text.t("В этой сети перехватывают защищённые соединения. Пароли — только через VPN.",
                                "Secure connections are intercepted in this network. Passwords — only through the VPN."));
            } catch (RuntimeException ignored) {
                // уведомление — не главное
            }
        }
        changed();
        return res;
    }

    public boolean certCheck() {
        return runTask(Text.t("Проверяю сертификаты", "Checking certificates"), "certs", new Runnable() {
            @Override
            public void run() {
                Map<String, Object> r = certFlow(false);
                long e = Json.num(r, "errors", 0);
                long w = Json.num(r, "warnings", 0);
                say(e > 0 ? Text.t("Сертификаты: найдена подмена", "Certificates: substitution found")
                        : w > 0 ? Text.t("Сертификаты: есть предупреждения", "Certificates: there are warnings")
                        : Text.t("Сертификаты в порядке", "Certificates are fine"), e > 0 ? "error" : "ok");
            }
        });
    }

    /** «Понятно, это я поставил» — сертификат Минцифры больше не показывается как проблема (пока не сменится). */
    public void certAck() {
        Map<String, Object> r = lastCerts;
        List<String> roots = strList(r, "russian_root");
        synchronized (lock) {
            settings.put("cert_root_ack", new ArrayList<Object>(roots));
        }
        saveSettings();
        resolve("cert_root");
        if (r != null) {
            r.put("acked", true);
        }
        changed();
    }

    /** Тихая проверка в фоне: смена сети и раз в 6 часов. Выключается «Слежкой за подменой сертификатов». */
    void certWatch() {
        if (!Json.bool(settings, "cert_watch", true) || !certWatching.compareAndSet(false, true)) {
            return;
        }
        Thread th = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(CERT_WATCH_DELAY_MS); // дать сети подняться
                    certFlow(true);
                } catch (InterruptedException ignored) {
                    // выключаемся
                } catch (Throwable e) {
                    recordBug(e, "проверка сертификатов");
                } finally {
                    certWatching.set(false);
                }
            }
        }, "certs");
        th.setDaemon(true);
        th.start();
    }

    public static long CERT_WATCH_DELAY_MS = 8000;

    // ---------- журнал ошибок ----------

    public Map<String, Object> errorsState() {
        return Json.obj("items", new ArrayList<Object>(errors.recent(ErrorLog.MAX_ENTRIES)), "repo", errorsRepo(),
                "file", errors.file().getName());
    }

    /** Куда отправлять заявки: свой репозиторий из настроек или тот, откуда приходят обновления. */
    public String errorsRepo() {
        String own = Json.str(settings, "github_repo");
        return own.isEmpty() ? ErrorLog.repoFrom(Update.URL) : own;
    }

    public String setErrorsRepo(String text) {
        String t = text == null ? "" : text.trim();
        String repo = ErrorLog.repoFrom(t.matches("[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+") ? "https://github.com/" + t : t);
        if (repo.isEmpty() && !t.isEmpty()) {
            throw new UserError(Text.t("Нужен адрес вида https://github.com/имя/репозиторий.",
                    "Need an address like https://github.com/name/repository."));
        }
        synchronized (lock) {
            settings.put("github_repo", repo);
        }
        saveSettings();
        return repo;
    }

    /** Текст заявки и ссылка на новую заявку (пустая — репозиторий не указан). */
    public Map<String, Object> errorsIssue() {
        Map<String, Object> t = errors.issueText(10);
        t.put("url", errors.issueUrl(errorsRepo(), 10));
        return t;
    }

    public void errorsClear() {
        errors.clear();
        changed();
    }

    // ---------- проверка утечек ----------

    public static String LEAK_IP_URL = "http://ip-api.com/json/?fields=status,countryCode,isp,query";
    public static String LEAK_DNS_URL = "http://edns.ip-api.com/json";
    private volatile Map<String, Object> lastLeaks;

    public boolean leakTest() {
        if (!isOn()) {
            throw new UserError(Text.t("Сначала включи VPN — проверять нечего.", "Turn the VPN on first — nothing to test."));
        }
        return runTask(Text.t("Проверяю утечки", "Testing for leaks"), "leaks", new Runnable() {
            @Override
            public void run() {
                leakFlow();
            }
        });
    }

    private static Map<String, Object> fetchJson(String url, int port) throws Exception {
        Http.Response r = Http.request(url, null, 10000, port, 65536);
        if (r.status != 200) {
            throw new java.io.IOException("HTTP " + r.status);
        }
        return Json.parseObject(r.text());
    }

    void leakFlow() {
        List<Object> items = new ArrayList<Object>();
        Map<String, Object> vpn = null;
        Map<String, Object> real = null;
        try {
            vpn = fetchJson(LEAK_IP_URL, appPort);
        } catch (Exception e) {
            items.add(Json.obj("state", "error", "title", Text.t("Через VPN не удалось узнать адрес", "Couldn't get the address through the VPN"),
                    "detail", Http.human(e)));
        }
        checkStop();
        try {
            real = fetchJson(LEAK_IP_URL, 0);
        } catch (Exception ignored) {
            // без адреса напрямую сравнивать не с чем
        }
        if (vpn != null) {
            String vip = Json.str(vpn, "query");
            if (real != null && vip.equals(Json.str(real, "query"))) {
                items.add(Json.obj("state", "error", "title", Text.t("VPN не меняет адрес: сайты видят твой настоящий IP",
                        "The VPN doesn't change your address: sites see your real IP"), "detail", vip,
                        "fix", Text.t("Выбери другой сервер.", "Choose another server.")));
            } else {
                items.add(Json.obj("state", "ok", "title", Text.t("Сайты через VPN видят адрес сервера, а не твой",
                        "Sites through the VPN see the server's address, not yours"),
                        "detail", vip + " (" + Json.str(vpn, "countryCode") + ", " + Json.str(vpn, "isp") + ")"));
            }
        }
        checkStop();
        try {
            Map<String, Object> d = Json.map(fetchJson(LEAK_DNS_URL, appPort), "dns");
            String geo = d == null ? "" : Json.str(d, "geo");
            String isp = real == null ? "" : Json.str(real, "isp");
            boolean same = false;
            for (String w : isp.split("\\s+")) {
                if (w.length() > 3 && geo.toLowerCase(Locale.ROOT).contains(w.toLowerCase(Locale.ROOT).replaceAll("[.,]", ""))) {
                    same = true;
                }
            }
            items.add(same ? Json.obj("state", "error", "title", Text.t("Запросы DNS идут через провайдера", "DNS requests go through your ISP"),
                    "detail", geo, "fix", Text.t("Включи «Шифрование DNS» и выключи «Частный DNS» в Android, если он указывает на провайдера.",
                            "Turn on DNS encryption and turn off Android Private DNS if it points to your ISP."))
                    : Json.obj("state", "ok", "title", Text.t("DNS не идёт через провайдера", "DNS doesn't go through your ISP"), "detail", geo));
        } catch (Exception e) {
            items.add(Json.obj("state", "info", "title", Text.t("DNS проверить не удалось", "Couldn't test DNS"), "detail", Http.human(e)));
        }
        items.add(Json.obj("state", "ok", "title", Text.t("WebRTC и звонки идут через VPN", "WebRTC and calls go through the VPN"),
                "detail", Text.t("На телефоне через VPN идёт весь трафик приложений.", "On the phone all app traffic goes through the VPN.")));
        if ("smart".equals(Json.str(settings, "mode", "vpn")) && !netPublic) {
            items.add(Json.obj("state", "info", "title", Text.t("Обычные сайты идут напрямую и видят настоящий адрес — так устроен экономный режим",
                    "Ordinary sites go direct and see your real address — that's how economy mode works")));
        } else if (Json.bool(settings, "ru_direct", true) && !netPublic) {
            items.add(Json.obj("state", "info", "title", Text.t("Российские сайты идут напрямую и видят настоящий адрес",
                    "Russian sites go direct and see your real address"), "detail",
                    Text.t("Так банки, Госуслуги и магазины открываются быстрее и не просят капчу.",
                            "This way banks, Gosuslugi and shops open faster and don't ask for a captcha.")));
        }
        long errors = 0;
        for (Object o : items) {
            if ("error".equals(Json.str(Json.map(o), "state"))) {
                errors++;
            }
        }
        log("Проверка утечек: проблем " + errors + ".", "Leak test: " + errors + " problems.");
        lastLeaks = Json.obj("items", items, "errors", errors, "at", System.currentTimeMillis());
        changed();
    }

    public boolean speedTest() {
        return runTask(Text.t("Замеряю скорость", "Measuring speed"), "speed", new Runnable() {
            @Override
            public void run() {
                speedTestFlow(8000);
            }
        });
    }

    void speedTestFlow(final long millis) {
        final int route = isOn() ? appPort : 0;
        String server;
        synchronized (lock) {
            server = current == null ? "" : current.name;
        }
        String err = "";
        for (String url : SPEED_URLS) {
            checkStop();
            final long[] got = {0};
            final long start = System.currentTimeMillis();
            java.io.OutputStream sink = new java.io.OutputStream() {
                @Override
                public void write(int b) throws java.io.IOException {
                    write(new byte[]{(byte) b}, 0, 1);
                }

                @Override
                public void write(byte[] b, int off, int len) throws java.io.IOException {
                    got[0] += len;
                    if (System.currentTimeMillis() - start > millis || here().stop) {
                        throw new SpeedDone();
                    }
                }
            };
            try {
                Http.exchange(url, null, 10000, route, Long.MAX_VALUE, false, sink);
            } catch (SpeedDone done) {
                // время вышло — так и задумано
            } catch (Exception e) {
                if (got[0] < 512 * 1024) {
                    err = Http.human(e);
                    continue; // этот адрес не отвечает — пробуем следующий
                }
            }
            checkStop();
            long ms = Math.max(1, System.currentTimeMillis() - start);
            if (got[0] < 256 * 1024) {
                continue;
            }
            double mbps = got[0] * 8.0 / ms / 1000.0;
            synchronized (lock) {
                lastSpeedTest = Json.obj("mbps", Math.round(mbps * 10) / 10.0, "at", System.currentTimeMillis(), "vpn", route > 0,
                        "server", server);
            }
            String v = String.format(Locale.US, "%.1f", mbps).replace('.', ',');
            log("Скорость " + (route > 0 ? "через VPN" + (server.isEmpty() ? "" : " («" + server + "»)") : "без VPN") + ": " + v + " Мбит/с.",
                    "Speed " + (route > 0 ? "via VPN" + (server.isEmpty() ? "" : " (“" + server + "”)") : "without VPN") + ": " + v + " Mbit/s.");
            say(Text.t("Скорость: " + v + " Мбит/с", "Speed: " + v + " Mbit/s"), "ok");
            return;
        }
        throw new UserError(Text.t("Не удалось замерить скорость: ", "Could not measure the speed: ")
                + (err.isEmpty() ? Text.t("файл не скачивается", "the file does not download") : err));
    }

    private static final class SpeedDone extends java.io.IOException {
        SpeedDone() {
            super("done");
        }
    }

    public Platform platform() {
        return p;
    }
}
