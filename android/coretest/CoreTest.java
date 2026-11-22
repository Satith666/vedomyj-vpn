import com.pultvpn.app.core.*;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Самопроверка ядра приложения для Android на обычной Java: имитация телефона (FakePlatform) и сервера подписки.
 * Запуск: coretest/run.sh
 */
public class CoreTest {
    static int passed, failed;

    static void check(boolean ok, String what) {
        if (!ok) {
            throw new AssertionError(what);
        }
    }

    interface Case {
        void run() throws Exception;
    }

    static void test(String name, Case c) {
        long t = System.currentTimeMillis();
        try {
            c.run();
            passed++;
            System.out.println("[OK]   " + name + " (" + (System.currentTimeMillis() - t) + " мс)");
        } catch (Throwable e) {
            failed++;
            System.out.println("[FAIL] " + name + ": " + e);
            e.printStackTrace(System.out);
        }
    }

    // ---------- имитация телефона ----------

    static final String U = "11111111-2222-3333-4444-555555555555";
    static final String PBK = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde";

    static String link(String host, String name) {
        return "vless://" + U + "@" + host + ":443?type=tcp&security=reality&pbk=" + PBK + "&sni=www.microsoft.com&sid=ab#"
                + Text.quote(name);
    }

    /** Прокси CONNECT (как HTTP-вход Xray): проверяет логин, соединяет и гоняет байты в обе стороны. */
    static class ConnectProxy implements java.io.Closeable {
        final java.net.ServerSocket ss;
        final String auth; // "" — без логина
        final boolean deny; // «не работает»: соединение сразу обрывается (как при блокировке)
        volatile int rejected;

        ConnectProxy(int port, String auth) throws Exception {
            this(port, auth, false);
        }

        ConnectProxy(int port, String auth, boolean deny) throws Exception {
            this.auth = auth;
            this.deny = deny;
            ss = new java.net.ServerSocket();
            ss.setReuseAddress(true);
            ss.bind(new InetSocketAddress("127.0.0.1", port));
            Thread t = new Thread(() -> {
                while (!ss.isClosed()) {
                    try {
                        java.net.Socket c = ss.accept();
                        new Thread(() -> serve(c)).start();
                    } catch (Exception e) {
                        return;
                    }
                }
            });
            t.setDaemon(true);
            t.start();
        }

        int port() { return ss.getLocalPort(); }

        void serve(java.net.Socket c) {
            if (deny) {
                try { c.close(); } catch (Exception ignored) { }
                return;
            }
            try {
                java.io.InputStream in = c.getInputStream();
                String first = line(in);
                String got = "";
                String h;
                while (!(h = line(in)).isEmpty()) {
                    if (h.toLowerCase().startsWith("proxy-authorization: basic ")) {
                        got = new String(Base64.getDecoder().decode(h.substring(27).trim()), StandardCharsets.UTF_8);
                    }
                }
                String[] p = first.split(" ");
                if (!auth.isEmpty() && !auth.equals(got)) {
                    rejected++;
                    c.getOutputStream().write("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nConnection: close\r\n\r\n".getBytes());
                    c.close();
                    return;
                }
                if (!"CONNECT".equals(p[0])) {
                    c.getOutputStream().write("HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n".getBytes());
                    c.close();
                    return;
                }
                String hp = p[1];
                int k = hp.lastIndexOf(':');
                String th = hp.substring(0, k).replace("[", "").replace("]", "");
                if (th.endsWith(".invalid")) th = "127.0.0.1"; // сервер VPN знает адрес, который провайдер «не находит»
                java.net.Socket up = new java.net.Socket();
                up.connect(new InetSocketAddress(th, Integer.parseInt(hp.substring(k + 1))), 3000);
                c.getOutputStream().write("HTTP/1.1 200 Connection established\r\n\r\n".getBytes());
                pipe(up.getInputStream(), c.getOutputStream(), c, up);
                pipe(in, up.getOutputStream(), up, c);
            } catch (Exception e) {
                try { c.close(); } catch (Exception ignored) { }
            }
        }

        static void pipe(java.io.InputStream from, java.io.OutputStream to, java.net.Socket a, java.net.Socket b) {
            Thread t = new Thread(() -> {
                byte[] buf = new byte[16384];
                try {
                    int n;
                    while ((n = from.read(buf)) > 0) { to.write(buf, 0, n); to.flush(); }
                } catch (Exception ignored) {
                } finally {
                    try { a.close(); } catch (Exception ignored) { }
                    try { b.close(); } catch (Exception ignored) { }
                }
            });
            t.setDaemon(true);
            t.start();
        }

        static String line(java.io.InputStream in) throws Exception {
            StringBuilder b = new StringBuilder();
            int ch;
            while ((ch = in.read()) >= 0 && ch != '\n') if (ch != '\r') b.append((char) ch);
            return b.toString();
        }

        public void close() {
            try { ss.close(); } catch (Exception ignored) { }
        }
    }

    /** Телефон с шифрованием (ключ — число: «другой телефон» — другой ключ). */
    static class CryptoFake extends Fake implements Engine.Crypto {
        int key = 7;
        CryptoFake(File dir) { super(dir); }
        public String seal(String plain) {
            byte[] b = plain.getBytes(StandardCharsets.UTF_8);
            for (int i = 0; i < b.length; i++) b[i] ^= key;
            return key + ":" + Base64.getEncoder().encodeToString(b);
        }
        public String open(String sealed) throws Exception {
            if (!sealed.startsWith(key + ":")) throw new Exception("bad key");
            byte[] b = Base64.getDecoder().decode(sealed.substring(sealed.indexOf(':') + 1));
            for (int i = 0; i < b.length; i++) b[i] ^= key;
            return new String(b, StandardCharsets.UTF_8);
        }
    }

    static final Map<String, byte[]> UPD = new java.util.concurrent.ConcurrentHashMap<String, byte[]>();

    /** Подпись выпуска так же, как build/sign_release.py (RSA PKCS#1 v1.5 + SHA-256). */
    static String rsaSign(byte[] msg, java.math.BigInteger n, java.math.BigInteger d) throws Exception {
        int k = (n.bitLength() + 7) / 8;
        byte[] prefix = new java.math.BigInteger("3031300d060960864801650304020105000420", 16).toByteArray();
        byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(msg);
        byte[] em = new byte[k];
        em[1] = 1;
        int tl = prefix.length + digest.length;
        for (int i = 2; i < k - tl - 1; i++) em[i] = (byte) 0xff;
        System.arraycopy(prefix, 0, em, k - tl, prefix.length);
        System.arraycopy(digest, 0, em, k - digest.length, digest.length);
        byte[] raw = new java.math.BigInteger(1, em).modPow(d, n).toByteArray();
        byte[] sig = new byte[k];
        int c = Math.min(raw.length, k);
        System.arraycopy(raw, raw.length - c, sig, k - c, c);
        return Base64.getEncoder().encodeToString(sig);
    }

    static final java.util.concurrent.atomic.AtomicInteger LEAK_CALLS = new java.util.concurrent.atomic.AtomicInteger();

    static class Fake implements Engine.Platform, Engine.DeviceInfo, Engine.Traffic, Engine.Notices, Engine.NetInfo {
        volatile Map<String, Object> net = Json.obj("kind", "wifi", "open", false);
        public Map<String, Object> netInfo() { return net; }
        volatile long rx, tx;
        public long[] trafficBytes() { return new long[]{rx, tx}; }
        final List<String> notices = new CopyOnWriteArrayList<String>();
        public void notice(String title, String text) { notices.add(title + ": " + text); }

        final File dir;
        volatile boolean alive;
        volatile String running = "";
        volatile String lastConfig = "";
        volatile List<String> lastExcluded = new ArrayList<String>();
        final Set<String> dead = Collections.synchronizedSet(new HashSet<String>());
        volatile boolean wlActive;
        volatile String hotspot = "";
        final List<String> calls = new CopyOnWriteArrayList<String>();
        volatile boolean appProxy; // поднимать HTTP-прокси на входе приложения (для проверки сайтов «через VPN»)
        ConnectProxy proxy;
        volatile Map<String, Object> device = new LinkedHashMap<String, Object>();

        public Map<String, Object> deviceInfo() { return device; }

        Fake(File dir) {
            this.dir = dir;
        }

        public File dataDir() { return dir; }
        public String deviceId() { return "abcdef0123456789"; }
        public String osVersion() { return "14"; }
        public String systemLang() { return "ru"; }
        public String appVersion() { return "0.9.0"; }
        public String coreVersion() { return "Lib v31, Xray-core v26.7.31"; }
        public String hotspotIp() { return hotspot; }
        public void changed() { }

        static String host(String cfgJson) {
            Map<String, Object> cfg = Json.parseObject(cfgJson);
            for (Object o : Json.list(cfg, "outbounds")) {
                Map<String, Object> ob = Json.map(o);
                if ("proxy".equals(Json.str(ob, "tag"))) {
                    Map<String, Object> st = Json.map(ob, "settings");
                    if ("wireguard".equals(Json.str(ob, "protocol"))) { // WARP: адрес Cloudflare — в peers
                        String ep = Json.str(Json.map(Json.list(st, "peers").get(0)), "endpoint");
                        return ep.substring(0, Math.max(0, ep.lastIndexOf(':')));
                    }
                    List<Object> v = Json.list(st, "vnext");
                    if (v == null) v = Json.list(st, "servers");
                    if (v == null) return Json.str(st, "address"); // Hysteria2: адрес прямо в settings
                    return Json.str(Json.map(v.get(0)), "address");
                }
            }
            return "";
        }

        final Set<String> blockedFps = Collections.synchronizedSet(new HashSet<String>(Arrays.asList("chrome")));

        boolean works(String host, String cfgJson) {
            if (dead.contains(host)) return false;
            if (host.startsWith("fpblocked")) { // провайдер режет отпечаток (как Chrome в мае 2026)
                for (String b : blockedFps) if (cfgJson.contains("\"fingerprint\":\"" + b + "\"")) return false;
            }
            if (wlActive && !host.startsWith("wl")) return false;
            if (host.startsWith("maskonly") && !cfgJson.contains("~mask") && !cfgJson.contains("finalmask")) return false;
            return true;
        }

        long delayOf(String host) {
            if (host.startsWith("fast")) return 40;
            if (host.startsWith("slow")) return 400;
            if (host.startsWith("wl")) return 250;
            return 120;
        }

        final Map<String, String> testConfigs = new java.util.concurrent.ConcurrentHashMap<String, String>();

        public long testDelay(String configJson, String url) throws Exception {
            calls.add("test");
            String h = host(configJson);
            testConfigs.put(h, configJson);
            if (!works(h, configJson)) throw new Exception("context deadline exceeded");
            Thread.sleep(5);
            return delayOf(h);
        }

        public void startVpn(String configJson, List<String> excluded) throws Exception {
            calls.add("start");
            String h = host(configJson);
            if (h.startsWith("nostart")) throw new Exception("failed to start core: bad config");
            lastConfig = configJson;
            lastExcluded = excluded;
            running = h;
            alive = true;
            if (appProxy) startProxy(configJson);
        }

        /** Вход app-in: прокси CONNECT с логином из настроек ядра (как HTTP-вход Xray). */
        void startProxy(String configJson) throws Exception {
            if (proxy != null) proxy.close();
            int port = 0;
            String auth = "";
            for (Object o : Json.list(Json.parseObject(configJson), "inbounds")) {
                Map<String, Object> ib = Json.map(o);
                if ("app-in".equals(Json.str(ib, "tag"))) {
                    port = (int) Json.num(ib, "port", 0);
                    Map<String, Object> acc = Json.map(Json.list(Json.map(ib, "settings"), "accounts").get(0));
                    auth = Json.str(acc, "user") + ":" + Json.str(acc, "pass");
                }
            }
            String h = host(configJson);
            // вход приложения в VPN: через «пустой» или мёртвый сервер данные не идут
            proxy = new ConnectProxy(port, auth, h.startsWith("empty") || !works(h, configJson));
        }

        public void stopVpn() {
            calls.add("stop");
            if (proxy != null) {
                proxy.close();
                proxy = null;
            }
            alive = false;
            running = "";
        }

        public boolean vpnAlive() { return alive; }

        final Set<String> dpiWorks = Collections.synchronizedSet(new HashSet<String>()); // какие способы обхода «помогают»
        final Set<String> deadProxies = Collections.synchronizedSet(new HashSet<String>());
        final List<String> testCores = new CopyOnWriteArrayList<String>();
        final Map<Integer, String> portWhat = new java.util.concurrent.ConcurrentHashMap<Integer, String>();

        /** Временное ядро: вход HTTP → «выход». Работает ли выход — решает имитация. */
        public java.io.Closeable startTestCore(String configJson) throws Exception {
            Map<String, Object> cfg = Json.parseObject(configJson);
            int port = (int) Json.num(Json.map(Json.list(cfg, "inbounds").get(0)), "port", 0);
            Map<String, Object> out = Json.map(Json.list(cfg, "outbounds").get(0));
            boolean works = true;
            String what = Json.str(out, "protocol");
            if ("freedom".equals(what)) {
                Map<String, Object> fr = Json.map(Json.map(out, "settings"), "fragment");
                String len = fr == null ? "" : Json.str(fr, "length");
                String id = "";
                for (Dpi.Strategy st : Dpi.STRATEGIES) {
                    Map<String, Object> ob = Dpi.outbound(st, "x", "");
                    if (Json.str(Json.map(Json.map(ob, "settings"), "fragment"), "length").equals(len)) id = st.id;
                }
                works = dpiWorks.contains(id);
                what = "dpi:" + id;
            } else {
                Map<String, Object> st = Json.map(out, "settings");
                List<Object> list = st.containsKey("servers") ? Json.list(st, "servers")
                        : st.containsKey("peers") ? Json.list(st, "peers") : Json.list(st, "vnext");
                String host = Json.str(Json.map(list.get(0)), "address");
                if (st.containsKey("peers")) {
                    String ep = Json.str(Json.map(list.get(0)), "endpoint");
                    host = ep.substring(0, Math.max(0, ep.lastIndexOf(':')));
                }
                String proto = Json.str(out, "protocol");
                // свои прокси — по списку «мёртвых»; серверы VPN — как при проверке, а «пустые» не пропускают данные
                works = "socks".equals(proto) || "http".equals(proto) ? !deadProxies.contains(host)
                        : works(host, configJson) && !host.startsWith("empty");
                what = "proxy:" + host + ":" + Json.str(out, "protocol") + (Json.map(out, "streamSettings") != null ? ":chain" : "");
            }
            testCores.add(what);
            portWhat.put(port, what);
            return new ConnectProxy(port, "", !works);
        }

        public long coreDelay(String url) throws Exception {
            if (!alive) throw new Exception("core is not running");
            if (!works(running, lastConfig)) throw new Exception("timeout");
            return delayOf(running);
        }

        String lastScript = "";
        static final String FRIEND = "7e57f00d-1b2c-4d5e-8f90-1234567890ab";

        public void sshRun(String host, int port, String user, String password, String script, Engine.LineSink out,
                           Engine.Stop stop) throws Exception {
            check(script.contains("PULT_RESULT"), "скрипт установки передаётся на сервер");
            if (!"secret".equals(password)) throw new Exception("Auth fail");
            lastScript = script;
            if (script.contains("/proc/loadavg")) {
                out.line("PULT_RESULT:90061|0.15 0.10 0.05|310/1987|3.1G/25G|123456|654321|active|4|1");
                return;
            }
            if (script.contains("ACTION=\"add\"") || script.contains("ACTION=\"remove\"")) {
                out.line("PULT_RESULT:" + FRIEND + "|" + PBK + "|0123abcd|a1b2c3d4e5f6");
                return;
            }
            for (String s : new String[]{"packages", "xray", "keys", "config", "tune", "start"}) {
                out.line("PULT_STEP:" + s);
            }
            out.line("some noise");
            out.line("PULT_RESULT:" + U + "|" + PBK + "|0123abcd|a1b2c3d4e5f6");
        }
    }

    // ---------- сертификаты ----------

    // Тестовый сертификат «Russian Trusted Sub CA / Минцифры» (самоподписанный, localhost) и его ключ (PKCS#8, base64 DER).
    // Только для самопроверки: ничего не подписывает, кроме тестового сервера на 127.0.0.1.
    static final String TEST_CA_CERT = "MIICSTCCAe+gAwIBAgIUdhQyq2MT2A/lg3togWRyN8u/ClMwCgYIKoZIzj0EAwIwbzELMAkGA1UEBhMCUlUxPzA9BgNVBAoMNlRo" +
            "ZSBNaW5pc3RyeSBvZiBEaWdpdGFsIERldmVsb3BtZW50IGFuZCBDb21tdW5pY2F0aW9uczEfMB0GA1UEAwwWUnVzc2lhbiBUcnVz" +
            "dGVkIFN1YiBDQTAeFw0yNjExMTgxOTQxMTJaFw00NjExMTMxOTQxMTJaMG8xCzAJBgNVBAYTAlJVMT8wPQYDVQQKDDZUaGUgTWlu" +
            "aXN0cnkgb2YgRGlnaXRhbCBEZXZlbG9wbWVudCBhbmQgQ29tbXVuaWNhdGlvbnMxHzAdBgNVBAMMFlJ1c3NpYW4gVHJ1c3RlZCBT" +
            "dWIgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAShUs1ODjSRx2e4ZUzIcqk3NS+bLDjRpf4NvNSRbZPNznsaRUoxvXFy1V3G" +
            "qpqxpczCw0Bsxc1t9AByKQT+AqE4o2kwZzAdBgNVHQ4EFgQUMkOHN5TPpcyACdRX+1fzXlihT1gwHwYDVR0jBBgwFoAUMkOHN5TP" +
            "pcyACdRX+1fzXlihT1gwDwYDVR0TAQH/BAUwAwEB/zAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSAAwRQIgB76H" +
            "cdDi8cqUF0Zg8IPZTTeinBHT9UiKXpQmT2xwIhQCIQCxhzukar1MEl8O1+yNcd0v+0W0l6rQLkg9DRw+t9Y7yg==";
    static final String TEST_CA_KEY = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4LI6uIO4v9YT863Lec1Ok5aGK9Hvdq0hBdHLcD9t64uhRANCAASh" +
            "Us1ODjSRx2e4ZUzIcqk3NS+bLDjRpf4NvNSRbZPNznsaRUoxvXFy1V3GqpqxpczCw0Bsxc1t9AByKQT+AqE4";

    static byte[] testCertDer() {
        return Base64.getDecoder().decode(TEST_CA_CERT);
    }

    /** TLS-сервер на 127.0.0.1 с тестовым сертификатом — как «провайдер, подменяющий сертификаты». */
    static javax.net.ssl.SSLServerSocket tlsServer() throws Exception {
        java.security.PrivateKey pk = java.security.KeyFactory.getInstance("EC")
                .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(Base64.getDecoder().decode(TEST_CA_KEY)));
        java.security.cert.Certificate c = java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(testCertDer()));
        java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("k", pk, "p".toCharArray(), new java.security.cert.Certificate[]{c});
        javax.net.ssl.KeyManagerFactory kmf = javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "p".toCharArray());
        javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("TLS");
        sc.init(kmf.getKeyManagers(), null, null);
        final javax.net.ssl.SSLServerSocket ss = (javax.net.ssl.SSLServerSocket) sc.getServerSocketFactory()
                .createServerSocket(0, 10, java.net.InetAddress.getByName("127.0.0.1"));
        Thread th = new Thread(() -> {
            while (!ss.isClosed()) {
                try {
                    final javax.net.ssl.SSLSocket s = (javax.net.ssl.SSLSocket) ss.accept();
                    new Thread(() -> {
                        try { s.setSoTimeout(3000); s.startHandshake(); s.getInputStream().read(); } catch (Exception ignored) { }
                        try { s.close(); } catch (Exception ignored) { }
                    }).start();
                } catch (Exception e) {
                    return;
                }
            }
        });
        th.setDaemon(true);
        th.start();
        return ss;
    }

    static Map<String, Object> certRes(String state, String issuer, String interceptor, String... russian) {
        return Json.obj("state", state, "issuer", issuer, "russian", new ArrayList<Object>(Arrays.asList((Object[]) russian)),
                "interceptor", interceptor, "sha256", "", "error", "ok".equals(state) ? "" : "x");
    }

    static final Certs.Fetcher CLEAN_CERTS = (host, port) -> certRes("ok", "Google Trust Services", "");

    static String titles(Map<String, Object> r) {
        StringBuilder b = new StringBuilder();
        for (Object o : Json.list(r, "items")) {
            Map<String, Object> i = Json.map(o);
            b.append(Json.str(i, "state")).append(": ").append(Json.str(i, "title")).append(" | ").append(Json.str(i, "detail")).append("\n");
        }
        return b.toString();
    }

    /** Телефон, на котором можно посмотреть сертификаты (как AndroidCAStore). */
    static class CertFake extends Fake implements Engine.CertStore {
        volatile List<byte[]> user = new ArrayList<byte[]>();
        CertFake(File dir) { super(dir); }
        public List<byte[]> caCerts(boolean u) { return u ? user : new ArrayList<byte[]>(); }
    }

    static String letters(int i) {
        StringBuilder b = new StringBuilder();
        do { b.append((char) ('a' + i % 26)); i /= 26; } while (i > 0);
        return b.toString();
    }

    /** Движок без обновления списков сайтов из интернета (в проверке интернета нет). */
    static Engine engine(Fake f) {
        Engine e = new Engine(f);
        e.settings.put("geo_updated", System.currentTimeMillis());
        e.settings.put("stall_check", false); // «16 КБ» — только в своём тесте
        e.settings.put("warp_fallback", false); // запасной WARP (регистрация у Cloudflare) — только в своём тесте
        return e;
    }

    static File tmpDir() throws Exception {
        return Files.createTempDirectory("pult-coretest-").toFile();
    }

    static void waitIdle(Engine e) throws Exception {
        long end = System.currentTimeMillis() + 20000;
        Thread.sleep(30);
        while (e.busy()) {
            if (System.currentTimeMillis() > end) throw new AssertionError("задача не закончилась за 20 с");
            Thread.sleep(20);
        }
    }

    static Map<String, Object> serverByName(Engine e, String name) {
        for (Object o : Json.list(e.state(), "servers")) {
            if (name.equals(Json.str(Json.map(o), "name"))) return Json.map(o);
        }
        return null;
    }

    static String currentName(Engine e) {
        return Json.str(Json.map(e.state(), "server"), "name");
    }

    // ---------- сервер подписки ----------

    static HttpServer http;
    static volatile String subBody = "";

    static int httpPort() {
        return http.getAddress().getPort();
    }
    static volatile int subStatus = 200;
    static volatile Map<String, String> subHeaders = new HashMap<String, String>();
    static volatile Map<String, String> lastRequestHeaders = new HashMap<String, String>();
    static volatile boolean foreignOpen = true;

    static void startHttp() throws Exception {
        http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        http.createContext("/sub", ex -> {
            Map<String, String> h = new HashMap<String, String>();
            for (Map.Entry<String, List<String>> en : ex.getRequestHeaders().entrySet()) {
                h.put(en.getKey().toLowerCase(), en.getValue().get(0));
            }
            lastRequestHeaders = h;
            for (Map.Entry<String, String> en : subHeaders.entrySet()) ex.getResponseHeaders().add(en.getKey(), en.getValue());
            byte[] b = subBody.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(subStatus, b.length);
            try (OutputStream o = ex.getResponseBody()) { o.write(b); }
        });
        http.createContext("/doh", ex -> { // защищённый DNS (RFC 8484): знает «pinned…» и «dnsblocked…»
            String q = ex.getRequestURI().getRawQuery().replaceAll(".*dns=([^&]*).*", "$1");
            byte[] wire = Base64.getUrlDecoder().decode(q);
            StringBuilder name = new StringBuilder();
            int i = 12;
            while (wire[i] != 0) {
                if (name.length() > 0) name.append('.');
                name.append(new String(wire, i + 1, wire[i], StandardCharsets.US_ASCII));
                i += 1 + wire[i];
            }
            String n = name.toString();
            String ip = n.startsWith("pinned") ? "127.0.0.1" : n.startsWith("dnsblocked") ? "45.12.0.20" : "";
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            out.write(new byte[]{0, 0, (byte) 0x81, (byte) (ip.isEmpty() ? 0x83 : 0x80), 0, 1, 0, (byte) (ip.isEmpty() ? 0 : 1), 0, 0, 0, 0});
            out.write(wire, 12, i + 5 - 12);
            if (!ip.isEmpty()) {
                out.write(new byte[]{(byte) 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4});
                for (String part : ip.split("\\.")) out.write(Integer.parseInt(part));
            }
            byte[] b = out.toByteArray();
            ex.sendResponseHeaders(200, b.length);
            try (OutputStream o = ex.getResponseBody()) { o.write(b); }
        });
        http.createContext("/geo/", ex -> { // списки сайтов: основной адрес «не открывается», запасной — да
            String path = ex.getRequestURI().getPath();
            if (path.startsWith("/geo/main/")) {
                ex.sendResponseHeaders(404, -1);
                ex.close();
                return;
            }
            byte[] b = new byte[200000];
            ex.sendResponseHeaders(200, b.length);
            try (OutputStream o = ex.getResponseBody()) { o.write(b); }
        });
        http.createContext("/rkn", ex -> { // заглушка провайдера интернета вместо подписки
            byte[] b = "<html><body>Доступ к ресурсу ограничен по решению Роскомнадзора</body></html>".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, b.length);
            try (OutputStream o = ex.getResponseBody()) { o.write(b); }
        });
        http.createContext("/ru", ex -> {
            ex.sendResponseHeaders(200, -1);
            ex.close();
        });
        http.createContext("/site-ok", ex -> {
            ex.sendResponseHeaders(204, -1);
            ex.close();
        });
        http.createContext("/big", ex -> {
            byte[] b = new byte[300 * 1024];
            Arrays.fill(b, (byte) 'x');
            ex.sendResponseHeaders(200, b.length);
            try (OutputStream o = ex.getResponseBody()) { o.write(b); }
        });
        http.createContext("/chunked", ex -> {
            ex.sendResponseHeaders(200, 0); // длина 0 — HttpServer отдаёт кусками
            try (OutputStream o = ex.getResponseBody()) {
                for (int i = 0; i < 50; i++) { o.write(("кусок " + i + "\n").getBytes(StandardCharsets.UTF_8)); o.flush(); }
            }
        });
        http.createContext("/ads/", ex -> {
            String name = ex.getRequestURI().getPath().substring(5);
            StringBuilder b = new StringBuilder("# список\n");
            String base = name.replaceFirst("^broken-", "");
            if (name.equals("ru")) {
                for (int i = 0; i < 61; i++) b.append("||ru").append(i).append(".adnet.example^\n");
                b.append("||site.example^$third-party\n");
            } else if (AdBlock.format(base).equals("abp")) { // списки «Монстра» — правила фильтров
                b.append("! *** easylist:easylist/easylist_adservers.txt ***\n");
                for (int i = 0; i < 60; i++) b.append("||").append(base).append(i).append(".abp.example^$third-party\n");
                b.append("##.banner\n||").append(base).append("-path.example/ads/*\n@@||").append(base).append("0.abp.example^\n");
            } else {
                for (int i = 0; i < 64; i++) b.append(name).append(i).append(".ads.example\n");
                b.append("doubleclick.net\nad.doubleclick.net\n0.0.0.0 hosts.example\n");
                if (name.endsWith("main")) {
                    b.append("yandex.ru\nwww.youtube.com\ni.imgur.com\nan.yandex.ru\nmanga-site.example\n");
                }
            }
            byte[] out = b.toString().getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, out.length);
            try (OutputStream o = ex.getResponseBody()) { o.write(out); }
        });
        http.createContext("/upd/", ex -> {
            byte[] b = UPD.get(ex.getRequestURI().getPath().substring(5));
            if (b == null) { ex.sendResponseHeaders(404, -1); ex.close(); return; }
            ex.sendResponseHeaders(200, b.length);
            try (OutputStream o = ex.getResponseBody()) { o.write(b); }
        });
        http.createContext("/leak-ip", ex -> {
            int n = LEAK_CALLS.getAndIncrement();
            byte[] b = (n % 2 == 0 ? "{\"status\":\"success\",\"countryCode\":\"NL\",\"isp\":\"Hosting BV\",\"query\":\"45.1.1.1\"}"
                    : "{\"status\":\"success\",\"countryCode\":\"RU\",\"isp\":\"Rostelecom\",\"query\":\"95.2.2.2\"}").getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, b.length);
            try (OutputStream o = ex.getResponseBody()) { o.write(b); }
        });
        http.createContext("/leak-dns", ex -> {
            byte[] b = "{\"dns\":{\"ip\":\"1.1.1.1\",\"geo\":\"Netherlands - Cloudflare\"}}".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, b.length);
            try (OutputStream o = ex.getResponseBody()) { o.write(b); }
        });
        http.createContext("/trace", ex -> {
            byte[] b = "fl=1\nip=203.0.113.77\nloc=US\n".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, b.length);
            try (OutputStream o = ex.getResponseBody()) { o.write(b); }
        });
        http.createContext("/redirect", ex -> {
            ex.getResponseHeaders().add("Location", "/site-ok");
            ex.sendResponseHeaders(302, -1);
            ex.close();
        });
        http.createContext("/site-region", ex -> {
            ex.sendResponseHeaders(451, -1);
            ex.close();
        });
        http.createContext("/foreign", ex -> {
            if (foreignOpen) {
                ex.sendResponseHeaders(204, -1);
                ex.close();
            } else {
                ex.close(); // обрыв соединения, как при блокировке
            }
        });
        http.start();
        String base = "http://127.0.0.1:" + http.getAddress().getPort();
        Engine.WL_ALLOWED = new String[]{base + "/ru"};
        Engine.WL_FOREIGN = new String[]{base + "/foreign"};
        Diagnostics.SITES = new String[][]{{"Сайт", base + "/site-ok"}, {"Сайт по стране", base + "/site-region"}};
        Engine.PORTS = (ip, port, timeout, err) -> !ip.startsWith("10.99.");  // 10.99.* — «раздача не отвечает»
        Dpi.CHECKS = new LinkedHashMap<String, String[][]>();
        Dpi.CHECKS.put("youtube", new String[][]{{base + "/big", "300000"}, {base + "/site-ok", "1"}});
        Dpi.CHECKS.put("discord", new String[][]{{base + "/site-ok", "1"}});
        Proxies.TRACE_URL = base + "/trace";
        Engine.DATA_URL = base + "/big";
        Engine.DATA_URLS_MORE = new String[]{base + "/big"};
        Engine.DATA_TIMEOUT_MS = 3000;
        Engine.WHAT_WORKS = new String[][]{{"Google", "http://127.0.0.1:1/"}, {"Telegram", base + "/site-ok"}};
        Engine.SPEED_URLS = new String[]{base + "/nothing-here", base + "/big"};
        AdBlock.URLS = (id, level) -> Arrays.asList(base + "/ads/broken-" + id, base + "/ads/" + id);
        Proxies.TIKTOK_URL = base + "/site-region";
        Http.DOH_SERVERS = new String[][]{{base + "/doh", "", ""}}; // защищённый DNS — местный, без интернета
        Engine.CLOCK_URL = base + "/site-ok";
        Engine.GEO_MAIN = base + "/geo/main/";
        Engine.GEO_MIRRORS = new String[]{base + "/geo/broken-", base + "/geo/mirror/"};
    }

    static String subUrl() {
        return "http://127.0.0.1:" + http.getAddress().getPort() + "/sub";
    }

    public static void main(String[] args) throws Exception {
        startHttp();
        Text.lang = "ru";
        // правила диспетчера (30 с тишины, 2 минуты между автосменами, минута после твоих действий) проверяет
        // отдельный тест «Диспетчер»; в остальных время сжато, иначе тесты ждали бы минутами
        Engine.SILENCE_MS = 0;
        Engine.SWITCH_GAP_MS = 0;
        Engine.USER_QUIET_MS = 0;
        Certs.FETCH = CLEAN_CERTS; // в проверке интернета нет: «контрольные сайты» отвечают как настоящие
        Engine.PINS = (h, p, sni) -> { // отпечаток сертификата без сети: «мёртвые» серверы не отвечают
            if (h.contains("dead")) throw new java.io.IOException("не отвечает");
            byte[] d = java.security.MessageDigest.getInstance("SHA-256").digest((h + "|" + sni).getBytes(StandardCharsets.UTF_8));
            StringBuilder b = new StringBuilder();
            for (byte x : d) b.append(String.format("%02x", x));
            return b.toString();
        };
        Engine.CERT_WATCH_DELAY_MS = 0;

        test("JSON: разбор, запись, экранирование и копии", () -> {
            Object v = Json.parse("{\"a\":[1,2.5,\"x\\u0041\\n\",true,null,{\"b\":-3}],\"c\":\"<s>\"}");
            String w = Json.write(v);
            check(w.equals("{\"a\":[1,2.5,\"xA\\n\",true,null,{\"b\":-3}],\"c\":\"\\u003cs\\u003e\"}"), w);
            check(Json.parse(w).equals(v), "повторный разбор даёт то же");
            Map<String, Object> m = Json.parseObject("{\"x\":{\"y\":[1]}}");
            Map<String, Object> c = Json.copy(m);
            Json.list(Json.map(c, "x"), "y").add(2L);
            check(Json.list(Json.map(m, "x"), "y").size() == 1, "глубокая копия");
            boolean threw = false;
            try { Json.parse("{\"a\":1,}"); } catch (IllegalArgumentException e) { threw = true; }
            check(threw, "лишняя запятая — ошибка");
            check(Json.canonical(Json.obj("b", 1, "a", 2)).equals("{\"a\":2,\"b\":1}"), "ключи по алфавиту");
        });

        test("Ссылки и подписки совпадают с программой для Windows", () -> {
            // подробная сверка — в run.sh (Dump против dump.py); здесь — самое важное
            Server s = Links.parseLink(link("nl.example.com", "🇳🇱 Нидерланды"));
            check(s != null && s.usable() && s.name.equals("🇳🇱 Нидерланды") && s.port == 443, "vless reality");
            Server stub = Links.parseLink("vless://" + U + "@0.0.0.0:1#Включите HWID");
            check(stub.stub && !stub.usable(), "заглушка провайдера");
            Server ins = Links.parseLink("vless://" + U + "@plain.example.com:80?security=none#plain");
            check(ins.insecure && !ins.usable(), "без шифрования на телефоне не используется");
            check(Links.parseLink("просто текст") == null, "не ссылка");
            Subscription sub = Subscription.parseBody(Text.b64encode((link("a.example.com", "A") + "\n" + link("b.example.com", "B"))
                    .getBytes(StandardCharsets.UTF_8)));
            check(sub.servers.size() == 2, "base64-подписка");
        });

        test("Подписка: ссылки-приглашения и понятные ошибки", () -> {
            check(Subscription.normalizeUrl("happ://add/https://sub.example.com/abc").equals("https://sub.example.com/abc"), "happ://add");
            check(Subscription.normalizeUrl("v2rayng://install-sub?url=https%3A%2F%2Fs.example.com%2Fx%3Fa%3D1")
                    .equals("https://s.example.com/x?a=1"), "v2rayng");
            String b64 = Text.b64encode("https://s2.example.com/t".getBytes(StandardCharsets.UTF_8));
            check(Subscription.normalizeUrl("someapp://import/" + b64).equals("https://s2.example.com/t"), "base64 в хвосте");
            for (String bad : new String[]{"", "happ://crypt3/xx", link("x.example.com", "x"), "abc"}) {
                boolean threw = false;
                try { Subscription.normalizeUrl(bad); } catch (Subscription.SubError e) { threw = true; }
                check(threw, "ошибка для: " + bad);
            }
        });

        test("Правила: российское напрямую, заблокированное через VPN, свои списки первыми", () -> {
            Map<String, Object> st = Store.defaults();
            st.put("mode", "smart");
            st.put("proxy_list", "example.org\n1.2.3.0/24\nплохая строка");
            st.put("block_list", "ads.example.com");
            List<Object> rules = Routing.buildRules(st, true);
            String w = Json.write(rules);
            check(w.indexOf("domain:ads.example.com") < w.indexOf("domain:example.org"), "блок раньше VPN");
            check(w.indexOf("geosite:ru-blocked") < w.lastIndexOf("domain:ru\""), "заблокированное раньше российского"); // первое — правило QUIC
            check(w.contains("geoip:ru\""), "российские IP напрямую при наличии списков");
            List<List<String>> e = Routing.splitEntries("example.org\nплохая строка\n# c\n");
            check(e.get(2).size() == 1 && e.get(0).size() == 1, "нераспознанное отдельно");
            st.put("ru_direct", false);
            check(!Json.write(Routing.buildRules(st, false)).contains("domain:xn--p1ai"), "без «российское напрямую»");
            Map<String, Object> d = Store.defaults();
            String dw = Json.write(Routing.buildRules(d, true));
            int lan = dw.indexOf("\"domain:local\"");
            int quicRu = dw.indexOf("\"port\":\"443\"");
            int quicBlock = dw.indexOf("\"port\":\"443\"", quicRu + 1);
            check(lan >= 0 && lan < quicRu, "домашняя сеть по имени — напрямую, раньше всего");
            check(quicRu > 0 && quicBlock > quicRu && dw.substring(quicBlock).startsWith("\"port\":\"443\",\"outboundTag\":\"block\"")
                    || dw.contains("\"network\":\"udp\",\"port\":\"443\",\"outboundTag\":\"block\""),
                    "QUIC мимо российских сайтов закрыт: " + dw.substring(0, Math.min(400, dw.length())));
            check(dw.indexOf("geosite:ru-available-only-inside") < quicBlock || !dw.contains("geosite:ru-available-only-inside"),
                    "российский QUIC — напрямую, до запрета");
            d.put("block_quic", false);
            check(!Json.write(Routing.buildRules(d, true)).contains("\"port\":\"443\""), "запрет QUIC выключается");
        });

        test("Переход со старого «умного» режима на «всё через VPN» — один раз", () -> {
            File dir = tmpDir();
            Fake fm = new Fake(dir);
            java.nio.file.Files.write(new File(dir, "settings.json").toPath(),
                    "{\"mode\":\"smart\",\"ru_direct\":false}".getBytes("UTF-8"));
            Engine em = new Engine(fm);
            check("vpn".equals(Json.str(em.settings, "mode")) && Json.bool(em.settings, "ru_direct", false)
                    && Json.bool(em.settings, "routing_v2", false), "старый умный режим → всё через VPN");
            boolean logged = false;
            for (String l : em.logLines()) logged |= l.contains("Маршрутизация");
            check(logged, "в журнале объяснение");
            Map<String, Object> back = new HashMap<String, Object>();
            back.put("mode", "smart");
            em.setSettings(back);
            em.shutdown();
            Engine em2 = new Engine(new Fake(dir));
            check("smart".equals(Json.str(em2.settings, "mode")), "выбранный потом экономный режим не сбрасывается");
            em2.shutdown();
        });

        test("Настройки ядра: туннель, DNS, раздача, маскировка", () -> {
            Server s = Links.parseLink(link("nl.example.com", "NL"));
            Map<String, Object> st = Store.defaults();
            check("vpn".equals(Json.str(st, "mode")) && Json.bool(st, "block_quic", false), "по умолчанию всё через VPN");
            check("AsIs".equals(Json.str(Json.map(XrayConfig.runConfig(s, st, new XrayConfig.Options()), "routing"), "domainStrategy")),
                    "всё через VPN: адреса сайтов не спрашиваются у провайдера");
            st.put("mode", "smart");
            XrayConfig.Options o = new XrayConfig.Options();
            o.appPort = 31000;
            o.appUser = "u";
            o.appPass = "p";
            o.coreVersion = "26.7.31";
            Map<String, Object> cfg = XrayConfig.runConfig(s, st, o);
            List<Object> obs = Json.list(cfg, "outbounds");
            check("direct".equals(Json.str(Json.map(obs.get(0)), "tag")), "умный режим: по умолчанию напрямую");
            st.put("mode", "vpn");
            cfg = XrayConfig.runConfig(s, st, o);
            check("proxy".equals(Json.str(Json.map(Json.list(cfg, "outbounds").get(0)), "tag")), "всё через VPN");
            Set<String> tags = new HashSet<String>();
            for (Object ob : Json.list(cfg, "outbounds")) check(tags.add(Json.str(Json.map(ob), "tag")), "теги не повторяются");
            String w = Json.write(cfg);
            check(w.contains("\"protocol\":\"tun\"") && w.contains("\"dns-out\"") && w.contains("dns-internal"), "TUN и DNS");
            check(w.contains("\"accounts\":[{\"user\":\"u\",\"pass\":\"p\"}]"), "служебный вход с логином");
            check(!w.contains("\"listen\":\"0.0.0.0\""), "ничего не слушает все адреса");
            o.shareIp = "192.168.43.1";
            o.shareUser = "pult";
            o.sharePass = "pw";
            w = Json.write(XrayConfig.runConfig(s, st, o));
            check(w.contains("\"listen\":\"192.168.43.1\"") && w.contains("\"auth\":\"password\""), "раздача только на точке доступа");
            o.mask = true;
            w = Json.write(XrayConfig.runConfig(s, st, o));
            check(w.contains("proxy~mask") && w.contains("tlshello"), "маскировка для старого ядра — через freedom");
            o.coreVersion = "Xray 26.11.1";
            w = Json.write(XrayConfig.runConfig(s, st, o));
            check(w.contains("finalmask") && !w.contains("proxy~mask"), "маскировка для нового ядра — finalmask");
            Map<String, Object> t = XrayConfig.testConfig(s, false, "26.7.31");
            check("proxy".equals(Json.str(Json.map(Json.list(t, "outbounds").get(0)), "tag")), "проверка идёт через сервер");
        });

        test("Перенос настроек: формат программы для Windows и защита от чужих значений", () -> {
            Map<String, Object> st = Store.defaults();
            st.put("mode", "vpn");
            st.put("block_ads", true);
            Json.list(st, "subscriptions").add(Json.obj("id", "x", "url", "https://s.example.com/a", "name", "Моя"));
            Map<String, Object> ex = Share.export(st, true, false, "0.9.0");
            check(!Json.write(Share.export(st, false, false, "0.9.0")).contains("s.example.com"), "без галочки ссылок нет");
            Map<String, Object> back = Share.parse(Json.parse(Json.write(ex)));
            check("vpn".equals(Json.str(Json.map(back, "settings"), "mode")), "режим переносится");
            check(Json.list(back, "subscriptions").size() == 1, "подписка по галочке");
            Map<String, Object> win = Json.obj("format", "pult-vpn-settings", "settings", Json.obj("mode", "hack",
                    "zapret_enabled", true, "block_ads", "yes", "evil", 1, "dns_encrypted", true),
                    "subscriptions", Json.arr(Json.obj("url", "javascript:alert(1)"), Json.obj("url", "happ://crypt4/x")),
                    "servers", Json.arr("vless://a@b:1", "line1\nline2", 5));
            Map<String, Object> r = Share.parse(win);
            Map<String, Object> s2 = Json.map(r, "settings");
            check(!s2.containsKey("mode") && !s2.containsKey("block_ads") && Json.bool(s2, "dns_encrypted", false),
                    "неверные значения пропущены, верные приняты");
            check(Json.list(r, "subscriptions").isEmpty() && Json.list(r, "servers").size() == 1, "опасные ссылки отброшены");
            check(Json.list(r, "skipped").size() == 7, "пропущенное посчитано: " + Json.list(r, "skipped"));
            check(Share.kind("https://x.example.com/s").equals("subscription") && Share.kind(link("a.b", "c")).equals("servers")
                    && Share.kind(Json.write(ex)).equals("settings") && Share.kind("WIFI:T:WPA;S:x;;").equals("wifi"), "что за текст");
        });

        test("Подписка с сервера: заголовки устройства, трафик, название, ошибки лимита", () -> {
            subBody = Text.b64encode((link("fast1.example.com", "Быстрый") + "\n" + link("mid1.example.com", "Средний"))
                    .getBytes(StandardCharsets.UTF_8));
            subHeaders = new HashMap<String, String>();
            subHeaders.put("subscription-userinfo", "upload=1024; download=2048; total=1073741824; expire=0");
            subHeaders.put("profile-title", "base64:" + Text.b64encode("Мой VPN".getBytes(StandardCharsets.UTF_8)));
            subStatus = 200;
            Subscription s = Subscription.fetch(subUrl(), "", 0, Subscription.deviceHeaders("hw123", "14"), 5000);
            check(s.servers.size() == 2 && s.title.equals("Мой VPN") && s.total == 1073741824L, "разбор ответа");
            check("hw123".equals(lastRequestHeaders.get("x-hwid")) && "Android".equals(lastRequestHeaders.get("x-device-os")),
                    "заголовки устройства");
            check(lastRequestHeaders.get("user-agent").startsWith("v2rayNG"), "первым — User-Agent приложения для Android");
            subStatus = 403;
            subHeaders.put("x-hwid-max-devices-reached", "true");
            String err = "";
            try { Subscription.fetch(subUrl(), "", 0, new HashMap<String, String>(), 5000); }
            catch (Subscription.SubError e) { err = e.getMessage(); }
            check(err.contains("лимит устройств") && err.contains("403"), err);
            subStatus = 200;
            subHeaders.clear();
            subBody = "vless://" + U + "@0.0.0.0:1#Продлите подписку";
            Subscription stub = Subscription.fetch(subUrl(), "", 0, new HashMap<String, String>(), 5000);
            check(stub.warnings.size() == 1 && stub.warnings.get(0).contains("Продлите"), "сообщение провайдера видно");
        });

        test("Подписка заблокирована у провайдера: защищённый DNS, другие серверы, подсказка", () -> {
            int port = http.getAddress().getPort();
            try {
                check(Http.dohResolve("pinned.invalid", 3000).equals(Arrays.asList("127.0.0.1"))
                        && Http.dohResolve("gone.invalid", 3000).isEmpty(), "защищённый DNS");
                subStatus = 200;
                subHeaders.clear();
                subBody = String.join("\n", link("fast1.example.com", "🇳🇱 Быстрый"), link("mid1.example.com", "🇷🇺 Москва"),
                        link("slow1.example.com", "🇩🇪 Медленный"));
                Subscription s = Subscription.fetch("http://pinned.invalid:" + port + "/sub", "", 0,
                        new HashMap<String, String>(), 5000);
                check(Subscription.routeDoh().equals(s.route) && s.servers.size() == 3, "по адресу из защищённого DNS: " + s.route);
                ConnectProxy dead = new ConnectProxy(0, "", true);
                java.net.ServerSocket tmp = new java.net.ServerSocket(0);
                int closed = tmp.getLocalPort();
                tmp.close();
                String err = "";
                try {
                    Subscription.fetch("http://pinned.invalid:" + closed + "/sub", "", dead.port(), new HashMap<String, String>(), 3000);
                } catch (Subscription.SubError ex) {
                    err = ex.getMessage();
                } finally {
                    dead.close();
                }
                check(err.contains("напрямую: адрес не найден (DNS)") && err.contains(Subscription.routeDoh())
                        && err.contains("через VPN:") && err.contains(Subscription.blockedHint()), "понятная ошибка:\n" + err);
                // нигде не пускает: подписка скачивается через другой рабочий сервер (временное ядро)
                Fake fr = new Fake(tmpDir());
                Engine er = engine(fr);
                er.addSubscription("http://127.0.0.1:" + port + "/sub", "Тест");
                waitIdle(er);
                check(Engine.flagOf("🇳🇱 Быстрый").equals("NL") && Engine.isRu("🇷🇺 Москва") && !Engine.isRu("🇩🇪 x"), "страна по флагу");
                List<Server> rel = er.relayServers();
                check(!rel.isEmpty() && rel.get(0).name.contains("Москва"), "сначала российский сервер: " + rel.size());
                check(er.connect(), "подключение");
                waitIdle(er);
                for (Server x : er.relayServers()) {
                    check(!x.name.equals(currentName(er)), "текущий сервер не используется: " + x.name);
                }
                er.disconnect();
                waitIdle(er);
                Map<String, Object> sm = Json.map(Json.list(er.settings, "subscriptions").get(0));
                sm.put("url", "http://gone.invalid:" + port + "/sub");
                int before = fr.testCores.size();
                er.refreshSubscriptions(false);
                waitIdle(er);
                check(Json.str(sm, "error").isEmpty(), "подписка обновилась: " + Json.str(sm, "error"));
                check(fr.testCores.size() > before, "через временное ядро");
                check(String.join("\n", er.logLines()).contains("загружено через сервер «🇷🇺 Москва»"),
                        "в журнале видно, как скачано: " + er.logLines());
                // страница блокировки провайдера интернета — не ответ подписки: поиск идёт дальше (другие серверы)
                final boolean[] relayed = {false};
                String rk = "";
                try {
                    Subscription.fetch("http://127.0.0.1:" + port + "/rkn", "", 0, new HashMap<String, String>(), 3000,
                            att -> { relayed[0] = true; return null; });
                } catch (Subscription.SubError ex) {
                    rk = ex.getMessage();
                }
                check(relayed[0] && rk.contains("страницу блокировки") && rk.contains(Subscription.blockedHint()),
                        "заглушка провайдера не останавливает поиск:\n" + rk);
                // имя сервера заблокировано в DNS провайдера: адрес из защищённого DNS, имя остаётся в TLS и Host
                String wsLink = "vless://" + U + "@dnsblocked1.example.com:443?security=tls&type=ws&path=%2Fw#DNS";
                fr.dead.add("dnsblocked1.example.com");
                er.addServers(wsLink);
                waitIdle(er);
                er.testServersTask();
                waitIdle(er);
                Server dn = null;
                for (Server x : er.relayServers()) if (x.address.equals("dnsblocked1.example.com")) dn = x;
                check(dn != null && "45.12.0.20".equals(dn.pinnedIp) && dn.ok, "сервер работает по адресу из защищённого DNS");
                Map<String, Object> ob = null;
                for (Object o : Json.list(Json.parseObject(fr.testConfigs.get("45.12.0.20")), "outbounds")) {
                    if ("proxy".equals(Json.str(Json.map(o), "tag"))) ob = Json.map(o);
                }
                Map<String, Object> ss = Json.map(ob, "streamSettings");
                check(Json.str(Json.map(Json.list(Json.map(ob, "settings"), "vnext").get(0)), "address").equals("45.12.0.20")
                        && Json.str(Json.map(ss, "tlsSettings"), "serverName").equals("dnsblocked1.example.com")
                        && Json.str(Json.map(ss, "wsSettings"), "host").equals("dnsblocked1.example.com"), "имя осталось в TLS и Host: " + ob);
                check(String.join("\n", er.logLines()).contains("DNS провайдера не знает адрес серверов: 1"), "в журнале видно");
                // свои загрузки: основной адрес списков не открывается — запасной; нигде — через другой сервер
                er.updateGeoNow();
                waitIdle(er);
                check(String.join("\n", er.logLines()).contains("Списки сайтов обновлены"), "списки с запасного адреса: " + er.logLines());
                String oldMain = Engine.GEO_MAIN;
                String[] oldMirrors = Engine.GEO_MIRRORS;
                Engine.GEO_MAIN = "http://geo.invalid:" + port + "/geo/mirror/";
                Engine.GEO_MIRRORS = new String[0];
                try {
                    er.updateGeoNow();
                    waitIdle(er);
                } finally {
                    Engine.GEO_MAIN = oldMain;
                    Engine.GEO_MIRRORS = oldMirrors;
                }
                check(String.join("\n", er.logLines()).contains("Списки сайтов: скачано через другой сервер"),
                        "через другой сервер: " + er.logLines());
                // часы
                Long skew = Engine.clockSkew();
                check(skew != null && Math.abs(skew) < 5000, "расхождение часов: " + skew);
                er.clockCheck(-900000L);
                check(Json.list(er.state(), "problems").toString().contains("отстают на 15 мин"), "часы отстают");
                er.clockCheck(1000L);
                check(!Json.list(er.state(), "problems").toString().contains("Часы"), "часы точные");
                er.shutdown();
            } finally {
                Http.DOH_SERVERS = new String[][]{{"http://127.0.0.1:" + port + "/doh", "", ""}};
            }
        });

        File dir = tmpDir();
        Fake fake = new Fake(dir);
        Engine e = engine(fake);

        test("Подписка → проверка → подключение к лучшему серверу", () -> {
            subStatus = 200;
            subHeaders.clear();
            subBody = String.join("\n", link("mid1.example.com", "Средний"), link("fast1.example.com", "Быстрый"),
                    link("slow1.example.com", "Медленный"), link("dead1.example.com", "Мёртвый"),
                    link("maskonly1.example.com", "Только с маскировкой"), link("wl1.example.com", "Белые списки WL"),
                    "vless://" + U + "@plain.example.com:80?security=none#Без шифрования");
            fake.dead.add("dead1.example.com");
            e.addSubscription(subUrl(), "Тест");
            waitIdle(e);
            Map<String, Object> st = e.state();
            check(Json.list(st, "servers").size() == 7, "серверы загружены");
            check(Json.bool(serverByName(e, "Только с маскировкой"), "mask", false), "маскировка нашла рабочий вариант");
            check(!Json.bool(serverByName(e, "Мёртвый"), "ok", true), "мёртвый помечен");
            check("Быстрый".equals(Json.str(Json.map(Json.list(st, "servers").get(0)), "name")), "лучший — первым");
            check(e.connect(), "подключение началось");
            waitIdle(e);
            check(e.isOn() && "Быстрый".equals(currentName(e)), "подключено к лучшему: " + currentName(e));
            check(fake.lastConfig.contains("\"protocol\":\"tun\""), "ядро получило настройки с туннелем");
            String rep = e.report();
            check(!rep.contains(U) && !rep.contains("127.0.0.1") && !rep.contains("example.com"), "в отчёте нет ссылок и ключей");
        });

        test("Диспетчер: идут данные — сервер не меняется; 30 с тишины; минута после твоих действий", () -> {
            long s0 = Engine.SILENCE_MS, g0 = Engine.SWITCH_GAP_MS, u0 = Engine.USER_QUIET_MS;
            Engine.SILENCE_MS = 30000; Engine.SWITCH_GAP_MS = 120000; Engine.USER_QUIET_MS = 60000;
            try {
                check(e.isOn(), "подключено");
                long now = System.currentTimeMillis();
                e.rxAt = now;
                check(e.maySwitch().contains("идут данные"), "данные идут: " + e.maySwitch());
                e.rxAt = now - 12000;
                check(e.maySwitch().contains("тишина меньше"), "тишина 12 с: " + e.maySwitch());
                e.rxAt = now - 40000;
                e.userConnAt = now;
                check(e.maySwitch().contains("сам подключал"), "после твоего действия: " + e.maySwitch());
                e.userConnAt = 0;
                check(e.maySwitch().isEmpty(), "40 с тишины — можно: " + e.maySwitch());
            } finally {
                Engine.SILENCE_MS = s0; Engine.SWITCH_GAP_MS = g0; Engine.USER_QUIET_MS = u0;
                e.rxAt = 0;
            }
        });

        test("Автопереход: сервер умер — переключение на другой без участия человека", () -> {
            fake.dead.add("fast1.example.com");
            for (int i = 0; i < 6; i++) e.monitor();
            waitIdle(e);
            check(e.isOn(), "VPN остался включённым");
            check("Средний".equals(currentName(e)), "переключился на следующий лучший: " + currentName(e));
            // журнал подключения: видно, что переключила автоматика и почему
            Map<String, Object> last = (Map<String, Object>) Json.list(Json.map(e.state(), "journal"), "items").get(0);
            check("switch".equals(Json.str(last, "kind")) && "Средний".equals(Json.str(last, "server"))
                    && !"user".equals(Json.str(last, "who")) && Json.str(last, "why").contains("перестал отвечать"),
                    "журнал: " + Json.write(last));
            check(Json.num(Json.map(e.state(), "journal"), "auto_hour", 0) >= 1, "счётчик автопереключений");
            check(e.report().contains("Журнал подключения"), "журнал в отчёте");
        });

        test("Белые списки: обычные серверы не работают — сам переходит на сервер для белых списков и обратно", () -> {
            fake.wlActive = true;
            foreignOpen = false;
            for (int i = 0; i < 6; i++) e.monitor();
            waitIdle(e);
            check(e.isOn() && "Белые списки WL".equals(currentName(e)), "сервер для белых списков: " + currentName(e));
            check(Json.bool(e.state(), "whitelist", false), "режим белых списков замечен");
            fake.wlActive = false;
            foreignOpen = true;
            fake.dead.remove("fast1.example.com");
            // фоновые задачи (подбор обхода замедлений и т.п.) тоже идут — ждём, пока очередь дойдёт до белых списков
            for (int i = 0; i < 200 && Json.bool(e.state(), "whitelist", false); i++) {
                e.monitor();
                waitIdle(e);
            }
            check(!Json.bool(e.state(), "whitelist", true), "белые списки закончились");
            check("Быстрый".equals(currentName(e)), "вернулся на лучший: " + currentName(e));
        });

        test("Выбор сервера вручную, настройки и исключённые приложения", () -> {
            String key = Json.str(serverByName(e, "Медленный"), "key");
            e.select(key);
            waitIdle(e);
            check("Медленный".equals(currentName(e)), "выбранный вручную");
            e.select("");
            waitIdle(e);
            Map<String, Object> in = new HashMap<String, Object>();
            in.put("mode", "взлом");
            in.put("block_ads", "да");
            in.put("excluded_apps", Json.arr("ru.sberbankmobile", "bad pkg!"));
            in.put("dns_encrypted", true);
            e.setSettings(in);
            waitIdle(e);
            check("vpn".equals(Json.str(e.settings, "mode")) && !Json.bool(e.settings, "block_ads", true), "неверное не принято");
            check(Json.bool(e.settings, "dns_encrypted", false), "верное принято");
            check(Json.list(e.settings, "excluded_apps").isEmpty(), "список с неверным именем приложения не принят");
            in.clear();
            in.put("excluded_apps", Json.arr("ru.sberbankmobile"));
            e.setSettings(in);
            waitIdle(e);
            check(fake.lastExcluded.contains("ru.sberbankmobile"), "исключённое приложение передано в VPN");
            check(fake.lastConfig.contains("dns-query"), "шифрование DNS применилось перезапуском");
        });

        test("Раздача: прокси только на адресе точки доступа, смена адреса подхватывается", () -> {
            fake.hotspot = "192.168.43.1";
            e.setShare(true, "system", "", "");
            waitIdle(e);
            check(fake.lastConfig.contains("\"listen\":\"192.168.43.1\""), "слушает точку доступа");
            fake.hotspot = "10.12.0.1";
            for (int i = 0; i < 4 && !e.busy(); i++) e.monitor();
            waitIdle(e);
            check(fake.lastConfig.contains("\"listen\":\"10.12.0.1\""), "новый адрес подхвачен: " + e.logLines().subList(Math.max(0, e.logLines().size() - 6), e.logLines().size()));
            String pass = Json.str(Json.map(e.state(), "share"), "pass");
            e.newSharePassword();
            waitIdle(e);
            check(!pass.equals(Json.str(Json.map(e.state(), "share"), "pass")), "новый пароль");
            e.setShare(false, "", "", "");
            waitIdle(e);
            check(!fake.lastConfig.contains("share-socks"), "раздача выключена");
        });

        test("Свой сервер: установка по SSH добавляет и проверяет два входа", () -> {
            boolean threw = false;
            try { e.vpsSetup("bad host!", "22", "root", "x", ""); } catch (Vps.VpsError ex) { threw = true; }
            check(threw, "неверный адрес отклонён сразу");
            e.vpsSetup("vps.example.net", "22", "root", "wrong", "");
            waitIdle(e);
            check(Json.str(Json.map(e.state(), "message"), "text").contains("пароль"), "неверный пароль — понятная ошибка");
            e.vpsSetup("vps.example.net", "", "", "secret", "Мой VPS");
            waitIdle(e);
            check(serverByName(e, "Мой VPS") != null && serverByName(e, "Мой VPS · XHTTP") != null, "оба входа добавлены");
            check(Json.bool(serverByName(e, "Мой VPS"), "ok", false), "свой сервер проверен");
            check(!Json.write(e.settings).contains("secret"), "пароль не сохранён");
        });

        test("Свой сервер: состояние и отдельные ключи для друзей", () -> {
            List<Object> mine = Json.list(e.state(), "vps");
            check(mine.size() == 1 && "Мой VPS".equals(Json.str(Json.map(mine.get(0)), "name")), "настроенный сервер запомнился");
            String id = Json.str(Json.map(mine.get(0)), "id");
            e.vpsStatus(id, "wrong");
            waitIdle(e);
            check(Json.str(Json.map(e.state(), "message"), "text").contains("пароль"), "неверный пароль — понятная ошибка");
            e.vpsStatus(id, "secret");
            waitIdle(e);
            Map<String, Object> st = Json.map(Json.map(Json.list(e.state(), "vps").get(0)), "status");
            check(Json.num(st, "conns", 0) == 4 && "active".equals(Json.str(st, "xray")) && "310/1987".equals(Json.str(st, "mem_mb")),
                    "состояние сервера: " + st);
            check(fake.lastScript.contains("/proc/loadavg"), "на сервер уходит скрипт состояния");
            e.vpsFriendAdd(id, "secret", "Саша");
            waitIdle(e);
            List<Object> fr = Json.list(Json.map(Json.list(e.state(), "vps").get(0)), "friends");
            check(fr.size() == 1 && "Саша".equals(Json.str(Json.map(fr.get(0)), "name")) && !Json.map(fr.get(0)).containsKey("links"),
                    "ключ для друга (на экран — без ссылки)");
            check(Fake.FRIEND.equals(Json.str(Json.map(e.state(), "vps_friend_new"), "id")), "QR-код откроется сам");
            check(e.vpsFriendLink(Fake.FRIEND).startsWith("vless://" + Fake.FRIEND + "@vps.example.net:443"), "QR-код — ключ друга");
            e.vpsFriendRemove(id, "secret", Fake.FRIEND);
            waitIdle(e);
            check(fake.lastScript.contains(Fake.FRIEND) && fake.lastScript.contains("ACTION=\"remove\""), "ключ удаляется на сервере");
            check(Json.list(Json.map(Json.list(e.state(), "vps").get(0)), "friends").isEmpty(), "и в приложении");
            boolean threw = false;
            try { e.vpsFriendRemove(id, "secret", "x; rm -rf /"); } catch (Exception ex) { threw = true; }
            check(threw, "мусорный ключ не уходит на сервер");
            check(!Json.write(e.settings).contains("secret"), "пароль не сохранён");
            e.vpsForget(id);
            check(Json.list(e.state(), "vps").isEmpty(), "сервер убирается из приложения");
        });

        test("VPN на время: выключается сам, «ещё час» продлевает", () -> {
            e.connect();
            waitIdle(e);
            check("on".equals(e.status()), "VPN включён");
            e.vpnFor(60);
            long u1 = e.vpnUntil();
            e.vpnFor(60);
            check(e.vpnUntil() - u1 >= 59 * 60000L, "ещё час добавляется");
            check(Json.num(e.state(), "vpn_until", 0) == e.vpnUntil(), "время видно в состоянии");
            e.vpnFor(-1);
            check(e.vpnUntil() == 0, "отмена");
            e.vpnFor(60);
            java.lang.reflect.Field f = Engine.class.getDeclaredField("vpnUntil");
            f.setAccessible(true);
            f.setLong(e, System.currentTimeMillis() - 1000);
            e.monitor();
            waitIdle(e);
            check("off".equals(e.status()) && e.vpnUntil() == 0, "время вышло — VPN выключен");
            check(fake.notices.toString().contains("Время VPN вышло"), "уведомление: " + fake.notices);
            e.connect();
            waitIdle(e);
        });

        test("Перенос настроек на другой телефон через QR или файл", () -> {
            String text = e.exportSettings(true, true);
            Fake f2 = new Fake(tmpDir());
            Engine e2 = engine(f2);
            check("settings".equals(Json.str(e2.importPreview(text), "kind")), "распознано как настройки");
            String msg = e2.importApply(text);
            waitIdle(e2);
            check(msg.contains("Подписок добавлено: 1"), msg);
            check(Json.list(e2.state(), "servers").size() >= 7, "серверы появились на втором телефоне");
            check(Json.bool(e2.settings, "dns_encrypted", false), "настройки перенесены");
            e2.shutdown();
        });

        test("Выключение и данные после перезапуска приложения", () -> {
            e.disconnect();
            check("off".equals(e.status()) && !fake.alive, "VPN выключен");
            check(!e.wasOn(), "не включать сам при следующем запуске");
            Engine again = new Engine(new Fake(dir));
            check(Json.list(again.state(), "servers").size() == Json.list(e.state(), "servers").size(), "серверы сохранились");
            check(Json.list(again.state(), "subs").size() == 1, "подписка сохранилась");
            again.shutdown();
        });

        test("HTTP через вход ядра: логин, перенаправления, куски, большие страницы, файл", () -> {
            String base = "http://127.0.0.1:" + http.getAddress().getPort();
            ConnectProxy px = new ConnectProxy(0, "u1:p1");
            try {
                Http.setProxyAuth(px.port(), "u1", "p1");
                Http.Response r = Http.get(base + "/chunked", null, 3000, px.port());
                check(r.status == 200 && r.text().contains("кусок 49"), "тело кусками через вход ядра: " + r.status);
                r = Http.get(base + "/redirect", null, 3000, px.port());
                check(r.status == 204, "перенаправление через вход ядра: " + r.status);
                r = Http.probe(base + "/big", null, 3000, px.port(), 64 * 1024);
                check(r.status == 200 && r.truncated && r.body.length == 64 * 1024, "большая страница обрезается, а не ошибка");
                r = Http.probe(base + "/big", null, 3000, 0, 64 * 1024);
                check(r.status == 200 && r.truncated, "напрямую тоже");
                try {
                    Http.request(base + "/big", null, 3000, px.port(), 1024);
                    check(false, "лимит для обычных запросов должен срабатывать");
                } catch (java.io.IOException ex) {
                    check(ex.getMessage().contains("слишком большой"), ex.getMessage());
                }
                File f = new File(tmpDir(), "big.bin");
                check(Http.downloadTo(base + "/big", f, 3000, px.port(), 1 << 20) == 300 * 1024 && f.length() == 300 * 1024
                        && !new File(f.getPath() + ".part").exists(), "файл качается сразу на диск");
                Http.setProxyAuth(px.port(), "u1", "wrong");
                try {
                    Http.get(base + "/site-ok", null, 3000, px.port());
                    check(false, "без верного логина вход ядра не пускает");
                } catch (java.io.IOException ex) {
                    check(ex.getMessage().contains("407"), "понятная ошибка про логин: " + ex.getMessage());
                }
            } finally {
                px.close();
                Http.setProxyAuth(0, "", "");
            }
        });

        test("Проверка программы: все пункты, отчёт без ссылок, ключей и адресов", () -> {
            Fake fc = new Fake(tmpDir());
            fc.appProxy = true;
            fc.device.put("battery_restricted", true);
            fc.dead.add("dead9.example.com");
            Engine ec = engine(fc);
            String sub = subUrl() + "?token=SECRETTOKEN123";
            subStatus = 200;
            subHeaders = new HashMap<String, String>();
            subBody = Text.b64encode((link("check1.example.com", "Проверочный") + "\n" + link("dead9.example.com", "Мёртвый") + "\n")
                    .getBytes(StandardCharsets.UTF_8));
            ec.addSubscription(sub, "Моя");
            waitIdle(ec);
            Engine.Staller oldStall = Engine.STALL;
            Engine.STALL = (h, port) -> h.contains("cloudflare") && port == 0
                    ? Json.obj("state", "stall", "bytes", 16000L, "detail", "freeze") : Json.obj("state", "ok", "bytes", 65536L);
            try {
                check(ec.runCheck(), "проверка запустилась");
                waitIdle(ec);
            } finally {
                Engine.STALL = oldStall;
            }
            Map<String, Object> st = Json.map(ec.state(), "check");
            check(st != null && !Json.list(st, "items").isEmpty(), "есть пункты проверки");
            String text = ec.checkText();
            check(text.contains("Проверка подписи обновлений работает"), "подпись обновлений проверена на телефоне:\n" + text);
            check(text.contains("speed.cloudflare.com: провайдер режет") && text.contains("cdn.jsdelivr.net: напрямую качается"),
                    "замирание у провайдера видно в отчёте");
            check(text.contains("Самопроверка логики: все"), "самопроверка логики пройдена:\n" + text);
            check(text.contains("Работают серверы"), "проверены серверы");
            check(text.contains("VPN выключен"), "сказано, что VPN выключен");
            check(!text.contains("SECRETTOKEN123") && !text.contains("127.0.0.1") && !text.contains("check1.example.com")
                    && !text.contains("11111111-2222"), "в отчёте нет ссылки подписки, адресов и ключей:\n" + text);
            File rep = new File(new File(fc.dir, "reports"), Json.str(st, "file"));
            check(rep.isFile() && rep.length() > 100, "отчёт сохранён в файл");
            ec.connect();
            waitIdle(ec);
            check(ec.isOn(), "подключено");
            ec.runCheck();
            waitIdle(ec);
            text = ec.checkText();
            check(text.contains("VPN работает"), "проверен VPN:\n" + text);
            check(text.contains("Закрыты для страны сервера: Сайт по стране"), "сайт, закрытый для страны, найден");
            check(!text.contains("Через VPN не открываются"), "через вход ядра сайты открываются:\n" + text);
            boolean fixShown = false;
            for (Object o : Json.list(Json.map(ec.state(), "check"), "items")) {
                fixShown |= "battery".equals(Json.str(Json.map(o), "fix"));
            }
            check(fixShown, "у пункта про батарею есть кнопка исправления");
            fc.hotspot = "10.99.0.1";
            ec.setShare(true, "system", "", "");
            waitIdle(ec);
            ec.runCheck();
            waitIdle(ec);
            text = ec.checkText();
            check(text.contains("[ОШИБКА] Раздача не отвечает") && text.contains("SOCKS"), "раздача не отвечает — с подробностями:\n" + text);
            check(!text.contains("10.99.0.1"), "адрес раздачи скрыт");
            String sc = Diagnostics.scrub("ip 10.1.2.3 и [2001:db8::1:2] fe80::1 2001:db8:0:0:0:0:0:1 vmess://abc "
                    + "1b2c3d4e-0000-4000-8000-000000000001 в 20:10:23 и 12:30, мой-секрет", Arrays.asList("мой-секрет"));
            check(sc.equals("ip <адрес> и <адрес> <адрес> <адрес> <ссылка> <ключ> в 20:10:23 и 12:30, <скрыто>"), sc);
            ec.shutdown();
        });

        test("Две очереди: пока в фоне долгая задача, VPN включается, переключается и выключается", () -> {
            Fake fq = new Fake(tmpDir());
            Engine eq = engine(fq);
            eq.addServers(link("fast1.example.com", "Быстрый") + "\n" + link("slow1.example.com", "Медленный"));
            waitIdle(eq);
            final boolean[] ran = {false};
            check(eq.runTask("Долгая фоновая", "test", () -> {
                long end = System.currentTimeMillis() + 1500;
                while (System.currentTimeMillis() < end) {
                    try { Thread.sleep(20); } catch (InterruptedException ex) { return; }
                }
                ran[0] = true;
            }), "фоновая задача запущена");
            check(eq.bgBusy() && !eq.connBusy(), "занята только фоновая очередь");
            check(eq.connect(), "подключение не ждёт фоновую задачу");
            long t0 = System.currentTimeMillis();
            while (!eq.isOn() && System.currentTimeMillis() - t0 < 1200) Thread.sleep(10);
            check(eq.isOn() && eq.bgBusy(), "подключено, пока фоновая задача ещё идёт");
            eq.select(Json.str(serverByName(eq, "Медленный"), "key"));
            t0 = System.currentTimeMillis();
            while (!"Медленный".equals(currentName(eq)) && System.currentTimeMillis() - t0 < 1200) Thread.sleep(10);
            check("Медленный".equals(currentName(eq)) && eq.bgBusy(), "сервер переключился, пока фоновая задача идёт");
            check(!eq.runTask("Вторая фоновая", "test", () -> { }), "вторая фоновая ждёт своей очереди");
            eq.disconnect();
            check("off".equals(eq.status()) && eq.bgBusy(), "выключилось сразу");
            waitIdle(eq);
            check(ran[0], "фоновая задача дошла до конца, её не прервали");
            eq.shutdown();
        });

        test("Свои маршруты и прокси: сервис через свой прокси, сайт через другой сервер, проверка прокси", () -> {
            Fake fr = new Fake(tmpDir());
            Engine er = engine(fr);
            er.addServers(link("fast1.example.com", "Быстрый") + "\n" + link("slow1.example.com", "Медленный"));
            waitIdle(er);
            er.connect();
            waitIdle(er);
            check("Быстрый".equals(currentName(er)), "подключено к быстрому");
            for (String bad : new String[]{"", "vless://x@h.example:443", "1.2.3.4", "a:b:c", "ftp://h.example:21"}) {
                try {
                    er.addProxy(bad, "", "auto", true);
                    check(false, "прокси «" + bad + "» должен быть отклонён");
                } catch (Engine.UserError ex) {
                    check(!ex.getMessage().isEmpty(), "понятная ошибка");
                }
            }
            Map<String, Object> px = er.addProxy("socks5://alice:Secret%40pw@198.51.100.7:1080", "Резидент", "auto", true);
            check("SOCKS5 198.51.100.7:1080".equals(Json.str(px, "label")) && Json.bool(px, "auth", false)
                    && !Json.write(px).contains("Secret"), "в интерфейс — без логина и пароля: " + Json.write(px));
            String id = Json.str(px, "id");
            check(er.checkProxy(id), "проверка прокси запущена");
            waitIdle(er);
            Map<String, Object> pub = Json.map(Json.list(er.routesState(), "proxies").get(0));
            Map<String, Object> chk = Json.map(pub, "check");
            check(Json.bool(chk, "ok", false) && "US".equals(Json.str(chk, "loc")) && "region".equals(Json.str(chk, "tiktok"))
                    && Json.bool(chk, "chain", false), "прокси работает, страна и TikTok: " + Json.write(chk));
            check(fr.testCores.get(fr.testCores.size() - 1).endsWith(":socks:chain"), "проверка — через основной сервер");
            er.setServiceRoute("TikTok", "custom:" + id);
            waitIdle(er);
            String cfg = fr.lastConfig;
            check(cfg.contains("\"tag\":\"custom0\"") && cfg.contains("\"dialerProxy\":\"proxy\"") && cfg.contains("Secret@pw"),
                    "в настройках ядра — свой прокси через VPN");
            check(cfg.contains("\"domain:tiktok.com\"") && cfg.contains("\"outboundTag\":\"custom0\""), "TikTok — через свой прокси");
            check(cfg.contains("\"network\":\"udp\""), "QUIC для TikTok закрыт — приложение сразу идёт по TCP");
            String slow = Json.str(serverByName(er, "Медленный"), "key");
            check("music.example.org".equals(er.routeSite("https://music.example.org/x", "server:" + slow, false)), "сайт записан");
            waitIdle(er);
            cfg = fr.lastConfig;
            check(cfg.contains("\"tag\":\"pin0\"") && cfg.contains("slow1.example.com"), "сайт — через другой сервер");
            int site = cfg.indexOf("domain:music.example.org");
            int svc = cfg.indexOf("domain:tiktok.com");
            check(site > 0 && site < svc, "сайты раньше сервисов");
            er.routeSite("example.org", "direct", false);
            waitIdle(er);
            Map<String, Object> rs = er.routesState();
            check(!Json.write(rs).contains("music.example.org") && Json.write(Json.list(rs, "sites")).contains("{\"site\":\"example.org\",\"value\":\"direct\""),
                    "правило для сайта перекрыло поддомен: " + Json.write(Json.list(rs, "sites")) + " / " + Json.str(er.settings, "direct_list"));
            er.setServiceRoute("YouTube", "dpi");
            waitIdle(er);
            check(fr.lastConfig.contains("\"tag\":\"dpi\"") && fr.lastConfig.contains("\"fragment\""), "YouTube — напрямую с дроблением");
            boolean warned = false;
            for (Object o : Json.list(er.routesState(), "services")) {
                Map<String, Object> m = Json.map(o);
                if ("YouTube".equals(Json.str(m, "name"))) warned = !Json.str(m, "warn").isEmpty() && "dpi".equals(Json.str(m, "choice"));
            }
            check(warned, "у YouTube — подсказка, что способ обхода ещё не подобран");
            fr.deadProxies.add("198.51.100.7");
            er.checkProxy(id);
            waitIdle(er);
            check(!Json.bool(Json.map(Json.map(Json.list(er.routesState(), "proxies").get(0)), "check"), "ok", true), "мёртвый прокси замечен");
            er.removeProxy(id);
            waitIdle(er);
            check(!fr.lastConfig.contains("custom0") && !Json.map(er.settings, "routes").containsKey("svc:TikTok"),
                    "прокси удалён — TikTok снова как по умолчанию");
            check(!String.join("\n", er.logLines()).contains("198.51.100.7") && !String.join("\n", er.logLines()).contains("alice"),
                    "адрес и логин прокси не попали в журнал");
            er.shutdown();
        });

        test("Обход замедлений: подбор способа, YouTube и Discord напрямую, откат в VPN, если перестал работать", () -> {
            Fake fd = new Fake(tmpDir());
            Engine ed = engine(fd);
            ed.addServers(link("fast1.example.com", "Быстрый"));
            waitIdle(ed);
            Map<String, Object> eco = new HashMap<String, Object>();
            eco.put("mode", "smart"); // обход замедлений нужен в экономном режиме: там YouTube идёт мимо VPN
            ed.setSettings(eco);
            waitIdle(ed);
            ed.connect();
            waitIdle(ed);
            fd.dpiWorks.add("tls_10");
            check(ed.dpiPick(), "подбор запущен");
            waitIdle(ed);
            check("tls_10".equals(Json.str(ed.settings, "dpi_strategy")) && Json.bool(ed.settings, "dpi_ok", false),
                    "подобран рабочий способ: " + Json.str(ed.settings, "dpi_strategy"));
            check(Json.list(ed.settings, "dpi_results").size() == Dpi.STRATEGIES.size(), "проверены все способы");
            waitIdle(ed);
            String cfg = fd.lastConfig;
            check(cfg.contains("\"length\":\"10-30\"") && cfg.contains("\"domain:googlevideo.com\"") && cfg.contains("\"domain:discord.com\""),
                    "YouTube и Discord — через выход с дроблением");
            int dpi = cfg.indexOf("\"outboundTag\":\"dpi\"");
            int builtin = cfg.indexOf("domain:telegram.org");
            check(dpi > 0 && dpi < builtin, "правило обхода раньше встроенного «через VPN»");
            Map<String, Object> mode = new HashMap<String, Object>();
            mode.put("mode", "vpn");
            ed.setSettings(mode);
            waitIdle(ed);
            check(!fd.lastConfig.contains("\"outboundTag\":\"dpi\""), "в «Глобальном» режиме всё через VPN");
            mode.put("mode", "smart");
            ed.setSettings(mode);
            waitIdle(ed);
            fd.dpiWorks.clear();
            ed.dpiCheckFlow();
            check(Json.bool(ed.settings, "dpi_ok", false), "одна неудача — ещё не повод");
            ed.dpiCheckFlow();
            waitIdle(ed);
            check(!Json.bool(ed.settings, "dpi_ok", true) && !fd.lastConfig.contains("\"outboundTag\":\"dpi\""),
                    "перестал работать — YouTube и Discord снова через VPN");
            ed.shutdown();
        });

        test("Блокировка рекламы: списки, файл для ядра, работа без VPN, пауза, журнал и исключения", () -> {
            Set<String> got = AdBlock.parse("# c\nexample-ads.com\n0.0.0.0 hosts.example\n*.wild.example\nbad domain\n||xy.example^\n", "domains");
            check(got.equals(new HashSet<>(Arrays.asList("example-ads.com", "hosts.example", "wild.example", "xy.example"))), "разбор: " + got);
            check(AdBlock.parse("||an.yandex.ru^\n||site.example^$third-party\n", "adblock").equals(Collections.singleton("an.yandex.ru")),
                    "из правил AdGuard — только адреса целиком");
            check(AdBlock.parseUser("https://Shop.Example.com/x\n||ads.site.ru^\n# комментарий\n*.cdn.example")
                    .equals(new HashSet<>(Arrays.asList("shop.example.com", "ads.site.ru", "cdn.example"))), "свои сайты из поля");
            Set<String> doms = new HashSet<>(Arrays.asList("example.com", "ads.example.com", "cdn.allowed.com", "allowed.com", "other.net"));
            check(AdBlock.applyAllow(doms, new HashSet<>(Arrays.asList("cdn.allowed.com", "example.com"))).equals(Collections.singleton("other.net")),
                    "исключения");
            check(AdBlock.minimize(new HashSet<>(Arrays.asList("a.com", "x.a.com", "b.org"))).equals(Arrays.asList("a.com", "b.org")), "без лишних поддоменов");
            check(AdBlock.decodeGeosite(AdBlock.encodeGeosite("ads", Arrays.asList("a.com", "b.org"))).get("ADS")
                    .equals(Arrays.asList("a.com", "b.org")), "файл для ядра читается обратно");

            Fake fa = new Fake(tmpDir());
            Engine ea = engine(fa);
            ea.addServers(link("fast1.example.com", "Быстрый"));
            waitIdle(ea);
            ea.connect();
            waitIdle(ea);
            Map<String, Object> r = ea.setAds(Json.obj("block_ads", true));
            check(Json.bool(r, "download", false), "первое включение качает списки");
            waitIdle(ea);
            Map<String, Object> st = ea.adsState();
            check(Json.bool(st, "ready", false) && Json.num(st, "total", 0) > 150 && Json.list(st, "missing").isEmpty(),
                    "списки скачаны (с запасного адреса) и собраны: " + Json.write(st));
            File dat = new File(new File(fa.dir, "assets"), AdBlock.DAT);
            List<String> inDat = AdBlock.decodeGeosite(Files.readAllBytes(dat.toPath())).get("ADS");
            check(inDat.contains("doubleclick.net") && !inDat.contains("ad.doubleclick.net") && inDat.contains("ru5.adnet.example"),
                    "в файле все списки, без лишних поддоменов");
            waitIdle(ea);
            check(fa.lastConfig.contains("ext:adblock.dat:ads") && fa.lastConfig.contains("\"access\""), "VPN: реклама в «чёрную дыру»");
            ea.disconnect();
            waitIdle(ea);
            check("off".equals(ea.status()) && ea.filterOn() && fa.alive, "VPN выключен — реклама блокируется без него");
            check(!fa.lastConfig.contains("\"tag\":\"proxy\"") && fa.lastConfig.contains("ext:adblock.dat:ads"), "без сервера: всё напрямую, кроме рекламы");
            // журнал: ядро пишет заблокированные соединения
            Files.write(new File(fa.dir, "access.log").toPath(), ("2026/11/12 21:00:00 from tcp:172.19.0.1:4000 accepted tcp:mc.ads.example:443 [tun-in -> adblock]\n"
                    + "2026/11/12 21:00:01 from tcp:172.19.0.1:4001 accepted tcp:vk.com:443 [tun-in -> direct]\n"
                    + "2026/11/12 21:00:02 from tcp:172.19.0.1:4002 accepted tcp:mc.ads.example:443 [tun-in >> adblock]\n").getBytes(StandardCharsets.UTF_8));
            ea.monitor();
            st = ea.adsState();
            check(Json.num(st, "today", 0) == 2 && Json.write(st).contains("mc.ads.example") && !Json.write(Json.list(st, "recent")).contains("vk.com"),
                    "счётчик и журнал рекламы: " + Json.write(st.get("top")));
            ea.adsPause(30);
            waitIdle(ea);
            check(!ea.filterOn() && !fa.alive && Json.num(ea.adsState(), "paused_until", 0) > 0, "пауза — защита без VPN выключена");
            ea.adsPause(0);
            waitIdle(ea);
            check(ea.filterOn() && fa.alive, "пауза снята — снова работает");
            Map<String, Object> lk = ea.adsLookup("https://sub.doubleclick.net/x");
            check(Json.bool(lk, "blocked", false) && Json.write(lk).contains("\"match\":\"doubleclick.net\""), "«Проверить сайт»: какой список: " + Json.write(lk));
            check(!Json.bool(ea.adsLookup("example.com"), "blocked", true), "обычный сайт не блокируется");
            // встроенная защита сайтов
            check(!inDat.contains("yandex.ru") && !inDat.contains("www.youtube.com") && !inDat.contains("i.imgur.com")
                    && inDat.contains("an.yandex.ru") && inDat.contains("manga-site.example"), "встроенная защита сайтов: " + inDat.subList(0, Math.min(8, inDat.size())) + " yandex=" + inDat.contains("yandex.ru") + " an=" + inDat.contains("an.yandex.ru") + " manga=" + inDat.contains("manga-site.example") + " yt=" + inDat.contains("www.youtube.com") + " imgur=" + inDat.contains("i.imgur.com"));
            Map<String, Object> ly = ea.adsLookup("yandex.ru");
            check(Json.bool(ly, "protected", false) && !Json.bool(ly, "blocked", true), "«Проверить сайт»: защищённый сайт: " + Json.write(ly));
            // к закрытому сайту заходят снова — вопрос «разрешить?» (и уведомление)
            Files.write(new File(fa.dir, "access.log").toPath(), ("2026/11/12 21:00:00 from tcp:172.19.0.1:4000 accepted tcp:mc.ads.example:443 [tun-in -> adblock]\n"
                    + "2026/11/12 21:00:01 from tcp:172.19.0.1:4001 accepted tcp:vk.com:443 [tun-in -> direct]\n"
                    + "2026/11/12 21:00:02 from tcp:172.19.0.1:4002 accepted tcp:mc.ads.example:443 [tun-in >> adblock]\n"
                    + "2026/11/12 21:00:03 from tcp:172.19.0.1:4003 accepted tcp:www.manga-site.example:443 [tun-in -> adblock]\n"
                    + "2026/11/12 21:00:04 from tcp:172.19.0.1:4004 accepted tcp:manga-site.example:443 [tun-in -> adblock]\n"
                    + "2026/11/12 21:00:05 from tcp:172.19.0.1:4005 accepted tcp:doubleclick.net:443 [tun-in -> adblock]\n"
                    + "2026/11/12 21:00:06 from tcp:172.19.0.1:4006 accepted tcp:doubleclick.net:443 [tun-in -> adblock]\n").getBytes(StandardCharsets.UTF_8));
            ea.monitor();
            for (int i = 0; i < 50 && Json.list(ea.adsState(), "suspects").isEmpty(); i++) Thread.sleep(100);
            List<Object> sus = Json.list(ea.adsState(), "suspects");
            check(sus.size() == 1 && Json.write(sus).contains("\"site\":\"manga-site.example\"") && fa.notices.size() == 1,
                    "«сайт закрыт блокировщиком»: " + Json.write(sus) + " " + fa.notices);
            check("manga-site.example".equals(ea.adsSiteAnswer("manga-site.example", false))
                    && Json.list(ea.adsState(), "suspects").isEmpty() && Json.list(ea.settings, "ads_site_ignore").contains("manga-site.example"),
                    "«Не надо» — больше не спрашивать");
            ea.adsAllow("mc.ads.example");
            waitIdle(ea);
            check(Json.str(ea.settings, "ads_allow").contains("mc.ads.example"), "сайт из журнала разрешён");
            ea.disconnect(); // «Выключить» в уведомлении
            check(!ea.filterOn() && !fa.alive, "выключено вручную");
            ea.monitor();
            waitIdle(ea);
            check(!ea.filterOn(), "само не включается, пока не включат вручную");
            check(ea.filterStart(), "включение кнопкой");
            waitIdle(ea);
            check(ea.filterOn(), "снова работает");
            ea.connect();
            waitIdle(ea);
            check(ea.isOn() && !ea.filterOn() && fa.lastConfig.contains("\"tag\":\"proxy\""), "включили VPN — тот же туннель, уже с сервером");
            ea.disconnect();
            waitIdle(ea);
            check(ea.filterOn(), "выключили VPN — снова защита без VPN");
            fa.alive = false; // туннель забрал другой VPN
            ea.monitor();
            ea.monitor();
            waitIdle(ea);
            check(!ea.filterOn() && !fa.alive, "другой VPN забрал туннель — не воюем за него");
            ea.shutdown();
        });

        test("«Сайт работает не полностью»: зависание после 16 КБ, адреса сайта, починка через VPN и другой сервер", () -> {
            // проверка «качается ли» на настоящих соединениях
            for (String mode : new String[]{"ok", "freeze", "close"}) {
                java.net.ServerSocket ss = new java.net.ServerSocket(0, 5, java.net.InetAddress.getByName("127.0.0.1"));
                Thread th = new Thread(() -> {
                    try (Socket c = ss.accept()) {
                        InputStream in = c.getInputStream();
                        OutputStream o = c.getOutputStream();
                        int sent = 0;
                        while (true) {
                            StringBuilder req = new StringBuilder();
                            int ch;
                            while (req.indexOf("\r\n\r\n") < 0 && (ch = in.read()) >= 0) req.append((char) ch);
                            if (req.length() == 0) return;
                            byte[] body = new byte[5000];
                            Arrays.fill(body, (byte) 'x');
                            byte[] head = ("HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1);
                            ByteArrayOutputStream all = new ByteArrayOutputStream();
                            all.write(head);
                            all.write(body);
                            byte[] resp = all.toByteArray();
                            for (int i = 0; i < resp.length; i += 1000) {
                                if (mode.equals("freeze") && sent > 16000) { Thread.sleep(4000); return; }
                                int n = Math.min(1000, resp.length - i);
                                o.write(resp, i, n);
                                o.flush();
                                sent += n;
                            }
                            if (mode.equals("close")) return;
                        }
                    } catch (Exception ignored) {
                        // проверка закончилась
                    }
                });
                th.setDaemon(true);
                th.start();
                Map<String, Object> r = Http.stallTest("127.0.0.1", 0, ss.getLocalPort(), 1500, 8000, Http.STALL_TARGET);
                String want = mode.equals("ok") ? "ok" : mode.equals("freeze") ? "stall" : "small";
                check(want.equals(Json.str(r, "state")), "проверка «качается ли» (" + mode + "): " + Json.write(r));
                ss.close();
            }
            check("fail".equals(Json.str(Http.stallTest("127.0.0.1", 0, 1, 1000, 3000, Http.STALL_TARGET), "state")), "не открывается совсем");

            Fake fr = new Fake(tmpDir());
            Engine er = engine(fr);
            er.addServers(link("fast1.example.com", "Быстрый") + "\n" + link("slow1.example.com", "Медленный"));
            waitIdle(er);
            er.connect();
            waitIdle(er);
            final Map<String, Integer> calls = new HashMap<String, Integer>();
            final List<String> direct = new CopyOnWriteArrayList<String>();
            Engine.Staller old = Engine.STALL;
            Engine.STALL = (h, port) -> {
                int n = calls.containsKey(h) ? calls.get(h) : 0;
                calls.put(h, n + 1);
                if (port == 0) direct.add(h);
                if (h.equals("img.cdnfreeze.example") && port == 0) return Json.obj("state", "stall", "bytes", 16000L, "detail", "соединение замирает после 15 КБ");
                if (h.equals("video.region2.example") && n == 0) return Json.obj("state", "fail", "bytes", 0L, "detail", "сайт не отвечает");
                if (h.equals("api.directok.example") && port != 0) return Json.obj("state", "fail", "bytes", 0L, "detail", "соединение сброшено");
                return Json.obj("state", "ok", "bytes", 70000L, "detail", "68 КБ");
            };
            try {
                long now = System.currentTimeMillis();
                er.noteHost(now - 400000, "unrelated.example", "direct");
                er.noteHost(now - 30000, "www.site.example", "direct");
                er.noteHost(now - 29000, "img.cdnfreeze.example", "direct");
                er.noteHost(now - 28000, "video.region2.example", "proxy");
                er.noteHost(now - 27000, "ads.tracker.example", "adblock");
                er.noteHost(now - 26000, "api.directok.example", "proxy"); // ни через один сервер — только без VPN
                er.repairSite("https://www.site.example/page");
                waitIdle(er);
                Map<String, Object> rp = Json.map(er.state(), "repair");
                String w = Json.write(rp);
                check(rp != null && Json.num(rp, "fixed", 0) == 3 && !w.contains("unrelated.example") && w.contains("\"state\":\"blocked\""),
                        "починка: " + w);
                Map<String, Object> routes = Json.map(er.settings, "routes");
                check("proxy".equals(Json.str(Json.map(routes, "site:cdnfreeze.example"), "via"))
                        && "server".equals(Json.str(Json.map(routes, "site:region2.example"), "via"))
                        && "direct".equals(Json.str(Json.map(routes, "site:directok.example"), "via")), "маршруты после починки: " + Json.write(routes));
                check(!direct.contains("video.region2.example"), "адрес, который шёл через VPN, напрямую не проверялся");
            } finally {
                Engine.STALL = old;
            }
            er.disconnect();
            waitIdle(er);
            try {
                er.repairSite("site.example");
                check(false, "без VPN починка не запускается");
            } catch (Engine.UserError ok) {
                // так и надо
            }
            er.shutdown();
        });

        test("Предупреждения о подписке: скоро закончится, мало трафика", () -> {
            Fake fa = new Fake(tmpDir());
            Engine ea = engine(fa);
            ea.addSubscription(subUrl(), "Моя");
            waitIdle(ea);
            Map<String, Object> sub = (Map<String, Object>) Json.list(ea.settings, "subscriptions").get(0);
            long day = 86400L;
            sub.put("usage", Json.obj("upload", 1L, "download", 95L << 30, "total", 100L << 30,
                    "expire", System.currentTimeMillis() / 1000 + 2 * day));
            fa.notices.clear();
            ea.subAlerts();
            String probs = Json.write(ea.state().get("problems"));
            check(probs.contains("закончится через 2 дн.") && probs.contains("меньше 10% трафика") && fa.notices.size() == 2,
                    "предупреждения: " + probs + " " + fa.notices);
            ea.subAlerts();
            check(fa.notices.size() == 2, "уведомление — не чаще раза в день");
            ea.settings.put("sub_alerts", false);
            ea.subAlerts();
            check(!Json.write(ea.state().get("problems")).contains("10%"), "выключили — предупреждений нет");
            ea.shutdown();
        });

        test("Профили сетей: открытый Wi-Fi — всё через VPN, VPN выключен — напоминание", () -> {
            Fake fn = new Fake(tmpDir());
            Engine en = engine(fn);
            en.addServers(link("fast1.example.com", "Быстрый"));
            waitIdle(en);
            fn.net = Json.obj("kind", "wifi", "open", true);
            en.netWatch();
            check(fn.notices.size() == 1 && Json.bool(en.state(), "net_public", false), "VPN выключен — напоминание: " + fn.notices);
            en.connect();
            waitIdle(en);
            check(fn.lastConfig.contains("\"tag\":\"proxy\"") && !fn.lastConfig.contains("geosite:ru-available-only-inside\"],\"outboundTag\":\"direct"),
                    "в открытом Wi-Fi — всё через VPN");
            String publicCfg = fn.lastConfig;
            fn.net = Json.obj("kind", "wifi", "open", true, "captive", true); // кафе просит войти — не закрываем страницу
            en.netWatch();
            waitIdle(en);
            check(!Json.bool(en.state(), "net_public", true) && String.join("\n", en.logLines()).contains("просит войти"),
                    "страница входа: ждём входа");
            fn.net = Json.obj("kind", "wifi", "open", true);
            en.netWatch();
            waitIdle(en);
            check(Json.bool(en.state(), "net_public", false), "вошёл — всё через VPN");
            fn.net = Json.obj("kind", "wifi", "open", false);
            en.netWatch();
            waitIdle(en);
            check(!fn.lastConfig.equals(publicCfg) && !Json.bool(en.state(), "net_public", true), "своя сеть — обычный режим");
            en.disconnect();
            en.shutdown();
        });

        test("Обновление приложения: подпись выпуска, контрольная сумма, подмена", () -> {
            java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            java.security.interfaces.RSAPrivateKey priv = (java.security.interfaces.RSAPrivateKey) kpg.generateKeyPair().getPrivate();
            String base = "http://127.0.0.1:" + http.getAddress().getPort() + "/upd/";
            byte[] apk = "APK-BYTES-OF-NEW-VERSION".getBytes(StandardCharsets.UTF_8);
            java.io.File tmpApk = new java.io.File(tmpDir(), "a.apk");
            Files.write(tmpApk.toPath(), apk);
            String payload = Json.write(Json.obj("version", "99.0.0", "notes", "", "android",
                    Json.obj("version", "99.1.0", "url", base + "new.apk", "sha256", Update.sha256(tmpApk))));
            String sig = rsaSign(payload.getBytes(StandardCharsets.UTF_8), priv.getModulus(), priv.getPrivateExponent());
            UPD.put("latest.json", Json.write(Json.obj("payload", payload, "sig", sig)).getBytes(StandardCharsets.UTF_8));
            UPD.put("forged.json", Json.write(Json.obj("payload", payload.replace("99.1.0", "99.2.0"), "sig", sig)).getBytes(StandardCharsets.UTF_8));
            UPD.put("new.apk", apk);
            String oldUrl = Update.URL, oldN = Update.PUBLIC_N;
            Update.URL = base + "latest.json";
            Update.PUBLIC_N = priv.getModulus().toString();
            try {
                Fake fu = new Fake(tmpDir());
                Engine eu = engine(fu);
                eu.appUpdateCheck();
                waitIdle(eu);
                String st = Json.write(Json.map(eu.state(), "app_update"));
                check(st.contains("\"ready\":true") && st.contains("99.1.0") && eu.updateApk().length() == apk.length,
                        "скачано и проверено: " + st);
                Update.URL = base + "forged.json";
                eu.updateApk().delete();
                eu.appUpdateCheck();
                waitIdle(eu);
                check(!eu.updateApk().exists(), "подменённый выпуск не скачивается");
                UPD.put("new.apk", "BROKEN".getBytes(StandardCharsets.UTF_8));
                Update.URL = base + "latest.json";
                eu.appUpdateCheck();
                waitIdle(eu);
                check(!eu.updateApk().exists(), "повреждённый APK не остаётся");
                eu.shutdown();
            } finally {
                Update.URL = oldUrl;
                Update.PUBLIC_N = oldN;
            }
        });

        test("Проверка утечек: адрес через VPN и DNS", () -> {
            String base = "http://127.0.0.1:" + http.getAddress().getPort();
            Engine.LEAK_IP_URL = base + "/leak-ip";
            Engine.LEAK_DNS_URL = base + "/leak-dns";
            Fake fl = new Fake(tmpDir());
            fl.appProxy = true;
            Engine el = engine(fl);
            el.addServers(link("fast1.example.com", "Быстрый"));
            waitIdle(el);
            try {
                el.leakTest();
                check(false, "без VPN проверка не запускается");
            } catch (Engine.UserError ok) {
                // так и надо
            }
            el.connect();
            waitIdle(el);
            LEAK_CALLS.set(0);
            el.leakTest();
            waitIdle(el);
            String w = Json.write(el.state().get("leaks"));
            check(w.contains("видят адрес сервера") && w.contains("DNS не идёт через провайдера") && w.contains("\"errors\":0"), "утечки: " + w);
            el.disconnect();
            el.shutdown();
        });

        test("Шифрование: подписки и серверы на диске, другой телефон", () -> {
            File cdir = tmpDir();
            CryptoFake fc = new CryptoFake(cdir);
            Engine ec = engine(fc);
            ec.addSubscription(subUrl() + "?token=SECRET777", "Моя");
            waitIdle(ec);
            ec.saveSettings();
            String raw = new String(Files.readAllBytes(new File(cdir, "settings.json").toPath()), StandardCharsets.UTF_8);
            String srv = new String(Files.readAllBytes(new File(cdir, "servers.json").toPath()), StandardCharsets.UTF_8);
            check(!raw.contains("SECRET777") && raw.contains("\"_secure\":\"VDMSEC1:") && srv.startsWith("VDMSEC1:")
                    && !srv.contains("fast1"), "на диске зашифровано: " + raw.substring(0, Math.min(200, raw.length())));
            int n = Json.list(ec.state(), "servers").size();
            ec.shutdown();
            Engine e2 = engine(fc);
            check(Json.list(e2.state(), "servers").size() == n && n > 0 && Json.write(e2.settings).contains("SECRET777"), "читается обратно");
            e2.shutdown();
            fc.key = 9; // другой телефон
            Engine e3 = engine(fc);
            check(Json.list(e3.settings, "subscriptions").isEmpty() && Json.write(e3.state().get("problems")).contains("расшифровались"),
                    "на другом телефоне — не расшифровать, и это видно");
            e3.saveSettings();
            e3.shutdown();
            fc.key = 7;
            Engine e4 = engine(fc);
            check(Json.write(e4.settings).contains("SECRET777"), "то, что не прочитали, не затирается");
            e4.setSettings(Json.obj("encrypt_data", false));
            check(new String(Files.readAllBytes(new File(cdir, "settings.json").toPath()), StandardCharsets.UTF_8).contains("SECRET777"),
                    "шифрование можно выключить");
            e4.shutdown();
        });

        test("Скорость: сейчас через туннель и замер", () -> {
            Fake fs = new Fake(tmpDir());
            fs.appProxy = true;
            Engine es = engine(fs);
            es.addServers(link("fast1.example.com", "Быстрый"));
            waitIdle(es);
            check(Json.num(Json.map(es.state(), "speed"), "down", -1) == 0, "VPN выключен — скорости нет");
            es.connect();
            waitIdle(es);
            es.state();
            fs.rx += 3 * 1024 * 1024;
            fs.tx += 100 * 1024;
            Thread.sleep(1000);
            Map<String, Object> sp = Json.map(es.state(), "speed");
            check(Json.num(sp, "down", 0) > 1500000 && Json.num(sp, "up", 0) > 50000, "скорость посчитана: " + Json.write(sp));
            check(Engine.speedText(2 * 1048576, 40 * 1024).equals("↓ 2,0 МБ/с ↑ 40 КБ/с"), Engine.speedText(2 * 1048576, 40 * 1024));
            check(es.speedTest(), "замер запущен");
            waitIdle(es);
            Map<String, Object> st = Json.map(es.state(), "speed_test");
            check(st != null && ((Number) st.get("mbps")).doubleValue() > 0 && Json.bool(st, "vpn", false), "замер через VPN: " + Json.write(st));
            es.shutdown();
        });

        test("Журнал ошибок: склейка, вычистка секретов, битые строки, заявка на GitHub", () -> {
            File jdir = tmpDir();
            ErrorLog log = new ErrorLog(jdir, "1.7.0", "Android 14",
                    text -> Diagnostics.scrub(text, Arrays.asList("secret-node.example.com")));
            log.record("problem", "Сервер 12 не отвечает", "адрес secret-node.example.com, подписка https://sub.example.com/abc, "
                    + U + ", 203.0.113.7", "", "srv");
            log.record("problem", "Сервер 13 не отвечает", "", "", "srv");
            check(log.size() == 1 && Json.num(log.recent(5).get(0), "count", 0) == 2, "одинаковые склеились: " + Json.write(log.recent(5)));
            String d = Json.str(log.recent(1).get(0), "detail");
            check(!d.contains("secret-node") && !d.contains("https://") && !d.contains(U) && !d.contains("203.0.113.7"), "секреты вычищены: " + d);
            try {
                Object o = null;
                o.toString();
            } catch (NullPointerException x) {
                log.recordExc(x, "задача: тест");
            }
            Map<String, Object> crash = log.recent(1).get(0);
            check(log.size() == 2 && "crash".equals(Json.str(crash, "kind")) && Json.str(crash, "trace").contains("CoreTest"),
                    "сбой с трассировкой: " + Json.write(crash));
            Files.write(new File(jdir, "errors.jsonl").toPath(), "{битая строка\n\n".getBytes(StandardCharsets.UTF_8),
                    java.nio.file.StandardOpenOption.APPEND);
            ErrorLog log2 = new ErrorLog(jdir, "1.7.0", "Android 14", null);
            check(log2.size() == 2, "после перезапуска записи на месте, битая строка пропущена");
            Map<String, Object> issue = log2.issueText(10);
            check(Json.str(issue, "title").startsWith("[1.7.0] NullPointerException") && Json.str(issue, "body").contains("Что я делал"),
                    "текст заявки: " + Json.str(issue, "title"));
            String url = log2.issueUrl("me/vedomyj-vpn", 10);
            check(url.startsWith("https://github.com/me/vedomyj-vpn/issues/new?title=") && url.endsWith("&labels=bug"), url);
            check(log2.issueUrl("", 10).isEmpty(), "без репозитория — без ссылки");
            check(ErrorLog.repoFrom("https://github.com/me/vpn/releases/latest/download/latest.json").equals("me/vpn"), "репозиторий из ссылки");
            check(ErrorLog.repoFrom("https://example.com/x").isEmpty(), "не GitHub");
            for (int i = 0; i < ErrorLog.MAX_ENTRIES + 20; i++) {
                log2.record("problem", "проблема " + letters(i), "", "", "x");
            }
            check(log2.size() == ErrorLog.MAX_ENTRIES, "не больше " + ErrorLog.MAX_ENTRIES + " записей");
            check(ErrorLog.isBug(new NullPointerException()) && ErrorLog.isBug(new IllegalStateException())
                    && !ErrorLog.isBug(new java.io.IOException("x")) && !ErrorLog.isBug(new Engine.UserError("x"))
                    && !ErrorLog.isBug(new Engine.Cancelled()), "что считается ошибкой в коде");
            log2.clear();
            check(new ErrorLog(jdir, "1.7.0", "Android 14", null).size() == 0, "очистка сохраняется");
        });

        test("Защита: предохранители, запасные пути памяти сети, автооткат, безопасный запуск, сбор ошибок", () -> {
            File pdir = tmpDir();
            Fake fp = new Fake(pdir);
            fp.appProxy = true;
            Engine ep = engine(fp);
            ep.addServers(link("fast8.example.com", "А") + "\n" + link("fast9.example.com", "Б") + "\n"
                    + link("secret-node8.example.com", "В"));
            waitIdle(ep);
            Server a = null, b = null, c = null;
            for (Object o : Json.list(ep.state(), "servers")) {
                Server s = ep.find(Json.str(Json.map(o), "key"));
                if ("А".equals(s.name)) a = s;
                if ("Б".equals(s.name)) b = s;
                if ("В".equals(s.name)) c = s;
            }
            // предохранители
            check(ep.fuseOk("маскировка"), "сначала можно");
            ep.fuseResult("маскировка", false);
            check(ep.fuseOk("маскировка"), "одна неудача — ещё не пауза");
            ep.fuseResult("маскировка", false);
            List<Object> fz = Json.list(Json.map(ep.state(), "pro"), "fuses");
            check(!ep.fuseOk("маскировка") && fz.size() == 1 && Json.num(Json.map(fz.get(0)), "left", 0) > 500,
                    "две неудачи — пауза 10 минут: " + Json.write(fz));
            check(String.join("\n", ep.logLines()).contains("Предохранитель: «маскировка»"), "в журнале — почему");
            ep.settings.put("fuses_enabled", false);
            check(ep.fuseOk("маскировка"), "выключены — пробуется");
            ep.settings.put("fuses_enabled", true);
            ep.fuseResult("маскировка", true);
            check(ep.fuseOk("маскировка"), "помог — сброс");
            ep.fuseResult("отпечаток safari", false);
            ep.fuseResult("отпечаток safari", false);
            check(Boolean.TRUE.equals(Api.call(ep, "fuses_clear", Json.obj())) && ep.fuseOk("отпечаток safari"), "«Сбросить»");
            // память сети: прежний путь — запасной, старше 30 дней — забыт
            String nid = ep.netId();
            check(!nid.isEmpty(), "сеть известна");
            ep.rememberWay(a);
            ep.rememberWay(b);
            ep.rememberWay(c);
            ep.rememberWay(c);
            Map<String, Object> way = ep.netWay();
            List<Map<String, Object>> alts = Engine.netAlts(way);
            check(c.key().equals(Json.str(way, "server")) && alts.size() == 2 && b.key().equals(Json.str(alts.get(0), "server"))
                    && a.key().equals(Json.str(alts.get(1), "server")), "два запасных пути: " + Json.write(way));
            way.put("at", System.currentTimeMillis() - 31L * 86_400_000L);
            check(ep.netWay() == null, "память старше 30 дней не используется");
            way.put("at", System.currentTimeMillis());
            // профессиональные настройки
            Map<String, Object> pst = (Map<String, Object>) Api.call(ep, "pro_set", Json.obj("values", Json.obj("fuses_enabled", false, "x_key", true, "safe_start", "да")));
            check(!Json.bool(Json.map(pst, "keys"), "fuses_enabled", true) && !ep.settings.containsKey("x_key")
                    && Json.bool(ep.settings, "safe_start", false), "только свои ключи и только да/нет");
            ep.settings.put("autopilot", false);
            List<Object> ch = (List<Object>) Api.call(ep, "pro_reset", Json.obj());
            check(ch.contains("fuses_enabled") && ch.contains("autopilot") && Json.bool(ep.settings, "fuses_enabled", false)
                    && Json.bool(ep.settings, "autopilot", false), "«Вернуть как было»: " + Json.write(ch));
            // автооткат: после изменения данные не идут — вернуть как было
            long keepWait = Engine.GUARD_WAIT_MS;
            try {
                Engine.GUARD_WAIT_MS = 0;
                ep.select(a.key());
                ep.connect();
                waitIdle(ep);
                check(ep.isOn(), "подключено");
                for (int i = 0; i < 5; i++) ep.monitor();
                ep.settings.put("dns_encrypted", false);
                ep.setSettings(Json.obj("dns_encrypted", true));
                waitIdle(ep);
                check(Json.bool(Json.map(ep.state(), "pro"), "guard", false), "изменение под присмотром");
                ep.settings.put("autopilot", false); // проверяем только автооткат, без автосмены сервера
                fp.dead.addAll(Arrays.asList("fast8.example.com", "fast9.example.com", "secret-node8.example.com"));
                for (int i = 0; i < 40 && Json.bool(ep.settings, "dns_encrypted", false); i++) {
                    ep.monitor();
                    Thread.sleep(100);
                }
                waitIdle(ep);
                check(!Json.bool(ep.settings, "dns_encrypted", true), "связь пропала — вернул как было: on=" + ep.isOn()
                        + " guard=" + Json.bool(Json.map(ep.state(), "pro"), "guard", false) + " log=" + String.join(" | ", ep.logLines().subList(Math.max(0, ep.logLines().size() - 8), ep.logLines().size())));
                check(String.join("\n", ep.logLines()).contains("Автооткат"), "в журнале — автооткат");
                fp.dead.clear();
                ep.settings.put("autopilot", true);
            } finally {
                Engine.GUARD_WAIT_MS = keepWait;
            }
            // сбор ошибок: секреты не попадают в отчёт
            Map<String, Object> cs = (Map<String, Object>) Api.call(ep, "collect_start", Json.obj("hours", 500));
            check(Json.bool(cs, "on", false) && Json.num(cs, "left", 0) <= 72 * 3600, "не больше 72 часов: " + Json.write(cs));
            ep.log("Сервер secret-node8.example.com не ответил", "Server secret-node8.example.com did not answer");
            String path = (String) Api.call(ep, "collect_stop", Json.obj());
            check(path != null && new File(path).isFile(), "отчёт сохранён");
            String rep = (String) Api.call(ep, "collect_text", Json.obj());
            check(rep.contains("сбор ошибок") && rep.contains("не ответил") && !rep.contains("secret-node8"), "отчёт без адресов: " + rep.substring(0, Math.min(300, rep.length())));
            check(!Json.bool(Json.map(ep.state(), "collect"), "on", true) && Json.bool(Json.map(ep.state(), "collect"), "report_ok", false), "сбор выключился");
            ep.shutdown();
            // безопасный запуск: два падения подряд при запуске
            Store.write(new File(pdir, "start.json"), "{\"crashes\":2}");
            Engine es = engine(new Fake(pdir));
            es.start();
            check(es.safeMode && !Json.bool(es.settings, "fp_auto", true), "безопасный запуск: автоматика выключена");
            check(Json.write(Json.list(es.state(), "problems")).contains("Безопасный запуск"), "человек об этом знает");
            es.saveSettings();
            check(Json.bool(Json.parseObject(Store.read(new File(pdir, "settings.json"))), "fp_auto", false), "в файле настройка прежняя");
            es.shutdown();
        });

        test("«Не работает» и «Белые списки»: проверка всеми путями, «работает полностью», «Отменить», приоритет белым спискам", () -> {
            Fake fn = new Fake(tmpDir());
            Engine en = engine(fn);
            en.addServers(link("fast1.example.com", "Быстрый") + "\n" + link("slow1.example.com", "Медленный") + "\n"
                    + link("wl1.example.com", "Белые списки WL"));
            waitIdle(en);
            en.connect();
            waitIdle(en);
            check("Быстрый".equals(currentName(en)), "без галочки — лучший обычный: " + currentName(en));
            Api.call(en, "wl_set", Json.obj("on", true));
            waitIdle(en);
            check("Белые списки WL".equals(currentName(en)) && Json.bool(Json.map(en.state(), "wl"), "on", false),
                    "галочка «Белые списки» — сначала сервер для них: " + currentName(en));
            Api.call(en, "wl_set", Json.obj("on", false));
            waitIdle(en);
            check("Быстрый".equals(currentName(en)) && !Json.bool(en.settings, "wl_priority", true), "сняли галочку — обычный лучший: " + currentName(en));
            // «Не работает»: сервис
            final Map<String, String> plan = new java.util.concurrent.ConcurrentHashMap<String, String>();
            Engine.Staller old = Engine.STALL;
            Engine.STALL = (h, port) -> {
                String what = port == 0 ? "direct" : fn.portWhat.containsKey(port) ? fn.portWhat.get(port) : "cur";
                String how = what.startsWith("proxy:fast1") ? "vpn" : what.startsWith("proxy:") ? "other" : what;
                String st = plan.containsKey(h + "|" + how) ? plan.get(h + "|" + how) : plan.containsKey(h + "|*") ? plan.get(h + "|*") : "ok";
                if ("stall".equals(st)) return Json.obj("state", "stall", "bytes", 16000L, "detail", "соединение замирает после 15 КБ");
                if ("fail".equals(st)) return Json.obj("state", "fail", "bytes", 0L, "detail", "сайт не отвечает");
                return Json.obj("state", "ok", "bytes", 70000L, "detail", "68 КБ");
            };
            try {
                String before = Json.write(en.settings.get("proxy_list"));
                plan.put("www.youtube.com|cur", "stall");
                plan.put("www.youtube.com|direct", "stall");
                Api.call(en, "nw_fix", Json.obj("kind", "service", "value", "YouTube"));
                waitIdle(en);
                Map<String, Object> last = Json.map(Json.map(en.state(), "nw"), "last");
                check(last != null && "proxy".equals(Json.str(last, "route")) && Json.bool(last, "changed", false)
                        && Json.bool(last, "can_undo", false) && Json.str(last, "verdict").contains("теперь через VPN"),
                        "YouTube режется — теперь через VPN: " + Json.write(last));
                check(Json.str(en.settings, "proxy_list").contains("youtube.com"), "маршрут записан");
                check(Json.write(Json.list(last, "steps")).contains("замирает"), "видно, что было «не полностью»");
                Api.call(en, "nw_undo", Json.obj());
                waitIdle(en);
                check(Json.write(en.settings.get("proxy_list")).equals(before)
                        && !Json.bool(Json.map(Json.map(en.state(), "nw"), "last"), "can_undo", true), "«Отменить» — как было");
                // ни как сейчас, ни через VPN, ни без VPN — через другой сервер
                plan.clear();
                plan.put("discord.com|cur", "fail");
                plan.put("discord.com|vpn", "fail");
                plan.put("discord.com|direct", "fail");
                en.nwFix("service", "Discord", "");
                waitIdle(en);
                last = Json.map(Json.map(en.state(), "nw"), "last");
                check(Json.str(last, "route").startsWith("server:") && Json.str(last, "verdict").contains("теперь через «"),
                        "через другой сервер: " + Json.write(last));
                // нигде — ничего не меняем
                plan.clear();
                plan.put("api.openai.com|*", "fail");
                en.nwFix("service", "ChatGPT", "");
                waitIdle(en);
                last = Json.map(Json.map(en.state(), "nw"), "last");
                check(!Json.bool(last, "changed", true) && Json.str(last, "verdict").contains("не открывается ни"), "нигде не работает: " + Json.write(last));
                // приложение: известное — проверяется как сервис; неизвестное — без VPN по выбору
                plan.clear();
                en.nwFix("app", "com.google.android.youtube", "");
                waitIdle(en);
                last = Json.map(Json.map(en.state(), "nw"), "last");
                check("YouTube".equals(Json.str(last, "name")) && Json.str(last, "verdict").contains("качается полностью"),
                        "приложение YouTube — проверка сервиса: " + Json.write(last));
                try {
                    en.nwFix("app", "com.example.game", "");
                    check(false, "неизвестное приложение без выбора пути");
                } catch (Engine.UserError ok) {
                    // так и надо
                }
                en.nwFix("app", "com.example.game", "direct");
                waitIdle(en);
                check(Json.list(en.settings, "excluded_apps").contains("com.example.game"), "неизвестное приложение — без VPN");
                Api.call(en, "nw_undo", Json.obj());
                waitIdle(en);
                check(!Json.list(en.settings, "excluded_apps").contains("com.example.game"), "«Отменить» для приложения");
                try {
                    en.nwFix("service", "Нет такого", "");
                    check(false, "неизвестный сервис");
                } catch (Engine.UserError ok) {
                    // так и надо
                }
                Map<String, Object> tg = en.nwTargets();
                check(Json.list(tg, "services").size() == Services.ALL.size() && Json.map(tg, "known_apps").containsKey("com.discord"),
                        "списки для окна");
                check("www.youtube.com".equals(Services.checkHost(Services.find("YouTube"))), "YouTube — по странице с плеером");
            } finally {
                Engine.STALL = old;
            }
            en.shutdown();
        });

        test("Реклама: списки «Монстра» и «Почему реклама проходит?» с «Исправить»", () -> {
            Fake fm = new Fake(tmpDir());
            Engine em = engine(fm);
            em.addServers(link("fast1.example.com", "Быстрый"));
            waitIdle(em);
            em.connect();
            waitIdle(em);
            Map<String, Object> c = em.adsCheckNow();
            check(Json.num(c, "errors", 0) == 1 && "ads_on".equals(Json.str(Json.map(Json.list(c, "items").get(0)), "fix")),
                    "блокировка выключена — так и сказать: " + Json.write(c));
            em.setAds(Json.obj("block_ads", true));
            waitIdle(em);
            Map<String, Object> st = em.adsState();
            Map<String, Object> counts = Json.map(st, "counts");
            check(Json.bool(Json.map(st, "lists"), "m_ads", false) && Json.num(counts, "easylist", 0) == 60
                    && Json.num(counts, "m_ads", 0) == 180 && Json.list(st, "missing").isEmpty(),
                    "списки «Монстра» включены сразу и собраны: " + Json.write(counts));
            List<String> inDat = AdBlock.decodeGeosite(Files.readAllBytes(new File(new File(fm.dir, "assets"), AdBlock.DAT).toPath())).get("ADS");
            check(inDat.contains("easylist5.abp.example") && !inDat.contains("easylist0.abp.example") && !inDat.contains("easylist-path.example"),
                    "из правил фильтров — адреса целиком, исключения списка соблюдаются");
            Engine.AdProbe oldProbe = Engine.AD_PROBE;
            final List<Integer> ports = new ArrayList<Integer>();
            Engine.AD_PROBE = (h, port) -> { ports.add(port); return false; };
            try {
                c = em.adsCheckNow();
                String w = Json.write(c);
                check(w.contains("Списки скачаны") && w.contains("Все приложения идут через фильтр") && w.contains("Рекламные адреса закрыты")
                        && Json.num(c, "errors", 1) == 0 && ports.size() == Engine.AD_LIVE, "всё в порядке: " + w);
                Engine.AD_PROBE = (h, port) -> true;
                c = em.adsCheckNow();
                check(Json.write(c).contains("\"fix\":\"ads_apply\"") && Json.num(c, "errors", 0) == 1, "реклама проходит — «Исправить»: " + Json.write(c));
            } finally {
                Engine.AD_PROBE = oldProbe;
            }
            em.setSettings(Json.obj("excluded_apps", Json.arr("com.example.game")));
            waitIdle(em);
            check(Json.write(em.adsCheckNow()).contains("\"fix\":\"apps\""), "приложения без VPN идут мимо — подсказка");
            em.setAds(Json.obj("ads_lists", Json.obj("m_ads", false)));
            waitIdle(em);
            check(!Json.bool(Json.map(em.adsState(), "lists"), "m_ads", true) && !Json.map(em.adsState(), "counts").containsKey("easylist"),
                    "группа «Монстра» выключается одной галочкой");
            check(Json.bool(Json.map(em.adsState(), "lists"), "m_privacy", false), "остальные группы не тронуты");
            Api.call(em, "ads_check", Json.obj());
            waitIdle(em);
            check(Json.map(em.adsState(), "check") != null, "итог проверки виден в окне");
            em.shutdown();
        });

        test("Способы для Xray: fm, перебор портов Hysteria2, шум UDP, старое ядро, проверка «16 КБ»", () -> {
            Server h = Links.parseLink("hysteria2://pw@hy.example.com:443,20000-30000/?sni=a.com&obfs=salamander&obfs-password=x#H");
            List<Map<String, Object>> oldCore = XrayConfig.proxyOutbounds(h, "proxy", false, "26.2.6");
            Map<String, Object> fmOld = Json.map(Json.map(oldCore.get(0), "streamSettings"), "finalmask");
            check(fmOld != null && !fmOld.containsKey("quicParams") && Json.write(fmOld).contains("salamander"), "старое ядро — только Salamander: " + Json.write(fmOld));
            List<Map<String, Object>> noisy = XrayConfig.proxyOutbounds(h, "proxy", true, "26.3.27");
            String nw = Json.write(Json.map(Json.map(noisy.get(0), "streamSettings"), "finalmask"));
            check(nw.contains("\"noise\"") && nw.contains("salamander") && nw.contains("udpHop"), "шум UDP поверх Salamander, перебор портов: " + nw);
            check(!Json.write(XrayConfig.proxyOutbounds(h, "proxy", true, "26.2.6")).contains("noise"), "старое ядро — без шума");
            check("шум UDP".equals(Engine.wayKind(h.withWay("", true))) && "UDP noise".equals(Engine.wayKindEn("шум UDP")), "вид способа");
            check(Json.write(Json.map(h.outbound, "streamSettings")).contains("udpHop"), "сам сервер не меняется");
            // «16 КБ»
            Fake fs = new Fake(tmpDir());
            Engine es = engine(fs);
            es.addServers(link("fast1.example.com", "Быстрый") + "\n" + link("empty1.example.com", "Пустой") + "\n"
                    + link("slow1.example.com", "Медленный"));
            waitIdle(es);
            es.settings.put("stall_check", true);
            es.testServersTask();
            waitIdle(es);
            Map<String, Object> st = es.state();
            String sv = Json.write(st.get("servers"));
            check(sv.contains("\"cut\":true"), "«пустой» сервер (пинг есть, данных нет) помечен: " + sv);
            boolean emptyLast = true;
            List<Server> rk = es.ranked();
            for (int i = 0; i < rk.size() - 1; i++) {
                if (rk.get(i).address.startsWith("empty")) emptyLast = false;
            }
            check(emptyLast, "помеченный — ниже в списке");
            es.settings.put("stall_check", false);
            check(es.stallCheck() == 0, "выключено — не проверяет");
            es.shutdown();
        });

        test("Журнал ошибок в движке: сбои задач, секреты серверов, действия интерфейса", () -> {
            Fake fe = new Fake(tmpDir());
            Engine ee = engine(fe);
            ee.addServers(link("secret-node.example.com", "Секретный"));
            waitIdle(ee);
            ee.runTask("Тест", "x", () -> { throw new IllegalStateException("сломалось на secret-node.example.com"); });
            waitIdle(ee);
            ee.runTask("Тест 2", "x", () -> { throw new Engine.UserError("понятная ошибка"); });
            waitIdle(ee);
            List<Object> items = Json.list((Map<String, Object>) Api.call(ee, "errors_list", Json.obj()), "items");
            check(items.size() == 1, "записан только сбой кода: " + Json.write(items));
            Map<String, Object> it = Json.map(items.get(0));
            check(Json.str(it, "title").startsWith("IllegalStateException") && Json.str(it, "where").equals("задача: Тест"), Json.write(it));
            check(!Json.write(it).contains("secret-node"), "адрес сервера вычищен: " + Json.str(it, "title"));
            check(Json.num(ee.state(), "errors_count", 0) == 1, "счётчик в состоянии");
            ee.recordBug(new java.io.IOException("сеть"), "действие: x");
            check(ee.errors().size() == 1, "ошибки сети — не баг");
            check("me/vedomyj-vpn".equals(Api.call(ee, "errors_repo", Json.obj("repo", "https://github.com/me/vedomyj-vpn.git"))), "репозиторий из ссылки");
            check("me/vedomyj-vpn".equals(Json.str(ee.settings, "github_repo")), "сохранён в настройках");
            boolean threw = false;
            try { Api.call(ee, "errors_repo", Json.obj("repo", "не ссылка")); } catch (Engine.UserError x) { threw = true; }
            check(threw, "непонятный адрес — понятная ошибка");
            Map<String, Object> issue = (Map<String, Object>) Api.call(ee, "errors_issue", Json.obj());
            check(Json.str(issue, "url").startsWith("https://github.com/me/vedomyj-vpn/issues/new?"), Json.str(issue, "url"));
            Api.call(ee, "errors_clear", Json.obj());
            check(ee.errors().size() == 0 && Json.num(ee.state(), "errors_count", -1) == 0, "очищено");
            ee.shutdown();
        });

        test("Сертификаты: подмена напрямую и через VPN, антивирус, неизвестный центр", () -> {
            Map<String, Object> r = Certs.check(30000, new String[]{"www.google.com"}, Arrays.asList("Russian Trusted Root CA"),
                    Arrays.asList("Charles Proxy CA"), (h, port) -> port == 0
                            ? certRes("ok", "Russian Trusted Sub CA", "", "Russian Trusted Sub CA")
                            : certRes("ok", "Google Trust Services", ""), true);
            String w = titles(r);
            check(Json.bool(r, "mitm", false) && !Json.bool(r, "vpn_mitm", true), w);
            check(w.contains("error: Напрямую сертификат www.google.com подменён") && w.contains("Через VPN он настоящий"), w);
            check(w.contains("warn: На телефоне стоит сертификат Минцифры: Russian Trusted Root CA"), w);
            check(w.contains("info: На телефоне установлены свои сертификаты: Charles Proxy CA"), w);
            check(Json.num(r, "errors", 0) == 1 && Json.num(r, "warnings", 0) == 1, w);

            r = Certs.check(30000, new String[]{"github.com"}, new ArrayList<String>(), null,
                    (h, port) -> port == 0 ? certRes("ok", "Sectigo Limited", "") : certRes("bad", "Evil Box CA", ""), true);
            w = titles(r);
            check(Json.bool(r, "vpn_mitm", false) && !Json.bool(r, "mitm", true) && w.contains("Через VPN сертификат github.com поддельный"), w);
            check(w.contains("ok: Сертификатов Минцифры на телефоне нет") && w.contains("ok: Подмены сертификатов напрямую нет"), w);

            r = Certs.check(0, new String[]{"www.google.com"}, null, null,
                    (h, port) -> certRes("ok", "Kaspersky Anti-Virus Personal Root", "Kaspersky"), true);
            w = titles(r);
            check(!Json.bool(r, "mitm", true) && w.contains("info: Антивирус проверяет защищённые соединения (Kaspersky)"), w);
            check(!w.contains("Минцифры"), "хранилище неизвестно — про него молчим: " + w);

            r = Certs.check(0, new String[]{"www.google.com"}, null, null, (h, port) -> certRes("ok", "Corp Inspection CA", ""), true);
            check(Json.bool(r, "mitm", false) && titles(r).contains("warn: Сертификат www.google.com выдан неизвестным центром"), titles(r));

            r = Certs.check(0, new String[]{"www.google.com"}, null, null, (h, port) -> certRes("fail", "", ""), true);
            check(!Json.bool(r, "mitm", true) && Json.list(r, "items").isEmpty(), "сайт закрыт — не подмена: " + titles(r));

            check(Certs.russianNames(testCertDer()).contains("Russian Trusted Sub CA")
                    && Certs.russianNames(testCertDer()).contains("Минцифры России"), "признаки в сертификате");
            check(Certs.russianNames("обычный сертификат".getBytes(StandardCharsets.UTF_8)).isEmpty(), "без признаков");
            check(Certs.knownPublic("Let's Encrypt") && !Certs.knownPublic("Russian Trusted Sub CA"), "публичные центры");
            check(Certs.certName(testCertDer()).equals("Russian Trusted Sub CA"), Certs.certName(testCertDer()));
        });

        test("Сертификаты: настоящее TLS-соединение (напрямую и через вход ядра)", () -> {
            javax.net.ssl.SSLServerSocket srv = tlsServer();
            ConnectProxy px = new ConnectProxy(0, "");
            try {
                int port = srv.getLocalPort();
                Map<String, Object> bad = Certs.fetch("localhost", port, 0, 5000);
                check("bad".equals(Json.str(bad, "state")) && Json.list(bad, "russian").contains("Russian Trusted Sub CA")
                        && Json.str(bad, "sha256").length() == 64, "система не доверяет — подмена видна: " + Json.write(bad));
                Map<String, Object> viaProxy = Certs.fetch("localhost", port, px.port(), 5000);
                check("bad".equals(Json.str(viaProxy, "state")), "через вход ядра (CONNECT): " + Json.write(viaProxy));
                final java.security.cert.X509Certificate mine = (java.security.cert.X509Certificate) java.security.cert.CertificateFactory
                        .getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(testCertDer()));
                Certs.trustOverride = new javax.net.ssl.X509TrustManager() {
                    public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) { }
                    public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a)
                            throws java.security.cert.CertificateException {
                        if (!c[0].equals(mine)) throw new java.security.cert.CertificateException("unknown");
                    }
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[]{mine}; }
                };
                Map<String, Object> ok = Certs.fetch("localhost", port, 0, 5000);
                check("ok".equals(Json.str(ok, "state")) && Json.str(ok, "issuer").contains("Ministry of Digital Development")
                        && !Json.list(ok, "russian").isEmpty(), "сертификату «доверяют», но он Минцифры: " + Json.write(ok));
                Map<String, Object> dead = Certs.fetch("localhost", px.port() == 1 ? 2 : 1, 0, 2000);
                check("fail".equals(Json.str(dead, "state")), "нет соединения — fail: " + Json.write(dead));
            } finally {
                Certs.trustOverride = null;
                srv.close();
                px.close();
            }
        });

        test("Сертификаты в движке: проблемы, «Понятно», фоновая слежка, журнал", () -> {
            CertFake fc = new CertFake(tmpDir());
            fc.user = Arrays.asList(testCertDer());
            Engine ec = engine(fc);
            Certs.Fetcher old = Certs.FETCH;
            Certs.FETCH = (h, port) -> certRes("bad", "Russian Trusted Sub CA", "", "Russian Trusted Sub CA");
            try {
                check(Boolean.TRUE.equals(Api.call(ec, "cert_check", Json.obj())), "проверка запущена");
                waitIdle(ec);
                Map<String, Object> st = ec.state();
                Map<String, Object> c = Json.map(st, "certs");
                check(c != null && Json.bool(c, "mitm", false) && !Json.bool(c, "acked", true), Json.write(c));
                String probs = Json.write(Json.list(st, "problems"));
                check(probs.contains("\"cert_mitm\"") && probs.contains("\"cert_root\"") && !probs.contains("\"cert_vpn\""), probs);
                String journal = Json.write(ec.errorsState());
                check(journal.contains("В этой сети подменяют сертификаты сайтов"), "проблема в журнале ошибок: " + journal);
                Api.call(ec, "cert_ack", Json.obj());
                check(!Json.write(Json.list(ec.state(), "problems")).contains("\"cert_root\""), "«Понятно» убрало проблему");
                check(Json.list(ec.settings, "cert_root_ack").contains("Russian Trusted Sub CA"), "запомнено");
                ec.certCheck();
                waitIdle(ec);
                check(!Json.write(Json.list(ec.state(), "problems")).contains("\"cert_root\""), "после повторной проверки не вернулась");
                Certs.FETCH = CLEAN_CERTS;
                ec.certCheck();
                waitIdle(ec);
                check(!Json.write(Json.list(ec.state(), "problems")).contains("\"cert_mitm\""), "подмена ушла — проблема тоже");

                // фоновая слежка: новая сеть → тихая проверка → уведомление, если нашлась подмена
                Certs.FETCH = (h, port) -> certRes("bad", "Evil", "");
                fc.net = Json.obj("kind", "wifi", "open", false);
                ec.netWatch();
                fc.net = Json.obj("kind", "cell");
                ec.netWatch();
                long end = System.currentTimeMillis() + 5000;
                while (fc.notices.isEmpty() && System.currentTimeMillis() < end) Thread.sleep(20);
                check(fc.notices.toString().contains("Подмена сертификатов"), "уведомление: " + fc.notices);
                check(Json.write(Json.list(ec.state(), "problems")).contains("\"cert_mitm\""), "проблема из фоновой проверки");
                ec.setSettings(Json.obj("cert_watch", false));
                check(Boolean.FALSE.equals(Json.map(ec.state(), "settings").get("cert_watch")), "слежка выключается");
                Certs.FETCH = CLEAN_CERTS;
                fc.net = Json.obj("kind", "wifi", "open", false);
                ec.netWatch();
                Thread.sleep(200);
                check(Json.write(Json.list(ec.state(), "problems")).contains("\"cert_mitm\""), "выключенная слежка не проверяет");
            } finally {
                Certs.FETCH = old;
                ec.shutdown();
            }
        });

        test("Лестница: другой отпечаток TLS, «подключено, но пусто», память сети, без петли, сторож данных", () -> {
            Fake fl = new Fake(tmpDir());
            fl.appProxy = true;
            Engine el = engine(fl);
            el.addServers(link("fpblocked1.example.com", "FP") + "\n" + link("empty1.example.com", "Пустой") + "\n"
                    + link("fast7.example.com", "Запасной") + "\n" + link("slow7.example.com", "Медленный"));
            waitIdle(el);
            el.testServersTask();
            waitIdle(el);
            Server fp = null, empty = null, backup = null, slow = null;
            for (Object o : Json.list(el.state(), "servers")) {
                Map<String, Object> m = Json.map(o);
                Server s = el.find(Json.str(m, "key"));
                if ("FP".equals(s.name)) fp = s;
                if ("Пустой".equals(s.name)) empty = s;
                if ("Запасной".equals(s.name)) backup = s;
                if ("Медленный".equals(s.name)) slow = s;
            }
            check(fp.ok && "firefox".equals(fp.fp), "отпечаток подобран при проверке: " + fp.fp + " " + fp.ok);
            String keepUrl = Engine.DATA_URL;
            String[] keepMore = Engine.DATA_URLS_MORE;
            try {
                Engine.DATA_URL = "http://127.0.0.1:" + httpPort() + "/no-such-path";
                Engine.DATA_URLS_MORE = new String[]{Engine.DATA_URL};
                Map<String, Object> dc = Engine.dataCheck(0);
                check(Json.bool(dc, "ok", false) && Json.bool(dc, "inconclusive", false), "адрес недоступен — сервер не бракуется: " + Json.write(dc));
                Engine.DATA_URL = "http://127.0.0.1:1/";
                Engine.DATA_URLS_MORE = new String[]{"http://127.0.0.1:1/x"};
                dc = Engine.dataCheck(0);
                check(!Json.bool(dc, "ok", true) && !Json.bool(dc, "inconclusive", false), "соединение не открывается: " + Json.write(dc));
            } finally {
                Engine.DATA_URL = keepUrl;
                Engine.DATA_URLS_MORE = keepMore;
            }
            check(Json.write(XrayConfig.testConfig(fp, false, "")).contains("\"fingerprint\":\"firefox\""), "и попал в настройки ядра");
            check(String.join("\n", el.logLines()).contains("Другой отпечаток TLS помог серверам: 1"), "в журнале — что помогло");
            // «подключено, но пусто»: пинг есть, данных нет — лестница уходит на сервер, через который данные идут
            check(empty.ok, "по пингу пустой сервер выглядит рабочим");
            el.select(empty.key());
            el.connect();
            waitIdle(el);
            check("Пустой".equals(currentName(el)), "подключено к пустому: " + currentName(el));
            el.settings.put("selected", "");
            el.settings.put("autopilot", true); // выбор сервера в списке выключает автосмену («VPN-сервер»)
            el.ladderRetry();
            waitIdle(el);
            check(el.isOn() && "Запасной".equals(currentName(el)), "лестница нашла рабочий: " + currentName(el));
            check(String.join("\n", el.logLines()).contains("Лестница: данные пошли — другой сервер: Запасной"), "шаг лестницы в журнале");
            String nid = el.netId();
            check(!nid.isEmpty() && backup.key().equals(Json.str(Json.map(Json.map(el.settings, "net_ways"), nid), "server")),
                    "способ запомнен для сети");
            // у текущего сервера заблокировали и Firefox — шаг «другой отпечаток» на том же сервере
            el.netMemoryClear();
            el.select(fp.key());
            waitIdle(el);
            check("FP".equals(currentName(el)), "подключено к FP: " + currentName(el));
            el.settings.put("selected", "");
            el.settings.put("autopilot", true); // выбор сервера в списке выключает автосмену («VPN-сервер»)
            fl.blockedFps.add("firefox");
            el.ladderRetry();
            waitIdle(el);
            check("FP".equals(currentName(el)) && "safari".equals(fp.fp), "тот же сервер, отпечаток safari: " + currentName(el) + " " + fp.fp);
            check("отпечаток safari".equals(Json.str(Json.map(el.state(), "ladder"), "way")), "способ виден в окне");
            fl.blockedFps.remove("firefox");
            // ничего не работает: «что работает напрямую», пауза, без петли
            fl.dead.addAll(Arrays.asList("fpblocked1.example.com", "empty1.example.com", "fast7.example.com", "slow7.example.com"));
            el.ladderRetry();
            waitIdle(el);
            Map<String, Object> ld = Json.map(el.state(), "ladder");
            check(Json.num(ld, "retry_at", 0) > System.currentTimeMillis() + 60000, "пауза перед следующей попыткой: " + Json.write(ld));
            check(Json.write(Json.map(ld, "what_works")).contains("{\"name\":\"Telegram\",\"ok\":true}")
                    && Json.write(Json.map(ld, "what_works")).contains("{\"name\":\"Google\",\"ok\":false}"), "что работает напрямую: " + Json.write(ld));
            check(Json.write(Json.list(el.state(), "problems")).contains("Нет связи через VPN"), "проблема видна");
            for (int i = 0; i < 9; i++) el.monitor();
            check(!el.busy(), "во время паузы лестница не крутится по кругу");
            fl.dead.clear();
            check(Boolean.TRUE.equals(Api.call(el, "ladder_retry", Json.obj())), "«Попробовать сейчас»");
            waitIdle(el);
            check(el.isOn() && Json.map(Json.map(el.state(), "ladder"), "what_works") == null, "снова работает");
            // память сети: в мобильной сети работал «Медленный» — при переходе на неё программа сразу берёт его
            fl.net = Json.obj("kind", "cell");
            String cellId = el.netId();
            fl.net = Json.obj("kind", "wifi", "open", false);
            Json.child(el.settings, "net_ways").put(cellId, Json.obj("server", slow.key(), "fp", "", "mask", false, "at", System.currentTimeMillis()));
            el.netWatch();
            fl.net = Json.obj("kind", "cell");
            el.netWatch();
            waitIdle(el);
            check("Медленный".equals(currentName(el)), "при смене сети — способ из памяти: " + currentName(el));
            // сторож данных: уходит, а не приходит — проверка данных и лестница
            el.select(empty.key());
            waitIdle(el);
            el.settings.put("selected", "");
            el.settings.put("autopilot", true); // выбор сервера в списке выключает автосмену («VPN-сервер»)
            check("Пустой".equals(currentName(el)), "снова на пустом: " + currentName(el));
            Engine.SILENT_MS = 0;
            try {
                fl.tx += 1000;
                el.monitor();
                fl.tx += 1000;
                el.monitor();
                Thread.sleep(500);
                waitIdle(el);
            } finally {
                Engine.SILENT_MS = 30000;
            }
            check(String.join("\n", el.logLines()).contains("Сторож данных") && !"Пустой".equals(currentName(el)),
                    "сторож заметил тишину и сменил сервер: " + currentName(el));
            // выключатели
            el.setSettings(Json.obj("fp_auto", false));
            waitIdle(el);
            check(fp.fp.isEmpty() && Boolean.FALSE.equals(Json.map(el.state(), "settings").get("fp_auto")), "подбор отпечатка выключается");
            Api.call(el, "net_memory_clear", Json.obj());
            check(Json.num(Json.map(el.state(), "ladder"), "count", -1) == 0, "память сетей очищается");
            el.shutdown();
        });

        test("Движки: Hysteria2 в ядре, AmneziaWG в своё приложение, TUIC — только на компьютере, выбор движка", () -> {
            Fake fd = new Fake(tmpDir());
            Engine ed = engine(fd);
            String awg = "# Дом\n[Interface]\nPrivateKey = cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MTI=\nAddress = 10.8.1.7/32\n"
                    + "Jc = 4\nJmin = 40\nJmax = 70\nH1 = 1844\n\n[Peer]\nPublicKey = cHVibGlja2V5cHVibGlja2V5cHVibGlja2V5cHViMTI=\n"
                    + "AllowedIPs = 0.0.0.0/0\nEndpoint = awg.example.com:51820\n";
            Map<String, Object> pv = ed.importPreview(awg);
            check("servers".equals(Json.str(pv, "kind")) && Json.num(pv, "servers", 0) == 1, "конфиг AmneziaWG узнан: " + pv);
            ed.addServers(link("fast8.example.com", "Xray") + "\nhysteria2://pw@fast9.example.com:8443?sni=h.example.com"
                    + "&obfs=salamander&obfs-password=op#Hy\ntuic://" + U + ":pw@fast10.example.com:443#Tuic");
            waitIdle(ed);
            ed.addServers(awg);
            waitIdle(ed);
            Map<String, Object> eng = Json.map(ed.state(), "engine");
            check(Json.canonical(Json.map(eng, "counts")).equals("{\"auto\":2,\"awg\":1,\"hy2\":1,\"singbox\":1,\"xray\":1}"),
                    "счёт движков: " + Json.canonical(eng));
            check("awg".equals(Json.str(serverByName(ed, "Дом"), "kind")) && !Json.bool(serverByName(ed, "Дом"), "usable", true),
                    "AmneziaWG — не в ядре Xray");
            check(!Json.bool(serverByName(ed, "Tuic"), "usable", true) && Json.str(serverByName(ed, "Tuic"), "note").contains("компьютер"),
                    "TUIC: только на компьютере");
            Server hy = ed.find(Json.str(serverByName(ed, "Hy"), "key"));
            check(hy.usable() && XrayConfig.fingerprintOf(hy.outbound) == null && "udp".equals(Engine.transportOf(hy)),
                    "Hysteria2: работает в ядре, отпечатка TLS нет, транспорт UDP");
            ed.setEnginePick("hy2");
            check(ed.connect(), "подключение началось");
            waitIdle(ed);
            check(ed.isOn() && "Hy".equals(currentName(ed)), "движок Hysteria2: " + currentName(ed));
            check(fd.lastConfig.contains("\"protocol\":\"hysteria\"") && fd.lastConfig.contains("salamander"), "ядро получило Hysteria2");
            ed.disconnect();
            waitIdle(ed);
            ed.setEnginePick("xray");
            check(ed.connect(), "подключение началось (Xray)");
            waitIdle(ed);
            check(ed.isOn() && "Xray".equals(currentName(ed)), "движок Xray: " + currentName(ed));
            ed.disconnect();
            waitIdle(ed);
            ed.setEnginePick("awg");
            Map<String, Object> info = ed.awgInfo("");
            check("Дом".equals(Json.str(info, "name")) && Json.str(info, "conf").contains("PrivateKey")
                    && Json.str(info, "file").endsWith(".conf"), "конфиг для приложения AmneziaWG: " + Json.str(info, "file"));
            try {
                ed.setEnginePick("singbox");
                check(false, "sing-box на телефоне не выбирается");
            } catch (Engine.UserError ignored) {
                // так и должно быть
            }
            Server home = ed.find(Json.str(info, "key"));
            Server back = Server.fromJson(Json.parseObject(Json.write(home.toJson())));
            check("awg".equals(back.engine) && back.awgConf.contains("Endpoint") && !Json.write(home.toJson()).contains("awgConf"),
                    "после перезапуска конфиг берётся из ссылки");
            // ключ Amnezia vpn:// — AmneziaWG внутри
            java.io.ByteArrayOutputStream raw = new java.io.ByteArrayOutputStream();
            byte[] json = Json.write(Json.obj("description", "Ключ", "containers", Json.arr(Json.obj("container", "amnezia-awg",
                    "awg", Json.obj("last_config", Json.write(Json.obj("config", awg))))))).getBytes(StandardCharsets.UTF_8);
            java.util.zip.Deflater d = new java.util.zip.Deflater();
            d.setInput(json);
            d.finish();
            byte[] buf = new byte[65536];
            int n = d.deflate(buf);
            raw.write(new byte[]{0, 0, (byte) (json.length >> 8), (byte) json.length}, 0, 4);
            raw.write(buf, 0, n);
            List<String> got = Links.textToLinks("vpn://" + Base64.getUrlEncoder().withoutPadding().encodeToString(raw.toByteArray()));
            check(got.size() == 1 && "Ключ".equals(Links.parseLink(got.get(0)).name), "ключ vpn:// → AmneziaWG: " + got);
            String rep = ed.report();
            check(!rep.contains("cHJpdmF0ZWtle") && !rep.contains("awg://") && !rep.contains("awg.example.com"), "в отчёте нет ключей AmneziaWG");
            // «не проверять сертификат»: новые ядра Xray не принимают allowInsecure — приложение закрепляет сертификат
            ed.setEnginePick("auto");
            ed.addServers("vless://" + U + "@fast11.example.com:443?type=ws&security=tls&sni=s.example.com&allowInsecure=1#Self");
            waitIdle(ed);
            Server self = ed.find(Json.str(serverByName(ed, "Self"), "key"));
            check(self.tlsUnverified && !Json.write(self.outbound).contains("allowInsecure"), "allowInsecure убран из настроек ядра");
            ed.testServersTask();
            waitIdle(ed);
            String pin = XrayConfig.CERT_PINS.get(self.key());
            check(pin != null && pin.length() == 64 && Json.write(ed.settings).contains(pin), "отпечаток снят и сохранён");
            check(Json.write(XrayConfig.runConfig(self, ed.settings, new XrayConfig.Options())).contains(pin), "ядро получает отпечаток");
            Server hyi = Links.parseLink("hysteria2://pw@h9.example.com:443?insecure=1#HyI");
            check(!hyi.supported && "hy2".equals(Links.kindOf(hyi)) && hyi.note.contains("компьютер"),
                    "Hysteria2 с самоподписанным сертификатом без отпечатка — только на компьютере");
        });

        test("Отключение системой и неудачный запуск ядра", () -> {
            e.connect();
            waitIdle(e);
            check(e.isOn(), "снова подключено");
            fake.alive = false; // другой VPN забрал туннель
            e.monitor();
            check("off".equals(e.status()), "состояние «выключен»");
            Engine e3 = engine(new Fake(tmpDir()));
            e3.addServers(link("nostart.example.com", "Сломанный"));
            waitIdle(e3);
            e3.connect();
            waitIdle(e3);
            check("off".equals(e3.status()), "не завис в «подключаюсь»");
            check(Json.str(Json.map(e3.state(), "message"), "text").contains("Ни один сервер"), "понятная ошибка");
            e3.shutdown();
        });

        test("WARP: ключи и шифр по официальным тестам, регистрация, создание и другие обманки", () -> {
            byte[] nine = new byte[32];
            nine[0] = 9;
            check(Warp.toHex(Warp.x25519(Warp.hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                    Warp.hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")), 0, 32)
                    .equals("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"), "X25519: RFC 7748, 5.2");
            byte[] a = Warp.hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
            byte[] b = Warp.hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
            check(Warp.toHex(Warp.x25519(a, Warp.x25519(b, nine)), 0, 32)
                    .equals("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"), "X25519: общий секрет");
            byte[] fips = new byte[16];
            for (int i = 0; i < 16; i++) fips[i] = (byte) i;
            check(Warp.toHex(Warp.aes128Block(fips, Warp.hex("00112233445566778899aabbccddeeff")), 0, 16)
                    .equals("69c4e0d86a7b0430d8cdb78070b4c55a"), "AES-128: FIPS-197");
            byte[][] qk = Warp.quicKeys(Warp.hex("8394c8f03e515708"));
            check(Warp.toHex(qk[0], 0, 16).equals("1f369613dd76d5467730efcbe3b1a22d") && Warp.toHex(qk[1], 0, 12).equals("fa044b2f42a3fd3b46fb255c")
                    && Warp.toHex(qk[2], 0, 16).equals("9f50449e04a0e810283a1e9933adedd2"), "ключи QUIC: RFC 9001");
            for (int i = 0; i < Warp.PRESETS.length; i++) {
                String i1 = Json.str(Warp.preset(i), "i1");
                check(i1.matches("(<b 0x[0-9a-f]+>|<r \\d+>|<rc \\d+>|<rd \\d+>)+"), "набор " + i + ": формат CPS");
            }
            // имитация Cloudflare: регистрация и включение WARP
            final List<String> calls = new ArrayList<String>();
            final String[] seenKey = {""};
            http.createContext("/warp/", ex -> {
                java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
                byte[] chunk = new byte[4096];
                for (int n; (n = ex.getRequestBody().read(chunk)) > 0; ) bo.write(chunk, 0, n);
                byte[] in = bo.toByteArray();
                String method = ex.getRequestMethod();
                calls.add(method + " " + ex.getRequestURI().getPath() + " " + ex.getRequestHeaders().getFirst("CF-Client-Version")
                        + " " + ex.getRequestHeaders().getFirst("Authorization"));
                if ("POST".equals(method)) seenKey[0] = Json.str(Json.parseObject(new String(in, StandardCharsets.UTF_8)), "key");
                byte[] out = ("POST".equals(method) ? Json.write(Json.obj("id", "dev1", "token", "tok-SECRET-1", "account", Json.obj("warp_enabled", false),
                        "config", Json.obj("peers", Json.arr(Json.obj("public_key", Warp.PEER_KEY)),
                                "interface", Json.obj("addresses", Json.obj("v4", "172.16.0.2", "v6", "2606:4700:110:8a36::1")))))
                        : "{\"warp_enabled\":true}").getBytes(StandardCharsets.UTF_8);
                ex.sendResponseHeaders(200, out.length);
                try (OutputStream o = ex.getResponseBody()) { o.write(out); }
            });
            Engine.WARP_BASES = new String[]{"http://127.0.0.1:" + httpPort() + "/warp"};
            try {
                Map<String, Object> acct = Warp.register(Engine.WARP_BASES[0], 0, "Android", null);
                check(calls.size() == 2 && calls.get(0).startsWith("POST /warp/" + Warp.API_VERSION + "/reg " + Warp.CLIENT_VERSION)
                        && calls.get(1).equals("PATCH /warp/" + Warp.API_VERSION + "/reg/dev1 " + Warp.CLIENT_VERSION + " Bearer tok-SECRET-1"),
                        "запросы к Cloudflare: " + calls);
                check(seenKey[0].equals(Warp.publicOf(Json.str(acct, "private_key"))) && !acct.containsKey("token"),
                        "Cloudflare получает только открытый ключ, метка доступа не хранится");
                Fake fw = new Fake(tmpDir());
                Engine ew = engine(fw);
                check(Json.str(ew.state(), "warp").isEmpty(), "своего WARP ещё нет");
                check(Boolean.TRUE.equals(Api.call(ew, "warp_create", Json.obj())), "кнопка «Создать бесплатный WARP»");
                waitIdle(ew);
                String key = Json.str(ew.state(), "warp");
                Map<String, Object> info = ew.awgInfo(key);
                check(!key.isEmpty() && Warp.NAME.equals(Json.str(info, "name")) && Json.bool(info, "warp", false)
                        && Warp.isWarp(Json.str(info, "conf")) && "awg".equals(ew.method()), "WARP создан, способ — AmneziaWG");
                String before = Warp.currentParams(Json.str(info, "conf")).toString();
                @SuppressWarnings("unchecked")
                Map<String, Object> next = (Map<String, Object>) Api.call(ew, "warp_next", Json.obj("key", key));
                String conf2 = Json.str(next, "conf");
                java.util.regex.Matcher pk = java.util.regex.Pattern.compile("PrivateKey = \\S+").matcher(Json.str(info, "conf"));
                check(pk.find() && conf2.contains(pk.group()) && !Warp.currentParams(conf2).toString().equals(before)
                        && Json.str(Warp.currentParams(conf2), "endpoint").equals(Warp.PRESETS[1][0]),
                        "другие обманки (ключ тот же): " + Json.str(next, "label"));
                check(Json.str(ew.state(), "warp").equals(Json.str(next, "key")) && Json.num(ew.settings, "warp_preset", 0) == 1,
                        "новый набор сохранён вместо старого");
                Api.call(ew, "warp_create", Json.obj());
                waitIdle(ew);
                int own = 0;
                for (Object o : Json.list(ew.state(), "servers")) if (Warp.NAME.equals(Json.str(Json.map(o), "name"))) own++;
                check(own == 1, "новый WARP заменяет прошлый: " + own);
                String logs = String.join("\n", ew.logLines());
                check(!logs.contains("tok-SECRET-1") && !logs.contains("PrivateKey"), "ключи не попадают в журнал");
                ew.shutdown();
            } finally {
                Engine.WARP_BASES = null;
            }
        });

        test("WARP во встроенном ядре: шум вместо обманок, запасной путь «Авто», WARP после VPN, QR-код", () -> {
            final int[] cnt = {0};
            Warp.Rnd rnd = n -> cnt[0]++ % n;
            byte[] cb = Warp.cpsBytes("<b 0x0102ff><r 2><rc 3><rd 2><t><c><n>", rnd, 0x01020304L);
            check(Warp.toHex(cb, 0, cb.length).equals("0102ff" + "0001" + "636465" + "3536" + "01020304" + "00000001" + "0708090a0b0c0d0e"),
                    "CPS → байты: " + Warp.toHex(cb, 0, cb.length));
            for (String bad : new String[]{"<b 0x01> мусор", "<r 99999>", "<b 0xZZ>", "текст<b 0x01>", "<r 5-2>"}) {
                boolean threw = false;
                try {
                    Warp.cpsBytes(bad, Warp.SECURE, 0);
                } catch (IllegalArgumentException ex) {
                    threw = true;
                }
                check(threw, "плохая запись CPS не принята: " + bad);
            }
            String priv = Warp.keypair(null)[0];
            Map<String, Object> acct = Json.obj("private_key", priv, "peer", Warp.PEER_KEY, "v4", "172.16.0.2", "v6", "2606:4700:110:8a36::1");
            String conf = Warp.buildConf(acct, Warp.preset(0));
            Map<String, Object> ob = Warp.xrayOutbound(conf, "proxy", true, Warp.SECURE);
            List<Object> noise = Json.list(Json.map(Json.map(Json.list(Json.map(Json.map(ob, "streamSettings"), "finalmask"), "udp").get(0)), "settings"), "noise");
            check("wireguard".equals(Json.str(ob, "protocol")) && Json.str(Json.map(noise.get(0)), "packet").length() == Warp.QUIC_SIZE * 2
                    && noise.size() >= 5 && Json.str(Json.map(noise.get(1)), "rand").matches("\\d+-\\d+"),
                    "outbound WireGuard с шумом: пакет-обманка и мусорные пакеты");
            check(!Warp.xrayOutbound(conf, "warp", false, Warp.SECURE).containsKey("streamSettings"), "без шума — без Finalmask");
            String sc = Warp.shareConf(conf);
            check(sc.length() < 1000 && sc.contains("PrivateKey = " + priv) && sc.contains(Warp.DNS_YANDEX_I1), "конфиг для QR — короткий");

            Fake fw = new Fake(tmpDir());
            Engine ew = engine(fw);
            ew.settings.put("warp_fallback", true);
            ew.settings.put("autopilot", true);
            ew.addServers(link("deadone1.example.com", "Раз") + "\n" + link("deadtwo1.example.com", "Два") + "\n" + Links.awgLink(conf, Warp.NAME));
            waitIdle(ew);
            check(ew.ownWarp() != null && Json.bool(Json.map(ew.state(), "warp_auto"), "own", false), "свой WARP найден");
            final List<String> probes = Collections.synchronizedList(new ArrayList<String>());
            Engine.WARP_PROBE = s -> {
                String ep = Json.str(Json.map(Json.list(Json.map(s.outbound, "settings"), "peers").get(0)), "endpoint");
                probes.add(ep);
                return ep.equals(Warp.PRESETS[2][0]);
            };
            try {
                ew.connect();
                waitIdle(ew);
                check(ew.isOn(), "подключено");
                fw.dead.addAll(Arrays.asList("deadone1.example.com", "deadtwo1.example.com"));
                ew.settings.put("selected", "");
                ew.ladderRetry();
                waitIdle(ew);
                check(ew.isOn() && ew.isWarpFallback() && "WARP".equals(currentName(ew)), "серверы не работают → запасной WARP: " + currentName(ew));
                check(probes.size() >= 2 && probes.get(probes.size() - 1).equals(Warp.PRESETS[2][0]), "обманки перебирались: " + probes);
                check(fw.lastConfig.contains("\"wireguard\"") && fw.lastConfig.contains("\"noise\""), "ядро: WireGuard с шумом");
                check(Json.write(ew.state().get("problems")).contains("пока через WARP"), "в окне — «пока через WARP»");
                check(Json.bool(Json.map(ew.state(), "warp_auto"), "fallback", false), "окно видит запасной WARP");
                // сервер ожил — программа сама уходит с WARP
                ew.warpReviveNow();
                waitIdle(ew);
                check(ew.isWarpFallback(), "серверы всё ещё мёртвые — остаёмся на WARP");
                fw.dead.remove("deadtwo1.example.com");
                ew.warpReviveNow();
                waitIdle(ew);
                check(ew.isOn() && "Два".equals(currentName(ew)) && !ew.isWarpFallback()
                        && !Json.write(ew.state().get("problems")).contains("пока через WARP"), "сервер ожил — вернулись: " + currentName(ew));
                // «WARP после VPN»
                ew.setServiceRoute("ChatGPT", "warp");
                ew.routeSite("chatgpt-test.example", "warp", false);
                waitIdle(ew);
                Map<String, Object> cfg = Json.parseObject(fw.lastConfig);
                Map<String, Object> wob = null;
                for (Object o : Json.list(cfg, "outbounds")) if ("warp".equals(Json.str(Json.map(o), "tag"))) wob = Json.map(o);
                check(wob != null && "wireguard".equals(Json.str(wob, "protocol"))
                        && "proxy".equals(Json.str(Json.map(Json.map(wob, "streamSettings"), "sockopt"), "dialerProxy")), "WARP идёт через VPN");
                check(Json.write(Json.map(cfg, "routing")).contains("\"outboundTag\":\"warp\""), "правило: сайт → WARP");
                // QR-код для другого устройства
                String text = (String) Api.call(ew, "warp_share", Json.obj());
                check(text.contains("PrivateKey = " + priv) && Json.str(Warp.currentParams(text), "endpoint").equals(Warp.PRESETS[2][0])
                        && text.length() < 1800, "QR: с обманками, которые работают в этой сети");
                // своего WARP нет — маршрут не ставится; запасной выключен — честное «ничего не работает»
                ew.removeServer(ew.ownWarp().key());
                boolean threw = false;
                try {
                    ew.setServiceRoute("ChatGPT", "warp");
                } catch (Engine.UserError ex) {
                    threw = true;
                }
                check(threw, "без своего WARP маршрут не ставится");
                ew.settings.put("warp_fallback", false);
                fw.dead.add("deadtwo1.example.com");
                ew.ladderRetry();
                waitIdle(ew);
                check(!ew.isWarpFallback(), "запасной WARP выключен — без него");
                String logs = String.join("\n", ew.logLines());
                check(!logs.contains(priv) && !logs.contains("PrivateKey"), "ключ WARP не попадает в журнал");
                ew.shutdown();
            } finally {
                Engine.WARP_PROBE = null;
            }
        });

        test("Семья: приглашение, «Разрешить», посылка, «Установить», ответ со снимком, защита", () -> {
            Engine h = engine(new Fake(tmpDir()));
            Engine d = engine(new Fake(tmpDir()));
            d.addServers(link("mama.example.com", "Мамин"));
            waitIdle(d);
            boolean threw = false;
            try { h.familyInvite("Мама"); } catch (Family.FamilyError ex) { threw = true; }
            check(threw, "без имени помощника приглашение не делается");
            Api.call(h, "family_me", Json.obj("name", "Сын"));
            @SuppressWarnings("unchecked")
            Map<String, Object> inv = (Map<String, Object>) Api.call(h, "family_invite", Json.obj("device", "Мама — телефон"));
            String pair = Json.str(inv, "pair");
            @SuppressWarnings("unchecked")
            Map<String, Object> got = (Map<String, Object>) Api.call(d, "family_receive", Json.obj("text", "Привет! " + Json.str(inv, "text")));
            check("invite".equals(Json.str(got, "kind")) && "Сын".equals(Json.str(got, "helper")), "приглашение: " + got);
            @SuppressWarnings("unchecked")
            Map<String, Object> acc = (Map<String, Object>) Api.call(d, "family_accept", Json.obj("text", Json.str(inv, "text"), "mode", "ask"));
            check(!Json.write(Json.map(d.state(), "family")).contains("secret"), "секретов в окне нет");
            Api.call(h, "family_receive", Json.obj("text", Json.str(acc, "reply")));
            Map<String, Object> dev = Json.map(Json.list(Json.map(h.state(), "family"), "devices").get(0));
            Map<String, Object> snap = Json.map(dev, "snap");
            check(snap != null && "android".equals(Json.str(snap, "app")) && Json.str(dev, "invite").isEmpty(), "снимок маминого телефона");
            String manualId = Json.str(Json.map(Json.list(snap, "manual").get(0)), "id");
            subBody = Text.b64encode(link("fam1.example.com", "Семейный").getBytes(StandardCharsets.UTF_8));
            String sub = "http://127.0.0.1:" + httpPort() + "/sub";
            @SuppressWarnings("unchecked")
            Map<String, Object> sent = (Map<String, Object>) Api.call(h, "family_send", Json.obj("pair", pair, "ops", Json.arr(
                    Json.obj("op", "sub_add", "url", sub, "name", "Новая"), Json.obj("op", "server_remove", "id", manualId),
                    Json.obj("op", "set", "values", Json.obj("dns_encrypted", true)))));
            String pkt = Json.str(sent, "text");
            check(!pkt.contains("127.0.0.1") && !pkt.contains("Новая"), "посылка зашифрована");
            @SuppressWarnings("unchecked")
            Map<String, Object> rc = (Map<String, Object>) Api.call(d, "family_receive", Json.obj("text", pkt));
            check("packet".equals(Json.str(rc, "kind")) && !Json.bool(rc, "auto", true) && Json.list(rc, "summary").size() == 3, "«Установить?»: " + rc);
            @SuppressWarnings("unchecked")
            Map<String, Object> again = (Map<String, Object>) Api.call(d, "family_receive", Json.obj("text", pkt));
            check("old".equals(Json.str(again, "kind")), "повтор не применяется");
            Api.call(d, "family_apply", Json.obj("pair", pair));
            waitIdle(d);
            boolean hasSub = false, hasMama = false;
            for (Object o : Json.list(d.settings, "subscriptions")) hasSub |= sub.equals(Json.str(Json.map(o), "url"));
            for (Object o : Json.list(d.state(), "servers")) hasMama |= "Мамин".equals(Json.str(Json.map(o), "name"));
            check(hasSub && !hasMama && Json.bool(d.settings, "dns_encrypted", false), "изменения применились");
            String reply = Json.str(Json.map(Json.list(Json.map(d.state(), "family"), "helpers").get(0)), "reply");
            Api.call(h, "family_receive", Json.obj("text", reply));
            dev = Json.map(Json.list(Json.map(h.state(), "family"), "devices").get(0));
            List<Object> sl = Json.list(dev, "sent");
            check("applied".equals(Json.str(Json.map(sl.get(sl.size() - 1)), "state")), "у сына: установлено " + sl);
            // подделка: один байт посылки
            String forged = Json.str((Map<String, Object>) Api.call(h, "family_send", Json.obj("pair", pair, "ops", Json.arr(Json.obj("op", "reconnect")))), "text");
            char[] cs = forged.toCharArray();
            int at = cs.length - 50;
            cs[at] = cs[at] == 'A' ? 'B' : 'A';
            threw = false;
            try { d.familyReceive(new String(cs)); } catch (Family.FamilyError ex) { threw = ex.getMessage().contains("подписи"); }
            check(threw, "испорченная посылка не принимается");
            // «применять сразу»
            Api.call(d, "family_mode", Json.obj("pair", pair, "mode", "auto"));
            Map<String, Object> s2 = (Map<String, Object>) Api.call(h, "family_send", Json.obj("pair", pair, "ops", Json.arr(Json.obj("op", "set", "values", Json.obj("dns_encrypted", false)))));
            Map<String, Object> r2 = (Map<String, Object>) Api.call(d, "family_receive", Json.obj("text", Json.str(s2, "text")));
            check(Json.bool(r2, "auto", false), "режим «сразу»");
            waitIdle(d);
            check(!Json.bool(d.settings, "dns_encrypted", true), "применилось само");
            String logs = String.join("\n", h.logLines()) + String.join("\n", d.logLines());
            check(!logs.contains("vedomyj-family://") && !logs.contains("127.0.0.1:" + httpPort() + "/sub"), "журналы чистые");
            // поделились текстом из мессенджера: «+» узнаёт посылку «Семьи»
            check("family".equals(Json.str(d.importPreview("Мама, вот: " + pkt), "kind")), "«+» узнаёт посылку");
            Api.call(d, "family_remove", Json.obj("pair", pair));
            threw = false;
            try { d.familyReceive(Json.str((Map<String, Object>) Api.call(h, "family_send", Json.obj("pair", pair, "ops", Json.arr(Json.obj("op", "reconnect")))), "text")); }
            catch (Family.FamilyError ex) { threw = true; }
            check(threw, "после «Отключить» посылки не принимаются");
            h.shutdown();
            d.shutdown();
        });

        e.shutdown();
        http.stop(0);
        System.out.println();
        System.out.println("Пройдено " + passed + " из " + (passed + failed) + ".");
        System.exit(failed == 0 ? 0 : 1);
    }
}
