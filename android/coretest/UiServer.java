import com.pultvpn.app.core.*;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;

/**
 * Проверка интерфейса Android-версии в обычном браузере: страница из assets/ui + настоящий движок (Engine)
 * на имитации телефона. window.Pult в браузере подменяется синхронным запросом к /call.
 * Запуск: java UiServer <папка assets/ui> <порт>
 */
public class UiServer {
    static Engine engine;
    static CoreTest.Fake fake;
    static String subBody = "";

    public static void main(String[] a) throws Exception {
        final File ui = new File(a[0]);
        int port = Integer.parseInt(a[1]);
        Text.lang = "ru";
        File dir = Files.createTempDirectory("pult-ui-").toFile();
        CoreTest.CertFake cf = new CoreTest.CertFake(dir);
        cf.user = Arrays.asList(CoreTest.testCertDer()); // на «телефоне» стоит сертификат Минцифры — для экрана проверки
        fake = cf;
        Certs.FETCH = CoreTest.CLEAN_CERTS; // контрольные сайты — без настоящей сети
        Engine.WHAT_WORKS = new String[][]{{"Google", "http://127.0.0.1:1/"}, {"YouTube", "http://127.0.0.1:1/"},
                {"Яндекс", "http://127.0.0.1:" + port + "/sub"}, {"VK", "http://127.0.0.1:" + port + "/sub"}};
        fake.dead.add("dead1.example.com");
        fake.appProxy = true;
        fake.device.put("battery_restricted", true);
        // «замирание» в проверке программы — без настоящей сети, чтобы проход по экранам не зависел от интернета
        Engine.STALL = (h, p) -> Json.obj("state", "ok", "bytes", 65536L, "ms", 120L);
        engine = new Engine(fake);
        engine.famDhtAuto = false; // «Семья» через сеть торрентов — без настоящей сети
        engine.settings.put("geo_updated", System.currentTimeMillis());
        engine.start();
        HttpServer http = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        StringBuilder b = new StringBuilder();
        String[][] names = {{"nl1", "🇳🇱 Нидерланды"}, {"fast1", "🇩🇪 Германия · Франкфурт"}, {"mid1", "🇫🇮 Финляндия"},
                {"slow1", "🇺🇸 США · Нью-Йорк"}, {"dead1", "🇬🇧 Великобритания"}, {"maskonly1", "🇵🇱 Польша"},
                {"wl1", "🇷🇺 Белые списки · Москва"}};
        for (String[] n : names) {
            b.append(CoreTest.link(n[0] + ".example.com", n[1])).append('\n');
        }
        b.append("vless://11111111-2222-3333-4444-555555555555@0.0.0.0:1#Подписка до 01.12.2026\n");
        subBody = Text.b64encode(b.toString().getBytes(StandardCharsets.UTF_8));
        http.createContext("/sub", ex -> {
            ex.getResponseHeaders().add("subscription-userinfo", "upload=104857600; download=5368709120; total=107374182400; expire=1796083200");
            ex.getResponseHeaders().add("profile-title", "base64:" + Text.b64encode("Мой VPN".getBytes(StandardCharsets.UTF_8)));
            byte[] body = subBody.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, body.length);
            try (OutputStream o = ex.getResponseBody()) { o.write(body); }
        });
        http.createContext("/ui/", ex -> {
            String path = ex.getRequestURI().getPath().substring(4);
            File f = new File(ui, path.isEmpty() ? "index.html" : path);
            if (!f.getCanonicalPath().startsWith(ui.getCanonicalPath()) || !f.isFile()) {
                ex.sendResponseHeaders(404, -1);
                ex.close();
                return;
            }
            String type = path.endsWith(".js") ? "text/javascript" : path.endsWith(".css") ? "text/css"
                    : path.endsWith(".svg") ? "image/svg+xml" : "text/html";
            byte[] body = Files.readAllBytes(f.toPath());
            if (path.endsWith(".html")) {
                // в проверке страница ходит к движку запросами — разрешаем их и подключаем подмену window.Pult
                String html = new String(body, StandardCharsets.UTF_8).replace("connect-src 'none'", "connect-src 'self'")
                        .replace("<script src=\"i18n.js\"></script>", "<script src=\"bridge.js\"></script><script src=\"i18n.js\"></script>");
                body = html.getBytes(StandardCharsets.UTF_8);
            }
            ex.getResponseHeaders().add("Content-Type", type + "; charset=utf-8");
            ex.sendResponseHeaders(200, body.length);
            try (OutputStream o = ex.getResponseBody()) { o.write(body); }
        });
        http.createContext("/ui/bridge.js", ex -> {
            byte[] body = ("window.Pult={call:function(a,args){var x=new XMLHttpRequest();x.open('POST','/call',false);"
                    + "x.send(JSON.stringify({action:a,args:args}));return x.responseText;}};").getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "text/javascript");
            ex.sendResponseHeaders(200, body.length);
            try (OutputStream o = ex.getResponseBody()) { o.write(body); }
        });
        http.createContext("/call", ex -> {
            InputStream in = ex.getRequestBody();
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] tmp = new byte[8192];
            int n;
            while ((n = in.read(tmp)) > 0) buf.write(tmp, 0, n);
            Map<String, Object> req = Json.parseObject(new String(buf.toByteArray(), StandardCharsets.UTF_8));
            String out;
            try {
                String args = Json.str(req, "args");
                Map<String, Object> am = args.isEmpty() ? Json.obj() : Json.parseObject(args);
                out = Json.write(Json.obj("ok", true, "result", dispatch(Json.str(req, "action"), am)));
            } catch (Exception e) {
                engine.recordBug(e, "действие: " + Json.str(req, "action"));
                out = Json.write(Json.obj("ok", false, "error", e.getMessage() == null ? e.toString() : e.getMessage()));
            }
            byte[] body = out.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
            ex.sendResponseHeaders(200, body.length);
            try (OutputStream o = ex.getResponseBody()) { o.write(body); }
        });
        // сайты для «Проверки программы» — свои, интернета в проверке нет
        for (String[] r : new String[][]{{"/site-ok", "204"}, {"/site-region", "451"}, {"/ru", "200"}, {"/foreign", "204"}}) {
            final int code = Integer.parseInt(r[1]);
            http.createContext(r[0], ex -> {
                ex.sendResponseHeaders(code, -1);
                ex.close();
            });
        }
        String base = "http://127.0.0.1:" + port;
        Engine.WL_ALLOWED = new String[]{base + "/ru"};
        Engine.WL_FOREIGN = new String[]{base + "/foreign"};
        Diagnostics.SITES = new String[][]{{"YouTube", base + "/site-ok"}, {"ChatGPT", base + "/site-region"}};
        Dpi.CHECKS = new LinkedHashMap<String, String[][]>();
        Dpi.CHECKS.put("youtube", new String[][]{{base + "/big", "300000"}, {base + "/site-ok", "1"}});
        Dpi.CHECKS.put("discord", new String[][]{{base + "/site-ok", "1"}});
        Proxies.TRACE_URL = base + "/trace";
        Proxies.TIKTOK_URL = base + "/site-region";
        AdBlock.URLS = (id, level) -> Arrays.asList(base + "/ads/" + id);
        fake.dpiWorks.add("tls_10");
        Engine.SPEED_URLS = new String[]{base + "/big"};
        Engine.DATA_URL = base + "/big"; // «идут ли данные» — первые 64 КБ
        http.createContext("/big", ex -> {
            byte[] big = new byte[300 * 1024];
            Arrays.fill(big, (byte) 'x');
            ex.sendResponseHeaders(200, big.length);
            try (OutputStream o = ex.getResponseBody()) { o.write(big); }
        });
        http.createContext("/trace", ex -> {
            byte[] tr = "ip=203.0.113.77\nloc=US\n".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, tr.length);
            try (OutputStream o = ex.getResponseBody()) { o.write(tr); }
        });
        http.createContext("/ads/", ex -> {
            String name = ex.getRequestURI().getPath().substring(5);
            StringBuilder lst = new StringBuilder();
            for (int i = 0; i < 120; i++) lst.append(name.equals("ru") ? "||ru" + i + ".adnet.example^\n" : name + i + ".ads.example\n");
            byte[] out = lst.toString().getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, out.length);
            try (OutputStream o = ex.getResponseBody()) { o.write(out); }
        });
        Engine.PORTS = (ip, p2, timeout, err) -> true;
        http.createContext("/test/", ex -> {
            // управление имитацией из проверки: /test/hotspot?ip=…, /test/dead?host=…
            String q = ex.getRequestURI().getQuery() == null ? "" : ex.getRequestURI().getQuery();
            String p = ex.getRequestURI().getPath();
            if (p.endsWith("/hotspot")) fake.hotspot = q.replace("ip=", "");
            if (p.endsWith("/dead")) fake.dead.add(q.replace("host=", ""));
            if (p.endsWith("/suburl")) {
                byte[] body = ("http://127.0.0.1:" + port + "/sub").getBytes(StandardCharsets.UTF_8);
                ex.sendResponseHeaders(200, body.length);
                try (OutputStream o = ex.getResponseBody()) { o.write(body); }
                return;
            }
            ex.sendResponseHeaders(204, -1);
            ex.close();
        });
        // как на телефоне: вызовы из окна и запросы самого движка (подписка, проверки) идут параллельно — иначе
        // запрос движка к этому же серверу ждал бы конца вызова, который ждёт движок
        http.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
        http.start();
        System.out.println("ready " + port);
    }

    static final String QR = "data:image/svg+xml;base64," + Text.b64encode(("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 21 21'>"
            + "<rect width='21' height='21' fill='#fff'/><path d='M1 1h7v7H1zM13 1h7v7h-7zM1 13h7v7H1zM10 10h2v2h-2zM14 14h3v3h-3z'/></svg>")
            .getBytes(StandardCharsets.UTF_8));

    static Object dispatch(String action, Map<String, Object> a) throws Exception {
        Engine e = engine;
        switch (action) {
            case "test_nothing": e.nothingWorks(); return true; // только для проверки: «ничего не работает»
            case "state": return e.state();
            case "log": return e.logLines();
            case "report": return e.report();
            case "check": return e.runCheck();
            case "check_text": return e.checkText();
            case "connect": e.connect(); return true;
            case "disconnect": e.disconnect(); return true;
            case "stop_task": e.stopTask(); return true;
            case "add_sub": return e.addSubscription(Json.str(a, "url"), Json.str(a, "name"));
            case "remove_sub": e.removeSubscription(Json.str(a, "id")); return true;
            case "refresh_subs": e.refreshSubscriptions(true); return true;
            case "add_servers": return e.addServers(Json.str(a, "text"));
            case "remove_server": e.removeServer(Json.str(a, "key")); return true;
            case "test": e.testServersTask(); return true;
            case "select": e.select(Json.str(a, "key")); return true;
            case "settings": e.setSettings(Json.map(a, "values")); return true;
            case "export": return e.exportSettings(Json.bool(a, "subs", false), Json.bool(a, "servers", false));
            case "import_preview": return e.importPreview(Json.str(a, "text"));
            case "import_apply": return e.importApply(Json.str(a, "text"));
            case "server_link": return e.find(Json.str(a, "key")).link;
            case "sub_link": return "https://sub.example.com/abc";
            case "qr": return QR;
            case "copy": return true;
            case "paste": return "";
            case "apps": return Json.arr(Json.obj("pkg", "ru.sberbankmobile", "name", "СберБанк"),
                    Json.obj("pkg", "com.vkontakte.android", "name", "ВКонтакте"), Json.obj("pkg", "org.telegram.messenger", "name", "Telegram"));
            case "hotspot_local": fake.hotspot = "192.168.49.1"; e.setShare(true, "local", "DIRECT-Pult-7x", "k3h9a2pq"); return true;
            case "hotspot_system": e.setShare(true, "system", "", ""); return true;
            case "hotspot_settings": return true;
            case "hotspot_stop": e.setShare(false, "", "", ""); return true;
            case "share_new_pass": e.newSharePassword(); return true;
            case "vps": e.vpsSetup(Json.str(a, "host"), Json.str(a, "port"), Json.str(a, "user"), Json.str(a, "password"), Json.str(a, "name")); return true;
            case "vps_bridge": e.vpsBridge(Json.str(a, "host"), Json.str(a, "port"), Json.str(a, "user"), Json.str(a, "password"), Json.str(a, "via"), Json.str(a, "name")); return true;
            case "vps_add": e.vpsAdd(Json.str(a, "host"), Json.str(a, "port"), Json.str(a, "user"), Json.str(a, "password"), Json.str(a, "name")); return true;
            case "vps_status": e.vpsStatus(Json.str(a, "id"), Json.str(a, "password")); return true;
            case "vps_friend_add": e.vpsFriendAdd(Json.str(a, "id"), Json.str(a, "password"), Json.str(a, "name")); return true;
            case "vps_friend_remove": e.vpsFriendRemove(Json.str(a, "id"), Json.str(a, "password"), Json.str(a, "friend")); return true;
            case "vps_forget": e.vpsForget(Json.str(a, "id")); return true;
            case "vps_friend_link": return e.vpsFriendLink(Json.str(a, "friend"));
            case "theme": case "scan": case "pick_file": case "save_file": case "share_text": case "share_report": case "vpn_settings": case "open_url":
                return true;
            case "filter_start": return e.filterStart();
            case "awg_open": return "store";
            default: {
                Object r = Api.call(e, action, a);
                if (r == Api.UNKNOWN) throw new Engine.UserError("unknown action: " + action);
                return r;
            }
        }
    }
}
