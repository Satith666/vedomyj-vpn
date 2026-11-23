package com.pultvpn.app.phone;

import android.Manifest;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.Color;
import android.graphics.Insets;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.view.View;
import android.view.Window;
import android.view.WindowInsets;
import android.view.WindowInsetsController;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;

import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;
import com.pultvpn.app.core.Api;
import com.pultvpn.app.core.Engine;
import com.pultvpn.app.core.Json;
import com.pultvpn.app.core.Text;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * Окно приложения: интерфейс — страница из assets/ui (как в программе для Windows), связь с движком —
 * через объект window.Pult. Страница загружается только из приложения, чужие сайты в окне не открываются.
 */
public final class MainActivity extends Activity {
    static final String EXTRA_CONNECT = "connect";
    static final int REQ_VPN = 1;
    static final int REQ_FILE = 2;
    static final int REQ_SAVE = 3;
    static final int REQ_HOTSPOT = 4;
    static final int REQ_NOTIFY = 5;
    static final int REQ_FILTER = 6;
    static final int REQ_UNLOCK = 7;
    static final long RELOCK_MS = 60000; // свернули больше чем на минуту — снова спросить

    // блокировка приложения экраном блокировки телефона (пин, графический ключ, отпечаток)
    private boolean unlocked;
    private boolean unlocking;
    private long stoppedAt;

    private WebView web;
    private FrameLayout root;
    private boolean pageReady;
    private String pendingIncoming;
    private String pendingSave;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        Window w = getWindow();
        // окно на весь экран; отступы под строку состояния и кнопки задаёт onApplyWindowInsets
        if (Build.VERSION.SDK_INT >= 30) {
            w.setDecorFitsSystemWindows(false);
        } else {
            w.getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                    | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION);
        }
        w.setStatusBarColor(Color.TRANSPARENT);
        w.setNavigationBarColor(Color.TRANSPARENT);

        root = new FrameLayout(this);
        root.setBackgroundColor(Color.parseColor("#0C1220"));
        web = new WebView(this);
        web.setBackgroundColor(Color.TRANSPARENT);
        root.addView(web, new FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT));
        root.setOnApplyWindowInsetsListener(new View.OnApplyWindowInsetsListener() {
            @SuppressWarnings("deprecation")
            @Override
            public WindowInsets onApplyWindowInsets(View v, WindowInsets insets) {
                if (Build.VERSION.SDK_INT >= 30) {
                    Insets i = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.ime()
                            | WindowInsets.Type.displayCutout());
                    v.setPadding(i.left, i.top, i.right, i.bottom);
                    return WindowInsets.CONSUMED;
                }
                v.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(),
                        insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
                return insets.consumeSystemWindowInsets();
            }
        });
        setContentView(root);

        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setAllowContentAccess(false);
        s.setAllowFileAccess(false); // file:///android_asset/ открывается и так
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        s.setTextZoom(100);
        web.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest req) {
                Uri u = req.getUrl();
                if ("file".equals(u.getScheme()) && u.getPath() != null && u.getPath().startsWith("/android_asset/ui/")) {
                    return false;
                }
                openExternal(u);
                return true;
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                pageReady = true;
                flushIncoming();
            }
        });
        web.addJavascriptInterface(new Bridge(), "Pult");
        web.loadUrl("file:///android_asset/ui/index.html");
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    /** Ссылка или текст, присланные из другого приложения («Поделиться» → VEDOMYJ VPN), и кнопка в шторке. */
    private String pendingPage;

    private void handleIntent(Intent intent) {
        if (intent == null) {
            return;
        }
        if (intent.getBooleanExtra(EXTRA_CONNECT, false)) {
            intent.removeExtra(EXTRA_CONNECT);
            connect();
            return;
        }
        String page = intent.getStringExtra("page");
        if (page != null && page.matches("[a-z_]{1,20}")) { // из уведомления: сразу нужный раздел
            intent.removeExtra("page");
            pendingPage = page;
            flushIncoming();
            return;
        }
        String text = null;
        if (Intent.ACTION_SEND.equals(intent.getAction())) {
            text = intent.getStringExtra(Intent.EXTRA_TEXT);
        } else if (Intent.ACTION_VIEW.equals(intent.getAction()) && intent.getData() != null) {
            text = intent.getData().toString();
        }
        if (text != null && !text.trim().isEmpty()) {
            pendingIncoming = text.trim();
            intent.setAction(Intent.ACTION_MAIN);
            flushIncoming();
        }
    }

    private void flushIncoming() {
        if (pageReady && pendingIncoming != null) {
            emit(Json.obj("type", "incoming", "text", pendingIncoming));
            pendingIncoming = null;
        }
        if (pageReady && pendingPage != null) {
            emit(Json.obj("type", "open_page", "page", pendingPage));
            pendingPage = null;
        }
    }

    /** Событие для страницы интерфейса. */
    void emit(final Map<String, Object> event) {
        final String js = "window.pultEvent && window.pultEvent(" + Json.write(event) + ")";
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                if (web != null) {
                    web.evaluateJavascript(js, null);
                }
            }
        });
    }

    /** Открыть нужный экран настроек Android; если прошивка его не знает — экран приложения. */
    private void openFix(String what) {
        Uri pkg = Uri.parse("package:" + getPackageName());
        java.util.List<Intent> tries = new java.util.ArrayList<Intent>();
        if ("battery".equals(what)) {
            tries.add(new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, pkg));
            tries.add(new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS));
        } else if ("notifications".equals(what)) {
            Intent n = new Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS);
            n.putExtra(Settings.EXTRA_APP_PACKAGE, getPackageName());
            tries.add(n);
        } else if ("data_saver".equals(what)) {
            tries.add(new Intent(Settings.ACTION_IGNORE_BACKGROUND_DATA_RESTRICTIONS_SETTINGS, pkg));
        } else if ("vpn".equals(what)) {
            tries.add(new Intent(Settings.ACTION_VPN_SETTINGS));
        } else if ("private_dns".equals(what)) {
            tries.add(new Intent("android.settings.PRIVATE_DNS_SETTINGS")); // есть не на всех прошивках
            tries.add(new Intent(Settings.ACTION_WIRELESS_SETTINGS));
        }
        tries.add(new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, pkg));
        for (Intent i : tries) {
            try {
                startActivity(i);
                return;
            } catch (RuntimeException ignored) {
                // этого экрана нет на этой прошивке — пробуем следующий
            }
        }
    }

    static final String AWG_PACKAGE = "org.amnezia.awg";

    private void openExternal(Uri u) {
        if (!"https".equals(u.getScheme()) && !"http".equals(u.getScheme())) {
            return;
        }
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, u));
        } catch (ActivityNotFoundException ignored) {
            // нет браузера
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    public void onBackPressed() {
        web.evaluateJavascript("window.pultBack ? window.pultBack() : false", new android.webkit.ValueCallback<String>() {
            @Override
            public void onReceiveValue(String value) {
                if (!"true".equals(value)) {
                    moveTaskToBack(true); // VPN продолжает работать
                }
            }
        });
    }

    @Override
    protected void onDestroy() {
        if (web != null) {
            web.removeJavascriptInterface("Pult");
            web.destroy();
            web = null;
        }
        super.onDestroy();
    }

    // ---------- подключение ----------

    @SuppressWarnings("deprecation")
    private void connect() {
        Intent prep = VpnService.prepare(this);
        if (prep != null) {
            try {
                startActivityForResult(prep, REQ_VPN);
            } catch (ActivityNotFoundException e) {
                emit(Json.obj("type", "error", "text", Text.t("Android не дал включить VPN.", "Android did not allow VPN.")));
            }
            return;
        }
        App.engine().markUser();
        App.engine().connect();
        askNotifications();
    }

    private void askNotifications() {
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQ_NOTIFY);
        }
    }

    @Override
    protected void onStart() {
        super.onStart();
        if (stoppedAt > 0 && System.currentTimeMillis() - stoppedAt > RELOCK_MS) {
            unlocked = false;
        }
        askUnlock();
    }

    @Override
    protected void onStop() {
        super.onStop();
        if (!unlocking) {
            stoppedAt = System.currentTimeMillis();
        }
    }

    /** Блокировка приложения включена — показать экран блокировки телефона, а до этого спрятать окно. */
    @SuppressWarnings("deprecation")
    private void askUnlock() {
        if (unlocked || unlocking || App.engine() == null
                || !com.pultvpn.app.core.Json.bool(App.engine().settings, "app_lock", false)) {
            web.setVisibility(View.VISIBLE);
            return;
        }
        android.app.KeyguardManager km = (android.app.KeyguardManager) getSystemService(KEYGUARD_SERVICE);
        if (km == null || !km.isDeviceSecure()) {
            unlocked = true; // на телефоне нет блокировки экрана — защищать нечем
            web.setVisibility(View.VISIBLE);
            return;
        }
        Intent i = km.createConfirmDeviceCredentialIntent("VEDOMYJ VPN",
                Text.t("Подтверди, что это ты", "Confirm it's you"));
        if (i == null) {
            unlocked = true;
            web.setVisibility(View.VISIBLE);
            return;
        }
        web.setVisibility(View.INVISIBLE);
        unlocking = true;
        startActivityForResult(i, REQ_UNLOCK);
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_UNLOCK) {
            unlocking = false;
            if (resultCode == RESULT_OK) {
                unlocked = true;
                stoppedAt = 0;
                web.setVisibility(View.VISIBLE);
            } else {
                finish(); // не подтвердили — окно не открываем (VPN при этом работает)
            }
            return;
        }
        IntentResult scan = IntentIntegrator.parseActivityResult(requestCode, resultCode, data);
        if (scan != null) {
            if (scan.getContents() != null) {
                emit(Json.obj("type", "scan", "text", scan.getContents()));
            }
            return;
        }
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) {
                App.engine().markUser();
                App.engine().connect();
                askNotifications();
            } else {
                emit(Json.obj("type", "error", "text", Text.t(
                        "Без разрешения на VPN подключиться нельзя. Нажми «Подключить» и выбери «ОК».",
                        "Without VPN permission the app can't connect. Tap Connect and choose OK.")));
            }
        } else if (requestCode == REQ_FILTER) {
            if (resultCode == RESULT_OK) {
                App.engine().filterStart();
            } else {
                emit(Json.obj("type", "error", "text", Text.t(
                        "Без разрешения на VPN реклама блокируется только при включённом VPN.",
                        "Without VPN permission ads are blocked only while VPN is on.")));
            }
        } else if (requestCode == REQ_FILE && resultCode == RESULT_OK && data != null && data.getData() != null) {
            try {
                InputStream in = getContentResolver().openInputStream(data.getData());
                if (in == null) {
                    throw new IllegalStateException("no file");
                }
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                byte[] b = new byte[8192];
                int n;
                try {
                    while ((n = in.read(b)) > 0) {
                        buf.write(b, 0, n);
                        if (buf.size() > 4 * 1024 * 1024) {
                            throw new IllegalStateException(Text.t("файл слишком большой", "the file is too large"));
                        }
                    }
                } finally {
                    in.close();
                }
                emit(Json.obj("type", "file", "text", new String(buf.toByteArray(), StandardCharsets.UTF_8)));
            } catch (Exception e) {
                emit(Json.obj("type", "error", "text", Text.t("Не удалось прочитать файл: ", "Could not read the file: ")
                        + e.getMessage()));
            }
        } else if (requestCode == REQ_SAVE && resultCode == RESULT_OK && data != null && data.getData() != null
                && pendingSave != null) {
            try {
                OutputStream out = getContentResolver().openOutputStream(data.getData());
                if (out == null) {
                    throw new IllegalStateException("no file");
                }
                try {
                    out.write(pendingSave.getBytes(StandardCharsets.UTF_8));
                } finally {
                    out.close();
                }
                emit(Json.obj("type", "saved"));
            } catch (Exception e) {
                emit(Json.obj("type", "error", "text", Text.t("Не удалось сохранить файл: ", "Could not save the file: ")
                        + e.getMessage()));
            }
            pendingSave = null;
        }
    }

    // ---------- раздача ----------

    private String[] hotspotPermissions() {
        if (Build.VERSION.SDK_INT >= 33) {
            return new String[]{Manifest.permission.NEARBY_WIFI_DEVICES};
        }
        return new String[]{Manifest.permission.ACCESS_FINE_LOCATION};
    }

    private void startHotspot() {
        for (String p : hotspotPermissions()) {
            if (checkSelfPermission(p) != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(hotspotPermissions(), REQ_HOTSPOT);
                return;
            }
        }
        Hotspot.startLocal(this, new Hotspot.Result() {
            @Override
            public void started(String ssid, String password) {
                App.engine().setShare(true, "local", ssid, password);
                emit(Json.obj("type", "hotspot", "ok", true));
            }

            @Override
            public void failed(String reason) {
                String text;
                if ("incompatible".equals(reason)) {
                    text = Text.t("Этот телефон не умеет одновременно Wi-Fi и свою сеть. Включи обычную точку доступа "
                                    + "в настройках телефона.",
                            "This phone can't run Wi-Fi and its own network at once. Turn on the regular hotspot in settings.");
                } else if ("disallowed".equals(reason)) {
                    text = Text.t("Раздача запрещена на этом телефоне (оператор или администратор).",
                            "Sharing is not allowed on this phone (carrier or administrator).");
                } else {
                    text = Text.t("Не удалось создать сеть Wi-Fi. Проверь, что Wi-Fi и геолокация включены, "
                                    + "или включи обычную точку доступа.",
                            "Could not create the Wi-Fi network. Check that Wi-Fi and location are on, or use the regular hotspot.");
                }
                emit(Json.obj("type", "hotspot", "ok", false, "text", text));
            }

            @Override
            public void stopped() {
                App.engine().setShare(false, "", "", "");
                emit(Json.obj("type", "hotspot", "ok", false, "stopped", true));
            }
        });
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] results) {
        if (requestCode != REQ_HOTSPOT) {
            return;
        }
        boolean ok = results.length > 0;
        for (int r : results) {
            ok &= r == PackageManager.PERMISSION_GRANTED;
        }
        if (ok) {
            startHotspot();
        } else {
            emit(Json.obj("type", "hotspot", "ok", false, "text", Text.t(
                    "Android требует разрешение, чтобы создать сеть Wi-Fi. Можно включить обычную точку доступа.",
                    "Android needs a permission to create a Wi-Fi network. You can use the regular hotspot instead.")));
        }
    }

    // ---------- оформление ----------

    @SuppressWarnings("deprecation")
    private void applyTheme(boolean dark) {
        root.setBackgroundColor(Color.parseColor(dark ? "#0C1220" : "#EDF0F6"));
        Window w = getWindow();
        if (Build.VERSION.SDK_INT >= 30) {
            WindowInsetsController c = w.getInsetsController();
            if (c != null) {
                int mask = WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                        | WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS;
                c.setSystemBarsAppearance(dark ? 0 : mask, mask);
            }
        } else {
            int f = w.getDecorView().getSystemUiVisibility();
            int light = View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
            w.getDecorView().setSystemUiVisibility(dark ? f & ~light : f | light);
        }
    }

    // ---------- мост для страницы интерфейса ----------

    /** Методы, которые вызывает страница (window.Pult.call). Работают в отдельном потоке WebView. */
    final class Bridge {
        @JavascriptInterface
        public String call(String action, String argsJson) {
            try {
                Map<String, Object> a = argsJson == null || argsJson.isEmpty() ? Json.obj() : Json.parseObject(argsJson);
                return Json.write(Json.obj("ok", true, "result", dispatch(action, a)));
            } catch (Engine.UserError e) {
                return Json.write(Json.obj("ok", false, "error", e.getMessage()));
            } catch (Exception e) {
                String m = e.getMessage() == null ? e.toString() : e.getMessage();
                App.engine().recordBug(e, "действие: " + action);
                return Json.write(Json.obj("ok", false, "error", m));
            }
        }
    }

    private void ui(Runnable r) {
        runOnUiThread(r);
    }

    @SuppressWarnings("deprecation")
    Object dispatch(String action, final Map<String, Object> a) throws Exception {
        final Engine e = App.engine();
        if (!"state".equals(action) && !"log".equals(action)) {
            e.markUser(); // действие человека: в журнале подключения будет «ты», а не автоматика
        }
        switch (action) {
            case "state":
                return e.state();
            case "log":
                return e.logLines();
            case "report":
                return e.report();
            case "check":
                return e.runCheck();
            case "check_text":
                return e.checkText();
            case "connect":
                ui(new Runnable() {
                    @Override
                    public void run() {
                        connect();
                    }
                });
                return true;
            case "disconnect":
                e.disconnect();
                return true;
            case "stop_task":
                e.stopTask();
                return true;
            case "add_sub":
                return e.addSubscription(Json.str(a, "url"), Json.str(a, "name"));
            case "remove_sub":
                e.removeSubscription(Json.str(a, "id"));
                return true;
            case "refresh_subs":
                e.refreshSubscriptions(true);
                return true;
            case "add_servers":
                return e.addServers(Json.str(a, "text"));
            case "remove_server":
                e.removeServer(Json.str(a, "key"));
                return true;
            case "test":
                e.testServersTask();
                return true;
            case "select":
                e.select(Json.str(a, "key"));
                return true;
            case "settings": {
                Map<String, Object> s = Json.map(a, "values");
                if (s != null) {
                    e.setSettings(s);
                }
                return true;
            }
            case "export":
                return e.exportSettings(Json.bool(a, "subs", false), Json.bool(a, "servers", false));
            case "import_preview":
                return e.importPreview(Json.str(a, "text"));
            case "import_apply":
                return e.importApply(Json.str(a, "text"));
            case "server_link": {
                com.pultvpn.app.core.Server s = e.find(Json.str(a, "key"));
                if (s == null || s.link.isEmpty()) {
                    throw new Engine.UserError(Text.t("У этого сервера нет ссылки.", "This server has no link."));
                }
                return s.link;
            }
            case "sub_link": {
                for (Object o : Json.list(e.settings, "subscriptions")) {
                    if (Json.str(Json.map(o), "id").equals(Json.str(a, "id"))) {
                        return Json.str(Json.map(o), "url");
                    }
                }
                throw new Engine.UserError(Text.t("Подписка не найдена.", "Subscription not found."));
            }
            case "qr":
                try {
                    return Qr.dataUri(Json.str(a, "text"));
                } catch (IllegalArgumentException ex) {
                    throw new Engine.UserError(Text.t("Слишком длинно для QR-кода — перенеси файлом.",
                            "Too long for a QR code — use a file."));
                }
            case "scan":
                ui(new Runnable() {
                    @Override
                    public void run() {
                        IntentIntegrator ii = new IntentIntegrator(MainActivity.this);
                        ii.setDesiredBarcodeFormats(IntentIntegrator.QR_CODE);
                        ii.setPrompt(Text.t("Наведи камеру на QR-код", "Point the camera at the QR code"));
                        ii.setBeepEnabled(false);
                        ii.setOrientationLocked(false);
                        ii.initiateScan();
                    }
                });
                return true;
            case "pick_file":
                ui(new Runnable() {
                    @Override
                    public void run() {
                        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                        i.addCategory(Intent.CATEGORY_OPENABLE);
                        i.setType("*/*");
                        startActivityForResult(i, REQ_FILE);
                    }
                });
                return true;
            case "save_file":
                pendingSave = Json.str(a, "text");
                ui(new Runnable() {
                    @Override
                    public void run() {
                        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                        i.addCategory(Intent.CATEGORY_OPENABLE);
                        i.setType(Json.str(a, "mime", "application/json"));
                        i.putExtra(Intent.EXTRA_TITLE, Json.str(a, "name", "vedomyj-vpn-settings.json"));
                        startActivityForResult(i, REQ_SAVE);
                    }
                });
                return true;
            case "share_text":
                ui(new Runnable() {
                    @Override
                    public void run() {
                        Intent i = new Intent(Intent.ACTION_SEND);
                        i.setType("text/plain");
                        i.putExtra(Intent.EXTRA_TEXT, Json.str(a, "text"));
                        startActivity(Intent.createChooser(i, "VEDOMYJ VPN"));
                    }
                });
                return true;
            case "install_update": {
                // проверенный APK — системному установщику (Android сам проверит подпись приложения)
                ui(new Runnable() {
                    @Override
                    public void run() {
                        Intent i = new Intent(Intent.ACTION_VIEW);
                        i.setDataAndType(ReportProvider.uri(MainActivity.this, ReportProvider.UPDATE),
                                "application/vnd.android.package-archive");
                        i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK);
                        try {
                            startActivity(i);
                        } catch (RuntimeException e) {
                            emit(Json.obj("type", "error", "text", Text.t("Не удалось открыть установщик: ", "Couldn't open the installer: ")
                                    + e.getMessage()));
                        }
                    }
                });
                return true;
            }
            case "share_report": {
                // отчёт файлом (.txt): в Telegram и почту уходит как документ; если файла нет — текстом
                final String name = Json.str(a, "name");
                final java.io.File f = new java.io.File(new java.io.File(getFilesDir(), ReportProvider.DIR), name);
                ui(new Runnable() {
                    @Override
                    public void run() {
                        Intent i = new Intent(Intent.ACTION_SEND);
                        i.setType("text/plain");
                        if (!name.isEmpty() && f.isFile()) {
                            i.putExtra(Intent.EXTRA_STREAM, ReportProvider.uri(MainActivity.this, name));
                            i.putExtra(Intent.EXTRA_SUBJECT, name);
                            i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                        } else {
                            i.putExtra(Intent.EXTRA_TEXT, Json.str(a, "text"));
                        }
                        startActivity(Intent.createChooser(i, "VEDOMYJ VPN"));
                    }
                });
                return true;
            }
            case "copy": {
                ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                cm.setPrimaryClip(ClipData.newPlainText("VEDOMYJ VPN", Json.str(a, "text")));
                return true;
            }
            case "paste": {
                ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                ClipData clip = cm.getPrimaryClip();
                if (clip == null || clip.getItemCount() == 0 || clip.getItemAt(0).getText() == null) {
                    return "";
                }
                return clip.getItemAt(0).getText().toString();
            }
            case "awg_open": {
                // AmneziaWG на телефоне включает своё приложение: открыть его или страницу в Google Play
                final Intent launch = getPackageManager().getLaunchIntentForPackage(AWG_PACKAGE);
                ui(new Runnable() {
                    @Override
                    public void run() {
                        if (launch != null) {
                            startActivity(launch);
                        } else {
                            openExternal(Uri.parse("https://play.google.com/store/apps/details?id=" + AWG_PACKAGE));
                        }
                    }
                });
                return launch != null ? "app" : "store";
            }
            case "open_url":
                openExternal(Uri.parse(Json.str(a, "url")));
                return true;
            case "apps":
                return apps();
            case "hotspot_local":
                ui(new Runnable() {
                    @Override
                    public void run() {
                        startHotspot();
                    }
                });
                return true;
            case "hotspot_system":
                e.setShare(true, "system", "", "");
                return true;
            case "hotspot_settings":
                ui(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            Intent i = new Intent();
                            i.setClassName("com.android.settings", "com.android.settings.TetherSettings");
                            startActivity(i);
                        } catch (Exception ex) {
                            startActivity(new Intent(Settings.ACTION_WIRELESS_SETTINGS));
                        }
                    }
                });
                return true;
            case "hotspot_stop":
                Hotspot.stopLocal();
                e.setShare(false, "", "", "");
                return true;
            case "share_new_pass":
                e.newSharePassword();
                return true;
            case "vps":
                e.vpsSetup(Json.str(a, "host"), Json.str(a, "port"), Json.str(a, "user"), Json.str(a, "password"),
                        Json.str(a, "name"));
                return true;
            case "vps_awg":
                e.vpsAwg(Json.str(a, "id"), Json.str(a, "password"));
                return true;
            case "vps_xdns":
                e.vpsXdns(Json.str(a, "id"), Json.str(a, "password"), Json.str(a, "domain"));
                return true;
            case "vps_awg_device":
                e.vpsAwgDevice(Json.str(a, "id"), Json.str(a, "password"), Json.str(a, "name"));
                return true;
            case "vps_awg_conf":
                return e.vpsAwgConf(Json.str(a, "id"));
            case "vps_bridge":
                e.vpsBridge(Json.str(a, "host"), Json.str(a, "port"), Json.str(a, "user"), Json.str(a, "password"),
                        Json.str(a, "via"), Json.str(a, "name"));
                return true;
            case "vps_add":
                e.vpsAdd(Json.str(a, "host"), Json.str(a, "port"), Json.str(a, "user"), Json.str(a, "password"),
                        Json.str(a, "name"));
                return true;
            case "vps_status":
                e.vpsStatus(Json.str(a, "id"), Json.str(a, "password"));
                return true;
            case "vps_friend_add":
                e.vpsFriendAdd(Json.str(a, "id"), Json.str(a, "password"), Json.str(a, "name"));
                return true;
            case "vps_friend_remove":
                e.vpsFriendRemove(Json.str(a, "id"), Json.str(a, "password"), Json.str(a, "friend"));
                return true;
            case "vps_forget":
                e.vpsForget(Json.str(a, "id"));
                return true;
            case "vps_friend_link":
                return e.vpsFriendLink(Json.str(a, "friend"));
            case "fix": {
                // кнопки из «Проверки программы»: снять ограничение батареи, включить уведомления
                final String what = Json.str(a, "what");
                ui(new Runnable() {
                    @Override
                    public void run() {
                        openFix(what);
                    }
                });
                return true;
            }
            case "vpn_settings":
                ui(new Runnable() {
                    @Override
                    public void run() {
                        startActivity(new Intent(Settings.ACTION_VPN_SETTINGS));
                    }
                });
                return true;
            case "theme": {
                final boolean dark = Json.bool(a, "dark", true);
                ui(new Runnable() {
                    @Override
                    public void run() {
                        applyTheme(dark);
                    }
                });
                return true;
            }
            case "filter_start":
                // защита без VPN тоже работает через туннель VPN — нужно то же разрешение Android
                ui(new Runnable() {
                    @Override
                    public void run() {
                        Intent prep = VpnService.prepare(MainActivity.this);
                        if (prep != null) {
                            try {
                                startActivityForResult(prep, REQ_FILTER);
                            } catch (ActivityNotFoundException ex) {
                                emit(Json.obj("type", "error", "text", Text.t("Android не дал включить VPN.", "Android did not allow VPN.")));
                            }
                        } else {
                            App.engine().filterStart();
                        }
                    }
                });
                return true;
            default: {
                Object r = Api.call(e, action, a);
                if (r == Api.UNKNOWN) {
                    throw new Engine.UserError("unknown action: " + Text.shorten(action, 40));
                }
                return r;
            }
        }
    }

    /** Приложения с иконкой на рабочем столе — чтобы выбрать, какие идут мимо VPN. */
    private List<Object> apps() {
        PackageManager pm = getPackageManager();
        Intent main = new Intent(Intent.ACTION_MAIN);
        main.addCategory(Intent.CATEGORY_LAUNCHER);
        List<ResolveInfo> list = pm.queryIntentActivities(main, 0);
        List<Map<String, Object>> out = new ArrayList<Map<String, Object>>();
        List<String> seen = new ArrayList<String>();
        for (ResolveInfo ri : list) {
            String pkg = ri.activityInfo.packageName;
            if (pkg.equals(getPackageName()) || seen.contains(pkg)) {
                continue;
            }
            seen.add(pkg);
            out.add(Json.obj("pkg", pkg, "name", String.valueOf(ri.loadLabel(pm))));
        }
        Collections.sort(out, new Comparator<Map<String, Object>>() {
            @Override
            public int compare(Map<String, Object> x, Map<String, Object> y) {
                return Json.str(x, "name").compareToIgnoreCase(Json.str(y, "name"));
            }
        });
        return new ArrayList<Object>(out);
    }
}
