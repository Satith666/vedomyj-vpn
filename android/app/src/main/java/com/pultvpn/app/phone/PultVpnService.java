package com.pultvpn.app.phone;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.graphics.drawable.Icon;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import com.pultvpn.app.R;
import com.pultvpn.app.core.Engine;
import com.pultvpn.app.core.Json;
import com.pultvpn.app.core.Text;
import com.pultvpn.app.core.XrayConfig;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import libv2ray.CoreCallbackHandler;
import libv2ray.CoreController;
import libv2ray.Libv2ray;

/**
 * VPN телефона: виртуальный адаптер (TUN) от Android и ядро Xray внутри приложения.
 * Само приложение исключено из туннеля — поэтому соединения ядра идут мимо VPN и петли нет.
 */
public final class PultVpnService extends VpnService {
    static final String ACTION_RUN = "com.pultvpn.app.RUN";
    static final String ACTION_STOP = "com.pultvpn.app.STOP";
    static final String ACTION_HOUR = "com.pultvpn.app.HOUR";
    static final int NOTIFICATION_ID = 1;

    private static volatile PultVpnService instance;
    /** Запуски ядра по очереди: основное и временные (проверки) не должны стартовать одновременно. */
    static final Object CORE_START = new Object();
    private static final Object START_LOCK = new Object();

    private ParcelFileDescriptor tun;
    private List<String> tunExcluded = new ArrayList<String>();
    private CoreController core;
    private volatile boolean running;
    private volatile boolean foreground;

    static PultVpnService current() {
        return instance;
    }

    /** Запустить службу (если ещё не запущена) и дождаться её. */
    static PultVpnService ensure(Context ctx) throws Exception {
        synchronized (START_LOCK) {
            PultVpnService s = instance;
            if (s != null && s.foreground) {
                return s;
            }
            Intent i = new Intent(ctx, PultVpnService.class);
            i.setAction(ACTION_RUN);
            if (Build.VERSION.SDK_INT >= 26) {
                ctx.startForegroundService(i);
            } else {
                ctx.startService(i);
            }
            long end = System.currentTimeMillis() + 8000;
            while (instance == null || !instance.foreground) {
                if (System.currentTimeMillis() > end) {
                    throw new IllegalStateException(Text.t("служба VPN не запустилась", "the VPN service did not start"));
                }
                Thread.sleep(50);
            }
            return instance;
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        instance = this;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        goForeground();
        String action = intent == null ? null : intent.getAction();
        Engine engine = App.engine();
        if (ACTION_STOP.equals(action)) {
            engine.disconnect();
            return START_NOT_STICKY;
        }
        if (ACTION_HOUR.equals(action)) {
            engine.vpnFor(60); // «выключить через час» / «ещё час»
            updateNotification();
            return START_STICKY;
        }
        if (ACTION_RUN.equals(action)) {
            return START_STICKY;
        }
        // запуск системой: «Постоянный VPN» или перезапуск после того, как Android закрыл приложение
        boolean alwaysOn = intent != null && VpnService.SERVICE_INTERFACE.equals(action);
        if ((alwaysOn || engine.wasOn()) && "off".equals(engine.status())) {
            engine.connect();
        } else if (!running && "off".equals(engine.status())) {
            shutdown();
        }
        return START_STICKY;
    }

    private void goForeground() {
        Notification n = buildNotification();
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION_ID, n);
        }
        foreground = true;
    }

    /** Включить туннель (если нужно — пересоздать) и запустить ядро с этими настройками. */
    synchronized void apply(String config, List<String> excluded) throws Exception {
        if (VpnService.prepare(this) != null) {
            throw new IllegalStateException("VPN_PERMISSION");
        }
        stopCore();
        if (tun == null || !excluded.equals(tunExcluded)) {
            ParcelFileDescriptor old = tun;
            Builder b = new Builder();
            b.setSession("VEDOMYJ VPN");
            b.setMtu(XrayConfig.MTU);
            b.addAddress(XrayConfig.TUN_V4, XrayConfig.TUN_V4_PREFIX);
            b.addRoute("0.0.0.0", 0);
            b.addDnsServer(XrayConfig.TUN_DNS);
            try {
                // IPv6 тоже в туннель — иначе часть сайтов шла бы мимо VPN
                b.addAddress(XrayConfig.TUN_V6, XrayConfig.TUN_V6_PREFIX);
                b.addRoute("::", 0);
            } catch (RuntimeException ignored) {
                // на некоторых прошивках IPv6 в VPN недоступен
            }
            b.addDisallowedApplication(getPackageName());
            for (String pkg : excluded) {
                try {
                    b.addDisallowedApplication(pkg);
                } catch (PackageManager.NameNotFoundException ignored) {
                    // приложение удалили — пропускаем
                }
            }
            if (Build.VERSION.SDK_INT >= 29) {
                b.setMetered(false);
            }
            Intent open = new Intent(this, MainActivity.class);
            b.setConfigureIntent(PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE));
            ParcelFileDescriptor fd = b.establish();
            if (fd == null) {
                throw new IllegalStateException("VPN_PERMISSION");
            }
            tun = fd;
            tunExcluded = new ArrayList<String>(excluded);
            if (old != null) {
                try {
                    old.close();
                } catch (IOException ignored) {
                    // уже закрыт
                }
            }
        }
        if (core == null) {
            core = Libv2ray.newCoreController(new Callback());
        }
        synchronized (CORE_START) {
            core.startLoop(config, tun.getFd());
        }
        running = true;
        updateNotification();
    }

    private void stopCore() {
        CoreController c = core;
        if (c != null && c.getIsRunning()) {
            try {
                c.stopLoop();
            } catch (Exception ignored) {
                // ядро уже остановилось
            }
        }
    }

    boolean running() {
        CoreController c = core;
        return running && tun != null && c != null && c.getIsRunning();
    }

    long delay(String url) throws Exception {
        CoreController c = core;
        if (c == null || !c.getIsRunning()) {
            throw new IllegalStateException("core is not running");
        }
        return c.measureDelay(url);
    }

    /** Выключить VPN и остановить службу. */
    synchronized void shutdown() {
        running = false;
        stopCore();
        if (tun != null) {
            try {
                tun.close();
            } catch (IOException ignored) {
                // уже закрыт
            }
            tun = null;
        }
        if (Build.VERSION.SDK_INT >= 24) {
            stopForeground(STOP_FOREGROUND_REMOVE);
        } else {
            stopForeground(true);
        }
        foreground = false;
        stopSelf();
    }

    @Override
    public void onRevoke() {
        // VPN забрал другой VPN или его выключили в настройках Android
        running = false;
        App.engine().onRevoked();
        shutdown();
    }

    @Override
    public void onDestroy() {
        running = false;
        stopCore();
        if (tun != null) {
            try {
                tun.close();
            } catch (IOException ignored) {
                // уже закрыт
            }
            tun = null;
        }
        instance = null;
        super.onDestroy();
    }

    // ---------- уведомление ----------

    private String lastText = "";

    void updateNotification() {
        if (!foreground) {
            return;
        }
        String text = statusText();
        if (text.equals(lastText)) {
            return; // Android всё равно не показывает частые обновления
        }
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm != null) {
            nm.notify(NOTIFICATION_ID, buildNotification());
        }
    }

    private String statusText() {
        Map<String, Object> st = App.engine().state();
        String status = Json.str(st, "status");
        if ("on".equals(status)) {
            Map<String, Object> srv = Json.map(st, "server");
            long d = Json.num(st, "delay", -1);
            Map<String, Object> sp = Json.map(st, "speed");
            String rate = sp == null ? "" : Engine.speedText(Json.num(sp, "down", 0), Json.num(sp, "up", 0));
            long until = Json.num(st, "vpn_until", 0);
            String timer = until > 0 ? " · " + Text.t("до ", "until ")
                    + new java.text.SimpleDateFormat("HH:mm", java.util.Locale.US).format(new java.util.Date(until)) : "";
            return Text.t("Подключено", "Connected") + (srv == null ? "" : " · " + Json.str(srv, "name"))
                    + (rate.isEmpty() ? (d > 0 ? " · " + d + Text.t(" мс", " ms") : "") : " · " + rate) + timer;
        }
        if ("connecting".equals(status)) {
            return Text.t("Подключаюсь…", "Connecting…");
        }
        if (Json.bool(st, "filter_on", false)) {
            Map<String, Object> ads = Json.map(st, "ads");
            boolean blocking = ads != null && !Json.str(ads, "mode").isEmpty() && Json.bool(ads, "without_vpn", true);
            long n = ads == null ? 0 : Json.num(ads, "today", 0);
            return Text.t("Без VPN: ", "Without VPN: ") + (blocking ? Text.t("блокирую рекламу", "blocking ads")
                    + (n > 0 ? " · " + n : "") : Text.t("обход замедлений", "throttling bypass"));
        }
        return Text.t("Выключено", "Off");
    }

    private Notification buildNotification() {
        String text = statusText();
        lastText = text;
        Intent open = new Intent(this, MainActivity.class);
        open.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent openPi = PendingIntent.getActivity(this, 1, open, PendingIntent.FLAG_IMMUTABLE);
        Intent stop = new Intent(this, PultVpnService.class);
        stop.setAction(ACTION_STOP);
        PendingIntent stopPi = PendingIntent.getService(this, 2, stop, PendingIntent.FLAG_IMMUTABLE);
        Intent hour = new Intent(this, PultVpnService.class);
        hour.setAction(ACTION_HOUR);
        PendingIntent hourPi = PendingIntent.getService(this, 3, hour, PendingIntent.FLAG_IMMUTABLE);
        boolean vpnOn = "on".equals(App.engine().status());
        Notification.Builder b = Build.VERSION.SDK_INT >= 26 ? new Notification.Builder(this, App.CHANNEL)
                : new Notification.Builder(this);
        b.setSmallIcon(R.drawable.ic_stat)
                .setContentTitle("VEDOMYJ VPN")
                .setContentText(text)
                .setContentIntent(openPi)
                .setOngoing(true)
                .setShowWhen(false)
                .setOnlyAlertOnce(true)
                .addAction(new Notification.Action.Builder(Icon.createWithResource(this, R.drawable.ic_stat),
                        "on".equals(App.engine().status()) || "connecting".equals(App.engine().status())
                                ? Text.t("Отключить", "Disconnect") : Text.t("Выключить", "Turn off"), stopPi).build());
        if (vpnOn) {
            // VPN на время: выключится сам через час (повторно — ещё час)
            b.addAction(new Notification.Action.Builder(Icon.createWithResource(this, R.drawable.ic_stat),
                    App.engine().vpnUntil() > 0 ? Text.t("Ещё 1 ч", "+1 h") : Text.t("Выключить через 1 ч", "Off in 1 h"),
                    hourPi).build());
        }
        return b.build();
    }

    private static final class Callback implements CoreCallbackHandler {
        @Override
        public long startup() {
            return 0;
        }

        @Override
        public long shutdown() {
            return 0;
        }

        @Override
        public long onEmitStatus(long code, String message) {
            return 0;
        }
    }
}
