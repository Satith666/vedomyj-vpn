package com.pultvpn.app.phone;

import android.app.Application;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.os.Build;

import com.pultvpn.app.core.Engine;

import java.io.File;

import libv2ray.Libv2ray;

/** Приложение: один движок на всё время жизни процесса. */
public final class App extends Application {
    public static final String CHANNEL = "vpn";
    public static final String NOTICES = "notices"; // заметные сообщения: «сайт закрыт блокировщиком» и т. п.
    private static App instance;
    private Engine engine;

    @Override
    public void onCreate() {
        super.onCreate();
        instance = this;
        // ядро Xray ищет списки сайтов (geosite.dat, geoip.dat) в этой папке
        File assets = new File(getFilesDir(), "assets");
        assets.mkdirs();
        try {
            Libv2ray.initCoreEnv(assets.getAbsolutePath(), "");
        } catch (Throwable ignored) {
            // без настройки окружения ядро всё равно запустится, просто без списков сайтов
        }
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel ch = new NotificationChannel(CHANNEL, "VPN", NotificationManager.IMPORTANCE_LOW);
            ch.setShowBadge(false);
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            NotificationChannel notices = new NotificationChannel(NOTICES, "Сообщения", NotificationManager.IMPORTANCE_DEFAULT);
            if (nm != null) {
                nm.createNotificationChannel(ch);
                nm.createNotificationChannel(notices);
            }
        }
        engine = new Engine(new AndroidPlatform(this));
        // необработанное исключение в любом потоке — в журнал ошибок (и дальше, как обычно: Android закроет приложение)
        final Thread.UncaughtExceptionHandler old = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread t, Throwable e) {
                try {
                    engine.errors().recordExc(e, "поток " + t.getName());
                    engine.noteCrash(); // упало сразу после запуска — следующий запуск будет безопасным
                } catch (Throwable ignored) {
                    // журнал — помощник
                }
                if (old != null) {
                    old.uncaughtException(t, e);
                }
            }
        });
        engine.start();
    }

    public static App get() {
        return instance;
    }

    public static Engine engine() {
        return instance.engine;
    }
}
