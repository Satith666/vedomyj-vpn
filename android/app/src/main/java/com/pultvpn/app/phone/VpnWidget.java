package com.pultvpn.app.phone;

import android.app.PendingIntent;
import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.widget.RemoteViews;

import com.pultvpn.app.R;
import com.pultvpn.app.core.Engine;
import com.pultvpn.app.core.Text;

/** Виджет на рабочий стол: видно, включён ли VPN, касание включает или выключает его. */
public final class VpnWidget extends AppWidgetProvider {
    static final String ACTION_TOGGLE = "com.pultvpn.app.WIDGET_TOGGLE";

    /** Обновить все виджеты (вызывается при смене состояния). */
    static void refresh(Context ctx) {
        try {
            AppWidgetManager m = AppWidgetManager.getInstance(ctx);
            int[] ids = m.getAppWidgetIds(new ComponentName(ctx, VpnWidget.class));
            if (ids != null && ids.length > 0) {
                draw(ctx, m, ids);
            }
        } catch (RuntimeException ignored) {
            // виджетов нет — обновлять нечего
        }
    }

    @Override
    public void onUpdate(Context ctx, AppWidgetManager m, int[] ids) {
        draw(ctx, m, ids);
    }

    @Override
    public void onReceive(Context ctx, Intent intent) {
        super.onReceive(ctx, intent);
        if (!ACTION_TOGGLE.equals(intent.getAction())) {
            return;
        }
        Engine e = App.engine();
        if (!"off".equals(e.status())) {
            e.disconnect();
        } else if (VpnService.prepare(ctx) == null) {
            e.connect();
        } else {
            // нужно разрешение на VPN — его можно дать только в окне приложения
            Intent i = new Intent(ctx, MainActivity.class);
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            i.putExtra(MainActivity.EXTRA_CONNECT, true);
            ctx.startActivity(i);
        }
        refresh(ctx);
    }

    static void draw(Context ctx, AppWidgetManager m, int[] ids) {
        String st = App.engine() == null ? "off" : App.engine().status();
        String text = "on".equals(st) ? Text.t("Включён — нажми, чтобы выключить", "On — tap to turn off")
                : "connecting".equals(st) ? Text.t("Подключаюсь…", "Connecting…")
                : Text.t("Выключен — нажми, чтобы включить", "Off — tap to turn on");
        Intent toggle = new Intent(ctx, VpnWidget.class);
        toggle.setAction(ACTION_TOGGLE);
        PendingIntent pi = PendingIntent.getBroadcast(ctx, 11, toggle,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        for (int id : ids) {
            RemoteViews v = new RemoteViews(ctx.getPackageName(), R.layout.widget);
            v.setTextViewText(R.id.widget_state, text);
            v.setInt(R.id.widget_icon, "setColorFilter", "on".equals(st) ? 0xFF3FD08F : 0xFF8A94AD);
            v.setOnClickPendingIntent(R.id.widget_root, pi);
            m.updateAppWidget(id, v);
        }
    }
}
