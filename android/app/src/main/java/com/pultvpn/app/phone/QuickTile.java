package com.pultvpn.app.phone;

import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

import com.pultvpn.app.core.Engine;

/** Кнопка в шторке уведомлений: включить или выключить VPN одним касанием. */
public final class QuickTile extends TileService {

    static void refresh(Context ctx) {
        try {
            TileService.requestListeningState(ctx, new ComponentName(ctx, QuickTile.class));
        } catch (RuntimeException ignored) {
            // плитку не добавили в шторку — обновлять нечего
        }
    }

    @Override
    public void onStartListening() {
        update();
    }

    @SuppressWarnings("deprecation")
    @Override
    public void onClick() {
        Engine e = App.engine();
        if (!"off".equals(e.status())) {
            e.disconnect();
        } else if (VpnService.prepare(this) == null) {
            e.connect();
        } else {
            // нужно разрешение на VPN — его можно дать только в окне приложения
            Intent i = new Intent(this, MainActivity.class);
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            i.putExtra(MainActivity.EXTRA_CONNECT, true);
            if (Build.VERSION.SDK_INT >= 34) {
                startActivityAndCollapse(PendingIntent.getActivity(this, 3, i,
                        PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT));
            } else {
                startActivityAndCollapse(i);
            }
        }
        update();
    }

    private void update() {
        Tile t = getQsTile();
        if (t == null) {
            return;
        }
        String st = App.engine().status();
        t.setState("off".equals(st) ? Tile.STATE_INACTIVE : Tile.STATE_ACTIVE);
        t.setLabel("VEDOMYJ VPN");
        t.updateTile();
    }
}
