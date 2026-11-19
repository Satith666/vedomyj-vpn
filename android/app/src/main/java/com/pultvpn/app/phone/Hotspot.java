package com.pultvpn.app.phone;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.wifi.SoftApConfiguration;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.regex.Pattern;

/**
 * Раздача: своя сеть Wi-Fi приложения (LocalOnlyHotspot) или обычная точка доступа телефона.
 * Устройства в этой сети ходят в интернет через прокси телефона, а он — через VPN.
 */
final class Hotspot {
    private Hotspot() {
    }

    interface Result {
        void started(String ssid, String password);

        void failed(String message);

        void stopped();
    }

    private static WifiManager.LocalOnlyHotspotReservation reservation;

    // имена адаптеров раздачи у разных производителей: ap0, swlan0, wlan1, softap0, p2p-wlan0-0, rndis0 (USB), bt-pan
    private static final Pattern SHARE_IF = Pattern.compile(
            "(ap|swlan|wlan|softap|p2p|rndis|usb|ncm|eth|bt-pan|bnep|wigig).*", Pattern.CASE_INSENSITIVE);
    private static final Pattern SKIP_IF = Pattern.compile(
            "(tun|ppp|rmnet|ccmni|dummy|lo|v4-|clat|ipsec|ifb|sit|ip6tnl|wwan|seth).*", Pattern.CASE_INSENSITIVE);

    /** Адрес телефона в сети раздачи ("" — раздача не включена). */
    static String hotspotIp(Context ctx) {
        String main = "";
        try {
            ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            Network active = cm == null ? null : cm.getActiveNetwork();
            LinkProperties lp = active == null ? null : cm.getLinkProperties(active);
            if (lp != null && lp.getInterfaceName() != null) {
                main = lp.getInterfaceName();
            }
        } catch (RuntimeException ignored) {
            // без сведений о сети просто не исключаем основной адаптер
        }
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                String name = ni.getName();
                if (!ni.isUp() || ni.isLoopback() || name.equals(main) || SKIP_IF.matcher(name).matches()
                        || !SHARE_IF.matcher(name).matches()) {
                    continue;
                }
                for (InetAddress a : Collections.list(ni.getInetAddresses())) {
                    if (a instanceof Inet4Address && a.isSiteLocalAddress()) {
                        return a.getHostAddress();
                    }
                }
            }
        } catch (Exception ignored) {
            // нет доступа к списку адаптеров
        }
        return "";
    }

    /** Своя сеть Wi-Fi приложения. Разрешения проверяет MainActivity. */
    @SuppressWarnings("deprecation")
    static void startLocal(Context ctx, final Result result) {
        WifiManager wm = (WifiManager) ctx.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        if (wm == null) {
            result.failed("no Wi-Fi");
            return;
        }
        if (reservation != null) {
            reservation.close();
            reservation = null;
        }
        try {
            wm.startLocalOnlyHotspot(new WifiManager.LocalOnlyHotspotCallback() {
                @Override
                public void onStarted(WifiManager.LocalOnlyHotspotReservation r) {
                    reservation = r;
                    String ssid = "";
                    String pass = "";
                    if (Build.VERSION.SDK_INT >= 30) {
                        SoftApConfiguration c = r.getSoftApConfiguration();
                        ssid = c.getSsid();
                        pass = c.getPassphrase();
                    } else {
                        WifiConfiguration c = r.getWifiConfiguration();
                        if (c != null) {
                            ssid = c.SSID;
                            pass = c.preSharedKey;
                        }
                    }
                    result.started(clean(ssid), clean(pass));
                }

                @Override
                public void onStopped() {
                    reservation = null;
                    result.stopped();
                }

                @Override
                public void onFailed(int reason) {
                    reservation = null;
                    result.failed(reason == ERROR_INCOMPATIBLE_MODE ? "incompatible"
                            : reason == ERROR_TETHERING_DISALLOWED ? "disallowed" : "failed");
                }
            }, new Handler(Looper.getMainLooper()));
        } catch (RuntimeException e) {
            result.failed(e.getMessage() == null ? "failed" : e.getMessage());
        }
    }

    static void stopLocal() {
        if (reservation != null) {
            reservation.close();
            reservation = null;
        }
    }

    static boolean localOn() {
        return reservation != null;
    }

    private static String clean(String s) {
        if (s == null) {
            return "";
        }
        if (s.length() >= 2 && s.startsWith("\"") && s.endsWith("\"")) {
            return s.substring(1, s.length() - 1);
        }
        return s;
    }
}
