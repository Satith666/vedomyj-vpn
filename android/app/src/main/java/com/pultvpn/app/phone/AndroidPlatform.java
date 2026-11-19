package com.pultvpn.app.phone;

import android.annotation.SuppressLint;
import android.app.NotificationManager;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.Build;
import android.os.PowerManager;
import android.os.StatFs;
import android.provider.Settings;

import com.pultvpn.app.BuildConfig;
import com.pultvpn.app.R;
import com.pultvpn.app.core.Engine;

import java.io.File;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import libv2ray.Libv2ray;

/** То, что движку даёт Android: ядро Xray, VPN, точка доступа, SSH, сведения о телефоне для проверки. */
final class AndroidPlatform implements Engine.Platform, Engine.DeviceInfo, Engine.Traffic, Engine.Notices, Engine.Crypto,
        Engine.NetInfo, Engine.CertStore {
    private static final String KEY_ALIAS = "vedomyj_secrets";

    /**
     * Сертификаты центров сертификации телефона: системные («system:…») или поставленные человеком и приложениями
     * («user:…»). Браузеры доверяют и тем и другим — поэтому сертификат Минцифры среди них важно заметить.
     */
    @Override
    public List<byte[]> caCerts(boolean user) {
        List<byte[]> out = new java.util.ArrayList<byte[]>();
        try {
            java.security.KeyStore ks = java.security.KeyStore.getInstance("AndroidCAStore");
            ks.load(null);
            java.util.Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String a = aliases.nextElement();
                if (a.startsWith("user:") != user) {
                    continue;
                }
                java.security.cert.Certificate c = ks.getCertificate(a);
                if (c != null) {
                    out.add(c.getEncoded());
                }
            }
        } catch (Exception e) {
            throw new IllegalStateException("AndroidCAStore: " + e.getMessage(), e);
        }
        return out;
    }

    /** Ключ AES в Android Keystore: достать его из телефона нельзя, на другом телефоне его нет. */
    private javax.crypto.SecretKey secretKey() throws Exception {
        java.security.KeyStore ks = java.security.KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (!ks.containsAlias(KEY_ALIAS)) {
            javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance(
                    android.security.keystore.KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            kg.init(new android.security.keystore.KeyGenParameterSpec.Builder(KEY_ALIAS,
                    android.security.keystore.KeyProperties.PURPOSE_ENCRYPT | android.security.keystore.KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build());
            return kg.generateKey();
        }
        return (javax.crypto.SecretKey) ks.getKey(KEY_ALIAS, null);
    }

    /** Какая сеть под VPN: Wi-Fi (и открытый ли он — Android 12+), мобильная или другая. */
    @Override
    public Map<String, Object> netInfo() {
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        out.put("kind", "other");
        out.put("open", false);
        ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) {
            return out;
        }
        for (Network n : cm.getAllNetworks()) {
            NetworkCapabilities c = cm.getNetworkCapabilities(n);
            if (c == null || c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                    || !c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                continue;
            }
            if (c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                out.put("kind", "wifi");
                // сеть просит войти через свою страницу (кафе, гостиница): Android сам покажет её уведомлением
                out.put("captive", c.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL));
                if (Build.VERSION.SDK_INT >= 31 && c.getTransportInfo() instanceof android.net.wifi.WifiInfo) {
                    int sec = ((android.net.wifi.WifiInfo) c.getTransportInfo()).getCurrentSecurityType();
                    // 0 — открытая сеть, 6 — OWE (шифрованная, но без пароля: тоже общественная)
                    out.put("open", sec == 0 || sec == 6);
                }
                return out;
            }
            if (c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                out.put("kind", "cell");
            }
        }
        return out;
    }

    @Override
    public String seal(String plain) throws Exception {
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        c.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey());
        byte[] iv = c.getIV();
        byte[] ct = c.doFinal(plain.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte[] out = new byte[1 + iv.length + ct.length];
        out[0] = (byte) iv.length;
        System.arraycopy(iv, 0, out, 1, iv.length);
        System.arraycopy(ct, 0, out, 1 + iv.length, ct.length);
        return android.util.Base64.encodeToString(out, android.util.Base64.NO_WRAP);
    }

    @Override
    public String open(String sealed) throws Exception {
        byte[] all = android.util.Base64.decode(sealed, android.util.Base64.NO_WRAP);
        int n = all[0];
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        c.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey(), new javax.crypto.spec.GCMParameterSpec(128, all, 1, n));
        byte[] pt = c.doFinal(all, 1 + n, all.length - 1 - n);
        return new String(pt, java.nio.charset.StandardCharsets.UTF_8);
    }

    private final Context ctx;
    private volatile String coreVersion;

    AndroidPlatform(Context ctx) {
        this.ctx = ctx.getApplicationContext();
    }

    @Override
    public File dataDir() {
        return ctx.getFilesDir();
    }

    @SuppressLint("HardwareIds")
    @Override
    public String deviceId() {
        String id = Settings.Secure.getString(ctx.getContentResolver(), Settings.Secure.ANDROID_ID);
        return id == null ? "" : id;
    }

    @Override
    public String osVersion() {
        return Build.VERSION.RELEASE;
    }

    @Override
    public String systemLang() {
        return Locale.getDefault().getLanguage();
    }

    @Override
    public String appVersion() {
        return BuildConfig.VERSION_NAME;
    }

    /** Для «Проверки программы»: всё, что может мешать VPN на этом телефоне. Каждый пункт — отдельно и без падений. */
    @Override
    public Map<String, Object> deviceInfo() {
        Map<String, Object> m = new LinkedHashMap<String, Object>();
        m.put("model", Build.MANUFACTURER + " " + Build.MODEL);
        if (Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0) {
            m.put("abi", Build.SUPPORTED_ABIS[0]);
        }
        try {
            m.put("vpn_permission", VpnService.prepare(ctx) == null);
        } catch (Exception ignored) {
            // нет сведений — не показываем
        }
        try {
            NotificationManager nm = (NotificationManager) ctx.getSystemService(Context.NOTIFICATION_SERVICE);
            m.put("notifications", nm.areNotificationsEnabled());
        } catch (Exception ignored) {
            // нет сведений
        }
        try {
            PowerManager pm = (PowerManager) ctx.getSystemService(Context.POWER_SERVICE);
            m.put("battery_restricted", !pm.isIgnoringBatteryOptimizations(ctx.getPackageName()));
        } catch (Exception ignored) {
            // нет сведений
        }
        try {
            ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            m.put("data_saver", cm.getRestrictBackgroundStatus() == ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED);
            Network net = cm.getActiveNetwork();
            NetworkCapabilities caps = net == null ? null : cm.getNetworkCapabilities(net);
            m.put("other_vpn", caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN));
        } catch (Exception ignored) {
            // нет сведений
        }
        try {
            String mode = Settings.Global.getString(ctx.getContentResolver(), "private_dns_mode");
            String host = Settings.Global.getString(ctx.getContentResolver(), "private_dns_specifier");
            if (mode != null) {
                m.put("private_dns", "hostname".equals(mode) && host != null ? host : mode);
            }
        } catch (Exception ignored) {
            // нет сведений
        }
        try {
            m.put("install_allowed", ctx.getPackageManager().canRequestPackageInstalls());
            android.app.KeyguardManager km = (android.app.KeyguardManager) ctx.getSystemService(Context.KEYGUARD_SERVICE);
            if (km != null) {
                m.put("keyguard_secure", km.isDeviceSecure());
            }
        } catch (Exception ignored) {
            // нет сведений
        }
        try {
            // адаптеры и их IPv4 — чтобы в отчёте было видно, на каком адаптере раздача (адреса из отчёта убираются)
            Map<String, Object> ifs = new LinkedHashMap<String, Object>();
            for (java.net.NetworkInterface ni : java.util.Collections.list(java.net.NetworkInterface.getNetworkInterfaces())) {
                if (!ni.isUp() || ni.isLoopback()) {
                    continue;
                }
                StringBuilder ips = new StringBuilder();
                for (java.net.InetAddress a : java.util.Collections.list(ni.getInetAddresses())) {
                    if (a instanceof java.net.Inet4Address) {
                        ips.append(ips.length() > 0 ? " " : "").append(a.getHostAddress());
                    }
                }
                ifs.put(ni.getName(), ips.toString());
            }
            m.put("ifaces", ifs);
        } catch (Exception ignored) {
            // нет доступа к списку адаптеров
        }
        try {
            m.put("free_mb", new StatFs(ctx.getFilesDir().getPath()).getAvailableBytes() / (1024 * 1024));
        } catch (Exception ignored) {
            // нет сведений
        }
        return m;
    }

    @Override
    public long testDelay(String configJson, String url) throws Exception {
        return Libv2ray.measureOutboundDelay(configJson, url);
    }

    /** Трафик самого приложения = всё, что идёт через туннель (ядро работает внутри приложения). */
    @Override
    public long[] trafficBytes() {
        int uid = android.os.Process.myUid();
        return new long[]{android.net.TrafficStats.getUidRxBytes(uid), android.net.TrafficStats.getUidTxBytes(uid)};
    }

    @Override
    public java.io.Closeable startTestCore(String configJson) throws Exception {
        final libv2ray.CoreController c = Libv2ray.newCoreController(new libv2ray.CoreCallbackHandler() {
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
        });
        synchronized (PultVpnService.CORE_START) {
            c.startLoop(configJson, 0); // без туннеля: только вход HTTP на 127.0.0.1
        }
        return new java.io.Closeable() {
            @Override
            public void close() {
                try {
                    c.stopLoop();
                } catch (Exception ignored) {
                    // уже остановлено
                }
            }
        };
    }

    @Override
    public void startVpn(String configJson, List<String> excludedApps) throws Exception {
        PultVpnService svc = PultVpnService.ensure(ctx);
        svc.apply(configJson, excludedApps);
    }

    @Override
    public void stopVpn() {
        PultVpnService svc = PultVpnService.current();
        if (svc != null) {
            svc.shutdown();
        }
    }

    @Override
    public boolean vpnAlive() {
        PultVpnService svc = PultVpnService.current();
        return svc != null && svc.running();
    }

    @Override
    public long coreDelay(String url) throws Exception {
        PultVpnService svc = PultVpnService.current();
        if (svc == null) {
            throw new IllegalStateException("VPN is off");
        }
        return svc.delay(url);
    }

    @Override
    public String coreVersion() {
        String v = coreVersion;
        if (v == null) {
            try {
                v = Libv2ray.checkVersionX();
            } catch (Throwable e) {
                v = "";
            }
            coreVersion = v;
        }
        return v;
    }

    @Override
    public String hotspotIp() {
        return Hotspot.hotspotIp(ctx);
    }

    @Override
    public void sshRun(String host, int port, String user, String password, String script, Engine.LineSink out,
                       Engine.Stop stop) throws Exception {
        Ssh.run(host, port, user, password, script, out, stop);
    }

    @Override
    public void notice(String title, String text) {
        NotificationManager nm = (NotificationManager) ctx.getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) {
            return;
        }
        android.content.Intent open = new android.content.Intent(ctx, MainActivity.class);
        open.setFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK | android.content.Intent.FLAG_ACTIVITY_SINGLE_TOP);
        open.putExtra("page", "ads");
        android.app.PendingIntent pi = android.app.PendingIntent.getActivity(ctx, 7, open,
                android.app.PendingIntent.FLAG_IMMUTABLE | android.app.PendingIntent.FLAG_UPDATE_CURRENT);
        android.app.Notification.Builder b = Build.VERSION.SDK_INT >= 26 ? new android.app.Notification.Builder(ctx, App.NOTICES)
                : new android.app.Notification.Builder(ctx);
        b.setSmallIcon(R.drawable.ic_stat)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(new android.app.Notification.BigTextStyle().bigText(text))
                .setContentIntent(pi)
                .setAutoCancel(true);
        try {
            nm.notify(2001, b.build());
        } catch (SecurityException ignored) {
            // нет разрешения на уведомления — вопрос всё равно виден в разделе «Реклама»
        }
    }

    @Override
    public void changed() {
        PultVpnService svc = PultVpnService.current();
        if (svc != null) {
            svc.updateNotification();
        }
        String st = App.engine() == null ? "" : App.engine().status();
        if (!st.equals(lastStatus)) {
            lastStatus = st;
            QuickTile.refresh(ctx);
            VpnWidget.refresh(ctx);
        }
    }

    private volatile String lastStatus = "";
}
