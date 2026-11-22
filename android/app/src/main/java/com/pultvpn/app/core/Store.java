package com.pultvpn.app.core;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

/** Файлы данных приложения: запись через временный файл, чтобы сбой не оставил половину файла. */
public final class Store {
    private Store() {
    }

    public static Map<String, Object> defaults() {
        return Json.obj(
                "lang", "",               // "" — как в системе
                "theme", "auto",
                "mode", "vpn",
                "block_quic", true,       // QUIC мимо российских сайтов — блок (через VPN он лагает)
                "routing_v2", false,      // переход на «всё через VPN» по умолчанию уже сделан
                "ru_direct", true,
                "autopilot", true,
                "dns_encrypted", false,
                "block_ads", false,
                "mask_auto", true,
                "whitelist_auto", true,
                "proxy_list", "",
                "direct_list", "",
                "block_list", "",
                "subscriptions", new ArrayList<Object>(),
                "manual_links", new ArrayList<Object>(),
                "hwid", "",
                "user_agent", "",
                "excluded_apps", new ArrayList<Object>(),
                "share_socks_port", 10810L,
                "share_http_port", 10811L,
                "share_user", "pult",
                "share_pass", "",
                "selected", "",
                "engine_pick", "auto",   // «Движок»: auto, xray, hy2; awg — AmneziaWG в своём приложении
                // защита (как protect.py): предохранители способов, автооткат изменений, безопасный запуск
                "fuses_enabled", true, "fuses", new LinkedHashMap<String, Object>(), "guard_rollback", true, "safe_start", true,
                "stall_check", true, // «16 КБ»: лучшие серверы качают 64 КБ, обрывающиеся — ниже
                "family_dht", true, // «Семья»: посылки сами — через сеть торрентов (BEP 44)
                "warp_fallback", true, // «Авто»: серверы не работают — временно свой WARP во встроенном ядре
                // галочка «Белые списки» на главном; wl_muted — сняли в этой сети, когда списки заметились сами
                "wl_priority", false, "wl_muted", "",
                // сбор ошибок (как collect.py)
                "collect_until", 0L, "collect_started", 0L, "collect_report", "",
                "last_awg_key", "",
                "cert_pins", new LinkedHashMap<String, Object>(), // ключ сервера → SHA-256 сертификата (вместо allowInsecure)
                "auto_update_hours", 12L,
                "geo_updated", 0L,
                "was_on", false,
                "hint_shown", false,
                // свои маршруты: "svc:<сервис>" / "site:<адрес>" → {via: server|custom|dpi|proxy|direct|block, …}
                "routes", new LinkedHashMap<String, Object>(),
                // свои прокси: [{id, name, type, tls, host, port, user, pass, chain, check}]
                "proxies", new ArrayList<Object>(),
                // обход замедлений YouTube и Discord (дробление в ядре, без root)
                "dpi_enabled", true,
                "dpi_youtube", true,
                "dpi_discord", true,
                "dpi_custom", "",
                "dpi_strategy", "",
                "dpi_ok", false,
                "dpi_tested_at", 0L,
                "dpi_results", new ArrayList<Object>(),
                "dpi_without_vpn", false,
                // блокировка рекламы
                "ads_level", "normal",
                "ads_rev", 0L,
                "ads_site_ignore", new ArrayList<Object>(),
                "ads_ask_sites", true,
                "encrypt_data", true,
                "app_lock", false,
                "net_profiles", true,
                "cert_watch", true,
                "fp_auto", true,
                "data_watch", true,
                "net_memory", true,
                "net_ways", new LinkedHashMap<String, Object>(),
                "cert_root_ack", new ArrayList<Object>(),
                "github_repo", "",
                "app_update", true,
                "app_update_checked", 0L,
                "sub_alerts", true,
                "sub_alerts_sent", new LinkedHashMap<String, Object>(),
                "ads_lists", Json.obj("popups", true, "threats", true, "ru", true),
                "ads_custom", "",
                "ads_allow", "",
                "ads_without_vpn", true,
                "ads_pause_until", 0L,
                "ads_update_hours", 24L,
                "ads_updated_at", 0L,
                "ads_info", new LinkedHashMap<String, Object>());
    }

    public static String read(File f) throws IOException {
        InputStream in = new FileInputStream(f);
        try {
            byte[] buf = new byte[(int) Math.min(f.length(), 64L * 1024 * 1024)];
            int off = 0;
            while (off < buf.length) {
                int n = in.read(buf, off, buf.length - off);
                if (n < 0) {
                    break;
                }
                off += n;
            }
            return new String(buf, 0, off, StandardCharsets.UTF_8);
        } finally {
            in.close();
        }
    }

    /** Дописать в конец файла (журналы). */
    public static void append(File f, byte[] data) throws IOException {
        File dir = f.getParentFile();
        if (dir != null && !dir.isDirectory() && !dir.mkdirs()) {
            throw new IOException("mkdir " + dir);
        }
        OutputStream out = new FileOutputStream(f, true);
        try {
            out.write(data);
        } finally {
            out.close();
        }
    }

    public static void write(File f, String text) throws IOException {
        write(f, text.getBytes(StandardCharsets.UTF_8));
    }

    public static void write(File f, byte[] data) throws IOException {
        File dir = f.getParentFile();
        if (dir != null && !dir.isDirectory() && !dir.mkdirs()) {
            throw new IOException("mkdir " + dir);
        }
        File tmp = new File(f.getPath() + ".tmp");
        OutputStream out = new FileOutputStream(tmp);
        try {
            out.write(data);
        } finally {
            out.close();
        }
        if (!tmp.renameTo(f)) {
            if (f.exists() && !f.delete()) {
                throw new IOException("delete " + f);
            }
            if (!tmp.renameTo(f)) {
                throw new IOException("rename " + tmp);
            }
        }
    }

    public static void writeText(File f, String text) throws IOException {
        write(f, text.getBytes(StandardCharsets.UTF_8));
    }

    /** Настройки: значения по умолчанию + сохранённые (неизвестные поля не теряются). */
    public static Map<String, Object> loadSettings(File f) {
        Map<String, Object> s = defaults();
        if (f.isFile()) {
            try {
                Map<String, Object> saved = Json.parseObject(read(f));
                s.putAll(saved);
            } catch (Exception e) {
                // испорченный файл — начинаем с настроек по умолчанию, а его сохраняем рядом
                f.renameTo(new File(f.getPath() + ".broken"));
            }
        }
        return s;
    }
}
