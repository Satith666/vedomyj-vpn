package com.pultvpn.app.core;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Журнал подключения (journal.jsonl) — то же, что pult/journal.py на компьютере: когда, что и почему
 * приложение подключило, переключило или отключило; кто это сделал — ты или автоматика (и какая).
 * Адресов и ключей нет: причины проходят через Diagnostics.scrub.
 */
public final class Journal {
    public static final int KEEP = 300;
    static final String[][] KINDS = {
            {"connect", "Подключение", "Connected"},
            {"switch", "Смена сервера", "Server switch"},
            {"hotswap", "Смена сервера без перезапуска", "Server switch without restart"},
            {"reconnect", "Переподключение", "Reconnecting"},
            {"disconnect", "Отключение", "Disconnected"},
            {"fail", "Не удалось подключиться", "Failed to connect"},
    };

    private final File file;
    private final ErrorLog.Scrubber scrubber;
    private final List<Map<String, Object>> items = new ArrayList<Map<String, Object>>();
    private int writes;

    public Journal(File dir, ErrorLog.Scrubber scrubber) {
        this.file = new File(dir, "journal.jsonl");
        this.scrubber = scrubber;
        try {
            if (file.isFile()) {
                for (String line : Store.read(file).split("\n")) {
                    line = line.trim();
                    if (line.isEmpty()) {
                        continue;
                    }
                    try {
                        Map<String, Object> m = Json.parseObject(line);
                        if (m != null && kindText(Json.str(m, "kind"), true) != null) {
                            items.add(m);
                        }
                    } catch (Exception ignored) {
                        // битая строка — пропускаем
                    }
                }
                while (items.size() > KEEP) {
                    items.remove(0);
                }
            }
        } catch (Exception ignored) {
            // журнал — помощник
        }
    }

    static String kindText(String kind, boolean ru) {
        for (String[] k : KINDS) {
            if (k[0].equals(kind)) {
                return ru ? k[1] : k[2];
            }
        }
        return null;
    }

    public synchronized Map<String, Object> add(String kind, String server, String who, String why, String engine) {
        String clean = why == null ? "" : why;
        try {
            clean = scrubber == null ? clean : scrubber.scrub(clean);
        } catch (Exception ignored) {
            // как есть
        }
        Map<String, Object> m = new LinkedHashMap<String, Object>();
        m.put("t", System.currentTimeMillis() / 1000.0);
        m.put("kind", kind);
        m.put("server", Text.shorten(server == null ? "" : server, 80));
        m.put("who", Text.shorten(who == null ? "" : who, 80));
        m.put("why", Text.shorten(clean, 200));
        m.put("engine", engine == null ? "" : engine);
        items.add(m);
        while (items.size() > KEEP) {
            items.remove(0);
        }
        save();
        return m;
    }

    private void save() {
        try {
            if (++writes % 50 == 0 || !file.isFile()) {
                StringBuilder b = new StringBuilder();
                for (Map<String, Object> m : items) {
                    b.append(Json.write(m)).append('\n');
                }
                Store.write(file, b.toString().getBytes(StandardCharsets.UTF_8));
            } else {
                Store.append(file, (Json.write(items.get(items.size() - 1)) + "\n").getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception ignored) {
            // журнал — помощник
        }
    }

    /** Последние n записей, новые сверху. */
    public synchronized List<Map<String, Object>> recent(int n) {
        List<Map<String, Object>> out = new ArrayList<Map<String, Object>>(
                items.subList(Math.max(0, items.size() - n), items.size()));
        Collections.reverse(out);
        return out;
    }

    /** Сколько раз за seconds секунд приложение само переподключало (без твоих нажатий). */
    public synchronized int autoCount(long seconds) {
        double since = System.currentTimeMillis() / 1000.0 - seconds;
        int n = 0;
        for (Map<String, Object> m : items) {
            String k = Json.str(m, "kind");
            if (Json.num(m, "t", 0L) >= since && !"user".equals(Json.str(m, "who"))
                    && ("switch".equals(k) || "hotswap".equals(k) || "reconnect".equals(k) || "fail".equals(k))) {
                n++;
            }
        }
        return n;
    }

    /** Для окна: записи (с понятным названием) и сколько раз приложение переподключало само. */
    public Map<String, Object> state() {
        boolean ru = !"en".equals(Text.lang);
        List<Object> list = new ArrayList<Object>();
        for (Map<String, Object> m : recent(30)) {
            Map<String, Object> c = new LinkedHashMap<String, Object>(m);
            String kt = kindText(Json.str(m, "kind"), ru);
            c.put("kind_text", kt == null ? Json.str(m, "kind") : kt);
            list.add(c);
        }
        return Json.obj("items", list, "auto_hour", autoCount(3600), "auto_day", autoCount(86400));
    }

    /** Строки для отчёта: сводка и последние записи. */
    public String reportText(int n) {
        boolean ru = !"en".equals(Text.lang);
        StringBuilder b = new StringBuilder();
        List<Map<String, Object>> all = recent(KEEP);
        b.append(ru ? "Журнал подключения: " : "Connection journal: ").append(all.size())
                .append(ru ? " записей; само приложение — " : " entries; by the app itself — ")
                .append(autoCount(3600)).append(ru ? " за час, " : " per hour, ")
                .append(autoCount(86400)).append(ru ? " за сутки" : " per day").append('\n');
        SimpleDateFormat f = new SimpleDateFormat("dd.MM HH:mm:ss", Locale.US);
        int i = 0;
        for (Map<String, Object> m : all) {
            if (i++ >= n) {
                break;
            }
            String kt = kindText(Json.str(m, "kind"), ru);
            String who = Json.str(m, "who");
            b.append(f.format(new Date(Json.num(m, "t", 0L) * 1000L))).append("  ")
                    .append(kt == null ? Json.str(m, "kind") : kt);
            if (!Json.str(m, "server").isEmpty()) {
                b.append(" — ").append(Json.str(m, "server"));
            }
            b.append(" (").append("user".equals(who) ? (ru ? "ты" : "you") : who.isEmpty() ? (ru ? "приложение" : "app") : who)
                    .append(')');
            if (!Json.str(m, "why").isEmpty()) {
                b.append(": ").append(Json.str(m, "why"));
            }
            b.append('\n');
        }
        return b.toString();
    }
}
