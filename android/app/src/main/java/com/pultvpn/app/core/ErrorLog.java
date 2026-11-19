package com.pultvpn.app.core;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Журнал ошибок (errors.jsonl в папке приложения) — то же, что pult/errorlog.py на компьютере:
 * сбои кода с трассировкой, проблемы («!»), итоги проверок с ошибками. Одинаковые записи склеиваются.
 * Ссылки, ключи и адреса вычищаются (Diagnostics.scrub) — записи можно выложить в заявку на GitHub.
 */
public final class ErrorLog {
    public static final int MAX_ENTRIES = 300;
    static final int ISSUE_BODY_LIMIT = 6000;
    private static final Pattern REPO = Pattern.compile("github\\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)");

    public interface Scrubber {
        String scrub(String text);
    }

    private final File file;
    private final Scrubber scrubber;
    private final String version;
    private final String os;
    private final List<Map<String, Object>> entries = new ArrayList<Map<String, Object>>();

    public ErrorLog(File dir, String version, String os, Scrubber scrubber) {
        this.file = new File(dir, "errors.jsonl");
        this.version = version;
        this.os = os;
        this.scrubber = scrubber;
        load();
    }

    /** Неожиданное исключение (ошибка в коде), а не понятная ошибка сети или настроек. */
    public static boolean isBug(Throwable e) {
        return !(e instanceof java.io.IOException) && !(e instanceof Engine.UserError)
                && !(e instanceof Engine.Cancelled) && !(e instanceof InterruptedException);
    }

    public static String repoFrom(String url) {
        Matcher m = REPO.matcher(url == null ? "" : url);
        if (!m.find()) {
            return "";
        }
        String name = m.group(2).endsWith(".git") ? m.group(2).substring(0, m.group(2).length() - 4) : m.group(2);
        return name.isEmpty() ? "" : m.group(1) + "/" + name;
    }

    private void load() {
        try {
            if (!file.isFile()) {
                return;
            }
            String text = Store.read(file);
            for (String line : text.split("\n")) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }
                try {
                    Map<String, Object> m = Json.parseObject(line);
                    if (m != null && !Json.str(m, "title").isEmpty()) {
                        entries.add(m);
                    }
                } catch (Exception ignored) {
                    // битая строка — пропускаем
                }
            }
            while (entries.size() > MAX_ENTRIES) {
                entries.remove(0);
            }
        } catch (Exception ignored) {
            // журнал — помощник
        }
    }

    private void save() {
        try {
            StringBuilder b = new StringBuilder();
            for (Map<String, Object> m : entries) {
                b.append(Json.write(m)).append('\n');
            }
            Store.write(file, b.toString().getBytes(StandardCharsets.UTF_8));
        } catch (Exception ignored) {
            // журнал — помощник
        }
    }

    private String clean(String s, int limit, boolean tail) {
        String out = s == null ? "" : s;
        try {
            out = scrubber == null ? out : scrubber.scrub(out);
        } catch (Exception ignored) {
            // как есть
        }
        if (out.length() > limit) {
            out = tail ? out.substring(out.length() - limit) : out.substring(0, limit);
        }
        return out;
    }

    static String signature(String kind, String where, String title) {
        String norm = (kind + "|" + where + "|" + title).toLowerCase(Locale.ROOT).replaceAll("\\d+", "#");
        try {
            byte[] h = MessageDigest.getInstance("SHA-1").digest(norm.getBytes(StandardCharsets.UTF_8));
            StringBuilder b = new StringBuilder();
            for (int i = 0; i < 6; i++) {
                b.append(String.format(Locale.ROOT, "%02x", h[i]));
            }
            return b.toString();
        } catch (Exception e) {
            return Integer.toHexString(norm.hashCode());
        }
    }

    public synchronized Map<String, Object> record(String kind, String title, String detail, String trace, String where) {
        title = clean(title, 300, false);
        detail = clean(detail, 1500, false);
        trace = clean(trace, 4000, true);
        where = clean(where, 120, false);
        String sig = signature(kind, where, title);
        long now = System.currentTimeMillis() / 1000L;
        for (int i = entries.size() - 1; i >= 0; i--) {
            Map<String, Object> m = entries.get(i);
            if (sig.equals(Json.str(m, "sig")) && version.equals(Json.str(m, "version"))) {
                m.put("count", Json.num(m, "count", 1) + 1);
                m.put("last", now);
                if (!detail.isEmpty()) {
                    m.put("detail", detail);
                }
                if (!trace.isEmpty()) {
                    m.put("trace", trace);
                }
                entries.remove(i);
                entries.add(m);
                save();
                return m;
            }
        }
        Map<String, Object> m = Json.obj("id", sig + "-" + now, "sig", sig, "kind", kind, "title", title, "detail", detail,
                "trace", trace, "where", where, "version", version, "os", os, "first", now, "last", now, "count", 1L);
        entries.add(m);
        while (entries.size() > MAX_ENTRIES) {
            entries.remove(0);
        }
        save();
        return m;
    }

    public Map<String, Object> recordExc(Throwable e, String where) {
        StringWriter w = new StringWriter();
        e.printStackTrace(new PrintWriter(w));
        String msg = e.getMessage();
        String title = e.getClass().getSimpleName() + (msg == null || msg.isEmpty() ? "" : ": " + msg);
        return record("crash", title, "", w.toString(), where);
    }

    public synchronized List<Map<String, Object>> recent(int limit) {
        List<Map<String, Object>> out = new ArrayList<Map<String, Object>>(entries.subList(Math.max(0, entries.size() - limit),
                entries.size()));
        Collections.reverse(out);
        return out;
    }

    public synchronized int size() {
        return entries.size();
    }

    public synchronized void clear() {
        entries.clear();
        save();
    }

    public File file() {
        return file;
    }

    /** Готовая заявка: {title, body} в разметке GitHub. */
    public Map<String, Object> issueText(int limit) {
        List<Map<String, Object>> chosen = recent(limit);
        if (chosen.isEmpty()) {
            return Json.obj("title", "", "body", "");
        }
        Map<String, Object> head = chosen.get(0);
        String title = "[" + Json.str(head, "version") + "] " + Json.str(head, "title");
        if (title.length() > 120) {
            title = title.substring(0, 120);
        }
        SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US);
        StringBuilder b = new StringBuilder();
        b.append("**Версия:** ").append(version).append(" (Android) · **Система:** ").append(os).append("\n\n")
                .append("Записи из журнала ошибок (ссылки, ключи и адреса вычищены программой):\n\n");
        for (Map<String, Object> m : chosen) {
            b.append("### ").append(Json.str(m, "title")).append('\n');
            b.append("- вид: `").append(Json.str(m, "kind")).append("`, где: `").append(Json.str(m, "where"))
                    .append("`, раз: ").append(Json.num(m, "count", 1)).append(", последний: ")
                    .append(f.format(new Date(Json.num(m, "last", 0) * 1000L))).append('\n');
            if (!Json.str(m, "detail").isEmpty()) {
                b.append("- подробности: ").append(Json.str(m, "detail")).append('\n');
            }
            String trace = Json.str(m, "trace");
            if (!trace.isEmpty()) {
                b.append("\n```\n").append(trace.length() > 1500 ? trace.substring(0, 1500) : trace).append("\n```\n");
            }
            b.append('\n');
        }
        b.append("**Что я делал перед ошибкой:**\n\n<!-- опиши своими словами -->");
        String body = b.toString();
        if (body.length() > ISSUE_BODY_LIMIT) {
            body = body.substring(0, ISSUE_BODY_LIMIT - 40) + "\n…(обрезано)";
        }
        return Json.obj("title", title, "body", body);
    }

    public String issueUrl(String repo, int limit) {
        if (repo == null || repo.isEmpty()) {
            return "";
        }
        Map<String, Object> t = issueText(limit);
        if (Json.str(t, "title").isEmpty()) {
            return "";
        }
        try {
            return "https://github.com/" + repo + "/issues/new?title=" + URLEncoder.encode(Json.str(t, "title"), "UTF-8")
                    + "&body=" + URLEncoder.encode(Json.str(t, "body"), "UTF-8") + "&labels=bug";
        } catch (java.io.UnsupportedEncodingException e) {
            return "";
        }
    }
}
