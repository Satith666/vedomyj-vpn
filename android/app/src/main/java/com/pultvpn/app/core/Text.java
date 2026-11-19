package com.pultvpn.app.core;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Pattern;

/** Строки: язык интерфейса, декодирование ссылок, base64, хэши, проверка адресов. */
public final class Text {
    private Text() {
    }

    /** Язык сообщений: "ru" или "en". Меняется из настроек. */
    public static volatile String lang = "ru";

    /** Сообщение на выбранном языке: каждая фраза пишется сразу в двух вариантах. */
    public static String t(String ru, String en) {
        return "en".equals(lang) ? en : ru;
    }

    /** Как unquote в Python: %XX → байты UTF-8, плюс остаётся плюсом. */
    public static String unquote(String s) {
        if (s == null || s.indexOf('%') < 0) {
            return s == null ? "" : s;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        StringBuilder b = new StringBuilder();
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == '%' && isHex(s, i + 1) && isHex(s, i + 2)) {
                out.write(Integer.parseInt(s.substring(i + 1, i + 3), 16));
                i += 3;
                continue;
            }
            if (out.size() > 0) {
                b.append(new String(out.toByteArray(), StandardCharsets.UTF_8));
                out.reset();
            }
            b.append(c);
            i++;
        }
        if (out.size() > 0) {
            b.append(new String(out.toByteArray(), StandardCharsets.UTF_8));
        }
        return b.toString();
    }

    private static boolean isHex(String s, int i) {
        if (i >= s.length()) {
            return false;
        }
        char c = s.charAt(i);
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    /** Кодирование для ссылок (как quote в Python с safe=""). */
    public static String quote(String s) {
        StringBuilder b = new StringBuilder();
        for (byte by : s.getBytes(StandardCharsets.UTF_8)) {
            int c = by & 0xff;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
                    || c == '.' || c == '~') {
                b.append((char) c);
            } else {
                b.append('%').append(String.format("%02X", c));
            }
        }
        return b.toString();
    }

    /** Base64 в любом виде: обычный, url-safe, без выравнивания, с переносами строк. null — не base64. */
    public static byte[] b64decode(String data) {
        if (data == null) {
            return null;
        }
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < data.length(); i++) {
            char c = data.charAt(i);
            if (!Character.isWhitespace(c)) {
                b.append(c == '-' ? '+' : c == '_' ? '/' : c);
            }
        }
        while (b.length() % 4 != 0) {
            b.append('=');
        }
        try {
            return Base64.getDecoder().decode(b.toString());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Base64 → текст UTF-8. null — если это не base64 или не текст. */
    public static String b64text(String data) {
        byte[] raw = b64decode(data);
        if (raw == null) {
            return null;
        }
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }

    public static String b64encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static String sha1hex(String s) {
        return hashHex("SHA-1", s);
    }

    public static String sha256hex(String s) {
        return hashHex("SHA-256", s);
    }

    private static String hashHex(String alg, String s) {
        try {
            byte[] d = MessageDigest.getInstance(alg).digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder b = new StringBuilder();
            for (byte x : d) {
                b.append(String.format("%02x", x & 0xff));
            }
            return b.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static final SecureRandom RNG = new SecureRandom();

    /** Случайная строка из букв и цифр без похожих символов (0/O, 1/l). */
    public static String randomWord(int len) {
        String abc = "abcdefghijkmnpqrstuvwxyz23456789";
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < len; i++) {
            b.append(abc.charAt(RNG.nextInt(abc.length())));
        }
        return b.toString();
    }

    // ---------- адреса ----------

    private static final Pattern IPV4 = Pattern.compile("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})");
    private static final Pattern IPV6 = Pattern.compile("[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*");

    public static boolean isIPv4(String s) {
        java.util.regex.Matcher m = IPV4.matcher(s == null ? "" : s);
        if (!m.matches()) {
            return false;
        }
        for (int i = 1; i <= 4; i++) {
            if (Integer.parseInt(m.group(i)) > 255) {
                return false;
            }
        }
        return true;
    }

    public static boolean isIPv6(String s) {
        if (s == null || !IPV6.matcher(s).matches() || s.length() < 2 || s.length() > 45) {
            return false;
        }
        int dbl = s.indexOf("::");
        if (dbl >= 0 && s.indexOf("::", dbl + 1) >= 0) {
            return false;
        }
        String[] parts = s.split(":", -1);
        return parts.length >= 3 && parts.length <= 8 || (dbl >= 0 && parts.length <= 9);
    }

    public static boolean isIp(String s) {
        return isIPv4(s) || isIPv6(s);
    }

    /** IP или подсеть вида 10.0.0.0/8, fc00::/7. */
    public static boolean isIpOrCidr(String s) {
        if (s == null) {
            return false;
        }
        int slash = s.indexOf('/');
        if (slash < 0) {
            return isIp(s);
        }
        String ip = s.substring(0, slash);
        String bits = s.substring(slash + 1);
        if (!bits.matches("\\d{1,3}")) {
            return false;
        }
        int n = Integer.parseInt(bits);
        if (isIPv4(ip)) {
            return n <= 32;
        }
        return isIPv6(ip) && n <= 128;
    }

    private static long v4(String ip) {
        String[] p = ip.split("\\.");
        long r = 0;
        for (String x : p) {
            r = (r << 8) | Integer.parseInt(x);
        }
        return r;
    }

    /** Входит ли IPv4-адрес в подсеть. */
    public static boolean inV4(String ip, String cidr) {
        if (!isIPv4(ip)) {
            return false;
        }
        String[] c = cidr.split("/");
        if (!isIPv4(c[0])) {
            return false;
        }
        int bits = c.length > 1 ? Integer.parseInt(c[1]) : 32;
        long mask = bits == 0 ? 0 : (0xFFFFFFFFL << (32 - bits)) & 0xFFFFFFFFL;
        return (v4(ip) & mask) == (v4(c[0]) & mask);
    }

    /** Локальный или частный адрес (сервер в своей сети — без TLS это нормально). */
    public static boolean isPrivateHost(String host) {
        String h = host == null ? "" : host.trim().toLowerCase();
        if (h.startsWith("[") && h.endsWith("]")) {
            h = h.substring(1, h.length() - 1);
        }
        if (isIPv4(h)) {
            String[] nets = {"0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
                    "192.168.0.0/16", "100.64.0.0/10", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24",
                    "203.0.113.0/24", "240.0.0.0/4"};
            for (String n : nets) {
                if (inV4(h, n)) {
                    return true;
                }
            }
            return false;
        }
        if (isIPv6(h)) {
            return h.equals("::1") || h.equals("::") || h.startsWith("fc") || h.startsWith("fd")
                    || h.startsWith("fe8") || h.startsWith("fe9") || h.startsWith("fea") || h.startsWith("feb");
        }
        return h.equals("localhost") || h.endsWith(".local") || h.endsWith(".lan") || h.endsWith(".internal")
                || h.endsWith(".home.arpa") || h.endsWith(".localhost");
    }

    public static String shorten(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, Math.max(0, max - 1)) + "…";
    }
}
