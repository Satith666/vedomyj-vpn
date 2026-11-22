package com.pultvpn.app.core;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * «Семья» — формат приглашений и посылок, как pult/family.py на компьютере (сверка — android/coretest/run.sh).
 * Приглашение vedomyj-family://i/… — имя помощника, имя устройства и случайный секрет (32 байта).
 * Посылка vedomyj-family://p/… — JSON, сжатый zlib, зашифрованный AES-128-CTR и подписанный HMAC-SHA256
 * ключами из секрета; у каждой — номер (старые не принимаются) и срок (7 дней). Менять можно только OPS.
 */
public final class Family {
    private Family() {
    }

    public static final String INVITE = "vedomyj-family://i/";
    public static final String PACKET = "vedomyj-family://p/";
    static final byte[] MAGIC = {'V', 'F', '1'};
    public static final long TTL = 7L * 24 * 3600;
    public static final int TO_DEVICE = 0, TO_HELPER = 1;
    static final int MAX_BODY = 512 * 1024;
    public static final List<String> OPS = Arrays.asList("sub_add", "sub_remove", "sub_update", "servers_add",
            "server_remove", "method", "set", "reconnect", "warp_create", "report");
    public static final List<String> SET_KEYS = Arrays.asList("block_ads", "dns_encrypted", "accel");
    public static final List<String> METHODS = Arrays.asList("auto", "server", "awg", "off");
    static final SecureRandom RND = new SecureRandom();

    /** Ошибка «Семьи» с понятным текстом. */
    public static final class FamilyError extends RuntimeException {
        public FamilyError(String text) {
            super(text);
        }
    }

    // ---------- формат ----------

    public static String b64u(byte[] b) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    public static byte[] unb64u(String s) {
        return java.util.Base64.getUrlDecoder().decode(s);
    }

    static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(key, "HmacSHA256"));
            return m.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String pairId(byte[] secret) {
        return Warp.toHex(hmac(secret, "vedomyj-family pair".getBytes(StandardCharsets.US_ASCII)), 0, 8);
    }

    static byte[][] keys(byte[] secret, int direction) {
        byte[] enc = Arrays.copyOf(hmac(secret, ("vedomyj-family enc " + direction).getBytes(StandardCharsets.US_ASCII)), 16);
        byte[] mac = hmac(secret, ("vedomyj-family mac " + direction).getBytes(StandardCharsets.US_ASCII));
        return new byte[][]{enc, mac};
    }

    static byte[] ctr(byte[] key, byte[] iv, byte[] data) {
        try {
            Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return c.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] newSecret() {
        byte[] s = new byte[32];
        RND.nextBytes(s);
        return s;
    }

    public static String makeInvite(String helper, String device, byte[] secret) {
        return INVITE + b64u(Json.canonical(Json.obj("v", 1, "h", helper, "d", device, "s", b64u(secret)))
                .getBytes(StandardCharsets.UTF_8));
    }

    private static final Pattern INVITE_RX = Pattern.compile(Pattern.quote(INVITE) + "([A-Za-z0-9_-]{20,4000})");
    private static final Pattern PACKET_RX = Pattern.compile(Pattern.quote(PACKET) + "([A-Za-z0-9_-]{40,})");

    /** {helper, device, secret(byte[])} или null — в тексте нет приглашения. */
    public static Map<String, Object> parseInvite(String text) {
        Matcher m = INVITE_RX.matcher(text == null ? "" : text);
        if (!m.find()) {
            return null;
        }
        Map<String, Object> d;
        byte[] secret;
        try {
            d = Json.parseObject(new String(unb64u(m.group(1)), StandardCharsets.UTF_8));
            secret = unb64u(Json.str(d, "s"));
        } catch (RuntimeException e) {
            throw new FamilyError(Text.t("Приглашение повреждено — попроси прислать его заново.",
                    "The invitation is damaged — ask to send it again."));
        }
        if (Json.num(d, "v", 0) != 1 || secret == null || secret.length != 32) {
            throw new FamilyError(Text.t("Приглашение от другой версии программы — обнови VEDOMYJ VPN.",
                    "The invitation is from another app version — update VEDOMYJ VPN."));
        }
        String h = Text.shorten(Json.str(d, "h"), 40);
        return Json.obj("helper", h.isEmpty() ? Text.t("Помощник", "Helper") : h, "device", Text.shorten(Json.str(d, "d"), 40),
                "secret", secret);
    }

    public static String seal(byte[] secret, int direction, long seq, Map<String, Object> payload, byte[] iv) {
        byte[] json = Json.canonical(payload).getBytes(StandardCharsets.UTF_8);
        Deflater df = new Deflater(9);
        df.setInput(json);
        df.finish();
        ByteArrayOutputStream zb = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        while (!df.finished()) {
            zb.write(buf, 0, df.deflate(buf));
        }
        df.end();
        byte[][] k = keys(secret, direction);
        if (iv == null) {
            iv = new byte[16];
            RND.nextBytes(iv);
        }
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        head.write(MAGIC, 0, 3);
        head.write(direction);
        byte[] pair = Warp.hex(pairId(secret));
        head.write(pair, 0, 8);
        for (int i = 7; i >= 0; i--) {
            head.write((int) (seq >>> (i * 8)) & 0xFF);
        }
        byte[] h = head.toByteArray();
        byte[] ct = ctr(k[0], iv, zb.toByteArray());
        byte[] signed = concat(h, iv, ct);
        return PACKET + b64u(concat(signed, hmac(k[1], signed)));
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            o.write(p, 0, p.length);
        }
        return o.toByteArray();
    }

    /** Посылка в тексте: {pair, direction, seq, raw} или null. */
    public static Map<String, Object> peek(String text) {
        Matcher m = PACKET_RX.matcher(text == null ? "" : text);
        if (!m.find()) {
            return null;
        }
        byte[] raw;
        try {
            raw = unb64u(m.group(1));
        } catch (IllegalArgumentException e) {
            raw = new byte[0];
        }
        if (raw.length < 3 + 1 + 8 + 8 + 16 + 32 || raw[0] != 'V' || raw[1] != 'F' || raw[2] != '1' || (raw[3] != 0 && raw[3] != 1)) {
            throw new FamilyError(Text.t("Посылка повреждена — попроси прислать её заново.",
                    "The package is damaged — ask to send it again."));
        }
        long seq = 0;
        for (int i = 12; i < 20; i++) {
            seq = (seq << 8) | (raw[i] & 0xFF);
        }
        return Json.obj("pair", Warp.toHex(raw, 4, 12), "direction", (long) raw[3], "seq", seq, "raw", raw);
    }

    public static Map<String, Object> open(byte[] secret, byte[] raw) {
        byte[][] k = keys(secret, raw[3]);
        byte[] signed = Arrays.copyOfRange(raw, 0, raw.length - 32);
        if (!MessageDigest.isEqual(hmac(k[1], signed), Arrays.copyOfRange(raw, raw.length - 32, raw.length))) {
            throw new FamilyError(Text.t("Посылка не прошла проверку подписи: она испорчена или не от твоей семьи.",
                    "The package failed the signature check: it is damaged or not from your family."));
        }
        byte[] body = ctr(k[0], Arrays.copyOfRange(raw, 20, 36), Arrays.copyOfRange(raw, 36, raw.length - 32));
        try {
            Inflater inf = new Inflater();
            inf.setInput(body);
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            while (!inf.finished()) {
                int n = inf.inflate(buf);
                if (n == 0 && (inf.needsInput() || inf.needsDictionary())) {
                    break;
                }
                o.write(buf, 0, n);
                if (o.size() > MAX_BODY) {
                    throw new DataFormatException("too large");
                }
            }
            inf.end();
            Object v = Json.parse(new String(o.toByteArray(), StandardCharsets.UTF_8));
            if (!(v instanceof Map)) {
                throw new DataFormatException("not an object");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) v;
            return m;
        } catch (DataFormatException | RuntimeException e) {
            throw new FamilyError(Text.t("Посылка не читается.", "The package cannot be read."));
        }
    }

    /** Только известные изменения и разумные размеры — иначе посылка целиком не принимается. */
    public static List<Map<String, Object>> checkOps(Object raw) {
        List<Object> ops = Json.list(raw);
        if (ops == null || ops.isEmpty() || ops.size() > 40) {
            throw new FamilyError(Text.t("В посылке нет изменений.", "The package has no changes."));
        }
        List<Map<String, Object>> out = new ArrayList<Map<String, Object>>();
        for (Object x : ops) {
            Map<String, Object> op = Json.map(x);
            if (op == null || !OPS.contains(Json.str(op, "op"))) {
                throw new FamilyError(Text.t("В посылке неизвестное изменение — обнови программу.",
                        "The package has an unknown change — update the app."));
            }
            String kind = Json.str(op, "op");
            Map<String, Object> o = new LinkedHashMap<String, Object>();
            o.put("op", kind);
            for (String k : new String[]{"url", "name", "id", "text", "method"}) {
                if (op.containsKey(k)) {
                    Object v = op.get(k);
                    if (!(v instanceof String) || ((String) v).length() > ("text".equals(k) ? 60000 : 4000)) {
                        throw new FamilyError(Text.t("В посылке слишком длинное значение.", "The package has a value that is too long."));
                    }
                    o.put(k, v);
                }
            }
            if ("method".equals(kind) && !METHODS.contains(Json.str(o, "method"))) {
                throw new FamilyError(Text.t("В посылке неизвестный способ.", "The package has an unknown mode."));
            }
            if ("set".equals(kind)) {
                Map<String, Object> vals = Json.map(op, "values");
                if (vals == null || vals.isEmpty()) {
                    throw new FamilyError(Text.t("В посылке неизвестная настройка.", "The package has an unknown setting."));
                }
                for (Map.Entry<String, Object> en : vals.entrySet()) {
                    if (!SET_KEYS.contains(en.getKey()) || !(en.getValue() instanceof Boolean)) {
                        throw new FamilyError(Text.t("В посылке неизвестная настройка.", "The package has an unknown setting."));
                    }
                }
                o.put("values", new LinkedHashMap<String, Object>(vals));
            }
            if ("sub_add".equals(kind) && !Json.str(o, "url").matches("^https?://.*")) {
                throw new FamilyError(Text.t("В посылке подписка без ссылки https://.", "The package has a subscription without an https:// link."));
            }
            if (("sub_remove".equals(kind) || "server_remove".equals(kind)) && Json.str(o, "id").isEmpty() && Json.str(o, "url").isEmpty()) {
                throw new FamilyError(Text.t("В посылке не сказано, что удалить.", "The package does not say what to remove."));
            }
            if ("servers_add".equals(kind) && Json.str(o, "text").isEmpty()) {
                throw new FamilyError(Text.t("В посылке нет серверов.", "The package has no servers."));
            }
            out.add(o);
        }
        return out;
    }

    /** Что поменяется — по-человечески, для «Установить?». */
    public static List<Object> summary(List<Map<String, Object>> ops) {
        List<Object> out = new ArrayList<Object>();
        for (Map<String, Object> o : ops) {
            String k = Json.str(o, "op");
            String t;
            switch (k) {
                case "sub_add":
                    t = Text.t("добавить подписку", "add subscription");
                    break;
                case "sub_remove":
                    t = Text.t("удалить подписку", "remove subscription");
                    break;
                case "sub_update":
                    t = Text.t("обновить подписки", "update subscriptions");
                    break;
                case "servers_add":
                    t = Text.t("добавить серверы", "add servers");
                    break;
                case "server_remove":
                    t = Text.t("удалить сервер", "remove server");
                    break;
                case "method":
                    t = Text.t("сменить способ: ", "change mode: ") + methodName(Json.str(o, "method"));
                    break;
                case "set": {
                    StringBuilder b = new StringBuilder(Text.t("переключить функции: ", "switch features: "));
                    boolean first = true;
                    for (Map.Entry<String, Object> en : Json.map(o, "values").entrySet()) {
                        if (!first) {
                            b.append(", ");
                        }
                        first = false;
                        boolean on = Boolean.TRUE.equals(en.getValue());
                        String name = "block_ads".equals(en.getKey()) ? Text.t("без рекламы", "no ads")
                                : "dns_encrypted".equals(en.getKey()) ? Text.t("шифрование DNS", "DNS encryption")
                                : Text.t("ускорение YouTube и Discord", "YouTube and Discord acceleration");
                        b.append(name).append(" — ").append(on ? Text.t("вкл", "on") : Text.t("выкл", "off"));
                    }
                    t = b.toString();
                    break;
                }
                case "reconnect":
                    t = Text.t("переподключить VPN", "reconnect the VPN");
                    break;
                case "warp_create":
                    t = Text.t("создать бесплатный WARP", "create a free WARP");
                    break;
                default:
                    t = Text.t("прислать состояние", "send the state");
            }
            if (("sub_add".equals(k) || "sub_remove".equals(k)) && !Json.str(o, "name").isEmpty()) {
                t += " «" + Text.shorten(Json.str(o, "name"), 40) + "»";
            }
            out.add(t);
        }
        return out;
    }

    static String methodName(String m) {
        switch (m) {
            case "server":
                return Text.t("VPN-сервер", "VPN server");
            case "awg":
                return "AmneziaWG";
            case "off":
                return Text.t("Без VPN", "Without VPN");
            default:
                return Text.t("Авто", "Auto");
        }
    }

    public static String serverId(String link) {
        return Text.sha1hex(link == null ? "" : link).substring(0, 12);
    }

    // ---------- доставка сама: почтовый ящик в сети торрентов (Dht.java, шаг 2; как family.py) ----------

    public static final byte[][] DHT_SALT = {"vf1/d0".getBytes(StandardCharsets.US_ASCII), "vf1/d1".getBytes(StandardCharsets.US_ASCII)};
    public static final int PART = 900;
    public static final int MAX_PARTS = 16;

    /** Ключ записей пары — из её секрета: у помощника и устройства он один и тот же. */
    public static Dht.Keys dhtKeys(byte[] secret) {
        return new Dht.Keys(hmac(secret, "vedomyj-family dht".getBytes(StandardCharsets.US_ASCII)));
    }

    public static byte[] rawOf(String text) {
        Map<String, Object> pk = peek(text);
        if (pk == null) {
            throw new FamilyError(Text.t("Здесь нет посылки «Семьи».", "There is no Family package here."));
        }
        return (byte[]) pk.get("raw");
    }

    static byte[] partSalt(int direction, long seq, int i) {
        return concat(DHT_SALT[direction], ("/" + seq + "/" + i).getBytes(StandardCharsets.US_ASCII));
    }

    /** Посылка → записи: главная (номер = номер посылки, хеш, число частей, первая часть) и остальные части. */
    public static List<Map<String, Object>> dhtItems(Dht.Keys keys, int direction, long seq, byte[] raw) {
        List<byte[]> parts = new ArrayList<byte[]>();
        for (int i = 0; i < raw.length; i += PART) {
            parts.add(Arrays.copyOfRange(raw, i, Math.min(raw.length, i + PART)));
        }
        if (parts.isEmpty()) {
            parts.add(new byte[0]);
        }
        if (parts.size() > MAX_PARTS) {
            throw new FamilyError(Text.t("Посылка слишком большая для доставки самой — отправь её текстом.",
                    "The package is too big to deliver by itself — send it as text."));
        }
        Map<String, Object> head = new LinkedHashMap<String, Object>();
        head.put("h", Arrays.copyOf(Dht.sha("SHA-256", raw), 16));
        head.put("n", (long) parts.size());
        head.put("p", parts.get(0));
        List<Map<String, Object>> out = new ArrayList<Map<String, Object>>();
        out.add(keys.item(DHT_SALT[direction], seq, head));
        for (int i = 1; i < parts.size(); i++) {
            out.add(keys.item(partSalt(direction, seq, i), 1, parts.get(i)));
        }
        return out;
    }

    /** Новый клиент сети на каждый поиск. */
    public interface ClientFor {
        Dht.Client make();
    }

    /** Новая посылка из ящика (номер больше afterSeq) → байты или null. */
    @SuppressWarnings("unchecked")
    public static byte[] dhtFetch(ClientFor cf, Dht.Keys keys, int direction, long afterSeq) throws java.io.IOException {
        Object[] head = cf.make().get(keys.pub, DHT_SALT[direction]);
        if (head == null || (Long) head[0] <= afterSeq) {
            return null;
        }
        long seq = (Long) head[0];
        Map<String, Object> v = head[1] instanceof Map ? (Map<String, Object>) head[1] : null;
        if (v == null || !(v.get("p") instanceof byte[]) || !(v.get("n") instanceof Long) || !(v.get("h") instanceof byte[])
                || (Long) v.get("n") < 1 || (Long) v.get("n") > MAX_PARTS) {
            throw new FamilyError(Text.t("Посылка в сети повреждена.", "The package in the network is damaged."));
        }
        int n = (int) (long) (Long) v.get("n");
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] first = (byte[]) v.get("p");
        out.write(first, 0, first.length);
        for (int i = 1; i < n; i++) {
            Object[] got = cf.make().get(keys.pub, partSalt(direction, seq, i));
            if (got == null || !(got[1] instanceof byte[])) {
                throw new FamilyError(Text.t("Часть посылки " + (i + 1) + " из " + n + " пока не нашлась в сети.",
                        "Part " + (i + 1) + " of " + n + " of the package is not in the network yet."));
            }
            byte[] b = (byte[]) got[1];
            out.write(b, 0, b.length);
        }
        byte[] raw = out.toByteArray();
        if (!Arrays.equals(Arrays.copyOf(Dht.sha("SHA-256", raw), 16), (byte[]) v.get("h"))) {
            throw new FamilyError(Text.t("Посылка в сети собралась с ошибкой.", "The package from the network was assembled with an error."));
        }
        return raw;
    }
}
