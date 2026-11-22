package com.pultvpn.app.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Бесплатный WARP (Cloudflare) своим конфигом AmneziaWG — то же, что pult/warp.py на компьютере (результат
 * совпадает байт в байт: это проверяет самопроверка).
 * Ключи X25519 создаются на телефоне, Cloudflare получает только открытый. Сервер WARP — обычный WireGuard,
 * поэтому из маскировки работают только «мусорные» пакеты перед подключением и пакет-обманка I1 (QUIC, DNS,
 * STUN, SIP); S1–S4 = 0, H1–H4 = 1…4. Наборов обманок несколько: на телефоне туннель включает приложение
 * AmneziaWG, поэтому следующий набор выбирается кнопкой «Другие обманки».
 * Идея наборов и генераторов I1 — по мотивам warpscout (MIT, (c) 2026 Nikita S.) и wgcf (MIT, (c) 2020 ViRb3).
 */
public final class Warp {
    private Warp() {
    }

    public static final String PEER_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";
    public static final String API_VERSION = "v0a5641";
    public static final String CLIENT_VERSION = "a-6.38.9-5641";
    public static final String USER_AGENT = "1.1.1.1/6.38.9-5641 (Android 16.0.0)";
    public static final String[] API_HOSTS = {"api.cloudflareclient.com", "api.devices.cloudflare.com"};
    public static final String NAME = "WARP (бесплатный)";
    public static final int QUIC_SIZE = 1200;
    static final SecureRandom RND = new SecureRandom();

    /** Регистрация не удалась; kind: blocked (нет связи), limit (403/429), bad (непонятный ответ). */
    public static final class WarpError extends Exception {
        public final String kind;

        WarpError(String text, String kind) {
            super(text);
            this.kind = kind;
        }
    }

    // ---------- X25519 (RFC 7748) ----------

    private static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger A24 = BigInteger.valueOf(121665);

    private static BigInteger le(byte[] b) {
        byte[] r = new byte[b.length + 1];
        for (int i = 0; i < b.length; i++) {
            r[b.length - i] = b[i];
        }
        return new BigInteger(r);
    }

    private static byte[] toLe(BigInteger x) {
        byte[] be = x.toByteArray();
        byte[] out = new byte[32];
        for (int i = 0; i < 32 && i < be.length; i++) {
            out[i] = be[be.length - 1 - i];
        }
        return out;
    }

    public static byte[] x25519(byte[] scalar, byte[] u) {
        byte[] k = scalar.clone();
        k[0] &= (byte) 248;
        k[31] &= 127;
        k[31] |= 64;
        BigInteger n = le(k);
        byte[] ub = u.clone();
        ub[31] &= 127;
        BigInteger x1 = le(ub).mod(P);
        BigInteger x2 = BigInteger.ONE, z2 = BigInteger.ZERO, x3 = x1, z3 = BigInteger.ONE;
        int swap = 0;
        for (int t = 254; t >= 0; t--) {
            int bit = n.testBit(t) ? 1 : 0;
            if ((swap ^ bit) == 1) {
                BigInteger tx = x2;
                x2 = x3;
                x3 = tx;
                BigInteger tz = z2;
                z2 = z3;
                z3 = tz;
            }
            swap = bit;
            BigInteger a = x2.add(z2).mod(P), b = x2.subtract(z2).mod(P);
            BigInteger aa = a.multiply(a).mod(P), bb = b.multiply(b).mod(P);
            BigInteger e = aa.subtract(bb).mod(P);
            BigInteger c = x3.add(z3).mod(P), d = x3.subtract(z3).mod(P);
            BigInteger da = d.multiply(a).mod(P), cb = c.multiply(b).mod(P);
            x3 = da.add(cb).pow(2).mod(P);
            z3 = x1.multiply(da.subtract(cb).pow(2)).mod(P);
            x2 = aa.multiply(bb).mod(P);
            z2 = e.multiply(aa.add(A24.multiply(e))).mod(P);
        }
        if (swap == 1) {
            x2 = x3;
            z2 = z3;
        }
        return toLe(x2.multiply(z2.modPow(P.subtract(BigInteger.valueOf(2)), P)).mod(P));
    }

    private static byte[] nine() {
        byte[] b = new byte[32];
        b[0] = 9;
        return b;
    }

    /** {закрытый, открытый} ключ WireGuard в base64. */
    public static String[] keypair(byte[] seed) {
        byte[] priv = seed != null ? seed.clone() : new byte[32];
        if (seed == null) {
            RND.nextBytes(priv);
        }
        priv[0] &= (byte) 248;
        priv[31] &= 127;
        priv[31] |= 64;
        return new String[]{Text.b64encode(priv), Text.b64encode(x25519(priv, nine()))};
    }

    public static String publicOf(String privB64) {
        return Text.b64encode(x25519(Text.b64decode(privB64), nine()));
    }

    // ---------- AES-128 и ключи QUIC (RFC 9001) ----------

    public static byte[] aes128Block(byte[] key, byte[] block) {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
            return c.doFinal(block);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(key, "HmacSHA256"));
            return m.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] hkdfLabel(byte[] secret, String label, int length) {
        byte[] full = ("tls13 " + label).getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream info = new ByteArrayOutputStream();
        info.write(length >> 8);
        info.write(length & 0xFF);
        info.write(full.length);
        info.write(full, 0, full.length);
        info.write(0);
        info.write(1);
        byte[] out = new byte[length];
        System.arraycopy(hmac(secret, info.toByteArray()), 0, out, 0, length);
        return out;
    }

    static final byte[] QUIC_SALT = hex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");

    /** {key, iv, hp} пакета Initial клиента. */
    public static byte[][] quicKeys(byte[] dcid) {
        byte[] initial = hmac(QUIC_SALT, dcid);
        byte[] client = hkdfLabel(initial, "client in", 32);
        return new byte[][]{hkdfLabel(client, "quic key", 16), hkdfLabel(client, "quic iv", 12), hkdfLabel(client, "quic hp", 16)};
    }

    // ---------- пакеты-обманки I1 (формат CPS AmneziaWG) ----------

    public static byte[] hex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return b;
    }

    public static String toHex(byte[] b, int from, int to) {
        StringBuilder sb = new StringBuilder();
        for (int i = from; i < to; i++) {
            sb.append(String.format(Locale.ROOT, "%02x", b[i] & 0xFF));
        }
        return sb.toString();
    }

    private static final class Chain {
        final StringBuilder sb = new StringBuilder();

        Chain raw(byte[] b, int from, int to) {
            if (to > from) {
                sb.append("<b 0x").append(toHex(b, from, to)).append('>');
            }
            return this;
        }

        Chain raw(byte[] b) {
            return raw(b, 0, b.length);
        }

        Chain text(String s) {
            return raw(s.getBytes(StandardCharsets.UTF_8));
        }

        Chain tag(String name, int n) {
            sb.append('<').append(name).append(' ').append(n).append('>');
            return this;
        }

        @Override
        public String toString() {
            return sb.toString();
        }
    }

    private static final class Buf extends ByteArrayOutputStream {
        Buf u8(int v) {
            write(v & 0xFF);
            return this;
        }

        Buf u16(int v) {
            write((v >> 8) & 0xFF);
            write(v & 0xFF);
            return this;
        }

        Buf u24(int v) {
            write((v >> 16) & 0xFF);
            return u16(v);
        }

        Buf u32(long v) {
            u16((int) ((v >> 16) & 0xFFFF));
            return u16((int) (v & 0xFFFF));
        }

        Buf put(byte[] b) {
            write(b, 0, b.length);
            return this;
        }
    }

    private static byte[] varint(int x) {
        if (x < 0x40) {
            return new byte[]{(byte) x};
        }
        if (x < 0x4000) {
            return new Buf().u16(x | 0x4000).toByteArray();
        }
        return new Buf().u32(x | 0x80000000L).toByteArray();
    }

    private static byte[] ext(int kind, byte[] data) {
        return new Buf().u16(kind).u16(data.length).put(data).toByteArray();
    }

    /** ClientHello TLS 1.3 для QUIC; random (32 байта) начинается с 6-го байта. */
    static byte[] clientHello(String sni, byte[] keyShare) {
        byte[] name = sni.getBytes(StandardCharsets.US_ASCII);
        byte[] tp = new Buf().put(hex("0104")).u32(0x80007530L).put(hex("0404")).u32(0x80F00000L)
                .put(hex("0802")).u16(0x4064).put(hex("0f00")).toByteArray();
        byte[] exts = new Buf()
                .put(ext(0, new Buf().u16(name.length + 3).u8(0).u16(name.length).put(name).toByteArray()))
                .put(ext(0x0A, hex("0004001d0017")))
                .put(ext(0x0D, hex("000a04030804040105030805")))
                .put(ext(0x10, hex("0003026833")))
                .put(ext(0x2B, hex("020304")))
                .put(ext(0x33, new Buf().u16(36).u16(0x1D).u16(32).put(keyShare).toByteArray()))
                .put(ext(0x2D, hex("0101")))
                .put(ext(0x39, tp)).toByteArray();
        byte[] body = new Buf().put(hex("0303")).put(new byte[32]).u8(0).put(hex("0006130113021303")).put(hex("0100"))
                .u16(exts.length).put(exts).toByteArray();
        return new Buf().u8(1).u24(body.length).put(body).toByteArray();
    }

    /** Первый пакет QUIC (Initial) к сайту sni — как pult/warp.py quic_i1. */
    public static String quicI1(String sni, byte[] dcid, byte[] keyShare) {
        byte[] hello = clientHello(sni, keyShare);
        byte[] frame = new Buf().u8(6).put(varint(0)).put(varint(hello.length)).toByteArray();
        byte[] hdrFixed = new Buf().u8(0xC0).u32(1).u8(dcid.length).put(dcid).u8(0).u8(0).toByteArray();
        byte[] pn = {0};
        int room = QUIC_SIZE - hdrFixed.length - 2 - pn.length - 16;
        int plen = Math.max(frame.length + hello.length, room);
        byte[] payload = new byte[plen];
        System.arraycopy(frame, 0, payload, 0, frame.length);
        System.arraycopy(hello, 0, payload, frame.length, hello.length);
        byte[] lenField = varint(pn.length + payload.length + 16);
        if (lenField.length != 2) {
            throw new IllegalStateException("QUIC: unexpected length");
        }
        byte[] header = new Buf().put(hdrFixed).put(lenField).put(pn).toByteArray();
        byte[][] k = quicKeys(dcid);
        byte[] nonce = k[1].clone();
        nonce[nonce.length - 1] ^= pn[0];
        byte[] ct = new byte[payload.length];
        byte[] ctrBlock = new byte[16];
        System.arraycopy(nonce, 0, ctrBlock, 0, 12);
        for (int i = 0; i * 16 < payload.length; i++) {
            int ctr = 2 + i;
            ctrBlock[12] = (byte) (ctr >>> 24);
            ctrBlock[13] = (byte) (ctr >>> 16);
            ctrBlock[14] = (byte) (ctr >>> 8);
            ctrBlock[15] = (byte) ctr;
            byte[] ks = aes128Block(k[0], ctrBlock);
            for (int j = 0; j < 16 && i * 16 + j < payload.length; j++) {
                ct[i * 16 + j] = (byte) (payload[i * 16 + j] ^ ks[j]);
            }
        }
        byte[] sample = new byte[16];
        System.arraycopy(ct, 4 - pn.length, sample, 0, 16);
        byte[] mask = aes128Block(k[2], sample);
        header[0] ^= mask[0] & 0x0F;
        header[header.length - 1] ^= mask[1];
        int rFrom = frame.length + 6;
        int rEnd = rFrom + 32;
        rFrom = Math.max(rFrom, 20 - pn.length);
        byte[] head = new Buf().put(header).put(java.util.Arrays.copyOfRange(ct, 0, rFrom)).toByteArray();
        return new Chain().raw(head).tag("r", rEnd - rFrom).raw(ct, rEnd, ct.length).tag("r", 16).toString();
    }

    public static String dnsI1(String host, int pad) {
        Buf q = new Buf();
        for (String part : host.replaceAll("^\\.+|\\.+$", "").split("\\.")) {
            byte[] b = part.getBytes(StandardCharsets.US_ASCII);
            q.u8(b.length).put(b);
        }
        q.u8(0);
        byte[] body = new Buf().put(hex("01000001000000000001")).put(q.toByteArray()).put(hex("00010001"))
                .u8(0).u16(41).u16(4096).u32(0).u16(pad + 4).u16(12).u16(pad).toByteArray();
        return new Chain().tag("r", 2).raw(body).tag("r", pad).toString();
    }

    /** Пакет-обманка из инструкции Amnezia (ответ DNS для yabs.yandex.ru). */
    public static final String DNS_YANDEX_I1 =
            "<r 2><b 0x8580000100010000000004796162730679616e6465780272750000010001c00c000100010000026d000457fa27d1>";

    public static String stunI1(int software) {
        return new Chain().raw(new Buf().u16(1).u16(4 + software).u32(0x2112A442L).toByteArray()).tag("r", 12)
                .raw(new Buf().u16(0x8022).u16(software).toByteArray()).tag("rc", software).toString();
    }

    public static String sipI1(String host, int a, int b) {
        return new Chain().text("OPTIONS sip:" + host + " SIP/2.0\r\nVia: SIP/2.0/UDP 192.168." + a + "." + b + ":5060;branch=z9hG4bK")
                .tag("rc", 10).text("\r\nFrom: <sip:").tag("rc", 8).text("@" + host + ">;tag=").tag("rd", 6)
                .text("\r\nTo: <sip:" + host + ">\r\nCall-ID: ").tag("rc", 16).text("@" + host + "\r\nCSeq: ").tag("rd", 4)
                .text(" OPTIONS\r\nMax-Forwards: 70\r\nUser-Agent: PJSIP/2.13\r\nContent-Length: 0\r\n\r\n").toString();
    }

    /** Наборы обманок: адрес и порт Cloudflare + вид пакета I1 (как PRESETS в pult/warp.py). */
    public static final String[][] PRESETS = {
            {"162.159.192.1:2408", "quic", "yandex.ru"},
            {"188.114.97.1:4500", "dns_yandex", ""},
            {"162.159.195.1:500", "stun", ""},
            {"188.114.99.1:1701", "quic", "vk.com"},
            {"162.159.192.7:4500", "dns", "icloud.com"},
            {"188.114.96.1:2408", "sip", "www.google.com"},
            {"162.159.195.5:4500", "quic", "www.google.com"},
    };

    private static int rand(int lo, int hi) {
        return lo + RND.nextInt(hi - lo + 1);
    }

    private static byte[] randBytes(int n) {
        byte[] b = new byte[n];
        RND.nextBytes(b);
        return b;
    }

    public static Map<String, Object> preset(int index) {
        String[] p = PRESETS[((index % PRESETS.length) + PRESETS.length) % PRESETS.length];
        String i1;
        switch (p[1]) {
            case "quic":
                i1 = quicI1(p[2], randBytes(8), randBytes(32));
                break;
            case "dns":
                i1 = dnsI1(p[2], rand(60, 180));
                break;
            case "stun":
                i1 = stunI1(rand(4, 8) * 4);
                break;
            case "sip":
                i1 = sipI1(p[2], rand(0, 255), rand(2, 254));
                break;
            default:
                i1 = DNS_YANDEX_I1;
        }
        int jmin = rand(10, 50);
        return Json.obj("endpoint", p[0], "jc", rand(4, 8), "jmin", jmin, "jmax", jmin + rand(20, 100), "i1", i1,
                "label", p[1] + (p[2].isEmpty() ? "" : " (" + p[2] + ")"));
    }

    // ---------- конфиг ----------

    private static List<String> obfLines(Map<String, Object> p) {
        List<String> l = new ArrayList<String>();
        l.add("Jc = " + Json.num(p, "jc", 4));
        l.add("Jmin = " + Json.num(p, "jmin", 10));
        l.add("Jmax = " + Json.num(p, "jmax", 50));
        l.add("S1 = 0");
        l.add("S2 = 0");
        l.add("H1 = 1");
        l.add("H2 = 2");
        l.add("H3 = 3");
        l.add("H4 = 4");
        l.add("I1 = " + Json.str(p, "i1"));
        return l;
    }

    public static String buildConf(Map<String, Object> acct, Map<String, Object> p) {
        List<String> addr = new ArrayList<String>();
        if (!Json.str(acct, "v4").isEmpty()) {
            addr.add(Json.str(acct, "v4") + "/32");
        }
        if (!Json.str(acct, "v6").isEmpty()) {
            addr.add(Json.str(acct, "v6") + "/128");
        }
        List<String> l = new ArrayList<String>();
        l.add("[Interface]");
        l.add("PrivateKey = " + Json.str(acct, "private_key"));
        l.add("Address = " + String.join(", ", addr));
        l.add("DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111");
        l.add("MTU = 1280");
        l.addAll(obfLines(p));
        l.add("");
        l.add("[Peer]");
        String peer = Json.str(acct, "peer");
        l.add("PublicKey = " + (peer.isEmpty() ? PEER_KEY : peer));
        l.add("AllowedIPs = 0.0.0.0/0, ::/0");
        l.add("Endpoint = " + Json.str(p, "endpoint"));
        l.add("PersistentKeepalive = 25");
        return String.join("\n", l) + "\n";
    }

    private static final Pattern PEER = Pattern.compile("(?im)^\\s*PublicKey\\s*=\\s*(\\S+)");
    private static final Pattern SECTION = Pattern.compile("\\[(\\w+)\\]");
    private static final java.util.Set<String> OBF = new java.util.HashSet<String>(java.util.Arrays.asList(
            "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"));

    public static boolean isWarp(String conf) {
        Matcher m = PEER.matcher(conf == null ? "" : conf);
        return m.find() && PEER_KEY.equals(m.group(1));
    }

    /** Тот же конфиг WARP с другим набором обманок (ключи и адреса — свои). */
    public static String variant(String conf, Map<String, Object> p) {
        List<String> out = new ArrayList<String>();
        String sect = "";
        boolean done = false;
        for (String raw : conf.trim().split("\r?\n", -1)) {
            String line = raw.trim();
            Matcher m = SECTION.matcher(line);
            if (m.matches()) {
                if ("interface".equals(sect) && !done) {
                    while (!out.isEmpty() && out.get(out.size() - 1).trim().isEmpty()) {
                        out.remove(out.size() - 1);
                    }
                    out.addAll(obfLines(p));
                    out.add("");
                    done = true;
                }
                sect = m.group(1).toLowerCase(Locale.ROOT);
                out.add(raw);
                continue;
            }
            String key = line.contains("=") ? line.substring(0, line.indexOf('=')).trim().toLowerCase(Locale.ROOT) : "";
            if ("interface".equals(sect) && OBF.contains(key)) {
                continue;
            }
            if ("peer".equals(sect) && "endpoint".equals(key)) {
                out.add("Endpoint = " + Json.str(p, "endpoint"));
                continue;
            }
            out.add(raw);
        }
        if ("interface".equals(sect) && !done) {
            out.addAll(obfLines(p));
        }
        return String.join("\n", out) + "\n";
    }

    public static Map<String, Object> currentParams(String conf) {
        Map<String, Object> p = new LinkedHashMap<String, Object>();
        String sect = "";
        for (String raw : (conf == null ? "" : conf).split("\r?\n")) {
            String line = raw.trim();
            Matcher m = SECTION.matcher(line);
            if (m.matches()) {
                sect = m.group(1).toLowerCase(Locale.ROOT);
                continue;
            }
            int eq = line.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String k = line.substring(0, eq).trim().toLowerCase(Locale.ROOT), v = line.substring(eq + 1).trim();
            if ("interface".equals(sect) && ("jc".equals(k) || "jmin".equals(k) || "jmax".equals(k))) {
                try {
                    p.put(k, Integer.parseInt(v));
                } catch (NumberFormatException ignored) {
                    p.put(k, v);
                }
            } else if ("interface".equals(sect) && "i1".equals(k)) {
                p.put(k, v);
            } else if ("peer".equals(sect) && "endpoint".equals(k)) {
                p.put("endpoint", v);
            }
        }
        return p;
    }

    // ---------- регистрация ----------

    /** Новое устройство WARP: {private_key, peer, v4, v6}. Метка доступа нужна только чтобы включить WARP. */
    public static Map<String, Object> register(String base, int proxyPort, String model, byte[] seed) throws WarpError {
        String[] kp = keypair(seed);
        SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.ROOT);
        f.setTimeZone(TimeZone.getTimeZone("UTC"));
        String url = base.replaceAll("/+$", "") + "/" + API_VERSION + "/reg";
        Map<String, Object> body = Json.obj("key", kp[1], "install_id", "", "fcm_token", "", "tos", f.format(new Date()),
                "model", model, "serial_number", "", "os_version", "16.0.0", "key_type", "curve25519",
                "tunnel_type", "wireguard", "locale", "en_US");
        Map<String, Object> r = call("POST", url, body, "", proxyPort);
        if (r.get("result") instanceof Map) {
            r = Json.map(r, "result");
        }
        Map<String, Object> cfg = Json.map(r, "config");
        cfg = cfg == null ? Json.obj() : cfg;
        List<Object> peers = Json.list(cfg, "peers");
        Map<String, Object> peer = peers != null && !peers.isEmpty() ? Json.map(peers.get(0)) : null;
        peer = peer == null ? Json.obj() : peer;
        Map<String, Object> iface = Json.map(cfg, "interface");
        Map<String, Object> addrs = iface == null ? null : Json.map(iface, "addresses");
        addrs = addrs == null ? Json.obj() : addrs;
        Map<String, Object> acct = Json.obj("private_key", kp[0], "peer", Json.str(peer, "public_key"),
                "v4", Json.str(addrs, "v4"), "v6", Json.str(addrs, "v6"));
        String id = Json.str(r, "id"), token = Json.str(r, "token");
        if (id.isEmpty() || token.isEmpty() || Json.str(acct, "peer").isEmpty() || Json.str(acct, "v4").isEmpty()) {
            throw new WarpError(Text.t("в ответе Cloudflare нет ключей", "the Cloudflare response has no keys"), "bad");
        }
        Map<String, Object> account = Json.map(r, "account");
        boolean enabled = Json.bool(r, "warp_enabled", false) || account != null && Json.bool(account, "warp_enabled", false);
        if (!enabled) {
            call("PATCH", url + "/" + id, Json.obj("warp_enabled", true), token, proxyPort);
        }
        return acct;
    }

    private static Map<String, Object> call(String method, String url, Map<String, Object> body, String token, int proxyPort)
            throws WarpError {
        Map<String, String> h = new LinkedHashMap<String, String>();
        h.put("Content-Type", "application/json; charset=UTF-8");
        h.put("User-Agent", USER_AGENT);
        h.put("CF-Client-Version", CLIENT_VERSION);
        if (!token.isEmpty()) {
            h.put("Authorization", "Bearer " + token);
        }
        Http.Response r;
        try {
            r = Http.send(method, url, h, Json.write(body).getBytes(StandardCharsets.UTF_8), 12000, proxyPort, true);
        } catch (IOException e) {
            throw new WarpError(e.getMessage() == null ? e.toString() : e.getMessage(), "blocked");
        }
        if (r.status == 403 || r.status == 429) {
            throw new WarpError(Text.t("Cloudflare отказал (код ", "Cloudflare refused (code ") + r.status + ")", "limit");
        }
        if (r.status < 200 || r.status >= 300) {
            throw new WarpError(Text.t("Cloudflare ответил ошибкой ", "Cloudflare returned error ") + r.status, "bad");
        }
        Object o;
        try {
            o = Json.parse(new String(r.body, StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            o = null;
        }
        if (!(o instanceof Map)) {
            throw new WarpError(Text.t("непонятный ответ Cloudflare", "unreadable Cloudflare response"), "bad");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> m = (Map<String, Object>) o;
        return m;
    }

    // ---------- WARP во встроенном ядре Xray (как warp.xray_outbound в pult/warp.py) ----------

    /** Случайное 0…n-1 (самопроверка подставляет предсказуемое). */
    public interface Rnd {
        int next(int n);
    }

    public static final Rnd SECURE = new Rnd() {
        @Override
        public int next(int n) {
            return RND.nextInt(n);
        }
    };

    private static final Pattern CPS_TAG = Pattern.compile("<(b|r|rc|rd|t|c|n)(?:\\s+([^>]*))?>");
    private static final String LETTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public static final int CPS_MAX = 4096;

    private static int cpsCount(String arg, Rnd rnd) {
        String a = arg == null ? "" : arg.trim();
        int dash = a.indexOf('-');
        int lo, hi;
        try {
            lo = Integer.parseInt(dash < 0 ? a : a.substring(0, dash).trim());
            hi = dash < 0 ? lo : Integer.parseInt(a.substring(dash + 1).trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("CPS: неверная длина");
        }
        if (lo < 0 || hi < lo || hi > CPS_MAX) {
            throw new IllegalArgumentException("CPS: неверная длина");
        }
        return hi > lo ? lo + rnd.next(hi - lo + 1) : lo;
    }

    /** Запись CPS AmneziaWG (<b 0x…>, <r N>, <rc N>, <rd N>, <t>, <c>, <n>) → байты одного пакета. */
    public static byte[] cpsBytes(String expr, Rnd rnd, long now) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        String text = expr == null ? "" : expr.trim();
        Matcher m = CPS_TAG.matcher(text);
        int pos = 0;
        while (m.find()) {
            if (!text.substring(pos, m.start()).trim().isEmpty()) {
                throw new IllegalArgumentException("CPS: лишний текст между тегами");
            }
            pos = m.end();
            String kind = m.group(1), arg = m.group(2) == null ? "" : m.group(2).trim();
            if ("b".equals(kind)) {
                String h = arg.toLowerCase(Locale.ROOT).startsWith("0x") ? arg.substring(2) : arg;
                if (h.length() % 2 != 0 || !h.matches("[0-9a-fA-F]*")) {
                    throw new IllegalArgumentException("CPS: неверные байты");
                }
                byte[] b = hex(h);
                out.write(b, 0, b.length);
            } else if ("r".equals(kind)) {
                int n = cpsCount(arg, rnd);
                for (int i = 0; i < n; i++) {
                    out.write(rnd.next(256));
                }
            } else if ("rc".equals(kind)) {
                int n = cpsCount(arg, rnd);
                for (int i = 0; i < n; i++) {
                    out.write(LETTERS.charAt(rnd.next(LETTERS.length())));
                }
            } else if ("rd".equals(kind)) {
                int n = cpsCount(arg, rnd);
                for (int i = 0; i < n; i++) {
                    out.write('0' + rnd.next(10));
                }
            } else if ("t".equals(kind)) {
                long t = now & 0xFFFFFFFFL;
                out.write((int) (t >> 24) & 0xFF);
                out.write((int) (t >> 16) & 0xFF);
                out.write((int) (t >> 8) & 0xFF);
                out.write((int) t & 0xFF);
            } else if ("c".equals(kind)) {
                out.write(0);
                out.write(0);
                out.write(0);
                out.write(1);
            } else {
                for (int i = 0; i < 8; i++) {
                    out.write(rnd.next(256));
                }
            }
            if (out.size() > CPS_MAX) {
                throw new IllegalArgumentException("CPS: слишком длинный пакет");
            }
        }
        if (!text.substring(pos).trim().isEmpty()) {
            throw new IllegalArgumentException("CPS: лишний текст после тегов");
        }
        return out.toByteArray();
    }

    /** Нужное ядру Xray из конфига WARP: ключи, адреса, сервер и обманки. */
    public static Map<String, Object> parseConf(String conf) {
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        List<Object> addr = new ArrayList<Object>();
        out.put("address", addr);
        out.put("mtu", 1280L);
        String sect = "";
        for (String raw : (conf == null ? "" : conf).split("\r?\n")) {
            String line = raw.trim();
            if (line.startsWith("#") || line.startsWith(";")) {
                continue;
            }
            Matcher sm = SECTION.matcher(line);
            if (sm.matches()) {
                sect = sm.group(1).toLowerCase(Locale.ROOT);
                continue;
            }
            int eq = line.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String k = line.substring(0, eq).trim().toLowerCase(Locale.ROOT), v = line.substring(eq + 1).trim();
            if ("interface".equals(sect)) {
                if ("privatekey".equals(k)) {
                    out.put("private_key", v);
                } else if ("address".equals(k)) {
                    addr.clear();
                    for (String a : v.split(",")) {
                        if (!a.trim().isEmpty()) {
                            addr.add(a.trim());
                        }
                    }
                } else if ("mtu".equals(k) && v.matches("\\d{1,5}")) {
                    out.put("mtu", (long) Math.max(1200, Math.min(1420, Integer.parseInt(v))));
                } else if (("jc".equals(k) || "jmin".equals(k) || "jmax".equals(k)) && v.matches("\\d{1,5}")) {
                    out.put(k, (long) Integer.parseInt(v));
                } else if ("i1".equals(k)) {
                    out.put("i1", v);
                }
            } else if ("peer".equals(sect)) {
                if ("publickey".equals(k)) {
                    out.put("peer", v);
                } else if ("endpoint".equals(k)) {
                    out.put("endpoint", v);
                }
            }
        }
        if (Json.str(out, "private_key").isEmpty() || Json.str(out, "peer").isEmpty() || Json.str(out, "endpoint").isEmpty()
                || addr.isEmpty()) {
            throw new IllegalArgumentException(Text.t("в конфиге WARP нет ключей или адреса сервера",
                    "the WARP config has no keys or server address"));
        }
        return out;
    }

    static final String NOISE_DELAY = "1-3";

    /** Шум перед подключением, как у AmneziaWG: сначала пакет-обманка I1, затем Jc мусорных пакетов. */
    public static List<Object> noiseItems(Map<String, Object> p, Rnd rnd) {
        List<Object> items = new ArrayList<Object>();
        String i1 = Json.str(p, "i1");
        if (!i1.isEmpty()) {
            try {
                byte[] b = cpsBytes(i1, rnd, System.currentTimeMillis() / 1000);
                items.add(Json.obj("type", "hex", "packet", toHex(b, 0, b.length), "delay", NOISE_DELAY));
            } catch (IllegalArgumentException ignored) {
                // неверная запись — без пакета-обманки, только мусорные пакеты
            }
        }
        long jc = Json.num(p, "jc", 0), lo = Json.num(p, "jmin", 0), hi = Json.num(p, "jmax", 0);
        if (jc > 0 && lo > 0 && lo <= hi && hi <= 1280) {
            for (int i = 0; i < Math.min(jc, 10); i++) {
                items.add(Json.obj("rand", hi > lo ? lo + "-" + hi : String.valueOf(lo), "delay", NOISE_DELAY));
            }
        }
        return items;
    }

    /** Outbound WireGuard для ядра Xray (WARP) с шумом Finalmask вместо обманок AmneziaWG. */
    public static Map<String, Object> xrayOutbound(String conf, String tag, boolean noise, Rnd rnd) {
        Map<String, Object> p = parseConf(conf);
        Map<String, Object> peer = Json.obj("publicKey", Json.str(p, "peer"), "endpoint", Json.str(p, "endpoint"), "keepAlive", 25L);
        Map<String, Object> ob = Json.obj("tag", tag, "protocol", "wireguard", "settings", Json.obj(
                "secretKey", Json.str(p, "private_key"), "address", p.get("address"), "peers", Json.arr(peer),
                "mtu", Json.num(p, "mtu", 1280), "noKernelTun", true));
        List<Object> items = noise ? noiseItems(p, rnd) : new ArrayList<Object>();
        if (!items.isEmpty()) {
            ob.put("streamSettings", Json.obj("finalmask", Json.obj("udp", Json.arr(
                    Json.obj("type", "noise", "settings", Json.obj("noise", items))))));
        }
        return ob;
    }

    /** Конфиг для другого устройства (QR-код): длинный пакет-обманка заменяется коротким из инструкции Amnezia. */
    public static String shareConf(String conf) {
        StringBuilder sb = new StringBuilder();
        for (String line : (conf == null ? "" : conf.trim()).split("\r?\n", -1)) {
            if (!line.trim().startsWith("#")) {
                sb.append(line).append('\n');
            }
        }
        String text = sb.toString();
        if (text.getBytes(StandardCharsets.UTF_8).length > 1800) {
            text = Pattern.compile("(?im)^\\s*I1\\s*=.*$").matcher(text).replaceAll(Matcher.quoteReplacement("I1 = " + DNS_YANDEX_I1));
        }
        return text;
    }
}
