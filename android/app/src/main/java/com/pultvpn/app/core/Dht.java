package com.pultvpn.app.core;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Сеть торрентов (Mainline DHT) как почтовый ящик «Семьи» — как pult/dht.py: bencode, ed25519 (RFC 8032),
 * записи BEP 44 и клиент «только для чтения» (BEP 43). Формат сверяется с программой для ПК (coretest/run.sh).
 */
public final class Dht {
    private Dht() {
    }

    public static final String[][] BOOTSTRAP = {{"router.bittorrent.com", "6881"}, {"dht.transmissionbt.com", "6881"},
            {"router.utorrent.com", "6881"}, {"dht.libtorrent.org", "25401"}};
    static final int K = 8;
    static final int ALPHA = 4;
    public static final int MAX_V = 1000;
    static final int MAX_SALT = 64;
    static final long LOOKUP_MS = 12000;
    static final int QUERY_MS = 2000;
    static final SecureRandom RND = new SecureRandom();
    /** Самопроверка: узлы сети — на этом же компьютере. */
    public static boolean LOCAL_OK = false;

    public static class DhtError extends RuntimeException {
        public DhtError(String text) {
            super(text);
        }
    }

    // ---------- bencode ----------
    // Строки — byte[]; ключи словарей — String в ISO-8859-1 (байт в байт); числа — Long.

    public static String key(byte[] b) {
        return new String(b, StandardCharsets.ISO_8859_1);
    }

    public static byte[] encode(Object v) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        enc(v, out);
        return out.toByteArray();
    }

    @SuppressWarnings("unchecked")
    private static void enc(Object v, ByteArrayOutputStream out) {
        if (v instanceof Boolean) {
            v = ((Boolean) v) ? 1L : 0L;
        }
        if (v instanceof Integer || v instanceof Long) {
            byte[] b = ("i" + ((Number) v).longValue() + "e").getBytes(StandardCharsets.US_ASCII);
            out.write(b, 0, b.length);
        } else if (v instanceof String || v instanceof byte[]) {
            byte[] s = v instanceof String ? ((String) v).getBytes(StandardCharsets.UTF_8) : (byte[]) v;
            byte[] h = (s.length + ":").getBytes(StandardCharsets.US_ASCII);
            out.write(h, 0, h.length);
            out.write(s, 0, s.length);
        } else if (v instanceof List) {
            out.write('l');
            for (Object x : (List<Object>) v) {
                enc(x, out);
            }
            out.write('e');
        } else if (v instanceof Map) {
            TreeMap<String, Object> sorted = new TreeMap<String, Object>(new Comparator<String>() {
                @Override
                public int compare(String a, String b) {
                    byte[] x = a.getBytes(StandardCharsets.ISO_8859_1), y = b.getBytes(StandardCharsets.ISO_8859_1);
                    for (int i = 0; i < Math.min(x.length, y.length); i++) {
                        int d = (x[i] & 0xFF) - (y[i] & 0xFF);
                        if (d != 0) {
                            return d;
                        }
                    }
                    return x.length - y.length;
                }
            });
            sorted.putAll((Map<String, Object>) v);
            out.write('d');
            for (Map.Entry<String, Object> e : sorted.entrySet()) {
                enc(e.getKey().getBytes(StandardCharsets.ISO_8859_1), out); // ключ — байт в байт (см. key)
                enc(e.getValue(), out);
            }
            out.write('e');
        } else {
            throw new IllegalArgumentException("bencode: " + (v == null ? "null" : v.getClass().getSimpleName()));
        }
    }

    /** Строгий разбор: лишние байты в конце — ошибка. Ключи словарей — в ISO-8859-1 (см. key). */
    public static Object decode(byte[] data) {
        int[] pos = {0};
        Object v;
        try {
            v = dec(data, pos, 0);
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new IllegalArgumentException("bencode: обрыв");
        }
        if (pos[0] != data.length) {
            throw new IllegalArgumentException("bencode: лишние байты");
        }
        return v;
    }

    private static int indexOf(byte[] d, byte c, int from) {
        for (int i = from; i < d.length; i++) {
            if (d[i] == c) {
                return i;
            }
        }
        throw new IllegalArgumentException("bencode: обрыв");
    }

    private static Object dec(byte[] d, int[] pos, int depth) {
        if (depth > 16) {
            throw new IllegalArgumentException("bencode: слишком глубоко");
        }
        int i = pos[0];
        if (i >= d.length) {
            throw new IllegalArgumentException("bencode: обрыв");
        }
        byte c = d[i];
        if (c == 'i') {
            int j = indexOf(d, (byte) 'e', i);
            String t = new String(d, i + 1, j - i - 1, StandardCharsets.US_ASCII);
            if (!t.matches("-?[0-9]+") || (t.startsWith("0") && t.length() > 1) || t.startsWith("-0")) {
                throw new IllegalArgumentException("bencode: неверное число");
            }
            pos[0] = j + 1;
            return Long.parseLong(t);
        }
        if (c == 'l') {
            List<Object> out = new ArrayList<Object>();
            pos[0] = i + 1;
            while (d[pos[0]] != 'e') {
                out.add(dec(d, pos, depth + 1));
            }
            pos[0]++;
            return out;
        }
        if (c == 'd') {
            Map<String, Object> out = new LinkedHashMap<String, Object>();
            pos[0] = i + 1;
            while (d[pos[0]] != 'e') {
                Object k = dec(d, pos, depth + 1);
                if (!(k instanceof byte[])) {
                    throw new IllegalArgumentException("bencode: ключ не строка");
                }
                out.put(key((byte[]) k), dec(d, pos, depth + 1));
            }
            pos[0]++;
            return out;
        }
        if (c >= '0' && c <= '9') {
            int j = indexOf(d, (byte) ':', i);
            int n = Integer.parseInt(new String(d, i, j - i, StandardCharsets.US_ASCII));
            if (n < 0 || j + 1 + n > d.length) {
                throw new IllegalArgumentException("bencode: обрыв строки");
            }
            pos[0] = j + 1 + n;
            return Arrays.copyOfRange(d, j + 1, j + 1 + n);
        }
        throw new IllegalArgumentException("bencode: неизвестный тип");
    }

    // ---------- ed25519 (RFC 8032) ----------

    static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    static final BigInteger L = BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
    static final BigInteger D = BigInteger.valueOf(-121665).multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P);
    static final BigInteger I = BigInteger.valueOf(2).modPow(P.subtract(BigInteger.ONE).shiftRight(2), P);
    static final BigInteger TWO = BigInteger.valueOf(2);
    static final BigInteger[] B;

    static {
        BigInteger y = BigInteger.valueOf(4).multiply(BigInteger.valueOf(5).modInverse(P)).mod(P);
        BigInteger x = xrecover(y);
        B = new BigInteger[]{x, y, BigInteger.ONE, x.multiply(y).mod(P)};
    }

    private static BigInteger xrecover(BigInteger y) {
        BigInteger xx = y.multiply(y).subtract(BigInteger.ONE).multiply(D.multiply(y).multiply(y).add(BigInteger.ONE).modInverse(P));
        BigInteger x = xx.modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P);
        if (!x.multiply(x).subtract(xx).mod(P).equals(BigInteger.ZERO)) {
            x = x.multiply(I).mod(P);
        }
        if (x.testBit(0)) {
            x = P.subtract(x);
        }
        return x;
    }

    private static BigInteger[] add(BigInteger[] p, BigInteger[] q) {
        BigInteger a = p[1].subtract(p[0]).multiply(q[1].subtract(q[0])).mod(P);
        BigInteger b = p[1].add(p[0]).multiply(q[1].add(q[0])).mod(P);
        BigInteger c = p[3].multiply(TWO).multiply(D).multiply(q[3]).mod(P);
        BigInteger dd = p[2].multiply(TWO).multiply(q[2]).mod(P);
        BigInteger e = b.subtract(a), f = dd.subtract(c), g = dd.add(c), h = b.add(a);
        return new BigInteger[]{e.multiply(f).mod(P), g.multiply(h).mod(P), f.multiply(g).mod(P), e.multiply(h).mod(P)};
    }

    private static BigInteger[] mul(BigInteger s, BigInteger[] p) {
        BigInteger[] q = {BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO};
        for (int i = 0; i < s.bitLength(); i++) {
            if (s.testBit(i)) {
                q = add(q, p);
            }
            p = add(p, p);
        }
        return q;
    }

    private static BigInteger le(byte[] b, int from, int len) {
        byte[] r = new byte[len + 1];
        for (int i = 0; i < len; i++) {
            r[len - i] = b[from + i];
        }
        return new BigInteger(r);
    }

    private static byte[] toLe(BigInteger x) {
        byte[] b = x.toByteArray();
        byte[] out = new byte[32];
        for (int i = 0; i < Math.min(32, b.length); i++) {
            out[i] = b[b.length - 1 - i];
        }
        return out;
    }

    private static byte[] encodePoint(BigInteger[] p) {
        BigInteger zi = p[2].modInverse(P);
        BigInteger x = p[0].multiply(zi).mod(P), y = p[1].multiply(zi).mod(P);
        byte[] out = toLe(y);
        if (x.testBit(0)) {
            out[31] |= (byte) 0x80;
        }
        return out;
    }

    private static BigInteger[] decodePoint(byte[] b) {
        if (b.length != 32) {
            throw new IllegalArgumentException("ed25519: неверная длина точки");
        }
        byte[] c = b.clone();
        int sign = (c[31] >> 7) & 1;
        c[31] &= 0x7F;
        BigInteger y = le(c, 0, 32);
        if (y.compareTo(P) >= 0) {
            throw new IllegalArgumentException("ed25519: неверная точка");
        }
        BigInteger xx = y.multiply(y).subtract(BigInteger.ONE).multiply(D.multiply(y).multiply(y).add(BigInteger.ONE).modInverse(P)).mod(P);
        BigInteger x = xx.modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P);
        if (!x.multiply(x).subtract(xx).mod(P).equals(BigInteger.ZERO)) {
            x = x.multiply(I).mod(P);
        }
        if (!x.multiply(x).subtract(xx).mod(P).equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("ed25519: точки нет на кривой");
        }
        if (x.signum() == 0 && sign == 1) {
            throw new IllegalArgumentException("ed25519: неверная точка");
        }
        if ((x.testBit(0) ? 1 : 0) != sign) {
            x = P.subtract(x);
        }
        return new BigInteger[]{x, y, BigInteger.ONE, x.multiply(y).mod(P)};
    }

    private static boolean same(BigInteger[] p, BigInteger[] q) {
        return p[0].multiply(q[2]).subtract(q[0].multiply(p[2])).mod(P).signum() == 0
                && p[1].multiply(q[2]).subtract(q[1].multiply(p[2])).mod(P).signum() == 0;
    }

    public static byte[] sha(String alg, byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance(alg);
            for (byte[] p : parts) {
                md.update(p);
            }
            return md.digest();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static BigInteger hint(byte[]... parts) {
        byte[] h = sha("SHA-512", parts);
        return le(h, 0, 64);
    }

    /** Секрет 32 байта → «развёрнутый» ключ 64 байта (скаляр + префикс), как в BEP 44. */
    public static byte[] edExpand(byte[] seed) {
        byte[] h = sha("SHA-512", seed);
        h[0] &= (byte) 248;
        h[31] &= 127;
        h[31] |= 64;
        return h;
    }

    public static byte[] edPublic(byte[] expanded) {
        return encodePoint(mul(le(expanded, 0, 32), B));
    }

    public static byte[] edSign(byte[] expanded, byte[] msg, byte[] pub) {
        if (pub == null) {
            pub = edPublic(expanded);
        }
        BigInteger a = le(expanded, 0, 32);
        BigInteger r = hint(Arrays.copyOfRange(expanded, 32, 64), msg).mod(L);
        byte[] bigR = encodePoint(mul(r, B));
        BigInteger s = r.add(hint(bigR, pub, msg).multiply(a)).mod(L);
        byte[] out = new byte[64];
        System.arraycopy(bigR, 0, out, 0, 32);
        System.arraycopy(toLe(s), 0, out, 32, 32);
        return out;
    }

    public static boolean edVerify(byte[] pub, byte[] msg, byte[] sig) {
        if (pub == null || sig == null || pub.length != 32 || sig.length != 64) {
            return false;
        }
        BigInteger[] a, r;
        try {
            a = decodePoint(pub);
            r = decodePoint(Arrays.copyOfRange(sig, 0, 32));
        } catch (IllegalArgumentException e) {
            return false;
        }
        BigInteger s = le(sig, 32, 32);
        if (s.compareTo(L) >= 0) {
            return false;
        }
        return same(mul(s, B), add(r, mul(hint(Arrays.copyOfRange(sig, 0, 32), pub, msg).mod(L), a)));
    }

    // ---------- записи BEP 44 ----------

    public static byte[] target(byte[] k, byte[] salt) {
        return sha("SHA-1", k, salt == null ? new byte[0] : salt);
    }

    public static byte[] signBuf(byte[] salt, long seq, byte[] vBencoded) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] head = salt != null && salt.length > 0 ? Family.concat("4:salt".getBytes(StandardCharsets.US_ASCII), encode(salt)) : new byte[0];
        byte[] mid = ("3:seqi" + seq + "e1:v").getBytes(StandardCharsets.US_ASCII);
        out.write(head, 0, head.length);
        out.write(mid, 0, mid.length);
        out.write(vBencoded, 0, vBencoded.length);
        return out.toByteArray();
    }

    /** Ключ записей пары: из 32 байт секрета (общий у обеих сторон). */
    public static final class Keys {
        public final byte[] expanded;
        public final byte[] pub;

        public Keys(byte[] seed) {
            if (seed == null || seed.length != 32) {
                throw new IllegalArgumentException("нужен секрет 32 байта");
            }
            expanded = edExpand(seed);
            pub = edPublic(expanded);
        }

        public Map<String, Object> item(byte[] salt, long seq, Object v) {
            byte[] vb = encode(v);
            if (vb.length > MAX_V || salt.length > MAX_SALT) {
                throw new DhtError(Text.t("запись слишком большая", "the item is too big"));
            }
            Map<String, Object> it = new LinkedHashMap<String, Object>();
            it.put("k", pub);
            it.put("salt", salt);
            it.put("seq", seq);
            it.put("v", v);
            it.put("sig", edSign(expanded, signBuf(salt, seq, vb), pub));
            return it;
        }
    }

    /** Ответ узла с записью → {seq, v}, если запись нашего ключа и подпись верна. */
    public static Object[] checkItem(byte[] k, byte[] salt, Map<String, Object> r) {
        Object rk = r.get("k"), seq = r.get("seq"), sig = r.get("sig");
        if (!(rk instanceof byte[]) || !Arrays.equals((byte[]) rk, k) || !(seq instanceof Long) || !r.containsKey("v")
                || !(sig instanceof byte[])) {
            return null;
        }
        byte[] vb = encode(r.get("v"));
        if (vb.length > MAX_V || !edVerify(k, signBuf(salt, (Long) seq, vb), (byte[]) sig)) {
            return null;
        }
        return new Object[]{seq, r.get("v")};
    }

    // ---------- клиент KRPC ----------

    static BigInteger dist(byte[] a, byte[] b) {
        byte[] x = new byte[21];
        for (int i = 0; i < 20; i++) {
            x[i + 1] = (byte) (a[i] ^ b[i]);
        }
        return new BigInteger(x);
    }

    public static final class Client {
        final List<InetSocketAddress> boot = new ArrayList<InetSocketAddress>();
        final String[][] bootNames;
        final long timeoutMs;
        final byte[] nid = new byte[20];

        public Client(String[][] bootstrap, long timeoutMs) {
            this.bootNames = bootstrap;
            this.timeoutMs = timeoutMs;
            RND.nextBytes(nid);
        }

        public Client(List<InetSocketAddress> bootstrap, long timeoutMs) {
            this.bootNames = new String[0][];
            this.boot.addAll(bootstrap);
            this.timeoutMs = timeoutMs;
            RND.nextBytes(nid);
        }

        private List<InetSocketAddress> addrs() {
            List<InetSocketAddress> out = new ArrayList<InetSocketAddress>(boot);
            for (String[] b : bootNames) {
                try {
                    for (InetAddress a : InetAddress.getAllByName(b[0])) {
                        if (a.getAddress().length == 4) {
                            out.add(new InetSocketAddress(a, Integer.parseInt(b[1])));
                        }
                    }
                } catch (Exception ignored) {
                    // узел не нашёлся — есть другие
                }
            }
            return out;
        }

        /** Запросы → ответы за waitMs: [{адрес, r}]. */
        @SuppressWarnings("unchecked")
        List<Object[]> exchange(DatagramSocket sock, List<Object[]> queries, long waitMs) {
            Map<String, InetSocketAddress> pending = new HashMap<String, InetSocketAddress>();
            for (Object[] q : queries) {
                byte[] tid = new byte[4];
                RND.nextBytes(tid);
                Map<String, Object> a = new LinkedHashMap<String, Object>((Map<String, Object>) q[2]);
                a.put("id", nid);
                Map<String, Object> msg = new LinkedHashMap<String, Object>();
                msg.put("t", tid);
                msg.put("y", "q");
                msg.put("q", q[1]);
                msg.put("a", a);
                msg.put("ro", 1L);
                byte[] data = encode(msg);
                try {
                    sock.send(new DatagramPacket(data, data.length, (InetSocketAddress) q[0]));
                    pending.put(key(tid), (InetSocketAddress) q[0]);
                } catch (Exception ignored) {
                    // недоступный адрес
                }
            }
            List<Object[]> out = new ArrayList<Object[]>();
            long end = System.currentTimeMillis() + waitMs;
            byte[] buf = new byte[4096];
            while (!pending.isEmpty() && System.currentTimeMillis() < end) {
                try {
                    sock.setSoTimeout((int) Math.max(1, Math.min(250, end - System.currentTimeMillis())));
                    DatagramPacket pk = new DatagramPacket(buf, buf.length);
                    sock.receive(pk);
                    Object m = decode(Arrays.copyOfRange(pk.getData(), 0, pk.getLength()));
                    if (!(m instanceof Map)) {
                        continue;
                    }
                    Map<String, Object> msg = (Map<String, Object>) m;
                    Object t = msg.get("t");
                    if (!(t instanceof byte[])) {
                        continue;
                    }
                    InetSocketAddress from = pending.get(key((byte[]) t));
                    if (from == null || !from.getAddress().equals(pk.getAddress())) {
                        continue;
                    }
                    pending.remove(key((byte[]) t));
                    Object y = msg.get("y");
                    if (y instanceof byte[] && "r".equals(key((byte[]) y)) && msg.get("r") instanceof Map) {
                        out.add(new Object[]{from, msg.get("r")});
                    } else {
                        out.add(new Object[]{from, null});
                    }
                } catch (SocketTimeoutException e) {
                    // ждём дальше
                } catch (Exception e) {
                    // испорченный ответ
                }
            }
            return out;
        }

        static List<Object[]> nodes(Object blob) {
            List<Object[]> out = new ArrayList<Object[]>();
            if (!(blob instanceof byte[])) {
                return out;
            }
            byte[] b = (byte[]) blob;
            for (int i = 0; i + 26 <= b.length; i += 26) {
                byte[] id = Arrays.copyOfRange(b, i, i + 20);
                int port = ((b[i + 24] & 0xFF) << 8) | (b[i + 25] & 0xFF);
                try {
                    InetAddress ip = InetAddress.getByAddress(Arrays.copyOfRange(b, i + 20, i + 24));
                    int first = b[i + 20] & 0xFF;
                    if (port > 0 && (LOCAL_OK || (first != 0 && first != 127 && first != 255))) {
                        out.add(new Object[]{id, new InetSocketAddress(ip, port)});
                    }
                } catch (Exception ignored) {
                    // неверный адрес
                }
            }
            return out;
        }

        /** Поиск ближайших к tgt узлов запросом get. → {ближайшие [{dist, id, addr, token}], лучшая запись или null}. */
        @SuppressWarnings("unchecked")
        Object[] lookup(final byte[] tgt, byte[] k, byte[] salt) throws java.io.IOException {
            DatagramSocket sock = new DatagramSocket();
            try {
                final Map<InetSocketAddress, byte[]> cands = new LinkedHashMap<InetSocketAddress, byte[]>();
                for (InetSocketAddress a : addrs()) {
                    cands.put(a, new byte[0]);
                }
                Set<InetSocketAddress> seen = new HashSet<InetSocketAddress>();
                final Map<InetSocketAddress, Object[]> done = new LinkedHashMap<InetSocketAddress, Object[]>();
                Object[] best = null;
                long end = System.currentTimeMillis() + timeoutMs;
                while (System.currentTimeMillis() < end) {
                    List<InetSocketAddress> order = new ArrayList<InetSocketAddress>();
                    for (InetSocketAddress a : cands.keySet()) {
                        if (!seen.contains(a)) {
                            order.add(a);
                        }
                    }
                    Collections.sort(order, new Comparator<InetSocketAddress>() {
                        @Override
                        public int compare(InetSocketAddress x, InetSocketAddress y) {
                            byte[] ix = cands.get(x), iy = cands.get(y);
                            if (ix.length == 0 || iy.length == 0) {
                                return Integer.compare(ix.length, iy.length);
                            }
                            return dist(ix, tgt).compareTo(dist(iy, tgt));
                        }
                    });
                    List<BigInteger> closest = new ArrayList<BigInteger>();
                    for (Object[] v : done.values()) {
                        closest.add(dist((byte[]) v[0], tgt));
                    }
                    Collections.sort(closest);
                    if (closest.size() >= K && !order.isEmpty()) {
                        BigInteger worst = closest.get(K - 1);
                        List<InetSocketAddress> keep = new ArrayList<InetSocketAddress>();
                        for (InetSocketAddress a : order) {
                            byte[] id = cands.get(a);
                            if (id.length == 0 || dist(id, tgt).compareTo(worst) < 0) {
                                keep.add(a);
                            }
                        }
                        order = keep;
                    }
                    if (order.isEmpty()) {
                        break;
                    }
                    List<Object[]> qs = new ArrayList<Object[]>();
                    for (InetSocketAddress a : order.subList(0, Math.min(ALPHA * 2, order.size()))) {
                        seen.add(a);
                        Map<String, Object> args = new LinkedHashMap<String, Object>();
                        args.put("target", tgt);
                        qs.add(new Object[]{a, "get", args});
                    }
                    for (Object[] res : exchange(sock, qs, Math.min(QUERY_MS, Math.max(200, end - System.currentTimeMillis())))) {
                        if (res[1] == null) {
                            continue;
                        }
                        Map<String, Object> r = (Map<String, Object>) res[1];
                        Object id = r.get("id");
                        if (!(id instanceof byte[]) || ((byte[]) id).length != 20) {
                            continue;
                        }
                        Object tok = r.get("token");
                        done.put((InetSocketAddress) res[0], new Object[]{id, tok instanceof byte[] ? tok : new byte[0]});
                        if (k != null) {
                            Object[] got = checkItem(k, salt, r);
                            if (got != null && (best == null || (Long) got[0] > (Long) best[0])) {
                                best = got;
                            }
                        }
                        for (Object[] n : nodes(r.get("nodes"))) {
                            InetSocketAddress na = (InetSocketAddress) n[1];
                            if (!cands.containsKey(na) && cands.size() < 2000) {
                                cands.put(na, (byte[]) n[0]);
                            }
                        }
                    }
                }
                List<Object[]> res = new ArrayList<Object[]>();
                for (Map.Entry<InetSocketAddress, Object[]> e : done.entrySet()) {
                    res.add(new Object[]{dist((byte[]) e.getValue()[0], tgt), e.getValue()[0], e.getKey(), e.getValue()[1]});
                }
                Collections.sort(res, new Comparator<Object[]>() {
                    @Override
                    public int compare(Object[] x, Object[] y) {
                        return ((BigInteger) x[0]).compareTo((BigInteger) y[0]);
                    }
                });
                return new Object[]{res.subList(0, Math.min(K, res.size())), best};
            } finally {
                sock.close();
            }
        }

        /** Свежая запись: {seq, v} или null. */
        public Object[] get(byte[] k, byte[] salt) throws java.io.IOException {
            Object[] best = (Object[]) lookup(target(k, salt), k, salt)[1];
            if (best == null && !LOCAL_OK) { // второй поиск с другим своим адресом в сети (как dht.Client.get)
                RND.nextBytes(nid);
                best = (Object[]) lookup(target(k, salt), k, salt)[1];
            }
            return best;
        }

        /** Положить запись (Keys.item) на ближайшие узлы → сколько узлов приняли. */
        @SuppressWarnings("unchecked")
        public int put(Map<String, Object> item) throws java.io.IOException {
            byte[] k = (byte[]) item.get("k"), salt = (byte[]) item.get("salt");
            Object[] found = lookup(target(k, salt), k, salt);
            Object[] best = (Object[]) found[1];
            long seq = (Long) item.get("seq");
            if (best != null && (Long) best[0] > seq) {
                throw new DhtError(Text.t("в сети уже есть запись новее", "the network already has a newer item"));
            }
            List<Object[]> qs = new ArrayList<Object[]>();
            for (Object[] c : (List<Object[]>) found[0]) {
                byte[] tok = (byte[]) c[3];
                if (tok.length == 0) {
                    continue;
                }
                Map<String, Object> a = new LinkedHashMap<String, Object>();
                a.put("k", k);
                a.put("seq", seq);
                a.put("sig", item.get("sig"));
                a.put("v", item.get("v"));
                a.put("token", tok);
                if (salt.length > 0) {
                    a.put("salt", salt);
                }
                qs.add(new Object[]{c[2], "put", a});
            }
            if (qs.isEmpty()) {
                return 0;
            }
            DatagramSocket sock = new DatagramSocket();
            try {
                int ok = 0;
                for (Object[] r : exchange(sock, qs, QUERY_MS * 3 / 2)) {
                    if (r[1] != null) {
                        ok++;
                    }
                }
                return ok;
            } finally {
                sock.close();
            }
        }
    }

    // ---------- узел для самопроверки (в программе не запускается) ----------

    public static final class LocalNode implements java.io.Closeable {
        public final byte[] nid = new byte[20];
        final DatagramSocket sock;
        public final InetSocketAddress addr;
        public final List<Object[]> peers = new ArrayList<Object[]>();
        final Map<String, Map<String, Object>> store = new HashMap<String, Map<String, Object>>();
        final byte[] secret = new byte[8];
        public volatile int puts;
        volatile boolean alive = true;

        public LocalNode() throws java.io.IOException {
            RND.nextBytes(nid);
            RND.nextBytes(secret);
            sock = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0));
            addr = new InetSocketAddress("127.0.0.1", sock.getLocalPort());
            Thread t = new Thread(new Runnable() {
                @Override
                public void run() {
                    loop();
                }
            });
            t.setDaemon(true);
            t.start();
        }

        byte[] token(InetAddress ip) {
            return Arrays.copyOf(sha("SHA-1", secret, ip.getAddress()), 8);
        }

        byte[] compact() {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (Object[] p : peers.subList(0, Math.min(8, peers.size()))) {
                InetSocketAddress a = (InetSocketAddress) p[1];
                byte[] id = (byte[]) p[0];
                out.write(id, 0, 20);
                byte[] ip = a.getAddress().getAddress();
                out.write(ip, 0, 4);
                out.write((a.getPort() >> 8) & 0xFF);
                out.write(a.getPort() & 0xFF);
            }
            return out.toByteArray();
        }

        @SuppressWarnings("unchecked")
        void loop() {
            byte[] buf = new byte[4096];
            while (alive) {
                try {
                    DatagramPacket pk = new DatagramPacket(buf, buf.length);
                    sock.receive(pk);
                    Map<String, Object> msg = (Map<String, Object>) decode(Arrays.copyOfRange(pk.getData(), 0, pk.getLength()));
                    String q = key((byte[]) msg.get("q"));
                    Map<String, Object> a = (Map<String, Object>) msg.get("a");
                    Map<String, Object> r = new LinkedHashMap<String, Object>();
                    r.put("id", nid);
                    Object err = null;
                    if ("get".equals(q) || "find_node".equals(q)) {
                        r.put("nodes", compact());
                        r.put("token", token(pk.getAddress()));
                        Map<String, Object> it = store.get(key((byte[]) a.get("target")));
                        if ("get".equals(q) && it != null) {
                            r.putAll(it);
                        }
                    } else if ("put".equals(q)) {
                        byte[] salt = a.get("salt") instanceof byte[] ? (byte[]) a.get("salt") : new byte[0];
                        byte[] k = (byte[]) a.get("k");
                        Map<String, Object> old = store.get(key(target(k, salt)));
                        if (!Arrays.equals((byte[]) a.get("token"), token(pk.getAddress()))) {
                            err = Arrays.asList((Object) 203L, "bad token");
                        } else if (!edVerify(k, signBuf(salt, (Long) a.get("seq"), encode(a.get("v"))), (byte[]) a.get("sig"))) {
                            err = Arrays.asList((Object) 206L, "invalid signature");
                        } else if (old != null && (Long) old.get("seq") > (Long) a.get("seq")) {
                            err = Arrays.asList((Object) 302L, "sequence number less than current");
                        } else {
                            Map<String, Object> it = new LinkedHashMap<String, Object>();
                            it.put("k", k);
                            it.put("seq", a.get("seq"));
                            it.put("sig", a.get("sig"));
                            it.put("v", a.get("v"));
                            store.put(key(target(k, salt)), it);
                            puts++;
                        }
                    }
                    Map<String, Object> reply = new LinkedHashMap<String, Object>();
                    reply.put("t", msg.get("t"));
                    if (err != null) {
                        reply.put("y", "e");
                        reply.put("e", err);
                    } else {
                        reply.put("y", "r");
                        reply.put("r", r);
                    }
                    byte[] out = encode(reply);
                    sock.send(new DatagramPacket(out, out.length, pk.getSocketAddress()));
                } catch (Exception e) {
                    if (!alive) {
                        return;
                    }
                }
            }
        }

        @Override
        public void close() {
            alive = false;
            sock.close();
        }
    }
}
