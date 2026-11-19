package com.pultvpn.app.core;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;

/**
 * Обновление приложения (как pult/update.py): файл выпуска {"payload": "<JSON>", "sig": "<base64>"},
 * подпись RSA PKCS#1 v1.5 + SHA-256 над байтами payload. Открытый ключ вшит сюда; пока его и адреса нет —
 * автообновление выключено. APK проверяется по SHA-256 из подписанного файла, а Android сам проверит,
 * что он подписан тем же ключом, что и установленное приложение.
 */
public final class Update {
    private Update() {
    }

    /** Адрес latest.json (тот же, что в pult/update.py). */
    public static String URL = "";
    /** Открытый ключ подписи выпусков: модуль (десятичное число) и экспонента. */
    public static String PUBLIC_N = "";
    public static long PUBLIC_E = 65537;

    private static final byte[] SHA256_PREFIX = hex("3031300d060960864801650304020105000420");

    public static boolean configured() {
        return !URL.isEmpty() && !PUBLIC_N.isEmpty();
    }

    static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    /** RSA PKCS#1 v1.5 с SHA-256: блок сравнивается целиком (как в программе для ПК). */
    public static boolean rsaVerify(byte[] message, byte[] sig, BigInteger n, BigInteger e) {
        try {
            int k = (n.bitLength() + 7) / 8;
            if (sig.length != k) {
                return false;
            }
            BigInteger m = new BigInteger(1, sig).modPow(e, n);
            byte[] raw = m.toByteArray();
            byte[] em = new byte[k];
            int copy = Math.min(raw.length, k);
            System.arraycopy(raw, raw.length - copy, em, k - copy, copy);
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(message);
            byte[] t = new byte[SHA256_PREFIX.length + digest.length];
            System.arraycopy(SHA256_PREFIX, 0, t, 0, SHA256_PREFIX.length);
            System.arraycopy(digest, 0, t, SHA256_PREFIX.length, digest.length);
            byte[] want = new byte[k];
            want[0] = 0;
            want[1] = 1;
            for (int i = 2; i < k - t.length - 1; i++) {
                want[i] = (byte) 0xff;
            }
            want[k - t.length - 1] = 0;
            System.arraycopy(t, 0, want, k - t.length, t.length);
            return MessageDigest.isEqual(em, want);
        } catch (Exception ex) {
            return false;
        }
    }

    /** Проверить подпись и вернуть выпуск; подпись не сходится — null. */
    public static Map<String, Object> unpack(Map<String, Object> signed, String n, long e) {
        try {
            String payload = Json.str(signed, "payload");
            byte[] sig = java.util.Base64.getDecoder().decode(Json.str(signed, "sig"));
            if (!rsaVerify(payload.getBytes(StandardCharsets.UTF_8), sig, new BigInteger(n), BigInteger.valueOf(e))) {
                return null;
            }
            return Json.parseObject(payload);
        } catch (Exception ex) {
            return null;
        }
    }

    // заранее подписанный тестовый выпуск: «Проверка программы» убеждается, что проверка подписи работает на этом телефоне
    static final String TEST_N = "101295429406745067193541624543707998398273298244221154198789317334431071128084200644582533"
            + "931239402875691632352411382752345680704385013003948843668640063200677900954753918486105371"
            + "229158290754542254789229423286036295043670385521109080937994207479197295453971661764166877"
            + "813085605467004048299229792068228546153";
    static final String TEST_PAYLOAD = "{\"notes\": \"vedomyj-selftest\", \"version\": \"0.0.1\"}";
    static final String TEST_SIG = "YN0Hg8io3FqLOJhYMBzXzc3ZOlezWvLaKAXxxyYtEpOMZTn74w5gmwsWF5PLtRRC1t0DbRyRLZJPdnHQjV2VqWSv/D"
            + "EuHfg4pya8wlaLjenBtnNUsRPl4+LmJ3Zu1ljqcX7VDYM07yETaBRcO2JGlTG0Q9YQB2yGv2QUBy/Jsyg=";

    /** Настоящая подпись принимается, подделка — нет. */
    public static boolean selfCheck() {
        Map<String, Object> good = unpack(Json.obj("payload", TEST_PAYLOAD, "sig", TEST_SIG), TEST_N, 65537);
        Map<String, Object> bad = unpack(Json.obj("payload", TEST_PAYLOAD.replace("0.0.1", "0.0.2"), "sig", TEST_SIG), TEST_N, 65537);
        return good != null && "vedomyj-selftest".equals(Json.str(good, "notes")) && bad == null;
    }

    /** Версия a новее b ("1.10.0" > "1.9.3"). */
    public static boolean newer(String a, String b) {
        String[] x = a.split("\\.");
        String[] y = b.split("\\.");
        for (int i = 0; i < Math.max(x.length, y.length); i++) {
            int xi = i < x.length ? num(x[i]) : 0;
            int yi = i < y.length ? num(y[i]) : 0;
            if (xi != yi) {
                return xi > yi;
            }
        }
        return false;
    }

    private static int num(String s) {
        try {
            return Integer.parseInt(s.replaceAll("\\D", ""));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    public static String sha256(java.io.File f) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        java.io.InputStream in = new java.io.FileInputStream(f);
        try {
            byte[] buf = new byte[1 << 16];
            int r;
            while ((r = in.read(buf)) > 0) {
                md.update(buf, 0, r);
            }
        } finally {
            in.close();
        }
        StringBuilder b = new StringBuilder();
        for (byte x : md.digest()) {
            b.append(String.format("%02x", x & 0xff));
        }
        return b.toString();
    }
}
