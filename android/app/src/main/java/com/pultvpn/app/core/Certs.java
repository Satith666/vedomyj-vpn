package com.pultvpn.app.core;

import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

/**
 * Проверка сертификатов — то же, что pult/certcheck.py на компьютере.
 * 1. Сертификаты на телефоне: стоит ли сертификат Минцифры («Russian Trusted Root CA» / «Sub CA») и другие,
 *    поставленные пользователем или приложениями. Браузеры (Chrome и др.) им доверяют — перехват соединений не заметят.
 * 2. Контрольные сайты (Google, GitHub, Википедия, Cloudflare): кто выдал их сертификаты — напрямую и через VPN.
 * Адреса и содержимое страниц не сохраняются: смотрим только, кто выдал сертификат.
 */
public final class Certs {
    private Certs() {
    }

    public static final String[] PROBE_HOSTS = {"www.google.com", "github.com", "www.wikipedia.org", "www.cloudflare.com"};

    // признаки сертификатов Минцифры (в DER они лежат как UTF8String/PrintableString)
    static final String[][] RUSSIAN_MARKS = {
            {"Russian Trusted Root CA", "Russian Trusted Root CA"},
            {"Russian Trusted Sub CA", "Russian Trusted Sub CA"},
            {"Минцифры", "Минцифры России"},
            {"Ministry of Digital Development", "Минцифры России"},
    };
    // антивирусы и фильтры, которые проверяют HTTPS (ставят свой корневой сертификат)
    static final String[] INTERCEPTORS = {"Kaspersky", "ESET", "Avast", "AVG", "Bitdefender", "Dr.Web", "Doctor Web", "Norton",
            "Fortinet", "FortiGate", "Zscaler", "Sophos", "Cisco Umbrella", "Check Point", "Palo Alto", "Netskope", "Blue Coat",
            "Symantec Web", "McAfee Web", "Trend Micro", "WebTitan", "Adguard", "AdGuard"};
    // известные публичные центры сертификации: их сертификаты у больших сайтов — норма
    static final String[] PUBLIC_CAS = {"Google Trust Services", "DigiCert", "Sectigo", "Let's Encrypt",
            "Internet Security Research Group", "GlobalSign", "Amazon", "Microsoft", "Cloudflare", "Entrust", "GoDaddy",
            "Starfield", "IdenTrust", "Certum", "Asseco", "Baltimore", "SSL.com", "HARICA", "Buypass", "Actalis", "QuoVadis",
            "COMODO", "Comodo", "USERTrust", "Apple", "Thawte", "GeoTrust", "RapidSSL", "Encryption Everywhere", "Telia",
            "Certainly", "Fastly", "Akamai", "ZeroSSL", "TrustAsia", "WoTrus", "Wikimedia", "GTS", "Go Daddy",
            "Network Solutions", "Gandi", "SwissSign", "D-TRUST", "T-Systems", "Deutsche Telekom", "Izenpe",
            "Firmaprofesional", "Chunghwa", "Secom", "SECOM", "Cybertrust", "Verizon", "VeriSign", "Symantec", "Trustwave",
            "SecureTrust", "AffirmTrust", "Atos", "emSign", "e-Tugra", "Hongkong Post"};

    /** Кто открывает соединение и смотрит сертификат: host, proxyPort (0 — напрямую). В проверке подменяется. */
    public interface Fetcher {
        Map<String, Object> fetch(String host, int proxyPort);
    }

    public static Fetcher FETCH = new Fetcher() {
        @Override
        public Map<String, Object> fetch(String host, int proxyPort) {
            return Certs.fetch(host, 443, proxyPort, 8000);
        }
    };

    /** Чем проверять сертификат (null — хранилище системы, как у браузера). Для самопроверки. */
    public static volatile X509TrustManager trustOverride;

    // ---------- признаки ----------

    private static boolean contains(byte[] hay, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= hay.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    public static List<String> russianNames(byte[] der) {
        List<String> found = new ArrayList<String>();
        if (der == null) {
            return found;
        }
        for (String[] m : RUSSIAN_MARKS) {
            if (contains(der, m[0].getBytes(StandardCharsets.UTF_8)) && !found.contains(m[1])) {
                found.add(m[1]);
            }
        }
        return found;
    }

    public static String interceptorName(String text) {
        String low = text == null ? "" : text.toLowerCase(Locale.ROOT);
        for (String n : INTERCEPTORS) {
            if (low.contains(n.toLowerCase(Locale.ROOT))) {
                return n;
            }
        }
        return "";
    }

    public static boolean knownPublic(String issuer) {
        String low = issuer == null ? "" : issuer.toLowerCase(Locale.ROOT);
        for (String ca : PUBLIC_CAS) {
            if (low.contains(ca.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    /** {O, CN} из имени вида «CN=…,O=…,C=RU» (RFC 2253, с экранированием). */
    static String[] orgAndCn(X500Principal p) {
        String org = "";
        String cn = "";
        String name = p == null ? "" : p.getName(X500Principal.RFC2253);
        List<String> parts = new ArrayList<String>();
        StringBuilder cur = new StringBuilder();
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c == '\\' && i + 1 < name.length()) {
                cur.append(name.charAt(++i));
            } else if (c == ',' || c == '+') {
                parts.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        parts.add(cur.toString());
        for (String part : parts) {
            int eq = part.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String k = part.substring(0, eq).trim().toUpperCase(Locale.ROOT);
            String v = part.substring(eq + 1).trim();
            if (k.equals("O") && org.isEmpty()) {
                org = v;
            } else if (k.equals("CN") && cn.isEmpty()) {
                cn = v;
            }
        }
        return new String[]{org, cn};
    }

    /** Короткое имя сертификата для списка: O или CN. */
    public static String certName(byte[] der) {
        try {
            X509Certificate c = (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                    .generateCertificate(new java.io.ByteArrayInputStream(der));
            String[] oc = orgAndCn(c.getSubjectX500Principal());
            return !oc[1].isEmpty() ? oc[1] : oc[0];
        } catch (Exception e) {
            return "?";
        }
    }

    private static String sha256(byte[] der) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(der);
            StringBuilder b = new StringBuilder();
            for (byte x : h) {
                b.append(String.format(Locale.ROOT, "%02x", x));
            }
            return b.toString();
        } catch (Exception e) {
            return "";
        }
    }

    // ---------- сертификат сайта ----------

    private static X509TrustManager systemTrust() throws Exception {
        TrustManagerFactory f = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        f.init((KeyStore) null);
        for (TrustManager t : f.getTrustManagers()) {
            if (t instanceof X509TrustManager) {
                return (X509TrustManager) t;
            }
        }
        throw new IllegalStateException("no X509TrustManager");
    }

    private static boolean certProblem(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof CertificateException || t instanceof javax.net.ssl.SSLPeerUnverifiedException
                    || t instanceof java.security.cert.CertPathValidatorException) {
                return true;
            }
            String m = t.getMessage() == null ? "" : t.getMessage();
            if (m.contains("certificate does not match") || m.contains("Trust anchor for certification path not found")) {
                return true;
            }
        }
        return false;
    }

    /**
     * {state: ok | bad | fail, issuer, russian: [...], interceptor, sha256, error}.
     * ok — сертификат проверен системой; bad — проверку не прошёл (поддельный или чужой); fail — не соединились.
     */
    public static Map<String, Object> fetch(String host, int port, int proxyPort, int timeoutMs) {
        final X509Certificate[] seen = new X509Certificate[1];
        SSLSocket ss = null;
        try {
            final X509TrustManager base = trustOverride != null ? trustOverride : systemTrust();
            X509TrustManager capture = new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    base.checkClientTrusted(chain, authType);
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    if (chain != null && chain.length > 0) {
                        seen[0] = chain[0]; // запоминаем, что прислали, даже если проверку не пройдёт
                    }
                    base.checkServerTrusted(chain, authType);
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return base.getAcceptedIssuers();
                }
            };
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{capture}, null);
            Socket raw = Http.openRaw(host, port, proxyPort, timeoutMs);
            ss = (SSLSocket) ctx.getSocketFactory().createSocket(raw, host, port, true);
            SSLParameters prm = ss.getSSLParameters();
            prm.setEndpointIdentificationAlgorithm("HTTPS");
            ss.setSSLParameters(prm);
            ss.startHandshake();
            if (Http.ANDROID && !HttpsURLConnection.getDefaultHostnameVerifier().verify(host, ss.getSession())) {
                throw new javax.net.ssl.SSLPeerUnverifiedException("certificate does not match " + host);
            }
            X509Certificate leaf = (X509Certificate) ss.getSession().getPeerCertificates()[0];
            byte[] der = leaf.getEncoded();
            String[] oc = orgAndCn(leaf.getIssuerX500Principal());
            String issuer = !oc[0].isEmpty() ? oc[0] : oc[1];
            return Json.obj("state", "ok", "issuer", issuer, "russian", new ArrayList<Object>(russianNames(der)),
                    "interceptor", interceptorName(oc[0] + " " + oc[1]), "sha256", sha256(der), "error", "");
        } catch (Exception e) {
            if (!certProblem(e) || seen[0] == null) {
                return Json.obj("state", "fail", "issuer", "", "russian", new ArrayList<Object>(), "interceptor", "",
                        "sha256", "", "error", Http.human(e));
            }
            byte[] der;
            try {
                der = seen[0].getEncoded();
            } catch (Exception x) {
                der = new byte[0];
            }
            List<String> names = russianNames(der);
            String[] oc = orgAndCn(seen[0].getIssuerX500Principal());
            String issuer = !names.isEmpty() ? names.get(0) : (!oc[0].isEmpty() ? oc[0] : oc[1]);
            return Json.obj("state", "bad", "issuer", issuer, "russian", new ArrayList<Object>(names),
                    "interceptor", interceptorName(oc[0] + " " + oc[1]), "sha256", sha256(der),
                    "error", Text.t("сертификат не прошёл проверку", "the certificate failed verification"));
        } finally {
            if (ss != null) {
                try {
                    ss.close();
                } catch (Exception ignored) {
                    // уже закрыт
                }
            }
        }
    }

    private static List<String> strs(Map<String, Object> m, String key) {
        List<String> out = new ArrayList<String>();
        List<Object> l = Json.list(m, key);
        if (l != null) {
            for (Object o : l) {
                out.add(String.valueOf(o));
            }
        }
        return out;
    }

    private static String join(List<String> l) {
        StringBuilder b = new StringBuilder();
        for (String s : l) {
            b.append(b.length() == 0 ? "" : ", ").append(s);
        }
        return b.toString();
    }

    // ---------- проверка целиком ----------

    /**
     * Итог для окна и отчётов: {items: [{state, title, detail, fix}], mitm, vpn_mitm, russian_root: [...], user_cas: [...],
     * errors, warnings}. vpnPort — вход приложения в VPN (0 — VPN выключен). roots — сертификаты Минцифры на телефоне,
     * userCas — другие сертификаты, поставленные пользователем (null — не знаем). direct=false — только путь через VPN.
     */
    public static Map<String, Object> check(int vpnPort, String[] hosts, List<String> roots, List<String> userCas,
                                            Fetcher fetcher, boolean direct) {
        hosts = hosts == null ? PROBE_HOSTS : hosts;
        fetcher = fetcher == null ? FETCH : fetcher;
        boolean store = direct && roots != null; // null — сертификаты телефона посмотреть не удалось
        roots = store ? roots : new ArrayList<String>();
        final List<Object> items = new ArrayList<Object>();
        String deleteHow = Text.t("Настройки → Безопасность → Шифрование и учётные данные → Пользовательские сертификаты "
                        + "(или «Надёжные сертификаты» → вкладка «Пользователь»)",
                "Settings → Security → Encryption & credentials → User credentials (or “Trusted credentials” → “User” tab)");
        if (store) {
            if (!roots.isEmpty()) {
                items.add(item("warn", Text.t("На телефоне стоит сертификат Минцифры: ", "A Russian Ministry of Digital Development certificate is installed: ")
                                + join(roots),
                        Text.t("Им можно подписать любой сайт, и браузер не заметит подмену. Обычно его ставят ради Сбербанка и Госуслуг.",
                                "It can sign any website and the browser won't notice the substitution. People usually install it for Sberbank and Gosuslugi."),
                        Text.t("Не нужен — удали: ", "Not needed — remove it: ") + deleteHow
                                + Text.t(". Для сайтов банков есть браузеры, где он уже встроен (Яндекс Браузер, Атом).",
                                ". For bank websites there are browsers with it built in (Yandex Browser, Atom).")));
            } else {
                items.add(item("ok", Text.t("Сертификатов Минцифры на телефоне нет", "No Russian Ministry certificates on the phone"), "", ""));
            }
            if (userCas != null && !userCas.isEmpty()) {
                String av = "";
                for (String n : userCas) {
                    av = av.isEmpty() ? interceptorName(n) : av;
                }
                items.add(item("info", Text.t("На телефоне установлены свои сертификаты: ", "Custom certificates are installed on the phone: ")
                                + join(userCas),
                        av.isEmpty() ? Text.t("Их ставит человек или приложение (рабочий профиль, блокировщик рекламы). Браузер им доверяет — "
                                        + "кто их поставил, может видеть защищённые соединения.",
                                "A person or an app installs them (work profile, ad blocker). The browser trusts them — whoever installed "
                                        + "them can see secure connections.")
                                : Text.t("Похоже, это " + av + ": он проверяет защищённые соединения. Это не провайдер.",
                                "Looks like " + av + ": it inspects secure connections. This is not your provider."),
                        Text.t("Не знаешь, откуда сертификат, — удали его: ", "Don't know where it came from — remove it: ") + deleteHow + "."));
            }
        }
        boolean mitm = false;
        boolean vpnMitm = false;
        List<String> directOk = new ArrayList<String>();
        String av = "";
        for (String host : hosts) {
            Map<String, Object> d = direct ? fetcher.fetch(host, 0) : Json.obj("state", "fail");
            Map<String, Object> v = vpnPort > 0 ? fetcher.fetch(host, vpnPort) : null;
            String vs = Json.str(v, "state");
            boolean vpnBad = v != null && ("bad".equals(vs) || ("ok".equals(vs) && (!strs(v, "russian").isEmpty()
                    || (!knownPublic(Json.str(v, "issuer")) && Json.str(v, "interceptor").isEmpty()))));
            if (vpnBad) {
                vpnMitm = true;
                String why = Json.str(v, "issuer").isEmpty() ? Json.str(v, "error") : Json.str(v, "issuer");
                items.add(item("error", Text.t("Через VPN сертификат " + host + " поддельный", "Through the VPN the certificate of " + host + " is fake"),
                        why, Text.t("Сервер VPN подменяет защищённые соединения. Не вводи пароли и смени сервер.",
                                "The VPN server substitutes secure connections. Don't enter passwords and switch the server.")));
            }
            String ds = Json.str(d, "state");
            if ("fail".equals(ds)) {
                continue; // сайт закрыт провайдером — сертификат не посмотреть, и это нормально
            }
            String issuer = Json.str(d, "issuer");
            if ("bad".equals(ds) || !strs(d, "russian").isEmpty()) {
                mitm = true;
                String how = issuer.isEmpty() ? Json.str(d, "error") : Text.t("сертификат выдан: ", "issued by: ") + issuer;
                String also = v != null && "ok".equals(vs) && !vpnMitm ? Text.t(" Через VPN он настоящий.", " Through the VPN it is genuine.") : "";
                items.add(item("error", Text.t("Напрямую сертификат " + host + " подменён", "Directly the certificate of " + host + " is substituted"),
                        how + "." + also,
                        Text.t("Соединения в этой сети перехватывают. Включи «Всё через VPN» и блокировку без VPN, пароли вводи только через VPN.",
                                "Connections in this network are intercepted. Turn on “Everything through VPN” and the kill switch; enter passwords only through the VPN.")));
            } else if (!Json.str(d, "interceptor").isEmpty()) {
                av = Json.str(d, "interceptor");
            } else if (!knownPublic(issuer)) {
                mitm = true;
                items.add(item("warn", Text.t("Сертификат " + host + " выдан неизвестным центром «" + issuer + "»",
                                "The certificate of " + host + " is issued by an unknown authority “" + issuer + "”"),
                        Text.t("Так бывает в сетях с проверкой трафика (работа, учёба, публичный Wi-Fi) или при перехвате.",
                                "This happens in networks with traffic inspection (work, school, public Wi-Fi) or during interception."),
                        Text.t("Пароли и личное — только через VPN.", "Passwords and personal stuff — only through the VPN.")));
            } else {
                directOk.add(host);
            }
        }
        if (!av.isEmpty()) {
            items.add(item("info", Text.t("Антивирус проверяет защищённые соединения (" + av + ")", "An antivirus inspects secure connections (" + av + ")"),
                    Text.t("Он видит, какие страницы ты открываешь. Это не провайдер — так работает твой антивирус.",
                            "It sees which pages you open. This is not your provider — that's how your antivirus works."),
                    Text.t("Не нравится — выключи в антивирусе «проверку защищённых соединений» (HTTPS).",
                            "Don't like it — turn off “secure connection scanning” (HTTPS) in the antivirus.")));
        }
        if (!directOk.isEmpty() && !mitm) {
            items.add(item("ok", Text.t("Подмены сертификатов напрямую нет", "No certificate substitution directly"), join(directOk), ""));
        }
        if (vpnPort > 0 && !vpnMitm) {
            items.add(item("ok", Text.t("Через VPN сертификаты настоящие", "Certificates through the VPN are genuine"), "", ""));
        }
        long errors = 0;
        long warnings = 0;
        for (Object o : items) {
            String st = Json.str(Json.map(o), "state");
            errors += "error".equals(st) ? 1 : 0;
            warnings += "warn".equals(st) ? 1 : 0;
        }
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        out.put("items", items);
        out.put("mitm", mitm);
        out.put("vpn_mitm", vpnMitm);
        out.put("russian_root", new ArrayList<Object>(roots));
        out.put("user_cas", userCas == null ? new ArrayList<Object>() : new ArrayList<Object>(userCas));
        out.put("errors", errors);
        out.put("warnings", warnings);
        return out;
    }

    private static Map<String, Object> item(String state, String title, String detail, String fix) {
        return Json.obj("state", state, "title", title, "detail", detail, "fix", fix);
    }
}
