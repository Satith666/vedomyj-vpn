package com.pultvpn.app.core;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * HTTP без библиотек. На телефоне запросы приложения идут мимо VPN (приложение исключено из туннеля).
 * Через ядро (вход HTTP 127.0.0.1:порт) — свой короткий клиент: туннель CONNECT с логином в первом же запросе.
 * Системный клиент Android через прокси с логином ходит ненадёжно (на телефоне так не открывался ни один сайт).
 */
public final class Http {
    private Http() {
    }

    public static final class Response {
        public int status;
        public Map<String, String> headers = new LinkedHashMap<String, String>(); // ключи в нижнем регистре
        public byte[] body = new byte[0];
        public long ms;
        public boolean truncated; // тело длиннее лимита и обрезано (только для проверок)

        public String text() {
            return new String(body, StandardCharsets.UTF_8);
        }
    }

    public static final int MAX_BODY = 8 * 1024 * 1024;
    static final String UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126 Mobile Safari/537.36";
    static final boolean ANDROID = System.getProperty("java.vendor", "").toLowerCase().contains("android");

    // логин для служебного входа ядра: без него другие приложения на телефоне могли бы ходить через него
    private static volatile int authPort;
    private static volatile String authUser = "";
    private static volatile String authPass = "";

    public static void setProxyAuth(int port, String user, String pass) {
        authPort = port;
        authUser = user;
        authPass = pass;
    }

    /** proxyPort: 0 — напрямую, иначе HTTP-прокси 127.0.0.1:proxyPort (вход ядра Xray). */
    public static Response get(String url, Map<String, String> headers, int timeoutMs, int proxyPort) throws IOException {
        return request(url, headers, timeoutMs, proxyPort, MAX_BODY);
    }

    /** Тело больше maxBody — ошибка «слишком большой ответ». */
    public static Response request(String url, Map<String, String> headers, int timeoutMs, int proxyPort, int maxBody)
            throws IOException {
        return exchange(url, headers, timeoutMs, proxyPort, maxBody, false, null);
    }

    /** Проверка сайта: читает не больше maxBytes и просто останавливается (большая страница — не ошибка). */
    public static Response probe(String url, Map<String, String> headers, int timeoutMs, int proxyPort, int maxBytes)
            throws IOException {
        return exchange(url, headers, timeoutMs, proxyPort, maxBytes, true, null);
    }

    /** Скачивает файл целиком (списки сайтов). */
    public static byte[] download(String url, int timeoutMs, int proxyPort, int maxBytes) throws IOException {
        Response r = request(url, null, timeoutMs, proxyPort, maxBytes);
        if (r.status != 200) {
            throw new IOException(Text.t("сервер ответил кодом ", "server answered with code ") + r.status);
        }
        return r.body;
    }

    /** Скачивает большой файл сразу на диск (через временный файл рядом). Возвращает размер. */
    public static long downloadTo(String url, File dest, int timeoutMs, int proxyPort, long maxBytes) throws IOException {
        File tmp = new File(dest.getPath() + ".part");
        OutputStream out = new FileOutputStream(tmp);
        Response r;
        try {
            try {
                r = exchange(url, null, timeoutMs, proxyPort, maxBytes, false, out);
            } catch (UnknownHostException e) {
                // свои загрузки (списки, обновления): DNS провайдера не знает адрес — берём его из защищённого DNS
                if (proxyPort > 0) {
                    throw e;
                }
                out.close();
                out = new FileOutputStream(tmp);
                r = viaProxy(url, null, timeoutMs, 0, maxBytes, false, out, null, null, true);
            }
        } catch (IOException e) {
            out.close();
            tmp.delete();
            throw e;
        }
        out.close();
        if (r.status != 200) {
            tmp.delete();
            throw new IOException(Text.t("сервер ответил кодом ", "server answered with code ") + r.status);
        }
        long size = tmp.length();
        if (dest.exists() && !dest.delete()) {
            tmp.delete();
            throw new IOException(Text.t("не удалось заменить файл", "could not replace the file"));
        }
        if (!tmp.renameTo(dest)) {
            tmp.delete();
            throw new IOException(Text.t("не удалось сохранить файл", "could not save the file"));
        }
        return size;
    }

    public static Response exchange(String url, Map<String, String> headers, int timeoutMs, int proxyPort, long maxBody,
                             boolean truncate, OutputStream sink) throws IOException {
        long started = System.nanoTime();
        Response r = proxyPort > 0 ? viaProxy(url, headers, timeoutMs, proxyPort, maxBody, truncate, sink, null, null, false)
                : direct(url, headers, timeoutMs, maxBody, truncate, sink);
        r.ms = (System.nanoTime() - started) / 1000000L;
        return r;
    }

    private static Response direct(String url, Map<String, String> headers, int timeoutMs, long maxBody, boolean truncate,
                                   OutputStream sink) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection(Proxy.NO_PROXY);
        try {
            c.setConnectTimeout(timeoutMs);
            c.setReadTimeout(timeoutMs);
            c.setInstanceFollowRedirects(true);
            c.setUseCaches(false);
            if (headers != null) {
                for (Map.Entry<String, String> e : headers.entrySet()) {
                    c.setRequestProperty(e.getKey(), e.getValue());
                }
            }
            Response r = new Response();
            r.status = c.getResponseCode();
            for (Map.Entry<String, List<String>> e : c.getHeaderFields().entrySet()) {
                if (e.getKey() != null && e.getValue() != null && !e.getValue().isEmpty()) {
                    r.headers.put(e.getKey().toLowerCase(), e.getValue().get(e.getValue().size() - 1));
                }
            }
            InputStream in = r.status >= 400 ? c.getErrorStream() : c.getInputStream();
            if (in != null) {
                try {
                    readBody(in, -1, maxBody, truncate, sink, r);
                } finally {
                    in.close();
                }
            }
            return r;
        } finally {
            c.disconnect();
        }
    }

    // ---------- свой клиент через вход ядра ----------

    /** Напрямую, но по адресу ip (из защищённого DNS) вместо DNS провайдера; в TLS — настоящее имя сайта,
     *  сертификат проверяется как обычно. */
    public static Response getPinned(String url, Map<String, String> headers, int timeoutMs, String pinHost, String pinIp)
            throws IOException {
        long started = System.nanoTime();
        Response r = viaProxy(url, headers, timeoutMs, 0, MAX_BODY, false, null, pinHost, pinIp, false);
        r.ms = (System.nanoTime() - started) / 1000000L;
        return r;
    }

    /** Свои загрузки (списки, обновления): напрямую; если DNS провайдера не знает адрес — через защищённый DNS.
     *  Проверки сайтов так делать нельзя: им нужно видеть, что DNS провайдера сайт не отдаёт. */
    public static Response requestOwn(String url, Map<String, String> headers, int timeoutMs, int proxyPort, int maxBody)
            throws IOException {
        if (proxyPort > 0) {
            return request(url, headers, timeoutMs, proxyPort, maxBody);
        }
        try {
            return request(url, headers, timeoutMs, 0, maxBody);
        } catch (UnknownHostException e) {
            return viaProxy(url, headers, timeoutMs, 0, maxBody, false, null, null, null, true);
        }
    }

    // Защищённый DNS (DoH, RFC 8484). Подключаемся к нему по известному адресу — сам запрос не уходит в DNS провайдера,
    // а сертификат проверяется по имени сервиса. Несколько сервисов: провайдер может закрыть один из них.
    public static String[][] DOH_SERVERS = {
            {"https://cloudflare-dns.com/dns-query", "cloudflare-dns.com", "1.1.1.1"},
            {"https://dns.google/dns-query", "dns.google", "8.8.8.8"},
            {"https://dns.quad9.net/dns-query", "dns.quad9.net", "9.9.9.9"},
            {"https://dns.adguard-dns.com/dns-query", "dns.adguard-dns.com", "94.140.14.14"},
    };
    private static final Map<String, Object[]> DOH_CACHE = new java.util.concurrent.ConcurrentHashMap<String, Object[]>();
    static final long DOH_TTL_MS = 600000L;

    /** Запрос DNS (тип A) в формате «как по сети». */
    public static byte[] dnsQuery(String host) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] head = {0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}; // id 0 (как велит RFC 8484), RD, 1 вопрос
        out.write(head, 0, head.length);
        String h = host.endsWith(".") ? host.substring(0, host.length() - 1) : host;
        for (String label : java.net.IDN.toASCII(h).split("\\.")) {
            byte[] b = label.getBytes(StandardCharsets.US_ASCII);
            if (b.length == 0 || b.length > 63) {
                throw new IllegalArgumentException("bad name");
            }
            out.write(b.length);
            out.write(b, 0, b.length);
        }
        byte[] tail = {0, 0, 1, 0, 1}; // конец имени, тип A, класс IN
        out.write(tail, 0, tail.length);
        return out.toByteArray();
    }

    private static int skipName(byte[] d, int i) {
        while (true) {
            int n = d[i] & 0xFF;
            if (n == 0) {
                return i + 1;
            }
            if ((n & 0xC0) == 0xC0) { // ссылка на имя выше
                return i + 2;
            }
            i += 1 + n;
        }
    }

    /** IPv4-адреса из ответа DNS. Битый ответ — пустой список. */
    public static List<String> dnsAnswers(byte[] d) {
        List<String> ips = new java.util.ArrayList<String>();
        try {
            if (d == null || d.length < 12 || (d[3] & 0x0F) != 0) { // код ответа не NOERROR
                return ips;
            }
            int qd = ((d[4] & 0xFF) << 8) | (d[5] & 0xFF);
            int an = ((d[6] & 0xFF) << 8) | (d[7] & 0xFF);
            int i = 12;
            for (int k = 0; k < qd; k++) {
                i = skipName(d, i) + 4;
            }
            for (int k = 0; k < an; k++) {
                i = skipName(d, i);
                int type = ((d[i] & 0xFF) << 8) | (d[i + 1] & 0xFF);
                int len = ((d[i + 8] & 0xFF) << 8) | (d[i + 9] & 0xFF);
                i += 10;
                if (type == 1 && len == 4 && i + 4 <= d.length) {
                    String ip = (d[i] & 0xFF) + "." + (d[i + 1] & 0xFF) + "." + (d[i + 2] & 0xFF) + "." + (d[i + 3] & 0xFF);
                    if (!"0.0.0.0".equals(ip)) {
                        ips.add(ip);
                    }
                }
                i += len;
            }
            return ips;
        } catch (ArrayIndexOutOfBoundsException e) {
            return new java.util.ArrayList<String>();
        }
    }

    /** IPv4-адреса сайта через защищённый DNS — в обход DNS провайдера. Пусто — не узнали. */
    public static List<String> dohResolve(String host, int timeoutMs) {
        List<String> ips = new java.util.ArrayList<String>();
        if (host == null || host.isEmpty() || host.length() > 253 || host.matches("[0-9.]+") || host.contains(":")) {
            return ips;
        }
        String key = host.toLowerCase();
        Object[] hit = DOH_CACHE.get(key);
        if (hit != null && System.currentTimeMillis() - (Long) hit[0] < DOH_TTL_MS) {
            @SuppressWarnings("unchecked")
            List<String> cached = (List<String>) hit[1];
            return new java.util.ArrayList<String>(cached);
        }
        String q;
        try {
            q = Text.b64encode(dnsQuery(key)).replace('+', '-').replace('/', '_').replace("=", "");
        } catch (RuntimeException e) {
            return ips;
        }
        Map<String, String> h = new LinkedHashMap<String, String>();
        h.put("Accept", "application/dns-message");
        for (String[] srv : DOH_SERVERS) {
            try {
                String url = srv[0] + "?dns=" + q;
                Response r = srv[1].isEmpty() ? request(url, h, timeoutMs, 0, 65536)
                        : viaProxy(url, h, timeoutMs, 0, 65536, false, null, srv[1], srv[2], false);
                List<String> got = r.status == 200 ? dnsAnswers(r.body) : new java.util.ArrayList<String>();
                if (!got.isEmpty()) {
                    DOH_CACHE.put(key, new Object[]{System.currentTimeMillis(), got});
                    return got;
                }
            } catch (Exception ignored) {
                // этот DNS не ответил — следующий
            }
        }
        return ips;
    }

    private static Response viaProxy(String url, Map<String, String> headers, int timeoutMs, int proxyPort, long maxBody,
                                     boolean truncate, OutputStream sink, String pinHost, String pinIp, boolean auto)
            throws IOException {
        String cur = url;
        for (int hop = 0; hop < 6; hop++) {
            URL u = new URL(cur);
            String host = u.getHost();
            boolean tls = "https".equalsIgnoreCase(u.getProtocol());
            if (!tls && !"http".equalsIgnoreCase(u.getProtocol())) {
                throw new IOException("unsupported scheme");
            }
            int port = u.getPort() > 0 ? u.getPort() : (tls ? 443 : 80);
            String hostPort = (host.contains(":") && !host.startsWith("[") ? "[" + host + "]" : host) + ":" + port;
            Socket raw = new Socket(Proxy.NO_PROXY);
            Socket s = raw;
            try {
                if (proxyPort <= 0) {
                    // напрямую: к адресу из защищённого DNS (для этого сайта) или как обычно; auto — если DNS
                    // провайдера не знает имя (и после перенаправления на другой сайт), спросить защищённый DNS
                    boolean pin = pinIp != null && host.equalsIgnoreCase(pinHost);
                    InetSocketAddress addr = pin ? new InetSocketAddress(java.net.InetAddress.getByName(pinIp), port)
                            : new InetSocketAddress(host, port);
                    if (addr.isUnresolved() && auto) {
                        List<String> got = dohResolve(host, 6000);
                        if (!got.isEmpty()) {
                            addr = new InetSocketAddress(java.net.InetAddress.getByName(got.get(0)), port);
                        }
                    }
                    if (addr.isUnresolved()) {
                        throw new UnknownHostException(host);
                    }
                    raw.connect(addr, timeoutMs);
                    raw.setSoTimeout(timeoutMs);
                    raw.setTcpNoDelay(true);
                } else {
                    raw.connect(new InetSocketAddress("127.0.0.1", proxyPort), timeoutMs);
                    raw.setSoTimeout(timeoutMs);
                    raw.setTcpNoDelay(true);
                    StringBuilder connect = new StringBuilder("CONNECT ").append(hostPort).append(" HTTP/1.1\r\nHost: ")
                            .append(hostPort).append("\r\n");
                    if (proxyPort == authPort && authPort > 0) {
                        connect.append("Proxy-Authorization: Basic ").append(Text.b64encode(
                                (authUser + ":" + authPass).getBytes(StandardCharsets.UTF_8))).append("\r\n");
                    }
                    connect.append("\r\n");
                    raw.getOutputStream().write(connect.toString().getBytes(StandardCharsets.ISO_8859_1));
                    raw.getOutputStream().flush();
                    InputStream rin = raw.getInputStream();
                    int code = statusCode(readLine(rin));
                    while (!readLine(rin).isEmpty()) {
                        // заголовки ответа прокси не нужны
                    }
                    if (code <= 0) {
                        throw new IOException(Text.t("соединение оборвалось", "connection dropped"));
                    }
                    if (code != 200) {
                        throw new IOException(code == 407 ? Text.t("вход ядра не принял логин (407)", "the core entry rejected the login (407)")
                                : Text.t("вход ядра ответил кодом ", "the core entry answered with code ") + code);
                    }
                }
                if (tls) {
                    SSLSocket ss = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(raw, host, port, true);
                    SSLParameters prm = ss.getSSLParameters();
                    prm.setEndpointIdentificationAlgorithm("HTTPS");
                    ss.setSSLParameters(prm);
                    ss.startHandshake();
                    if (ANDROID && !HttpsURLConnection.getDefaultHostnameVerifier().verify(host, ss.getSession())) {
                        throw new SSLException("certificate does not match " + host);
                    }
                    s = ss;
                }
                String path = u.getFile().isEmpty() ? "/" : u.getFile();
                Map<String, String> h = new LinkedHashMap<String, String>();
                h.put("Host", port == (tls ? 443 : 80) ? host : hostPort);
                h.put("User-Agent", UA);
                h.put("Accept", "*/*");
                if (headers != null) {
                    for (Map.Entry<String, String> e : headers.entrySet()) {
                        h.put(e.getKey(), e.getValue());
                    }
                }
                h.put("Accept-Encoding", "identity");
                h.put("Connection", "close");
                StringBuilder req = new StringBuilder("GET ").append(path).append(" HTTP/1.1\r\n");
                for (Map.Entry<String, String> e : h.entrySet()) {
                    String v = e.getValue() == null ? "" : e.getValue().replace("\r", "").replace("\n", "");
                    req.append(e.getKey()).append(": ").append(v).append("\r\n");
                }
                req.append("\r\n");
                OutputStream out = s.getOutputStream();
                out.write(req.toString().getBytes(StandardCharsets.UTF_8));
                out.flush();
                InputStream in = new BufferedInputStream(s.getInputStream(), 16384);
                Response r = new Response();
                r.status = statusCode(readLine(in));
                if (r.status <= 0) {
                    throw new IOException(Text.t("сайт не ответил", "the site did not answer"));
                }
                String line;
                while (!(line = readLine(in)).isEmpty()) {
                    int k = line.indexOf(':');
                    if (k > 0) {
                        r.headers.put(line.substring(0, k).trim().toLowerCase(), line.substring(k + 1).trim());
                    }
                }
                String loc = r.headers.get("location");
                if (r.status >= 300 && r.status < 400 && loc != null && !loc.isEmpty()) {
                    cur = new URL(u, loc).toString();
                    continue;
                }
                if ("chunked".equalsIgnoreCase(r.headers.get("transfer-encoding"))) {
                    readBody(new Chunked(in), -1, maxBody, truncate, sink, r);
                } else {
                    long len = -1;
                    try {
                        len = Long.parseLong(r.headers.containsKey("content-length") ? r.headers.get("content-length") : "-1");
                    } catch (NumberFormatException ignored) {
                        len = -1;
                    }
                    readBody(in, len, maxBody, truncate, sink, r);
                }
                return r;
            } finally {
                try {
                    s.close();
                } catch (IOException ignored) {
                    // уже закрыт
                }
                try {
                    raw.close();
                } catch (IOException ignored) {
                    // уже закрыт
                }
            }
        }
        throw new IOException(Text.t("слишком много перенаправлений", "too many redirects"));
    }

    /** Тело ответа: в память (r.body) или в sink. len = -1 — до конца соединения. */
    private static void readBody(InputStream in, long len, long maxBody, boolean truncate, OutputStream sink, Response r)
            throws IOException {
        if (maxBody == 0 && sink == null) {
            return; // тело не нужно (проверка «отвечает ли»)
        }
        ByteArrayOutputStream mem = sink == null ? new ByteArrayOutputStream() : null;
        OutputStream out = sink != null ? sink : mem;
        byte[] buf = new byte[16384];
        long total = 0;
        while (len < 0 || total < len) {
            int want = (int) (len < 0 ? buf.length : Math.min(buf.length, len - total));
            int n = in.read(buf, 0, want);
            if (n < 0) {
                break;
            }
            if (maxBody >= 0 && total + n > maxBody) {
                if (!truncate) {
                    throw new IOException(Text.t("слишком большой ответ", "response is too large"));
                }
                out.write(buf, 0, (int) (maxBody - total));
                total = maxBody;
                r.truncated = true;
                break;
            }
            out.write(buf, 0, n);
            total += n;
        }
        if (mem != null) {
            r.body = mem.toByteArray();
        }
    }

    // ---------- «качается ли»: зависание соединения после первых килобайт (как в программе для ПК) ----------

    public static final int STALL_TARGET = 64 * 1024;

    /** Считает байты, пришедшие из сети. */
    private static final class Counting extends InputStream {
        final InputStream in;
        long n;

        Counting(InputStream in) {
            this.in = in;
        }

        @Override
        public int read() throws IOException {
            int c = in.read();
            if (c >= 0) {
                n++;
            }
            return c;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int r = in.read(b, off, len);
            if (r > 0) {
                n += r;
            }
            return r;
        }
    }

    private static final class Closed extends IOException {
        Closed() {
            super("closed");
        }
    }

    /** Один ответ HTTP/1.1 целиком. → {код, Location, закрыто ли соединение}. */
    private static Object[] readOne(Counting in) throws IOException {
        String status = readLine(in);
        if (status.isEmpty() && in.n == 0) {
            throw new Closed();
        }
        int code = statusCode(status);
        if (code <= 0) {
            throw new Closed();
        }
        long len = -1;
        boolean chunked = false;
        boolean close = false;
        String location = "";
        String line;
        while (!(line = readLine(in)).isEmpty()) {
            int c = line.indexOf(':');
            if (c <= 0) {
                continue;
            }
            String k = line.substring(0, c).trim().toLowerCase(java.util.Locale.ROOT);
            String v = line.substring(c + 1).trim();
            if (k.equals("content-length")) {
                try {
                    len = Long.parseLong(v);
                } catch (NumberFormatException ignored) {
                    len = -1;
                }
            } else if (k.equals("transfer-encoding") && v.toLowerCase(java.util.Locale.ROOT).contains("chunked")) {
                chunked = true;
            } else if (k.equals("connection") && v.equalsIgnoreCase("close")) {
                close = true;
            } else if (k.equals("location")) {
                location = v;
            }
        }
        byte[] buf = new byte[16384];
        if (chunked) {
            while (true) {
                String sz = readLine(in);
                int semi = sz.indexOf(';');
                long size;
                try {
                    size = Long.parseLong((semi >= 0 ? sz.substring(0, semi) : sz).trim(), 16);
                } catch (NumberFormatException e) {
                    return new Object[]{code, location, true};
                }
                if (size == 0) {
                    while (!readLine(in).isEmpty()) {
                        // окончание и заголовки после него
                    }
                    break;
                }
                skip(in, size + 2, buf);
            }
        } else if (len >= 0) {
            skip(in, len, buf);
        } else if (!(code == 204 || code == 304 || code < 200)) {
            while (in.read(buf) >= 0) {
                // длина не указана — до закрытия
            }
            close = true;
        }
        return new Object[]{code, location, close};
    }

    private static void skip(InputStream in, long n, byte[] buf) throws IOException {
        while (n > 0) {
            int r = in.read(buf, 0, (int) Math.min(buf.length, n));
            if (r < 0) {
                throw new Closed();
            }
            n -= r;
        }
    }

    /**
     * Проверка «качается ли» с сайта: одно соединение, страница несколько раз подряд (keep-alive), пока не придёт
     * target байт. → {state: ok | stall | fail | small, bytes, detail}. proxyPort 0 — напрямую (приложение вне VPN).
     */
    public static Map<String, Object> stallTest(String host, int proxyPort, int port, int stallMs, int totalMs, int target) {
        long t0 = System.currentTimeMillis();
        long deadline = t0 + totalMs;
        Socket raw = new Socket(Proxy.NO_PROXY);
        Socket s = raw;
        Counting in;
        OutputStream out;
        try {
            if (proxyPort > 0) {
                raw.connect(new InetSocketAddress("127.0.0.1", proxyPort), 8000);
                raw.setSoTimeout(8000);
                String hp = host + ":" + port;
                StringBuilder c = new StringBuilder("CONNECT ").append(hp).append(" HTTP/1.1\r\nHost: ").append(hp).append("\r\n");
                if (proxyPort == authPort && authPort > 0) {
                    c.append("Proxy-Authorization: Basic ").append(Text.b64encode(
                            (authUser + ":" + authPass).getBytes(StandardCharsets.UTF_8))).append("\r\n");
                }
                raw.getOutputStream().write(c.append("\r\n").toString().getBytes(StandardCharsets.ISO_8859_1));
                InputStream rin = raw.getInputStream();
                int code = statusCode(readLine(rin));
                while (!readLine(rin).isEmpty()) {
                    // заголовки прокси
                }
                if (code != 200) {
                    throw new IOException(Text.t("вход ядра ответил кодом ", "the core entry answered with code ") + code);
                }
            } else {
                raw.connect(new InetSocketAddress(host, port), 8000);
            }
            raw.setSoTimeout(stallMs);
            if (port == 443) {
                javax.net.ssl.SSLContext ctx = javax.net.ssl.SSLContext.getInstance("TLS");
                ctx.init(null, new javax.net.ssl.TrustManager[]{new javax.net.ssl.X509TrustManager() {
                    // только замер скорости: никаких данных не отправляем, сертификат не важен
                    @Override
                    public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {
                    }

                    @Override
                    public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {
                    }

                    @Override
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new java.security.cert.X509Certificate[0];
                    }
                }}, null);
                SSLSocket ss = (SSLSocket) ctx.getSocketFactory().createSocket(raw, host, port, true);
                ss.startHandshake();
                s = ss;
            }
            in = new Counting(new BufferedInputStream(s.getInputStream(), 16384));
            out = s.getOutputStream();
        } catch (Exception e) {
            closeQuietly(s);
            closeQuietly(raw);
            return Json.obj("state", "fail", "bytes", 0L, "detail", human(e));
        }
        String path = "/";
        int done = 0;
        long started = 0; // сколько байт было до начала текущего ответа
        try {
            while (in.n < target && done < 40 && System.currentTimeMillis() < deadline) {
                started = in.n;
                String req = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: " + UA
                        + "\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: keep-alive\r\n\r\n";
                out.write(req.getBytes(StandardCharsets.UTF_8));
                out.flush();
                done++;
                Object[] r = readOne(in);
                if ((Boolean) r[2]) {
                    break;
                }
                int code = (Integer) r[0];
                String loc = (String) r[1];
                if (code >= 300 && code < 400 && loc.startsWith("/") && !loc.startsWith("//")) {
                    path = loc;
                }
            }
        } catch (SocketTimeoutException e) {
            long kb = Math.max(1, in.n / 1024);
            return in.n >= 1024 ? Json.obj("state", "stall", "bytes", in.n, "detail", Text.t("соединение замирает после " + kb + " КБ",
                    "connection freezes after " + kb + " KB")) : Json.obj("state", "fail", "bytes", in.n, "detail", Text.t("сайт не отвечает", "the site does not respond"));
        } catch (Closed e) {
            // сервер сам закрыл соединение — норма
        } catch (IOException e) {
            if (in.n == 0) {
                return Json.obj("state", "fail", "bytes", 0L, "detail", human(e));
            }
            if (in.n < target && in.n > started) { // оборвали посреди ответа; между ответами — сервер просто закрыл
                long kb = Math.max(1, in.n / 1024);
                return Json.obj("state", "stall", "bytes", in.n, "detail", Text.t("соединение обрывается после " + kb + " КБ",
                        "connection is cut after " + kb + " KB"));
            }
        } finally {
            closeQuietly(s);
            closeQuietly(raw);
        }
        long ms = System.currentTimeMillis() - t0;
        return in.n >= target ? Json.obj("state", "ok", "bytes", in.n, "detail", Text.t(in.n / 1024 + " КБ за " + ms + " мс", in.n / 1024 + " KB in " + ms + " ms"))
                : Json.obj("state", "small", "bytes", in.n, "detail", "");
    }

    /**
     * Голое TCP-соединение с host:port — напрямую (proxyPort 0) или через вход ядра (CONNECT, с логином для входа
     * приложения). Для проверки сертификатов: TLS поверх него делает тот, кто вызвал.
     */
    static Socket openRaw(String host, int port, int proxyPort, int timeoutMs) throws IOException {
        Socket raw = new Socket(Proxy.NO_PROXY);
        try {
            if (proxyPort > 0) {
                raw.connect(new InetSocketAddress("127.0.0.1", proxyPort), timeoutMs);
                raw.setSoTimeout(timeoutMs);
                String hp = host + ":" + port;
                StringBuilder c = new StringBuilder("CONNECT ").append(hp).append(" HTTP/1.1\r\nHost: ").append(hp).append("\r\n");
                if (proxyPort == authPort && authPort > 0) {
                    c.append("Proxy-Authorization: Basic ").append(Text.b64encode(
                            (authUser + ":" + authPass).getBytes(StandardCharsets.UTF_8))).append("\r\n");
                }
                raw.getOutputStream().write(c.append("\r\n").toString().getBytes(StandardCharsets.ISO_8859_1));
                raw.getOutputStream().flush();
                InputStream rin = raw.getInputStream();
                int code = statusCode(readLine(rin));
                while (!readLine(rin).isEmpty()) {
                    // заголовки прокси
                }
                if (code != 200) {
                    throw new IOException(code <= 0 ? Text.t("соединение оборвалось", "connection dropped")
                            : Text.t("вход ядра ответил кодом ", "the core entry answered with code ") + code);
                }
            } else {
                raw.connect(new InetSocketAddress(host, port), timeoutMs);
                raw.setSoTimeout(timeoutMs);
            }
            return raw;
        } catch (IOException e) {
            closeQuietly(raw);
            throw e;
        }
    }

    private static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (IOException ignored) {
            // уже закрыт
        }
    }

    static int statusCode(String line) {
        // «HTTP/1.1 200 OK»
        String[] p = line == null ? new String[0] : line.trim().split(" ");
        if (p.length < 2 || !p[0].startsWith("HTTP/")) {
            return -1;
        }
        try {
            return Integer.parseInt(p[1]);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) >= 0) {
            if (c == '\n') {
                break;
            }
            if (c != '\r') {
                b.write(c);
            }
            if (b.size() > 64 * 1024) {
                throw new IOException("header line too long");
            }
        }
        return new String(b.toByteArray(), StandardCharsets.ISO_8859_1);
    }

    /** Тело в кусках (Transfer-Encoding: chunked). */
    private static final class Chunked extends InputStream {
        private final InputStream in;
        private long left;
        private boolean done;

        Chunked(InputStream in) {
            this.in = in;
        }

        private boolean next() throws IOException {
            if (done) {
                return false;
            }
            if (left == 0) {
                String line = readLine(in).trim();
                if (line.isEmpty()) {
                    line = readLine(in).trim(); // CRLF после предыдущего куска
                }
                int semi = line.indexOf(';');
                try {
                    left = Long.parseLong(semi >= 0 ? line.substring(0, semi) : line, 16);
                } catch (NumberFormatException e) {
                    throw new IOException("bad chunk");
                }
                if (left == 0) {
                    done = true;
                    return false;
                }
            }
            return true;
        }

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            return read(one, 0, 1) < 0 ? -1 : one[0] & 0xff;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (!next()) {
                return -1;
            }
            int n = in.read(b, off, (int) Math.min(len, left));
            if (n < 0) {
                throw new IOException("unexpected end of chunk");
            }
            left -= n;
            return n;
        }
    }

    /** Понятный текст ошибки сети. */
    public static String human(Throwable e) {
        if (e instanceof SocketTimeoutException) {
            return Text.t("нет ответа (время вышло)", "no answer (timed out)");
        }
        if (e instanceof UnknownHostException) {
            return Text.t("адрес не найден (DNS)", "address not found (DNS)");
        }
        if (e instanceof SSLException) {
            return Text.t("ошибка защищённого соединения (TLS)", "secure connection error (TLS)");
        }
        String m = e.getMessage();
        if (m == null || m.isEmpty()) {
            return e.getClass().getSimpleName();
        }
        String low = m.toLowerCase();
        if (low.contains("refused")) {
            return Text.t("соединение отклонено", "connection refused");
        }
        if (low.contains("reset")) {
            return Text.t("соединение сброшено", "connection reset");
        }
        if (low.contains("unreachable")) {
            return Text.t("сеть недоступна", "network unreachable");
        }
        return Text.shorten(m, 160);
    }
}
