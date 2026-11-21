import com.pultvpn.app.core.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Сверка с программой для Windows: разбор ссылок, правил и ссылок своего сервера (вывод — JSON по строке). */
public class Dump {
    public static void main(String[] a) throws Exception {
        BufferedReader r = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        PrintStream out = new PrintStream(System.out, true, "UTF-8");
        String mode = a[0];
        String line;
        Set<String> siteLines = new HashSet<String>();
        StringBuilder updIn = new StringBuilder();
        while ((line = r.readLine()) != null) {
            if (mode.equals("updateverify")) {
                updIn.append(line);
                continue;
            }
            if (mode.equals("proxies")) {
                try {
                    out.println(Json.canonical(Proxies.parse(line, "auto")));
                } catch (Proxies.ProxyError e) {
                    out.println("\"bad\"");
                }
                continue;
            }
            if (mode.equals("siteentry")) {
                out.println(Json.canonical(Routing.siteEntry(line)));
                continue;
            }
            if (mode.equals("adsite")) {
                out.println(Json.canonical(Arrays.asList((Object) AdBlock.protectedKind(line), AdBlock.siteName(line), AdBlock.looksLikeAds(line))));
                if (!line.trim().isEmpty()) {
                    siteLines.add(line.trim());
                }
                continue;
            }
            if (mode.equals("adsline")) {
                Set<String> got = new TreeSet<String>(AdBlock.parse(line.replace("\\n", "\n"), line.startsWith("||") ? "adblock" : "domains"));
                out.println(Json.canonical(new ArrayList<Object>(got)));
                continue;
            }
            if (mode.equals("links")) {
                Server s = Links.parseLink(line);
                if (s == null) { out.println("null"); continue; }
                Map<String, Object> m = Json.obj("name", s.name, "protocol", s.protocol, "address", s.address,
                        "port", s.port, "outbound", s.outbound, "supported", s.supported, "insecure", s.insecure,
                        "stub", s.stub, "kind", Links.kindOf(s));
                out.println(Json.canonical(m));
            } else if (mode.equals("routing")) {
                try {
                    String[] e = Routing.normalizeEntry(line);
                    out.println(e == null ? "null" : Json.canonical(Json.arr(e[0], e[1])));
                } catch (IllegalArgumentException e) {
                    out.println("\"bad\"");
                }
            } else if (mode.equals("sub")) {
                StringBuilder all = new StringBuilder(line);
                String l2;
                while ((l2 = r.readLine()) != null) all.append('\n').append(l2);
                Subscription s = Subscription.parseBody(all.toString());
                List<Object> names = new ArrayList<Object>();
                for (Server x : s.servers) names.add(Json.arr(x.name, x.protocol, x.supported, x.stub, x.insecure));
                out.println(Json.canonical(names));
            }
        }
        if (mode.equals("adsite")) {
            out.println(Json.canonical(Json.arr(new ArrayList<Object>(new TreeSet<String>(AdBlock.SAFE_TREE)),
                    new ArrayList<Object>(new TreeSet<String>(AdBlock.SAFE_SITES)))));
            out.println(Json.canonical(new ArrayList<Object>(new TreeSet<String>(AdBlock.protect(siteLines)))));
        }
        if (mode.equals("updateverify")) {
            Map<String, Object> v = Json.parseObject(updIn.toString());
            Map<String, Object> ok = Update.unpack(Json.map(v, "signed"), Json.str(v, "n"), Json.num(v, "e", 65537));
            Map<String, Object> bad = Update.unpack(Json.map(v, "forged"), Json.str(v, "n"), Json.num(v, "e", 65537));
            out.println((ok == null ? "bad" : "ok " + Json.str(ok, "version") + " " + Json.str(ok, "notes")) + " | " + (bad == null ? "forged rejected" : "FORGED ACCEPTED"));
        }
        if (mode.equals("vps")) {
            out.print(Vps.script());
        }
        if (mode.equals("dns")) {
            for (String h : new String[]{"allvsub.cc", "Sub.Example.COM.", "пример.рф", "a.b.c.d.e"}) {
                StringBuilder hx = new StringBuilder();
                for (byte b : Http.dnsQuery(h.toLowerCase())) hx.append(String.format("%02x", b & 0xFF));
                out.println(hx);
            }
            String resp = "00008180000100030000000007616c6c767375620263630000010001c00c0005000100000e100002c00cc00c000100010000003c0004b9b2d0a0c00c000100010000003c000400000000";
            byte[] d = new byte[resp.length() / 2];
            for (int i = 0; i < d.length; i++) d[i] = (byte) Integer.parseInt(resp.substring(2 * i, 2 * i + 2), 16);
            out.println(Http.dnsAnswers(d));
            out.println(Http.dnsAnswers(java.util.Arrays.copyOf(d, 40)));
        }
        if (mode.equals("vpsextra")) {
            out.print(Vps.statusScript());
            out.print(Vps.friendScript("add", ""));
            out.print(Vps.friendScript("remove", "11111111-2222-3333-4444-555555555555"));
            out.println(Json.canonical(Vps.parseStatus("90061|0.15 0.10 0.05|310/1987|3.1G/25G|123456|654321|active|4|1")));
            out.println(Json.canonical(Vps.parseStatus("x|<b>|9999999999999999999|a;b|-1|2|act$ive|٣|0")));
        }
        if (mode.equals("services")) {
            List<Object> l = new ArrayList<Object>();
            for (Services.Service sv : Services.ALL) l.add(Json.arr(sv.name, new ArrayList<Object>(sv.domains), sv.russian));
            out.println(Json.canonical(Json.arr(l, new ArrayList<Object>(Services.YOUTUBE_DOMAINS), new ArrayList<Object>(Services.DISCORD_DOMAINS))));
        }
        if (mode.equals("warp")) {
            byte[] seed = new byte[32];
            for (int i = 0; i < 32; i++) seed[i] = (byte) i;
            out.println(Json.canonical(Json.arr((Object[]) Warp.keypair(seed))));
            byte[] d1 = new byte[8], k1 = new byte[32], d2 = new byte[8];
            for (int i = 0; i < 8; i++) { d1[i] = (byte) i; d2[i] = (byte) (200 + i); }
            for (int i = 0; i < 32; i++) k1[i] = (byte) (100 + i);
            out.println(Warp.quicI1("vk.com", d1, k1));
            out.println(Warp.quicI1("www.google.com", d2, new byte[32]));
            out.println(Warp.dnsI1("yandex.ru", 100));
            out.println(Warp.stunI1(16));
            out.println(Warp.sipI1("www.google.com", 1, 2));
            Map<String, Object> acct = Json.obj("private_key", Warp.keypair(seed)[0], "peer", Warp.PEER_KEY,
                    "v4", "172.16.0.2", "v6", "2606:4700:110:8a36::1");
            Map<String, Object> p1 = Json.obj("endpoint", "162.159.192.1:2408", "jc", 5, "jmin", 20, "jmax", 90, "i1", Warp.DNS_YANDEX_I1);
            Map<String, Object> p2 = Json.obj("endpoint", "188.114.99.1:1701", "jc", 7, "jmin", 11, "jmax", 33, "i1", Warp.stunI1(20));
            String conf = Warp.buildConf(acct, p1);
            out.print(conf);
            String v = Warp.variant(conf, p2);
            out.print(v);
            Map<String, Object> cp = Warp.currentParams(v);
            out.println(cp.get("endpoint") + "|" + cp.get("jc") + "|" + cp.get("jmin") + "|" + cp.get("jmax") + "|" + cp.get("i1"));
            out.println(Json.canonical(Json.arr(Warp.isWarp(conf), Warp.isWarp(conf.replace(Warp.PEER_KEY, "x")))));
        }
        if (mode.equals("vpslinks")) {
            out.println(Json.canonical(Vps.makeLinks("203.0.113.10", "11111111-2222-3333-4444-555555555555|" +
                "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde|0123abcd|a1b2c3d4e5f6", "Мой сервер")));
        }
    }
}
