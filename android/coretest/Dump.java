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
        StringBuilder famIn = new StringBuilder();
        while ((line = r.readLine()) != null) {
            if (mode.equals("familyopen")) {
                famIn.append(line).append('\n');
                continue;
            }
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
            if (mode.equals("adsabp")) {
                List<Set<String>> ab = AdBlock.parseAbp(line.replace("\\n", "\n"));
                out.println(Json.canonical(Arrays.asList((Object) new ArrayList<Object>(new TreeSet<String>(ab.get(0))),
                        new ArrayList<Object>(new TreeSet<String>(ab.get(1))))));
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
        if (mode.equals("vpsawg")) {
            final int[] c = {0};
            Warp.Rnd rnd = n -> (int) ((c[0]++ * 7919L) % n);
            String pub = "qgIEo+uU039puNbXT/0Dp83v1gKwmUMtxRlqB1VdrX4=";
            for (int k = 0; k < 3; k++) {
                Map<String, Object> p = Vps.awgParams(rnd);
                out.println(Json.canonical(p));
                out.println(Json.canonical(Vps.checkAwgParams(p)));
            }
            Map<String, Object> p = Vps.awgParams(rnd);
            out.print(Vps.awgScript(pub, 45123, p));
            out.print(Vps.awgPeerScript(pub));
            for (String rr : new String[]{pub + "|45123", pub + "|45123|7", "x|45123", pub + "|80", pub + "|45123|999"}) {
                try {
                    Object[] x = Vps.parseAwgResult(rr);
                    out.println(x[0] + " " + x[1] + " " + x[2]);
                } catch (Vps.VpsError e) {
                    out.println("bad");
                }
            }
            out.print(Vps.awgClientConf("203.0.113.10", 45123, pub, "0DwJdaudL51JBFBTWtyQF+QPxOBERLhw0ye1fXBLjEQ=", 3, p, Warp.DNS_YANDEX_I1));
            Map<String, Object> bad = new LinkedHashMap<String, Object>(p);
            bad.put("H2", p.get("H1"));
            try {
                Vps.checkAwgParams(bad);
                out.println("accepted");
            } catch (Vps.VpsError e) {
                out.println("bad");
            }
        }
        if (mode.equals("vpsbridge")) {
            String good = "vless://3f1c2a9e-1b2c-4d5e-8f90-1234567890ab@203.0.113.10:443?type=tcp&security=reality"
                    + "&pbk=cHVibGljLWtleS1mb3ItdGVzdGluZy1yZWFsaXR5LXh4&fp=chrome&sni=www.microsoft.com&sid=0123456789abcdef&flow=xtls-rprx-vision#x";
            String[] links = {good, good.replace("203.0.113.10", "[2001:db8::7]"), good.replace(":443?", ":8443?").replace("&flow=xtls-rprx-vision", ""),
                    good.replace("3f1c2a9e", "$(id)x"), good.replace("203.0.113.10", "a;b"), good.replace("security=reality", "security=tls"),
                    good.replace("type=tcp", "type=ws"), good.replace("sni=www.microsoft.com", "sni=$HOME"), good.replace(":443?", ":99999?"),
                    good.replace("sid=0123456789abcdef", "sid="), "vmess://abc"};
            for (String l : links) {
                try {
                    out.println(Json.canonical(Vps.parseForward(l)));
                } catch (Vps.VpsError e) {
                    out.println("bad");
                }
            }
            out.print(Vps.bridgeScript(Vps.parseForward(good), Vps.RU_SNI));
            out.println(String.join("\n", Vps.makeLinks("198.51.100.5", "9a9a9a9a-1b2c-4d5e-8f90-1234567890ab|cnUtcHVibGljLWtleS1mb3ItdGVzdGluZy1icmlkZ2V4|fedcba9876543210|0a0b0c0d", "Мост · белые списки", Vps.RU_SNI)));
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
            // WARP во встроенном ядре: запись CPS → байты, outbound WireGuard с шумом, конфиг для QR
            final int[] c = {0};
            Warp.Rnd rnd = new Warp.Rnd() {
                @Override
                public int next(int n) {
                    return c[0]++ % n;
                }
            };
            byte[] cb = Warp.cpsBytes("<b 0x0102ff><r 2><rc 3><rd 2><r 4-9><t><c><n>", rnd, 0x01020304L);
            out.println(Warp.toHex(cb, 0, cb.length));
            out.println(Json.canonical(Warp.xrayOutbound(v, "proxy", true, rnd)));
            out.println(Json.canonical(Warp.xrayOutbound(conf, "warp", false, rnd)));
            Map<String, Object> p3 = Json.obj("endpoint", "162.159.195.5:4500", "jc", 4, "jmin", 30, "jmax", 30, "i1", Warp.quicI1("vk.com", d1, k1));
            String big = Warp.buildConf(acct, p3);
            out.print(Warp.shareConf(big));
            out.print(Warp.shareConf("# комментарий\n" + conf));
            out.println(Json.canonical(Warp.xrayOutbound(big, "proxy", true, rnd)));
        }
        if (mode.equals("dht")) {
            Map<String, Object> inner = new LinkedHashMap<String, Object>();
            inner.put("b", -3L);
            Map<String, Object> v = new LinkedHashMap<String, Object>();
            v.put("z", "");
            v.put("m", "ж");
            v.put("a", Arrays.asList((Object) 1L, "x", inner));
            byte[] b = Dht.encode(v);
            out.println(Warp.toHex(b, 0, b.length));
            byte[] seed = new byte[32];
            for (int i = 0; i < 32; i++) seed[i] = (byte) i;
            Dht.Keys keys = new Dht.Keys(seed);
            out.println(Warp.toHex(keys.pub, 0, 32));
            Map<String, Object> head = new LinkedHashMap<String, Object>();
            head.put("p", "abc".getBytes(StandardCharsets.US_ASCII));
            head.put("n", 2L);
            head.put("h", new byte[16]);
            byte[] sig = (byte[]) keys.item("vf1/d0".getBytes(StandardCharsets.US_ASCII), 5, head).get("sig");
            out.println(Warp.toHex(sig, 0, 64));
            byte[] tg = Dht.target(keys.pub, "foobar".getBytes(StandardCharsets.US_ASCII));
            out.println(Warp.toHex(tg, 0, 20));
            byte[] raw = new byte[2000];
            for (int i = 0; i < raw.length; i++) raw[i] = (byte) (i % 251);
            for (Map<String, Object> it : Family.dhtItems(Family.dhtKeys(seed), 1, 7, raw)) {
                byte[] vb = Dht.encode(it.get("v"));
                byte[] sg = (byte[]) it.get("sig");
                out.println(new String((byte[]) it.get("salt"), StandardCharsets.US_ASCII) + " " + it.get("seq") + " "
                        + Warp.toHex(Dht.sha("SHA-1", vb), 0, 20) + " " + Warp.toHex(sg, 0, 64));
            }
            Object back = Dht.decode(b);
            out.println(Warp.toHex(Dht.encode(back), 0, Dht.encode(back).length).equals(Warp.toHex(b, 0, b.length)));
        }
        if (mode.equals("familyseal")) {
            byte[] sec = new byte[32], iv = new byte[16];
            for (int i = 0; i < 32; i++) sec[i] = (byte) i;
            for (int i = 0; i < 16; i++) iv[i] = (byte) (16 + i);
            List<Object> ops = Json.arr(Json.obj("op", "sub_add", "url", "https://example.com/s?x=1", "name", "Мамина подписка"),
                    Json.obj("op", "set", "values", Json.obj("dns_encrypted", true)), Json.obj("op", "method", "method", "server"));
            out.println(Family.makeInvite("Сын", "Мама — телефон", sec));
            out.println(Family.seal(sec, 0, 7, Json.obj("t", "cmd", "at", 1, "exp", 9999999999L, "from", "Сын", "ops", ops), iv));
            out.println(Family.seal(sec, 1, 3, Json.obj("t", "report", "at", 2, "exp", 9999999999L, "snap",
                    Json.obj("app", "pc", "subs", Json.arr()), "results", Json.arr()), null));
        }
        if (mode.equals("familyopen")) {
            byte[] sec = new byte[32];
            for (int i = 0; i < 32; i++) sec[i] = (byte) i;
            for (String fl : famIn.toString().split("\n")) {
                fl = fl.trim();
                if (fl.isEmpty()) continue;
                Map<String, Object> inv = Family.parseInvite(fl);
                if (inv != null) {
                    byte[] s2 = (byte[]) inv.get("secret");
                    out.println("invite " + inv.get("helper") + " " + inv.get("device") + " " + Warp.toHex(s2, 0, 32) + " " + Family.pairId(s2));
                    continue;
                }
                Map<String, Object> pk = Family.peek(fl);
                Map<String, Object> pl = Family.open(sec, (byte[]) pk.get("raw"));
                long dir = Json.num(pk, "direction", 0);
                out.println("packet " + Json.str(pk, "pair") + " " + dir + " " + Json.num(pk, "seq", 0) + " " + Json.canonical(pl) + " "
                        + (dir == 0 ? Json.canonical(Family.summary(Family.checkOps(pl.get("ops")))) : ""));
            }
        }
        if (mode.equals("vpslinks")) {
            out.println(Json.canonical(Vps.makeLinks("203.0.113.10", "11111111-2222-3333-4444-555555555555|" +
                "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde|0123abcd|a1b2c3d4e5f6", "Мой сервер")));
        }
    }
}
