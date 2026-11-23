"""Те же проверки на стороне программы для Windows (запуск: python3 dump.py <режим> < ввод)."""
import json, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from pult import adblock, dpi, links, proxies, routing, services, subscription, vps

def canon(v):
    return json.dumps(v, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

mode = sys.argv[1]
data = sys.stdin.read()
if mode == "links":
    for line in (data[:-1] if data.endswith("\n") else data).split("\n"):
        s = links.parse_link(line)
        if s is None:
            print("null"); continue
        # TUIC и AnyTLS на телефоне не работают (на компьютере их ведёт мост sing-box)
        print(canon({"name": s.name, "protocol": s.protocol, "address": s.address, "port": s.port,
                     "outbound": s.outbound, "supported": s.supported and s.engine != "singbox", "insecure": s.insecure,
                     "stub": s.stub, "kind": links.kind_of(s)}))
elif mode == "routing":
    for line in (data[:-1] if data.endswith("\n") else data).split("\n"):
        try:
            e = routing.normalize_entry(line)
            print("null" if e is None else canon(list(e)))
        except ValueError:
            print('"bad"')
elif mode == "sub":
    s = subscription.parse_body(data.rstrip("\n"))
    print(canon([[x.name, x.protocol, x.supported, x.stub, x.insecure] for x in s.servers]))
elif mode == "proxies":
    for line in (data[:-1] if data.endswith("\n") else data).split("\n"):
        try:
            p = proxies.parse(line)
            print(canon({"type": p["type"], "tls": p["tls"], "host": p["host"], "port": p["port"], "user": p["user"],
                         "pass": p["pass"], "type_known": p["type_known"]}))
        except proxies.ProxyError:
            print('"bad"')
elif mode == "siteentry":
    for line in (data[:-1] if data.endswith("\n") else data).split("\n"):
        print(canon(routing.site_entry(line)))
elif mode == "adsline":
    for line in (data[:-1] if data.endswith("\n") else data).split("\n"):
        text = line.replace("\\n", "\n")
        print(canon(sorted(adblock.parse(text, "adblock" if line.startswith("||") else "domains"))))
elif mode == "adsabp":
    for line in (data[:-1] if data.endswith("\n") else data).split("\n"):
        b, a = adblock.parse_abp(line.replace("\\n", "\n"))
        print(canon([sorted(b), sorted(a)]))
elif mode == "adsite":
    for line in (data[:-1] if data.endswith("\n") else data).split("\n"):
        print(canon([adblock.protected(line), adblock.site_name(line), adblock.looks_like_ads(line)]))
    print(canon([sorted(adblock.SAFE_TREE), sorted(adblock.SAFE_SITES)]))
    doms = {x.strip() for x in data.split("\n") if x.strip()}
    print(canon(sorted(adblock.protect(doms))))
elif mode == "updatevector":
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "build"))
    import release_keys
    from pult import update
    key = release_keys.generate(1024)
    signed = update.pack({"version": "99.0.0", "notes": "Тест <b>&</b> «кавычки»", "android": {"url": "https://x/a.apk"}},
                         key["n"], key["d"])
    forged = dict(signed, payload=signed["payload"].replace("99.0.0", "99.0.1"))
    print(json.dumps({"n": str(key["n"]), "e": key["e"], "signed": signed, "forged": forged}, ensure_ascii=False))
elif mode == "services":
    print(canon([[[s["name"], s["domains"], bool(s.get("russian"))] for s in services.SERVICES], dpi.YOUTUBE_DOMAINS, dpi.DISCORD_DOMAINS]))
elif mode == "vps":
    sys.stdout.write(vps.script())
elif mode == "vproto":
    from pult import dialect, xray
    c = [0]

    def rnd(n):
        c[0] += 1
        return (c[0] * 7919) % n
    uid, pw = "3f1c2a9e-1b2c-4d5e-8f90-1234567890ab", "kAbcdefghijklmnopqrstuvwx_-1"
    enc = "mlkem768x25519plus.native.0rtt.zYxW_vUtS-0987654321zyxwvutsrqponmlkjihgf"
    for _ in range(6):
        d = dialect.make(rnd)
        print(canon(d))
        sys.stdout.write(dialect.request(d) + dialect.response(d))
    d = dialect.make(rnd)
    print(canon(dialect.mask(d, pw)))
    for key, bad in (("host", "a.b.c;reboot"), ("path", "/x y"), ("ua", "x\r\nEvil: 1"), ("query", "a=$(id)"),
                     ("server", "nginx\r\n"), ("ctype", "text/html\n"), ("padMin", 50), ("padMax", -1)):
        try:
            dialect.check(dict(d, **{key: bad}))
            print("accepted")
        except ValueError:
            print("bad")
    print(canon(vps.proto_server_config(d, uid, pw)))
    sys.stdout.write(vps.proto_script(d, uid, pw))
    for args in ((d, "x;reboot", pw), (d, uid, "$(reboot)aaaaaaaaaaaa"), (dict(d, host="x;y"), uid, pw)):
        try:
            vps.proto_script(*args)
            print("accepted")
        except vps.VpsError:
            print("bad")
    for r in ("80|26.11.9|" + enc, "80|26.11.9", "22|26.11.9|" + enc, "8080|x|" + enc, "8080|26.11.9|" + enc + ";id"):
        try:
            x = vps.parse_proto_result(r)
            print(f"{x[0]} {x[1]} {x[2]}")
        except vps.VpsError:
            print("bad")
    link = vps.make_proto_link("203.0.113.10", 8080, uid, enc, d, pw, "Germany · Свой протокол")
    print(link)
    srv = links.parse_link(link)
    print(canon(srv.outbound))
    print(dialect.is_vproto(srv), srv.insecure)
    for ver in ("26.9.30", "26.11.9"):
        print(canon(xray.proxy_outbounds(srv, "proxy", False, ver)))
elif mode == "vpsxdns":
    from pult import xray
    uid, pw = "3f1c2a9e-1b2c-4d5e-8f90-1234567890ab", "kAbcdefghijklmnopqrstuvwx_-1"
    for d in ("T.Example.RU.", "t.my-site.ru", "т.пример.рф", "example.ru", "t.$(id).ru", "t..ru", "-t.example.ru", "a" * 70 + ".ru.ru", ""):
        try:
            print(vps.check_domain(d))
        except vps.VpsError:
            print("bad")
    for d in ("t.a.ru", "t.example.ru", "t." + "x" * 25 + ".ru", "t." + "x" * 35 + ".ru", "t." + "x" * 50 + ".ru"):
        print(links.xdns_mtu(d))
    print(canon(vps.xdns_server_config("t.example.ru", uid, pw)))
    sys.stdout.write(vps.xdns_script("t.example.ru", uid, pw))
    sys.stdout.write(vps.xdns_script("t.example.ru", uid, pw, iface="vdx0"))
    for args in (("t.example.ru", "x;reboot", pw), ("t.example.ru", uid, "$(reboot)aaaaaaaaaaaa"), ("t.example.ru", uid, pw, "eth0;id")):
        try:
            vps.xdns_script(*args)
            print("accepted")
        except vps.VpsError:
            print("bad")
    enc = "mlkem768x25519plus.native.0rtt.zYxW_vUtS-0987654321zyxwvutsrqponmlkjihgf"
    for r in ("5300|26.11.9|" + enc, "5300|26.11.9", "x|26.10.31|" + enc, "5300|$(id)|" + enc, "5300|26.11.9|" + enc + ";id"):
        try:
            x = vps.parse_xdns_result(r)
            print(f"{x[0]} {x[1]} {x[2]}")
        except vps.VpsError:
            print("bad")
    for res, addr in ((vps.XDNS_RESOLVERS, ""), (("127.0.0.1:5454",), "77.88.8.8")):
        link = vps.make_xdns_link("t.example.ru", uid, pw, enc, "Germany · DNS-туннель", resolvers=res, address=addr)
        print(link)
        srv = links.parse_link(link)
        print(canon(srv.outbound))
        print(links.is_xdns(srv), links.xdns_domain_of(srv.outbound["streamSettings"]), srv.insecure)
        for ver in ("26.9.30", "26.10.21", "26.11.9"):
            print(canon(xray.proxy_outbounds(srv, "proxy", False, ver)))
elif mode == "vpsawg":
    from pult import warp
    cnt = [0]

    def rnd(n):
        cnt[0] += 1
        return ((cnt[0] - 1) * 7919) % n
    pub = "qgIEo+uU039puNbXT/0Dp83v1gKwmUMtxRlqB1VdrX4="
    for _ in range(3):
        p = vps.awg_params(rnd)
        print(canon(p))
        print(canon(vps.check_awg_params(p)))
    p = vps.awg_params(rnd)
    sys.stdout.write(vps.awg_script(pub, 45123, p))
    sys.stdout.write(vps.awg_peer_script(pub))
    for r in (pub + "|45123", pub + "|45123|7", "x|45123", pub + "|80", pub + "|45123|999"):
        try:
            x = vps.parse_awg_result(r)
            print(f"{x[0]} {x[1]} {x[2]}")
        except vps.VpsError:
            print("bad")
    sys.stdout.write(vps.awg_client_conf("203.0.113.10", 45123, pub, "0DwJdaudL51JBFBTWtyQF+QPxOBERLhw0ye1fXBLjEQ=", 3, p, warp.DNS_YANDEX_I1))
    try:
        vps.check_awg_params(dict(p, H2=p["H1"]))
        print("accepted")
    except vps.VpsError:
        print("bad")
elif mode == "vpsbridge":
    good = ("vless://3f1c2a9e-1b2c-4d5e-8f90-1234567890ab@203.0.113.10:443?type=tcp&security=reality"
            "&pbk=cHVibGljLWtleS1mb3ItdGVzdGluZy1yZWFsaXR5LXh4&fp=chrome&sni=www.microsoft.com&sid=0123456789abcdef&flow=xtls-rprx-vision#x")
    for ln in (good, good.replace("203.0.113.10", "[2001:db8::7]"), good.replace(":443?", ":8443?").replace("&flow=xtls-rprx-vision", ""),
               good.replace("3f1c2a9e", "$(id)x"), good.replace("203.0.113.10", "a;b"), good.replace("security=reality", "security=tls"),
               good.replace("type=tcp", "type=ws"), good.replace("sni=www.microsoft.com", "sni=$HOME"), good.replace(":443?", ":99999?"),
               good.replace("sid=0123456789abcdef", "sid="), "vmess://abc"):
        try:
            print(canon(vps.parse_forward(ln)))
        except vps.VpsError:
            print("bad")
    sys.stdout.write(vps.bridge_script(vps.parse_forward(good)))
    print("\n".join(vps.make_links("198.51.100.5", "9a9a9a9a-1b2c-4d5e-8f90-1234567890ab|cnUtcHVibGljLWtleS1mb3ItdGVzdGluZy1icmlkZ2V4|fedcba9876543210|0a0b0c0d",
                                    "Мост · белые списки", vps.RU_SNI)))
elif mode == "dns":
    from pult import netutil
    for h in ("allvsub.cc", "Sub.Example.COM.", "пример.рф", "a.b.c.d.e"):
        print(netutil.dns_query(h.lower()).hex())
    d = bytes.fromhex("00008180000100030000000007616c6c767375620263630000010001c00c0005000100000e100002c00cc00c000100010000003c0004b9b2d0a0c00c000100010000003c000400000000")
    print("[" + ", ".join(netutil.dns_answers(d)) + "]")
    print("[" + ", ".join(netutil.dns_answers(d[:40])) + "]")
elif mode == "vpsextra":
    sys.stdout.write(vps.status_script())
    sys.stdout.write(vps.friend_script("add"))
    sys.stdout.write(vps.friend_script("remove", "11111111-2222-3333-4444-555555555555"))
    print(canon(vps.parse_status("90061|0.15 0.10 0.05|310/1987|3.1G/25G|123456|654321|active|4|1")))
    print(canon(vps.parse_status("x|<b>|9999999999999999999|a;b|-1|2|act$ive|٣|0")))
elif mode == "vpslinks":
    print(canon(vps.make_links("203.0.113.10", "11111111-2222-3333-4444-555555555555|AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde|0123abcd|a1b2c3d4e5f6", "Мой сервер")))
elif mode == "warp":
    from pult import warp
    seed = bytes(range(32))
    print(canon(list(warp.keypair(seed))))
    print(warp.quic_i1("vk.com", bytes(range(8)), bytes(range(100, 132))))
    print(warp.quic_i1("www.google.com", bytes(range(200, 208)), bytes(32)))
    print(warp.dns_i1("yandex.ru", 100))
    print(warp.stun_i1(16))
    print(warp.sip_i1("www.google.com", 1, 2))
    acct = {"private_key": warp.keypair(seed)[0], "peer": warp.PEER_KEY, "v4": "172.16.0.2", "v6": "2606:4700:110:8a36::1"}
    p1 = {"endpoint": "162.159.192.1:2408", "jc": 5, "jmin": 20, "jmax": 90, "i1": warp.DNS_YANDEX_I1}
    p2 = {"endpoint": "188.114.99.1:1701", "jc": 7, "jmin": 11, "jmax": 33, "i1": warp.stun_i1(20)}
    conf = warp.build_conf(acct, p1)
    sys.stdout.write(conf)
    v = warp.variant(conf, p2)
    sys.stdout.write(v)
    cp = warp.current_params(v)
    print("|".join(str(cp[k]) for k in ("endpoint", "jc", "jmin", "jmax", "i1")))
    print(canon([warp.is_warp(conf), warp.is_warp(conf.replace(warp.PEER_KEY, "x"))]))
    cnt = [0]

    def rnd(n):
        cnt[0] += 1
        return (cnt[0] - 1) % n
    print(warp.cps_bytes("<b 0x0102ff><r 2><rc 3><rd 2><r 4-9><t><c><n>", rnd, now=0x01020304).hex())
    print(canon(warp.xray_outbound(v, "proxy", True, rnd)))
    print(canon(warp.xray_outbound(conf, "warp", False, rnd)))
    p3 = {"endpoint": "162.159.195.5:4500", "jc": 4, "jmin": 30, "jmax": 30, "i1": warp.quic_i1("vk.com", bytes(range(8)), bytes(range(100, 132)))}
    big = warp.build_conf(acct, p3)
    sys.stdout.write(warp.share_conf(big))
    sys.stdout.write(warp.share_conf("# комментарий\n" + conf))
    print(canon(warp.xray_outbound(big, "proxy", True, rnd)))
elif mode == "dht":
    from pult import dht, family
    b = dht.bencode({"z": "", "m": "ж", "a": [1, "x", {"b": -3}]})
    print(b.hex())
    keys = dht.Keys(bytes(range(32)))
    print(keys.public.hex())
    print(keys.item(b"vf1/d0", 5, {"p": b"abc", "n": 2, "h": bytes(16)})["sig"].hex())
    print(dht.target(keys.public, b"foobar").hex())
    raw = bytes(i % 251 for i in range(2000))
    import hashlib
    for it in family.dht_items(family.dht_keys(bytes(range(32))), 1, 7, raw):
        print(it["salt"].decode(), it["seq"], hashlib.sha1(dht.bencode(it["v"])).hexdigest(), it["sig"].hex())
    print("true" if dht.bencode(dht.bdecode(b)) == b else "false")
elif mode == "familyseal":
    from pult import family
    sec = bytes(range(32))
    ops = [{"op": "sub_add", "url": "https://example.com/s?x=1", "name": "Мамина подписка"}, {"op": "set", "values": {"dns_encrypted": True}},
           {"op": "method", "method": "server"}]
    print(family.make_invite("Сын", "Мама — телефон", sec))
    print(family.seal(sec, 0, 7, {"t": "cmd", "at": 1, "exp": 9999999999, "from": "Сын", "ops": ops}, bytes(range(16, 32))))
    print(family.seal(sec, 1, 3, {"t": "report", "at": 2, "exp": 9999999999, "snap": {"app": "pc", "subs": []}, "results": []}))
elif mode == "familyopen":
    from pult import family
    sec = bytes(range(32))
    for line in data.splitlines():
        line = line.strip()
        if not line:
            continue
        inv = family.parse_invite(line)
        if inv:
            print("invite", inv["helper"], inv["device"], inv["secret"].hex(), family.pair_id(inv["secret"]))
            continue
        pair, direction, seq, raw = family.peek(line)
        print("packet", pair, direction, seq, canon(family.open_packet(sec, raw)), canon(family.summary(family.check_ops(family.open_packet(sec, raw)["ops"]))) if direction == 0 else "")
