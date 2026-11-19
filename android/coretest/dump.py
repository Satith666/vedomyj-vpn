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
