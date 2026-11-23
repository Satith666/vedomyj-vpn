package com.pultvpn.app.core;

import java.util.ArrayList;
import java.util.List;

/**
 * Мастер своего сервера (VPS): тот же скрипт, что в программе для Windows. Ставит Xray с VLESS + Reality
 * (порт 443) и запасным входом XHTTP + Reality (8443). Пароль от сервера человек вводит в приложении,
 * он нигде не сохраняется. Ссылки собирает приложение по строгим шаблонам.
 */
public final class Vps {
    private Vps() {
    }

    public static final String SNI = "www.microsoft.com";
    public static final int PORT_TCP = 443;
    public static final int PORT_XHTTP = 8443;

    public static final class VpsError extends Exception {
        public VpsError(String msg) {
            super(msg);
        }
    }

    public static String step(String key) {
        switch (key) {
            case "packages": return Text.t("Ставлю нужные пакеты на сервер", "Installing packages on the server");
            case "xray": return Text.t("Ставлю Xray на сервер", "Installing Xray on the server");
            case "keys": return Text.t("Создаю ключи", "Creating keys");
            case "config": return Text.t("Записываю настройки сервера", "Writing server settings");
            case "tune": return Text.t("Включаю ускорение BBR и открываю порты", "Enabling BBR and opening ports");
            case "start": return Text.t("Запускаю Xray на сервере", "Starting Xray on the server");
            case "awg": return Text.t("Ставлю AmneziaWG на сервер", "Installing AmneziaWG on the server");
            case "peer": return Text.t("Добавляю устройство на сервер", "Adding a device to the server");
            default: return key;
        }
    }

    public static String error(String key) {
        switch (key) {
            case "root": return Text.t("нужен вход под пользователем root (в панели хостинга он обычно и выдаётся)",
                    "you need to log in as root (hosting panels usually give you root)");
            case "os": return Text.t("на сервере неподходящая система — нужна Ubuntu, Debian, CentOS, AlmaLinux или Rocky",
                    "unsupported system on the server — Ubuntu, Debian, CentOS, AlmaLinux or Rocky is needed");
            case "install": return Text.t("не удалось установить Xray — у сервера нет доступа к GitHub или закончилось место",
                    "could not install Xray — the server can't reach GitHub or is out of disk space");
            case "keys": return Text.t("Xray не создал ключи", "Xray did not create keys");
            case "port": return Text.t("порт " + PORT_TCP + " на сервере занят другой программой (например, сайтом)",
                    "port " + PORT_TCP + " on the server is used by another program (for example, a website)");
            case "config": return Text.t("Xray не принял настройки", "Xray rejected the settings");
            case "awg_os": return Text.t("AmneziaWG программа ставит только на Ubuntu (22.04 или новее)",
                    "the app installs AmneziaWG only on Ubuntu (22.04 or newer)");
            case "awg_install": return Text.t("не удалось установить AmneziaWG — у сервера нет доступа к репозиторию Amnezia или закончилось место",
                    "could not install AmneziaWG — the server can't reach the Amnezia repository or is out of space");
            case "awg_repo": return Text.t("сервер не смог подключить репозиторий Amnezia (launchpad.net) — проверь, что у сервера есть интернет, и попробуй снова",
                    "the server could not add the Amnezia repository (launchpad.net) — check that the server has internet and try again");
            case "awg_build": return Text.t("модуль AmneziaWG не собрался для ядра сервера — обнови систему сервера (apt upgrade), перезагрузи его и попробуй снова",
                    "the AmneziaWG module did not build for the server kernel — update the server system (apt upgrade), reboot it and try again");
            case "awg_module": return Text.t("модуль AmneziaWG не загрузился — обнови систему сервера, перезагрузи его и попробуй снова",
                    "the AmneziaWG module did not load — update the server system, reboot it and try again");
            case "awg_service": return Text.t("AmneziaWG на сервере не запустился", "AmneziaWG did not start on the server");
            case "noawg": return Text.t("на сервере нет AmneziaWG, установленного программой — сначала нажми «AmneziaWG 2.0»",
                    "the server has no AmneziaWG installed by the app — press “AmneziaWG 2.0” first");
            case "awg_full": return Text.t("на сервере уже 248 устройств — больше не поместится", "the server already has 248 devices — no more fit");
            case "service": return Text.t("Xray на сервере не запустился", "Xray did not start on the server");
            case "noxray": return Text.t("на сервере нет Xray, установленного программой — сначала настрой сервер мастером",
                    "the server has no Xray installed by the program — set up the server with the wizard first");
            case "python": return Text.t("на сервере нет python3, и его не удалось установить",
                    "the server has no python3 and it could not be installed");
            default: return key;
        }
    }

    static final String SCRIPT = "#!/bin/bash\n"
            + "# VEDOMYJ VPN: installs Xray (VLESS + Reality and XHTTP + Reality) with the official XTLS installer.\n"
            + "say()  { echo \"PULT_STEP:$1\"; }\n"
            + "fail() { echo \"PULT_ERROR:$1\"; exit 1; }\n"
            + "[ \"$(id -u)\" = \"0\" ] || fail root\n"
            + "export DEBIAN_FRONTEND=noninteractive\n"
            + "say packages\n"
            + "if command -v apt-get >/dev/null 2>&1; then\n"
            + "  apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq curl unzip openssl >/dev/null 2>&1\n"
            + "elif command -v dnf >/dev/null 2>&1; then\n"
            + "  dnf install -y -q curl unzip openssl >/dev/null 2>&1\n"
            + "elif command -v yum >/dev/null 2>&1; then\n"
            + "  yum install -y -q curl unzip openssl >/dev/null 2>&1\n"
            + "else\n"
            + "  fail os\n"
            + "fi\n"
            + "command -v curl >/dev/null 2>&1 || fail os\n"
            + "if command -v ss >/dev/null 2>&1 && ss -ltnp 2>/dev/null | grep -E ':__PORT_TCP__\\b' | grep -vq xray; then fail port; fi\n"
            + "say xray\n"
            + "bash -c \"$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)\" @ install >/tmp/pult-xray-install.log 2>&1 || fail install\n"
            + "XRAY=/usr/local/bin/xray\n"
            + "[ -x \"$XRAY\" ] || fail install\n"
            + "say keys\n"
            + "UUID=$($XRAY uuid | tr -d ' \\r\\n')\n"
            + "KEYS=$($XRAY x25519)\n"
            + "PRIV=$(echo \"$KEYS\" | grep -i 'private' | head -n1 | sed 's/.*: *//' | tr -d ' \\r')\n"
            + "PUB=$(echo \"$KEYS\" | grep -iE 'public|password' | grep -vi 'private' | head -n1 | sed 's/.*: *//' | tr -d ' \\r')\n"
            + "SID=$(openssl rand -hex 8)\n"
            + "XPATH=$(openssl rand -hex 6)\n"
            + "[ -n \"$UUID\" ] && [ -n \"$PRIV\" ] && [ -n \"$PUB\" ] || fail keys\n"
            + "say config\n"
            + "mkdir -p /usr/local/etc/xray\n"
            + "cat > /usr/local/etc/xray/config.json <<JSON\n"
            + "{\n"
            + "  \"log\": {\"loglevel\": \"warning\"},\n"
            + "  \"inbounds\": [\n"
            + "    {\"tag\": \"reality\", \"listen\": \"0.0.0.0\", \"port\": __PORT_TCP__, \"protocol\": \"vless\",\n"
            + "     \"settings\": {\"clients\": [{\"id\": \"$UUID\", \"flow\": \"xtls-rprx-vision\"}], \"decryption\": \"none\"},\n"
            + "     \"streamSettings\": {\"network\": \"tcp\", \"security\": \"reality\",\n"
            + "       \"realitySettings\": {\"dest\": \"__SNI__:443\", \"serverNames\": [\"__SNI__\"], \"privateKey\": \"$PRIV\", \"shortIds\": [\"$SID\"]}},\n"
            + "     \"sniffing\": {\"enabled\": true, \"destOverride\": [\"http\", \"tls\", \"quic\"], \"routeOnly\": true}},\n"
            + "    {\"tag\": \"xhttp\", \"listen\": \"0.0.0.0\", \"port\": __PORT_XHTTP__, \"protocol\": \"vless\",\n"
            + "     \"settings\": {\"clients\": [{\"id\": \"$UUID\"}], \"decryption\": \"none\"},\n"
            + "     \"streamSettings\": {\"network\": \"xhttp\", \"xhttpSettings\": {\"path\": \"/$XPATH\"}, \"security\": \"reality\",\n"
            + "       \"realitySettings\": {\"dest\": \"__SNI__:443\", \"serverNames\": [\"__SNI__\"], \"privateKey\": \"$PRIV\", \"shortIds\": [\"$SID\"]}},\n"
            + "     \"sniffing\": {\"enabled\": true, \"destOverride\": [\"http\", \"tls\", \"quic\"], \"routeOnly\": true}}\n"
            + "  ],\n"
            + "  \"outbounds\": [{\"protocol\": \"freedom\", \"tag\": \"direct\"}, {\"protocol\": \"blackhole\", \"tag\": \"block\"}],\n"
            + "  \"routing\": {\"rules\": [{\"type\": \"field\", \"ip\": [\"geoip:private\"], \"outboundTag\": \"block\"}]}\n"
            + "}\n"
            + "JSON\n"
            + "$XRAY run -test -c /usr/local/etc/xray/config.json >/dev/null 2>&1 || fail config\n"
            + "say tune\n"
            + "if ! grep -q 'tcp_congestion_control=bbr' /etc/sysctl.conf 2>/dev/null; then\n"
            + "  printf 'net.core.default_qdisc=fq\\nnet.ipv4.tcp_congestion_control=bbr\\n' >> /etc/sysctl.conf\n"
            + "fi\n"
            + "sysctl -p >/dev/null 2>&1 || true\n"
            + "if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then\n"
            + "  ufw allow __PORT_TCP__/tcp >/dev/null 2>&1; ufw allow __PORT_XHTTP__/tcp >/dev/null 2>&1\n"
            + "fi\n"
            + "if command -v firewall-cmd >/dev/null 2>&1; then\n"
            + "  firewall-cmd --permanent --add-port=__PORT_TCP__/tcp >/dev/null 2>&1\n"
            + "  firewall-cmd --permanent --add-port=__PORT_XHTTP__/tcp >/dev/null 2>&1\n"
            + "  firewall-cmd --reload >/dev/null 2>&1 || true\n"
            + "fi\n"
            + "say start\n"
            + "systemctl enable xray >/dev/null 2>&1 || true\n"
            + "systemctl restart xray >/dev/null 2>&1\n"
            + "sleep 2\n"
            + "systemctl is-active --quiet xray || fail service\n"
            + "echo \"PULT_RESULT:$UUID|$PUB|$SID|$XPATH\"\n";

    public static String script() {
        return SCRIPT.replace("__PORT_TCP__", String.valueOf(PORT_TCP)).replace("__PORT_XHTTP__", String.valueOf(PORT_XHTTP))
                .replace("__SNI__", SNI);
    }

    // состояние своего сервера и ключи для друзей — те же скрипты, что в программе для Windows
    static final String STATUS_SCRIPT = "#!/bin/bash\n"
            + "up=$(cut -d. -f1 /proc/uptime 2>/dev/null)\n"
            + "load=$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null)\n"
            + "mem=$(free -m 2>/dev/null | awk '/^Mem:/ {print $3\"/\"$2}')\n"
            + "disk=$(df -h / 2>/dev/null | awk 'NR==2 {print $3\"/\"$2}')\n"
            + "iface=$(ip route 2>/dev/null | awk '/default/ {print $5; exit}')\n"
            + "rx=0; tx=0\n"
            + "if [ -n \"$iface\" ] && [ -r /proc/net/dev ]; then\n"
            + "  rx=$(awk -v i=\"$iface:\" '$1==i {print $2}' /proc/net/dev); tx=$(awk -v i=\"$iface:\" '$1==i {print $10}' /proc/net/dev)\n"
            + "fi\n"
            + "xr=$(systemctl is-active xray 2>/dev/null)\n"
            + "conns=$(ss -tn state established 2>/dev/null | grep -cE ':(__PORT_TCP__|__PORT_XHTTP__)\\b')\n"
            + "clients=$(grep -o '\"id\": *\"[0-9a-fA-F-]\\{36\\}\"' /usr/local/etc/xray/config.json 2>/dev/null | sort -u | wc -l)\n"
            + "echo \"PULT_RESULT:${up:-0}|${load:-?}|${mem:-?}|${disk:-?}|${rx:-0}|${tx:-0}|${xr:-unknown}|${conns:-0}|${clients:-0}\"\n";

    static final String FRIEND_SCRIPT = "#!/bin/bash\n"
            + "fail() { echo \"PULT_ERROR:$1\"; exit 1; }\n"
            + "[ \"$(id -u)\" = \"0\" ] || fail root\n"
            + "CFG=/usr/local/etc/xray/config.json\n"
            + "XRAY=/usr/local/bin/xray\n"
            + "[ -f \"$CFG\" ] && [ -x \"$XRAY\" ] || fail noxray\n"
            + "command -v python3 >/dev/null 2>&1 || { apt-get install -y -qq python3 >/dev/null 2>&1 || fail python; }\n"
            + "ACTION=\"__ACTION__\"; TARGET=\"__UUID__\"\n"
            + "NEW=$($XRAY uuid | tr -d ' \\r')\n"
            + "[ \"$ACTION\" = \"add\" ] && TARGET=\"$NEW\"\n"
            + "OUT=$(python3 - \"$CFG\" \"$ACTION\" \"$TARGET\" <<'PY'\n"
            + "import json, sys\n"
            + "path, action, uid = sys.argv[1:4]\n"
            + "cfg = json.load(open(path))\n"
            + "priv = sid = xpath = \"\"\n"
            + "for ib in cfg.get(\"inbounds\", []):\n"
            + "    clients = ib.setdefault(\"settings\", {}).setdefault(\"clients\", [])\n"
            + "    if action == \"add\":\n"
            + "        c = {\"id\": uid}\n"
            + "        if ib.get(\"tag\") == \"reality\":\n"
            + "            c[\"flow\"] = \"xtls-rprx-vision\"\n"
            + "        clients.append(c)\n"
            + "    else:\n"
            + "        ib[\"settings\"][\"clients\"] = [c for c in clients if c.get(\"id\") != uid] or clients\n"
            + "    rs = ib.get(\"streamSettings\", {}).get(\"realitySettings\", {})\n"
            + "    priv = priv or rs.get(\"privateKey\", \"\")\n"
            + "    sid = sid or (rs.get(\"shortIds\") or [\"\"])[0]\n"
            + "    xpath = xpath or ib.get(\"streamSettings\", {}).get(\"xhttpSettings\", {}).get(\"path\", \"\").lstrip(\"/\")\n"
            + "json.dump(cfg, open(path + \".new\", \"w\"), indent=1)\n"
            + "print(priv + \"|\" + sid + \"|\" + xpath)\n"
            + "PY\n"
            + ") || fail config\n"
            + "$XRAY run -test -c \"$CFG.new\" >/dev/null 2>&1 || { rm -f \"$CFG.new\"; fail config; }\n"
            + "mv \"$CFG.new\" \"$CFG\"\n"
            + "systemctl restart xray >/dev/null 2>&1\n"
            + "sleep 2\n"
            + "systemctl is-active --quiet xray || fail service\n"
            + "PRIV=${OUT%%|*}; REST=${OUT#*|}; SID=${REST%%|*}; XPATH=${REST#*|}\n"
            + "PUB=$($XRAY x25519 -i \"$PRIV\" | grep -iE 'public|password' | grep -vi 'private' | head -n1 | sed 's/.*: *//' | tr -d ' \\r')\n"
            + "echo \"PULT_RESULT:$TARGET|$PUB|$SID|$XPATH\"\n";

    public static String statusScript() {
        return STATUS_SCRIPT.replace("__PORT_TCP__", String.valueOf(PORT_TCP)).replace("__PORT_XHTTP__", String.valueOf(PORT_XHTTP));
    }

    public static String friendScript(String action, String uuid) throws VpsError {
        if (!("add".equals(action) || "remove".equals(action)) || ("remove".equals(action) && (uuid == null
                || !uuid.matches("[0-9a-fA-F-]{36}")))) {
            throw new VpsError(Text.t("неизвестное действие", "unknown action"));
        }
        return FRIEND_SCRIPT.replace("__ACTION__", action).replace("__UUID__", "remove".equals(action) ? uuid : "");
    }

    /** Строка состояния сервера → понятные поля (все значения проверяются). */
    public static java.util.Map<String, Object> parseStatus(String result) throws VpsError {
        String[] p = result.split("\\|", -1);
        if (p.length != 9) {
            throw new VpsError(Text.t("сервер прислал непонятный ответ", "the server sent an unclear answer"));
        }
        return Json.obj("uptime_s", num(p[0]), "load", clean(p[1]), "mem_mb", clean(p[2]), "disk", clean(p[3]),
                "rx", num(p[4]), "tx", num(p[5]), "xray", clean(p[6]), "conns", num(p[7]), "clients", num(p[8]));
    }

    private static long num(String v) {
        if (!v.matches("[0-9]{1,18}")) {
            return 0L;
        }
        return Long.parseLong(v);
    }

    private static String clean(String v) {
        String c = v.replaceAll("[^0-9A-Za-z./ ,:-]", "");
        return c.length() > 40 ? c.substring(0, 40) : c;
    }

    /** {host, port, user} после проверки. */
    public static Object[] checkInput(String host, String port, String user) throws VpsError {
        String h = host == null ? "" : host.trim();
        if (h.startsWith("[") && h.endsWith("]")) {
            h = h.substring(1, h.length() - 1);
        }
        String u = user == null || user.trim().isEmpty() ? "root" : user.trim();
        int p;
        try {
            p = port == null || port.trim().isEmpty() ? 22 : Integer.parseInt(port.trim());
        } catch (NumberFormatException e) {
            throw new VpsError(Text.t("Порт SSH — это число, обычно 22.", "The SSH port is a number, usually 22."));
        }
        if (!(h.matches("[A-Za-z0-9.\\-]{1,253}") || h.matches("[0-9A-Fa-f:]{2,39}")) || p < 1 || p > 65535) {
            throw new VpsError(Text.t("Впиши адрес сервера (IP из письма хостинга), например 203.0.113.10.",
                    "Enter the server address (the IP from the hosting email), for example 203.0.113.10."));
        }
        if (!u.matches("[a-z_][a-z0-9_\\-]{0,31}")) {
            throw new VpsError(Text.t("Неверное имя пользователя — обычно это root.", "Invalid user name — usually root."));
        }
        return new Object[]{h, p, u};
    }

    /** Разбор вывода скрипта по строкам. */
    public static final class Progress {
        public String step = "";
        public String error = "";
        public String result = "";

        /** true — шаг сменился. */
        public boolean feed(String line) {
            String l = line.trim();
            if (l.startsWith("PULT_STEP:")) {
                String s = l.substring(10);
                boolean changed = !s.equals(step);
                step = s;
                return changed;
            }
            if (l.startsWith("PULT_ERROR:")) {
                error = l.substring(11);
            } else if (l.startsWith("PULT_RESULT:")) {
                result = l.substring(12);
            }
            return false;
        }
    }

    /** Ссылки на свой сервер. Значения из ответа сервера проверяются по строгим шаблонам. */
    public static List<String> makeLinks(String host, String result, String name) throws VpsError {
        return makeLinks(host, result, name, SNI);
    }

    public static List<String> makeLinks(String host, String result, String name, String sni) throws VpsError {
        String[] parts = result.split("\\|", -1);
        if (parts.length != 4) {
            throw new VpsError(Text.t("сервер прислал непонятный ответ", "the server sent an unclear answer"));
        }
        String uuid = parts[0];
        String pub = parts[1];
        String sid = parts[2];
        String path = parts[3];
        if (!uuid.matches("[0-9a-fA-F-]{36}") || !pub.matches("[A-Za-z0-9_\\-]{40,50}") || !sid.matches("[0-9a-f]{2,16}")
                || !path.matches("[0-9a-f]{4,32}")) {
            throw new VpsError(Text.t("сервер прислал непонятный ответ", "the server sent an unclear answer"));
        }
        String hp = host.contains(":") ? "[" + host + "]" : host;
        String common = "security=reality&pbk=" + pub + "&fp=chrome&sni=" + sni + "&sid=" + sid;
        List<String> links = new ArrayList<String>();
        links.add("vless://" + uuid + "@" + hp + ":" + PORT_TCP + "?type=tcp&" + common + "&flow=xtls-rprx-vision#"
                + Text.quote(name));
        links.add("vless://" + uuid + "@" + hp + ":" + PORT_XHTTP + "?type=xhttp&path=%2F" + path + "&" + common + "#"
                + Text.quote(name + " · XHTTP"));
        return links;
    }

    // ---------- мост через российский сервер (как pult/vps.py, 1.23) ----------

    public static final String RU_SNI = "vk.com";
    public static final String BRIDGE_NAME = "Мост (белые списки)";
    static final String RX_UUID = "[0-9a-fA-F-]{36}", RX_PUB = "[A-Za-z0-9_\\-]{40,50}", RX_SID = "[0-9a-f]{0,16}",
            RX_HOST = "[A-Za-z0-9.\\-]{1,253}|[0-9A-Fa-f:]{2,39}", RX_SNI = "[a-z0-9.\\-]{3,100}";

    /** Ссылка основного сервера (VLESS + Reality) → куда мосту передавать трафик. Всё проверяется по шаблонам. */
    public static java.util.Map<String, Object> parseForward(String link) throws VpsError {
        VpsError bad = new VpsError(Text.t("у основного сервера нет подходящего входа (нужен VLESS + Reality, как делает мастер)",
                "the main server has no suitable entry (VLESS + Reality is needed, as the wizard makes)"));
        String l = link == null ? "" : link.trim();
        if (!l.startsWith("vless://")) {
            throw bad;
        }
        l = l.substring(8);
        int hash = l.indexOf('#');
        if (hash >= 0) {
            l = l.substring(0, hash);
        }
        String query = "";
        int q = l.indexOf('?');
        if (q >= 0) {
            query = l.substring(q + 1);
            l = l.substring(0, q);
        }
        int at = l.lastIndexOf('@');
        if (at < 0) {
            throw bad;
        }
        String uuid = Text.unquote(l.substring(0, at)), hp = l.substring(at + 1);
        String host;
        int port = PORT_TCP;
        if (hp.startsWith("[")) {
            int end = hp.indexOf(']');
            if (end < 0) {
                throw bad;
            }
            host = hp.substring(1, end);
            if (hp.length() > end + 1 && hp.charAt(end + 1) == ':') {
                port = parsePort(hp.substring(end + 2), bad);
            }
        } else {
            int c = hp.lastIndexOf(':');
            host = c >= 0 ? hp.substring(0, c) : hp;
            if (c >= 0) {
                port = parsePort(hp.substring(c + 1), bad);
            }
        }
        java.util.Map<String, String> qs = new java.util.LinkedHashMap<String, String>();
        for (String kv : query.split("&")) {
            int eq = kv.indexOf('=');
            if (eq > 0 && !qs.containsKey(kv.substring(0, eq))) {
                qs.put(kv.substring(0, eq), Text.unquote(kv.substring(eq + 1)));
            }
        }
        String type = qs.containsKey("type") ? qs.get("type") : "tcp";
        String pbk = str(qs, "pbk"), sid = str(qs, "sid"), sni = str(qs, "sni"), flow = str(qs, "flow");
        host = host.toLowerCase(java.util.Locale.ROOT);
        if (!"reality".equals(qs.get("security")) || !"tcp".equals(type) || !host.matches(RX_HOST) || !uuid.matches(RX_UUID)
                || !pbk.matches(RX_PUB) || !sid.matches(RX_SID) || !sni.matches(RX_SNI)
                || !(flow.isEmpty() || "xtls-rprx-vision".equals(flow))) {
            throw bad;
        }
        java.util.Map<String, Object> fwd = new java.util.LinkedHashMap<String, Object>();
        fwd.put("address", host);
        fwd.put("port", (long) port);
        fwd.put("uuid", uuid);
        fwd.put("pbk", pbk);
        fwd.put("sid", sid);
        fwd.put("sni", sni);
        fwd.put("flow", flow);
        return fwd;
    }

    private static String str(java.util.Map<String, String> m, String k) {
        return m.containsKey(k) ? m.get(k) : "";
    }

    private static int parsePort(String v, VpsError bad) throws VpsError {
        if (!v.matches("[0-9]{1,5}") || Integer.parseInt(v) < 1 || Integer.parseInt(v) > 65535) {
            throw bad;
        }
        return Integer.parseInt(v);
    }

    /** Настройки Xray моста — как bridge_config в pult/vps.py (порядок ключей тот же). */
    public static java.util.Map<String, Object> bridgeConfig(String uuid, String priv, String sid, String xpath,
                                                            java.util.Map<String, Object> fwd, String sni) {
        java.util.Map<String, Object> user = Json.obj("id", fwd.get("uuid"), "encryption", "none");
        if (!Json.str(fwd, "flow").isEmpty()) {
            user.put("flow", fwd.get("flow"));
        }
        return Json.obj(
                "log", Json.obj("loglevel", "warning"),
                "inbounds", Json.arr(
                        Json.obj("tag", "reality", "listen", "0.0.0.0", "port", (long) PORT_TCP, "protocol", "vless",
                                "settings", Json.obj("clients", Json.arr(Json.obj("id", uuid, "flow", "xtls-rprx-vision")), "decryption", "none"),
                                "streamSettings", Json.obj("network", "tcp", "security", "reality", "realitySettings", reality(sni, priv, sid)),
                                "sniffing", sniff()),
                        Json.obj("tag", "xhttp", "listen", "0.0.0.0", "port", (long) PORT_XHTTP, "protocol", "vless",
                                "settings", Json.obj("clients", Json.arr(Json.obj("id", uuid)), "decryption", "none"),
                                "streamSettings", Json.obj("network", "xhttp", "xhttpSettings", Json.obj("path", "/" + xpath),
                                        "security", "reality", "realitySettings", reality(sni, priv, sid)),
                                "sniffing", sniff())),
                "outbounds", Json.arr(
                        Json.obj("tag", "abroad", "protocol", "vless",
                                "settings", Json.obj("vnext", Json.arr(Json.obj("address", fwd.get("address"), "port", fwd.get("port"),
                                        "users", Json.arr(user)))),
                                "streamSettings", Json.obj("network", "tcp", "security", "reality",
                                        "realitySettings", Json.obj("serverName", fwd.get("sni"), "publicKey", fwd.get("pbk"),
                                                "shortId", fwd.get("sid"), "fingerprint", "chrome"))),
                        Json.obj("tag", "direct", "protocol", "freedom"),
                        Json.obj("tag", "block", "protocol", "blackhole")),
                "routing", Json.obj("domainStrategy", "IPIfNonMatch", "rules", Json.arr(
                        Json.obj("type", "field", "ip", Json.arr("geoip:private"), "outboundTag", "block"),
                        Json.obj("type", "field", "domain", Json.arr("domain:ru", "domain:su", "domain:xn--p1ai"), "outboundTag", "direct"),
                        Json.obj("type", "field", "ip", Json.arr("geoip:ru"), "outboundTag", "direct"),
                        Json.obj("type", "field", "network", "tcp,udp", "outboundTag", "abroad"))));
    }

    private static java.util.Map<String, Object> reality(String sni, String priv, String sid) {
        return Json.obj("dest", sni + ":443", "serverNames", Json.arr(sni), "privateKey", priv, "shortIds", Json.arr(sid));
    }

    private static java.util.Map<String, Object> sniff() {
        return Json.obj("enabled", true, "destOverride", Json.arr("http", "tls", "quic"), "routeOnly", true);
    }

    /** Скрипт для российского сервера: тот же, что для основного, но с настройками моста. */
    public static String bridgeScript(java.util.Map<String, Object> fwd, String sni) throws VpsError {
        if (!sni.matches(RX_SNI)) {
            throw new VpsError(Text.t("неверный адрес сайта для маскировки", "bad masking site address"));
        }
        String cfg = Json.write(bridgeConfig("$UUID", "$PRIV", "$SID", "$XPATH", fwd, sni));
        String mark = "cat > /usr/local/etc/xray/config.json <<JSON\n";
        int start = SCRIPT.indexOf(mark) + mark.length();
        int end = SCRIPT.indexOf("\nJSON\n", start);
        String body = SCRIPT.substring(0, start) + cfg + SCRIPT.substring(end);
        return body.replace("__PORT_TCP__", String.valueOf(PORT_TCP)).replace("__PORT_XHTTP__", String.valueOf(PORT_XHTTP))
                .replace("__SNI__", sni).replace("(VLESS + Reality and XHTTP + Reality)", "(bridge: VLESS + Reality → main server)");
    }

    // ---------- AmneziaWG 2.0 на своём сервере и устройства (как pult/vps.py, 1.24) ----------

    public static final String AWG_NET = "10.66.66";
    static final String RX_WGKEY = "[A-Za-z0-9+/]{42,43}=";
    static final String[] AWG_KEYS = {"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"};

    /** Набор маскировки AmneziaWG 2.0 (порядок случайных чисел — как в awg_params, для сверки). */
    public static java.util.Map<String, Object> awgParams(final Warp.Rnd rnd) {
        class R {
            long r(long lo, long hi) {
                return lo + rnd.next((int) (hi - lo + 1));
            }
        }
        R g = new R();
        long jmin = g.r(20, 60);
        long s1 = g.r(15, 150);
        long s2 = g.r(15, 150);
        while (s2 == s1 + 56) {
            s2 = g.r(15, 150);
        }
        String[] hs = new String[4];
        long lo = g.r(100_000, 10_000_000);
        for (int i = 0; i < 4; i++) {
            long width = g.r(100_000, 50_000_000);
            hs[i] = lo + "-" + (lo + width);
            lo = lo + width + g.r(1_000, 100_000_000);
        }
        int[] order = {0, 1, 2, 3};
        for (int i = 3; i > 0; i--) {
            int j = rnd.next(i + 1);
            int t = order[i];
            order[i] = order[j];
            order[j] = t;
        }
        java.util.Map<String, Object> p = new java.util.LinkedHashMap<String, Object>();
        p.put("Jc", g.r(3, 8));
        p.put("Jmin", jmin);
        p.put("Jmax", jmin + g.r(20, 300));
        p.put("S1", s1);
        p.put("S2", s2);
        p.put("S3", g.r(8, 55));
        p.put("S4", g.r(4, 27));
        for (int i = 0; i < 4; i++) {
            p.put("H" + (i + 1), hs[order[i]]);
        }
        return p;
    }

    /** Параметры идут в скрипт для сервера — только числа и диапазоны чисел. */
    public static java.util.Map<String, Object> checkAwgParams(java.util.Map<String, Object> p) throws VpsError {
        VpsError bad = new VpsError(Text.t("неверные параметры AmneziaWG", "bad AmneziaWG parameters"));
        java.util.Map<String, Object> out = new java.util.LinkedHashMap<String, Object>();
        for (String k : new String[]{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4"}) {
            String v = String.valueOf(p.get(k));
            if (!v.matches("[0-9]{1,4}") || Long.parseLong(v) > 1280) {
                throw bad;
            }
            out.put(k, Long.parseLong(v));
        }
        long[][] rng = new long[4][];
        for (int i = 0; i < 4; i++) {
            String k = "H" + (i + 1);
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("([0-9]{1,10})-([0-9]{1,10})").matcher(String.valueOf(p.get(k)));
            if (!m.matches()) {
                throw bad;
            }
            long a = Long.parseLong(m.group(1)), b = Long.parseLong(m.group(2));
            if (a < 5 || a > b || b > 4294967295L) {
                throw bad;
            }
            out.put(k, a + "-" + b);
            rng[i] = new long[]{a, b};
        }
        java.util.Arrays.sort(rng, new java.util.Comparator<long[]>() {
            @Override
            public int compare(long[] x, long[] y) {
                return x[0] != y[0] ? Long.compare(x[0], y[0]) : Long.compare(x[1], y[1]);
            }
        });
        for (int i = 0; i < 3; i++) {
            if (rng[i][1] >= rng[i + 1][0]) {
                throw bad;
            }
        }
        if ((Long) out.get("Jmin") > (Long) out.get("Jmax")) {
            throw bad;
        }
        return out;
    }

    static String awgLines(java.util.Map<String, Object> p) throws VpsError {
        java.util.Map<String, Object> c = checkAwgParams(p);
        StringBuilder b = new StringBuilder();
        for (String k : AWG_KEYS) {
            b.append(b.length() == 0 ? "" : "\n").append(k).append(" = ").append(c.get(k));
        }
        return b.toString();
    }

    static final String AWG_SCRIPT = "#!/bin/bash\n"
            + "# VEDOMYJ VPN: installs AmneziaWG 2.0 (kernel module from ppa:amnezia/ppa) next to Xray.\n"
            + "LOG=/var/log/vedomyj-awg.log\n"
            + "say()  { echo \"PULT_STEP:$1\"; echo \"== $1\" >> \"$LOG\"; }\n"
            + "fail() { tail -n 25 \"$LOG\" 2>/dev/null | sed 's/^/PULT_LOG:/'; echo \"PULT_ERROR:$1\"; exit 1; }\n"
            + "[ \"$(id -u)\" = \"0\" ] || { echo \"PULT_ERROR:root\"; exit 1; }\n"
            + ": > \"$LOG\"\n"
            + ". /etc/os-release 2>/dev/null\n"
            + "[ \"$ID\" = \"ubuntu\" ] || fail awg_os\n"
            + "export DEBIAN_FRONTEND=noninteractive\n"
            + "APT=\"apt-get -y -q -o DPkg::Lock::Timeout=300 -o Acquire::Retries=5\"\n"
            + "say packages\n"
            + "$APT update >> \"$LOG\" 2>&1\n"
            + "$APT install software-properties-common gnupg iptables >> \"$LOG\" 2>&1 || fail awg_install\n"
            + "$APT install python3-launchpadlib >> \"$LOG\" 2>&1 || true\n"
            + "$APT install \"linux-headers-$(uname -r)\" >> \"$LOG\" 2>&1 || true\n"
            + "say awg\n"
            + "add-apt-repository -y ppa:amnezia/ppa >> \"$LOG\" 2>&1 || fail awg_repo\n"
            + "$APT update >> \"$LOG\" 2>&1\n"
            + "# a new Ubuntu with no Amnezia packages yet: use the packages built for 24.04 (noble)\n"
            + "if ! apt-cache policy amneziawg-tools 2>/dev/null | grep -q 'Candidate: [0-9]'; then\n"
            + "  echo \"== no packages for $VERSION_CODENAME, using noble\" >> \"$LOG\"\n"
            + "  for f in /etc/apt/sources.list.d/amnezia-ubuntu-ppa*; do\n"
            + "    [ -f \"$f\" ] && sed -i -E \"s/^(Suites:[[:space:]]*)$VERSION_CODENAME\\$/\\1noble/; s#(ppa\\.launchpadcontent\\.net/amnezia/ppa/ubuntu/?[[:space:]]+)$VERSION_CODENAME([[:space:]])#\\1noble\\2#\" \"$f\"\n"
            + "  done\n"
            + "  $APT update >> \"$LOG\" 2>&1\n"
            + "fi\n"
            + "$APT install amneziawg-tools >> \"$LOG\" 2>&1 || fail awg_install\n"
            + "command -v awg >/dev/null 2>&1 || fail awg_install\n"
            + "$APT install amneziawg >> \"$LOG\" 2>&1 || fail awg_build\n"
            + "modprobe amneziawg >> \"$LOG\" 2>&1 || fail awg_module\n"
            + "say keys\n"
            + "umask 077\n"
            + "mkdir -p /etc/amnezia/amneziawg\n"
            + "SPRIV=$(awg genkey)\n"
            + "SPUB=$(echo \"$SPRIV\" | awg pubkey)\n"
            + "[ -n \"$SPUB\" ] || fail keys\n"
            + "IFACE=$(ip route 2>/dev/null | awk '/default/ {print $5; exit}')\n"
            + "[ -n \"$IFACE\" ] || IFACE=eth0\n"
            + "say config\n"
            + "systemctl stop awg-quick@awg0 >/dev/null 2>&1 || true\n"
            + "cat > /etc/amnezia/amneziawg/awg0.conf <<CONF\n"
            + "[Interface]\n"
            + "PrivateKey = $SPRIV\n"
            + "Address = __NET__.1/24\n"
            + "ListenPort = __PORT__\n"
            + "__PARAMS__\n"
            + "PostUp = sysctl -w net.ipv4.ip_forward=1; iptables -t nat -A POSTROUTING -s __NET__.0/24 -o $IFACE -j MASQUERADE; iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT\n"
            + "PostDown = iptables -t nat -D POSTROUTING -s __NET__.0/24 -o $IFACE -j MASQUERADE; iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT\n"
            + "\n"
            + "[Peer]\n"
            + "PublicKey = __CPUB__\n"
            + "AllowedIPs = __NET__.2/32\n"
            + "CONF\n"
            + "say tune\n"
            + "if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then\n"
            + "  ufw allow __PORT__/udp >/dev/null 2>&1\n"
            + "fi\n"
            + "if command -v firewall-cmd >/dev/null 2>&1; then\n"
            + "  firewall-cmd --permanent --add-port=__PORT__/udp >/dev/null 2>&1; firewall-cmd --reload >/dev/null 2>&1 || true\n"
            + "fi\n"
            + "say start\n"
            + "systemctl enable awg-quick@awg0 >/dev/null 2>&1 || true\n"
            + "systemctl restart awg-quick@awg0 >/dev/null 2>&1\n"
            + "sleep 2\n"
            + "awg show awg0 >/dev/null 2>&1 || fail awg_service\n"
            + "echo \"PULT_RESULT:$SPUB|__PORT__\"\n";

    static final String AWG_PEER_SCRIPT = "#!/bin/bash\n"
            + "fail() { echo \"PULT_ERROR:$1\"; exit 1; }\n"
            + "echo \"PULT_STEP:peer\"\n"
            + "[ \"$(id -u)\" = \"0\" ] || fail root\n"
            + "CONF=/etc/amnezia/amneziawg/awg0.conf\n"
            + "[ -f \"$CONF\" ] && command -v awg >/dev/null 2>&1 || fail noawg\n"
            + "N=\"\"\n"
            + "for i in $(seq 3 250); do\n"
            + "  grep -q \"__NET__.$i/32\" \"$CONF\" || { N=$i; break; }\n"
            + "done\n"
            + "[ -n \"$N\" ] || fail awg_full\n"
            + "printf '\\n[Peer]\\nPublicKey = %s\\nAllowedIPs = __NET__.%s/32\\n' \"__CPUB__\" \"$N\" >> \"$CONF\"\n"
            + "awg set awg0 peer \"__CPUB__\" allowed-ips \"__NET__.$N/32\" >/dev/null 2>&1 || fail awg_service\n"
            + "SPUB=$(awg show awg0 public-key)\n"
            + "PORT=$(awg show awg0 listen-port)\n"
            + "echo \"PULT_RESULT:$SPUB|$PORT|$N\"\n";

    public static String awgScript(String clientPub, int port, java.util.Map<String, Object> params) throws VpsError {
        if (clientPub == null || !clientPub.matches(RX_WGKEY) || port < 1024 || port > 65535) {
            throw new VpsError(Text.t("неверный ключ или порт AmneziaWG", "bad AmneziaWG key or port"));
        }
        return AWG_SCRIPT.replace("__PARAMS__", awgLines(params)).replace("__CPUB__", clientPub)
                .replace("__PORT__", String.valueOf(port)).replace("__NET__", AWG_NET);
    }

    public static String awgPeerScript(String clientPub) throws VpsError {
        if (clientPub == null || !clientPub.matches(RX_WGKEY)) {
            throw new VpsError(Text.t("неверный ключ AmneziaWG", "bad AmneziaWG key"));
        }
        return AWG_PEER_SCRIPT.replace("__CPUB__", clientPub).replace("__NET__", AWG_NET);
    }

    /** «ключ сервера|порт[|номер устройства]» → {ключ, порт, номер}. */
    public static Object[] parseAwgResult(String result) throws VpsError {
        VpsError bad = new VpsError(Text.t("сервер прислал непонятный ответ", "the server sent an unclear answer"));
        String[] parts = (result == null ? "" : result).split("\\|", -1);
        if ((parts.length != 2 && parts.length != 3) || !parts[0].matches(RX_WGKEY) || !parts[1].matches("[0-9]{4,5}")
                || (parts.length == 3 && !parts[2].matches("[0-9]{1,3}"))) {
            throw bad;
        }
        int port = Integer.parseInt(parts[1]);
        int n = parts.length == 3 ? Integer.parseInt(parts[2]) : 2;
        if (port < 1024 || port > 65535 || n < 2 || n > 250) {
            throw bad;
        }
        return new Object[]{parts[0], port, n};
    }

    public static String awgClientConf(String host, int port, String serverPub, String clientPriv, int n,
                                       java.util.Map<String, Object> params, String i1) throws VpsError {
        String hp = host.contains(":") ? "[" + host + "]" : host;
        StringBuilder b = new StringBuilder();
        b.append("[Interface]\nPrivateKey = ").append(clientPriv).append("\nAddress = ").append(AWG_NET).append('.').append(n)
                .append("/32\nDNS = 1.1.1.1, 1.0.0.1\n").append(awgLines(params)).append('\n');
        if (i1 != null && !i1.isEmpty()) {
            b.append("I1 = ").append(i1).append('\n');
        }
        b.append("\n[Peer]\nPublicKey = ").append(serverPub).append("\nEndpoint = ").append(hp).append(':').append(port)
                .append("\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n");
        return b.toString();
    }
}
