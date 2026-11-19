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
        String common = "security=reality&pbk=" + pub + "&fp=chrome&sni=" + SNI + "&sid=" + sid;
        List<String> links = new ArrayList<String>();
        links.add("vless://" + uuid + "@" + hp + ":" + PORT_TCP + "?type=tcp&" + common + "&flow=xtls-rprx-vision#"
                + Text.quote(name));
        links.add("vless://" + uuid + "@" + hp + ":" + PORT_XHTTP + "?type=xhttp&path=%2F" + path + "&" + common + "#"
                + Text.quote(name + " · XHTTP"));
        return links;
    }
}
