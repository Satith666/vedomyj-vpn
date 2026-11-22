"""Мастер своего сервера (VPS): ставит на сервер Xray с VLESS + Reality и запасным входом XHTTP.

Как это работает:
- программа открывает окно Windows с ssh (он встроен в Windows 10 и 11) и передаёт серверу скрипт установки;
- пароль от сервера человек вводит сам в этом окне — программа его не видит и нигде не хранит;
- скрипт ставит Xray официальным установщиком (github.com/XTLS/Xray-install), создаёт ключи и настройки,
  включает BBR и открывает порты, а в конце печатает строку PULT_RESULT с данными для подключения;
- ссылки собирает сама программа (по строгим шаблонам), сервер в ответе может прислать только значения.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
from urllib.parse import quote

IS_WINDOWS = sys.platform == "win32"
SNI = "www.microsoft.com"  # сайт, под который маскируется сервер (Reality)
PORT_TCP = 443
PORT_XHTTP = 8443

STEPS = {
    "packages": "Ставлю нужные пакеты на сервер",
    "xray": "Ставлю Xray на сервер",
    "keys": "Создаю ключи",
    "config": "Записываю настройки сервера",
    "tune": "Включаю ускорение BBR и открываю порты",
    "start": "Запускаю Xray на сервере",
}
ERRORS = {
    "root": "нужен вход под пользователем root (в панели хостинга он обычно и выдаётся)",
    "os": "на сервере неподходящая система — нужна Ubuntu, Debian, CentOS, AlmaLinux или Rocky",
    "install": "не удалось установить Xray — у сервера нет доступа к GitHub или закончилось место",
    "keys": "Xray не создал ключи",
    "port": f"порт {PORT_TCP} на сервере занят другой программой (например, сайтом)",
    "config": "Xray не принял настройки",
    "service": "Xray на сервере не запустился",
    "noxray": "на сервере нет Xray, установленного программой — сначала настрой сервер мастером",
    "python": "на сервере нет python3, и его не удалось установить",
}

SCRIPT = r"""#!/bin/bash
# VEDOMYJ VPN: installs Xray (VLESS + Reality and XHTTP + Reality) with the official XTLS installer.
say()  { echo "PULT_STEP:$1"; }
fail() { echo "PULT_ERROR:$1"; exit 1; }
[ "$(id -u)" = "0" ] || fail root
export DEBIAN_FRONTEND=noninteractive
say packages
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq curl unzip openssl >/dev/null 2>&1
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y -q curl unzip openssl >/dev/null 2>&1
elif command -v yum >/dev/null 2>&1; then
  yum install -y -q curl unzip openssl >/dev/null 2>&1
else
  fail os
fi
command -v curl >/dev/null 2>&1 || fail os
if command -v ss >/dev/null 2>&1 && ss -ltnp 2>/dev/null | grep -E ':__PORT_TCP__\b' | grep -vq xray; then fail port; fi
say xray
bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/tmp/pult-xray-install.log 2>&1 || fail install
XRAY=/usr/local/bin/xray
[ -x "$XRAY" ] || fail install
say keys
UUID=$($XRAY uuid | tr -d ' \r\n')
KEYS=$($XRAY x25519)
PRIV=$(echo "$KEYS" | grep -i 'private' | head -n1 | sed 's/.*: *//' | tr -d ' \r')
PUB=$(echo "$KEYS" | grep -iE 'public|password' | grep -vi 'private' | head -n1 | sed 's/.*: *//' | tr -d ' \r')
SID=$(openssl rand -hex 8)
XPATH=$(openssl rand -hex 6)
[ -n "$UUID" ] && [ -n "$PRIV" ] && [ -n "$PUB" ] || fail keys
say config
mkdir -p /usr/local/etc/xray
cat > /usr/local/etc/xray/config.json <<JSON
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {"tag": "reality", "listen": "0.0.0.0", "port": __PORT_TCP__, "protocol": "vless",
     "settings": {"clients": [{"id": "$UUID", "flow": "xtls-rprx-vision"}], "decryption": "none"},
     "streamSettings": {"network": "tcp", "security": "reality",
       "realitySettings": {"dest": "__SNI__:443", "serverNames": ["__SNI__"], "privateKey": "$PRIV", "shortIds": ["$SID"]}},
     "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true}},
    {"tag": "xhttp", "listen": "0.0.0.0", "port": __PORT_XHTTP__, "protocol": "vless",
     "settings": {"clients": [{"id": "$UUID"}], "decryption": "none"},
     "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/$XPATH"}, "security": "reality",
       "realitySettings": {"dest": "__SNI__:443", "serverNames": ["__SNI__"], "privateKey": "$PRIV", "shortIds": ["$SID"]}},
     "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true}}
  ],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}],
  "routing": {"rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "block"}]}
}
JSON
$XRAY run -test -c /usr/local/etc/xray/config.json >/dev/null 2>&1 || fail config
say tune
if ! grep -q 'tcp_congestion_control=bbr' /etc/sysctl.conf 2>/dev/null; then
  printf 'net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n' >> /etc/sysctl.conf
fi
sysctl -p >/dev/null 2>&1 || true
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
  ufw allow __PORT_TCP__/tcp >/dev/null 2>&1; ufw allow __PORT_XHTTP__/tcp >/dev/null 2>&1
fi
if command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port=__PORT_TCP__/tcp >/dev/null 2>&1
  firewall-cmd --permanent --add-port=__PORT_XHTTP__/tcp >/dev/null 2>&1
  firewall-cmd --reload >/dev/null 2>&1 || true
fi
say start
systemctl enable xray >/dev/null 2>&1 || true
systemctl restart xray >/dev/null 2>&1
sleep 2
systemctl is-active --quiet xray || fail service
echo "PULT_RESULT:$UUID|$PUB|$SID|$XPATH"
"""


# состояние своего сервера: нагрузка, память, место, трафик, работает ли Xray, сколько подключений
STATUS_SCRIPT = r"""#!/bin/bash
up=$(cut -d. -f1 /proc/uptime 2>/dev/null)
load=$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null)
mem=$(free -m 2>/dev/null | awk '/^Mem:/ {print $3"/"$2}')
disk=$(df -h / 2>/dev/null | awk 'NR==2 {print $3"/"$2}')
iface=$(ip route 2>/dev/null | awk '/default/ {print $5; exit}')
rx=0; tx=0
if [ -n "$iface" ] && [ -r /proc/net/dev ]; then
  rx=$(awk -v i="$iface:" '$1==i {print $2}' /proc/net/dev); tx=$(awk -v i="$iface:" '$1==i {print $10}' /proc/net/dev)
fi
xr=$(systemctl is-active xray 2>/dev/null)
conns=$(ss -tn state established 2>/dev/null | grep -cE ':(__PORT_TCP__|__PORT_XHTTP__)\b')
clients=$(grep -o '"id": *"[0-9a-fA-F-]\{36\}"' /usr/local/etc/xray/config.json 2>/dev/null | sort -u | wc -l)
echo "PULT_RESULT:${up:-0}|${load:-?}|${mem:-?}|${disk:-?}|${rx:-0}|${tx:-0}|${xr:-unknown}|${conns:-0}|${clients:-0}"
"""

# доступ для друга: отдельный пользователь (свой ключ UUID) в обоих входах; убрать — по UUID
FRIEND_SCRIPT = r"""#!/bin/bash
fail() { echo "PULT_ERROR:$1"; exit 1; }
[ "$(id -u)" = "0" ] || fail root
CFG=/usr/local/etc/xray/config.json
XRAY=/usr/local/bin/xray
[ -f "$CFG" ] && [ -x "$XRAY" ] || fail noxray
command -v python3 >/dev/null 2>&1 || { apt-get install -y -qq python3 >/dev/null 2>&1 || fail python; }
ACTION="__ACTION__"; TARGET="__UUID__"
NEW=$($XRAY uuid | tr -d ' \r')
[ "$ACTION" = "add" ] && TARGET="$NEW"
OUT=$(python3 - "$CFG" "$ACTION" "$TARGET" <<'PY'
import json, sys
path, action, uid = sys.argv[1:4]
cfg = json.load(open(path))
priv = sid = xpath = ""
for ib in cfg.get("inbounds", []):
    clients = ib.setdefault("settings", {}).setdefault("clients", [])
    if action == "add":
        c = {"id": uid}
        if ib.get("tag") == "reality":
            c["flow"] = "xtls-rprx-vision"
        clients.append(c)
    else:
        ib["settings"]["clients"] = [c for c in clients if c.get("id") != uid] or clients
    rs = ib.get("streamSettings", {}).get("realitySettings", {})
    priv = priv or rs.get("privateKey", "")
    sid = sid or (rs.get("shortIds") or [""])[0]
    xpath = xpath or ib.get("streamSettings", {}).get("xhttpSettings", {}).get("path", "").lstrip("/")
json.dump(cfg, open(path + ".new", "w"), indent=1)
print(priv + "|" + sid + "|" + xpath)
PY
) || fail config
$XRAY run -test -c "$CFG.new" >/dev/null 2>&1 || { rm -f "$CFG.new"; fail config; }
mv "$CFG.new" "$CFG"
systemctl restart xray >/dev/null 2>&1
sleep 2
systemctl is-active --quiet xray || fail service
PRIV=${OUT%%|*}; REST=${OUT#*|}; SID=${REST%%|*}; XPATH=${REST#*|}
PUB=$($XRAY x25519 -i "$PRIV" | grep -iE 'public|password' | grep -vi 'private' | head -n1 | sed 's/.*: *//' | tr -d ' \r')
echo "PULT_RESULT:$TARGET|$PUB|$SID|$XPATH"
"""


def status_script() -> str:
    return STATUS_SCRIPT.replace("__PORT_TCP__", str(PORT_TCP)).replace("__PORT_XHTTP__", str(PORT_XHTTP))


def friend_script(action: str, uuid: str = "") -> str:
    if action not in ("add", "remove") or (action == "remove" and not re.fullmatch(r"[0-9a-fA-F-]{36}", uuid)):
        raise VpsError("неизвестное действие")
    return FRIEND_SCRIPT.replace("__ACTION__", action).replace("__UUID__", uuid if action == "remove" else "")


def parse_status(result: str) -> dict:
    """Строка состояния сервера → понятные поля (все значения проверяются)."""
    parts = result.split("|")
    if len(parts) != 9:
        raise VpsError("сервер прислал непонятный ответ")
    num = lambda v: int(v) if re.fullmatch(r"[0-9]{1,18}", v) else 0  # noqa: E731
    clean = lambda v: re.sub(r"[^0-9A-Za-z./ ,:-]", "", v)[:40]  # noqa: E731
    return {"uptime_s": num(parts[0]), "load": clean(parts[1]), "mem_mb": clean(parts[2]), "disk": clean(parts[3]),
            "rx": num(parts[4]), "tx": num(parts[5]), "xray": clean(parts[6]), "conns": num(parts[7]),
            "clients": num(parts[8])}


class VpsError(RuntimeError):
    pass


def script() -> str:
    return (SCRIPT.replace("__PORT_TCP__", str(PORT_TCP)).replace("__PORT_XHTTP__", str(PORT_XHTTP))
            .replace("__SNI__", SNI))


# ---------- мост через российский сервер (1.23) ----------
# Российский VPS принимает подключение (маскировка под российский сайт — такие адреса пускают и «белые списки»)
# и передаёт его на твой основной сервер за границей. Российские сайты он открывает сам, напрямую.

RU_SNI = "vk.com"
BRIDGE_NAME = "Мост (белые списки)"
_RX_UUID = r"[0-9a-fA-F-]{36}"
_RX_PUB = r"[A-Za-z0-9_\-]{40,50}"
_RX_SID = r"[0-9a-f]{0,16}"
_RX_HOST = r"[A-Za-z0-9.\-]{1,253}|[0-9A-Fa-f:]{2,39}"
_RX_SNI = r"[a-z0-9.\-]{3,100}"


def parse_forward(link: str) -> dict:
    """Ссылка основного сервера (VLESS + Reality) → куда мосту передавать трафик. Всё проверяется по шаблонам:
    эти значения попадают в скрипт для сервера."""
    from urllib.parse import parse_qs, unquote, urlsplit
    u = urlsplit((link or "").strip())
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    host = (u.hostname or "").strip("[]")
    try:
        port = u.port or PORT_TCP
    except ValueError:
        raise VpsError("у основного сервера нет подходящего входа (нужен VLESS + Reality, как делает мастер)") from None
    fwd = {"address": host, "port": port, "uuid": unquote(u.username or ""), "pbk": q.get("pbk", ""),
           "sid": q.get("sid", ""), "sni": q.get("sni", ""), "flow": q.get("flow", "")}
    if u.scheme != "vless" or q.get("security") != "reality" or q.get("type", "tcp") != "tcp" \
            or not re.fullmatch(_RX_HOST, host) or not re.fullmatch(_RX_UUID, fwd["uuid"]) \
            or not re.fullmatch(_RX_PUB, fwd["pbk"]) or not re.fullmatch(_RX_SID, fwd["sid"]) \
            or not re.fullmatch(_RX_SNI, fwd["sni"]) or fwd["flow"] not in ("", "xtls-rprx-vision") \
            or not 1 <= int(fwd["port"]) <= 65535:
        raise VpsError("у основного сервера нет подходящего входа (нужен VLESS + Reality, как делает мастер)")
    return fwd


def bridge_config(uuid: str, priv: str, sid: str, xpath: str, fwd: dict, sni: str = RU_SNI,
                  port_tcp: int = PORT_TCP, port_xhttp: int = PORT_XHTTP, listen: str = "0.0.0.0") -> dict:
    """Настройки Xray моста. В скрипт идут с переменными оболочки ($UUID…), в проверку на GitHub — с настоящими."""
    reality = {"dest": f"{sni}:443", "serverNames": [sni], "privateKey": priv, "shortIds": [sid]}
    sniff = {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}
    user = {"id": fwd["uuid"], "encryption": "none"}
    if fwd.get("flow"):
        user["flow"] = fwd["flow"]
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "reality", "listen": listen, "port": port_tcp, "protocol": "vless",
             "settings": {"clients": [{"id": uuid, "flow": "xtls-rprx-vision"}], "decryption": "none"},
             "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": reality}, "sniffing": sniff},
            {"tag": "xhttp", "listen": listen, "port": port_xhttp, "protocol": "vless",
             "settings": {"clients": [{"id": uuid}], "decryption": "none"},
             "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": f"/{xpath}"}, "security": "reality",
                                "realitySettings": dict(reality)}, "sniffing": sniff},
        ],
        "outbounds": [
            {"tag": "abroad", "protocol": "vless",
             "settings": {"vnext": [{"address": fwd["address"], "port": int(fwd["port"]), "users": [user]}]},
             "streamSettings": {"network": "tcp", "security": "reality",
                                "realitySettings": {"serverName": fwd["sni"], "publicKey": fwd["pbk"],
                                                    "shortId": fwd["sid"], "fingerprint": "chrome"}}},
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
            {"type": "field", "domain": ["domain:ru", "domain:su", "domain:xn--p1ai"], "outboundTag": "direct"},
            {"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "abroad"},
        ]},
    }


def bridge_script(fwd: dict, sni: str = RU_SNI) -> str:
    """Скрипт для российского сервера: тот же, что для основного, но с настройками моста."""
    import json
    if not re.fullmatch(_RX_SNI, sni):
        raise VpsError("неверный адрес сайта для маскировки")
    cfg = json.dumps(bridge_config("$UUID", "$PRIV", "$SID", "$XPATH", fwd, sni), separators=(",", ":"), ensure_ascii=True)
    start = SCRIPT.index("cat > /usr/local/etc/xray/config.json <<JSON\n") + len("cat > /usr/local/etc/xray/config.json <<JSON\n")
    end = SCRIPT.index("\nJSON\n", start)
    body = SCRIPT[:start] + cfg + SCRIPT[end:]
    return (body.replace("__PORT_TCP__", str(PORT_TCP)).replace("__PORT_XHTTP__", str(PORT_XHTTP))
            .replace("__SNI__", sni).replace("(VLESS + Reality and XHTTP + Reality)", "(bridge: VLESS + Reality → main server)"))


def check_input(host: str, port, user: str) -> tuple[str, int, str]:
    host = (host or "").strip().strip("[]")
    user = (user or "root").strip()
    try:
        port = int(port or 22)
    except (TypeError, ValueError):
        raise VpsError("Порт SSH — это число, обычно 22.") from None
    if not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}|[0-9A-Fa-f:]{2,39}", host) or not 1 <= port <= 65535:
        raise VpsError("Впиши адрес сервера (IP из письма хостинга), например 203.0.113.10.")
    if not re.fullmatch(r"[a-z_][a-z0-9_\-]{0,31}", user):
        raise VpsError("Неверное имя пользователя — обычно это root.")
    return host, port, user


def ssh_path() -> str:
    found = shutil.which("ssh")
    if found:
        return found
    win = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "OpenSSH", "ssh.exe")
    return win if os.path.isfile(win) else ""


def start(host: str, port: int, user: str, script_path: str, out_path: str, hint: str = "",
          body: str | None = None) -> subprocess.Popen:
    """Открывает окно с ssh: там человек вводит пароль от сервера. Вывод скрипта пишется в out_path.
    body — какой скрипт выполнить (по умолчанию — установка)."""
    ssh = ssh_path()
    if not ssh:
        raise VpsError("В Windows не включён клиент OpenSSH: Параметры → Приложения → Дополнительные компоненты → "
                       "«Клиент OpenSSH».")
    with open(script_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(script() if body is None else body)
    open(out_path, "w").close()
    opts = "-o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15 -o ConnectTimeout=20"
    line = (f'"{ssh}" {opts} -p {port} {user}@{host} "bash -s" < "{script_path}" > "{out_path}"')
    if IS_WINDOWS:
        hint = re.sub(r'[&|<>^"%]', "", hint or "VEDOMYJ VPN")  # текст для echo — без спецсимволов cmd
        # строка целиком, а не списком: иначе Python экранирует кавычки так, что cmd их не поймёт (/s — снять внешние)
        inner = f"chcp 65001 >nul & title VEDOMYJ VPN & echo {hint} & echo. & {line}"
        return subprocess.Popen(f'cmd.exe /s /c "{inner}"', creationflags=subprocess.CREATE_NEW_CONSOLE)
    return subprocess.Popen(["/bin/sh", "-c", line])


def read_progress(out_path: str) -> tuple[str, str, str]:
    """(шаг, ошибка, результат) из того, что скрипт уже напечатал."""
    try:
        with open(out_path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return "", "", ""
    step = error = result = ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("PULT_STEP:"):
            step = line[10:]
        elif line.startswith("PULT_ERROR:"):
            error = line[11:]
        elif line.startswith("PULT_RESULT:"):
            result = line[12:]
    return step, error, result


def make_links(host: str, result: str, name: str, sni: str = SNI) -> list[str]:
    """Ссылки на свой сервер. Значения из ответа сервера проверяются по строгим шаблонам."""
    parts = result.split("|")
    if len(parts) != 4:
        raise VpsError("сервер прислал непонятный ответ")
    uuid, pub, sid, path = parts
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", uuid) or not re.fullmatch(r"[A-Za-z0-9_\-]{40,50}", pub) \
            or not re.fullmatch(r"[0-9a-f]{2,16}", sid) or not re.fullmatch(r"[0-9a-f]{4,32}", path):
        raise VpsError("сервер прислал непонятный ответ")
    hp = f"[{host}]" if ":" in host else host
    common = f"security=reality&pbk={pub}&fp=chrome&sni={sni}&sid={sid}"
    return [
        f"vless://{uuid}@{hp}:{PORT_TCP}?type=tcp&{common}&flow=xtls-rprx-vision#{quote(name)}",
        f"vless://{uuid}@{hp}:{PORT_XHTTP}?type=xhttp&path=%2F{path}&{common}#{quote(name + ' · XHTTP')}",
    ]


def wait(proc: subprocess.Popen, out_path: str, on_step, should_stop, timeout: float = 900.0) -> str:
    """Ждёт конца установки. Возвращает строку результата или бросает VpsError с понятной причиной."""
    started = time.time()
    last = ""
    while True:
        step, error, result = read_progress(out_path)
        if step and step != last:
            last = step
            on_step(STEPS.get(step, step))
        if result:
            return result
        if error:
            raise VpsError(ERRORS.get(error, error))
        if proc.poll() is not None:
            time.sleep(0.5)
            step, error, result = read_progress(out_path)
            if result:
                return result
            if error:
                raise VpsError(ERRORS.get(error, error))
            if not last:
                raise VpsError("не удалось войти на сервер — проверь адрес, порт, имя пользователя и пароль")
            raise VpsError("связь с сервером оборвалась во время установки — попробуй ещё раз")
        if should_stop():
            proc.terminate()
            raise VpsError("остановлено")
        if time.time() - started > timeout:
            proc.terminate()
            raise VpsError("установка идёт слишком долго — попробуй ещё раз")
        time.sleep(1.0)
