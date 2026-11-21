"""«Семья»: ты настраиваешь VPN родителей на расстоянии.

Как устроено (шаг 1 — посылки текстом; шаг 2 — доставка сама, через сеть торрентов):
  • помощник (ты) делает приглашение для устройства: в нём имя помощника, имя устройства и случайный секрет
    (32 байта). Приглашение — ссылка vedomyj-family://i/… (и QR-код): мама открывает его в своей программе и
    нажимает «Разрешить». Без её «Разрешить» устройство не подключается;
  • дальше — посылки vedomyj-family://p/…: от помощника — изменения (подписки, серверы, способ, функции),
    от устройства — снимок его программы и что получилось. Посылка сжата (zlib), зашифрована AES-128-CTR и
    подписана HMAC-SHA256 ключами из секрета: прочитать и подделать её может только тот, у кого есть секрет;
  • у каждой посылки номер (старые и повторные не принимаются) и срок (7 дней);
  • что можно менять — только белый список OPS: настройки программы, не компьютер; сайты и история не видны.
Секреты лежат в настройках вместе с подписками — зашифрованными (secure.py).
Телефон — core/Family.java, формат тот же (сверка в android/coretest/run.sh).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import zlib

from . import APP_VERSION, i18n, warp

INVITE = "vedomyj-family://i/"
PACKET = "vedomyj-family://p/"
MAGIC = b"VF1"
TTL = 7 * 24 * 3600
MAX_TEXT = 200_000
MAX_BODY = 512 * 1024
TO_DEVICE, TO_HELPER = 0, 1

# Что помощник может поменять на устройстве — и ничего больше.
OPS = ("sub_add", "sub_remove", "sub_update", "servers_add", "server_remove", "method", "set", "reconnect",
       "warp_create", "report")
SET_KEYS = ("block_ads", "dns_encrypted", "accel")
METHODS = ("auto", "server", "awg", "off")
OP_NAMES = {"sub_add": "добавить подписку", "sub_remove": "удалить подписку", "sub_update": "обновить подписки",
            "servers_add": "добавить серверы", "server_remove": "удалить сервер", "method": "сменить способ",
            "set": "переключить функции", "reconnect": "переподключить VPN", "warp_create": "создать бесплатный WARP",
            "report": "прислать состояние"}


class FamilyError(RuntimeError):
    pass


# ---------- формат ----------

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _h(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def pair_id(secret: bytes) -> str:
    return _h(secret, b"vedomyj-family pair")[:8].hex()


def keys(secret: bytes, direction: int) -> tuple[bytes, bytes]:
    return (_h(secret, b"vedomyj-family enc %d" % direction)[:16], _h(secret, b"vedomyj-family mac %d" % direction))


def dumps(v) -> str:
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def make_invite(helper: str, device: str, secret: bytes) -> str:
    return INVITE + b64u(dumps({"v": 1, "h": helper, "d": device, "s": b64u(secret)}).encode("utf-8"))


def parse_invite(text: str) -> dict | None:
    m = re.search(re.escape(INVITE) + r"([A-Za-z0-9_-]{20,4000})", text or "")
    if not m:
        return None
    try:
        d = json.loads(unb64u(m.group(1)).decode("utf-8"))
        secret = unb64u(str(d["s"]))
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        raise FamilyError("Приглашение повреждено — попроси прислать его заново.") from None
    if d.get("v") != 1 or len(secret) != 32:
        raise FamilyError("Приглашение от другой версии программы — обнови VEDOMYJ VPN.")
    return {"helper": str(d.get("h") or "")[:40] or "Помощник", "device": str(d.get("d") or "")[:40], "secret": secret}


def seal(secret: bytes, direction: int, seq: int, payload: dict, iv: bytes | None = None) -> str:
    body = zlib.compress(dumps(payload).encode("utf-8"), 9)
    enc, mac = keys(secret, direction)
    iv = iv if iv is not None else secrets.token_bytes(16)
    head = MAGIC + bytes([direction]) + bytes.fromhex(pair_id(secret)) + seq.to_bytes(8, "big")
    ct = warp.aes128_ctr(enc, iv, body)
    return PACKET + b64u(head + iv + ct + _h(mac, head + iv + ct))


def peek(text: str) -> tuple[str, int, int, bytes] | None:
    """(пара, направление, номер, сырые байты) — без расшифровки; None — в тексте нет посылки."""
    m = re.search(re.escape(PACKET) + r"([A-Za-z0-9_-]{40,})", text or "")
    if not m:
        return None
    try:
        raw = unb64u(m.group(1))
    except ValueError:
        raise FamilyError("Посылка повреждена — попроси прислать её заново.") from None
    if len(raw) < 3 + 1 + 8 + 8 + 16 + 32 or raw[:3] != MAGIC or raw[3] not in (0, 1):
        raise FamilyError("Посылка повреждена — попроси прислать её заново.")
    return raw[4:12].hex(), raw[3], int.from_bytes(raw[12:20], "big"), raw


def open_packet(secret: bytes, raw: bytes) -> dict:
    direction = raw[3]
    enc, mac = keys(secret, direction)
    head, iv, ct, tag = raw[:20], raw[20:36], raw[36:-32], raw[-32:]
    if not hmac.compare_digest(_h(mac, head + iv + ct), tag):
        raise FamilyError("Посылка не прошла проверку подписи: она испорчена или не от твоей семьи.")
    try:
        d = zlib.decompressobj()
        body = d.decompress(warp.aes128_ctr(enc, iv, ct), MAX_BODY)
        if d.unconsumed_tail:
            raise ValueError("слишком большая")
        payload = json.loads(body.decode("utf-8"))
    except (zlib.error, ValueError, UnicodeDecodeError):
        raise FamilyError("Посылка не читается.") from None
    if not isinstance(payload, dict):
        raise FamilyError("Посылка не читается.")
    return payload


def check_ops(ops) -> list[dict]:
    """Только известные изменения и разумные размеры — иначе ошибка (посылку целиком не принимаем)."""
    if not isinstance(ops, list) or not 0 < len(ops) <= 40:
        raise FamilyError("В посылке нет изменений.")
    out = []
    for op in ops:
        if not isinstance(op, dict) or op.get("op") not in OPS:
            raise FamilyError("В посылке неизвестное изменение — обнови программу.")
        o = {"op": op["op"]}
        for k in ("url", "name", "id", "text", "method"):
            if k in op:
                v = op[k]
                if not isinstance(v, str) or len(v) > (60_000 if k == "text" else 4000):
                    raise FamilyError("В посылке слишком длинное значение.")
                o[k] = v
        if op["op"] == "method" and o.get("method") not in METHODS:
            raise FamilyError("В посылке неизвестный способ.")
        if op["op"] == "set":
            vals = op.get("values")
            if not isinstance(vals, dict) or not vals or any(k not in SET_KEYS or not isinstance(v, bool)
                                                             for k, v in vals.items()):
                raise FamilyError("В посылке неизвестная настройка.")
            o["values"] = dict(vals)
        if op["op"] == "sub_add" and not re.match(r"^https?://", o.get("url", "")):
            raise FamilyError("В посылке подписка без ссылки https://.")
        if op["op"] in ("sub_remove", "server_remove") and not (o.get("id") or o.get("url")):
            raise FamilyError("В посылке не сказано, что удалить.")
        if op["op"] == "servers_add" and not o.get("text"):
            raise FamilyError("В посылке нет серверов.")
        out.append(o)
    return out


def summary(ops: list[dict]) -> list[str]:
    """Что поменяется — по-человечески, для окна «Установить?» (без ссылок и ключей)."""
    out = []
    for o in ops:
        t = OP_NAMES[o["op"]]
        if o["op"] in ("sub_add", "sub_remove") and o.get("name"):
            t += f" «{o['name'][:40]}»"
        elif o["op"] == "method":
            t += f": {({'auto': 'Авто', 'server': 'VPN-сервер', 'awg': 'AmneziaWG', 'off': 'Без VPN'})[o['method']]}"
        elif o["op"] == "set":
            names = {"block_ads": "без рекламы", "dns_encrypted": "шифрование DNS", "accel": "ускорение YouTube и Discord"}
            t += ": " + ", ".join(f"{names[k]} — {'вкл' if v else 'выкл'}" for k, v in o["values"].items())
        out.append(t)
    return out


def server_id(link: str) -> str:
    return hashlib.sha1((link or "").encode("utf-8")).hexdigest()[:12]


# ---------- часть движка ----------

class FamilyMixin:
    """Часть Engine: приглашения, посылки, применение изменений, снимок программы."""

    def _fam(self) -> dict:
        f = self.settings.get("family")
        if not isinstance(f, dict):
            f = {}
        f.setdefault("me", "")
        f.setdefault("helpers", [])
        f.setdefault("devices", [])
        self.settings["family"] = f
        return f

    def _fam_find(self, pair: str) -> tuple[str, dict] | tuple[None, None]:
        f = self._fam()
        for role in ("helpers", "devices"):
            for x in f[role]:
                if x.get("pair") == pair:
                    return role, x
        return None, None

    def family_state(self) -> dict:
        """Для окна — без секретов."""
        f = self._fam()
        return {
            "me": f["me"],
            "helpers": [{"pair": h["pair"], "name": h["name"], "mode": h.get("mode", "ask"), "since": h.get("since", 0),
                         "pending": {"summary": [i18n.tr(x) for x in summary(h["pending"]["ops"])],
                                     "at": h["pending"].get("at", 0)}
                         if h.get("pending") else None, "reply": h.get("reply", "")} for h in f["helpers"]],
            "devices": [{"pair": d["pair"], "name": d["name"], "since": d.get("since", 0), "snap": d.get("snap"),
                         "snap_at": d.get("snap_at", 0), "invite": "" if d.get("snap") else d.get("invite", ""),
                         "sent": [dict(x, summary=[i18n.tr(y) for y in x.get("summary", [])]) for x in d.get("sent", [])[-10:]]}
                        for d in f["devices"]],
        }

    def family_set_me(self, name: str) -> None:
        self._fam()["me"] = (name or "").strip()[:40]
        self.save()

    def family_invite(self, device: str) -> dict:
        """Помощник: новое устройство в семье и приглашение для него."""
        f = self._fam()
        device = (device or "").strip()[:40] or "Устройство"
        if not f["me"]:
            raise FamilyError("Сначала напиши, как тебя подписать (например, «Сын»).")
        if len(f["devices"]) >= 20:
            raise FamilyError("В семье уже 20 устройств — убери ненужные.")
        secret = secrets.token_bytes(32)
        invite = make_invite(f["me"], device, secret)
        f["devices"].append({"pair": pair_id(secret), "name": device, "secret": b64u(secret), "since": int(time.time()),
                             "seq_in": 0, "seq_out": 0, "snap": None, "snap_at": 0, "sent": [], "invite": invite})
        self.save()
        self.log(f"Семья: приглашение для «{device}» готово.")
        self.notify("family")
        return {"pair": pair_id(secret), "text": invite}

    def family_receive(self, text: str) -> dict:
        """Что вставили или чем поделились: приглашение или посылка. Посылку от помощника в режиме «спрашивать»
        только запоминает (окно спросит «Установить?»), в режиме «применять сразу» — применяет."""
        text = (text or "")[:MAX_TEXT]
        inv = parse_invite(text)
        if inv:
            pair = pair_id(inv["secret"])
            role, _ = self._fam_find(pair)
            if role == "devices":
                raise FamilyError("Это твоё же приглашение — его нужно отправить тому, кого подключаешь.")
            return {"kind": "invite", "helper": inv["helper"], "device": inv["device"], "pair": pair,
                    "known": role == "helpers"}
        pk = peek(text)
        if not pk:
            raise FamilyError("Здесь нет приглашения или посылки «Семьи».")
        pair, direction, seq, raw = pk
        role, ent = self._fam_find(pair)
        if not ent or (direction == TO_DEVICE) != (role == "helpers"):
            raise FamilyError("Эта посылка не для этого устройства (или его убрали из семьи).")
        payload = open_packet(unb64u(ent["secret"]), raw)
        if seq <= int(ent.get("seq_in", 0)):
            return {"kind": "old", "name": ent["name"]}
        if int(payload.get("exp", 0)) < time.time():
            raise FamilyError("Посылка устарела (ей больше недели) — попроси прислать заново.")
        ent["seq_in"] = seq
        if direction == TO_HELPER:
            return self._fam_report(ent, payload)
        ops = check_ops(payload.get("ops"))
        ent["pending"] = {"ops": ops, "at": int(payload.get("at", 0)), "seq": seq}
        ent["reply"] = ""
        self.save()
        self.log(f"Семья: {ent['name']} прислал(а) настройки — изменений: {len(ops)}.")
        auto = ent.get("mode") == "auto"
        if auto:
            self.run_task(f"Семья: применяю настройки от «{ent['name']}»", self.family_apply, pair)
        self.notify("family")
        return {"kind": "packet", "pair": pair, "from": ent["name"], "summary": [i18n.tr(x) for x in summary(ops)], "auto": auto}

    def family_accept(self, text: str, mode: str = "ask") -> dict:
        """Устройство: «Разрешить» — помощник из приглашения может присылать настройки."""
        inv = parse_invite(text)
        if not inv:
            raise FamilyError("Здесь нет приглашения «Семьи».")
        f = self._fam()
        pair = pair_id(inv["secret"])
        f["helpers"] = [h for h in f["helpers"] if h.get("pair") != pair]
        ent = {"pair": pair, "name": inv["helper"], "secret": b64u(inv["secret"]), "mode": "auto" if mode == "auto" else "ask",
               "since": int(time.time()), "seq_in": 0, "seq_out": 0, "pending": None, "reply": "", "device": inv["device"]}
        f["helpers"].append(ent)
        self.save()
        self.log(f"Семья: «{inv['helper']}» теперь может настраивать VPN на этом устройстве.")
        ent["reply"] = self._fam_reply(ent, [{"op": "hello", "ok": True}])
        self.save()
        self.notify("family")
        return {"pair": pair, "reply": ent["reply"]}

    def family_set_mode(self, pair: str, mode: str) -> None:
        role, ent = self._fam_find(pair)
        if role != "helpers":
            raise FamilyError("Помощник не найден.")
        ent["mode"] = "auto" if mode == "auto" else "ask"
        self.save()
        self.notify("family")

    def family_remove(self, pair: str) -> None:
        f = self._fam()
        role, ent = self._fam_find(pair)
        if not ent:
            return
        f[role] = [x for x in f[role] if x.get("pair") != pair]
        self.save()
        self.log(f"Семья: «{ent['name']}» убран(а) из семьи." if role == "devices"
                 else f"Семья: «{ent['name']}» больше не может настраивать VPN на этом устройстве.")
        self.notify("family")

    def family_send(self, pair: str, ops) -> str:
        """Помощник: посылка с изменениями для устройства (текст — в мессенджер)."""
        role, ent = self._fam_find(pair)
        if role != "devices":
            raise FamilyError("Устройство не найдено.")
        ops = check_ops(ops)
        ent["seq_out"] = int(ent.get("seq_out", 0)) + 1
        now = int(time.time())
        text = seal(unb64u(ent["secret"]), TO_DEVICE, ent["seq_out"],
                    {"t": "cmd", "at": now, "exp": now + TTL, "from": self._fam()["me"], "ops": ops})
        sent = ent.setdefault("sent", [])
        sent.append({"seq": ent["seq_out"], "at": now, "summary": summary(ops), "state": "sent"})
        del sent[:-20]
        self.save()
        self.log(f"Семья: посылка для «{ent['name']}» готова — изменений: {len(ops)}.")
        self.notify("family")
        return text

    def family_decline(self, pair: str) -> str:
        role, ent = self._fam_find(pair)
        if role != "helpers" or not ent.get("pending"):
            raise FamilyError("Нечего отклонять.")
        ent["pending"] = None
        ent["reply"] = self._fam_reply(ent, [{"op": "declined", "ok": False}], declined=True)
        self.save()
        self.notify("family")
        return ent["reply"]

    def family_report_text(self, pair: str) -> str:
        """Устройство: «Отправить состояние помощнику»."""
        role, ent = self._fam_find(pair)
        if role != "helpers":
            raise FamilyError("Помощник не найден.")
        ent["reply"] = self._fam_reply(ent, [])
        self.save()
        return ent["reply"]

    def family_apply(self, pair: str) -> None:
        """Устройство: применить посылку (из задачи). Потом — ответ помощнику со снимком и итогом."""
        role, ent = self._fam_find(pair)
        if role != "helpers" or not ent.get("pending"):
            raise FamilyError("Нечего устанавливать.")
        pending = ent["pending"]
        ent["pending"] = None
        self._lane.why = f"настройки от «{ent['name']}» (Семья)"
        was_on = bool(self.connected or self.awg_active)
        results, reconnect = [], False
        for op in pending["ops"]:
            self.check_stop()
            try:
                reconnect |= bool(self._fam_apply_op(op))
                results.append({"op": op["op"], "ok": True})
            except Exception as exc:  # одно не вышло — остальное всё равно применяем
                results.append({"op": op["op"], "ok": False, "error": str(exc)[:200]})
                self.log(f"Семья: «{OP_NAMES[op['op']]}» не получилось: {exc}")
        ok = sum(1 for r in results if r["ok"])
        self.log(f"Семья: применено {ok} из {len(results)} изменений от «{ent['name']}».")
        if reconnect and was_on and not (self.connected or self.awg_active):
            srv = self.toggle_target()
            if srv:
                self.run_task("Семья: подключаю VPN заново", self.connect_start, srv, lane="conn")
        elif reconnect and self.connected:
            self.run_task("Семья: применяю настройки", self.reconnect, True, lane="conn")
        ent["applied_seq"] = pending.get("seq", 0)
        ent["reply"] = self._fam_reply(ent, results)
        self.save()
        self.notify("family")
        self.notify("info", text=f"Настройки от «{ent['name']}» установлены: {ok} из {len(results)}.")

    def _fam_apply_op(self, op: dict) -> bool:
        """Одно изменение. True — нужно переподключить VPN."""
        kind = op["op"]
        if kind == "sub_add":
            self.add_subscription(op["url"], op.get("name", ""))
            return True
        if kind == "sub_remove":
            meta = next((m for m in self.settings["subscriptions"]
                         if m["id"] == op.get("id") or (op.get("url") and m["url"] == op.get("url"))), None)
            if not meta:
                raise FamilyError("подписки уже нет")
            self.remove_subscription(meta["id"])
            return True
        if kind == "sub_update":
            if self.settings["subscriptions"]:
                self.update_subscription(None)
            return True
        if kind == "servers_add":
            self.add_servers(op["text"])
            return True
        if kind == "server_remove":
            srv = next((x for x in self.servers if x.sub_id == "manual" and server_id(x.link) == op.get("id")), None)
            if not srv:
                raise FamilyError("сервера уже нет")
            self.remove_server(srv.key)
            return True
        if kind == "method":
            m = op["method"]
            if m == "off":
                self.set_method("off")
                if self.dpi_supported or self.connected or self.awg_active:
                    self.method_off()
                return False
            if m == "awg" and not self.awg_servers():
                raise FamilyError("нет конфига AmneziaWG")
            self.set_method(m)
            return True
        if kind == "set":
            again = False
            for k, v in op["values"].items():
                if k == "block_ads":
                    download, _ = self.set_ads(enabled=v)
                    if download:
                        self.update_adblock()
                    again = True
                elif k == "dns_encrypted":
                    if bool(self.settings.get("dns_encrypted")) != v:
                        self.settings["dns_encrypted"] = v
                        again = True
                elif k == "accel" and self.dpi_supported:
                    (self.accel_on if v else self.accel_off)()
            self.save()
            return again
        if kind == "reconnect":
            return True
        if kind == "warp_create":
            self.create_warp()
            return False
        return False  # report — ответ и так придёт со снимком

    def _fam_snapshot(self) -> dict:
        s = self.settings
        manual = [x for x in self.servers if x.sub_id == "manual"]
        subs = []
        for m in s["subscriptions"]:
            subs.append({"id": m["id"], "name": self.sub_name(m), "url": m["url"],
                         "n": sum(1 for x in self.servers if x.sub_id == m["id"]), "err": m["id"] in self.sub_errors})
        status = "awg" if self.awg_active else "on" if self.connected else "off"
        cur = self.awg_active or (self.current if self.connected else None)
        accel = bool(self.dpi_supported and (s.get("zapret_enabled") or s.get("byedpi_role") not in (None, "", "off")))
        return {"app": "pc", "ver": APP_VERSION, "status": status, "server": cur.name if cur else "",
                "method": self.method(), "subs": subs,
                "manual": [{"id": server_id(x.link), "name": x.name, "kind": "awg" if x.engine == "awg" else "server"}
                           for x in manual][:60],
                "set": {"block_ads": bool(s.get("block_ads")), "dns_encrypted": bool(s.get("dns_encrypted")),
                        "accel": accel},
                "accel_ok": bool(self.dpi_supported),
                "problems": [p["title"] for p in self.problems_list()][:6]}

    def _fam_reply(self, ent: dict, results: list, declined: bool = False) -> str:
        ent["seq_out"] = int(ent.get("seq_out", 0)) + 1
        now = int(time.time())
        payload = {"t": "report", "at": now, "exp": now + TTL, "snap": self._fam_snapshot(), "results": results,
                   "applied": int(ent.get("applied_seq", 0)), "declined": declined, "device": ent.get("device", "")}
        return seal(unb64u(ent["secret"]), TO_HELPER, ent["seq_out"], payload)

    def _fam_report(self, ent: dict, payload: dict) -> dict:
        snap = payload.get("snap") if isinstance(payload.get("snap"), dict) else None
        if snap:
            ent["snap"] = snap
            ent["snap_at"] = int(payload.get("at", time.time()))
            ent["invite"] = ""  # устройство подключилось — приглашение больше не нужно
        results = payload.get("results") if isinstance(payload.get("results"), list) else []
        sent = ent.get("sent", [])
        if sent and results and not any(r.get("op") == "hello" for r in results if isinstance(r, dict)):
            last = sent[-1]
            if payload.get("declined"):
                last["state"] = "declined"
            else:
                bad = [r for r in results if isinstance(r, dict) and not r.get("ok")]
                last["state"] = "failed" if bad and len(bad) == len(results) else "partial" if bad else "applied"
                last["errors"] = [str(r.get("error", ""))[:200] for r in bad][:5]
        self.save()
        self.log(f"Семья: пришло состояние «{ent['name']}».")
        self.notify("family")
        return {"kind": "report", "pair": ent["pair"], "name": ent["name"]}
