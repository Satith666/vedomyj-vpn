"""Проверка серверов: отклик, пинг, разброс, скорость."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import netutil, singbox
from .links import Server
from .xray import Paths, XrayError, XrayProcess, build_test_config, check_config, fingerprint_of

SPEED_URLS = [
    "https://speed.cloudflare.com/__down?bytes=60000000",
    "http://cachefly.cachefly.net/100mb.test",
    "https://proof.ovh.net/files/100Mb.dat",
]
# «идут ли данные»: небольшой файл (берутся первые 64 КБ) — не пинг, а настоящая загрузка через сервер
DATA_URLS = [
    "https://speed.cloudflare.com/__down?bytes=262144",
    "http://cachefly.cachefly.net/1mb.test",
    "https://proof.ovh.net/files/1Mb.dat",
]
DATA_TIMEOUT = 8.0
# какие отпечатки TLS пробовать, если сервер не отвечает (Chrome в мае 2026 блокировали отдельно)
FP_RETRY = ("firefox", "safari")
CHUNK = 40
RESERVED_PORTS = {10808, 10809}


CORE_VERSIONS: dict[str, str] = {}
SINGBOX_EXE = ""  # путь к sing-box: TUIC и AnyTLS проверяются через временный мост (выставляет движок)


def _is_bridge(exe: str | None) -> bool:
    return bool(SINGBOX_EXE) and exe == SINGBOX_EXE


def _config_for(exe: str | None, servers: list[Server], ports: list[int], mask, version: str) -> dict:
    """Временное ядро для проверки: Xray с входом на каждый сервер или мост sing-box (TUIC, AnyTLS)."""
    if _is_bridge(exe):
        return singbox.bridge_config(list(zip(ports, [s.sb_outbound for s in servers])))
    return build_test_config(servers, ports, mask, version)  # путь к ядру → версия (от неё зависит, как включать маскировку)


def score(r: dict) -> float | None:
    """Чем меньше, тем лучше. Учитывает пинг, отклик, разброс и скорость (если замеряли)."""
    if not r or not r.get("ok") or r.get("ping_ms") is None:
        return None
    s = float(r["ping_ms"]) + 0.25 * float(r.get("delay_ms") or 0) + 0.5 * float(r.get("jitter_ms") or 0)
    speed = r.get("speed_mbps")
    if speed:
        s -= min(float(speed), 300.0) * 0.4
    elif r.get("speed_ok") is False:
        s += 1000
    return s


def game_score(r: dict) -> float | None:
    if not r or not r.get("ok") or r.get("ping_ms") is None:
        return None
    return float(r["ping_ms"]) + float(r.get("jitter_ms") or 0)


INSECURE_PENALTY = 40.0  # мс: сервер без шифрования выбираем, только если он заметно лучше


def ranked(servers: list[Server], key=score) -> list[Server]:
    good = [s for s in servers if s.supported and key(s.result) is not None]
    return sorted(good, key=lambda s: key(s.result) + (INSECURE_PENALTY if s.insecure else 0.0))


def _valid_subset(paths: Paths, chunk: list[Server], ports: list[int], on_result, log,
                  exe: str | None = None, mask: bool | int | None = False) -> list[Server]:
    if _is_bridge(exe):
        return chunk  # настройки моста проверит сам sing-box при запуске
    ver = CORE_VERSIONS.get(exe or "", "")
    ok, msg = check_config(paths, build_test_config(chunk, ports, mask, ver), paths.test_config, exe=exe)
    if ok:
        return chunk
    if len(chunk) > 1:
        log(f"Настройки одного из серверов не приняты ядром ({msg}). Проверяю серверы по одному.")
    good = []
    for srv in chunk:
        ok1, msg1 = check_config(paths, build_test_config([srv], ports[:1], mask, ver), paths.test_config, exe=exe)
        if ok1:
            good.append(srv)
        else:
            srv.result = {"ok": False, "status": "ошибка настроек", "error": msg1, "tested_at": time.time()}
            on_result(srv)
    return good


def _groups(paths: Paths, servers: list[Server], ensure_core) -> list[tuple[str, list[Server]]]:
    """Делит серверы по ядру: обычное, совместимое (для серверов без шифрования) и мост sing-box.
    AmneziaWG здесь не проверяется: он запускается своим клиентом."""
    xr = [s for s in servers if getattr(s, "engine", "xray") == "xray"]
    normal = [s for s in xr if not s.insecure]
    legacy = [s for s in xr if s.insecure]
    bridge = [s for s in servers if getattr(s, "engine", "xray") == "singbox"]
    groups = []
    if normal:
        groups.append((paths.xray, normal))
    if legacy:
        if ensure_core:
            ensure_core()
        groups.append((paths.legacy_xray, legacy))
    if bridge:
        if SINGBOX_EXE:
            groups.append((SINGBOX_EXE, bridge))
    return groups


def fp_capable(srv: Server) -> bool:
    """Можно ли менять отпечаток TLS: у сервера есть TLS или Reality."""
    return fingerprint_of(srv.outbound or {}) is not None


def fp_of(srv: Server) -> str:
    """Отпечаток, с которым сервер подключается сейчас: подобранный программой или из ссылки (по умолчанию chrome)."""
    return (srv.result or {}).get("fp") or fingerprint_of(srv.outbound or {}) or "chrome"


def test_servers(paths: Paths, servers: list[Server], ping_host: str, ping_path: str, on_result,
                 stop_event=None, log=print, ensure_core=None, mask_retry: bool = False, fp_retry: bool = False) -> int:
    """Пинг всех серверов. Возвращает количество рабочих.
    mask_retry — не ответившие серверы проверяются ещё раз с маскировкой; кому помогло, запоминается.
    fp_retry — потом ещё раз с другими отпечатками TLS (FP_RETRY); помогший запоминается в result["fp"]."""
    for srv in servers:
        if not srv.supported:
            status = "сообщение провайдера" if srv.stub else "не поддерживается"
            srv.result = {"ok": False, "status": status, "error": srv.note, "tested_at": time.time()}
            on_result(srv)
    working = 0
    for exe, candidates in _groups(paths, [s for s in servers if s.supported], ensure_core):
        working += _test_group(paths, exe, candidates, ping_host, ping_path, on_result, stop_event, log)
    if mask_retry and not (stop_event and stop_event.is_set()):
        failed = [s for s in servers if s.supported and getattr(s, "engine", "xray") == "xray"
                  and (s.result or {}).get("status") == "не отвечает"]
        for variant in (1, 2):  # первый способ не помог — пробуем второй
            if not failed or (stop_event and stop_event.is_set()):
                break
            for exe, candidates in _groups(paths, failed, ensure_core):
                helped = _test_group(paths, exe, candidates, ping_host, ping_path, on_result, stop_event, log,
                                     mask=True if variant == 1 else variant)
                if helped:
                    log(f"Маскировка помогла {helped} серверам — они снова работают.")
                working += helped
            failed = [s for s in failed if (s.result or {}).get("status") == "не отвечает"]
    if fp_retry and not (stop_event and stop_event.is_set()):
        failed = [s for s in servers if s.supported and fp_capable(s)
                  and (s.result or {}).get("status") == "не отвечает"]
        helped_total = 0
        for fp in FP_RETRY:
            todo = [s for s in failed if fp_of(s) != fp]
            if not todo or (stop_event and stop_event.is_set()):
                break
            for exe, candidates in _groups(paths, todo, ensure_core):
                helped = _test_group(paths, exe, candidates, ping_host, ping_path, on_result, stop_event, log, fp=fp)
                helped_total += helped
                working += helped
            failed = [s for s in failed if (s.result or {}).get("status") == "не отвечает"]
        if helped_total:
            log(f"Другой отпечаток TLS помог {helped_total} серверам — они снова работают.")
    return working


def _test_group(paths: Paths, exe: str, candidates: list[Server], ping_host: str, ping_path: str, on_result,
                stop_event, log, mask: bool = False, fp: str | None = None) -> int:
    """fp — проверить с этим отпечатком TLS (None — с тем, что запомнен у сервера)."""
    working = 0
    for start in range(0, len(candidates), CHUNK):
        if stop_event and stop_event.is_set():
            break
        chunk = candidates[start:start + CHUNK]
        original = {id(s): s.result for s in chunk}
        kept_fp = {id(s): (s.result or {}).get("fp", "") for s in chunk}
        if fp is not None:
            for s in chunk:
                s.result = dict(s.result or {}, fp=fp)
        ports = netutil.find_free_ports(len(chunk), avoid=RESERVED_PORTS)
        chunk = _valid_subset(paths, chunk, ports, on_result, log, exe=exe, mask=mask)
        if not chunk:
            continue
        ports = ports[:len(chunk)]
        proc = XrayProcess(paths)
        try:
            proc.start(_config_for(exe, chunk, ports, mask, CORE_VERSIONS.get(exe, "")), paths.test_config,
                       wait_for=ports, exe=exe)
        except XrayError as exc:
            for srv in chunk:
                srv.result = {"ok": False, "status": "ошибка ядра", "error": str(exc), "tested_at": time.time()}
                on_result(srv)
            continue
        previous = {id(s): s.result for s in chunk}
        for srv in chunk:
            srv.result = dict(srv.result or {}, status="проверяю…", testing=True)
            on_result(srv)
        cancelled = False
        try:
            pool = ThreadPoolExecutor(max_workers=12)
            futures = {pool.submit(_ping_with_retry, ping_host, ping_path, port, stop_event): srv
                       for srv, port in zip(chunk, ports)}
            pending = set(futures)
            try:
                for fut in as_completed(futures):
                    pending.discard(fut)
                    if stop_event and stop_event.is_set():
                        cancelled = True
                        break
                    srv = futures[fut]
                    r = fut.result()
                    old_speed = (previous.get(id(srv)) or {}).get("speed_mbps")
                    srv.result = {
                        "ok": r["ok"],
                        "delay_ms": r["delay_ms"],
                        "ping_ms": r["ping_ms"],
                        "jitter_ms": r["jitter_ms"],
                        "status": "работает" if r["ok"] else "не отвечает",
                        "error": r["error"],
                        "tested_at": time.time(),
                    }
                    if r["ok"] and old_speed:
                        srv.result["speed_mbps"] = old_speed
                    if r["ok"] and mask:
                        srv.result["mask"] = True if mask is True else mask  # какой вариант помог
                    use_fp = fp if (fp is not None and r["ok"]) else kept_fp.get(id(srv), "")
                    if use_fp:
                        srv.result["fp"] = use_fp  # подобранный отпечаток остаётся за сервером
                    if r["ok"]:
                        working += 1
                    on_result(srv)
            finally:
                if cancelled:
                    proc.stop()  # оставшиеся замеры сразу оборвутся
                pool.shutdown(wait=True, cancel_futures=True)
        finally:
            proc.stop()
        if cancelled:
            # незавершённые серверы возвращаем к прошлому результату
            for fut in pending | {f for f in futures if futures[f].result.get("testing")}:
                srv = futures[fut]
                if srv.result.get("testing"):
                    srv.result = original.get(id(srv)) or {}
                    on_result(srv)
            break
    return working


def _ping_with_retry(host: str, path: str, port: int, stop_event=None) -> dict:
    r = netutil.http_ping(host, path, proxy_port=port, rounds=5, timeout=7)
    if not r["ok"] and not (stop_event and stop_event.is_set()):
        time.sleep(0.5)
        r = netutil.http_ping(host, path, proxy_port=port, rounds=5, timeout=9)
    return r


def speed_test_servers(paths: Paths, servers: list[Server], on_result, seconds: float = 7.0,
                       stop_event=None, log=print, ensure_core=None) -> None:
    for exe, group in _groups(paths, servers, ensure_core):
        _speed_group(paths, exe, group, on_result, seconds, stop_event, log)


def _speed_group(paths: Paths, exe: str, servers: list[Server], on_result, seconds: float, stop_event, log) -> None:
    if not servers:
        return
    ports = netutil.find_free_ports(len(servers), avoid=RESERVED_PORTS)
    servers = _valid_subset(paths, servers, ports, on_result, log, exe=exe, mask=None)
    if not servers:
        return
    ports = ports[:len(servers)]
    proc = XrayProcess(paths)
    proc.start(_config_for(exe, servers, ports, None, CORE_VERSIONS.get(exe, "")), paths.test_config,
               wait_for=ports, exe=exe)
    try:
        for srv, port in zip(servers, ports):
            if stop_event and stop_event.is_set():
                break
            before = dict(srv.result or {})
            srv.result = dict(before, status="замер скорости…", testing=True)
            on_result(srv)
            r = netutil.speed_test(port, SPEED_URLS, seconds=seconds, stop_event=stop_event)
            if stop_event and stop_event.is_set():
                srv.result = before
                on_result(srv)
                break
            srv.result = dict(before)
            srv.result["speed_mbps"] = r["mbps"]
            srv.result["speed_ok"] = r["ok"]
            srv.result["status"] = "работает" if srv.result.get("ok") or r["ok"] else "не отвечает"
            if not r["ok"]:
                srv.result["status"] = "медленно/обрыв"
                srv.result["error"] = r["error"]
            on_result(srv)
    finally:
        proc.stop()


def probe_data(paths: Paths, servers: list[Server], stop_event=None, exe: str | None = None,
               mask: bool | int | None = None) -> list[dict]:
    """Идут ли данные через каждый сервер (по data_check, а не пингу) — одним временным ядром, параллельно.
    Серверы берутся с их способом подключения (result["fp"], а при mask=None — и result["mask"]).
    → [{"ok", "bytes", "ms", "error"}] в том же порядке."""
    if not servers:
        return []
    ports = netutil.find_free_ports(len(servers), avoid=RESERVED_PORTS)
    proc = XrayProcess(paths)
    try:
        proc.start(_config_for(exe, servers, ports, mask, CORE_VERSIONS.get(exe or "", "")), paths.test_config,
                   wait_for=ports, exe=exe)
    except XrayError as exc:
        return [{"ok": False, "bytes": 0, "ms": None, "error": str(exc)} for _ in servers]
    try:
        with ThreadPoolExecutor(max_workers=min(8, len(servers))) as pool:
            return list(pool.map(lambda port: netutil.data_check(port, DATA_URLS, timeout=DATA_TIMEOUT,
                                                                 stop_event=stop_event), ports))
    finally:
        proc.stop()
