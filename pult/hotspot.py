"""Раздача VPN по Wi-Fi через «Мобильный хот-спот» Windows.

Компьютер создаёт свою сеть Wi-Fi. Если включён режим TUN, раздача идёт с виртуального адаптера программы,
и всё, что подключилось к этой сети, сразу идёт через VPN — на устройствах ничего настраивать не нужно.
Управление — через встроенный в Windows PowerShell 5.1 и WinRT (NetworkOperatorTetheringManager).
Имя сети и пароль передаются через переменные окружения, а не в тексте команды.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

IS_WINDOWS = sys.platform == "win32"
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

SCRIPT = r"""
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$ext = [System.WindowsRuntimeSystemExtensions].GetMethods()
$asTaskOp = ($ext | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
$asTaskAct = ($ext | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncAction' })[0]
function Await($op, $type) { $t = $asTaskOp.MakeGenericMethod($type).Invoke($null, @($op)); $t.Wait(-1) | Out-Null; $t.Result }
function AwaitAction($op) { $t = $asTaskAct.Invoke($null, @($op)); $t.Wait(-1) | Out-Null }
[Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime] | Out-Null
[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime] | Out-Null
$resultType = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]
$profile = $null
$viaTun = $false
if ($env:PULT_PREFER) {
  $guid = $null
  try { $guid = (Get-NetAdapter -Name $env:PULT_PREFER -ErrorAction Stop).InterfaceGuid } catch { }
  foreach ($p in [Windows.Networking.Connectivity.NetworkInformation]::GetConnectionProfiles()) {
    $id = ''
    try { $id = $p.NetworkAdapter.NetworkAdapterId.ToString('B') } catch { }
    if (($guid -and $id -and ($id -ieq $guid)) -or $p.ProfileName -eq $env:PULT_PREFER) { $profile = $p; $viaTun = $true }
  }
}
if (-not $profile) { $profile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile() }
if (-not $profile) { throw 'NO_INTERNET' }
$tm = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($profile)
$out = @{ status = 'Success'; message = '' }
if ($env:PULT_CMD -eq 'start') {
  $cfg = $tm.GetCurrentAccessPointConfiguration()
  $cfg.Ssid = $env:PULT_SSID
  $cfg.Passphrase = $env:PULT_PASS
  AwaitAction ($tm.ConfigureAccessPointAsync($cfg))
  if ([string]$tm.TetheringOperationalState -eq 'On') { Await ($tm.StopTetheringAsync()) $resultType | Out-Null }
  $r = Await ($tm.StartTetheringAsync()) $resultType
  $out.status = [string]$r.Status; $out.message = [string]$r.AdditionalErrorMessage
} elseif ($env:PULT_CMD -eq 'stop') {
  $r = Await ($tm.StopTetheringAsync()) $resultType
  $out.status = [string]$r.Status; $out.message = [string]$r.AdditionalErrorMessage
}
$out.state = [string]$tm.TetheringOperationalState
$out.clients = [int]$tm.ClientCount
$out.tun = $viaTun
$out | ConvertTo-Json -Compress
"""

STATUS_TEXT = {
    "WiFiDeviceOff": "Wi-Fi на компьютере выключен — включи его",
    "OperationInProgress": "Windows уже включает или выключает раздачу — попробуй через минуту",
    "EntitlementCheckFailure": "оператор или Windows не разрешили раздачу",
    "MobileBroadbandDeviceOff": "мобильный модем выключен",
    "NetworkLimitedConnectivity": "у компьютера нет полноценного интернета",
    "BluetoothDeviceOff": "Bluetooth выключен",
}


class HotspotError(RuntimeError):
    pass


def run(cmd: str, ssid: str = "", password: str = "", prefer: str = "") -> dict:
    """cmd: start / stop / status. Возвращает {on, clients, via_tun}."""
    if not IS_WINDOWS:
        raise HotspotError("Раздача по Wi-Fi работает только в Windows.")
    env = dict(os.environ, PULT_CMD=cmd, PULT_SSID=ssid, PULT_PASS=password, PULT_PREFER=prefer)
    try:
        proc = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                               "-Command", SCRIPT], env=env, capture_output=True, text=True, timeout=90,
                              encoding="utf-8", errors="replace", creationflags=NO_WINDOW)
    except (OSError, subprocess.SubprocessError) as exc:
        raise HotspotError(f"не удалось запустить PowerShell: {exc}") from exc
    lines = [ln for ln in (proc.stdout or "").splitlines() if ln.strip().startswith("{")]
    if not lines:
        err = (proc.stderr or "").strip()
        if "NO_INTERNET" in err:
            raise HotspotError("у компьютера сейчас нет интернета — раздавать нечего")
        if "Wi-Fi" in err or "WiFi" in err or "0x8007" in err or "not supported" in err.lower():
            raise HotspotError("на этом компьютере нет подходящего адаптера Wi-Fi или раздача не поддерживается")
        tail = err.splitlines()[-1][:200] if err else "без подробностей"
        raise HotspotError(f"Windows не включила раздачу: {tail}")
    data = json.loads(lines[-1])
    status = str(data.get("status") or "")
    if status and status != "Success":
        raise HotspotError(STATUS_TEXT.get(status, f"Windows не включила раздачу ({status})"))
    return {"on": data.get("state") == "On", "clients": int(data.get("clients") or 0), "via_tun": bool(data.get("tun"))}


def wifi_qr_text(ssid: str, password: str) -> str:
    """Текст QR-кода для подключения к Wi-Fi: камера телефона предложит подключиться сама."""
    esc = lambda v: "".join("\\" + c if c in '\\;,:"' else c for c in v)  # noqa: E731
    return f"WIFI:T:WPA;S:{esc(ssid)};P:{esc(password)};;"
