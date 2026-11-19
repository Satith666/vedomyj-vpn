# VEDOMYJ VPN — сборка установочных файлов на этом компьютере: Windows (.exe), Android (.apk) или всё сразу.
# Запуск: двойной щелчок по «Собрать.bat». Готовые файлы — в папке dist.
param([ValidateSet('ask', 'windows', 'android', 'all')][string]$What = 'ask')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'dist'
New-Item -ItemType Directory -Force -Path $dist | Out-Null

if ($What -eq 'ask') {
    Write-Host 'VEDOMYJ VPN — что собрать?' -ForegroundColor Cyan
    Write-Host '  1 — Windows: установщик .exe и портативная версия (1–2 минуты)'
    Write-Host '  2 — Android: APK для телефона (первый раз 10–20 минут, потом 2–5)'
    Write-Host '  3 — всё сразу'
    $answer = Read-Host 'Напиши 1, 2 или 3 и нажми Enter'
    $What = switch ($answer.Trim()) { '1' { 'windows' } '2' { 'android' } default { 'all' } }
}

$failed = @()
$jobs = @()
if ($What -in @('windows', 'all')) { $jobs += @{ Name = 'Windows'; Script = 'build.ps1'; Log = 'windows-build-log.txt' } }
if ($What -in @('android', 'all')) { $jobs += @{ Name = 'Android'; Script = 'build-android.ps1'; Log = 'android-build-log.txt' } }
foreach ($job in $jobs) {
    Write-Host ''
    $log = Join-Path $dist $job.Log
    try { Start-Transcript -Path $log -Force | Out-Null } catch { }
    try {
        & (Join-Path $PSScriptRoot $job.Script)
    } catch {
        Write-Host ''
        Write-Host "$($job.Name): $($_.Exception.Message)" -ForegroundColor Red
        $failed += $job
    } finally {
        try { Stop-Transcript | Out-Null } catch { }
    }
}

Write-Host ''
if ($failed) {
    foreach ($job in $failed) {
        Write-Host "Не собралось: $($job.Name). Пришли мне файл dist\$($job.Log) — разберусь." -ForegroundColor Red
    }
} else {
    Write-Host 'Всё собрано. Открываю папку dist.' -ForegroundColor Green
    Start-Process explorer.exe $dist
}
