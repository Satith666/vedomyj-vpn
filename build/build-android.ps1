# VEDOMYJ VPN — сборка APK для Android на этом компьютере (то же, что делает GitHub).
# Запуск: «Собрать.bat» → пункт «Android». Ничего не устанавливает в систему: Java, Android SDK и Gradle
# скачиваются в отдельную папку (%LOCALAPPDATA%\VedomyjVPN-build) и потом используются повторно.
# Первая сборка скачивает около 1,5 ГБ и идёт 10–20 минут, следующие — 2–5 минут.
# Если запущен VEDOMYJ VPN, всё скачивается через него (так надёжнее доходят GitHub и Google).
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression.FileSystem

$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'dist'
New-Item -ItemType Directory -Force -Path $dist | Out-Null

function Step($text) { Write-Host "  - $text" }
function IsAscii($text) { return -not ($text -match '[^\x20-\x7E]') }

# Инструменты Android плохо работают с русскими буквами и пробелами в пути — тогда берём C:\VedomyjVPN-build
$tools = Join-Path $env:LOCALAPPDATA 'VedomyjVPN-build'
if (-not (IsAscii $tools) -or $tools.Contains(' ')) { $tools = Join-Path $env:SystemDrive 'VedomyjVPN-build' }
$jdk = Join-Path $tools 'jdk'
$sdk = Join-Path $tools 'sdk'
$work = Join-Path $tools 'work\android'
$keys = Join-Path $tools 'keystore'
$downloads = Join-Path $tools 'downloads'
$tmp = Join-Path $tools 'tmp'
New-Item -ItemType Directory -Force -Path $tools, $downloads, $tmp, $keys | Out-Null

$ver = (Select-String -Path (Join-Path $root 'android\app\build.gradle') -Pattern "versionName '([^']+)'").Matches[0].Groups[1].Value
Write-Host "VEDOMYJ VPN для Android $ver — сборка APK" -ForegroundColor Cyan
Write-Host "  Папка инструментов: $tools"

# ---------- прокси: если работает VEDOMYJ VPN, качаем через него ----------
function Test-Port($port) {
    try {
        $c = New-Object Net.Sockets.TcpClient
        $ok = $c.ConnectAsync('127.0.0.1', [int]$port).Wait(700) -and $c.Connected
        $c.Close()
        return $ok
    } catch { return $false }
}
$proxyPort = $null
$candidates = @()
foreach ($f in @((Join-Path $root 'data\settings.json'), (Join-Path $env:LOCALAPPDATA 'Programs\VedomyjVPN\data\settings.json'))) {
    if (Test-Path $f) {
        try { $candidates += [int]((Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json).http_port) } catch { }
    }
}
try {
    $ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    if ($ie.ProxyEnable -eq 1 -and $ie.ProxyServer -match '127\.0\.0\.1:(\d+)') { $candidates += [int]$Matches[1] }
} catch { }
foreach ($p in ($candidates | Select-Object -Unique)) {
    if ($p -and (Test-Port $p)) { $proxyPort = $p; break }
}
if ($proxyPort) {
    Step "Качаю через VEDOMYJ VPN (порт $proxyPort)"
    $proxyUrl = "http://127.0.0.1:$proxyPort"
    # Java (Gradle, sdkmanager, скачивание ядра) тоже пойдёт через программу
    $env:JAVA_TOOL_OPTIONS = "-Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=$proxyPort -Dhttp.proxyHost=127.0.0.1 " +
        "-Dhttp.proxyPort=$proxyPort -Dhttp.nonProxyHosts=localhost|127.*"
} else {
    Step 'VEDOMYJ VPN не запущен — качаю напрямую'
    $proxyUrl = $null
}

function Get-File($urls, $dest, $minBytes) {
    foreach ($u in $urls) {
        try {
            Write-Host "    $u"
            $req = @{ UseBasicParsing = $true; Uri = $u; OutFile = "$dest.part" }
            if ($proxyUrl) { $req.Proxy = $proxyUrl }
            Invoke-WebRequest @req
            if ((Get-Item "$dest.part").Length -lt $minBytes) { throw 'слишком маленький файл' }
            Move-Item "$dest.part" $dest -Force
            return
        } catch {
            Write-Host "    не получилось: $($_.Exception.Message)" -ForegroundColor DarkYellow
            Remove-Item "$dest.part" -Force -ErrorAction SilentlyContinue
        }
    }
    throw "Не удалось скачать $([IO.Path]::GetFileName($dest)). Проверь интернет или включи VEDOMYJ VPN и запусти сборку ещё раз."
}

function Expand-Into($zip, $target) {
    # распаковать архив, у которого внутри одна папка, прямо в $target
    $tmpDir = Join-Path $tmp ([IO.Path]::GetRandomFileName())
    [IO.Compression.ZipFile]::ExtractToDirectory($zip, $tmpDir)
    $inner = Get-ChildItem $tmpDir
    $from = if ($inner.Count -eq 1 -and $inner[0].PSIsContainer) { $inner[0].FullName } else { $tmpDir }
    Remove-Item $target -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
    Move-Item $from $target
    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
}

# .bat-файлы (sdkmanager, gradlew) запускаем через cmd: он сам объединяет вывод и ошибки, а Windows PowerShell
# не превращает обычные сообщения Java в красные «ошибки». Полоски загрузки в журнал не пишем.
function Invoke-Cmd([string]$line, [switch]$Quiet, [switch]$Yes) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    # -Yes: на любые вопросы «принять лицензию? (y/N)» отвечаем «y», чтобы сборка не зависла в ожидании
    $answers = if ($Yes) { 1..40 | ForEach-Object { 'y' } } else { @() }
    try {
        $answers | cmd /c "call $line 2>&1" | ForEach-Object {
            if (-not $Quiet -and $_ -notmatch 'ETA:|^\s*$|UseAllWindowsProcessorGroups|Picked up JAVA_TOOL_OPTIONS') { $_ }
        } | Out-Host
    } finally { $ErrorActionPreference = $old }
}

$arm = $env:PROCESSOR_ARCHITECTURE -eq 'ARM64'

# ---------- Java 17 ----------
if (-not (Test-Path (Join-Path $jdk 'bin\java.exe'))) {
    Step 'Скачиваю Java 17 (около 190 МБ)'
    $zip = Join-Path $downloads 'jdk17.zip'
    if (-not (Test-Path $zip)) {
        $a = if ($arm) { 'aarch64' } else { 'x64' }
        Get-File @("https://api.adoptium.net/v3/binary/latest/17/ga/windows/$a/jdk/hotspot/normal/eclipse?project=jdk",
                   "https://aka.ms/download-jdk/microsoft-jdk-17-windows-$a.zip") $zip 50MB
    }
    Expand-Into $zip $jdk
}
$env:JAVA_HOME = $jdk
$m = Select-String -Path (Join-Path $jdk 'release') -Pattern 'JAVA_VERSION="([^"]+)"' -ErrorAction SilentlyContinue
Step ("Java: " + $(if ($m) { $m.Matches[0].Groups[1].Value } else { '?' }))

# ---------- Android SDK ----------
$sdkmanager = Join-Path $sdk 'cmdline-tools\latest\bin\sdkmanager.bat'
if (-not (Test-Path $sdkmanager)) {
    Step 'Скачиваю Android SDK (инструменты командной строки)'
    $zip = Join-Path $downloads 'cmdline-tools.zip'
    if (-not (Test-Path $zip)) {
        $builds = @()
        try {
            $xmlArgs = @{ UseBasicParsing = $true; Uri = 'https://dl.google.com/android/repository/repository2-3.xml' }
            if ($proxyUrl) { $xmlArgs.Proxy = $proxyUrl }
            $xml = (Invoke-WebRequest @xmlArgs).Content
            $builds = [regex]::Matches($xml, 'commandlinetools-win-(\d+)_latest\.zip') | ForEach-Object { [int]$_.Groups[1].Value } |
                Sort-Object -Descending -Unique
        } catch { }
        $builds = @($builds) + @(14742923, 13114758, 11076708) | Select-Object -Unique
        Get-File ($builds | ForEach-Object { "https://dl.google.com/android/repository/commandlinetools-win-${_}_latest.zip" }) $zip 50MB
    }
    Expand-Into $zip (Join-Path $sdk 'cmdline-tools\latest')
}
$env:ANDROID_HOME = $sdk
$env:ANDROID_SDK_ROOT = $sdk
# Лицензия Android SDK (https://developer.android.com/studio/terms): отмечаем её принятой — тогда недостающие
# части SDK может докачать и сам Gradle, даже если sdkmanager не справится
$licDir = Join-Path $sdk 'licenses'
New-Item -ItemType Directory -Force -Path $licDir | Out-Null
$licFile = Join-Path $licDir 'android-sdk-license'
$known = @('24333f8a63b6825ea9c5514f83c2829b004d1fee', 'd56f5187479451eabf01fb78af6dfcb131a6481e',
           '8933bad161af4178b1185d1a37fbf41ea5269c55')
$lic = @(if (Test-Path $licFile) { Get-Content $licFile | Where-Object { $_.Trim() } })
$add = @($known | Where-Object { $lic -notcontains $_ })
if ($add) { Set-Content -Path $licFile -Value (@($lic) + $add) -Encoding ASCII }

$have = (Test-Path (Join-Path $sdk 'platforms\android-35')) -and (Test-Path (Join-Path $sdk 'build-tools\35.0.0'))
if (-not $have) {
    Step 'Скачиваю платформу Android 35 и инструменты сборки (около 400 МБ)'
    # имена пакетов — в кавычках: без них cmd режет «platforms;android-35» по точке с запятой
    $sdkArgs = "--sdk_root=$sdk"
    Invoke-Cmd "`"$sdkmanager`" $sdkArgs --licenses" -Quiet -Yes
    Invoke-Cmd "`"$sdkmanager`" $sdkArgs `"platforms;android-35`" `"build-tools;35.0.0`" `"platform-tools`"" -Yes
    if (-not (Test-Path (Join-Path $sdk 'platforms\android-35'))) {
        Step 'sdkmanager не скачал платформу — её докачает Gradle во время сборки'
    }
}

# ---------- копия проекта в папке без русских букв ----------
Step 'Готовлю проект'
New-Item -ItemType Directory -Force -Path $work | Out-Null
# ключ подписи, скачанное ядро и прошлые сборки не трогаем (robocopy не удаляет исключённое)
& robocopy (Join-Path $root 'android') $work /MIR /XD keystore build .gradle libs .idea /XF local.properties /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw 'Не удалось скопировать папку android.' }
$global:LASTEXITCODE = 0
$sdkEsc = $sdk.Replace('\', '\\').Replace(':', '\:')
Set-Content -Path (Join-Path $work 'local.properties') -Value "sdk.dir=$sdkEsc" -Encoding ASCII
# один и тот же ключ подписи для всех сборок: иначе новая версия не встанет поверх старой
$workKeys = Join-Path $work 'keystore'
if ((Test-Path (Join-Path $keys 'release.jks')) -and -not (Test-Path (Join-Path $workKeys 'release.jks'))) {
    New-Item -ItemType Directory -Force -Path $workKeys | Out-Null
    Copy-Item (Join-Path $keys '*') $workKeys -Force
}

# ---------- сборка ----------
Step 'Собираю APK (первый раз Gradle скачивает ещё около 500 МБ)'
$env:GRADLE_USER_HOME = Join-Path $tools 'gradle'
$env:TEMP = $tmp
$env:TMP = $tmp
Push-Location $work
try {
    Invoke-Cmd "`"$(Join-Path $work 'gradlew.bat')`" --no-daemon assembleRelease"
    if ($LASTEXITCODE -ne 0) { throw 'Сборка APK не удалась. Пришли мне файл dist\android-build-log.txt.' }
} finally {
    Pop-Location
}

# новый ключ подписи сохраняем рядом с инструментами
if ((Test-Path (Join-Path $workKeys 'release.jks')) -and -not (Test-Path (Join-Path $keys 'release.jks'))) {
    Copy-Item (Join-Path $workKeys '*') $keys -Force
    $newKey = $true
} else { $newKey = $false }

# ---------- готовые файлы ----------
$names = [ordered]@{ 'universal' = 'universal'; 'arm64' = 'arm64'; 'armeabi' = 'arm32'; 'x86_64' = 'x86_64' }
$out = @()
foreach ($f in Get-ChildItem (Join-Path $work 'app\build\outputs\apk\release') -Filter '*.apk') {
    foreach ($k in $names.Keys) {
        if ($f.Name -like "*$k*") {
            $dest = Join-Path $dist "VedomyjVPN-$ver-$($names[$k]).apk"
            Copy-Item $f.FullName $dest -Force
            $out += $dest
            break
        }
    }
}
if (-not $out) { throw 'APK не найдены после сборки.' }

Write-Host ''
Write-Host 'Готово. В папке dist:' -ForegroundColor Green
Write-Host "  VedomyjVPN-$ver-universal.apk — подходит для любого телефона (ставь этот, если не знаешь какой)"
Write-Host "  VedomyjVPN-$ver-arm64.apk     — для большинства современных телефонов, весит меньше"
Write-Host "  VedomyjVPN-$ver-arm32.apk     — для старых телефонов"
Write-Host "  VedomyjVPN-$ver-x86_64.apk    — для эмуляторов на компьютере"
if ($newKey) {
    Write-Host ''
    Write-Host 'Создан ключ подписи приложения. Сохрани копию этой папки (например, на флешку):' -ForegroundColor Yellow
    Write-Host "  $keys"
    Write-Host '  Без неё новые версии не встанут поверх старой — придётся удалять приложение. Никому её не отправляй.' -ForegroundColor Yellow
}
