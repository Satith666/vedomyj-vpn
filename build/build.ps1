# VEDOMYJ VPN — сборка: установщик (.exe), портативная версия и версия с исходниками для нейросети.
# Запуск: двойной щелчок по «Собрать.bat» в папке программы. Нужен интернет (скачивается Python с python.org).
# Всё складывается в папку dist. Ничего не устанавливает в систему.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression.FileSystem

$root = Split-Path -Parent $PSScriptRoot
$ver = (Select-String -Path (Join-Path $root 'pult\__init__.py') -Pattern 'APP_VERSION = "([^"]+)"').Matches[0].Groups[1].Value
$dist = Join-Path $root 'dist'
$cache = Join-Path $dist 'cache'
$stage = Join-Path $dist 'VedomyjVPN'
$source = Join-Path $dist 'source\VedomyjVPN'
Write-Host "VEDOMYJ VPN $ver — сборка" -ForegroundColor Cyan

function Step($text) { Write-Host "  - $text" }

Remove-Item $stage, (Join-Path $dist 'source') -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $dist, $cache, $stage, $source | Out-Null

# ---------- файлы программы ----------
Step 'Копирую файлы программы'
$items = @('main.py', 'check.py', 'field_check.py', 'update_from_zip.py', 'full_check.py', 'start.bat', 'Проверка.bat', 'Проверка новых функций.bat', 'Обновить.bat', 'Полная проверка.bat', 'README.md', 'CHANGELOG.md', 'AI_GUIDE.md', 'pult', 'ui')
foreach ($item in $items) {
    Copy-Item -Path (Join-Path $root $item) -Destination $stage -Recurse -Force
    Copy-Item -Path (Join-Path $root $item) -Destination $source -Recurse -Force
}
foreach ($dir in @($stage, $source)) {
    New-Item -ItemType Directory -Force -Path (Join-Path $dir 'bin') | Out-Null
    Copy-Item -Path (Join-Path $root 'bin\README.txt') -Destination (Join-Path $dir 'bin') -Force
    Get-ChildItem -Path $dir -Recurse -Directory -Filter '__pycache__' | Remove-Item -Recurse -Force
}
Copy-Item -Path (Join-Path $root 'build') -Destination $source -Recurse -Force
Copy-Item -Path (Join-Path $root 'Собрать.bat') -Destination $source -Force
# Android-версия — только исходники: без ключа подписи, скачанного ядра и результатов сборки
$androidSrc = Join-Path $root 'android'
if (Test-Path $androidSrc) {
    & robocopy $androidSrc (Join-Path $source 'android') /E /XD keystore build .gradle libs .idea /XF local.properties /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { throw 'Не удалось скопировать папку android.' }
    $global:LASTEXITCODE = 0
}
$githubDir = Join-Path $root '.github'
if (Test-Path $githubDir) { Copy-Item -Path $githubDir -Destination $source -Recurse -Force }

# ---------- встроенный Python ----------
Step 'Скачиваю встроенный Python с python.org'
$versions = @('3.13.12', '3.13.11', '3.13.10', '3.13.9', '3.13.8', '3.13.7', '3.12.10')
$pyZip = $null
foreach ($v in $versions) {
    $file = Join-Path $cache "python-$v-embed-amd64.zip"
    if (Test-Path $file) { $pyZip = $file; break }
    try {
        Invoke-WebRequest -UseBasicParsing -Uri "https://www.python.org/ftp/python/$v/python-$v-embed-amd64.zip" -OutFile $file
        $pyZip = $file
        break
    } catch {
        Remove-Item $file -Force -ErrorAction SilentlyContinue
    }
}
if (-not $pyZip) { throw 'Не удалось скачать Python с python.org — проверь интернет.' }
Step ("Python: " + [IO.Path]::GetFileName($pyZip))
$pyDir = Join-Path $stage 'python'
[IO.Compression.ZipFile]::ExtractToDirectory($pyZip, $pyDir)
# папка программы — в путях встроенного Python, иначе не найдутся модули программы
$pth = Get-ChildItem -Path $pyDir -Filter 'python*._pth' | Select-Object -First 1
Add-Content -Path $pth.FullName -Value '..' -Encoding ASCII

# ---------- компилятор C# из Windows ----------
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
if (-not (Test-Path $csc)) { throw 'Не найден компилятор .NET Framework 4 (csc.exe).' }
$icon = Join-Path $root 'ui\icons\app.ico'
$manifest = Join-Path $PSScriptRoot 'app.manifest'
$common = @('/nologo', '/optimize+', '/platform:anycpu', '/codepage:65001', '/target:winexe',
            "/win32icon:$icon", "/win32manifest:$manifest")

Step 'Собираю VedomyjVPN.exe'
& $csc @common "/out:$(Join-Path $stage 'VedomyjVPN.exe')" '/r:System.Windows.Forms.dll' (Join-Path $PSScriptRoot 'launcher.cs')
if ($LASTEXITCODE -ne 0) { throw 'Не собралась запускалка VedomyjVPN.exe.' }

# ---------- портативная версия ----------
Step 'Упаковываю портативную версию'
$portable = Join-Path $dist "VedomyjVPN-$ver-portable.zip"
Remove-Item $portable -Force -ErrorAction SilentlyContinue
[IO.Compression.ZipFile]::CreateFromDirectory($stage, $portable, [IO.Compression.CompressionLevel]::Optimal, $true)

# ---------- установщик ----------
Step 'Собираю установщик'
$appZip = Join-Path $cache 'app.zip'
Copy-Item -Path $portable -Destination $appZip -Force
$code = (Get-Content -Path (Join-Path $PSScriptRoot 'installer.cs') -Raw -Encoding UTF8).Replace('%VERSION%', $ver)
$codeFile = Join-Path $cache 'installer.cs'
Set-Content -Path $codeFile -Value $code -Encoding UTF8
$setup = Join-Path $dist "VedomyjVPN-$ver-setup.exe"
& $csc @common "/out:$setup" "/resource:$appZip,app.zip" '/r:System.Windows.Forms.dll' '/r:System.Drawing.dll' `
    '/r:System.IO.Compression.dll' '/r:System.IO.Compression.FileSystem.dll' '/r:Microsoft.CSharp.dll' '/r:System.Core.dll' $codeFile
if ($LASTEXITCODE -ne 0) { throw 'Не собрался установщик.' }

# ---------- версия с исходниками ----------
Step 'Упаковываю версию с исходниками'
$srcZip = Join-Path $dist "VedomyjVPN-$ver-source.zip"
Remove-Item $srcZip -Force -ErrorAction SilentlyContinue
[IO.Compression.ZipFile]::CreateFromDirectory($source, $srcZip, [IO.Compression.CompressionLevel]::Optimal, $true)

Write-Host ''
Write-Host 'Готово. В папке dist:' -ForegroundColor Green
Write-Host "  VedomyjVPN-$ver-setup.exe     — установщик (без прав администратора)"
Write-Host "  VedomyjVPN-$ver-portable.zip  — портативная версия: распакуй и запусти VedomyjVPN.exe"
Write-Host "  VedomyjVPN-$ver-source.zip    — исходники для нейросети (без Python и без папки data)"
