@echo off
chcp 65001 >nul
cd /d "%~dp0"
rem Обновление поверх старой версии: подписки и настройки (папка data) остаются.
rem Можно перетащить архив VedomyjVPN-....zip мышкой на этот файл.
rem Каждая ветка — в скобках: cmd читает её целиком, поэтому замена самого этого файла ей не мешает.
if exist "python\python.exe" ( "python\python.exe" update_from_zip.py %* & exit /b )
where py >nul 2>nul && ( py -3 update_from_zip.py %* & exit /b )
where python >nul 2>nul && ( python update_from_zip.py %* & exit /b )
echo Python не найден. Установи его с https://www.python.org/downloads/ (отметь "Add python.exe to PATH").
pause
exit /b
