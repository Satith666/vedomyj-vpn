@echo off
chcp 65001 >nul
cd /d "%~dp0"
if exist "VedomyjVPN.exe" goto launcher
if exist "python\pythonw.exe" goto bundled
where pyw >nul 2>nul && goto pyw
where pythonw >nul 2>nul && goto pythonw
where python >nul 2>nul && goto python
echo Python не найден.
echo Установи его с https://www.python.org/downloads/ и при установке отметь "Add python.exe to PATH".
echo Или скачай готовую сборку VEDOMYJ VPN с Python внутри.
pause
exit /b
:launcher
start "" "VedomyjVPN.exe"
exit /b
:bundled
start "" "python\pythonw.exe" main.py
exit /b
:pyw
start "" pyw -3 main.py
exit /b
:pythonw
start "" pythonw main.py
exit /b
:python
start "" python main.py
exit /b
