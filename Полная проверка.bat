@echo off
chcp 65001 >nul
cd /d "%~dp0"
if exist "python\python.exe" goto bundled
where py >nul 2>nul && goto py
where python >nul 2>nul && goto python
echo Python не найден. Установи его с https://www.python.org/downloads/
pause
exit /b
:bundled
"python\python.exe" full_check.py %*
pause
exit /b
:py
py -3 full_check.py %*
pause
exit /b
:python
python full_check.py %*
pause
