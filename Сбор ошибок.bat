@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo Сбор ошибок VEDOMYJ VPN
echo.
echo Программа будет работать как обычно и складывать в отчёт всё, что пошло не так:
echo ошибки программы и ядра, обрывы связи, ускорение, рекламу, смену сети.
echo Адресов серверов, ссылок и ключей в отчёте нет — его можно присылать как есть.
echo.
set H=24
set /p H=Сколько часов собирать (от 1 до 72, Enter — 24): 
if "%H%"=="" set H=24
if exist "VedomyjVPN.exe" goto launcher
if exist "python\pythonw.exe" goto bundled
where pyw >nul 2>nul && goto pyw
where pythonw >nul 2>nul && goto pythonw
where python >nul 2>nul && goto python
echo Python не найден. Установи его с https://www.python.org/downloads/
pause
exit /b
:launcher
start "" "VedomyjVPN.exe" --collect %H%
goto done
:bundled
start "" "python\pythonw.exe" main.py --collect %H%
goto done
:pyw
start "" pyw -3 main.py --collect %H%
goto done
:pythonw
start "" pythonw main.py --collect %H%
goto done
:python
start "" python main.py --collect %H%
goto done
:done
echo.
echo Сбор ошибок включён на %H% ч. Можно закрыть это окно и пользоваться программой.
echo Когда время выйдет, отчёт появится в папке data\reports (файл errors-дата.txt),
echo а программа покажет сообщение. Остановить раньше: Дополнительно → Профессиональные.
echo Пришли файл отчёта — по нему я найду и исправлю ошибки.
echo.
pause
