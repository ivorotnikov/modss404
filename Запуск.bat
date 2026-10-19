@echo off
cd /d "%~dp0"
pyw -3 "%~dp0app.py"
if errorlevel 1 py -3 "%~dp0app.py"
if errorlevel 1 (
  echo Нужен Python 3. Скачайте его с https://www.python.org/downloads/ и включите Add python.exe to PATH.
  pause
)
