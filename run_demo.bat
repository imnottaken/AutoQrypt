@echo off
rem Starts the AutoQrypt two-button ESP32 demo and opens it in the browser.
cd /d "%~dp0"
.venv\Scripts\python.exe scripts\hil.py demo COM7
pause
