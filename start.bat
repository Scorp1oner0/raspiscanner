@echo off
REM ---------------------------------------------------------------------------
REM RaspiScanner - avvio su Windows (build per il portatile del tecnico).
REM Doppio click su questo file. Serve Python 3.9+ installato con l'opzione
REM "Add Python to PATH" spuntata durante l'installazione.
REM
REM Cosa cambia rispetto al Raspberry Pi (vedi docs\WINDOWS.md):
REM  - la scheda di rete NON viene riconfigurata: si usa la rete gia' attiva
REM    su Windows (sola lettura);
REM  - niente hotspot Wi-Fi;
REM  - l'ARP scan L2 completo richiede Npcap (https://npcap.com) + avvio
REM    "Come amministratore". Senza, funziona lo stesso: ripiega su uno
REM    sweep TCP-connect + la tabella ARP di sistema.
REM ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo.
    echo   Python not found.
    echo   Install Python 3.9 or later from https://www.python.org/downloads/
    echo   making sure to check "Add Python to PATH", then run this file again.
    echo.
    pause
    exit /b 1
)

if not exist ".venv" (
    echo Creating Python environment...
    python -m venv .venv
)

call ".venv\Scripts\activate.bat"

echo Installing/updating dependencies...
python -m pip install -q --upgrade pip
python -m pip install -q -r requirements-windows.txt
if errorlevel 1 (
    echo.
    echo   Installing dependencies failed. Check your internet connection
    echo   and try again.
    echo.
    pause
    exit /b 1
)

echo Updating vendor database (OUI) from the IEEE (optional, needs internet)...
python scripts\update_oui.py --if-missing || echo   (full OUI not downloaded, using the bundled minimal list)

echo.
echo Starting RaspiScanner at https://127.0.0.1:7332
echo (self-signed certificate: the browser shows a warning you accept once)
echo Close this window to stop it.
echo.
start "" https://127.0.0.1:7332
python raspi-scanner.py

endlocal
