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
    echo   Python non trovato.
    echo   Installa Python 3.9 o superiore da https://www.python.org/downloads/
    echo   ricordando di spuntare "Add Python to PATH", poi riavvia questo file.
    echo.
    pause
    exit /b 1
)

if not exist ".venv" (
    echo Creazione ambiente Python...
    python -m venv .venv
)

call ".venv\Scripts\activate.bat"

echo Installazione/aggiornamento dipendenze...
python -m pip install -q --upgrade pip
python -m pip install -q -r requirements-windows.txt
if errorlevel 1 (
    echo.
    echo   Installazione dipendenze fallita. Controlla la connessione a
    echo   internet e riprova.
    echo.
    pause
    exit /b 1
)

echo Aggiornamento database vendor (OUI) dall'IEEE (facoltativo, serve internet)...
python scripts\update_oui.py --if-missing || echo   (OUI completo non scaricato, uso la lista minima inclusa)

echo.
echo RaspiScanner in avvio su https://127.0.0.1:7332
echo (certificato self-signed: il browser mostra un avviso da accettare una volta)
echo Chiudi questa finestra per fermarlo.
echo.
start "" https://127.0.0.1:7332
python raspi-scanner.py

endlocal
