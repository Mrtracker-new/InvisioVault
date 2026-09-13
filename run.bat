@echo off
echo Starting InvisioVault...
echo.

REM Start backend in a new window
echo Starting Backend Server...
start "InvisioVault Backend" cmd /k "cd /d %~dp0backend && .venv\Scripts\activate && python app.py"

REM Wait a moment for backend to start
timeout /t 3 /nobreak >nul

REM Start frontend in a new window
echo Starting Frontend Server on Network...
start "InvisioVault Frontend" cmd /k "cd /d %~dp0frontend && npm run dev -- --host"

echo.
echo Both servers are starting in separate windows!
echo Backend:  http://localhost:5000
echo Frontend: https://localhost:5173 (HTTPS enabled for mobile camera scanning)
echo           Check the frontend window for your Network https:// URL
echo.
echo Press any key to exit this window (servers will keep running)...
pause >nul
