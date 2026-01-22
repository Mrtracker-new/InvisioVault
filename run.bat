@echo off
echo Starting InvisioVault...
echo.

REM Start backend in a new window
echo Starting Backend Server...
start "InvisioVault Backend" cmd /k "cd /d %~dp0backend && .venv\Scripts\activate && python app.py"

REM Wait a moment for backend to start
timeout /t 3 /nobreak >nul

REM Start frontend in a new window
echo Starting Frontend Server...
start "InvisioVault Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"

echo.
echo Both servers are starting in separate windows!
echo Backend: http://localhost:5000
echo Frontend: http://localhost:5173
echo.
echo Press any key to exit this window (servers will keep running)...
pause >nul
