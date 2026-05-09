@echo off
title Spherenex Network Traffic Monitor
echo ============================================
echo   Spherenex Network Traffic Monitor
echo ============================================
echo.

:: Install Python backend deps
echo [1/3] Installing Python backend dependencies...
pip install -r backend\requirements.txt -q
if errorlevel 1 (
    echo ERROR: pip install failed. Make sure Python is installed.
    pause & exit /b 1
)

:: Install frontend deps (if not done)
echo [2/3] Installing frontend dependencies...
call npm install --silent 2>nul

:: Start backend in new window
echo [3/3] Starting backend and frontend...
start "Spherenex Backend (port 8000)" cmd /k "cd backend && python main.py"

:: Wait a moment then start frontend
timeout /t 2 /nobreak >nul
start "Spherenex Frontend (port 5173)" cmd /k "npm run dev"

echo.
echo  Backend  : http://localhost:8000
echo  Frontend : http://localhost:5173
echo.
echo  Admin Panel : http://localhost:5173/
echo  User Panel  : http://localhost:5173/user
echo  Demo Panel  : http://localhost:5173/hack
echo.
echo Opening browser...
timeout /t 3 /nobreak >nul
start http://localhost:5173
