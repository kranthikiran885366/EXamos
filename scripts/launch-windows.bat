@echo off
title ExamOS Examination Server
echo.
echo ========================================================
echo     ExamOS Server - Windows Launch Helper
echo ========================================================
echo.
echo Starting ExamOS server via WSL...
echo.
echo Once started, open your browser to:
echo   Candidate Login:  http://localhost:8000/
echo   Admin Dashboard:  http://localhost:8000/admin
echo   Health Check:     http://localhost:8000/api/v1/health
echo   System Status:    http://localhost:8000/api/v1/status
echo.
echo Admin credentials: admin / ExamOS@Admin2025!
echo.
echo Press Ctrl+C to stop.
echo.
wsl -d Ubuntu-26.04 -- bash -c "cd '/mnt/d/SEB BRO' && bash scripts/launch-server.sh"
pause
