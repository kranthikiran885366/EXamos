@echo off
title ExamOS P0 Enterprise Certification
echo.
echo ========================================================
echo   ExamOS P0 Enterprise Certification Suite
echo ========================================================
echo.
echo Running full enterprise validation (60+ dynamic checks)...
echo.
wsl -d Ubuntu-26.04 -- bash -c "cd '/mnt/d/SEB BRO' && bash tests/p0/enterprise-validate.sh"
echo.
echo Results saved to artifacts/p0/enterprise/
echo.
pause
