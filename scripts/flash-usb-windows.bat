@echo off
setlocal enabledelayedexpansion
title ExamOS Bare-Metal USB Flashing Assistant (Windows)

echo ======================================================================
echo    ExamOS Enterprise - Bare-Metal Physical Laptop Flashing Guide
echo ======================================================================
echo.

set "IMG_RAW=D:\SEB BRO\image\examos.raw"
set "IMG_ISO=D:\SEB BRO\output\examos.iso"
set "IMG_VMDK=D:\SEB BRO\output\examos-flat.vmdk"

set "TARGET_IMG="
if exist "%IMG_RAW%" (
    set "TARGET_IMG=%IMG_RAW%"
) else if exist "%IMG_ISO%" (
    set "TARGET_IMG=%IMG_ISO%"
) else if exist "%IMG_VMDK%" (
    set "TARGET_IMG=%IMG_VMDK%"
)

if "%TARGET_IMG%"=="" (
    echo [ERROR] No built ExamOS image found in D:\SEB BRO.
    echo Please run the Linux build script first.
    pause
    exit /b 1
)

echo Built ExamOS Image Located:
echo   %TARGET_IMG%
echo.
echo Recommended Flashing Methods for Windows:
echo.
echo [Option 1: Rufus (Recommended for UEFI Bare-Metal Boot)]
echo   1. Download and run Rufus (https://rufus.ie)
echo   2. Device: Select your plugged-in USB Drive (>= 4 GB)
echo   3. Boot selection: Click SELECT and choose:
echo        %TARGET_IMG%
echo   4. Partition scheme: GPT
echo   5. Target system: UEFI (non-CSM)
echo   6. Click START (Select "Write in DD Image mode" if prompted)
echo.
echo [Option 2: balenaEtcher]
echo   1. Open balenaEtcher
echo   2. "Flash from file" - choose:
echo        %TARGET_IMG%
echo   3. "Select target" - choose your USB drive
echo   4. Click "Flash!"
echo.
echo [Option 3: WSL Direct dd]
echo   Open WSL terminal as root and run:
echo     sudo bash "scripts/flash-usb.sh"
echo.
echo ======================================================================
echo Laptop Bare-Metal Boot Instructions:
echo   - Insert the flashed USB drive into your laptop
echo   - Power on and tap the Boot Key:
echo       Dell:    F12
echo       Lenovo:  F12 / Fn+F12
echo       HP:      F9
echo       Asus:    F8 / Esc
echo       Acer:    F12
echo   - Select 'UEFI: [USB Drive Name]'
echo ======================================================================
echo.
pause
