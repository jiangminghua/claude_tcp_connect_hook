@echo off
:: WFP Driver Unloader Script
:: Stops the driver service and optionally removes it completely
:: Must run as Administrator

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Please run as Administrator
    pause
    exit /b 1
)

set SERVICE_NAME=WfpDriver

echo === WFP Driver Unloader ===
echo.

:: Check if service exists
sc query %SERVICE_NAME% >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Service '%SERVICE_NAME%' does not exist.
    echo [+] Nothing to do.
    pause
    exit /b 0
)

:: Show current status
echo [*] Current driver status:
sc query %SERVICE_NAME% | findstr STATE
echo.

:: Stop the driver
echo [*] Stopping driver...
sc stop %SERVICE_NAME% >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] Driver stop requested.
    :: Wait for driver to fully stop
    timeout /t 2 /nobreak >nul
) else (
    echo [*] Driver is not running or already stopped.
)

:: Verify it stopped
sc query %SERVICE_NAME% | findstr "STOPPED" >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] Driver stopped successfully.
) else (
    echo [!] Warning: Driver may not have stopped cleanly.
    echo [!] A reboot may be required.
)

echo.

:: Delete the service
echo [*] Deleting driver service...
sc delete %SERVICE_NAME%
if %errorlevel% equ 0 (
    echo [+] Service deleted.
) else (
    echo [!] Failed to delete service. A reboot may be required.
)

echo.
echo [+] Driver unload complete.
pause
