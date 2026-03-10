@echo off
:: WFP Driver Loader Script
:: Must run as Administrator

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Please run as Administrator
    pause
    exit /b 1
)

set DRIVER_NAME=WfpDriver
set DRIVER_SYS=%~dp0WfpDriver\x64\Release\WfpDriver.sys
set CERT_FILE=%~dp0WfpDriver\WfpTestCert.cer
set SERVICE_NAME=WfpDriver

if "%1"=="stop" goto :stop
if "%1"=="uninstall" goto :uninstall
if "%1"=="status" goto :status
if "%1"=="start" goto :start
if "%1"=="" goto :start
echo Usage: %~nx0 [start^|stop^|uninstall^|status]
exit /b 1

:start
echo === WFP Driver Loader ===
echo.

:: Check if driver file exists
if not exist "%DRIVER_SYS%" (
    echo [!] Driver not found: %DRIVER_SYS%
    echo [!] Please build the WfpDriver project first.
    pause
    exit /b 1
)

:: Check test signing
echo [*] Checking test signing mode...
bcdedit /enum {current} | findstr /i "testsigning.*Yes" >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Test signing is NOT enabled.
    echo [!] Run: bcdedit /set testsigning on
    echo [!] Then reboot the system.
    echo.
    set /p ENABLE="Enable test signing now? (y/n): "
    if /i "%ENABLE%"=="y" (
        bcdedit /set testsigning on
        echo [+] Test signing enabled. Please reboot and run this script again.
    )
    pause
    exit /b 1
)
echo [+] Test signing is enabled.

:: Install test certificate to Trusted Root store
if exist "%CERT_FILE%" (
    echo [*] Installing test certificate to Trusted Root store...
    certutil -addstore Root "%CERT_FILE%" >nul 2>&1
    certutil -addstore TrustedPublisher "%CERT_FILE%" >nul 2>&1
    echo [+] Test certificate installed.
) else (
    echo [!] Test certificate not found: %CERT_FILE%
    echo [!] Build the driver first to generate the certificate.
    pause
    exit /b 1
)

:: Check if service already exists
sc query %SERVICE_NAME% >nul 2>&1
if %errorlevel% equ 0 (
    echo [*] Service already exists, stopping first...
    sc stop %SERVICE_NAME% >nul 2>&1
    timeout /t 2 /nobreak >nul
    sc delete %SERVICE_NAME% >nul 2>&1
    timeout /t 1 /nobreak >nul
)

:: Create and start the service
echo [*] Creating driver service...
sc create %SERVICE_NAME% type=kernel binPath="%DRIVER_SYS%" start=demand
if %errorlevel% neq 0 (
    echo [!] Failed to create service
    pause
    exit /b 1
)
echo [+] Service created.

echo [*] Starting driver...
sc start %SERVICE_NAME%
if %errorlevel% neq 0 (
    echo [!] Failed to start driver. Check Event Viewer for details.
    echo [!] Common issues:
    echo     - Test signing not enabled (reboot required)
    echo     - Driver crash (check WinDbg / DbgView)
    pause
    exit /b 1
)
echo [+] Driver started successfully!
echo.
echo [*] You can now run ProxyClient.exe
echo [*] To stop:      %~nx0 stop
echo [*] To uninstall: %~nx0 uninstall
goto :eof

:stop
echo [*] Stopping driver...
sc stop %SERVICE_NAME%
if %errorlevel% equ 0 (
    echo [+] Driver stopped.
) else (
    echo [!] Failed to stop driver (may not be running)
)
goto :eof

:uninstall
echo [*] Stopping driver...
sc stop %SERVICE_NAME% >nul 2>&1
timeout /t 2 /nobreak >nul
echo [*] Deleting service...
sc delete %SERVICE_NAME%
if %errorlevel% equ 0 (
    echo [+] Driver uninstalled.
) else (
    echo [!] Failed to delete service
)
goto :eof

:status
sc query %SERVICE_NAME%
goto :eof
