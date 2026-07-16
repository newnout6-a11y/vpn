@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "ACTION=%~1"
if "%ACTION%"=="" set "ACTION=start"
set "TARGET=%~2"
set "PORT=%~3"
set "SLOT=%~4"
if "%SLOT%"=="" set "SLOT=1"
if "%PORT%"=="" set /a PORT=17989+SLOT
if "%ACTION%"=="trigger" set "ACTION=connect"

call :set_control_url
curl -fsS "!CONTROL_URL!/status?format=text" >nul 2>nul
if errorlevel 1 (
  if exist "%~dp0VPN Tunnel Enforcer.exe" (
    start "" /min "%~dp0VPN Tunnel Enforcer.exe"
    for /L %%i in (1,1,30) do (
      call :set_control_url
      curl -fsS "!CONTROL_URL!/status?format=text" >nul 2>nul
      if not errorlevel 1 goto :api_ready
      ping 127.0.0.1 -n 2 >nul
    )
  )
)

:api_ready
call :set_control_url
set "TOKEN=%VPNTE_CONTROL_TOKEN%"
if "%TOKEN%"=="" if exist "%APPDATA%\VPN Tunnel Enforcer\external-proxy-control-token" (
  set /p TOKEN=<"%APPDATA%\VPN Tunnel Enforcer\external-proxy-control-token"
)

set "ENC_TARGET=%TARGET%"
if not "%TARGET%"=="" (
  for /f "delims=" %%A in ('powershell -NoProfile -Command "[uri]::EscapeDataString($env:TARGET)" 2^>nul') do set "ENC_TARGET=%%A"
)

set "URL=!CONTROL_URL!/%ACTION%?format=text&slot=%SLOT%"

if "%ACTION%"=="connect" (
  if "%TARGET%"=="" (
    echo Usage: vpnte-proxy.cmd connect PROFILE_ID 1>&2
    exit /b 2
  )
  set "URL=%URL%&port=%PORT%&id=%ENC_TARGET%"
) else (
  if not "%ACTION%"=="status" if not "%ACTION%"=="stop" if not "%ACTION%"=="list" set "URL=%URL%&port=%PORT%"
  if not "%TARGET%"=="" if not "%ACTION%"=="status" if not "%ACTION%"=="stop" set "URL=%URL%&country=%ENC_TARGET%"
)

if "%ACTION%"=="status" goto :get_request
if "%ACTION%"=="list" goto :get_request

if "%TOKEN%"=="" (
  echo External proxy control token was not found. Start VPN Tunnel Enforcer and try again. 1>&2
  exit /b 1
)

curl -fsS -X POST -H "X-VPNTE-Control-Token: %TOKEN%" "%URL%"
goto :after_request

:get_request
curl -fsS "%URL%"

:after_request
if errorlevel 1 (
  echo VPN Tunnel Enforcer is not running or external proxy API is unavailable. 1>&2
  exit /b 1
)
exit /b 0

:set_control_url
set "CONTROL_URL=%VPNTE_CONTROL_URL%"
if not "%CONTROL_URL%"=="" goto :trim_control_url
if exist "%APPDATA%\VPN Tunnel Enforcer\external-proxy-control-endpoint.json" (
  for /f "usebackq delims=" %%A in (`powershell -NoProfile -Command "$p = Join-Path $env:APPDATA 'VPN Tunnel Enforcer\external-proxy-control-endpoint.json'; try { $j = Get-Content -LiteralPath $p -Raw | ConvertFrom-Json; if ($j.url) { [string]$j.url } elseif ($j.host -and $j.port) { 'http://' + $j.host + ':' + $j.port } } catch {}" 2^>nul`) do set "CONTROL_URL=%%A"
)
if "%CONTROL_URL%"=="" set "CONTROL_URL=http://127.0.0.1:17873"

:trim_control_url
if "%CONTROL_URL:~-1%"=="/" set "CONTROL_URL=%CONTROL_URL:~0,-1%"
exit /b 0
