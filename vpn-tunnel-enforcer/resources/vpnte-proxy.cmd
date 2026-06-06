@echo off
setlocal

set "ACTION=%~1"
if "%ACTION%"=="" set "ACTION=start"
set "TARGET=%~2"
set "PORT=%~3"
if "%PORT%"=="" set "PORT=17990"
if "%ACTION%"=="trigger" set "ACTION=connect"

curl -fsS "http://127.0.0.1:17873/status?format=text" >nul 2>nul
if errorlevel 1 (
  if exist "%~dp0VPN Tunnel Enforcer.exe" (
    start "" /min "%~dp0VPN Tunnel Enforcer.exe"
    for /L %%i in (1,1,30) do (
      curl -fsS "http://127.0.0.1:17873/status?format=text" >nul 2>nul
      if not errorlevel 1 goto :api_ready
      ping 127.0.0.1 -n 2 >nul
    )
  )
)

:api_ready
set "URL=http://127.0.0.1:17873/%ACTION%?format=text"

if "%ACTION%"=="connect" (
  if "%TARGET%"=="" (
    echo Usage: vpnte-proxy.cmd connect PROFILE_ID 1>&2
    exit /b 2
  )
  set "URL=%URL%&port=%PORT%&id=%TARGET%"
) else (
  if not "%ACTION%"=="status" if not "%ACTION%"=="stop" if not "%ACTION%"=="list" set "URL=%URL%&port=%PORT%"
  if not "%TARGET%"=="" if not "%ACTION%"=="status" if not "%ACTION%"=="stop" set "URL=%URL%&country=%TARGET%"
)

curl -fsS "%URL%"
if errorlevel 1 (
  echo VPN Tunnel Enforcer is not running or external proxy API is unavailable. 1>&2
  exit /b 1
)
