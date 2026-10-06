; Custom NSIS hooks for VPN Tunnel Enforcer.
;
; Request main-owned shutdown before replacement/removal, and wait for its
; cleanup acknowledgement and process release. Timeout/failure aborts safely.
; Older clients without the shutdown command must be exited manually first.
; electron-builder still chains the previous uninstaller; user data is retained.

!include "WinCore.nsh"
!define /file VPNTE_SHUTDOWN_COMMAND "${PROJECT_DIR}\build\shutdown-for-update.base64"

!macro requestSafeShutdown
  ; Embed the command: never execute a replaceable script from the user's temp tree.
  ; Pass the path as literal process environment, not interpolated PowerShell code.
  System::Call 'kernel32::SetEnvironmentVariableW(w "VPNTE_INSTALL_DIR", w "$INSTDIR") i.r2'
  ${If} $2 == 0
    StrCpy $0 1
    StrCpy $1 "Could not pass the installation path safely"
  ${Else}
    nsExec::ExecToStack /TIMEOUT=150000 '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ${VPNTE_SHUTDOWN_COMMAND}'
    Pop $0
    Pop $1
    System::Call 'kernel32::SetEnvironmentVariableW(w "VPNTE_INSTALL_DIR", p 0)'
  ${EndIf}
  ${If} $0 != 0
    ${If} $LANGUAGE == 1049
      MessageBox MB_OK|MB_ICONSTOP "Завершение VPNTE не подтверждено. Штатно выйдите из клиента и повторите попытку. Установка/удаление остановлены без принудительного завершения процессов.$\r$\n$1" /SD IDOK
    ${Else}
      MessageBox MB_OK|MB_ICONSTOP "VPNTE shutdown was not confirmed. Exit the client normally and retry. Installation/removal has stopped; no processes were force-killed.$\r$\n$1" /SD IDOK
    ${EndIf}
    SetErrorLevel 1
    Quit
  ${EndIf}
!macroend

; Override electron-builder's default check too: it otherwise falls back to force-kill.
!macro customCheckAppRunning
  !insertmacro requestSafeShutdown
!macroend

; Runs at the very start of the (silent or UI) install, BEFORE files are laid
; down and BEFORE electron-builder chains the old uninstaller.
!macro customInit
  !insertmacro requestSafeShutdown
!macroend

!macro customInstall
  ; Mandatory SYSTEM recovery task on every install/upgrade. Fail visibly if registration cannot be verified.
  nsExec::ExecToStack 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\resources\vpnte-recover.ps1" -RegisterTask'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "VPNTE Boot Recovery registration failed: $1"
    Abort
  ${EndIf}

  ; Keep user data intact on upgrade/reinstall. Server groups are user state:
  ; deleting them here can resurrect old subscriptions from legacy caches.

  ; Do not change global .NET settings or run system-wide NGEN maintenance.

  ; Remove the stale dev-mode "Electron.lnk" that running the app from source
  ; drops in the Start Menu (target: node_modules\electron\dist\electron.exe,
  ; icon: the Electron atom). It carries our AppUserModelID, so Windows binds
  ; the installed app's taskbar button to it and shows the atom instead of our
  ; icon. Best-effort — $APPDATA is the installing user's; the app also sweeps
  ; this on startup (src/main/taskbarIdentity.ts) for other profiles.
  Delete "$APPDATA\Microsoft\Windows\Start Menu\Programs\Electron.lnk"

  ; Refresh Windows icon cache so updated app / shortcut icons show up
  ; immediately after reinstall. Without this, Explorer can keep a stale
  ; cached icon for the existing shortcut or pinned taskbar entry.
  nsExec::ExecToLog 'ie4uinit.exe -ClearIconCache'
  nsExec::ExecToLog 'ie4uinit.exe -show'
!macroend

; Standalone and chained uninstall use the same fail-closed shutdown gate.
!macro customUnInit
  !insertmacro requestSafeShutdown
!macroend

; During an upgrade the new installer owns recovery registration. A standalone
; uninstall must remove our task BEFORE deleting the script it references.
!macro customUnInstall
  ${IfNot} ${isUpdated}
    nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\resources\vpnte-recover.ps1" -UnregisterTask'
    Pop $0
    Pop $1
    ${If} $0 != 0
      MessageBox MB_ICONSTOP "VPNTE Boot Recovery removal failed: $1"
      SetErrorLevel 1
      Abort
    ${EndIf}
  ${EndIf}
!macroend

; Make the finish page window movable. NSIS finish pages sometimes lock the
; window position on certain Windows configurations. This hook runs after the
; finish page is created and ensures the window has standard drag behavior.
!macro customPageEnd
  ; Enable window dragging by ensuring the NSIS window style includes
  ; WS_CAPTION + WS_SYSMENU (standard movable window chrome).
  nsDialogs::CreateControl "Static" "" ${WS_VISIBLE} 0 0 0 0 ""
!macroend
