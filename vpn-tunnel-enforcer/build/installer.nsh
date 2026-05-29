; Custom NSIS hooks for VPN Tunnel Enforcer.
;
; Goal: make the installer fully self-service. The user double-clicks the new
; setup and everything else (closing the running app, stopping our sing-box
; runtime, removing the previous version, cleaning a stale group cache so the
; smart per-subscription migration re-runs) happens automatically — no manual
; "uninstall first / close the app" steps.
;
; electron-builder already auto-runs the previous version's uninstaller on
; install when perMachine is set; these macros add the process-killing and
; cache-cleanup that electron-builder doesn't do on its own.

!macro killRunningApp
  ; Stop our own background sing-box runtime first (it holds the TUN adapter
  ; and would otherwise block file replacement / leave a half-running tunnel).
  nsExec::Exec 'taskkill /F /IM vpnte-sing-box.exe /T'
  ; Then the app itself. /T also takes child processes. Ignore errors — the
  ; process may simply not be running.
  nsExec::Exec 'taskkill /F /IM "VPN Tunnel Enforcer.exe" /T'
  ; Give Windows a moment to release file handles before we touch Program Files.
  Sleep 800
!macroend

; Runs at the very start of the (silent or UI) install, BEFORE files are laid
; down and BEFORE electron-builder chains the old uninstaller.
!macro customInit
  !insertmacro killRunningApp
!macroend

; Runs after the new files are installed. We delete the cached server-groups
; store so the app's startup migration re-bins every key into the correct
; per-subscription group on first launch (the flat/legacy grouping from older
; builds is discarded; the keys themselves in server-picker.json are kept).
!macro customInstall
  ; %APPDATA% of the installing user. NSIS expands $APPDATA per-user.
  Delete "$APPDATA\vpn-tunnel-enforcer\server-groups.json"
!macroend

; Runs at the start of uninstall (both the standalone uninstaller and the
; auto-uninstall electron-builder triggers before an upgrade). Kill the app so
; the uninstaller never fails on locked files.
!macro customUnInit
  !insertmacro killRunningApp
!macroend
