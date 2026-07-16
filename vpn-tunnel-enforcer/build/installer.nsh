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

!include "WinCore.nsh"

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

!macro customInstall
  ; Keep user data intact on upgrade/reinstall. Server groups are user state:
  ; deleting them here can resurrect old subscriptions from legacy caches.

  ; NGEN pre-compile PowerShell assemblies — makes every PowerShell spawn
  ; ~10x faster by avoiding JIT compilation on each invocation. The app
  ; spawns PowerShell 5-10 times during a connect cycle, so this saves
  ; ~200-500ms per spawn. Safe: ngen is a standard Windows tool; if it
  ; fails (non-admin, missing .NET), the install continues normally.
  ; Note: NSIS treats $$ as literal $, so PS variables need double-$.
  nsExec::ExecToLog 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "try { [Environment]::SetEnvironmentVariable("DOTNET_NGEN_OPT","1","Machine"); $${asm}=[System.Reflection.Assembly]::LoadWithPartialName("System.Management.Automation"); if($${asm}){ $${ng}=Join-Path $${env:WINDIR} "Microsoft.NET\Framework64\v4.0.30319\ngen.exe"; if(Test-Path $${ng}){ & $${ng} install $${asm}.Location /nologo /silent; & $${ng} update /nologo /silent } } } catch {}"'

  ; Refresh Windows icon cache so updated app / shortcut icons show up
  ; immediately after reinstall. Without this, Explorer can keep a stale
  ; cached icon for the existing shortcut or pinned taskbar entry.
  nsExec::ExecToLog 'ie4uinit.exe -ClearIconCache'
  nsExec::ExecToLog 'ie4uinit.exe -show'
!macroend

; Runs at the start of uninstall (both the standalone uninstaller and the
; auto-uninstall electron-builder triggers before an upgrade). Kill the app so
; the uninstaller never fails on locked files.
!macro customUnInit
  !insertmacro killRunningApp
!macroend

; Make the finish page window movable. NSIS finish pages sometimes lock the
; window position on certain Windows configurations. This hook runs after the
; finish page is created and ensures the window has standard drag behavior.
!macro customPageEnd
  ; Enable window dragging by ensuring the NSIS window style includes
  ; WS_CAPTION + WS_SYSMENU (standard movable window chrome).
  nsDialogs::CreateControl "Static" "" ${WS_VISIBLE} 0 0 0 0 ""
!macroend
