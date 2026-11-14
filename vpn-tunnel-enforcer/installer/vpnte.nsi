; VPN Tunnel Enforcer: per-user installer and uninstaller (NSIS 3.13, built by `cargo xtask dist`).
;
; No administrator rights anywhere (owner requirement 2026-11-11, NOADMIN.md): both run with the user's own
; token, install into $LOCALAPPDATA\Programs, write only HKCU and the user's own links, and never elevate.
; The one exception is the helper service (owner decision 12.11.2026): setup installs it without asking by
; running `vpnte-service.exe request-install`, which asks Windows to run the service's own install verb
; elevated (Windows shows its one prompt). Declined or failed, setup goes on and the app works in proxy mode.
; Identity is the Electron installer's (electron-builder, last version 1.1.24): the same GUID registry keys
; (now under HKCU), exe and uninstaller names, shortcut name and AUMID.
; The old per-machine installation (Electron 1.x, HKLM + Program Files) cannot be removed without
; administrator rights: it is detected by reading HKLM, left in place and named to the user once. Its
; uninstaller is never started.
; Calls into the app go through its `--setup <command>` helper mode (contract: installer/PROGRESS.md). The
; helper always runs from a copy in $PLUGINSDIR: never from $INSTDIR, whose files are being replaced.
; No PowerShell, no scheduled tasks, no force-kill of the client: the shutdown gate asks it to exit.
;
; Defines passed by xtask: VERSION (X.Y.Z), STAGE (verified installed layout), OUTDIR (target\dist).

Unicode true
ManifestDPIAware true
RequestExecutionLevel user
SetCompressor /SOLID lzma
SetCompressorDictSize 64
; A file that cannot be written stops setup; never skip it silently into a mixed installation.
AllowSkipFiles off

!ifndef VERSION
  !error "VERSION is not defined: build with `cargo xtask dist`"
!endif
!ifndef STAGE
  !error "STAGE is not defined: build with `cargo xtask dist`"
!endif
!ifndef OUTDIR
  !error "OUTDIR is not defined: build with `cargo xtask dist`"
!endif

!include MUI2.nsh
!include LogicLib.nsh
!include x64.nsh
!include WinVer.nsh
!include FileFunc.nsh
!include WordFunc.nsh
!include "webview2.nsh"

!define PRODUCT "VPN Tunnel Enforcer"
!define EXE "VPN Tunnel Enforcer.exe"
!define UNINST "Uninstall VPN Tunnel Enforcer.exe"
; UUIDv5(electron-builder namespace 50e065bc-3134-11e6-9bab-38c9862bdaf3, "com.vpntunnelenforcer.app")
!define APP_GUID "6ed500d7-e3cc-5276-81ea-221a0c3a3238"
!define KEY_INSTALL "Software\${APP_GUID}"
!define KEY_UNINSTALL "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_GUID}"
!define DESCRIPTION "Force all traffic through VPN Happ — Hard (TUN) or Soft (Autoconfig) mode with IP leak monitoring"
!define HELPER "$PLUGINSDIR\vpnte-setup.exe"
!define SHCNE_ASSOCCHANGED 0x08000000

Name "${PRODUCT}"
OutFile "${OUTDIR}\VPN-Tunnel-Enforcer-Setup-${VERSION}.exe"
; The user's own program folder (FOLDERID_UserProgramFiles); no directory page, /D= still chooses another one.
InstallDir "$LOCALAPPDATA\Programs\${PRODUCT}"
BrandingText "${PRODUCT} ${VERSION}"
ShowInstDetails hide
ShowUninstDetails hide

!define MUI_ICON "..\crates\ui\assets\icon.ico"
!define MUI_UNICON "..\crates\ui\assets\icon.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_FUNCTION RunApp
; A WebView2 runtime that could not be installed adds one line here (webview2.nsh): no extra box to click.
!define MUI_FINISHPAGE_TEXT "$(MUI_TEXT_FINISH_INFO_TEXT)$WebView2Note"
!define MUI_FINISHPAGE_TEXT_LARGE
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Russian"
!include "lang.nsh"

VIProductVersion "${VERSION}.0"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductName" "${PRODUCT}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileDescription" "${PRODUCT} Setup"
VIAddVersionKey /LANG=${LANG_ENGLISH} "LegalCopyright" "Copyright (c) Vladimir Sakharov"

; Command-line flags (electron-builder spelling, so old installers and the future updater can pass them).
Var Updated        ; --updated: an upgrade chain; keep shortcuts as they are, skip the system cleanup
Var ForceRun       ; --force-run: start the app after a silent install
Var NoDesktop      ; --no-desktop-shortcut
Var KeepShortcuts  ; --keep-shortcuts (uninstaller)
Var DeleteAppData  ; --delete-app-data (uninstaller): user data is kept unless this is given
Var Fresh          ; 1 = no per-user installation existed before this run (the first install for this user)

!macro ReadFlag NAME VAR
  ClearErrors
  ${GetOptions} $R9 "${NAME}" $R8
  ${IfNot} ${Errors}
    StrCpy ${VAR} 1
  ${EndIf}
!macroend

; Shutdown gate: the helper asks the installed client to exit and waits for its acknowledgement (exit code
; 73 of the bound primary process). It never force-kills the client; a refusal stops setup. `!=` is a string
; comparison, so nsExec's "error" / "timeout" results refuse as well.
!macro Gate
  nsExec::ExecToStack /TIMEOUT=150000 '"${HELPER}" --setup await-shutdown --install-dir "$INSTDIR"'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_OK|MB_ICONSTOP "$(GateFailed)$\r$\n$1" /SD IDOK
    SetErrorLevel 1
    Quit
  ${EndIf}
!macroend

!macro RefreshShell
  System::Call 'shell32::SHChangeNotify(i ${SHCNE_ASSOCCHANGED}, i 0, p 0, p 0)'
!macroend

; ---------------------------------------------------------------------------------------------------------
; Installer

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_OK|MB_ICONSTOP "$(NeedsX64)" /SD IDOK
    Abort
  ${EndIf}
  ${IfNot} ${AtLeastWin10}
  ${OrIfNot} ${AtLeastBuild} 19041
    MessageBox MB_OK|MB_ICONSTOP "$(NeedsWin10)" /SD IDOK
    Abort
  ${EndIf}
  ; HKLM is only ever read (the old per-machine installation, in the 64-bit view the Electron installer used).
  SetRegView 64
  SetShellVarContext current
  ; One setup at a time; the mutex name is the Electron installer's, so the two generations exclude each other.
  System::Call 'kernel32::CreateMutexW(p 0, i 1, w "${APP_GUID}") p .r0 ?e'
  Pop $1
  ${If} $1 = 183 ; ERROR_ALREADY_EXISTS
    MessageBox MB_OK|MB_ICONEXCLAMATION "$(AlreadyRunning)" /SD IDOK
    Abort
  ${EndIf}
  StrCpy $Fresh 1
  ReadRegStr $0 HKCU "${KEY_UNINSTALL}" "UninstallString"
  ${If} $0 != ""
    StrCpy $Fresh 0
  ${EndIf}
  ; Upgrade where this user's installation already lives, unless /D= chose a path.
  ${If} $INSTDIR == "$LOCALAPPDATA\Programs\${PRODUCT}"
    ReadRegStr $0 HKCU "${KEY_INSTALL}" "InstallLocation"
    ${If} $0 != ""
      StrCpy $INSTDIR $0
    ${EndIf}
  ${EndIf}
  ${GetParameters} $R9
  !insertmacro ReadFlag "--updated" $Updated
  !insertmacro ReadFlag "--force-run" $ForceRun
  !insertmacro ReadFlag "--no-desktop-shortcut" $NoDesktop
FunctionEnd

Section "Install"
  SetDetailsPrint both
  InitPluginsDir
  File "/oname=${HELPER}" "${STAGE}\${EXE}" ; same bytes as the installed exe, stored once (datablock optimisation)
  !insertmacro Gate
  Call UninstallPrevious
  ; The Electron installer left a copy of itself (~134 MB) in each installing user's profile and never removed it.
  RMDir /r "$LOCALAPPDATA\vpn-tunnel-enforcer-updater"

  SetOutPath "$INSTDIR"
  File "${STAGE}\${EXE}"
  File "${STAGE}\vpnte-service.exe"
  File "${STAGE}\vpnte-proxy.exe"
  File "${STAGE}\vpnte-proxy.cmd"
  File "${STAGE}\vpnte-proxy.ps1"
  SetOutPath "$INSTDIR\resources"
  File /r "${STAGE}\resources\*"
  SetOutPath "$INSTDIR\licenses"
  File /r "${STAGE}\licenses\*"
  SetOutPath "$INSTDIR"
  WriteUninstaller "$INSTDIR\${UNINST}"
  ; The WebView2 bootstrapper (~95 s on a clean Windows) runs beside the steps below (lab live-9 L9-9).
  Call StartWebView2
  Call WriteRegistry
  Call CreateShortcuts
  Call RegisterLinks
  Call InstallService
  Call EnsureWebView2
  Call MachineWideNotice
  ${If} ${Silent}
  ${AndIf} $ForceRun == 1
    Call RunApp
  ${EndIf}
SectionEnd

; The helper service, installed or updated without asking (owner decision 12.11.2026). The service exe asks
; Windows to run its own `install` elevated and waits: one Windows prompt, none when the installed service is
; already this build. Exit codes: 0 done, 5 the prompt was declined (or nobody can approve it), 4 an update
; failed and the service is stopped until Windows starts it (the one case that gets a line), else failed. In
; every case setup goes on; without the service the app works in proxy mode and offers the install in Settings.
Function InstallService
  nsExec::ExecToStack /TIMEOUT=600000 '"$INSTDIR\vpnte-service.exe" request-install'
  Pop $0
  Pop $1
  DetailPrint "$1"
  ${If} $0 == 4
    MessageBox MB_OK|MB_ICONINFORMATION "$(ServiceStopped)" /SD IDOK
  ${EndIf}
FunctionEnd

; Link schemes (vless://, hiddify://import/ ...) for this user, under HKCU\Software\Classes: the helper takes
; the free ones on the first installation and later only points ours at this installation, so a scheme the user
; turned off stays off and one another program answers is never taken here. A failure is a detail line, never a
; failed installation (the app registers at its first start as well). `--setup uninstall` removes exactly the
; schemes recorded for this installation.
Function RegisterLinks
  nsExec::ExecToStack /TIMEOUT=60000 '"${HELPER}" --setup register-links --install-dir "$INSTDIR"'
  Pop $0
  Pop $1
  DetailPrint "$1"
FunctionEnd

; Chains this user's previous uninstaller (same key under HKCU) so the user never has to uninstall first.
; It runs from a copy with `_?=` so that ExecWait waits for the real work; user data is always kept. The
; per-machine key (HKLM) is never followed: that uninstaller needs administrator rights.
Function UninstallPrevious
  ReadRegStr $R0 HKCU "${KEY_UNINSTALL}" "UninstallString"
  ${If} $R0 == ""
    Return
  ${EndIf}
  ; UninstallString is `"<dir>\Uninstall VPN Tunnel Enforcer.exe"`: take the quoted path.
  StrCpy $R1 $R0 1
  ${If} $R1 == '"'
    StrCpy $R1 $R0 "" 1
    ${WordFind} $R1 '"' "+1" $R1
  ${Else}
    StrCpy $R1 $R0
  ${EndIf}
  ReadRegStr $R2 HKCU "${KEY_INSTALL}" "InstallLocation"
  ${If} $R2 == ""
    ${GetParent} $R1 $R2
  ${EndIf}
  ${IfNot} ${FileExists} $R1
    DetailPrint "Previous uninstaller not found ($R1): installing over the old files"
    Return
  ${EndIf}
  CopyFiles /SILENT /FILESONLY $R1 "$PLUGINSDIR\old-uninstaller.exe"
  StrCpy $R4 0
  attempt:
    ClearErrors
    ExecWait '"$PLUGINSDIR\old-uninstaller.exe" /S --keep-shortcuts --updated _?=$R2' $R3
    ${If} ${Errors}
      ClearErrors
      ExecWait '"$R1" /S --keep-shortcuts --updated _?=$R2' $R3
    ${EndIf}
    ${If} ${Errors}
      DetailPrint "Not able to launch the previous uninstaller: installing over the old files"
      Return
    ${EndIf}
    ${If} $R3 = 0
      Return
    ${EndIf}
    IntOp $R4 $R4 + 1
    ${If} $R4 < 5
      Sleep 1000
      Goto attempt
    ${EndIf}
    MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "$(PreviousBusy)" /SD IDCANCEL IDRETRY attempt
  MessageBox MB_OK|MB_ICONSTOP "$(PreviousFailed)$\r$\n[$R3]" /SD IDOK
  SetErrorLevel 2
  Quit
FunctionEnd

; The Electron installer's value set, in the user's hive: Apps & features lists this installation for this
; user next to an old per-machine one. No `/allusers` (an electron-builder flag for per-machine removal).
Function WriteRegistry
  WriteRegStr HKCU "${KEY_INSTALL}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${KEY_INSTALL}" "KeepShortcuts" "true"
  WriteRegStr HKCU "${KEY_INSTALL}" "ShortcutName" "${PRODUCT}"
  WriteRegStr HKCU "${KEY_UNINSTALL}" "DisplayName" "${PRODUCT} ${VERSION}"
  WriteRegStr HKCU "${KEY_UNINSTALL}" "UninstallString" '"$INSTDIR\${UNINST}"'
  WriteRegStr HKCU "${KEY_UNINSTALL}" "QuietUninstallString" '"$INSTDIR\${UNINST}" /S'
  WriteRegStr HKCU "${KEY_UNINSTALL}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${KEY_UNINSTALL}" "DisplayIcon" "$INSTDIR\${EXE},0"
  WriteRegStr HKCU "${KEY_UNINSTALL}" "Comments" "${DESCRIPTION}"
  WriteRegDWORD HKCU "${KEY_UNINSTALL}" "NoModify" 1
  WriteRegDWORD HKCU "${KEY_UNINSTALL}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  WriteRegDWORD HKCU "${KEY_UNINSTALL}" "EstimatedSize" $0
FunctionEnd

; Both links are mandatory and the user's own: Windows keeps the app in Settings > Notifications only while a
; Start-menu link carries its AUMID. A fresh install re-creates both; an --updated run keeps a deleted desktop
; link deleted. An old per-machine installation keeps its all-users links (removing them needs administrator
; rights); they carry the same AUMID and go with that installation.
Function CreateShortcuts
  CreateShortCut "$SMPROGRAMS\${PRODUCT}.lnk" "$INSTDIR\${EXE}" "" "$INSTDIR\${EXE}" 0 "" "" "${DESCRIPTION}"
  ${If} $Updated == 1
    StrCpy $0 0
    ${If} ${FileExists} "$DESKTOP\${PRODUCT}.lnk"
      StrCpy $0 1
    ${EndIf}
  ${Else}
    StrCpy $0 1
  ${EndIf}
  ${If} $0 == 1
  ${AndIf} $NoDesktop != 1
    CreateShortCut "$DESKTOP\${PRODUCT}.lnk" "$INSTDIR\${EXE}" "" "$INSTDIR\${EXE}" 0 "" "" "${DESCRIPTION}"
  ${EndIf}
  ; NSIS cannot set the AUMID property of a link; the helper stamps it. A failure is not fatal.
  nsExec::ExecToStack /TIMEOUT=60000 '"${HELPER}" --setup stamp-shortcuts --install-dir "$INSTDIR"'
  Pop $0
  Pop $1
  ${If} $0 != 0
    DetailPrint "Shortcut AUMID not stamped ($0): $1"
  ${EndIf}
  !insertmacro RefreshShell
  ; Explorer keeps stale icons of pinned items otherwise. The 64-bit tool: $SYSDIR is WOW64-redirected here.
  ${DisableX64FSRedirection}
  nsExec::Exec '"$SYSDIR\ie4uinit.exe" -show'
  Pop $0
  ${EnableX64FSRedirection}
FunctionEnd

; Starts the installed app as this user, unelevated (contract: `launch-as-user`).
Function RunApp
  nsExec::Exec /TIMEOUT=30000 '"${HELPER}" --setup launch-as-user --install-dir "$INSTDIR"'
  Pop $0
FunctionEnd

; The old per-machine installation (Electron 1.x: HKLM key, Program Files, all-users links) needs administrator
; rights to remove, so it stays. The user is told once, at the first installation for this user (a silent one
; only logs it). Its uninstaller is never started from here.
Function MachineWideNotice
  ReadRegStr $0 HKLM "${KEY_UNINSTALL}" "UninstallString"
  ${If} $0 == ""
    Return
  ${EndIf}
  ReadRegStr $1 HKLM "${KEY_UNINSTALL}" "DisplayVersion"
  DetailPrint "Per-machine installation $1 found: left in place (removing it needs administrator rights)"
  ${If} $Fresh == 1
    MessageBox MB_OK|MB_ICONINFORMATION "$(MachineWideKept)" /SD IDOK
  ${EndIf}
FunctionEnd

; ---------------------------------------------------------------------------------------------------------
; Uninstaller

Function un.onInit
  SetRegView 64
  SetShellVarContext current
  ${GetParameters} $R9
  !insertmacro ReadFlag "--updated" $Updated
  !insertmacro ReadFlag "--keep-shortcuts" $KeepShortcuts
  !insertmacro ReadFlag "--delete-app-data" $DeleteAppData
FunctionEnd

Section "Uninstall"
  SetDetailsPrint both
  InitPluginsDir
  ${If} ${FileExists} "$INSTDIR\${EXE}"
    CopyFiles /SILENT /FILESONLY "$INSTDIR\${EXE}" "${HELPER}"
    !insertmacro Gate
    ${If} $Updated != 1
      ; This user's system proxy, tweaks and autostart go before the files: a proxy left pointing at the
      ; dead engine port cuts the browsers off. Network filters only if this process happens to be elevated.
      ; During an upgrade the new version owns all of it.
      nsExec::ExecToStack /TIMEOUT=150000 '"${HELPER}" --setup uninstall --install-dir "$INSTDIR"'
      Pop $0
      Pop $1
      DetailPrint "$1"
      ${If} $0 != 0
        MessageBox MB_OK|MB_ICONSTOP "$(CleanupFailed)$\r$\n$1" /SD IDOK
        SetErrorLevel 1
        Abort
      ${EndIf}
      ; This Windows user leaves the helper service (no prompt); the last user's leave removes it. Exit code
      ; 3: it stays to remove its network filters later (one calm line); the per-user part goes on regardless.
      ${If} ${FileExists} "$INSTDIR\vpnte-service.exe"
        nsExec::ExecToStack /TIMEOUT=120000 '"$INSTDIR\vpnte-service.exe" forget-me'
        Pop $0
        Pop $1
        DetailPrint "$1"
        ${If} $0 == 3
          MessageBox MB_OK|MB_ICONINFORMATION "$(ServiceKept)" /SD IDOK
        ${EndIf}
      ${EndIf}
    ${EndIf}
  ${ElseIf} $Updated != 1
    MessageBox MB_OK|MB_ICONSTOP "$(AppMissing)" /SD IDOK
    SetErrorLevel 1
    Abort
  ${EndIf}
  ${If} $Updated == 1
    ; Refuse before deleting anything, so a failed upgrade leaves the old installation complete.
    Call un.EnsureFilesFree
  ${EndIf}

  Delete "$INSTDIR\${EXE}"
  Delete "$INSTDIR\vpnte-service.exe"
  Delete "$INSTDIR\vpnte-proxy.exe"
  Delete "$INSTDIR\vpnte-proxy.cmd"
  Delete "$INSTDIR\vpnte-proxy.ps1"
  RMDir /r "$INSTDIR\resources"
  RMDir /r "$INSTDIR\licenses"
  Delete "$INSTDIR\${UNINST}"
  RMDir "$INSTDIR"

  ${If} $KeepShortcuts != 1
    Delete "$SMPROGRAMS\${PRODUCT}.lnk"
    Delete "$DESKTOP\${PRODUCT}.lnk"
    !insertmacro RefreshShell
  ${EndIf}
  ${If} $DeleteAppData == 1
  ${AndIf} $Updated != 1
    RMDir /r "$APPDATA\${PRODUCT}"
    RMDir /r "$LOCALAPPDATA\${PRODUCT}"
    ; The Electron data folder is the old per-machine installation's while that one is still installed.
    ReadRegStr $0 HKLM "${KEY_UNINSTALL}" "UninstallString"
    ${If} $0 == ""
      RMDir /r "$APPDATA\vpn-tunnel-enforcer"
    ${EndIf}
  ${EndIf}
  DeleteRegKey HKCU "${KEY_UNINSTALL}"
  DeleteRegKey HKCU "${KEY_INSTALL}"
SectionEnd

; A file that another process still holds open cannot be replaced; check every installed file first.
Function un.EnsureFilesFree
  StrCpy $R0 "$INSTDIR"
  Call un.EnsureDirFree
  StrCpy $R0 "$INSTDIR\resources"
  Call un.EnsureDirFree
  StrCpy $R0 "$INSTDIR\licenses"
  Call un.EnsureDirFree
FunctionEnd

; Files directly in $R0 (no recursion: the layout is flat below each folder).
Function un.EnsureDirFree
  ${IfNot} ${FileExists} "$R0\*.*"
    Return
  ${EndIf}
  FindFirst $R1 $R2 "$R0\*"
  ${DoWhile} $R2 != ""
    ${IfNot} ${FileExists} "$R0\$R2\*.*"
    ${AndIf} "$R0\$R2" != "$INSTDIR\${UNINST}"
      ClearErrors
      FileOpen $R3 "$R0\$R2" a
      ${If} ${Errors}
        FindClose $R1
        MessageBox MB_OK|MB_ICONSTOP "$(FilesBusy)$\r$\n$R0\$R2" /SD IDOK
        SetErrorLevel 2
        Abort
      ${EndIf}
      FileClose $R3
    ${EndIf}
    FindNext $R1 $R2
  ${Loop}
  FindClose $R1
FunctionEnd
