; VPN Tunnel Enforcer: per-machine installer and uninstaller (NSIS 3.13, built by `cargo xtask dist`).
;
; Identity is byte-identical to the Electron installer (electron-builder, last version 1.1.24): the same GUID
; registry keys, exe and uninstaller names, shortcut names and AUMID. So this installer finds and chains the
; Electron uninstaller and upgrades in place, and an Electron installer could chain this uninstaller back.
; Calls into the app go through its `--setup <command>` helper mode (contract: installer/PROGRESS.md). The
; helper always runs from a copy in $PLUGINSDIR: never from $INSTDIR, whose files are being replaced.
; No PowerShell, no scheduled tasks, no force-kill of the client: the shutdown gate asks it to exit.
;
; Defines passed by xtask: VERSION (X.Y.Z), STAGE (verified installed layout), OUTDIR (target\dist).

Unicode true
ManifestDPIAware true
RequestExecutionLevel admin
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

!define PRODUCT "VPN Tunnel Enforcer"
!define EXE "VPN Tunnel Enforcer.exe"
!define UNINST "Uninstall VPN Tunnel Enforcer.exe"
; UUIDv5(electron-builder namespace 50e065bc-3134-11e6-9bab-38c9862bdaf3, "com.vpntunnelenforcer.app")
!define APP_GUID "6ed500d7-e3cc-5276-81ea-221a0c3a3238"
!define KEY_INSTALL "Software\${APP_GUID}"
!define KEY_UNINSTALL "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_GUID}"
!define DESCRIPTION "Force all traffic through VPN Happ — Hard (TUN) or Soft (Autoconfig) mode with IP leak monitoring"
!define HELPER "$PLUGINSDIR\vpnte-setup.exe"
!define WV2_CLIENT "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
!define SHCNE_ASSOCCHANGED 0x08000000

Name "${PRODUCT}"
OutFile "${OUTDIR}\VPN-Tunnel-Enforcer-Setup-${VERSION}.exe"
; No directory page (an always-elevated app must not live in a user-writable folder); /D= stays for admins.
InstallDir "$PROGRAMFILES64\${PRODUCT}"
BrandingText "${PRODUCT} ${VERSION}"
ShowInstDetails hide
ShowUninstDetails hide

!define MUI_ICON "..\crates\ui\assets\icon.ico"
!define MUI_UNICON "..\crates\ui\assets\icon.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_FUNCTION RunApp
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
  SetRegView 64
  SetShellVarContext all
  ; One setup at a time; the mutex name is the Electron installer's, so the two generations exclude each other.
  System::Call 'kernel32::CreateMutexW(p 0, i 1, w "${APP_GUID}") p .r0 ?e'
  Pop $1
  ${If} $1 = 183 ; ERROR_ALREADY_EXISTS
    MessageBox MB_OK|MB_ICONEXCLAMATION "$(AlreadyRunning)" /SD IDOK
    Abort
  ${EndIf}
  ; Upgrade where the product already lives (64-bit view: read after SetRegView), unless /D= chose a path.
  ${If} $INSTDIR == "$PROGRAMFILES64\${PRODUCT}"
    ReadRegStr $0 HKLM "${KEY_INSTALL}" "InstallLocation"
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
  ; The Electron installer left a copy of itself (~134 MB) per installing user and never removed it.
  SetShellVarContext current
  RMDir /r "$LOCALAPPDATA\vpn-tunnel-enforcer-updater"
  SetShellVarContext all

  SetOutPath "$INSTDIR"
  File "${STAGE}\${EXE}"
  File "${STAGE}\vpnte-proxy.exe"
  File "${STAGE}\vpnte-proxy.cmd"
  File "${STAGE}\vpnte-proxy.ps1"
  SetOutPath "$INSTDIR\resources"
  File /r "${STAGE}\resources\*"
  SetOutPath "$INSTDIR\licenses"
  File /r "${STAGE}\licenses\*"
  SetOutPath "$INSTDIR"
  WriteUninstaller "$INSTDIR\${UNINST}"
  Call WriteRegistry
  Call CreateShortcuts
  Call CheckWebView2
  ${If} ${Silent}
  ${AndIf} $ForceRun == 1
    Call RunApp
  ${EndIf}
SectionEnd

; Chains the previous uninstaller (Electron or Rust: same key) so the user never has to uninstall first.
; It runs from a copy with `_?=` so that ExecWait waits for the real work; user data is always kept.
Function UninstallPrevious
  ReadRegStr $R0 HKLM "${KEY_UNINSTALL}" "UninstallString"
  ${If} $R0 == ""
    Return
  ${EndIf}
  ; UninstallString is `"<dir>\Uninstall VPN Tunnel Enforcer.exe" /allusers`: take the quoted path.
  StrCpy $R1 $R0 1
  ${If} $R1 == '"'
    StrCpy $R1 $R0 "" 1
    ${WordFind} $R1 '"' "+1" $R1
  ${Else}
    StrCpy $R1 $R0
  ${EndIf}
  ReadRegStr $R2 HKLM "${KEY_INSTALL}" "InstallLocation"
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
    ExecWait '"$PLUGINSDIR\old-uninstaller.exe" /S /KEEP_APP_DATA /allusers --keep-shortcuts --updated _?=$R2' $R3
    ${If} ${Errors}
      ClearErrors
      ExecWait '"$R1" /S /KEEP_APP_DATA /allusers --keep-shortcuts --updated _?=$R2' $R3
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

; Exactly the value set the Electron installer wrote, so Apps & features and old installers see one product.
Function WriteRegistry
  WriteRegStr HKLM "${KEY_INSTALL}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${KEY_INSTALL}" "KeepShortcuts" "true"
  WriteRegStr HKLM "${KEY_INSTALL}" "ShortcutName" "${PRODUCT}"
  WriteRegStr HKLM "${KEY_UNINSTALL}" "DisplayName" "${PRODUCT} ${VERSION}"
  WriteRegStr HKLM "${KEY_UNINSTALL}" "UninstallString" '"$INSTDIR\${UNINST}" /allusers'
  WriteRegStr HKLM "${KEY_UNINSTALL}" "QuietUninstallString" '"$INSTDIR\${UNINST}" /allusers /S'
  WriteRegStr HKLM "${KEY_UNINSTALL}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${KEY_UNINSTALL}" "DisplayIcon" "$INSTDIR\${EXE},0"
  WriteRegStr HKLM "${KEY_UNINSTALL}" "Comments" "${DESCRIPTION}"
  WriteRegDWORD HKLM "${KEY_UNINSTALL}" "NoModify" 1
  WriteRegDWORD HKLM "${KEY_UNINSTALL}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  WriteRegDWORD HKLM "${KEY_UNINSTALL}" "EstimatedSize" $0
FunctionEnd

; Both links are mandatory: Windows keeps the app in Settings > Notifications only while a Start-menu link
; carries its AUMID. A fresh install re-creates both; an --updated run keeps a deleted desktop link deleted.
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

; The UI needs the Evergreen WebView2 runtime (preinstalled on Windows 11). Only a hint: never abort.
Function CheckWebView2
  ReadRegStr $0 HKLM "SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\${WV2_CLIENT}" "pv"
  ${If} $0 == ""
  ${OrIf} $0 == "0.0.0.0"
    ReadRegStr $0 HKCU "Software\Microsoft\EdgeUpdate\Clients\${WV2_CLIENT}" "pv"
  ${EndIf}
  ${If} $0 == ""
  ${OrIf} $0 == "0.0.0.0"
    DetailPrint "WebView2 runtime not found"
    MessageBox MB_OK|MB_ICONEXCLAMATION "$(WebView2Missing)" /SD IDOK
  ${EndIf}
FunctionEnd

; Starts the app as the desktop user, not with the installer's elevated token (the app elevates itself).
Function RunApp
  nsExec::Exec /TIMEOUT=30000 '"${HELPER}" --setup launch-as-user --install-dir "$INSTDIR"'
  Pop $0
FunctionEnd

; ---------------------------------------------------------------------------------------------------------
; Uninstaller

Function un.onInit
  SetRegView 64
  SetShellVarContext all
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
      ; Network protection objects, the autostart task and the user's tweaks go before the files: strict
      ; filters would keep the PC offline without the app. During an upgrade the new version owns them.
      nsExec::ExecToStack /TIMEOUT=150000 '"${HELPER}" --setup uninstall --install-dir "$INSTDIR"'
      Pop $0
      Pop $1
      DetailPrint "$1"
      ${If} $0 != 0
        MessageBox MB_OK|MB_ICONSTOP "$(CleanupFailed)$\r$\n$1" /SD IDOK
        SetErrorLevel 1
        Abort
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
    SetShellVarContext current
    RMDir /r "$APPDATA\${PRODUCT}"
    RMDir /r "$APPDATA\vpn-tunnel-enforcer"
    RMDir /r "$LOCALAPPDATA\${PRODUCT}"
    SetShellVarContext all
    RMDir /r "$APPDATA\VPNTE"
    RMDir /r "$APPDATA\VPN-Tunnel-Enforcer"
  ${EndIf}
  DeleteRegKey HKLM "${KEY_UNINSTALL}"
  DeleteRegKey HKLM "${KEY_INSTALL}"
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
