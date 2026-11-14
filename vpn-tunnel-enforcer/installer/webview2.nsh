; Microsoft Edge WebView2 runtime: the app's window needs it. Windows 11 has it; a clean Windows 10 or Windows
; Sandbox does not (sandbox lab, 14.11.2026). Found: nothing to do. Missing: Microsoft's Evergreen bootstrapper,
; installed with the app (resources\, pinned in resources/engines.toml), installs it. Run unelevated it installs
; for this user only and asks nothing (Microsoft's distribution docs; `/silent /install`, in this order: the reverse
; fails). It downloads the runtime, so offline it fails: then one calm line on the finish page says what to do and
; setup completes; the app offers the same install at its next start.
; Detection as Microsoft documents it for 64-bit Windows: `pv` under the machine key (the 32-bit view) or under the
; user key, anything but empty or 0.0.0.0. The keys and the program are defines so that xtask's test can point
; them at a throw-away key and a stand-in.

!ifndef WV2_MACHINE_ROOT
  !define WV2_MACHINE_ROOT HKLM
!endif
!ifndef WV2_MACHINE_KEY
  !define WV2_MACHINE_KEY "SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
!endif
!ifndef WV2_USER_KEY
  !define WV2_USER_KEY "Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
!endif
!ifndef WV2_RUN
  !define WV2_RUN '"$INSTDIR\resources\MicrosoftEdgeWebview2Setup.exe" /silent /install'
!endif
; Seconds to wait for the registration after a successful exit (see EnsureWebView2).
!ifndef WV2_SETTLE_SECONDS
  !define WV2_SETTLE_SECONDS 120
!endif

Var WebView2Note ; "" or the finish page's extra line when the runtime could not be installed

; $R0 = the installed runtime's version, or "" when there is none.
Function WebView2Version
  ReadRegStr $R0 ${WV2_MACHINE_ROOT} "${WV2_MACHINE_KEY}" "pv"
  ${If} $R0 == "0.0.0.0"
    StrCpy $R0 ""
  ${EndIf}
  ${If} $R0 == ""
    ReadRegStr $R0 HKCU "${WV2_USER_KEY}" "pv"
    ${If} $R0 == "0.0.0.0"
      StrCpy $R0 ""
    ${EndIf}
  ${EndIf}
FunctionEnd

; Lab live-9 L9-9: on a clean Windows the bootstrapper takes ~95 s (it downloads the runtime), so it runs beside
; the rest of setup: StartWebView2 right after the files are in place, EnsureWebView2 at the end waits for it.
Var WebView2Process ; the running bootstrapper's process handle, "" when none runs
Var WebView2Exit    ; "" = not run (the runtime was there), "error" = could not be started
Var WebView2Started ; 1 once StartWebView2 ran

; Starts the bootstrapper when the runtime is missing and returns at once. CreateProcess, as ExecWait does: a
; program that asked for elevation would fail here, never prompt. Not nsExec: Edge Update leaves a process
; behind that would keep nsExec's output pipe open until its timeout.
Function StartWebView2
  StrCpy $WebView2Started 1
  StrCpy $WebView2Process ""
  StrCpy $WebView2Exit ""
  Call WebView2Version
  ${If} $R0 != ""
    DetailPrint "WebView2 runtime $R0 found"
    Return
  ${EndIf}
  DetailPrint "$(WebView2Installing)"
  Push $R3
  Push $R4
  Push $R5
  Push $R6
  StrCpy $R3 '${WV2_RUN}'
  ; STARTUPINFOW (cb filled in by &l4) and PROCESS_INFORMATION of this 32-bit installer. CREATE_NO_WINDOW
  ; (0x08000000): no console window if the program is a console one; the bootstrapper shows nothing anyway.
  System::Call '*(&l4,i,i,i,i,i,i,i,i,i,i,i,&i2,&i2,i,i,i,i) p .R4'
  System::Call '*(p,p,i,i) p .R5'
  System::Call 'kernel32::CreateProcessW(p 0, t R3, p 0, p 0, i 0, i 0x08000000, p 0, p 0, p R4, p R5) i .R6'
  ${If} $R6 == 0
    StrCpy $WebView2Exit "error"
  ${Else}
    System::Call '*$R5(p .R6, p .R3)'
    System::Call 'kernel32::CloseHandle(p R3)'
    StrCpy $WebView2Process $R6
  ${EndIf}
  System::Free $R4
  System::Free $R5
  Pop $R6
  Pop $R5
  Pop $R4
  Pop $R3
FunctionEnd

; Waits for the bootstrapper StartWebView2 started (started here when it was not) and leaves $R0 = the runtime's
; version ("" = still missing) and $R1 = the bootstrapper's exit code ("" = not run, "error" = could not be
; started). Never aborts.
Function EnsureWebView2
  ${If} $WebView2Started != 1
    Call StartWebView2
  ${EndIf}
  StrCpy $WebView2Note ""
  StrCpy $R1 $WebView2Exit
  ${If} $WebView2Process != ""
    System::Call 'kernel32::WaitForSingleObject(p $WebView2Process, i -1)'
    System::Call 'kernel32::GetExitCodeProcess(p $WebView2Process, *i .R1)'
    System::Call 'kernel32::CloseHandle(p $WebView2Process)'
    StrCpy $WebView2Process ""
  ${EndIf}
  Call WebView2Version
  ${If} $R1 == ""
    Return
  ${EndIf}
  ; The bootstrapper can exit 0 before the runtime is registered (WebView2Feedback #1349, still open in 2026):
  ; Microsoft's advice is to wait for the registry value.
  ${If} $R1 == 0
    StrCpy $R2 0
    ${DoWhile} $R0 == ""
      ${If} $R2 >= ${WV2_SETTLE_SECONDS}
        ${Break}
      ${EndIf}
      Sleep 1000
      IntOp $R2 $R2 + 1
      Call WebView2Version
    ${Loop}
  ${EndIf}
  ${If} $R0 != ""
    DetailPrint "WebView2 runtime $R0 installed"
    Return
  ${EndIf}
  ; Microsoft documents no exit code but 0: the code goes to the log, the user gets what to do.
  DetailPrint "WebView2 runtime not installed (bootstrapper exit code $R1)"
  StrCpy $WebView2Note "$\r$\n$\r$\n$(WebView2Later)"
FunctionEnd
