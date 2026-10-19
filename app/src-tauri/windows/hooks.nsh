; atlas-duck NSIS installer hooks (bundle.windows.nsis.installerHooks).
;
; Spec sec. 9.4 (Windows) and sec. 12.2: in BOTH install modes (per-user and per-machine) the
; installer grants read+execute to
;   ALL APPLICATION PACKAGES            (S-1-15-2-1)
;   ALL RESTRICTED APPLICATION PACKAGES (S-1-15-2-2)
; on the sandbox worker and on every DLL it loads from the install directory, so the
; AppContainer / LPAC worker can map its own image. SIDs are used, never account names:
; the names are localized ("ALLE ANWENDUNGSPAKETE" on a German Windows).
;
; Tauri's installer.nsi (tauri-bundler 2.10.1, the bundler of tauri-cli 2.12.1) includes this
; file after MUI2.nsh and before its pages, and expands:
;   NSIS_HOOK_PREINSTALL    first in `Section Install`, BEFORE its CheckIfAppIsRunning (which
;                           closes only atlas-duck-app.exe, through the Restart Manager);
;   NSIS_HOOK_POSTINSTALL   at the end of `Section Install`, after every file is copied;
;   NSIS_HOOK_PREUNINSTALL  first in `Section Uninstall`, BEFORE its CheckIfAppIsRunning and
;                           before the template reads the "delete app data" checkbox;
;   NSIS_HOOK_POSTUNINSTALL at the end of `Section Uninstall`.
; An upgrade through the GUI's default choice first runs the PREVIOUS version's uninstaller
; (`_?=$INSTDIR`, in place), so the uninstaller drains too (M10 Task 23, V19 check).
;
; Upgrade drain (sec. 12.2, sec. 2.5, PD-172): the running app is asked to quit with a
; registered window message sent to its hidden end-session window (found by class; the app runs
; the shutdown path and logs APP_STOP {installer}); then every process whose image path is
; under $INSTDIR is terminated (the CLI, long-lived `atlas-duck mcp` processes, instances in
; other user sessions, reconciled at their next start). Processes are selected by image path,
; never by name. Both names are shared with app/src-tauri/src/os_hooks/windows.rs (a unit test
; compares them).
!define ATLAS_DUCK_ENDSESSION_CLASS "atlas-duck-end-session"
!define ATLAS_DUCK_INSTALLER_QUIT_MESSAGE "AtlasDuckInstallerQuit"
; How long the drain waits for the app (sec. 12.2: up to 90 s; the app's own path takes at most
; 88 s, os_hooks::PATH_WAIT).
!define ATLAS_DUCK_DRAIN_MS 90000

; Finish page (sec. 12.2). MUI_PAGE_FINISH reads this define; the template sets none.
!define MUI_FINISHPAGE_TEXT "$(^NameDA) has been installed on your computer.$\r$\n$\r$\nRestart your MCP clients so they use the new version."

; Stack in: the full path of one file. Grants (RX) to both SIDs with one icacls call.
; A failed grant is logged and sets the installer's exit code to 1, so a silent install fails
; loudly in CI. It does not abort: the app still starts and reports the floor as not met
; (sec. 9.4: a per-machine install with missing ACEs needs a repair install).
Function AtlasDuckGrantAces
  Exch $1
  Push $0
  nsExec::ExecToLog '"$SYSDIR\icacls.exe" "$1" /grant "*S-1-15-2-1:(RX)" /grant "*S-1-15-2-2:(RX)"'
  Pop $0
  ${If} $0 != "0"
    DetailPrint "atlas-duck: icacls failed for $1 (result $0)"
    SetErrorLevel 1
  ${EndIf}
  Pop $0
  Pop $1
FunctionEnd

; The worker plus every *.dll directly in $INSTDIR. The worker's own DLL set (the files named
; by `worker_ace_files`, T19) is a subset of this. Granting read+execute on the app's own
; public binaries to the two AppContainer groups exposes nothing.
Function AtlasDuckGrantWorkerAces
  Push $0
  Push $1
  Push "$INSTDIR\atlas-duck-sandbox.exe"
  Call AtlasDuckGrantAces
  FindFirst $0 $1 "$INSTDIR\*.dll"
  atlas_duck_next_dll:
    StrCmp $1 "" atlas_duck_dll_done
    Push "$INSTDIR\$1"
    Call AtlasDuckGrantAces
    FindNext $0 $1
    Goto atlas_duck_next_dll
  atlas_duck_dll_done:
  FindClose $0
  Pop $1
  Pop $0
FunctionEnd

; The upgrade drain, once for the installer and once (`un.`) for the uninstaller. Registers are
; saved and restored: the template's code around the hooks keeps its own.
;   1. The app's end-session window (by class). Only when its process image is directly in
;      $INSTDIR (another install's app is left alone) is it sent the registered quit message;
;      the app answers after its shutdown path ended (at most ${ATLAS_DUCK_DRAIN_MS} ms; no
;      SMTO_ABORTIFHUNG: the window's thread waits on purpose while the path runs).
;   2. One PowerShell run (inputs through the environment, so no path is ever quoted into the
;      command): waits for that app process for the rest of the budget, then terminates every
;      process whose image's directory is $INSTDIR, except this installer and its parent (the
;      previous uninstaller runs in place, `_?=$INSTDIR`, under the new installer). It refuses a
;      drive root or a directory under %SystemRoot% (exit 3). Its exit code is the number of
;      processes still alive. A failure is logged and the install goes on: the template's own
;      CheckIfAppIsRunning still closes atlas-duck-app.exe, and a file still in use stops the copy
;      with NSIS's own retry dialog.
!macro ATLAS_DUCK_DRAIN_FUNCTION UN
Function ${UN}AtlasDuckDrain
  Push $0
  Push $1
  Push $2
  Push $3
  Push $4
  Push $5
  Push $6
  Push $7
  ; $4: seconds left to wait for the app; $5: the app's pid (0: nothing to wait for)
  StrCpy $4 0
  StrCpy $5 0
  FindWindow $0 "${ATLAS_DUCK_ENDSESSION_CLASS}"
  ${If} $0 <> 0
    System::Call 'user32::GetWindowThreadProcessId(p r0, *i .r1)'
    StrCpy $2 ""
    ; PROCESS_QUERY_LIMITED_INFORMATION
    System::Call 'kernel32::OpenProcess(i 0x1000, i 0, i r1) p .r3'
    ${If} $3 <> 0
      System::Call 'kernel32::QueryFullProcessImageNameW(p r3, i 0, w .r2, *i ${NSIS_MAX_STRLEN})'
      System::Call 'kernel32::CloseHandle(p r3)'
    ${EndIf}
    ; The image's directory ($2 up to its last backslash); `==` compares case-insensitively.
    ${GetParent} $2 $6
    ${If} $6 == $INSTDIR
      System::Call 'user32::RegisterWindowMessageW(w "${ATLAS_DUCK_INSTALLER_QUIT_MESSAGE}") i .r3'
      ${If} $3 <> 0
        DetailPrint "atlas-duck: asking the running app to quit"
        System::Call 'kernel32::GetTickCount() i .r6'
        System::Call 'user32::SendMessageTimeoutW(p r0, i r3, p 0, p 0, i 0, i ${ATLAS_DUCK_DRAIN_MS}, *p .r7)'
        System::Call 'kernel32::GetTickCount() i .r7'
        IntOp $7 $7 - $6
        IntOp $4 ${ATLAS_DUCK_DRAIN_MS} - $7
        IntOp $4 $4 / 1000
        ${If} $4 < 0
          StrCpy $4 0
        ${EndIf}
        StrCpy $5 $1
      ${EndIf}
    ${EndIf}
  ${EndIf}
  System::Call 'kernel32::GetCurrentProcessId() i .r6'
  System::Call 'kernel32::SetEnvironmentVariableW(w "ATLAS_DUCK_DRAIN_DIR", w "$INSTDIR")'
  System::Call 'kernel32::SetEnvironmentVariableW(w "ATLAS_DUCK_DRAIN_SELF", w "$6")'
  System::Call 'kernel32::SetEnvironmentVariableW(w "ATLAS_DUCK_DRAIN_APP", w "$5")'
  System::Call 'kernel32::SetEnvironmentVariableW(w "ATLAS_DUCK_DRAIN_WAIT", w "$4")'
  ; PowerShell `$` is written `$$` here (NSIS would expand it).
  nsExec::ExecToLog `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -Command "$$d=$$env:ATLAS_DUCK_DRAIN_DIR.TrimEnd('\');if($$d.Length -lt 4 -or ($$d+'\').StartsWith($$env:SystemRoot+'\','OrdinalIgnoreCase')){exit 3};$$k=[int]$$env:ATLAS_DUCK_DRAIN_SELF;$$a=[int]$$env:ATLAS_DUCK_DRAIN_APP;$$t=[int]$$env:ATLAS_DUCK_DRAIN_WAIT;if($$a -and $$t){Wait-Process -Id $$a -Timeout $$t -EA 0};$$p=@(Get-CimInstance Win32_Process -EA 1);$$s=@($$PID,$$k)+@($$p|?{$$_.ProcessId -eq $$k}|%{$$_.ParentProcessId});$$l=@($$p|?{$$e=$$_.ExecutablePath;$$e -and $$s -notcontains $$_.ProcessId -and $$e.Substring(0,$$e.LastIndexOf('\')) -eq $$d});foreach($$x in $$l){'atlas-duck: terminating '+$$x.ExecutablePath;Stop-Process -Id $$x.ProcessId -Force -EA 0};if($$l){Wait-Process -Id $$l.ProcessId -Timeout 10 -EA 0;exit @(Get-Process -Id $$l.ProcessId -EA 0).Count}"`
  Pop $0
  ${If} $0 != "0"
    DetailPrint "atlas-duck: the upgrade drain did not end cleanly (result $0)"
  ${EndIf}
  ; Unset: nothing started later (the app on the finish page) inherits them.
  System::Call 'kernel32::SetEnvironmentVariableW(w "ATLAS_DUCK_DRAIN_DIR", p 0)'
  System::Call 'kernel32::SetEnvironmentVariableW(w "ATLAS_DUCK_DRAIN_SELF", p 0)'
  System::Call 'kernel32::SetEnvironmentVariableW(w "ATLAS_DUCK_DRAIN_APP", p 0)'
  System::Call 'kernel32::SetEnvironmentVariableW(w "ATLAS_DUCK_DRAIN_WAIT", p 0)'
  Pop $7
  Pop $6
  Pop $5
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
FunctionEnd
!macroend
!insertmacro ATLAS_DUCK_DRAIN_FUNCTION ""
!insertmacro ATLAS_DUCK_DRAIN_FUNCTION "un."

; Upgrade and reinstall: drain before the template's CheckIfAppIsRunning and before any file is
; copied.
!macro NSIS_HOOK_PREINSTALL
  Call AtlasDuckDrain
!macroend

!macro NSIS_HOOK_POSTINSTALL
  Call AtlasDuckGrantWorkerAces
!macroend

; Uninstall (sec. 12.5): drain first (the files can then be removed), and the template's
; "delete app data" checkbox is disabled: no Tauri config key turns it off (tauri-utils 2.10.1
; NsisConfig has none), so its state is cleared here, after the confirm page set it and before
; `Section Uninstall` reads it. The box is still drawn but deletes nothing. (What it would delete,
; $APPDATA\<identifier> and $LOCALAPPDATA\<identifier>, is not the atlas-duck data dir either: the
; identifier differs from the data-dir folder name, sec. 12.5, checked by CI-06.) If a Tauri bump
; renames the variable, this line stops the build instead of silently re-enabling the deletion.
; The uninstaller never deletes $APPDATA\atlas-duck, $LOCALAPPDATA\atlas-duck or any other data
; outside $INSTDIR: these hooks delete nothing.
!macro NSIS_HOOK_PREUNINSTALL
  Call un.AtlasDuckDrain
  StrCpy $DeleteAppDataCheckboxState 0
!macroend

; Explicitly nothing after uninstall: the data dir, the config dir, paths.toml and cli.toml, the
; external anchor dir and every keychain entry stay (sec. 12.5; "Prepare for removal" and the
; manual-removal docs cover them).
!macro NSIS_HOOK_POSTUNINSTALL
!macroend
