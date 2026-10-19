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
; the shutdown path and logs APP_STOP {installer}); then every atlas-duck process whose image is
; directly in $INSTDIR is terminated (the CLI, long-lived `atlas-duck mcp` processes, instances
; in other user sessions, reconciled at their next start). A process is selected by its full
; image path: directory $INSTDIR AND file name one of ATLAS_DUCK_IMAGES. Never by name alone
; (another install's processes stay), never by directory alone (an install into a shared folder,
; `/D=C:\Tools`, must not kill the other programs there). The class and the message name are
; shared with app/src-tauri/src/os_hooks/windows.rs (a unit test compares them).
!define ATLAS_DUCK_ENDSESSION_CLASS "atlas-duck-end-session"
!define ATLAS_DUCK_INSTALLER_QUIT_MESSAGE "AtlasDuckInstallerQuit"
; The images the installer puts in $INSTDIR: the main binary (tauri.conf.json mainBinaryName) and
; the other Cargo [[bin]]s, which the bundler installs next to it. A PowerShell list; a unit test
; compares it with app/src-tauri/Cargo.toml and tauri.conf.json.
!define ATLAS_DUCK_APP_IMAGE "atlas-duck-app.exe"
!define ATLAS_DUCK_IMAGES "'atlas-duck-app.exe','atlas-duck.exe','atlas-duck-sandbox.exe'"
; How long the drain waits for the app (sec. 12.2: up to 90 s; the app's own path takes at most
; 88 s, os_hooks::PATH_WAIT).
!define ATLAS_DUCK_DRAIN_MS 90000
; Bound of the PowerShell run (nsExec /TIMEOUT: the time without output, then nsExec returns
; "timeout"). Above the longest silent stretch of a normal run: the wait for the app (at most
; ATLAS_DUCK_DRAIN_MS) plus the process query. A hung WMI query ends the run here, before anything
; is selected: nothing is killed and the install goes on.
!define ATLAS_DUCK_DRAIN_TIMEOUT_MS 150000
; The drain's PowerShell command is about 900 characters (a unit test keeps it under 1000); NSIS
; truncates longer strings at NSIS_MAX_STRLEN, which would run a cut script.
!if ${NSIS_MAX_STRLEN} < 1024
  !error "atlas-duck: the drain's PowerShell command needs NSIS_MAX_STRLEN >= 1024"
!endif

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
;   1. The app's end-session window: every top-level window of the class is looked at (a window
;      of another program or of the other install mode may come first), up to 32. The first whose
;      process image is $INSTDIR\${ATLAS_DUCK_APP_IMAGE} (another install's app is left alone) is
;      sent the registered quit message; the app answers 1 after its shutdown path ended (at most
;      ${ATLAS_DUCK_DRAIN_MS} ms; no SMTO_ABORTIFHUNG: the window's thread waits on purpose while
;      the path runs). A failed send or another answer (DefWindowProcW's 0: the app could not
;      register the message) means the app did not take the request: no wait for it.
;   2. One PowerShell run (inputs through the environment, so no path is ever quoted into the
;      command), bounded by ${ATLAS_DUCK_DRAIN_TIMEOUT_MS} ms without output: waits for that app
;      process for the rest of the budget, then terminates every process whose image is
;      $INSTDIR\<one of ATLAS_DUCK_IMAGES>, except this installer and its parent (the previous
;      uninstaller runs in place, `_?=$INSTDIR`, under the new installer). It refuses a drive
;      root or a directory under %SystemRoot% (exit 3). Any error stops it before it kills
;      (ErrorActionPreference Stop: exit 1). Its exit code is otherwise the number of processes
;      still alive. Its module path is the system's only (PowerShell adds Program Files'), so no
;      module from the user's Documents folder loads into an elevated drain. A failure or a
;      timeout is logged and the install goes on: the template's own CheckIfAppIsRunning still
;      closes atlas-duck-app.exe, and a file still in use stops the copy with NSIS's own retry
;      dialog.
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
  ; $0: the window ($0 = 0: none of ours); $2: its process image; $7: windows looked at
  StrCpy $0 0
  StrCpy $2 ""
  StrCpy $7 0
  ${Do}
    System::Call 'user32::FindWindowExW(p 0, p r0, w "${ATLAS_DUCK_ENDSESSION_CLASS}", p 0) p .r0'
    ${If} $0 = 0
      ${ExitDo}
    ${EndIf}
    IntOp $7 $7 + 1
    System::Call 'user32::GetWindowThreadProcessId(p r0, *i .r1)'
    StrCpy $2 ""
    ; PROCESS_QUERY_LIMITED_INFORMATION
    System::Call 'kernel32::OpenProcess(i 0x1000, i 0, i r1) p .r3'
    ${If} $3 <> 0
      System::Call 'kernel32::QueryFullProcessImageNameW(p r3, i 0, w .r2, *i ${NSIS_MAX_STRLEN})'
      System::Call 'kernel32::CloseHandle(p r3)'
    ${EndIf}
    ; `==` compares case-insensitively.
    ${If} $2 == "$INSTDIR\${ATLAS_DUCK_APP_IMAGE}"
      ${ExitDo}
    ${EndIf}
  ${LoopUntil} $7 >= 32
  ${If} $0 <> 0
  ${AndIf} $2 == "$INSTDIR\${ATLAS_DUCK_APP_IMAGE}"
    System::Call 'user32::RegisterWindowMessageW(w "${ATLAS_DUCK_INSTALLER_QUIT_MESSAGE}") i .r3'
    ${If} $3 <> 0
      DetailPrint "atlas-duck: asking the running app to quit"
      System::Call 'kernel32::GetTickCount() i .r6'
      StrCpy $7 0
      System::Call 'user32::SendMessageTimeoutW(p r0, i r3, p 0, p 0, i 0, i ${ATLAS_DUCK_DRAIN_MS}, *p .r7) p .r2'
      ; $2: the send succeeded (0: failed or timed out); $7: the app's answer (1: it took the
      ; request and its path ended or its own wait expired).
      ${If} $2 <> 0
      ${AndIf} $7 = 1
        System::Call 'kernel32::GetTickCount() i .r7'
        IntOp $7 $7 - $6
        IntOp $4 ${ATLAS_DUCK_DRAIN_MS} - $7
        IntOp $4 $4 / 1000
        ${If} $4 < 0
          StrCpy $4 0
        ${EndIf}
        StrCpy $5 $1
      ${Else}
        DetailPrint "atlas-duck: the app did not take the quit request (sent $2, answer $7)"
      ${EndIf}
    ${EndIf}
  ${EndIf}
  System::Call 'kernel32::GetCurrentProcessId() i .r6'
  System::Call 'kernel32::SetEnvironmentVariableW(w "ATLAS_DUCK_DRAIN_DIR", w "$INSTDIR")'
  System::Call 'kernel32::SetEnvironmentVariableW(w "ATLAS_DUCK_DRAIN_SELF", w "$6")'
  System::Call 'kernel32::SetEnvironmentVariableW(w "ATLAS_DUCK_DRAIN_APP", w "$5")'
  System::Call 'kernel32::SetEnvironmentVariableW(w "ATLAS_DUCK_DRAIN_WAIT", w "$4")'
  ; Windows PowerShell 5.1 given only this path adds Program Files' (admin-writable) and leaves
  ; out the user's Documents\WindowsPowerShell\Modules.
  System::Call 'kernel32::SetEnvironmentVariableW(w "PSModulePath", w "$SYSDIR\WindowsPowerShell\v1.0\Modules")'
  ; PowerShell `$` is written `$$` here (NSIS would expand it).
  nsExec::ExecToLog /TIMEOUT=${ATLAS_DUCK_DRAIN_TIMEOUT_MS} `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -Command "$$ErrorActionPreference='Stop';$$d=$$env:ATLAS_DUCK_DRAIN_DIR.TrimEnd('\');if($$d.Length -lt 4 -or ($$d+'\').StartsWith($$env:SystemRoot+'\','OrdinalIgnoreCase')){exit 3};$$k=[int]$$env:ATLAS_DUCK_DRAIN_SELF;$$a=[int]$$env:ATLAS_DUCK_DRAIN_APP;$$t=[int]$$env:ATLAS_DUCK_DRAIN_WAIT;$$f=@(${ATLAS_DUCK_IMAGES}|%{$$d+'\'+$$_});if($$a -and $$t){Wait-Process -Id $$a -Timeout $$t -EA 0};$$p=@(Get-CimInstance Win32_Process -EA 1);$$s=@($$PID,$$k)+@($$p|?{$$_.ProcessId -eq $$k}|%{$$_.ParentProcessId});$$l=@($$p|?{$$s -notcontains $$_.ProcessId -and $$f -contains $$_.ExecutablePath});foreach($$x in $$l){'atlas-duck: terminating '+$$x.ExecutablePath;Stop-Process -Id $$x.ProcessId -Force -EA 0};if($$l){Wait-Process -Id $$l.ProcessId -Timeout 10 -EA 0;exit @(Get-Process -Id $$l.ProcessId -EA 0).Count}"`
  Pop $0
  ${If} $0 != "0"
    DetailPrint "atlas-duck: the upgrade drain did not end cleanly (result $0)"
  ${EndIf}
  ; Unset: nothing started later (the app on the finish page) inherits them. Without
  ; PSModulePath a later PowerShell computes its default path again.
  System::Call 'kernel32::SetEnvironmentVariableW(w "ATLAS_DUCK_DRAIN_DIR", p 0)'
  System::Call 'kernel32::SetEnvironmentVariableW(w "ATLAS_DUCK_DRAIN_SELF", p 0)'
  System::Call 'kernel32::SetEnvironmentVariableW(w "ATLAS_DUCK_DRAIN_APP", p 0)'
  System::Call 'kernel32::SetEnvironmentVariableW(w "ATLAS_DUCK_DRAIN_WAIT", p 0)'
  System::Call 'kernel32::SetEnvironmentVariableW(w "PSModulePath", p 0)'
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
; CI-06 (ci/check-installers-lib.mjs) requires this shape: only `Call un.X` lines and the StrCpy,
; the StrCpy last, and the variable named on that line only in this file (comments included).
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
