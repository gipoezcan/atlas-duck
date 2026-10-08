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
; Tauri's installer.nsi expands NSIS_HOOK_POSTINSTALL at the end of `Section Install`,
; after every file is copied and before the installer finishes. Only that macro is defined
; here. NSIS_HOOK_PREINSTALL, NSIS_HOOK_PREUNINSTALL and NSIS_HOOK_POSTUNINSTALL (upgrade
; drain, uninstall rules) belong to M10.

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

!macro NSIS_HOOK_POSTINSTALL
  Call AtlasDuckGrantWorkerAces
!macroend
