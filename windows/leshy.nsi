; Leshy Windows installer (NSIS).
; Built by windows/build-package.ps1, which passes /DVERSION=x.y.z and stages
; the payload into windows/stage/. Run makensis from the windows/ directory.
; NSIS has no line continuation: keep command strings on a single line.

!ifndef VERSION
  !define VERSION "0.0.0"
!endif

!define APP_NAME "Leshy"
!define SERVICE_NAME "leshy"
!define DATA_DIR "$COMMONPROGRAMDATA\leshy"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\leshy"

!include "MUI2.nsh"

Name "${APP_NAME} ${VERSION}"
OutFile "dist\leshy-${VERSION}-x64-setup.exe"
InstallDir "$PROGRAMFILES64\leshy"
InstallDirRegKey HKLM "${UNINST_KEY}" "InstallLocation"
RequestExecutionLevel admin

Var CONFIG_PATH

!insertmacro MUI_PAGE_LICENSE "stage\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Install"
  StrCpy $CONFIG_PATH "${DATA_DIR}\config.toml"

  ; Upgrade path: stop and delete any previous service so the binary is
  ; unlocked and the service definition is re-created cleanly.
  DetailPrint "Stopping previous ${APP_NAME} service (if any)"
  nsExec::ExecToLog '"$SYSDIR\sc.exe" stop ${SERVICE_NAME}'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\sc.exe" delete ${SERVICE_NAME}'
  Pop $0
  Sleep 500

  SetOutPath "$INSTDIR"
  File "stage\leshy.exe"
  File "/oname=config.example.toml" "stage\config.example.toml"
  File "stage\LICENSE"

  ; Machine-wide data layout under C:\ProgramData\leshy.
  CreateDirectory "${DATA_DIR}\run"
  CreateDirectory "${DATA_DIR}\logs"
  ; $PLUGINSDIR is the only location that survives to install time; extract
  ; the seed config there so CopyFiles can reach it on the target machine.
  InitPluginsDir
  File "/oname=$PLUGINSDIR\default-config.toml" "stage\default-config.toml"
  ${If} ${FileExists} "$CONFIG_PATH"
    DetailPrint "Keeping existing config: $CONFIG_PATH"
  ${Else}
    CopyFiles /SILENT "$PLUGINSDIR\default-config.toml" "$CONFIG_PATH"
    DetailPrint "Wrote default config: $CONFIG_PATH"
  ${EndIf}

  DetailPrint "Registering the ${SERVICE_NAME} service"
  nsExec::ExecToLog '"$INSTDIR\leshy.exe" service install --name ${SERVICE_NAME} --config "$CONFIG_PATH"'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONEXCLAMATION "Service registration failed (exit code $0). Re-run it manually from an elevated prompt: $\"$INSTDIR\leshy.exe$\" service install --name ${SERVICE_NAME} --config $\"$CONFIG_PATH$\""
  ${Else}
    DetailPrint "Service registered. Start it with: sc.exe start ${SERVICE_NAME}"
  ${EndIf}

  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayName" "${APP_NAME} (DNS-driven split-tunnel router)"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINST_KEY}" "Publisher" "${APP_NAME} contributors"
  WriteRegStr HKLM "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\leshy.exe"
SectionEnd

Section "Uninstall"
  DetailPrint "Removing the ${SERVICE_NAME} service"
  nsExec::ExecToLog '"$INSTDIR\leshy.exe" service uninstall --name ${SERVICE_NAME}'
  Pop $0

  Delete "$INSTDIR\leshy.exe"
  Delete "$INSTDIR\config.example.toml"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "${UNINST_KEY}"
  ; ${DATA_DIR} (config, device files, logs) is user data and is kept.
SectionEnd
