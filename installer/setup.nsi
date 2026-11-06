; Perf Saver - installeur Windows (NSIS)
; makensis -DVERSION=1.0.0 -DSRC=<dossier contenant PerfSaver.exe et WebView2Loader.dll> installer/setup.nsi
Unicode true
!include "MUI2.nsh"
!ifndef VERSION
  !define VERSION "1.0.0"
!endif
!ifndef SRC
  !define SRC "..\dist"
!endif
!define APP "Perf Saver"
!define UNKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\PerfSaver"

Name "${APP}"
OutFile "${SRC}\PerfSaver-Setup-${VERSION}.exe"
InstallDir "$PROGRAMFILES64\Perf Saver"
InstallDirRegKey HKLM "${UNKEY}" "InstallLocation"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
BrandingText "${APP} ${VERSION}"

!define MUI_ICON "..\src-tauri\icons\icon.ico"
!define MUI_UNICON "..\src-tauri\icons\icon.ico"
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "Installation de ${APP} ${VERSION}"
!define MUI_WELCOMEPAGE_TEXT "${APP} libère ton PC pendant que tu joues : il ferme ce qui est inutile, met en pause les services superflus et donne la priorité à ton jeu.$\r$\n$\r$\nTout est réversible et rien n'est envoyé sur Internet.$\r$\n$\r$\nClique sur Suivant pour continuer."
!define MUI_LICENSEPAGE_CHECKBOX
!define MUI_FINISHPAGE_RUN "$INSTDIR\PerfSaver.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Lancer ${APP}"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENCE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "French"

VIProductVersion "${VERSION}.0"
VIAddVersionKey /LANG=${LANG_FRENCH} "ProductName" "${APP}"
VIAddVersionKey /LANG=${LANG_FRENCH} "FileDescription" "Installation de ${APP}"
VIAddVersionKey /LANG=${LANG_FRENCH} "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=${LANG_FRENCH} "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=${LANG_FRENCH} "LegalCopyright" "(c) 2026 Grenofar - Licence MIT"

Section "Install"
  nsExec::Exec 'taskkill /f /im PerfSaver.exe'
  Sleep 400
  SetOutPath "$INSTDIR"
  File "${SRC}\PerfSaver.exe"
  File "${SRC}\WebView2Loader.dll"
  File "LICENCE.txt"
  WriteUninstaller "$INSTDIR\Desinstaller.exe"
  CreateShortcut "$DESKTOP\${APP}.lnk" "$INSTDIR\PerfSaver.exe"
  CreateShortcut "$SMPROGRAMS\${APP}.lnk" "$INSTDIR\PerfSaver.exe"
  WriteRegStr HKLM "${UNKEY}" "DisplayName" "${APP}"
  WriteRegStr HKLM "${UNKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNKEY}" "Publisher" "Grenofar"
  WriteRegStr HKLM "${UNKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNKEY}" "DisplayIcon" "$INSTDIR\PerfSaver.exe"
  WriteRegStr HKLM "${UNKEY}" "UninstallString" '"$INSTDIR\Desinstaller.exe"'
  WriteRegDWORD HKLM "${UNKEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNKEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  nsExec::Exec 'taskkill /f /im PerfSaver.exe'
  nsExec::Exec 'schtasks /delete /tn PerfSaver /f'
  Sleep 400
  Delete "$INSTDIR\PerfSaver.exe"
  Delete "$INSTDIR\WebView2Loader.dll"
  Delete "$INSTDIR\LICENCE.txt"
  Delete "$INSTDIR\Desinstaller.exe"
  RMDir "$INSTDIR"
  Delete "$DESKTOP\${APP}.lnk"
  Delete "$SMPROGRAMS\${APP}.lnk"
  DeleteRegKey HKLM "${UNKEY}"
SectionEnd
