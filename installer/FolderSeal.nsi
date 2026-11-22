; Copyright (c) EurekaGao. Installer contains program files only.
Unicode true
RequestExecutionLevel admin
ManifestDPIAware true
SetCompressor /SOLID lzma
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
!include "x64.nsh"
!include "WinVer.nsh"

!ifndef PROJECT_ROOT
  !define PROJECT_ROOT "${__FILEDIR__}\.."
!endif
!define PRODUCT "密封夹"
!define PRODUCT_ID "EurekaGao.FolderSeal"
!define VERSION "2.10.0"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_ID}"
!define PRODUCT_MARKER "EurekaGao.FolderSeal.v1"

Name "${PRODUCT}"
OutFile "${PROJECT_ROOT}\artifacts\dist\FolderSeal-${VERSION}-Setup.exe"
InstallDir "$PROGRAMFILES\EurekaGao\FolderSeal"
ShowInstDetails show
ShowUninstDetails show
BrandingText "EurekaGao"
VIProductVersion "${VERSION}.0"
VIAddVersionKey /LANG=2052 "ProductName" "${PRODUCT}"
VIAddVersionKey /LANG=2052 "CompanyName" "EurekaGao"
VIAddVersionKey /LANG=2052 "FileDescription" "密封夹安装程序"
VIAddVersionKey /LANG=2052 "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=2052 "LegalCopyright" "Copyright (c) EurekaGao"

!define MUI_ABORTWARNING
!define MUI_ICON "${PROJECT_ROOT}\assets\FolderSeal.ico"
!define MUI_UNICON "${PROJECT_ROOT}\assets\FolderSeal.ico"
!define MUI_WELCOMEPAGE_TITLE "安装密封夹"
!define MUI_WELCOMEPAGE_TEXT "在你选择的位置创建独立的加密文件夹，用一个密码打开所有加密文件夹，并限制常规删除。$\r$\n$\r$\n安装程序只安装软件和说明，不会移动、加密或删除你的任何资料。安装后可直接在资源管理器右键加密文件或文件夹。密码需要你在软件中自行设置。$\r$\n$\r$\n安装和运行软件需要管理员授权。"
!define MUI_FINISHPAGE_RUN "$INSTDIR\FolderSeal.exe"
!define MUI_FINISHPAGE_RUN_TEXT "打开密封夹"
!define MUI_FINISHPAGE_RUN_NOTCHECKED
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\使用说明.txt"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "查看使用说明"
!define MUI_FINISHPAGE_SHOWREADME_NOTCHECKED
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH
!insertmacro MUI_LANGUAGE "SimpChinese"

Function .onInit
  SetShellVarContext all
  ${IfNot} ${AtLeastWin10}
    MessageBox MB_OK|MB_ICONSTOP "需要 Windows 10 或更新版本。"
    Abort
  ${EndIf}
  ${If} ${RunningX64}
    SetRegView 64
  ${EndIf}
  ReadRegDWORD $0 HKLM "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" "Release"
  ${If} $0 < 461808
    MessageBox MB_OK|MB_ICONSTOP "此软件需要 .NET Framework 4.7.2 或更新版本。请先安装兼容运行时。"
    Abort
  ${EndIf}
  ; Preserve an explicit /D= directory; only replace the untouched default.
  ${If} $INSTDIR == "$PROGRAMFILES\EurekaGao\FolderSeal"
    ${If} ${RunningX64}
      StrCpy $INSTDIR "$PROGRAMFILES64\EurekaGao\FolderSeal"
    ${EndIf}
    ReadRegStr $0 HKLM "${UNINSTALL_KEY}" "InstallLocation"
    ${If} $0 != ""
      StrCpy $INSTDIR $0
    ${EndIf}
  ${EndIf}
FunctionEnd

Function CheckInstallDirectory
  ; A fresh install must use an empty directory; upgrades require our exact marker.
  IfFileExists "$INSTDIR\.folderseal-product" upgrade fresh
  upgrade:
    ClearErrors
    FileOpen $0 "$INSTDIR\.folderseal-product" r
    IfErrors invalid
    FileRead $0 $1
    FileClose $0
    StrCmp $1 "${PRODUCT_MARKER}" valid invalid
  fresh:
    ClearErrors
    FindFirst $0 $1 "$INSTDIR\*"
    IfErrors valid
  scan:
    StrCmp $1 "." next
    StrCmp $1 ".." next
    FindClose $0
    Goto invalid
  next:
    FindNext $0 $1
    IfErrors endscan
    Goto scan
  endscan:
    FindClose $0
    Goto valid
  invalid:
    MessageBox MB_OK|MB_ICONSTOP "为避免覆盖你的文件，请选择一个空文件夹，或本软件原来的安装目录。"
    Abort
  valid:
FunctionEnd

Section "程序和开始菜单入口（必选）" MainSection
  SectionIn RO
  Call CheckInstallDirectory
  SetOutPath "$INSTDIR"
  SetOverwrite on
  ClearErrors
  File /oname=FolderSeal.exe "${PROJECT_ROOT}\artifacts\bin\FolderSeal.exe"
  File /oname=使用说明.txt "${PROJECT_ROOT}\docs\安装版使用说明.txt"
  IfErrors install_failed
  FileOpen $0 "$INSTDIR\.folderseal-product" w
  FileWrite $0 "${PRODUCT_MARKER}"
  FileClose $0
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  ; Replace legacy product entries during upgrades; keep the desktop opt-in.
  IfFileExists "$DESKTOP\文件夹加密工具（EurekaGao）.lnk" 0 migrate_start_menu
  ClearErrors
  CreateShortcut "$DESKTOP\${PRODUCT}.lnk" "$INSTDIR\FolderSeal.exe"
  IfErrors migrate_start_menu
  Delete "$DESKTOP\文件夹加密工具（EurekaGao）.lnk"
  migrate_start_menu:
  Delete "$SMPROGRAMS\EurekaGao\文件夹加密工具\文件夹加密工具.lnk"
  Delete "$SMPROGRAMS\EurekaGao\文件夹加密工具\使用说明.lnk"
  Delete "$SMPROGRAMS\EurekaGao\文件夹加密工具\卸载.lnk"
  RMDir "$SMPROGRAMS\EurekaGao\文件夹加密工具"
  CreateDirectory "$SMPROGRAMS\EurekaGao\${PRODUCT}"
  CreateShortcut "$SMPROGRAMS\EurekaGao\${PRODUCT}\${PRODUCT}.lnk" "$INSTDIR\FolderSeal.exe"
  CreateShortcut "$SMPROGRAMS\EurekaGao\${PRODUCT}\使用说明.lnk" "$INSTDIR\使用说明.txt"
  CreateShortcut "$SMPROGRAMS\EurekaGao\${PRODUCT}\卸载.lnk" "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayName" "${PRODUCT}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "Publisher" "EurekaGao"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\FolderSeal.exe"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
  WriteRegStr HKLM "${UNINSTALL_KEY}" "QuietUninstallString" '$\"$INSTDIR\Uninstall.exe$\" /S'
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoRepair" 1
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "EstimatedSize" 512
  ; Explorer verbs for the current user; the program switch and uninstaller remove the same keys.
  WriteRegStr HKCU "Software\Classes\Directory\shell\FolderSeal.Seal" "" "加密此文件夹（密封夹）"
  WriteRegStr HKCU "Software\Classes\Directory\shell\FolderSeal.Seal" "Icon" "$\"$INSTDIR\FolderSeal.exe$\",0"
  WriteRegStr HKCU "Software\Classes\Directory\shell\FolderSeal.Seal" "MultiSelectModel" "Single"
  WriteRegStr HKCU "Software\Classes\Directory\shell\FolderSeal.Seal\command" "" "$\"$INSTDIR\FolderSeal.exe$\" --seal $\"%1$\""
  WriteRegStr HKCU "Software\Classes\*\shell\FolderSeal.Seal" "" "加密此文件（密封夹）"
  WriteRegStr HKCU "Software\Classes\*\shell\FolderSeal.Seal" "Icon" "$\"$INSTDIR\FolderSeal.exe$\",0"
  WriteRegStr HKCU "Software\Classes\*\shell\FolderSeal.Seal" "MultiSelectModel" "Single"
  WriteRegStr HKCU "Software\Classes\*\shell\FolderSeal.Seal\command" "" "$\"$INSTDIR\FolderSeal.exe$\" --seal $\"%1$\""
  WriteRegStr HKCU "Software\Classes\Directory\shell\FolderSeal.Open" "" "用密封夹打开"
  WriteRegStr HKCU "Software\Classes\Directory\shell\FolderSeal.Open" "Icon" "$\"$INSTDIR\FolderSeal.exe$\",0"
  WriteRegStr HKCU "Software\Classes\Directory\shell\FolderSeal.Open\command" "" "$\"$INSTDIR\FolderSeal.exe$\" --open-vault $\"%1$\""
  Goto installed
  install_failed:
    MessageBox MB_OK|MB_ICONSTOP "程序文件未能完整安装。请关闭正在运行的软件后重试。"
    SetErrorLevel 1
    Abort
  installed:
SectionEnd

Section /o "创建桌面快捷方式" DesktopSection
  CreateShortcut "$DESKTOP\${PRODUCT}.lnk" "$INSTDIR\FolderSeal.exe"
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${MainSection} "安装程序、使用说明、开始菜单入口和卸载程序。你的加密资料和密码不包含在安装包中。"
  !insertmacro MUI_DESCRIPTION_TEXT ${DesktopSection} "在所有用户桌面创建一个软件启动入口。"
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Function un.onInit
  SetShellVarContext all
  ${If} ${RunningX64}
    SetRegView 64
  ${EndIf}
  ClearErrors
  FileOpen $0 "$INSTDIR\.folderseal-product" r
  IfErrors invalid
  FileRead $0 $1
  FileClose $0
  StrCmp $1 "${PRODUCT_MARKER}" valid
  invalid:
    MessageBox MB_OK|MB_ICONSTOP "安装目录标记不匹配，已停止卸载。"
    Abort
  valid:
FunctionEnd

Section "Uninstall"
  ; No recursive removal: personal data, encrypted folders and sessions are untouched.
  ClearErrors
  Delete "$INSTDIR\FolderSeal.exe"
  IfErrors uninstall_failed
  Delete "$INSTDIR\使用说明.txt"
  Delete "$DESKTOP\文件夹加密工具（EurekaGao）.lnk"
  Delete "$DESKTOP\${PRODUCT}.lnk"
  Delete "$SMPROGRAMS\EurekaGao\${PRODUCT}\${PRODUCT}.lnk"
  Delete "$SMPROGRAMS\EurekaGao\${PRODUCT}\使用说明.lnk"
  Delete "$SMPROGRAMS\EurekaGao\${PRODUCT}\卸载.lnk"
  RMDir "$SMPROGRAMS\EurekaGao\${PRODUCT}"
  RMDir "$SMPROGRAMS\EurekaGao"
  DeleteRegKey HKLM "${UNINSTALL_KEY}"
  Delete "$INSTDIR\.folderseal-product"
  Delete "$INSTDIR\Uninstall.exe"
  DeleteRegKey HKCU "Software\Classes\Directory\shell\FolderSeal.Seal"
  DeleteRegKey HKCU "Software\Classes\*\shell\FolderSeal.Seal"
  DeleteRegKey HKCU "Software\Classes\Directory\shell\FolderSeal.Open"
  RMDir "$INSTDIR"
  Goto removed
  uninstall_failed:
    MessageBox MB_OK|MB_ICONSTOP "程序仍在运行或无法删除。请先关闭软件，再重新卸载。"
    SetErrorLevel 1
    Abort
  removed:
SectionEnd
