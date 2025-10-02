
; miqro_gui_installer.iss — Inno Setup script for Miqrochain GUI + daemon
; Build with: "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" miqro_gui_installer.iss

#define MyAppName "Miqrochain Core"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "Miqrochain"
#define MyAppURL "https://github.com/your-org/miqrochain"
#define MyAppExeName "miqro-gui.exe"

; ============================================================================
[Setup]
AppId={{B9B4C2F3-8C39-4D8E-9B3E-2F5D7F7D0F21}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\Miqrochain
DefaultGroupName=Miqrochain
DisableDirPage=no
DisableProgramGroupPage=no
OutputDir=dist\installer
OutputBaseFilename=miqrochain-setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
WizardStyle=modern
UninstallDisplayIcon={app}\bin\{#MyAppExeName}
SetupLogging=yes

; ============================================================================
[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"

; ============================================================================
[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"; Flags: unchecked
Name: "startoninstall"; Description: "Start Miqrochain Core after installation"; GroupDescription: "Post-install:"; Flags: unchecked

; ============================================================================
[Dirs]
; Ensure app bin dir exists
Name: "{app}\bin"

; ============================================================================
[Files]
; Bundle everything from your staging folder "dist\Miqrochain\"
; Put miqro-gui.exe, miqrod.exe, Qt DLLs, platforms\*, etc. there before compiling.
Source: "dist\Miqrochain\*"; DestDir: "{app}\bin"; Flags: recursesubdirs createallsubdirs ignoreversion

; ============================================================================
[Icons]
Name: "{group}\Miqrochain Core"; Filename: "{app}\bin\{#MyAppExeName}"
Name: "{group}\Uninstall Miqrochain"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Miqrochain Core"; Filename: "{app}\bin\{#MyAppExeName}"; Tasks: desktopicon

; ============================================================================
[Run]
; Optionally open inbound P2P port 9833 in Windows Firewall (TCP)
Filename: "{cmd}"; \
  Parameters: "/c netsh advfirewall firewall add rule name=""Miqrochain P2P 9833"" dir=in action=allow protocol=TCP localport=9833"; \
  Flags: runhidden runascurrentuser

; Start the app if requested
Filename: "{app}\bin\{#MyAppExeName}"; Description: "Launch Miqrochain Core"; Flags: nowait postinstall skipifsilent; Tasks: startoninstall

; ============================================================================
[UninstallRun]
; Remove firewall rule on uninstall
Filename: "{cmd}"; Parameters: "/c netsh advfirewall firewall delete rule name=""Miqrochain P2P 9833"""; Flags: runhidden runascurrentuser

; ============================================================================
[Code]
// (Optional) You can extend with custom logic; not required for basic install.
