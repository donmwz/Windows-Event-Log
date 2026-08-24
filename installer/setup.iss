; Inno Setup 6 — Windows Event Log Monitor (SQLite)
#define MyAppName "Windows Event Log Monitor"
#define MyAppVersion "1.1.0"
#define MyAppPublisher "Windows Event Log"
#define MyAppExeName "WindowsEventLog.exe"

[Setup]
AppId={{8F3C2A1B-9D4E-4F6A-B2C1-7E5D0A9F3B21}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\WindowsEventLog
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=WindowsEventLog-Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\dist\WindowsEventLog\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{#MyAppName} (Yonetici)"; Filename: "{app}\{#MyAppExeName}"; Flags: runasadmin
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
  MsgBox(
    'Kurulumdan sonra WindowsEventLog.exe ile baslatabilirsiniz.' + #13#10 +
    'Veriler gomulu SQLite dosyasinda saklanir (Docker gerekmez).' + #13#10 + #13#10 +
    'Security event loglari icin programi Yonetici olarak calistirin.',
    mbInformation, MB_OK);
end;
