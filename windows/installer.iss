#define MyAppName "ICD360S Mail Client"
#define MyAppVersion "2.20.4"
#define MyAppPublisher "ICD360S e.V."
#define MyAppURL "https://icd360s.de"
#define MyAppExeName "icd360s_mail_client.exe"
#define MyAppId "{{B8F3D8E1-7A4C-4E5D-9F2A-3C1E8D6F9A2B}"

[Setup]
; App info
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL=https://mail.icd360s.de/updates/

; Install paths
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes

; Output
OutputDir=..\build\installer
OutputBaseFilename=ICD360S_MailClient_Setup_v{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes

; Windows version
MinVersion=10.0.17763
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; Wizard appearance
WizardStyle=modern

; Uninstall
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}

; Privileges
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "german"; MessagesFile: "compiler:Languages\German.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "pintotaskbar"; Description: "Pin to Windows Taskbar (recommended)"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
; Main executable
Source: "..\build\windows\x64\runner\Release\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

; Flutter engine and dependencies
Source: "..\build\windows\x64\runner\Release\*.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\build\windows\x64\runner\Release\data\*"; DestDir: "{app}\data"; Flags: ignoreversion recursesubdirs createallsubdirs

; Visual C++ Redistributable 2015-2025
Source: "redist\vc_redist.x64.exe"; DestDir: "{tmp}"; Flags: ignoreversion deleteafterinstall

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Install VC++ Redistributable silently (skip if already installed)
Filename: "{tmp}\vc_redist.x64.exe"; Parameters: "/install /quiet /norestart"; StatusMsg: "Installing Visual C++ Redistributable..."; Check: VCRedistNeedsInstall; Flags: waituntilterminated
; Launch app after install
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
function VCRedistNeedsInstall: Boolean;
var
  Version: String;
begin
  if RegQueryStringValue(HKLM, 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\X64', 'Version', Version) then
  begin
    Log('VC++ Redistributable found: ' + Version);
    Result := False;
  end
  else
  begin
    Log('VC++ Redistributable NOT found - will install');
    Result := True;
  end;
end;

function InitializeSetup(): Boolean;
begin
  // Check if app is running
  if CheckForMutexes('ICD360S_MailClient_Mutex') then
  begin
    MsgBox('ICD360S Mail Client is currently running.' + #13#10 + 'Please close it and try again.', mbError, MB_OK);
    Result := False;
  end
  else
    Result := True;
end;

function InitializeUninstall(): Boolean;
begin
  // Check if app is running before uninstall
  if CheckForMutexes('ICD360S_MailClient_Mutex') then
  begin
    MsgBox('ICD360S Mail Client is currently running.' + #13#10 + 'Please close it before uninstalling.', mbError, MB_OK);
    Result := False;
  end
  else
    Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    // Pin to taskbar if selected
    if WizardIsTaskSelected('pintotaskbar') then
    begin
      Exec('powershell.exe',
        '-Command "$shell = New-Object -ComObject Shell.Application; ' +
        '$item = $shell.Namespace(''' + ExpandConstant('{app}') + ''').ParseName(''' +
        ExpandConstant('{#MyAppExeName}') + '''); ' +
        '$item.InvokeVerb(''taskbarpin'')"',
        '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    end;
  end;
end;



