; Global Ghost Net — Windows installer.
;
; Build with scripts/build_installer.ps1 (which stages the payload and passes
; the version), or run ISCC manually from this directory:
;
;     ISCC.exe /DMyAppVersion=0.4.1 /DMyAppVersionQuad=0.4.1.0 installer\ggn.iss
;
; Design notes, because installers are easy to get subtly wrong:
;
;   * Per-user, no UAC. `PrivilegesRequired=lowest` puts the program in
;     %LOCALAPPDATA%\Programs\GlobalGhostNet and the Add/Remove Programs entry
;     under HKCU. Any user can install it, nothing needs administrator rights,
;     and no elevation prompt appears — which is what a consumer VPN app should
;     do. Inno writes the "Apps & Features" entry itself (display name, version,
;     publisher, icon, size and UninstallString) as long as the app id below
;     never changes: that id is the app's identity for upgrades and uninstalls.
;
;   * The uninstaller keeps user data by default and *asks* before deleting it.
;     The identity key is not something to throw away behind someone's back, and
;     Inno cannot know about `%APPDATA%\GlobalGhostNet` on its own.
;
;   * The payload comes from a staging directory the build script prepares, so
;     this file never has to care where cargo put the binary.

#define MyAppName "Global Ghost Net"
#define MyAppExeName "ggn.exe"
#define MyAppShortName "ggn"
#define MyAppDirName "GlobalGhostNet"
#define MyAppPublisher "Keller Systems"
#define MyAppURL "https://ggn.kellersystems.dev/"
#define MyAppRepoURL "https://github.com/KELLERBABG/Global-Ghost-Net"

; Supplied by the build script from the compiled binary's version resource.
#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif
#ifndef MyAppVersionQuad
  #define MyAppVersionQuad MyAppVersion + ".0"
#endif
; Directory holding the files to install (relative to this .iss file).
#ifndef StageDir
  #define StageDir "..\dist\staging"
#endif

[Setup]
; The app id must stay identical for the lifetime of the product: Windows keys
; upgrades and the uninstall entry off it. The doubled "{{" is how Inno escapes
; a literal "{" in a directive value.
AppId={{8CF92C03-D5CA-45A7-8FA7-7DF96986EB4D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppRepoURL}/issues
AppUpdatesURL={#MyAppRepoURL}/releases
AppComments=A private mesh network for your own devices. No accounts, no central servers.
DefaultDirName={autopf}\{#MyAppDirName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
DisableDirPage=auto
AllowNoIcons=yes
PrivilegesRequired=lowest
; The desktop build is 64-bit only (WebView2 / Wintun).
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
; Handles an already-running copy on upgrade instead of showing "file in use".
CloseApplications=yes
RestartApplications=yes
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
OutputDir=..\dist
OutputBaseFilename={#MyAppShortName}-{#MyAppVersion}-windows-setup
SetupIconFile=..\assets\icon.ico
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
VersionInfoVersion={#MyAppVersionQuad}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} Setup
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersionQuad}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#StageDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; A single Start Menu shortcut, not a one-item folder.
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Comment: "Open the Global Ghost Net control center"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Registry]
; Makes the app findable by name (Win+R -> "ggn", and ShellExecute lookups).
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\App Paths\{#MyAppExeName}"; \
    ValueType: string; ValueName: ""; ValueData: "{app}\{#MyAppExeName}"; Flags: uninsdeletekey

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; \
    Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Two folders the uninstaller has no record of, because neither was created by
; Setup: both hold only regenerable WebView2 browser cache, which is why removing
; them is unconditional.
;
;   1. The redirected cache in the user's local (non-roaming) profile, which is
;      where current builds put it on purpose.
;   2. The old location beside the executable, for anyone upgrading from a build
;      that still let WebView2 pick its own spot.
Type: filesandordirs; Name: "{localappdata}\{#MyAppDirName}\webview2"
Type: filesandordirs; Name: "{app}\{#MyAppExeName}.WebView2"

[Code]

const
  { Where the application keeps its state, and the product's WebView2 id. }
  DataDirName = 'GlobalGhostNet';
  WebView2Client = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';

{ Is a WebView2 runtime registered in any of the places it can live? }
function WebView2RuntimePresent: Boolean;
var
  Version: String;
begin
  Result :=
    RegQueryStringValue(HKLM64, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\' + WebView2Client, 'pv', Version) or
    RegQueryStringValue(HKLM32, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\' + WebView2Client, 'pv', Version) or
    RegQueryStringValue(HKCU, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\' + WebView2Client, 'pv', Version);
end;

procedure InitializeWizard;
begin
  { Not a blocker: without WebView2 the app still runs and serves its control
    center to a normal browser tab. Warning up front is kinder than letting
    someone wonder why no window appeared. }
  if WebView2RuntimePresent then
    exit;

  Log('WebView2 runtime not detected; the application will fall back to a browser tab.');
  { Never prompt during an unattended install: those run with no one to answer,
    and a modal dialog would simply hang the deployment. }
  if WizardSilent then
    exit;

  MsgBox('The Microsoft Edge WebView2 runtime was not found on this PC.' + #13#10 + #13#10 +
         'Global Ghost Net normally opens its own window. Without WebView2 it will ' +
         'fall back to opening the control center in your default browser instead.' + #13#10 + #13#10 +
         'To get the native window, install the free runtime from:' + #13#10 +
         'https://developer.microsoft.com/microsoft-edge/webview2/',
         mbInformation, MB_OK);
end;

{ Remove state files that a build from before the per-user data directory could
  have dropped next to the executable. Only ever called when the user has
  explicitly asked for their data to be deleted. }
procedure RemoveLegacyStateFiles;
var
  Names: TArrayOfString;
  I: Integer;
begin
  SetArrayLength(Names, 6);
  Names[0] := 'identity.key';
  Names[1] := 'peers.cache';
  Names[2] := 'ghost-consumer.json';
  Names[3] := 'ghost-consumer.json.tmp';
  Names[4] := 'ghost-topology.json';
  Names[5] := 'ghost.log';
  for I := 0 to GetArrayLength(Names) - 1 do
    DeleteFile(ExpandConstant('{app}\' + Names[I]));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep <> usPostUninstall then
    exit;
  { A silent uninstall must never destroy an identity key. }
  if UninstallSilent then
    exit;
  DataDir := ExpandConstant('{userappdata}\' + DataDirName);
  if not DirExists(DataDir) then
    exit;

  if MsgBox('Also delete your Global Ghost Net identity key and settings?' + #13#10 + #13#10 +
            DataDir + #13#10 + #13#10 +
            'Choose No to keep them. A later reinstall then comes back as the same ' +
            'device, with the same name and pairings.',
            mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
  begin
    DelTree(DataDir, True, True, True);
    RemoveLegacyStateFiles;
  end;
end;
