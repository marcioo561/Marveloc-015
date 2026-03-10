; ============================================================
;  Marveloc_Ver_015.iss  —  Inno Setup Compiler script
;
;  PRÉ-REQUISITOS:
;    1. Inno Setup 6.x instalado  (https://jrsoftware.org/isinfo.php)
;    2. PyInstaller já executado:
;         pyinstaller MarveloC_Ver_015.spec --noconfirm
;    3. A pasta dist\Marveloc\ deve existir com Marveloc.exe dentro
;    4. Os arquivos icon.ico, config.json e blocklist.txt devem estar
;       na mesma pasta deste .iss
;
;  COMO COMPILAR:
;    - Abra este arquivo no Inno Setup Compiler
;    - Menu:  Build > Compile   (ou pressione F9)
;    - O instalador será gerado em:  installer\MarvelocSetup_1.5.0.exe
; ============================================================

#define MyAppName        "Marveloc"
#define MyAppVersion     "1.5.0"
#define MyAppPublisher   "Marcio Fernandes"
#define MyAppURL         "https://github.com/marcioo561/Marveloc-Ver9"
#define MyAppExeName     "Marveloc.exe"
#define MyAppDir         "dist\Marveloc"
#define MyAppDataDir     "{localappdata}\Marveloc"

; ── [Setup] ─────────────────────────────────────────────────────────
[Setup]
; GUID único — NÃO altere após a primeira publicação pública
AppId={{B0B7A2E3-9A2D-4C6A-9B5B-0E6F9C2A1115}

AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}

; Diretório de instalação padrão
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes

; Ícone do instalador (deve estar na mesma pasta do .iss)
SetupIconFile=icon.ico

; ── Imagens do assistente de instalação (descomente se criar os arquivos) ──
; WizardImageFile=assets\wizard_banner.bmp         ; 164 x 314 px (lateral)
; WizardSmallImageFile=assets\wizard_small.bmp     ; 55 x 55 px   (canto)

; Saída do instalador gerado
OutputDir=installer
OutputBaseFilename=MarvelocSetup_{#MyAppVersion}

; Compressão máxima LZMA2
Compression=lzma2/ultra64
SolidCompression=yes
LZMAUseSeparateProcess=yes
LZMADictionarySize=1048576

; Visual moderno do assistente
WizardStyle=modern
ShowLanguageDialog=no

; Requer administrador (necessário para instalar em Arquivos de Programas)
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog

; Metadados visíveis em Propriedades do instalador
VersionInfoVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=Instalador do Navegador {#MyAppName}
VersionInfoCopyright=© 2025 {#MyAppPublisher}
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}

; Ícone e nome visíveis em "Aplicativos e recursos" do Windows
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName} {#MyAppVersion}

; Impede iniciar o instalador se o app já estiver em execução
CloseApplications=yes
CloseApplicationsFilter=*.exe
RestartApplications=no

; Suporte a instalação silenciosa via linha de comando:
;   MarvelocSetup.exe /SILENT          (mostra progress, sem perguntas)
;   MarvelocSetup.exe /VERYSILENT      (completamente silencioso)
;   MarvelocSetup.exe /DIR="C:\Pasta"  (define pasta de instalação)

; ── [Languages] ─────────────────────────────────────────────────────
[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"
Name: "english";             MessagesFile: "compiler:Default.isl"

; ── [Tasks] ─────────────────────────────────────────────────────────
[Tasks]
Name: "desktopicon";         Description: "Criar ícone na Área de Trabalho";            GroupDescription: "Atalhos adicionais:"; Flags: unchecked
Name: "startuprun";          Description: "Iniciar Marveloc automaticamente com o Windows"; GroupDescription: "Inicialização:";    Flags: unchecked
Name: "setdefaultbrowser";   Description: "Definir Marveloc como navegador padrão";      GroupDescription: "Preferências:";      Flags: unchecked

; ── [Files] ─────────────────────────────────────────────────────────
[Files]
; ── Executável e todos os arquivos gerados pelo PyInstaller ──────────
Source: "{#MyAppDir}\*";     DestDir: "{app}";  Flags: recursesubdirs ignoreversion createallsubdirs

; ── Arquivos de dados do projeto (criados apenas se não existirem) ───
Source: "config.json";       DestDir: "{app}";  Flags: ignoreversion onlyifdoesntexist
Source: "blocklist.txt";     DestDir: "{app}";  Flags: ignoreversion onlyifdoesntexist
Source: "icon.ico";          DestDir: "{app}";  Flags: ignoreversion

; ── [Icons] ─────────────────────────────────────────────────────────
[Icons]
; Menu Iniciar
Name: "{group}\{#MyAppName}";              Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"; Comment: "Navegador Marveloc — Privacidade e Segurança"
Name: "{group}\Desinstalar {#MyAppName}";  Filename: "{uninstallexe}";        IconFilename: "{app}\icon.ico"

; Área de Trabalho (somente se a task estiver marcada)
Name: "{autodesktop}\{#MyAppName}";        Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"; Tasks: desktopicon; Comment: "Navegador Marveloc"

; Janela Privada (atalho direto para modo anônimo)
Name: "{group}\{#MyAppName} — Janela Privada"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--private"; IconFilename: "{app}\icon.ico"; Comment: "Abrir uma janela privada do Marveloc"

; ── [Registry] ──────────────────────────────────────────────────────
[Registry]
; Registra o app em "Aplicativos e recursos" (Painel de Controle / Configurações)
Root: HKLM; Subkey: "Software\{#MyAppPublisher}\{#MyAppName}"; ValueType: string; ValueName: "Version";    ValueData: "{#MyAppVersion}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\{#MyAppPublisher}\{#MyAppName}"; ValueType: string; ValueName: "InstallDir"; ValueData: "{app}";           Flags: uninsdeletekey

; Iniciar com o Windows (somente se task marcada)
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#MyAppName}"; ValueData: """{app}\{#MyAppExeName}"""; Flags: uninsdeletevalue; Tasks: startuprun

; Registro de "Abrir com" para links http/https (base para navegador padrão)
Root: HKLM; Subkey: "Software\Clients\StartMenuInternet\{#MyAppName}";                              ValueType: string; ValueName: "";          ValueData: "{#MyAppName}";              Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Clients\StartMenuInternet\{#MyAppName}\Capabilities";                ValueType: string; ValueName: "ApplicationName";        ValueData: "{#MyAppName}";         Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Clients\StartMenuInternet\{#MyAppName}\Capabilities";                ValueType: string; ValueName: "ApplicationDescription"; ValueData: "Navegador Marveloc — Privacidade e Segurança"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Clients\StartMenuInternet\{#MyAppName}\Capabilities\URLAssociations"; ValueType: string; ValueName: "http";    ValueData: "MarvelocHTML";              Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Clients\StartMenuInternet\{#MyAppName}\Capabilities\URLAssociations"; ValueType: string; ValueName: "https";   ValueData: "MarvelocHTML";              Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Clients\StartMenuInternet\{#MyAppName}\shell\open\command";           ValueType: string; ValueName: "";          ValueData: """{app}\{#MyAppExeName}"" ""%1"""; Flags: uninsdeletekey

; Classe ProgID para associação de protocolo
Root: HKLM; Subkey: "Software\Classes\MarvelocHTML";                         ValueType: string; ValueName: "";          ValueData: "URL do Marveloc";                  Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\MarvelocHTML";                         ValueType: string; ValueName: "FriendlyTypeName"; ValueData: "Página Web do Marveloc";   Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\MarvelocHTML\shell\open\command";      ValueType: string; ValueName: "";          ValueData: """{app}\{#MyAppExeName}"" ""%1"""; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\RegisteredApplications";                       ValueType: string; ValueName: "{#MyAppName}"; ValueData: "Software\Clients\StartMenuInternet\{#MyAppName}\Capabilities"; Flags: uninsdeletevalue

; ── [Run] ───────────────────────────────────────────────────────────
[Run]
; Abre o Marveloc ao fim da instalação (checkbox opcional)
Filename: "{app}\{#MyAppExeName}"; Description: "Executar {#MyAppName} agora"; Flags: nowait postinstall skipifsilent

; Define como navegador padrão via configurações do Windows (se task marcada)
Filename: "{sys}\control.exe"; Parameters: "/name Microsoft.DefaultPrograms /page pageDefaultProgram"; Description: "Definir como navegador padrão"; Flags: nowait postinstall skipifsilent shellexec; Tasks: setdefaultbrowser

; ── [UninstallDelete] ───────────────────────────────────────────────
[UninstallDelete]
; Remove pasta de dados de sessão temporária (preserva perfis do usuário)
Type: filesandordirs; Name: "{app}\data"
Type: filesandordirs; Name: "{app}\__pycache__"

; OPCIONAL — descomente para apagar TODOS os dados do usuário ao desinstalar:
; Type: filesandordirs; Name: "{#MyAppDataDir}"

; ── [Code] ──────────────────────────────────────────────────────────
[Code]

// ── Verifica se o Marveloc já está em execução ──────────────────────
function IsAppRunning(const FileName: String): Boolean;
var
  FSWbemLocator: Variant;
  FWMIService:   Variant;
  FWbemObjectSet: Variant;
begin
  Result := False;
  try
    FSWbemLocator  := CreateOleObject('WbemScripting.SWbemLocator');
    FWMIService    := FSWbemLocator.ConnectServer('', 'root\CIMV2', '', '');
    FWbemObjectSet := FWMIService.ExecQuery(
      Format('SELECT * FROM Win32_Process WHERE Name="%s"', [FileName])
    );
    Result := (FWbemObjectSet.Count > 0);
  except
    // Se WMI não disponível, continua sem bloquear
    Result := False;
  end;
end;

// ── Inicialização: verifica processo em execução ─────────────────────
function InitializeSetup(): Boolean;
begin
  if IsAppRunning('Marveloc.exe') then
  begin
    MsgBox(
      'O Marveloc está em execução.' + #13#10 +
      'Por favor, feche o navegador antes de continuar a instalação.',
      mbError, MB_OK
    );
    Result := False;
    Exit;
  end;
  Result := True;
end;

// ── Inicialização da desinstalação ───────────────────────────────────
function InitializeUninstall(): Boolean;
begin
  if IsAppRunning('Marveloc.exe') then
  begin
    MsgBox(
      'O Marveloc está em execução.' + #13#10 +
      'Por favor, feche o navegador antes de desinstalar.',
      mbError, MB_OK
    );
    Result := False;
    Exit;
  end;
  Result := True;
end;

// ── Mensagem de boas-vindas personalizada ────────────────────────────
function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
end;

// ── Ao concluir: mostra mensagem com dica de uso ────────────────────
procedure DeinitializeSetup();
begin
  // Executado após o instalador terminar (com ou sem sucesso)
end;
