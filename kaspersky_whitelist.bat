@echo off
:: ================================================================
::  kaspersky_whitelist.bat  —  Submissão ao Kaspersky Whitelist
::  e coleta de informações para portais de antivírus
::
::  Este script:
::    1. Calcula hashes SHA256 de todos os arquivos do build
::    2. Gera um relatório de submissão formatado
::    3. Abre os portais corretos de whitelist de cada AV
::    4. Gera o arquivo manifest.json para submissão automatizada
:: ================================================================
setlocal EnableDelayedExpansion

set APP_NAME=Marveloc
set APP_VERSION=1.5.0
set APP_EXE=dist\%APP_NAME%\%APP_NAME%.exe
set INSTALLER=installer\MarvelocSetup_%APP_VERSION%.exe
set REPORT_FILE=whitelist_submission_%APP_VERSION%.txt
set HASH_FILE=hashes_%APP_VERSION%.txt

echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║     Marveloc — Submissao para Whitelist de AV        ║
echo  ╚══════════════════════════════════════════════════════╝
echo.

:: ── ETAPA 1: Calcula hashes ──────────────────────────────────────
echo [1/4] Calculando hashes SHA256...
echo. > "%HASH_FILE%"
echo ═══════════════════════════════════════════════════════ >> "%HASH_FILE%"
echo  Marveloc %APP_VERSION% — Hashes SHA256                >> "%HASH_FILE%"
echo  Gerado em: %DATE% %TIME%                              >> "%HASH_FILE%"
echo ═══════════════════════════════════════════════════════ >> "%HASH_FILE%"
echo. >> "%HASH_FILE%"

if exist "%APP_EXE%" (
    echo [Executável principal] >> "%HASH_FILE%"
    certutil -hashfile "%APP_EXE%" SHA256 | findstr /v "hash" >> "%HASH_FILE%"
    echo. >> "%HASH_FILE%"
)

if exist "%INSTALLER%" (
    echo [Instalador] >> "%HASH_FILE%"
    certutil -hashfile "%INSTALLER%" SHA256 | findstr /v "hash" >> "%HASH_FILE%"
    echo. >> "%HASH_FILE%"
)

:: Hashes de todos os .exe no dist
echo [Todos os executáveis em dist\%APP_NAME%\] >> "%HASH_FILE%"
for /r "dist\%APP_NAME%" %%f in (*.exe *.dll) do (
    echo %%~nxf >> "%HASH_FILE%"
    certutil -hashfile "%%f" SHA256 | findstr /v "hash" >> "%HASH_FILE%"
)

echo       Hashes salvos em: %HASH_FILE%

:: ── ETAPA 2: Gera relatório de submissão ─────────────────────────
echo.
echo [2/4] Gerando relatorio de submissao...

(
echo ═══════════════════════════════════════════════════════════════
echo  RELATORIO DE SUBMISSAO PARA WHITELIST DE ANTIVIRUS
echo  Aplicativo: %APP_NAME% %APP_VERSION%
echo  Data: %DATE% %TIME%
echo ═══════════════════════════════════════════════════════════════
echo.
echo INFORMACOES DO APLICATIVO:
echo   Nome:          Marveloc Browser
echo   Versao:        %APP_VERSION%
echo   Desenvolvedor: Marcio Fernandes
echo   Website:       https://github.com/marcioo561/Marveloc-Ver9
echo   Descricao:     Navegador web focado em privacidade, construido
echo                  com Python/PyQt5 e QtWebEngine (Chromium).
echo   Categoria:     Browser / Utilitario
echo   Plataforma:    Windows 10/11 x64
echo.
echo TECNOLOGIAS UTILIZADAS:
echo   - Python 3.x (via PyInstaller)
echo   - PyQt5 + QtWebEngine (Chromium)
echo   - SQLite3 (historico e favoritos)
echo   - PyCryptodome (AES-GCM, criptografia local)
echo   - pywin32 (integracao Windows API / DPAPI)
echo.
echo COMPORTAMENTOS DO PROCESSO:
echo   - Cria pasta de dados em: %%LOCALAPPDATA%%\Marveloc\ (perfis)
echo   - Escreve SQLite em:      %%APPDATA%%\Marveloc\data\
echo   - Lanca processo filho:   QtWebEngineProcess.exe (Chromium renderer)
echo   - Acesso a rede:          HTTP/HTTPS (navegacao web normal)
echo   - SEM acesso a:           Microfone, Camera, Clipboard sem acao do usuario
echo   - SEM auto-update:        Nao faz download de codigo executavel
echo   - SEM mineracao:          Nao usa GPU/CPU para criptografia externa
echo.
echo HASHES SHA256:
) > "%REPORT_FILE%"

if exist "%APP_EXE%" (
    echo   Marveloc.exe: >> "%REPORT_FILE%"
    certutil -hashfile "%APP_EXE%" SHA256 | findstr /v "hash" >> "%REPORT_FILE%"
)
if exist "%INSTALLER%" (
    echo   MarvelocSetup_%APP_VERSION%.exe: >> "%REPORT_FILE%"
    certutil -hashfile "%INSTALLER%" SHA256 | findstr /v "hash" >> "%REPORT_FILE%"
)

(
echo.
echo PORTAIS DE SUBMISSAO UTILIZADOS:
echo   [x] Kaspersky:  https://opentip.kaspersky.com / https://whitelist.kaspersky.com
echo   [x] VirusTotal: https://virustotal.com
echo   [x] Microsoft:  https://www.microsoft.com/en-us/wdsi/filesubmission
echo   [x] Avast:      https://www.avast.com/false-positive-file-form.php
echo   [x] Bitdefender:https://www.bitdefender.com/submit/
echo   [x] Norton:     https://submit.norton.com/
) >> "%REPORT_FILE%"

echo       Relatorio salvo em: %REPORT_FILE%

:: ── ETAPA 3: Gera manifest.json para submissao automatizada ──────
echo.
echo [3/4] Gerando manifest.json...

:: Obtém hash do executável
set EXE_HASH=NAO_ENCONTRADO
if exist "%APP_EXE%" (
    for /f "skip=1 tokens=*" %%h in ('certutil -hashfile "%APP_EXE%" SHA256') do (
        if not defined _EXE_HASH_SET (
            set EXE_HASH=%%h
            set _EXE_HASH_SET=1
        )
    )
)

(
echo {
echo   "application": {
echo     "name": "Marveloc Browser",
echo     "version": "%APP_VERSION%",
echo     "developer": "Marcio Fernandes",
echo     "website": "https://github.com/marcioo561/Marveloc-Ver9",
echo     "description": "Privacy-focused web browser built with Python/PyQt5 and QtWebEngine",
echo     "category": "browser",
echo     "platform": "windows",
echo     "architecture": "x64"
echo   },
echo   "files": [
echo     {
echo       "filename": "Marveloc.exe",
echo       "sha256": "!EXE_HASH!",
echo       "type": "main_executable",
echo       "description": "Main browser process"
echo     },
echo     {
echo       "filename": "QtWebEngineProcess.exe",
echo       "sha256": "see hashes_%APP_VERSION%.txt",
echo       "type": "child_process",
echo       "description": "Chromium renderer process (Qt)"
echo     }
echo   ],
echo   "behaviors": {
echo     "network_access": true,
echo     "file_write_paths": ["%%LOCALAPPDATA%%\\Marveloc", "%%APPDATA%%\\Marveloc"],
echo     "registry_keys": ["HKLM\\Software\\Marcio Fernandes\\Marveloc"],
echo     "child_processes": ["QtWebEngineProcess.exe"],
echo     "autostart": false,
echo     "self_update": false,
echo     "code_injection": false,
echo     "kernel_access": false
echo   },
echo   "build": {
echo     "tool": "PyInstaller 6.x",
echo     "python_version": "3.x",
echo     "framework": "PyQt5 + QtWebEngine",
echo     "signed": true,
echo     "timestamp_server": "http://timestamp.sectigo.com"
echo   }
echo }
) > manifest.json

echo       manifest.json gerado.

:: ── ETAPA 4: Abre portais de submissao ───────────────────────────
echo.
echo [4/4] Abrindo portais de whitelist...
echo.
echo  ┌─────────────────────────────────────────────────────┐
echo  │  Portais que serao abertos no navegador:            │
echo  │                                                     │
echo  │  1. Kaspersky OpenTIP / Whitelist Program           │
echo  │  2. VirusTotal (analise + feedback)                 │
echo  │  3. Microsoft Defender Submission                   │
echo  └─────────────────────────────────────────────────────┘
echo.
echo  Pressione qualquer tecla para abrir os portais...
pause >nul

start "" "https://opentip.kaspersky.com"
timeout /t 2 /nobreak >nul
start "" "https://whitelist.kaspersky.com/en"
timeout /t 2 /nobreak >nul
start "" "https://www.virustotal.com/gui/home/upload"
timeout /t 2 /nobreak >nul
start "" "https://www.microsoft.com/en-us/wdsi/filesubmission"

:: ── RESUMO ───────────────────────────────────────────────────────
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║           SUBMISSAO PREPARADA COM SUCESSO!           ╔
echo  ╚══════════════════════════════════════════════════════╝
echo.
echo  Arquivos gerados:
echo    %REPORT_FILE%     ← copie o conteudo nos formularios
echo    %HASH_FILE%        ← lista de hashes de todos os arquivos
echo    manifest.json              ← metadados estruturados
echo.
echo  INSTRUCOES PARA CADA PORTAL:
echo  ─────────────────────────────────────────────────────────
echo.
echo  [KASPERSKY]
echo    1. Acesse: https://whitelist.kaspersky.com/en
echo    2. Clique "Submit files for review"
echo    3. Envie: Marveloc.exe + QtWebEngineProcess.exe + instalador
echo    4. Categoria: "Browser / Internet tool"
echo    5. Cole o conteudo de "%REPORT_FILE%" no campo de descricao
echo    6. Prazo de resposta: 3 a 10 dias uteis
echo.
echo  [VIRUSTOTAL]
echo    1. Acesse: https://virustotal.com
echo    2. Faca upload do instalador
echo    3. Se deteccao for falso positivo:
echo       - Clique no AV que detectou
echo       - "Report incorrect detection"
echo    4. Use o hash SHA256 para acompanhar o status
echo.
echo  [MICROSOFT DEFENDER]
echo    1. Acesse: https://www.microsoft.com/en-us/wdsi/filesubmission
echo    2. Login com conta Microsoft (pode ser pessoal)
echo    3. Submit type: "I believe this file is safe"
echo    4. Envie o instalador .exe
echo.
pause
endlocal
