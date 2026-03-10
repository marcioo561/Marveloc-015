@echo off
:: ================================================================
::  build.bat  —  Build completo do Marveloc com assinatura digital
::
::  CONFIGURAÇÃO OBRIGATÓRIA (edite as linhas abaixo):
::    CERT_THUMBPRINT  → Thumbprint do seu certificado (ver instrução)
::    CERT_SUBJECT     → Nome exibido na assinatura ("Marcio Fernandes")
::    TIMESTAMP_URL    → Servidor de timestamp da sua CA
::
::  COMO OBTER O THUMBPRINT:
::    1. Pressione Win+R → certmgr.msc
::    2. Pessoal > Certificados > duplo clique no seu cert
::    3. Aba "Detalhes" → role até "Impressão digital"
::    4. Copie o valor hexadecimal (ex: a1b2c3d4e5...)
::
::  PRÉ-REQUISITOS:
::    - Python 3.x com PyInstaller instalado
::    - Windows SDK (signtool.exe) instalado
::    - Inno Setup 6.x instalado
::    - Certificado Code Signing instalado no Windows
:: ================================================================
setlocal EnableDelayedExpansion

:: ────────────────────────────────────────────────────────────────
::  ██  EDITE ESTAS VARIÁVEIS  ██
:: ────────────────────────────────────────────────────────────────

set CERT_THUMBPRINT=SEU_THUMBPRINT_AQUI
set CERT_SUBJECT=Marcio Fernandes
set APP_NAME=Marveloc
set APP_VERSION=1.5.0
set MAIN_SCRIPT=MarveloC_Ver_015.py
set SPEC_FILE=MarveloC_Ver_015.spec
set ISS_FILE=Marveloc_Ver_015.iss

:: Servidor de timestamp (use o da sua CA):
::   Sectigo / Certum:   http://timestamp.sectigo.com
::   DigiCert:           http://timestamp.digicert.com
::   GlobalSign:         http://timestamp.globalsign.com/scripts/timstamp.dll
set TIMESTAMP_URL=http://timestamp.sectigo.com

:: ────────────────────────────────────────────────────────────────
::  Caminhos das ferramentas (ajuste se necessário)
:: ────────────────────────────────────────────────────────────────

:: signtool — busca automaticamente nas versões do Windows SDK
set SIGNTOOL=""
for /f "delims=" %%i in ('where signtool 2^>nul') do set SIGNTOOL="%%i"
if !SIGNTOOL!=="" (
    :: Busca nas pastas padrão do Windows SDK
    for %%v in (10.0.22621.0 10.0.19041.0 10.0.18362.0 10.0.17763.0) do (
        if exist "C:\Program Files (x86)\Windows Kits\10\bin\%%v\x64\signtool.exe" (
            set SIGNTOOL="C:\Program Files (x86)\Windows Kits\10\bin\%%v\x64\signtool.exe"
        )
    )
)

:: Inno Setup Compiler
set ISCC=""
for /f "delims=" %%i in ('where iscc 2^>nul') do set ISCC="%%i"
if !ISCC!=="" (
    if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" set ISCC="C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
    if exist "C:\Program Files\Inno Setup 6\ISCC.exe"       set ISCC="C:\Program Files\Inno Setup 6\ISCC.exe"
)

:: ────────────────────────────────────────────────────────────────
::  INÍCIO DO BUILD
:: ────────────────────────────────────────────────────────────────
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║        Marveloc %APP_VERSION% — Build + Assinatura Digital       ║
echo  ╚══════════════════════════════════════════════════════╝
echo.

:: Verifica se o script principal existe
if not exist "%MAIN_SCRIPT%" (
    echo [ERRO] Arquivo "%MAIN_SCRIPT%" nao encontrado!
    echo        Execute este .bat na pasta do projeto.
    pause & exit /b 1
)

:: ── ETAPA 1: Limpeza ─────────────────────────────────────────────
echo [1/6] Limpando builds anteriores...
if exist "dist\%APP_NAME%" rmdir /s /q "dist\%APP_NAME%"
if exist "build\%APP_NAME%" rmdir /s /q "build\%APP_NAME%"
echo       OK

:: ── ETAPA 2: PyInstaller ─────────────────────────────────────────
echo.
echo [2/6] Compilando com PyInstaller...
echo       Script: %SPEC_FILE%
echo.
pyinstaller "%SPEC_FILE%" --noconfirm
if errorlevel 1 (
    echo.
    echo [ERRO] PyInstaller falhou! Verifique as mensagens acima.
    pause & exit /b 1
)
echo       PyInstaller concluido com sucesso.

:: Verifica se o executável foi gerado
if not exist "dist\%APP_NAME%\%APP_NAME%.exe" (
    echo [ERRO] dist\%APP_NAME%\%APP_NAME%.exe nao foi gerado!
    pause & exit /b 1
)

:: ── ETAPA 3: Assinatura do executável principal ───────────────────
echo.
echo [3/6] Assinando executavel principal...
if !SIGNTOOL!=="" (
    echo [AVISO] signtool.exe nao encontrado. Pulando assinatura.
    echo         Instale o Windows SDK: https://developer.microsoft.com/windows/downloads/windows-sdk/
    goto :skip_sign_exe
)

:: Assina Marveloc.exe
!SIGNTOOL! sign ^
    /sha1 "%CERT_THUMBPRINT%" ^
    /tr "%TIMESTAMP_URL%" ^
    /td sha256 ^
    /fd sha256 ^
    /d "%APP_NAME% Browser" ^
    /du "https://github.com/marcioo561/Marveloc-Ver9" ^
    "dist\%APP_NAME%\%APP_NAME%.exe"

if errorlevel 1 (
    echo [ERRO] Assinatura do executavel falhou!
    echo        Verifique se o certificado esta instalado e o thumbprint esta correto.
    pause & exit /b 1
)
echo       Marveloc.exe assinado com sucesso.

:: Assina também o QtWebEngineProcess.exe (necessário para Chromium)
if exist "dist\%APP_NAME%\QtWebEngineProcess.exe" (
    echo       Assinando QtWebEngineProcess.exe...
    !SIGNTOOL! sign ^
        /sha1 "%CERT_THUMBPRINT%" ^
        /tr "%TIMESTAMP_URL%" ^
        /td sha256 ^
        /fd sha256 ^
        /d "%APP_NAME% — WebEngine Process" ^
        "dist\%APP_NAME%\QtWebEngineProcess.exe"
    echo       QtWebEngineProcess.exe assinado.
)

:skip_sign_exe

:: ── ETAPA 4: Verificação da assinatura ───────────────────────────
echo.
echo [4/6] Verificando assinatura digital...
if !SIGNTOOL!=="" goto :skip_verify

!SIGNTOOL! verify /pa /v "dist\%APP_NAME%\%APP_NAME%.exe" >nul 2>&1
if errorlevel 1 (
    echo [AVISO] Verificacao da assinatura retornou aviso. Continuando...
) else (
    echo       Assinatura verificada com sucesso!
)
:skip_verify

:: ── ETAPA 5: Inno Setup ──────────────────────────────────────────
echo.
echo [5/6] Compilando instalador com Inno Setup...
if !ISCC!=="" (
    echo [AVISO] ISCC.exe nao encontrado. Pulando Inno Setup.
    echo         Instale o Inno Setup 6: https://jrsoftware.org/isinfo.php
    goto :skip_inno
)

if not exist "%ISS_FILE%" (
    echo [AVISO] Arquivo "%ISS_FILE%" nao encontrado. Pulando Inno Setup.
    goto :skip_inno
)

!ISCC! "%ISS_FILE%"
if errorlevel 1 (
    echo [ERRO] Inno Setup falhou!
    pause & exit /b 1
)
echo       Instalador gerado com sucesso.

:: ── ETAPA 6: Assina o instalador gerado ──────────────────────────
echo.
echo [6/6] Assinando instalador...
set INSTALLER_FILE=installer\MarvelocSetup_%APP_VERSION%.exe

if not exist "%INSTALLER_FILE%" (
    echo [AVISO] Instalador nao encontrado em "%INSTALLER_FILE%". Pulando.
    goto :skip_sign_installer
)

if !SIGNTOOL!=="" goto :skip_sign_installer

!SIGNTOOL! sign ^
    /sha1 "%CERT_THUMBPRINT%" ^
    /tr "%TIMESTAMP_URL%" ^
    /td sha256 ^
    /fd sha256 ^
    /d "Instalador do %APP_NAME% %APP_VERSION%" ^
    /du "https://github.com/marcioo561/Marveloc-Ver9" ^
    "%INSTALLER_FILE%"

if errorlevel 1 (
    echo [AVISO] Assinatura do instalador falhou. O .exe pode estar em uso.
) else (
    echo       Instalador assinado com sucesso.
)
:skip_sign_installer
:skip_inno

:: ── RESUMO FINAL ─────────────────────────────────────────────────
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║                  BUILD CONCLUIDO!                    ║
echo  ╚══════════════════════════════════════════════════════╝
echo.
echo  Executavel:   dist\%APP_NAME%\%APP_NAME%.exe
if exist "installer\MarvelocSetup_%APP_VERSION%.exe" (
    echo  Instalador:   installer\MarvelocSetup_%APP_VERSION%.exe
)
echo.
echo  Proximos passos:
echo    1. Teste o executavel em uma maquina limpa (sem Python)
echo    2. Envie o instalador para o VirusTotal: https://virustotal.com
echo    3. Submeta ao Kaspersky Whitelist (instrucoes no README)
echo.
pause
endlocal
