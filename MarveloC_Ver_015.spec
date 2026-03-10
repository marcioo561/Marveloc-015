# -*- mode: python ; coding: utf-8 -*-
# ============================================================
#  MarveloC_Ver_015.spec  —  PyInstaller build config
#
#  PASSO 1 — Gere o executável:
#      pyinstaller MarveloC_Ver_015.spec --noconfirm
#
#  PASSO 2 — Compile o instalador:
#      Abra Marveloc_Ver_015.iss no Inno Setup Compiler e clique Build > Compile
#
#  O executável ficará em:   dist\Marveloc\Marveloc.exe
#  O instalador ficará em:   installer\MarvelocSetup_1.5.0.exe
# ============================================================

import sys
import os
from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs

# ── Coleta automática de dados do Qt / WebEngine ─────────────────────
qt_data        = collect_data_files('PyQt5',                    include_py_files=False)
webengine_data = collect_data_files('PyQt5.QtWebEngineWidgets', include_py_files=False)

# ── Arquivos de runtime do projeto ───────────────────────────────────
# Cria config.json e blocklist.txt padrão se não existirem
_runtime_datas = []
for fname in ('config.json', 'blocklist.txt', 'icon.ico'):
    if os.path.exists(fname):
        _runtime_datas.append((fname, '.'))

a = Analysis(
    ['MarveloC_Ver_015.py'],          # <<< Script principal atualizado
    pathex=['.'],
    binaries=[
        *collect_dynamic_libs('PyQt5'),
    ],
    datas=[
        *_runtime_datas,
        *qt_data,
        *webengine_data,
    ],
    hiddenimports=[
        # ── PyQt5 core ───────────────────────────────────────────────
        'PyQt5',
        'PyQt5.QtWidgets',
        'PyQt5.QtWebEngineWidgets',
        'PyQt5.QtWebEngineCore',
        'PyQt5.QtPrintSupport',
        'PyQt5.QtCore',
        'PyQt5.QtGui',
        'PyQt5.sip',
        # ── Criptografia (pycryptodome) ───────────────────────────────
        'Crypto',
        'Crypto.Cipher',
        'Crypto.Cipher.AES',
        'Crypto.Util',
        'Crypto.Util.Padding',
        'Crypto.Random',
        # ── Windows / pywin32 (importação condicional no código) ──────
        'win32security',
        'ntsecuritycon',
        'pywintypes',
        'ctypes',
        'ctypes.wintypes',
        # ── Stdlib usada pelo projeto ─────────────────────────────────
        'sqlite3',
        'hmac',
        'hashlib',
        'base64',
        'secrets',
        'fnmatch',                    # novo em Ver_015 (UserScripts)
        'collections',
        'collections.defaultdict',
        'logging',
        'logging.handlers',
        'urllib.request',
        'urllib.error',
        'urllib.parse',
        'email.mime.text',
        'email.mime.multipart',
        'email.mime.base',
        'email.encoders',
        'html.parser',
        'webbrowser',
        'subprocess',
        'platform',
        'smtplib',
        'mimetypes',
        'tempfile',
        'shutil',
        'json',
        'datetime',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Remove módulos não utilizados para reduzir tamanho do build
        'tkinter',
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'PIL',
        'IPython',
        'jupyter',
        'notebook',
        'test',
        'unittest',
        'pydoc',
        'doctest',
        'difflib',
        'distutils',
        'setuptools',
        'pkg_resources',
    ],
    noarchive=False,
    optimize=1,          # Remove docstrings, leve melhoria de tamanho
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='Marveloc',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,                       # Sem janela de console preta
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico',
    # Metadados visíveis em Propriedades > Detalhes do .exe
    version_file='version_info.txt',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[
        # Nunca comprimir com UPX — podem corromper ou ser bloqueados por antivírus
        'vcruntime*.dll',
        'msvcp*.dll',
        'api-ms-win*.dll',
        'Qt5WebEngine*.dll',
        'Qt5WebEngineCore*.dll',
        'QtWebEngineProcess.exe',
        'QtWebEngineProcess*.exe',
        'resources.pak',
        'icudtl.dat',
        '*.pak',
    ],
    name='Marveloc',
)
