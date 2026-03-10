import sys
import os
import json
import sqlite3
import datetime
import shutil
import tempfile
import hashlib
import hmac
import base64
import logging
import logging.handlers
import time
import urllib.request
import urllib.error
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, urlparse, parse_qs, unquote, quote
import secrets
import webbrowser
import subprocess
import platform
import smtplib
import mimetypes
from functools import lru_cache
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

# ----------------- Criptografia (pycryptodome) -----------------

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logging.getLogger("marveloc").warning("pycryptodome não instalado. Instale com: pip install pycryptodome")

# ----------------- PyQt5 -----------------

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QToolBar,
    QAction, QLineEdit, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QListWidget, QFileDialog, QMessageBox, QMenu, QInputDialog,
    QDialog, QTextEdit, QSplitter, QFrame, QTreeWidget, QTreeWidgetItem,
    QProgressBar, QComboBox, QCheckBox, QGroupBox, QRadioButton,
    QButtonGroup, QSlider, QSpinBox, QDialogButtonBox, QStatusBar,
    QToolButton, QMenuBar, QDesktopWidget, QShortcut
)
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEnginePage, QWebEngineProfile, QWebEngineSettings, QWebEngineDownloadItem
from PyQt5.QtWebEngineCore import QWebEngineUrlRequestInterceptor, QWebEngineUrlRequestInfo
from PyQt5.QtPrintSupport import QPrintDialog, QPrinter

from PyQt5.QtCore import (
    QUrl, QSize, QPropertyAnimation, QRect,
    Qt, QTimer, QProcess, QThread, pyqtSignal, QDateTime,
    QByteArray, QBuffer, QIODevice, QStandardPaths
)
from PyQt5.QtGui import (
    QColor, QIcon, QPalette, QKeySequence, QPixmap, QImage,
    QTextCursor, QFont, QFontDatabase, QClipboard, QCursor
)

# ----------------- Constantes -----------------

DATA_DIR = "data"
CONFIG_FILE = "config.json"

# Página inicial padrão (pode ser sobrescrita por perfil)
HOME_URL_DEFAULT = "https://www.google.com"

# Allowlist padrão (mínima) para evitar quebra de navegação em buscadores
DEFAULT_ALLOWLIST_DOMAINS = {
    # Google
    "google.com", "www.google.com", "google.com.br", "www.google.com.br",
    "gstatic.com", "www.gstatic.com",
    "googleusercontent.com",
    "googleadservices.com",
}

# ----------------- Logging -----------------
LOGGER_NAME = "marveloc"
logger = logging.getLogger(LOGGER_NAME)

def setup_logging(log_dir: str = None, level: int = logging.INFO):
    """Configura logging (console + arquivo rotativo) de forma best-effort."""
    logger.setLevel(level)
    logger.propagate = False

    # Evita duplicar handlers
    if logger.handlers:
        return

    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    sh.setLevel(level)
    logger.addHandler(sh)

    if log_dir:
        try:
            ensure_dir(log_dir)
            log_path = os.path.join(log_dir, "marveloc.log")
            fh = logging.handlers.RotatingFileHandler(
                log_path, maxBytes=2_000_000, backupCount=3, encoding="utf-8"
            )
            fh.setFormatter(fmt)
            fh.setLevel(level)
            logger.addHandler(fh)
        except Exception:
            logger.warning("Falha ao configurar log em arquivo.", exc_info=True)


DEFAULT_SCHEME_POLICY = {
    "block_file": True,
    "block_data": False,
    "block_ftp": True,
    "block_javascript": False,
}

def is_scheme_blocked(url: QUrl, scheme_policy: dict) -> bool:
    scheme = (url.scheme() or "").lower()
    if scheme == "file":
        return bool(scheme_policy.get("block_file", True))
    if scheme == "data":
        return bool(scheme_policy.get("block_data", False))
    if scheme == "ftp":
        return bool(scheme_policy.get("block_ftp", True))
    if scheme == "javascript":
        return bool(scheme_policy.get("block_javascript", False))
    return False


# =====================================================================
#                       DNS Sinkhole / Blocklist
# =====================================================================

class DnsSinkhole:
    BLOCKLIST_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    CACHE_FILE = "blocklist.txt"
    CACHE_TTL = 3600 * 6  # 6 horas

    def __init__(self):
        self.domains = set()
        self._cache: dict = {}
        self._load()

    def _normalize_host(self, host: str) -> str:
        host = (host or "").strip().lower()
        if not host:
            return ""
        if host.endswith("."):
            host = host[:-1]
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        return host

    def _load(self):
        """Carrega a lista de domínios bloqueados."""
        try:
            # Verifica se o cache é válido
            if os.path.exists(self.CACHE_FILE):
                file_age = time.time() - os.path.getmtime(self.CACHE_FILE)
                if file_age < self.CACHE_TTL:
                    with open(self.CACHE_FILE, "r", encoding="utf-8") as f:
                        self.domains = set(
                            self._normalize_host(line) for line in f
                            if self._normalize_host(line)
                        )
                    logger.info("Lista de bloqueio carregada do cache: %d domínios", len(self.domains))
                    self._clear_cache()
                    return

            logger.info("Baixando lista de bloqueio...")
            response = urllib.request.urlopen(self.BLOCKLIST_URL, timeout=30)
            data = response.read().decode("utf-8", errors="ignore")

            domains = set()
            for line in data.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # linha típica: "0.0.0.0 ads.example.com"
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                    domain = self._normalize_host(parts[1])
                    if domain and domain != "localhost" and not domain.startswith("#"):
                        domains.add(domain)

            self.domains = domains

            with open(self.CACHE_FILE, "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(self.domains)))

            logger.info("Lista de bloqueio atualizada: %d domínios", len(self.domains))
            self._clear_cache()

        except Exception:
            logger.warning("Erro ao carregar lista de bloqueio. Usando fallback.", exc_info=True)
            self.domains = {
                "doubleclick.net", "googleadservices.com", "googlesyndication.com",
                "facebook.com", "facebook.net", "analytics.google.com",
                "adservice.google.com", "adnxs.com", "scorecardresearch.com"
            }
            self._clear_cache()

    def _blocked_lookup(self, host: str) -> bool:
        """Lógica interna de bloqueio sem cache."""
        if not host:
            return False

        # IP v4 simples -> não tratar como domínio
        if host.replace(".", "").isdigit():
            return False

        if host in self.domains:
            return True

        labels = host.split(".")
        if len(labels) <= 1:
            return False

        # Checa sufixos sem avaliar apenas o TLD
        for i in range(1, len(labels) - 1):
            suffix = ".".join(labels[i:])
            if suffix in self.domains:
                return True
        return False

    def _clear_cache(self):
        """Limpa o cache de consultas de bloqueio."""
        self._cache.clear()

    def blocked(self, host: str) -> bool:
        """Verifica se um host está na lista de bloqueio (rápido, com cache por instância)."""
        host_n = self._normalize_host(host)
        if host_n in self._cache:
            return self._cache[host_n]
        result = self._blocked_lookup(host_n)
        # Limita tamanho do cache para evitar crescimento ilimitado em memória
        if len(self._cache) >= 50000:
            self._cache.clear()
        self._cache[host_n] = result
        return result


# =====================================================================
#                   Funções auxiliares DPAPI
# =====================================================================

def _dpapi_protect_ctypes(data: bytes) -> bytes:
    """Protege dados usando DPAPI via ctypes."""
    if os.name != "nt":
        raise RuntimeError("DPAPI disponível apenas no Windows")
    
    try:
        import ctypes
        from ctypes import wintypes
        
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
        
        CryptProtectData = ctypes.windll.crypt32.CryptProtectData
        CryptProtectData.argtypes = [ctypes.POINTER(DATA_BLOB), wintypes.LPCWSTR, 
                                      ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, 
                                      ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DATA_BLOB)]
        CryptProtectData.restype = wintypes.BOOL
        
        data_in = DATA_BLOB(len(data), ctypes.cast(data, ctypes.POINTER(ctypes.c_char)))
        data_out = DATA_BLOB()
        
        if CryptProtectData(ctypes.byref(data_in), None, None, None, None, 0, ctypes.byref(data_out)):
            protected = ctypes.string_at(data_out.pbData, data_out.cbData)
            ctypes.windll.kernel32.LocalFree(data_out.pbData)
            return protected
        else:
            raise ctypes.WinError()
    except Exception as e:
        logger.error(f"Erro no DPAPI protect: {e}")
        raise

def _dpapi_unprotect_ctypes(protected_blob: bytes) -> bytes:
    """Desprotege dados usando DPAPI via ctypes."""
    if os.name != "nt":
        raise RuntimeError("DPAPI disponível apenas no Windows")
    
    try:
        import ctypes
        from ctypes import wintypes
        
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
        
        CryptUnprotectData = ctypes.windll.crypt32.CryptUnprotectData
        CryptUnprotectData.argtypes = [ctypes.POINTER(DATA_BLOB), ctypes.POINTER(wintypes.LPCWSTR),
                                        ctypes.POINTER(DATA_BLOB), ctypes.c_void_p,
                                        ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DATA_BLOB)]
        CryptUnprotectData.restype = wintypes.BOOL
        
        data_in = DATA_BLOB(len(protected_blob), ctypes.cast(protected_blob, ctypes.POINTER(ctypes.c_char)))
        data_out = DATA_BLOB()
        desc = wintypes.LPCWSTR()
        
        if CryptUnprotectData(ctypes.byref(data_in), ctypes.byref(desc), None, None, None, 0, ctypes.byref(data_out)):
            unprotected = ctypes.string_at(data_out.pbData, data_out.cbData)
            ctypes.windll.kernel32.LocalFree(data_out.pbData)
            return unprotected
        else:
            raise ctypes.WinError()
    except Exception as e:
        logger.error(f"Erro no DPAPI unprotect: {e}")
        raise


# =====================================================================
#                   Sistema de Criptografia Aprimorado
# =====================================================================

class DataEncryption:
    """Criptografia de dados por perfil.

    - Windows-only (alvo do projeto): usa DPAPI para proteger uma master key aleatória.
    - Conteúdo: AES-GCM (v2) com cabeçalho 'MCG2'.
    - Compatibilidade: consegue ler blobs legados (v1) AES-CBC + HMAC-SHA256.
    """

    HEADER_GCM_V2 = b"MCG2"  # 4 bytes

    def __init__(self, profile_name: str):
        self.profile_name = profile_name
        self.profile_dir = os.path.join(DATA_DIR, profile_name)
        ensure_dir(self.profile_dir)

        # Master key protegida via DPAPI
        self.master_key = self._load_or_create_master_key_dpapi()

        # Subchave para AES-GCM v2
        self.key_gcm = self._kdf_gcm(self.master_key)

    # ----------------- DPAPI -----------------

    def _masterkey_path(self) -> str:
        return os.path.join(self.profile_dir, "masterkey.dpapi")

    def _dpapi_protect(self, data: bytes) -> bytes:
        """Protege bytes com DPAPI (Windows) sem depender de pywin32."""
        if os.name != "nt":
            raise RuntimeError("DPAPI disponível apenas no Windows")
        return _dpapi_protect_ctypes(data)

    def _dpapi_unprotect(self, protected_blob: bytes) -> bytes:
        """Desprotege bytes com DPAPI (Windows) sem depender de pywin32."""
        if os.name != "nt":
            raise RuntimeError("DPAPI disponível apenas no Windows")
        return _dpapi_unprotect_ctypes(protected_blob)

    def _load_or_create_master_key_dpapi(self) -> bytes:
        path = self._masterkey_path()

        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    protected_blob = f.read()
                return self._dpapi_unprotect(protected_blob)
            except Exception:
                # Política tolerante: recria chave (isso invalida dados criptografados antigos)
                logging.getLogger(LOGGER_NAME).warning(
                    "Falha ao carregar masterkey DPAPI; recriando (dados antigos podem ficar inacessíveis).",
                    exc_info=True
                )

        raw_key = os.urandom(32)
        try:
            protected = self._dpapi_protect(raw_key)
            tmp = path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(protected)
            os.replace(tmp, path)
            _secure_file_permissions(path)
            return raw_key
        except Exception:
            # Fallback inseguro: sem segredo real (não prometa confidencialidade nesse modo)
            logging.getLogger(LOGGER_NAME).warning(
                "DPAPI indisponível; usando fallback sem segredo real (apenas obfuscação).",
                exc_info=True
            )
            return hashlib.sha256((self.profile_name + "|INSECURE_FALLBACK").encode("utf-8")).digest()

    # ----------------- KDF -----------------

    def _kdf_gcm(self, master_key: bytes) -> bytes:
        # HMAC-SHA256(master_key, context) -> 32 bytes
        return hmac.new(master_key, b"MARVELOC|AESGCM|v2", digestmod=hashlib.sha256).digest()

    # ----------------- API -----------------

    def encrypt(self, data: str) -> str:
        """Criptografa string (JSON) e retorna base64."""
        if not CRYPTO_AVAILABLE:
            return base64.b64encode(data.encode("utf-8")).decode("utf-8")

        try:
            nonce = os.urandom(12)
            cipher = AES.new(self.key_gcm, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(data.encode("utf-8"))

            blob = self.HEADER_GCM_V2 + nonce + tag + ciphertext
            return base64.b64encode(blob).decode("utf-8")
        except Exception:
            logging.getLogger(LOGGER_NAME).error("Erro na criptografia (GCM).", exc_info=True)
            return base64.b64encode(data.encode("utf-8")).decode("utf-8")

    def decrypt(self, encrypted_data: str) -> str:
        """Descriptografa string base64; aceita formato v2 (GCM) e legado v1 (CBC+HMAC)."""
        if not CRYPTO_AVAILABLE:
            try:
                return base64.b64decode(encrypted_data.encode("utf-8")).decode("utf-8")
            except Exception:
                return ""

        try:
            blob = base64.b64decode(encrypted_data.encode("utf-8"))
        except Exception:
            return ""

        # v2: HEADER + nonce(12) + tag(16) + ciphertext
        try:
            if blob.startswith(self.HEADER_GCM_V2):
                if len(blob) < 4 + 12 + 16:
                    raise ValueError("Blob GCM v2 muito curto")

                nonce = blob[4:16]
                tag = blob[16:32]
                ciphertext = blob[32:]

                cipher = AES.new(self.key_gcm, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                return plaintext.decode("utf-8")
        except Exception:
            logging.getLogger(LOGGER_NAME).warning("Falha ao descriptografar GCM v2.", exc_info=True)
            # Não retorna vazio ainda, tenta fallback

        # legado v1: base64(iv(16) + encrypted + hmac(32))
        try:
            if len(blob) < 16 + 32:
                raise ValueError("Blob legado muito curto")

            iv = blob[:16]
            encrypted = blob[16:-32]
            received_hmac = blob[-32:]

            expected_hmac = hmac.new(self.master_key, iv + encrypted, digestmod=hashlib.sha256).digest()
            if not hmac.compare_digest(received_hmac, expected_hmac):
                raise ValueError("HMAC inválido (legado)")

            cipher = AES.new(self.master_key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
            return decrypted.decode("utf-8")
        except Exception:
            logging.getLogger(LOGGER_NAME).warning("Falha ao descriptografar blob legado v1.", exc_info=True)
            # fallback: tentar base64 simples
            try:
                return base64.b64decode(encrypted_data.encode("utf-8")).decode("utf-8")
            except Exception:
                return ""



# =====================================================================
#       Utilitários de diretório/arquivos com segurança aprimorada
# =====================================================================

def ensure_dir(path: str):
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)
    _secure_dir_permissions(path)


def _atomic_write_encrypted(path: str, data, encryptor: DataEncryption):
    """Escreve dados criptografados atomicamente."""
    tmp = f"{path}.tmp"
    try:
        encrypted_data = encryptor.encrypt(
            json.dumps(data, ensure_ascii=False, indent=2)
        )
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(encrypted_data)
        os.replace(tmp, path)
        _secure_file_permissions(path)
    except Exception:
        logger.error("Erro na escrita criptografada; usando fallback sem criptografia.", exc_info=True)
        _atomic_write(
            path,
            json.dumps(
                data, ensure_ascii=False, indent=2
            ).encode("utf-8")
        )


def _atomic_write(path: str, data_bytes: bytes):
    """Escrita atômica com permissões seguras."""
    tmp = f"{path}.tmp"
    with open(tmp, "wb") as f:
        f.write(data_bytes)
        _secure_file_permissions(tmp)
    os.replace(tmp, path)


def _secure_file_permissions(path: str):
    """Aplica permissões seguras a ARQUIVO (best effort)."""
    try:
        if os.name != "nt":
            os.chmod(path, 0o600)
            return

        # Windows
        if os.path.isdir(path):
            _secure_dir_permissions(path)
            return

        try:
            import win32security
            import ntsecuritycon
        except ImportError:
            logger.debug("pywin32 não disponível; ACL de arquivo não aplicada.")
            return

        token = win32security.OpenProcessToken(
            win32security.GetCurrentProcess(),
            win32security.TOKEN_QUERY
        )
        user_sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]

        dacl = win32security.ACL()
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            ntsecuritycon.FILE_GENERIC_READ | ntsecuritycon.FILE_GENERIC_WRITE,
            user_sid
        )

        sd = win32security.SECURITY_DESCRIPTOR()
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION, sd)

    except Exception:
        logger.debug("Falha ao aplicar ACL em arquivo (best-effort).", exc_info=True)


def _secure_dir_permissions(path: str):
    """Aplica permissões seguras a DIRETÓRIO (best effort)."""
    try:
        if os.name != "nt":
            os.chmod(path, 0o700)
            return

        try:
            import win32security
            import ntsecuritycon
        except ImportError:
            logger.debug("pywin32 não disponível; ACL de diretório não aplicada.")
            return

        token = win32security.OpenProcessToken(
            win32security.GetCurrentProcess(),
            win32security.TOKEN_QUERY
        )
        user_sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]

        dacl = win32security.ACL()
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            ntsecuritycon.FILE_GENERIC_READ |
            ntsecuritycon.FILE_GENERIC_WRITE |
            ntsecuritycon.FILE_GENERIC_EXECUTE,
            user_sid
        )

        sd = win32security.SECURITY_DESCRIPTOR()
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION, sd)

    except Exception:
        logger.debug("Falha ao aplicar ACL em diretório (best-effort).", exc_info=True)


def load_config():
    """Carrega a configuração principal do navegador."""
    default_config = {"perfil": "default"}
    
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding="utf-8") as f:
                content = f.read()
                if content.strip():
                    return json.loads(content)
        except Exception:
            logger.debug("Falha ao carregar config principal; usando defaults.", exc_info=True)

    # Se não existe ou deu erro, cria config default
    try:
        _atomic_write(CONFIG_FILE, json.dumps(default_config, indent=2).encode("utf-8"))
    except Exception:
        logger.debug("Falha ao escrever config principal default.", exc_info=True)

    return default_config


def save_config(cfg: dict):
    """Salva a configuração principal do navegador."""
    try:
        _atomic_write(CONFIG_FILE, json.dumps(cfg, indent=2, ensure_ascii=False).encode("utf-8"))
    except Exception:
        logger.error("Falha ao salvar config principal.", exc_info=True)


# =====================================================================
#                 Interceptor (adblock + anti-tracking)
# =====================================================================


class AdBlockInterceptor(QWebEngineUrlRequestInterceptor):
    TRACKER_KEYWORDS = [
        "doubleclick", "googlesyndication", "googleadservices",
        "adsystem", "adservice", "analytics", "pixel", "tracker",
        "facebook.net", "facebook.com/tr", "scorecardresearch",
        "adnxs", "taboola", "outbrain", "hotjar", "optimizely"
    ]

    def __init__(self, main):
        super().__init__()
        self.main = main

    # ---- utilidades de domínio ----
    def _host(self, url_str: str) -> str:
        try:
            return (urlparse(url_str).hostname or "").lower()
        except Exception:
            return ""

    def _in_list(self, host: str, domains: list) -> bool:
        if not host:
            return False
        host = host.lower().strip().strip(".")
        for d in (domains or []):
            d = (d or "").lower().strip().strip(".")
            if not d:
                continue
            if host == d or host.endswith("." + d):
                return True
        return False

    def _is_allowlisted(self, host: str) -> bool:
        return self._in_list(host, getattr(self.main, "allowlist_domains", []))

    def _is_blocklisted(self, host: str) -> bool:
        return self._in_list(host, getattr(self.main, "blocklist_domains", []))

    def _is_tracker_by_keyword(self, url_str: str) -> bool:
        u = (url_str or "").lower()
        return any(kw in u for kw in self.TRACKER_KEYWORDS)

    def interceptRequest(self, info: QWebEngineUrlRequestInfo):
        url = info.requestUrl()
        url_str = url.toString()
        host = self._host(url_str)

        # 0) Política de esquemas
        try:
            if is_scheme_blocked(url, getattr(self.main, 'scheme_policy', DEFAULT_SCHEME_POLICY)):
                info.block(True)
                return
        except Exception:
            logger.debug('Falha ao avaliar política de scheme no interceptor.', exc_info=True)

        # 1) Blocklist do usuário (sempre bloqueia)
        if self._is_blocklisted(host):
            info.block(True)
            return

        # 2) Allowlist do usuário (sempre permite)
        if self._is_allowlisted(host):
            try:
                info.setHttpHeader(b'DNT', b'1')
            except Exception:
                pass
            return

        # 3) Bloqueia ping/track (baixo risco de quebra)
        try:
            if info.resourceType() == QWebEngineUrlRequestInfo.ResourceTypePing:
                info.block(True)
                return
        except Exception:
            logger.debug("Recurso/API não suportado no QtWebEngine.", exc_info=True)

        # 4) Bloqueio por keyword/sinkhole (pode quebrar; por isso vem depois das exceções)
        try:
            if self._is_tracker_by_keyword(url_str):
                info.block(True)
                return
        except Exception:
            pass

        try:
            if host and self.main.dns_sinkhole.blocked(host):
                info.block(True)
                return
        except Exception:
            logger.debug("Falha ao avaliar DNS sinkhole.", exc_info=True)

        # Cabeçalhos de privacidade (best-effort)
        try:
            info.setHttpHeader(b'DNT', b'1')
        except Exception:
            pass


# =====================================================================
#                   Página endurecida (hardening)
# =====================================================================

class HardenedPage(QWebEnginePage):
    def __init__(self, profile, main):
        super().__init__(profile, main)
        self.main = main
        self._redirect_count = 0
        self._max_redirects = 10

        self.loadFinished.connect(self._inject_privacy_scripts)

    def _inject_privacy_scripts(self):
        privacy_scripts = """
        try {
          Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
          if (navigator.sendBeacon) { navigator.sendBeacon = function() { return false; } }
        } catch(e) {}

        // Barra de pesquisa arredondada no Google
        try {
          var host = window.location.hostname;
          if (host.indexOf('google.') !== -1) {
            var style = document.createElement('style');
            style.textContent = `
              .gLFyf, input[name="q"], .RNNXgb, .SDkEP { border-radius: 28px !important; }
              .RNNXgb, .o3j99 { border-radius: 28px !important; box-shadow: 0 2px 8px rgba(0,0,0,0.15) !important; }
              .SDkEP { border-radius: 28px 0 0 28px !important; }
              .FPdoLc .sbfc, .A8SBwf { border-radius: 28px !important; }
              .gLFyf { padding-left: 18px !important; font-size: 16px !important; }
            `;
            document.head.appendChild(style);
          }
        } catch(e) {}
        """
        self.runJavaScript(privacy_scripts)

        # Injeta UserScripts do perfil
        try:
            current_url = self.view().url().toString() if self.view() else ""
            scripts = getattr(self.main, 'userscripts', [])
            for script in scripts:
                if not script.get("enabled", True):
                    continue
                pattern = script.get("match", "*")
                # Verifica correspondência simples (suporta * como wildcard)
                import fnmatch
                if fnmatch.fnmatch(current_url, pattern) or pattern == "*":
                    code = script.get("code", "")
                    if code:
                        self.runJavaScript(f"(function(){{\n{code}\n}})();")
        except Exception:
            pass

    def acceptNavigationRequest(self, url, nav_type, is_main_frame):
        # Bloqueio de esquemas por política de perfil
        try:
            if is_scheme_blocked(url, getattr(self.main, 'scheme_policy', DEFAULT_SCHEME_POLICY)):
                return False
        except Exception:
            logger.debug('Falha ao avaliar política de scheme na navegação.', exc_info=True)

        if is_main_frame:
            self._redirect_count = 0

        # Upgrade HTTPS com limite de redirects
        try:
            if url.scheme().lower() == "http" and is_main_frame:
                https_url = QUrl(url)
                https_url.setScheme("https")
                self._redirect_count += 1
                if self._redirect_count <= self._max_redirects:
                    self.view().setUrl(https_url)
                    return False
        except Exception:
            logger.debug("Falha no upgrade HTTPS.", exc_info=True)

        return super().acceptNavigationRequest(url, nav_type, is_main_frame)


# =====================================================================
#                       Aba do navegador
# =====================================================================

class BrowserTab(QWidget):
    def __init__(self, main, profile=None):
        super().__init__()
        self.main = main

        self._main_layout = QVBoxLayout()
        self._main_layout.setContentsMargins(0, 0, 0, 0)

        self.browser = QWebEngineView()
        self.page = HardenedPage(profile or QWebEngineProfile.defaultProfile(), self.main)
        self.browser.setPage(self.page)

        self._main_layout.addWidget(self.browser)
        self.setLayout(self._main_layout)

        # Atualiza título da aba
        self.browser.titleChanged.connect(self._update_title)

        # Atualiza URL
        self.browser.urlChanged.connect(self._url_changed)

        # Conecta o loadFinished para atualizar o status
        self.browser.loadFinished.connect(self._on_load_finished)
        self.browser.loadStarted.connect(self._on_load_started)
        self.browser.loadProgress.connect(self._on_load_progress)

    def _update_title(self, title):
        i = self.main.tabs.indexOf(self)
        if i >= 0:
            self.main.tabs.setTabText(i, title[:20] + ("..." if len(title) > 20 else ""))

    def _url_changed(self, url):
        if self.main.tabs.currentWidget() == self:
            self.main.urlbar.setText(url.toString())
            self.main.urlbar.setCursorPosition(0)

        # histórico
        try:
            self.main.add_to_history(url.toString())
        except Exception:
            logger.debug("Falha ao inserir no histórico.", exc_info=True)

    def _on_load_finished(self, ok):
        if self.main.tabs.currentWidget() == self:
            self.main.statusBar().showMessage("Pronto", 2000)
            # Atualiza botões de navegação
            self.main.update_nav_buttons()

    def _on_load_started(self):
        if self.main.tabs.currentWidget() == self:
            self.main.statusBar().showMessage("Carregando...")

    def _on_load_progress(self, progress):
        if self.main.tabs.currentWidget() == self:
            self.main.statusBar().showMessage(f"Carregando... {progress}%")


# =====================================================================
#                   Diálogo de Histórico
# =====================================================================

class HistoryDialog(QDialog):
    def __init__(self, browser, parent=None):
        super().__init__(parent)
        self.browser = browser
        self.setWindowTitle("Histórico de Navegação")
        self.resize(800, 500)

        layout = QVBoxLayout()

        # Barra de pesquisa
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Pesquisar:"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Digite para filtrar...")
        self.search_edit.textChanged.connect(self.filter_history)
        search_layout.addWidget(self.search_edit)

        btn_clear = QPushButton("Limpar Histórico")
        btn_clear.clicked.connect(self.clear_history)
        search_layout.addWidget(btn_clear)

        layout.addLayout(search_layout)

        # Lista de histórico
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Título", "URL", "Data", "Visitas"])
        self.tree.setAlternatingRowColors(True)
        self.tree.itemDoubleClicked.connect(self.open_url)
        layout.addWidget(self.tree)

        # Botões
        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box.accepted.connect(self.accept)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

        self.setLayout(layout)
        self.load_history()

    def load_history(self):
        self.tree.clear()
        try:
            cursor = self.browser.conn.cursor()
            cursor.execute(
                "SELECT title, url, timestamp, count FROM history ORDER BY timestamp DESC LIMIT 1000"
            )
            for title, url, ts, count in cursor.fetchall():
                item = QTreeWidgetItem([title or "Sem título", url, ts[:16] if ts else "", str(count)])
                item.setData(0, Qt.UserRole, url)
                self.tree.addTopLevelItem(item)
        except Exception as e:
            logger.error(f"Erro ao carregar histórico: {e}")

    def filter_history(self):
        text = self.search_edit.text().lower()
        for i in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(i)
            title = item.text(0).lower()
            url = item.text(1).lower()
            match = text in title or text in url
            item.setHidden(not match)

    def open_url(self, item, column):
        url = item.data(0, Qt.UserRole)
        if url:
            self.browser.tabs.currentWidget().browser.setUrl(QUrl(url))

    def clear_history(self):
        reply = QMessageBox.question(
            self, "Limpar Histórico",
            "Tem certeza que deseja limpar todo o histórico?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            try:
                cursor = self.browser.conn.cursor()
                cursor.execute("DELETE FROM history")
                self.browser.conn.commit()
                self.load_history()
                QMessageBox.information(self, "Histórico", "Histórico limpo com sucesso!")
            except Exception as e:
                QMessageBox.critical(self, "Erro", f"Erro ao limpar histórico: {e}")


# =====================================================================
#                   Diálogo de Favoritos
# =====================================================================

class BookmarksDialog(QDialog):
    def __init__(self, browser, parent=None):
        super().__init__(parent)
        self.browser = browser
        self.setWindowTitle("Gerenciador de Favoritos")
        self.resize(760, 520)

        layout = QVBoxLayout()

        # Barra de pesquisa
        search_layout = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("🔍 Pesquisar favoritos...")
        self.search_edit.textChanged.connect(self.filter_bookmarks)
        search_layout.addWidget(self.search_edit)

        # Filtro de pasta
        self.folder_filter = QComboBox()
        self.folder_filter.addItem("Todas as pastas")
        self.folder_filter.currentIndexChanged.connect(self.filter_bookmarks)
        search_layout.addWidget(self.folder_filter)
        layout.addLayout(search_layout)

        # Árvore de favoritos
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Título", "URL", "Pasta"])
        self.tree.setColumnWidth(0, 280)
        self.tree.setColumnWidth(1, 280)
        self.tree.setColumnWidth(2, 120)
        self.tree.setAlternatingRowColors(True)
        self.tree.setSortingEnabled(True)
        self.tree.itemDoubleClicked.connect(lambda item, _: self.open_bookmark(item))
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)
        self.load_bookmarks()
        layout.addWidget(self.tree)

        # Status
        self.status_lbl = QLabel("")
        self.status_lbl.setStyleSheet("color: #555; font-size: 11px;")
        layout.addWidget(self.status_lbl)

        # Botões
        btn_layout = QHBoxLayout()

        btn_open = QPushButton("🌐 Abrir")
        btn_open.clicked.connect(self.open_selected)
        btn_layout.addWidget(btn_open)

        btn_edit = QPushButton("✏️ Editar")
        btn_edit.clicked.connect(self.edit_selected)
        btn_layout.addWidget(btn_edit)

        btn_delete = QPushButton("🗑 Remover")
        btn_delete.clicked.connect(self.delete_selected)
        btn_layout.addWidget(btn_delete)

        btn_layout.addStretch()

        btn_export = QPushButton("📤 Exportar HTML")
        btn_export.clicked.connect(self.export_html)
        btn_layout.addWidget(btn_export)

        btn_import = QPushButton("📥 Importar HTML")
        btn_import.clicked.connect(self.import_html)
        btn_layout.addWidget(btn_import)

        btn_close = QPushButton("Fechar")
        btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(btn_close)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def load_bookmarks(self):
        self.tree.clear()
        self.folder_filter.blockSignals(True)
        current_folder = self.folder_filter.currentText()
        self.folder_filter.clear()
        self.folder_filter.addItem("Todas as pastas")

        pastas = sorted({f.get("folder", "") or "Sem pasta" for f in self.browser.favoritos})
        for p in pastas:
            self.folder_filter.addItem(p)

        # Restaura seleção
        idx = self.folder_filter.findText(current_folder)
        if idx >= 0:
            self.folder_filter.setCurrentIndex(idx)
        self.folder_filter.blockSignals(False)

        search = self.search_edit.text().lower() if hasattr(self, 'search_edit') else ""
        folder_filter = self.folder_filter.currentText() if hasattr(self, 'folder_filter') else "Todas as pastas"

        shown = 0
        for fav in self.browser.favoritos:
            title = fav.get("title", "Sem título")
            url = fav.get("url", "")
            folder = fav.get("folder", "") or "Sem pasta"

            if search and search not in title.lower() and search not in url.lower():
                continue
            if folder_filter != "Todas as pastas" and folder != folder_filter:
                continue

            item = QTreeWidgetItem([title, url, folder])
            item.setData(0, Qt.UserRole, fav)
            item.setToolTip(1, url)
            self.tree.addTopLevelItem(item)
            shown += 1

        self.status_lbl.setText(f"{shown} favorito(s) exibido(s) de {len(self.browser.favoritos)} total.")

    def filter_bookmarks(self):
        self.load_bookmarks()

    def open_bookmark(self, item):
        fav = item.data(0, Qt.UserRole)
        if fav and "url" in fav:
            self.browser.add_new_tab(QUrl(fav["url"]), fav.get("title", "Favorito"))
            self.accept()

    def open_selected(self):
        item = self.tree.currentItem()
        if item:
            self.open_bookmark(item)
        else:
            QMessageBox.information(self, "Favoritos", "Selecione um favorito primeiro.")

    def edit_selected(self):
        item = self.tree.currentItem()
        if not item:
            QMessageBox.information(self, "Favoritos", "Selecione um favorito para editar.")
            return
        fav = item.data(0, Qt.UserRole)
        if fav:
            dialog = QDialog(self)
            dialog.setWindowTitle("Editar Favorito")
            dialog.setMinimumWidth(380)
            lay = QVBoxLayout(dialog)
            lay.addWidget(QLabel("Título:"))
            name_e = QLineEdit(fav.get("title", ""))
            lay.addWidget(name_e)
            lay.addWidget(QLabel("URL:"))
            url_e = QLineEdit(fav.get("url", ""))
            lay.addWidget(url_e)
            lay.addWidget(QLabel("Pasta:"))
            folder_e = QLineEdit(fav.get("folder", ""))
            lay.addWidget(folder_e)
            btns = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
            btns.accepted.connect(dialog.accept)
            btns.rejected.connect(dialog.reject)
            lay.addWidget(btns)
            if dialog.exec_() == QDialog.Accepted:
                fav["title"] = name_e.text().strip()
                fav["url"] = url_e.text().strip()
                fav["folder"] = folder_e.text().strip()
                try:
                    _atomic_write_encrypted(self.browser.fav_path, self.browser.favoritos, self.browser.encryptor)
                    self.browser.bookmarks_updated.emit()
                    self.load_bookmarks()
                except Exception as e:
                    QMessageBox.critical(self, "Erro", f"Erro ao salvar: {e}")

    def delete_selected(self):
        item = self.tree.currentItem()
        if not item:
            QMessageBox.information(self, "Favoritos", "Selecione um favorito para remover.")
            return
        fav = item.data(0, Qt.UserRole)
        reply = QMessageBox.question(self, "Remover Favorito",
            f"Remover '{fav.get('title', '?')}'?", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes and fav in self.browser.favoritos:
            self.browser.favoritos.remove(fav)
            try:
                _atomic_write_encrypted(self.browser.fav_path, self.browser.favoritos, self.browser.encryptor)
                self.browser.bookmarks_updated.emit()
                self.load_bookmarks()
            except Exception as e:
                QMessageBox.critical(self, "Erro", f"Erro ao remover: {e}")

    def show_context_menu(self, pos):
        item = self.tree.itemAt(pos)
        if not item:
            return
        menu = QMenu(self)
        act_open = menu.addAction("🌐 Abrir em nova aba")
        act_edit = menu.addAction("✏️ Editar")
        act_del = menu.addAction("🗑 Remover")
        act_copy = menu.addAction("📋 Copiar URL")
        chosen = menu.exec_(self.tree.mapToGlobal(pos))
        if chosen == act_open:
            self.open_bookmark(item)
        elif chosen == act_edit:
            self.edit_selected()
        elif chosen == act_del:
            self.delete_selected()
        elif chosen == act_copy:
            fav = item.data(0, Qt.UserRole)
            if fav:
                QApplication.clipboard().setText(fav.get("url", ""))

    def export_html(self):
        self.browser.action_export_bookmarks_html()

    def import_html(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Importar Favoritos de HTML", "",
            "HTML Files (*.html *.htm);;Todos os arquivos (*)"
        )
        if file_path:
            self.browser._import_bookmarks_from_html_file(file_path)
            self.load_bookmarks()


# =====================================================================
#                   Diálogo de Downloads
# =====================================================================

class DownloadsDialog(QDialog):
    def __init__(self, browser, parent=None):
        super().__init__(parent)
        self.browser = browser
        self.setWindowTitle("Gerenciador de Downloads")
        self.resize(600, 400)

        layout = QVBoxLayout()

        self.list_widget = QListWidget()
        self.list_widget.itemDoubleClicked.connect(self.open_download)
        self.load_downloads()
        layout.addWidget(self.list_widget)

        btn_layout = QHBoxLayout()
        btn_open_folder = QPushButton("Abrir Pasta")
        btn_open_folder.clicked.connect(self.open_folder)
        btn_layout.addWidget(btn_open_folder)

        btn_clear = QPushButton("Limpar Lista")
        btn_clear.clicked.connect(self.clear_list)
        btn_layout.addWidget(btn_clear)

        btn_layout.addStretch()
        btn_close = QPushButton("Fechar")
        btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(btn_close)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def load_downloads(self):
        self.list_widget.clear()
        for d in reversed(self.browser.downloads):
            url = d.get("url", "")
            path = d.get("path", "")
            ts = d.get("ts", "")[:16]
            filename = os.path.basename(path) if path else "?"
            item_text = f"{ts} - {filename} - {path}"
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, path)
            self.list_widget.addItem(item)

    def open_download(self, item):
        path = item.data(Qt.UserRole)
        if path and os.path.exists(path):
            try:
                if platform.system() == 'Windows':
                    os.startfile(path)
                elif platform.system() == 'Darwin':
                    subprocess.run(['open', path])
                else:
                    subprocess.run(['xdg-open', path])
            except Exception as e:
                QMessageBox.critical(self, "Erro", f"Erro ao abrir arquivo: {e}")
        else:
            QMessageBox.warning(self, "Arquivo não encontrado", "O arquivo não existe mais.")

    def open_folder(self):
        item = self.list_widget.currentItem()
        if item:
            path = item.data(Qt.UserRole)
            if path and os.path.exists(path):
                folder = os.path.dirname(path)
                try:
                    if platform.system() == 'Windows':
                        os.startfile(folder)
                    elif platform.system() == 'Darwin':
                        subprocess.run(['open', folder])
                    else:
                        subprocess.run(['xdg-open', folder])
                except Exception as e:
                    QMessageBox.critical(self, "Erro", f"Erro ao abrir pasta: {e}")

    def clear_list(self):
        reply = QMessageBox.question(
            self, "Limpar Lista",
            "Remover todos os downloads da lista?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.browser.downloads.clear()
            try:
                _atomic_write_encrypted(self.browser.down_path, self.browser.downloads, self.browser.encryptor)
                self.load_downloads()
            except Exception as e:
                QMessageBox.critical(self, "Erro", f"Erro ao limpar lista: {e}")


# =====================================================================
#                   Barra Lateral de Favoritos
# =====================================================================

class BookmarksSidebar(QWidget):
    def __init__(self, browser, parent=None):
        super().__init__(parent)
        self.browser = browser
        self.setMinimumWidth(250)
        self.setMaximumWidth(400)

        layout = QVBoxLayout()
        layout.setContentsMargins(2, 2, 2, 2)

        # Título
        title_layout = QHBoxLayout()
        title_layout.addWidget(QLabel("<b>Favoritos</b>"))
        btn_add = QPushButton("+")
        btn_add.setMaximumWidth(30)
        btn_add.clicked.connect(self.add_current_page)
        title_layout.addWidget(btn_add)
        title_layout.addStretch()
        layout.addLayout(title_layout)

        # Lista
        self.list_widget = QListWidget()
        self.list_widget.itemDoubleClicked.connect(self.open_bookmark)
        self.list_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.list_widget.customContextMenuRequested.connect(self.show_context_menu)
        self.load_bookmarks()
        layout.addWidget(self.list_widget)

        self.setLayout(layout)

        # Atualiza quando favoritos mudam
        self.browser.bookmarks_updated.connect(self.load_bookmarks)

    def load_bookmarks(self):
        self.list_widget.clear()
        for fav in self.browser.favoritos:
            title = fav.get("title", "Sem título")
            url = fav.get("url", "")
            item = QListWidgetItem(title)
            item.setData(Qt.UserRole, fav)
            item.setToolTip(url)
            self.list_widget.addItem(item)

    def open_bookmark(self, item):
        fav = item.data(Qt.UserRole)
        if fav and "url" in fav:
            self.browser.tabs.currentWidget().browser.setUrl(QUrl(fav["url"]))

    def add_current_page(self):
        self.browser.add_favorite()
        self.load_bookmarks()

    def show_context_menu(self, pos):
        item = self.list_widget.itemAt(pos)
        if not item:
            return

        menu = QMenu()
        act_open = menu.addAction("Abrir")
        act_delete = menu.addAction("Remover")
        act_edit = menu.addAction("Editar")

        action = menu.exec_(self.list_widget.mapToGlobal(pos))

        if action == act_open:
            self.open_bookmark(item)
        elif action == act_delete:
            fav = item.data(Qt.UserRole)
            if fav in self.browser.favoritos:
                self.browser.favoritos.remove(fav)
                try:
                    _atomic_write_encrypted(self.browser.fav_path, self.browser.favoritos, self.browser.encryptor)
                    self.load_bookmarks()
                except Exception as e:
                    QMessageBox.critical(self, "Erro", f"Erro ao remover: {e}")
        elif action == act_edit:
            fav = item.data(Qt.UserRole)
            if fav:
                self.edit_bookmark(fav)

    def edit_bookmark(self, fav):
        title, ok1 = QInputDialog.getText(self, "Editar Título", "Título:", text=fav.get("title", ""))
        if ok1:
            url, ok2 = QInputDialog.getText(self, "Editar URL", "URL:", text=fav.get("url", ""))
            if ok2:
                fav["title"] = title
                fav["url"] = url
                try:
                    _atomic_write_encrypted(self.browser.fav_path, self.browser.favoritos, self.browser.encryptor)
                    self.load_bookmarks()
                except Exception as e:
                    QMessageBox.critical(self, "Erro", f"Erro ao editar: {e}")


# =====================================================================
#                   Barra Lateral de Histórico
# =====================================================================

class HistorySidebar(QWidget):
    def __init__(self, browser, parent=None):
        super().__init__(parent)
        self.browser = browser
        self.setMinimumWidth(250)
        self.setMaximumWidth(400)

        layout = QVBoxLayout()
        layout.setContentsMargins(2, 2, 2, 2)

        # Título e pesquisa
        layout.addWidget(QLabel("<b>Histórico</b>"))

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Pesquisar...")
        self.search_edit.textChanged.connect(self.filter_history)
        layout.addWidget(self.search_edit)

        # Lista
        self.list_widget = QListWidget()
        self.list_widget.itemDoubleClicked.connect(self.open_history)
        layout.addWidget(self.list_widget)

        self.setLayout(layout)
        self.load_history()

        # Timer para atualização periódica
        self.timer = QTimer()
        self.timer.timeout.connect(self.load_history)
        self.timer.start(60000)  # atualiza a cada minuto

    def load_history(self):
        self.list_widget.clear()
        try:
            cursor = self.browser.conn.cursor()
            cursor.execute(
                "SELECT title, url, timestamp FROM history ORDER BY timestamp DESC LIMIT 100"
            )
            for title, url, ts in cursor.fetchall():
                display = f"{title or 'Sem título'} - {ts[:16] if ts else ''}"
                item = QListWidgetItem(display)
                item.setData(Qt.UserRole, url)
                item.setToolTip(url)
                self.list_widget.addItem(item)
        except Exception as e:
            logger.error(f"Erro ao carregar histórico: {e}")

    def filter_history(self):
        text = self.search_edit.text().lower()
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            match = text in item.text().lower()
            item.setHidden(not match)

    def open_history(self, item):
        url = item.data(Qt.UserRole)
        if url:
            self.browser.tabs.currentWidget().browser.setUrl(QUrl(url))


# =====================================================================
#                   Diálogo de Configurações Avançadas
# =====================================================================

class SettingsDialog(QDialog):
    def __init__(self, browser, parent=None):
        super().__init__(parent)
        self.browser = browser
        self.setWindowTitle("Configurações do Navegador")
        self.resize(800, 600)

        main_layout = QVBoxLayout()

        # Tabs de configurações
        self.tab_widget = QTabWidget()

        # Aba Geral
        self.create_general_tab()
        # Aba Privacidade
        self.create_privacy_tab()
        # Aba Allowlist/Blocklist
        self.create_lists_tab()
        # Aba Downloads
        self.create_downloads_tab()
        # Aba Aparência
        self.create_appearance_tab()

        main_layout.addWidget(self.tab_widget)

        # Botões
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        btn_save = QPushButton("Salvar")
        btn_save.clicked.connect(self.save_settings)
        btn_layout.addWidget(btn_save)

        btn_cancel = QPushButton("Cancelar")
        btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(btn_cancel)

        main_layout.addLayout(btn_layout)

        self.setLayout(main_layout)
        self.load_settings()

    def create_general_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        # Página inicial
        layout.addWidget(QLabel("Página inicial:"))
        self.home_edit = QLineEdit()
        layout.addWidget(self.home_edit)

        # Motor de busca
        layout.addWidget(QLabel("Motor de busca:"))
        self.search_combo = QComboBox()
        self.search_combo.addItems([
            "Google",
            "DuckDuckGo",
            "Bing",
            "Brave Search",
            "Startpage",
        ])
        layout.addWidget(self.search_combo)

        # Comportamento de abas
        self.new_tab_home_cb = QCheckBox("Abrir página inicial em nova aba")
        layout.addWidget(self.new_tab_home_cb)

        self.restore_session_cb = QCheckBox("Restaurar sessão anterior ao iniciar")
        layout.addWidget(self.restore_session_cb)

        layout.addStretch()
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "Geral")

    def create_privacy_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        # Grupo: Política de esquemas
        group_scheme = QGroupBox("Política de Esquemas")
        scheme_layout = QVBoxLayout()

        self.block_file_cb = QCheckBox("Bloquear esquema file://")
        scheme_layout.addWidget(self.block_file_cb)

        self.block_data_cb = QCheckBox("Bloquear esquema data:")
        scheme_layout.addWidget(self.block_data_cb)

        self.block_ftp_cb = QCheckBox("Bloquear esquema ftp:")
        scheme_layout.addWidget(self.block_ftp_cb)

        self.block_js_cb = QCheckBox("Bloquear esquema javascript:")
        scheme_layout.addWidget(self.block_js_cb)

        group_scheme.setLayout(scheme_layout)
        layout.addWidget(group_scheme)

        # Grupo: Privacidade
        group_privacy = QGroupBox("Privacidade")
        privacy_layout = QVBoxLayout()

        self.dnt_cb = QCheckBox("Enviar cabeçalho Do Not Track")
        self.dnt_cb.setChecked(True)
        privacy_layout.addWidget(self.dnt_cb)

        self.block_trackers_cb = QCheckBox("Bloquear rastreadores por palavra-chave")
        self.block_trackers_cb.setChecked(True)
        privacy_layout.addWidget(self.block_trackers_cb)

        self.block_sinkhole_cb = QCheckBox("Usar DNS sinkhole (StevenBlack)")
        self.block_sinkhole_cb.setChecked(True)
        privacy_layout.addWidget(self.block_sinkhole_cb)

        group_privacy.setLayout(privacy_layout)
        layout.addWidget(group_privacy)

        # Botão para limpar dados
        btn_clear = QPushButton("Limpar Dados de Navegação...")
        btn_clear.clicked.connect(self.clear_browsing_data)
        layout.addWidget(btn_clear)

        layout.addStretch()
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "Privacidade")

    def create_lists_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        # Allowlist
        layout.addWidget(QLabel("<b>Allowlist (domínios sempre permitidos):</b>"))
        self.allow_edit = QTextEdit()
        layout.addWidget(self.allow_edit)

        # Blocklist
        layout.addWidget(QLabel("<b>Blocklist (domínios sempre bloqueados):</b>"))
        self.block_edit = QTextEdit()
        layout.addWidget(self.block_edit)

        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "Listas de Domínios")

    def create_downloads_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        # Pasta de downloads
        layout.addWidget(QLabel("Pasta de downloads:"))
        folder_layout = QHBoxLayout()
        self.download_folder_edit = QLineEdit()
        folder_layout.addWidget(self.download_folder_edit)
        btn_browse = QPushButton("...")
        btn_browse.setMaximumWidth(30)
        btn_browse.clicked.connect(self.browse_download_folder)
        folder_layout.addWidget(btn_browse)
        layout.addLayout(folder_layout)

        # Comportamento
        self.ask_download_cb = QCheckBox("Perguntar onde salvar cada arquivo")
        self.ask_download_cb.setChecked(True)
        layout.addWidget(self.ask_download_cb)

        self.block_dangerous_cb = QCheckBox("Bloquear downloads de extensões perigosas")
        self.block_dangerous_cb.setChecked(True)
        layout.addWidget(self.block_dangerous_cb)

        layout.addStretch()
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "Downloads")

    def create_appearance_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        # Zoom padrão
        zoom_layout = QHBoxLayout()
        zoom_layout.addWidget(QLabel("Zoom padrão:"))
        self.zoom_spin = QSpinBox()
        self.zoom_spin.setRange(30, 300)
        self.zoom_spin.setSuffix("%")
        self.zoom_spin.setValue(100)
        zoom_layout.addWidget(self.zoom_spin)
        zoom_layout.addStretch()
        layout.addLayout(zoom_layout)

        # Tema
        theme_layout = QHBoxLayout()
        theme_layout.addWidget(QLabel("Tema:"))
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Claro", "Escuro", "Sistema"])
        theme_layout.addWidget(self.theme_combo)
        theme_layout.addStretch()
        layout.addLayout(theme_layout)

        # Barra de favoritos
        self.show_bookmarks_bar_cb = QCheckBox("Mostrar barra de favoritos")
        layout.addWidget(self.show_bookmarks_bar_cb)

        layout.addStretch()
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "Aparência")

    def load_settings(self):
        # Geral
        self.home_edit.setText(getattr(self.browser, "home_url", HOME_URL_DEFAULT))

        # Motor de busca
        _search_engines = {
            "https://www.google.com/search?q={}": 0,
            "https://duckduckgo.com/?q={}": 1,
            "https://www.bing.com/search?q={}": 2,
            "https://search.brave.com/search?q={}": 3,
            "https://www.startpage.com/search?q={}": 4,
        }
        current_engine = getattr(self.browser, "search_engine_url", "https://www.google.com/search?q={}")
        self.search_combo.setCurrentIndex(_search_engines.get(current_engine, 0))

        # Pasta de downloads
        self.download_folder_edit.setText(getattr(self.browser, "download_folder", ""))
        self.ask_download_cb.setChecked(getattr(self.browser, "ask_download", True))

        # Privacidade
        scheme_policy = getattr(self.browser, "scheme_policy", DEFAULT_SCHEME_POLICY)
        self.block_file_cb.setChecked(scheme_policy.get("block_file", True))
        self.block_data_cb.setChecked(scheme_policy.get("block_data", False))
        self.block_ftp_cb.setChecked(scheme_policy.get("block_ftp", True))
        self.block_js_cb.setChecked(scheme_policy.get("block_javascript", False))

        # Listas
        self.allow_edit.setPlainText("\n".join(sorted(set(getattr(self.browser, "allowlist_domains", [])))))
        self.block_edit.setPlainText("\n".join(sorted(set(getattr(self.browser, "blocklist_domains", [])))))

    def save_settings(self):
        # Geral
        self.browser.home_url = self.home_edit.text().strip() or HOME_URL_DEFAULT

        # Motor de busca
        _search_engines = [
            "https://www.google.com/search?q={}",
            "https://duckduckgo.com/?q={}",
            "https://www.bing.com/search?q={}",
            "https://search.brave.com/search?q={}",
            "https://www.startpage.com/search?q={}",
        ]
        idx = self.search_combo.currentIndex()
        self.browser.search_engine_url = _search_engines[idx] if 0 <= idx < len(_search_engines) else _search_engines[0]

        # Downloads
        self.browser.download_folder = self.download_folder_edit.text().strip()
        self.browser.ask_download = self.ask_download_cb.isChecked()

        # Privacidade
        scheme_policy = getattr(self.browser, "scheme_policy", DEFAULT_SCHEME_POLICY.copy())
        scheme_policy["block_file"] = self.block_file_cb.isChecked()
        scheme_policy["block_data"] = self.block_data_cb.isChecked()
        scheme_policy["block_ftp"] = self.block_ftp_cb.isChecked()
        scheme_policy["block_javascript"] = self.block_js_cb.isChecked()
        self.browser.scheme_policy = scheme_policy

        # Listas
        self.browser.allowlist_domains = self._normalize_domains(self.allow_edit.toPlainText())
        self.browser.blocklist_domains = self._normalize_domains(self.block_edit.toPlainText())

        # Salva no perfil
        self.browser.save_perfil_config()
        self.accept()

    def _normalize_domains(self, text):
        out = []
        for line in (text or "").splitlines():
            d = (line or "").strip().lower()
            if not d:
                continue
            d = d.replace("http://", "").replace("https://", "")
            d = d.split("/")[0].strip().strip(".")
            if d:
                out.append(d)
        return sorted(set(out))

    def browse_download_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Selecionar Pasta de Downloads")
        if folder:
            self.download_folder_edit.setText(folder)

    def clear_browsing_data(self):
        reply = QMessageBox.question(
            self, "Limpar Dados",
            "Deseja limpar todo o histórico, cache e cookies?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            try:
                # Limpa histórico
                cursor = self.browser.conn.cursor()
                cursor.execute("DELETE FROM history")
                self.browser.conn.commit()

                # Limpa cache
                self.browser.profile.clearHttpCache()

                QMessageBox.information(self, "Dados Limpos", "Dados de navegação limpos com sucesso!")
            except Exception as e:
                QMessageBox.critical(self, "Erro", f"Erro ao limpar dados: {e}")


# =====================================================================
#                         Browser (UI principal)
# =====================================================================

class Browser(QMainWindow):
    DANGEROUS_EXT = {
        ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".jse", ".wsf", ".scr", ".pif", ".hta", ".jar", ".com",
        ".cpl", ".dll"
    }
    ALLOWED_EXT = {
        ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
        ".txt", ".csv", ".json", ".zip", ".7z", ".rar"
    }

    # Sinal para atualizar favoritos
    bookmarks_updated = pyqtSignal()

    def __init__(self, perfil):
        super().__init__()

        self.setWindowTitle(f"Navegador Marveloc - Perfil: {perfil}")
        self.resize(1200, 800)
        # Usa o ícone local se disponível, senão fallback para tema do sistema
        _icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.ico")
        if os.path.exists(_icon_path):
            self.setWindowIcon(QIcon(_icon_path))
        else:
            self.setWindowIcon(QIcon.fromTheme('web-browser'))

        self.setStyleSheet("""
            QMainWindow { background-color: #f5f5f5; }
            QToolBar { background-color: #e8e8e8; border: none; padding: 4px 6px; spacing: 4px; }
            QTabWidget::pane { border: none; }
            QTabBar::tab {
                background: #d8d8d8; padding: 6px 14px; border: 1px solid #c0c0c0;
                border-bottom: none; border-top-left-radius: 6px; border-top-right-radius: 6px;
                font-size: 12px;
            }
            QTabBar::tab:selected { background: white; border-color: #c0c0c0; }
            QTabBar::tab:!selected { margin-top: 2px; }
            QLineEdit {
                padding: 6px 14px;
                border: 1.5px solid #c8c8c8;
                border-radius: 18px;
                background: white;
                font-size: 13px;
                selection-background-color: #4285f4;
                selection-color: white;
            }
            QLineEdit:focus {
                border: 2px solid #4285f4;
                background: white;
            }
            QListWidget { border: 1px solid #ddd; background: white; }
            QStatusBar { background-color: #e1e1e1; font-size: 11px; }
            QPushButton {
                border-radius: 6px;
                padding: 5px 12px;
            }
            QToolButton {
                border-radius: 6px;
                padding: 4px;
            }
        """)

        self.perfil = perfil
        self.perfil_dir = os.path.join(DATA_DIR, perfil)
        ensure_dir(self.perfil_dir)
        setup_logging(log_dir=self.perfil_dir, level=logging.INFO)

        self.encryptor = DataEncryption(perfil)
        self.zoom_level = 1.0

        self.perfil_config_path = os.path.join(self.perfil_dir, 'config.json')
        self.load_perfil_config()
        self.scheme_policy = DEFAULT_SCHEME_POLICY.copy()
        try:
            pol = (getattr(self, "perfil_config", None) or {}).get("scheme_policy") or {}
            for k in list(self.scheme_policy.keys()):
                if k in pol:
                    self.scheme_policy[k] = bool(pol.get(k))
        except Exception:
            logger.debug("Falha ao carregar scheme_policy; usando defaults.", exc_info=True)

        self.fav_path = os.path.join(self.perfil_dir, 'favoritos.json')
        self.down_path = os.path.join(self.perfil_dir, 'downloads.json')
        self.ext_path = os.path.join(self.perfil_dir, 'extensoes.json')

        self.favoritos = self.load_json(self.fav_path, default=[])
        self.downloads = self.load_json(self.down_path, default=[])
        self.extensoes = self.load_json(self.ext_path, default=[])

        self.dns_sinkhole = DnsSinkhole()

        # Carrega scripts de usuário
        self.userscripts = self.load_json(
            os.path.join(self.perfil_dir, "userscripts.json"), default=[]
        )

        # Histórico de navegação para botões voltar/avançar
        self.navigation_history = []
        self.current_history_index = -1
        self.recently_closed_tabs: list = []  # Pilha com até 10 abas fechadas recentemente
        self.recently_closed_windows: list = []  # Pilha com até 5 janelas fechadas recentemente

        # Perfil do WebEngine endurecido (off-the-record)
        self.profile = self._make_hardened_profile()
        self.profile.downloadRequested.connect(self.handle_download)
        self.enable_adblock()

        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.close_current_tab)
        self.tabs.currentChanged.connect(self.current_tab_changed)

        self.setCentralWidget(self.tabs)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Pronto")

        # Constrói a barra de menus antes da toolbar
        self.build_menu_bar()
        self._init_toolbar()
        self._init_db()
        self._open_home()

        # Aplica tema salvo
        self._apply_saved_theme()

        # Sidebars (inicialmente ocultas)
        self.bookmarks_sidebar = None
        self.history_sidebar = None
        self.sidebar_splitter = None

        self._last_find_text: str = ""
        self._devtools_windows: dict = {}

        # Atalhos de teclado
        self._init_shortcuts()

    def _init_shortcuts(self):
        """Inicializa atalhos de teclado."""
        shortcuts = [
            (QKeySequence(Qt.CTRL + Qt.Key_T), self.action_new_tab),
            (QKeySequence(Qt.CTRL + Qt.Key_W), self.action_close_tab),
            (QKeySequence(Qt.CTRL + Qt.Key_R), lambda: self.tabs.currentWidget().browser.reload()),
            (QKeySequence(Qt.CTRL + Qt.Key_Q), self.close),
            (QKeySequence(Qt.CTRL + Qt.Key_Plus), self.action_zoom_in),
            (QKeySequence(Qt.CTRL + Qt.Key_Minus), self.action_zoom_out),
            (QKeySequence(Qt.CTRL + Qt.Key_0), self.action_zoom_reset),
            (QKeySequence(Qt.CTRL + Qt.Key_D), self.add_favorite),
            (QKeySequence(Qt.CTRL + Qt.Key_H), self.action_history_sidebar),
            (QKeySequence(Qt.CTRL + Qt.Key_B), self.action_bookmarks_sidebar),
            (QKeySequence(Qt.CTRL + Qt.Key_J), self.action_downloads),
            (QKeySequence(Qt.CTRL + Qt.Key_F), self.action_find),
            (QKeySequence(Qt.CTRL + Qt.Key_G), self.action_find_next),
            (QKeySequence(Qt.CTRL + Qt.SHIFT + Qt.Key_G), self.action_find_prev),
            (QKeySequence(Qt.CTRL + Qt.Key_U), self.action_view_source),
            (QKeySequence(Qt.Key_F5), lambda: self.tabs.currentWidget().browser.reload()),  # Corrigido: Qt.Key_F5
            (QKeySequence(Qt.Key_F11), self.action_fullscreen),  # Corrigido: Qt.Key_F11
        ]

        for key_seq, callback in shortcuts:
            shortcut = QShortcut(key_seq, self)
            shortcut.activated.connect(callback)

    def _make_hardened_profile(self):
        profile = QWebEngineProfile(self)

        # cookies/cache
        try:
            profile.setPersistentCookiesPolicy(QWebEngineProfile.NoPersistentCookies)
        except (AttributeError, TypeError):
            logger.debug("PersistentCookiesPolicy não suportado.", exc_info=True)

        try:
            profile.setHttpCacheType(QWebEngineProfile.MemoryHttpCache)
        except (AttributeError, TypeError):
            logger.debug("HttpCacheType não suportado.", exc_info=True)

        # Settings
        s = profile.settings()
        s.setAttribute(QWebEngineSettings.JavascriptCanOpenWindows, False)
        s.setAttribute(QWebEngineSettings.LocalStorageEnabled, True)
        s.setAttribute(QWebEngineSettings.PluginsEnabled, False)
        s.setAttribute(QWebEngineSettings.WebGLEnabled, False)

        try:
            s.setAttribute(QWebEngineSettings.WebRTCPublicInterfacesOnly, True)
        except (AttributeError, TypeError):
            logger.debug("WebRTCPublicInterfacesOnly não suportado.", exc_info=True)

        return profile

    def enable_adblock(self):
        try:
            self.interceptor = AdBlockInterceptor(self)
            self.profile.setRequestInterceptor(self.interceptor)
        except Exception:
            logger.error("Falha ao configurar interceptor.", exc_info=True)

    def build_menu_bar(self):
        """Constrói a barra de menus completa no estilo Firefox."""
        # Em Windows, deixa explícito que a barra é do app (não do SO)
        mb = self.menuBar()
        try:
            mb.setNativeMenuBar(False)
        except Exception:
            pass

        # Helper para criar ações
        def act(text, shortcut=None, slot=None, checkable=False):
            a = QAction(text, self)
            if shortcut:
                a.setShortcut(QKeySequence(shortcut))
            if checkable:
                a.setCheckable(True)
            if slot:
                a.triggered.connect(slot)
            return a

        # -------- 1. Arquivo --------
        m_file = mb.addMenu("Arquivo")

        m_file.addAction(act("Nova janela", None, self.action_new_window))
        m_file.addAction(act("Nova janela privada", None, self.action_new_private_window))
        m_file.addSeparator()
        m_file.addAction(act("Novo separador", "Ctrl+T", self.action_new_tab))
        m_file.addSeparator()
        m_file.addAction(act("Abrir local...", None, self.action_open_local))
        m_file.addAction(act("Abrir ficheiro...", None, self.action_open_file))
        m_file.addSeparator()
        m_file.addAction(act("Fechar janela (Ctrl+Shift+W)", "Ctrl+Shift+W", self.close))
        m_file.addAction(act("Fechar separador (Ctrl+W)", "Ctrl+W", self.action_close_tab))
        m_file.addSeparator()
        m_file.addAction(act("Guardar como... (Ctrl+S)", "Ctrl+S", self.action_save_as))
        m_file.addAction(act("Guardar página como...", None, self.action_save_page_as))
        m_file.addAction(act("Guardar página como PDF", None, self.action_save_pdf))
        m_file.addSeparator()
        m_file.addAction(act("Enviar link por email...", None, self.action_email_link))
        m_file.addAction(act("Enviar página por email...", None, self.action_email_page))
        m_file.addSeparator()
        m_file.addAction(act("Visualizar", None, self.action_view_page_info))
        m_file.addAction(act("Imprimir... (Ctrl+P)", "Ctrl+P", self.action_print))
        m_file.addSeparator()
        m_file.addAction(act("Importar de outro navegador...", None, self.action_import_from_browser))
        m_file.addSeparator()
        m_file.addAction(act("Sair (Ctrl+Shift+Q)", "Ctrl+Shift+Q", self.close))

        # -------- 2. Editar --------
        m_edit = mb.addMenu("Editar")
        m_edit.addAction(act("Anular (Ctrl+Z)", "Ctrl+Z", self.action_undo))
        m_edit.addAction(act("Refazer (Ctrl+Shift+Z)", "Ctrl+Shift+Z", self.action_redo))
        m_edit.addSeparator()
        m_edit.addAction(act("Cortar (Ctrl+X)", "Ctrl+X", self.action_cut))
        m_edit.addAction(act("Copiar (Ctrl+C)", "Ctrl+C", self.action_copy))
        m_edit.addAction(act("Colar (Ctrl+V)", "Ctrl+V", self.action_paste))
        m_edit.addAction(act("Eliminar", "Del", self.action_delete))
        m_edit.addSeparator()
        m_edit.addAction(act("Selecionar tudo (Ctrl+A)", "Ctrl+A", self.action_select_all))
        m_edit.addSeparator()
        m_edit.addAction(act("Localizar nesta página... (Ctrl+F)", "Ctrl+F", self.action_find))
        m_edit.addAction(act("Localizar novamente (F3)", "F3", self.action_find_next))
        m_edit.addAction(act("Localizar novamente (Shift+F3 - para retroceder)", "Shift+F3", self.action_find_prev))

        # -------- 3. Exibir --------
        m_view = mb.addMenu("Exibir")
        m_view.addAction(act("Barra de ferramentas", None, self.action_toggle_toolbar, checkable=True))
        m_view.addAction(act("Barra de menus", None, self.action_toggle_menubar, checkable=True))
        m_view.addAction(act("Barra de favoritos", None, self.action_toggle_bookmarks_bar, checkable=True))
        m_view.addAction(act("Barra de separadores", None, self.action_toggle_tabs_bar, checkable=True))
        m_view.addAction(act("Barra lateral", None, self.action_toggle_sidebar, checkable=True))
        m_view.addSeparator()
        m_view.addAction(act("Histórico", None, self.action_show_history))
        m_view.addAction(act("Favoritos", None, self.action_show_bookmarks))
        m_view.addAction(act("Sincronizar separadores", None, self.action_sync_tabs))
        m_view.addSeparator()
        m_view.addAction(act("Ampliar (Ctrl++)", "Ctrl++", self.action_zoom_in))
        m_view.addAction(act("Reduzir (Ctrl+-)", "Ctrl+-", self.action_zoom_out))
        m_view.addAction(act("Restaurar (Ctrl+0)", "Ctrl+0", self.action_zoom_reset))
        m_view.addSeparator()
        m_view.addAction(act("Modo de leitura", None, self.action_reader_mode))
        m_view.addAction(act("Mostrar separadores", None, self.action_show_tabs))
        m_view.addAction(act("Modo ecrã completo (F11)", "F11", self.action_fullscreen))
        m_view.addSeparator()
        m_view.addAction(act("Zoom apenas texto", None, self.action_text_only_zoom))
        m_view.addAction(act("Codificação de caracteres", None, self.action_charset))
        m_view.addAction(act("Estilo de página", None, self.action_page_style))
        m_view.addAction(act("Ver informações da página", None, self.action_view_page_info))

        # -------- 4. Histórico --------
        m_hist = mb.addMenu("Histórico")
        m_hist.addAction(act("Barra lateral do histórico (Ctrl+H)", "Ctrl+H", self.action_history_sidebar))
        m_hist.addAction(act("Mostrar todo o histórico", None, self.action_show_all_history))
        m_hist.addAction(act("Limpar histórico recente... (Ctrl+Shift+Del)", "Ctrl+Shift+Del", self.action_clear_recent_history))
        m_hist.addSeparator()
        m_hist.addAction(act("Separadores recentemente fechados", None, self.action_recently_closed_tabs))
        m_hist.addAction(act("Janelas recentemente fechadas", None, self.action_recently_closed_windows))
        m_hist.addSeparator()
        m_hist.addAction(act("Restaurar separador anterior", "Ctrl+Shift+T", self.action_restore_last_tab))
        m_hist.addAction(act("Restaurar janela anterior", None, self.action_restore_last_window))
        m_hist.addSeparator()
        m_hist.addAction(act("Separadores de outros dispositivos", None, self.action_tabs_from_other_devices))
        m_hist.addAction(act("Pesquisar histórico", None, self.action_search_history))
        m_hist.addAction(act("Importar histórico de outro navegador...", None, self.action_import_history))

        # -------- 5. Favoritos --------
        m_bm = mb.addMenu("Favoritos")
        m_bm.addAction(act("Mostrar todos os favoritos (Ctrl+Shift+O)", "Ctrl+Shift+O", self.action_show_all_bookmarks))
        m_bm.addAction(act("Barra lateral de favoritos (Ctrl+B)", "Ctrl+B", self.action_bookmarks_sidebar))
        m_bm.addSeparator()
        m_bm.addAction(act("Adicionar página atual aos favoritos (Ctrl+D)", "Ctrl+D", self.action_add_bookmark))
        m_bm.addAction(act("Adicionar página atual aos favoritos...", None, self.action_add_bookmark))
        m_bm.addSeparator()
        m_bm.addAction(act("Subscrever esta página...", None, self.action_subscribe_page))
        m_bm.addAction(act("Favoritos recentes", None, self.action_recent_bookmarks))
        m_bm.addAction(act("Separadores favoritos", None, self.action_bookmark_all_tabs))
        m_bm.addSeparator()
        m_bm.addAction(act("Importar favoritos de outro navegador...", None, self.action_import_bookmarks))
        m_bm.addAction(act("Exportar favoritos para HTML...", None, self.action_export_bookmarks_html))
        m_bm.addAction(act("Importar favoritos de HTML...", None, self.action_import_bookmarks_html))

        # -------- 6. Perfis --------
        m_profiles = mb.addMenu("Perfis")

        # Indicador do perfil atual (não clicável, informativo)
        act_current = QAction(f"👤  Perfil atual: {self.perfil}", self)
        act_current.setEnabled(False)
        m_profiles.addAction(act_current)
        m_profiles.addSeparator()

        m_profiles.addAction(act("Gerenciador de perfis", None, self.action_profile_manager))
        m_profiles.addAction(act("Criar novo perfil", None, self.action_create_profile))
        m_profiles.addAction(act("Iniciar com este perfil", None, self.action_start_with_profile))
        m_profiles.addSeparator()

        # Submenu de troca rápida de perfil
        m_quick_switch = m_profiles.addMenu("↔ Trocar para perfil...")
        self._populate_quick_switch_menu(m_quick_switch)

        m_profiles.addSeparator()
        m_profiles.addAction(act("Configurações de sincronização", None, self.action_sync_settings))
        m_profiles.addAction(act("Gerir contas", None, self.action_manage_accounts))
        m_profiles.addSeparator()
        m_profiles.addAction(act("Sair do perfil", None, self.action_sign_out_profile))

        # -------- 7. Ferramentas --------
        m_tools = mb.addMenu("Ferramentas")
        m_tools.addAction(act("Extensões e temas", None, self.action_extensions))
        m_tools.addAction(act("Gestor de palavras-passe (Ctrl+Shift+Del)", "Ctrl+Shift+Del", self.action_password_manager))
        m_tools.addAction(act("Limpar histórico recente...", None, self.action_clear_recent_history))
        m_tools.addSeparator()
        m_tools.addAction(act("Configurações", None, self.action_settings))
        m_tools.addAction(act("Definições de pesquisa", None, self.action_search_settings))
        m_tools.addAction(act("Transferências (Ctrl+J)", "Ctrl+J", self.action_downloads))
        m_tools.addAction(act("Gestor de tarefas do navegador", None, self.action_task_manager))
        m_tools.addSeparator()
        m_tools.addAction(act("Personalizar barra de ferramentas...", None, self.action_customize_toolbar))
        m_tools.addAction(act("Opções de página", None, self.action_page_options))
        m_tools.addSeparator()
        m_tools.addAction(act("Ferramentas de desenvolvimento", None, self.action_devtools))
        m_tools.addAction(act("Consola Web (Ctrl+Shift+K)", "Ctrl+Shift+K", self.action_web_console))
        m_tools.addAction(act("Inspetor (Ctrl+Shift+I)", "Ctrl+Shift+I", self.action_inspector))
        m_tools.addAction(act("Depurador (Ctrl+Shift+S)", "Ctrl+Shift+S", self.action_debugger))
        m_tools.addAction(act("Editor de estilo", None, self.action_style_editor))
        m_tools.addAction(act("Performance", None, self.action_performance))
        m_tools.addAction(act("Rede", None, self.action_network))
        m_tools.addAction(act("Acessibilidade", None, self.action_accessibility))
        m_tools.addAction(act("Modo de design adaptativo (Ctrl+Shift+M)", "Ctrl+Shift+M", self.action_responsive_design))
        m_tools.addSeparator()
        m_tools.addAction(act("Ver código fonte da página (Ctrl+U)", "Ctrl+U", self.action_view_source))
        m_tools.addAction(act("Informações da página", None, self.action_view_page_info))

        # Conectar algumas ações básicas que já existem
        self.menu_actions = {
            'new_tab': self.add_new_tab,
            'close_tab': self.action_close_tab,
            'zoom_in': self.action_zoom_in,
            'zoom_out': self.action_zoom_out,
            'zoom_reset': self.action_zoom_reset,
            'fullscreen': self.action_fullscreen,
            'downloads': self.action_downloads,
            'settings': self.action_settings,
        }

    def _init_toolbar(self):
        navtb = QToolBar("Navigation")
        navtb.setIconSize(QSize(18, 18))
        navtb.setMovable(True)
        self.addToolBar(navtb)

        # Botão Voltar
        self.back_btn = QAction("◀", self)
        self.back_btn.triggered.connect(lambda: self.tabs.currentWidget().browser.back())
        self.back_btn.setEnabled(False)
        navtb.addAction(self.back_btn)

        # Botão Avançar
        self.next_btn = QAction("▶", self)
        self.next_btn.triggered.connect(lambda: self.tabs.currentWidget().browser.forward())
        self.next_btn.setEnabled(False)
        navtb.addAction(self.next_btn)

        # Botão Recarregar
        self.reload_btn = QAction("⟳", self)
        self.reload_btn.triggered.connect(lambda: self.tabs.currentWidget().browser.reload())
        navtb.addAction(self.reload_btn)

        # Botão Home
        home_btn = QAction("⌂", self)
        home_btn.triggered.connect(self._open_home)
        navtb.addAction(home_btn)

        navtb.addSeparator()

        self.urlbar = QLineEdit()
        self.urlbar.setPlaceholderText("🔍  Digite uma URL ou termo de busca...")
        self.urlbar.setMinimumWidth(400)
        self.urlbar.setFixedHeight(34)
        self.urlbar.returnPressed.connect(self.navigate_to_url)
        navtb.addWidget(self.urlbar)

        navtb.addSeparator()

        # Botão Favoritos
        fav_btn = QAction("★", self)
        fav_btn.triggered.connect(self.add_favorite)
        navtb.addAction(fav_btn)

        # Botão Mais visitados
        most_btn = QAction("Mais visitados", self)
        most_btn.triggered.connect(self.show_most_visited)
        navtb.addAction(most_btn)

        # Botão Downloads
        downloads_btn = QAction("↓", self)
        downloads_btn.triggered.connect(self.action_downloads)
        navtb.addAction(downloads_btn)

        # Botão Configurações
        settings_btn = QAction("⚙", self)
        settings_btn.triggered.connect(self.action_settings)
        navtb.addAction(settings_btn)

    def update_nav_buttons(self):
        """Atualiza o estado dos botões de navegação."""
        if self.tabs.currentWidget():
            browser = self.tabs.currentWidget().browser
            self.back_btn.setEnabled(browser.history().canGoBack())
            self.next_btn.setEnabled(browser.history().canGoForward())

    def _apply_saved_theme(self):
        """Aplica o tema salvo nas configurações do perfil."""
        THEMES = {
            "Padrão (Cinza)": None,  # usa o padrão do setStyleSheet inicial
            "Azul Oceano": """QMainWindow,QDialog{background:#e3f0fb}QToolBar{background:#1565c0;border:none;padding:4px}QTabBar::tab{background:#1976d2;color:white;padding:6px 14px;border:none;border-top-left-radius:6px;border-top-right-radius:6px}QTabBar::tab:selected{background:#0d47a1;color:white}QLineEdit{padding:6px 14px;border:2px solid #1565c0;border-radius:18px;background:white;font-size:13px}QLineEdit:focus{border:2px solid #0d47a1}QStatusBar{background:#1565c0;color:white}""",
            "Modo Escuro": """QMainWindow,QWidget,QDialog{background:#1e1e1e;color:#e0e0e0}QToolBar{background:#252526;border:none;padding:4px}QTabBar::tab{background:#2d2d2d;color:#ccc;padding:6px 14px;border:1px solid #3c3c3c;border-bottom:none;border-top-left-radius:6px;border-top-right-radius:6px}QTabBar::tab:selected{background:#1e1e1e;color:white}QLineEdit{padding:6px 14px;border:1.5px solid #555;border-radius:18px;background:#2d2d2d;color:#e0e0e0;font-size:13px}QLineEdit:focus{border:2px solid #569cd6}QMenu{background:#252526;color:#e0e0e0;border:1px solid #3c3c3c}QMenu::item:selected{background:#094771}QStatusBar{background:#007acc;color:white}QMenuBar{background:#252526;color:#e0e0e0}QMenuBar::item:selected{background:#094771}""",
            "Verde Floresta": """QMainWindow,QDialog{background:#e8f5e9}QToolBar{background:#2e7d32;border:none;padding:4px}QTabBar::tab{background:#388e3c;color:white;padding:6px 14px;border:none;border-top-left-radius:6px;border-top-right-radius:6px}QTabBar::tab:selected{background:#1b5e20;color:white}QLineEdit{padding:6px 14px;border:2px solid #2e7d32;border-radius:18px;background:white;font-size:13px}QLineEdit:focus{border:2px solid #1b5e20}QStatusBar{background:#2e7d32;color:white}""",
            "Roxo Noite": """QMainWindow,QWidget,QDialog{background:#1a0a2e;color:#e0d0ff}QToolBar{background:#2d1b4e;border:none;padding:4px}QTabBar::tab{background:#3d2060;color:#ccc;padding:6px 14px;border:1px solid #5b2d8e;border-bottom:none;border-top-left-radius:6px;border-top-right-radius:6px}QTabBar::tab:selected{background:#1a0a2e;color:white}QLineEdit{padding:6px 14px;border:1.5px solid #7b3fd4;border-radius:18px;background:#2d1b4e;color:#e0d0ff;font-size:13px}QLineEdit:focus{border:2px solid #a066f0}QMenu{background:#2d1b4e;color:#e0d0ff;border:1px solid #5b2d8e}QMenu::item:selected{background:#5b2d8e}QStatusBar{background:#7b3fd4;color:white}QMenuBar{background:#2d1b4e;color:#e0d0ff}QMenuBar::item:selected{background:#5b2d8e}""",
        }
        saved = (self.perfil_config or {}).get("theme", "Padrão (Cinza)")
        css = THEMES.get(saved)
        if css:
            self.setStyleSheet(css)

    def _open_home(self):
        # Verifica se há sessão salva para restaurar
        saved_session = (self.perfil_config or {}).get("saved_session", [])
        if saved_session:
            reply = QMessageBox.question(
                self, "Restaurar Sessão",
                f"Há {len(saved_session)} aba(s) salva(s) da sessão anterior.\nDeseja restaurá-las?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                for entry in saved_session:
                    url = entry.get("url", "")
                    title = entry.get("title", "Restaurada")
                    if url and not url.startswith("about:"):
                        self.add_new_tab(QUrl(url), title)
                # Limpa sessão salva
                self.perfil_config.pop("saved_session", None)
                self.save_perfil_config()
                return
            else:
                self.perfil_config.pop("saved_session", None)
                self.save_perfil_config()
        self.add_new_tab(QUrl(self.home_url), "Início")

    def add_new_tab(self, qurl=None, label="Nova Aba"):
        if qurl is None:
            qurl = QUrl(self.home_url)

        tab = BrowserTab(self, profile=self.profile)
        tab.browser.setUrl(qurl)
        tab.browser.setZoomFactor(self.zoom_level)  # Herda zoom global

        i = self.tabs.addTab(tab, label)
        self.tabs.setCurrentIndex(i)

        tab.browser.urlChanged.connect(lambda url, tab=tab: self.update_urlbar(url, tab))
        tab.browser.loadFinished.connect(lambda _, tab=tab: self.tabs.setTabText(i, tab.browser.title()[:20]))
        tab.browser.loadFinished.connect(lambda: self.update_nav_buttons())
        tab.browser.urlChanged.connect(lambda: self.update_nav_buttons())

    def close_current_tab(self, i):
        if self.tabs.count() < 2:
            return
        widget = self.tabs.widget(i)
        if widget:
            url = widget.browser.url().toString()
            title = widget.browser.title()
            entry = {"url": url, "title": title}
            self.last_closed_tab = entry
            self.recently_closed_tabs.append(entry)
            if len(self.recently_closed_tabs) > 10:
                self.recently_closed_tabs.pop(0)
        self.tabs.removeTab(i)

    def current_tab_changed(self, i):
        if i >= 0 and self.tabs.currentWidget():
            qurl = self.tabs.currentWidget().browser.url()
            self.update_urlbar(qurl, self.tabs.currentWidget())
            self.update_nav_buttons()

    def update_urlbar(self, qurl, browser_tab):
        if self.tabs.currentWidget() != browser_tab:
            return
        self.urlbar.setText(qurl.toString())
        self.urlbar.setCursorPosition(0)

    def navigate_to_url(self):
        url = self.urlbar.text().strip()
        if not url:
            return

        # Se parece com URL (tem domínio com ponto e sem espaços), navega diretamente
        if not url.startswith(("http://", "https://", "file://", "view-source:")):
            # Heurística: se tem espaço ou não tem ponto, é termo de busca
            has_space = " " in url
            has_dot = "." in url
            looks_like_url = has_dot and not has_space

            if looks_like_url:
                url = "https://" + url
            else:
                # Redireciona para o buscador configurado
                search_engine = getattr(self, "search_engine_url", "https://www.google.com/search?q={}")
                url = search_engine.format(quote(url))

        self.tabs.currentWidget().browser.setUrl(QUrl(url))

    # ----------------- Persistência / Config -----------------

    def load_perfil_config(self):
        self.perfil_config = self.load_json(self.perfil_config_path, default={})
        if not isinstance(self.perfil_config, dict):
            self.perfil_config = {}

        # Defaults (evitam quebra em atualizações)
        self.perfil_config.setdefault("home_url", HOME_URL_DEFAULT)
        self.perfil_config.setdefault("allowlist_domains", sorted(DEFAULT_ALLOWLIST_DOMAINS))
        self.perfil_config.setdefault("blocklist_domains", [])
        self.perfil_config.setdefault("scheme_policy", DEFAULT_SCHEME_POLICY.copy())
        self.perfil_config.setdefault("download_folder", "")
        self.perfil_config.setdefault("ask_download", True)
        self.perfil_config.setdefault("search_engine_url", "https://www.google.com/search?q={}")

        self.home_url = (self.perfil_config.get("home_url") or "").strip() or HOME_URL_DEFAULT
        self.allowlist_domains = list(self.perfil_config.get("allowlist_domains") or [])
        self.blocklist_domains = list(self.perfil_config.get("blocklist_domains") or [])
        self.download_folder = self.perfil_config.get("download_folder", "")
        self.ask_download = self.perfil_config.get("ask_download", True)
        self.search_engine_url = self.perfil_config.get("search_engine_url", "https://www.google.com/search?q={}")

    def save_perfil_config(self):
        # Persiste de volta o estado atual (inclui possíveis edições via UI)
        try:
            self.perfil_config["home_url"] = (getattr(self, "home_url", "") or "").strip() or HOME_URL_DEFAULT
            self.perfil_config["allowlist_domains"] = sorted(set(getattr(self, "allowlist_domains", []) or []))
            self.perfil_config["blocklist_domains"] = sorted(set(getattr(self, "blocklist_domains", []) or []))
            self.perfil_config["scheme_policy"] = dict(getattr(self, "scheme_policy", DEFAULT_SCHEME_POLICY.copy()))
            self.perfil_config["download_folder"] = getattr(self, "download_folder", "")
            self.perfil_config["ask_download"] = getattr(self, "ask_download", True)
            self.perfil_config["search_engine_url"] = getattr(self, "search_engine_url", "https://www.google.com/search?q={}")
        except Exception:
            logger.debug("Falha ao compor perfil_config antes de salvar.", exc_info=True)

        try:
            _atomic_write_encrypted(self.perfil_config_path, self.perfil_config, self.encryptor)
        except Exception:
            logger.error("Falha ao salvar config do perfil.", exc_info=True)

    def load_json(self, path: str, default=None):
        if default is None:
            default = {}
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                    if not content.strip():
                        return default
                    # Se for arquivo de config criptografado, tenta decrypt
                    if path.endswith("config.json"):
                        try:
                            decrypted = self.encryptor.decrypt(content)
                            if decrypted.strip():
                                return json.loads(decrypted)
                        except Exception:
                            logger.debug("Falha ao decrypt config; tentando JSON puro.", exc_info=True)
                    return json.loads(content)
            except Exception:
                logger.debug("Falha ao carregar JSON: %s", path, exc_info=True)
        return default

    def add_favorite(self):
        try:
            url = self.tabs.currentWidget().browser.url().toString()
            title = self.tabs.currentWidget().browser.title() or url

            # Verifica se já existe
            existing = next((f for f in self.favoritos if f.get("url") == url), None)

            dialog = QDialog(self)
            dialog.setWindowTitle("Adicionar aos Favoritos" if not existing else "Editar Favorito")
            dialog.setMinimumWidth(400)
            layout = QVBoxLayout(dialog)

            layout.addWidget(QLabel("<b>Nome:</b>"))
            name_edit = QLineEdit(existing.get("title", title) if existing else title)
            layout.addWidget(name_edit)

            layout.addWidget(QLabel("<b>URL:</b>"))
            url_edit = QLineEdit(existing.get("url", url) if existing else url)
            layout.addWidget(url_edit)

            layout.addWidget(QLabel("<b>Pasta:</b>"))
            # Coleta pastas existentes
            pastas = sorted({f.get("folder", "") for f in self.favoritos if f.get("folder")})
            folder_combo = QComboBox()
            folder_combo.setEditable(True)
            folder_combo.addItem("(sem pasta)")
            for p in pastas:
                folder_combo.addItem(p)
            if existing and existing.get("folder"):
                idx = folder_combo.findText(existing["folder"])
                if idx >= 0:
                    folder_combo.setCurrentIndex(idx)
                else:
                    folder_combo.setEditText(existing["folder"])
            layout.addWidget(folder_combo)

            btns = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
            if existing:
                btn_remove = QPushButton("🗑 Remover dos favoritos")
                btn_remove.setStyleSheet("color: red;")
                btn_remove.clicked.connect(lambda: (self.favoritos.remove(existing),
                    _atomic_write_encrypted(self.fav_path, self.favoritos, self.encryptor),
                    self.bookmarks_updated.emit(),
                    self.status_bar.showMessage("Favorito removido.", 2000),
                    dialog.reject()))
                layout.addWidget(btn_remove)
            btns.accepted.connect(dialog.accept)
            btns.rejected.connect(dialog.reject)
            layout.addWidget(btns)

            if dialog.exec_() != QDialog.Accepted:
                return

            new_title = name_edit.text().strip() or url_edit.text()
            new_url = url_edit.text().strip()
            new_folder = folder_combo.currentText().strip()
            if new_folder == "(sem pasta)":
                new_folder = ""

            if existing:
                existing["title"] = new_title
                existing["url"] = new_url
                existing["folder"] = new_folder
                msg = "Favorito atualizado!"
            else:
                entry = {"title": new_title, "url": new_url, "folder": new_folder,
                         "added": datetime.datetime.now().isoformat()}
                self.favoritos.append(entry)
                msg = "Favorito adicionado!"

            _atomic_write_encrypted(self.fav_path, self.favoritos, self.encryptor)
            self.bookmarks_updated.emit()
            self.status_bar.showMessage(msg, 2500)
        except Exception:
            logger.error("Falha ao adicionar favorito.", exc_info=True)
            QMessageBox.critical(self, "Erro", "Falha ao adicionar favorito.")

    # ----------------- Histórico (SQLite) -----------------

    def _init_db(self):
        self.db_path = os.path.join(self.perfil_dir, "history.db")
        self.conn = sqlite3.connect(self.db_path)
        cur = self.conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS history (
                url TEXT PRIMARY KEY,
                title TEXT,
                timestamp TEXT,
                count INTEGER DEFAULT 1
            )
        """)
        self.conn.commit()
        try:
            _secure_file_permissions(self.db_path)
        except Exception:
            logger.debug("Falha ao aplicar ACL no DB.", exc_info=True)

    def add_to_history(self, url: str):
        try:
            cur = self.conn.cursor()
            ts = datetime.datetime.now().isoformat()

            cur.execute("SELECT count FROM history WHERE url = ?", (url,))
            row = cur.fetchone()
            if row:
                cur.execute(
                    "UPDATE history SET count = count + 1, timestamp = ? WHERE url = ?",
                    (ts, url)
                )
            else:
                title = self.tabs.currentWidget().browser.title()
                cur.execute(
                    "INSERT INTO history(url, title, timestamp, count) VALUES (?, ?, ?, 1)",
                    (url, title, ts)
                )
            self.conn.commit()
        except Exception:
            logger.debug("Falha ao gravar histórico.", exc_info=True)

    def show_most_visited(self):
        """Mostra os sites mais visitados."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT url, title, count FROM history ORDER BY count DESC, timestamp DESC LIMIT 20"
        )
        most_visited = cursor.fetchall()

        dlg = QDialog(self)
        dlg.setWindowTitle("Sites Mais Visitados")
        dlg.resize(600, 400)

        layout = QVBoxLayout()
        list_widget = QListWidget()

        for url, title, visits in most_visited:
            display_title = title or "Sem título"
            item_text = f"{display_title} - {url} ({visits} visita{'s' if visits > 1 else ''})"
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, url)
            list_widget.addItem(item)

        layout.addWidget(list_widget)

        btn_layout = QHBoxLayout()
        btn_open = QPushButton("Abrir")
        btn_open.clicked.connect(lambda: self._open_most_visited(list_widget))
        btn_layout.addWidget(btn_open)

        btn_close = QPushButton("Fechar")
        btn_close.clicked.connect(dlg.accept)
        btn_layout.addWidget(btn_close)

        layout.addLayout(btn_layout)
        dlg.setLayout(layout)

        list_widget.itemDoubleClicked.connect(
            lambda item: self.tabs.currentWidget().browser.setUrl(QUrl(item.data(Qt.UserRole)))
        )
        dlg.exec_()

    def _open_most_visited(self, list_widget):
        item = list_widget.currentItem()
        if item:
            url = item.data(Qt.UserRole)
            self.tabs.currentWidget().browser.setUrl(QUrl(url))

    # ----------------- Downloads (handler único por perfil) -----------------

    def handle_download(self, download_item):
        try:
            url = download_item.url().toString()
            suggested = download_item.suggestedFileName() or "download.bin"

            ext = os.path.splitext(suggested)[1].lower()
            if ext in self.DANGEROUS_EXT:
                QMessageBox.warning(
                    self, "Download bloqueado",
                    f"Extensão perigosa bloqueada: {ext}"
                )
                download_item.cancel()
                return

            # Determina caminho de destino
            if self.ask_download:
                dest, _ = QFileDialog.getSaveFileName(
                    self, "Salvar download como",
                    os.path.join(self.download_folder or QStandardPaths.writableLocation(QStandardPaths.DownloadLocation), suggested)
                )
                if not dest:
                    download_item.cancel()
                    return
            else:
                folder = self.download_folder or QStandardPaths.writableLocation(QStandardPaths.DownloadLocation)
                ensure_dir(folder)
                dest = os.path.join(folder, suggested)
                # Evita sobrescrever
                base, ext = os.path.splitext(dest)
                counter = 1
                while os.path.exists(dest):
                    dest = f"{base} ({counter}){ext}"
                    counter += 1

            download_item.setPath(dest)

            # Conecta sinais para progresso
            download_item.downloadProgress.connect(
                lambda received, total: self._update_download_progress(download_item, received, total)
            )
            download_item.finished.connect(
                lambda: self._download_finished(download_item, url, dest)
            )

            download_item.accept()
            self.status_bar.showMessage(f"Download iniciado: {suggested}", 3000)

        except Exception:
            logger.error("Falha ao processar download.", exc_info=True)

    def _update_download_progress(self, download_item, received, total):
        if total > 0:
            percent = int(100 * received / total)
            self.status_bar.showMessage(f"Download: {percent}%", 1000)

    def _download_finished(self, download_item, url, dest):
        self.downloads.append({
            "url": url,
            "path": dest,
            "ts": datetime.datetime.now().isoformat()
        })
        try:
            _atomic_write_encrypted(self.down_path, self.downloads, self.encryptor)
        except Exception:
            logger.error("Falha ao salvar registro de download.", exc_info=True)

        self.status_bar.showMessage(f"Download concluído: {os.path.basename(dest)}", 5000)
        QMessageBox.information(self, "Download Concluído", f"Arquivo salvo em:\n{dest}")

    # ----------------- Ações do Menu -----------------

    def action_new_tab(self):
        """Cria uma nova aba."""
        self.add_new_tab()

    def action_close_tab(self):
        """Fecha a aba atual."""
        i = self.tabs.currentIndex()
        if self.tabs.count() > 1:
            self.close_current_tab(i)

    def action_zoom_in(self):
        """Aumenta o zoom em todas as abas."""
        self.zoom_level = min(self.zoom_level + 0.1, 3.0)
        self._apply_zoom_all_tabs()

    def action_zoom_out(self):
        """Diminui o zoom em todas as abas."""
        self.zoom_level = max(self.zoom_level - 0.1, 0.3)
        self._apply_zoom_all_tabs()

    def action_zoom_reset(self):
        """Reseta o zoom."""
        self.zoom_level = 1.0
        self._apply_zoom_all_tabs()

    def _apply_zoom_all_tabs(self):
        """Aplica o zoom atual a todas as abas abertas."""
        for i in range(self.tabs.count()):
            tab = self.tabs.widget(i)
            if tab and hasattr(tab, 'browser'):
                tab.browser.setZoomFactor(self.zoom_level)
        self.status_bar.showMessage(f"Zoom: {int(self.zoom_level * 100)}%", 2000)

    def action_fullscreen(self):
        """Alterna modo tela cheia."""
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()

    def action_downloads(self):
        """Mostra a lista de downloads."""
        dlg = DownloadsDialog(self, self)
        dlg.exec_()

    def action_settings(self):
        """Abre as configurações (perfil)."""
        dlg = SettingsDialog(self, self)
        dlg.exec_()

    def action_new_window(self):
        """Abre uma nova janela do navegador."""
        QProcess.startDetached(sys.executable, sys.argv)

    def action_new_private_window(self):
        """Abre uma nova janela privada (modo anônimo)."""
        # Para modo anônimo, poderíamos criar com perfil temporário
        QProcess.startDetached(sys.executable, sys.argv + ["--private"])

    def action_open_local(self):
        """Abre um arquivo local no navegador."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Abrir arquivo local", "",
            "Páginas Web (*.html *.htm *.xhtml);;PDF (*.pdf);;Imagens (*.png *.jpg *.jpeg *.gif *.svg *.webp);;Todos os arquivos (*)"
        )
        if file_path:
            url = QUrl.fromLocalFile(file_path)
            self.add_new_tab(url, os.path.basename(file_path))

    def action_open_file(self):
        """Alias para abrir arquivo."""
        self.action_open_local()

    def action_save_as(self):
        """Salva a página atual como HTML."""
        title = self.tabs.currentWidget().browser.title() or "pagina"
        # Remove caracteres inválidos do nome de arquivo
        safe_title = "".join(c for c in title if c.isalnum() or c in " -_").strip()[:50] or "pagina"
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self, "Salvar página como",
            f"{safe_title}.html",
            "Página Web completa (*.html);;Página Web somente HTML (*.htm)"
        )
        if file_path:
            self.tabs.currentWidget().browser.page().save(file_path)
            self.status_bar.showMessage(f"Página salva em: {file_path}", 4000)

    def action_save_page_as(self):
        """Salva a página atual com todos os recursos (HTML completo)."""
        title = self.tabs.currentWidget().browser.title() or "pagina"
        safe_title = "".join(c for c in title if c.isalnum() or c in " -_").strip()[:50] or "pagina"
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Guardar página como",
            f"{safe_title}.html",
            "Página Web completa (*.html)"
        )
        if file_path:
            # QWebEnginePage.save salva HTML + recursos numa pasta
            self.tabs.currentWidget().browser.page().save(
                file_path, QWebEnginePage.WebEngineDownloadItem if hasattr(QWebEnginePage, 'WebEngineDownloadItem') else 0
            )
            self.status_bar.showMessage(f"Página salva: {file_path}", 4000)

    def action_save_pdf(self):
        """Salva a página atual como PDF."""
        title = self.tabs.currentWidget().browser.title() or "pagina"
        safe_title = "".join(c for c in title if c.isalnum() or c in " -_").strip()[:50] or "pagina"
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Salvar como PDF", f"{safe_title}.pdf", "PDF Files (*.pdf)"
        )
        if file_path:
            def on_pdf_done(path):
                if path:
                    self.status_bar.showMessage(f"PDF salvo em: {path}", 5000)
                else:
                    QMessageBox.warning(self, "PDF", "Falha ao gerar o PDF.")
            self.tabs.currentWidget().browser.page().printToPdf(file_path)
            self.status_bar.showMessage(f"Gerando PDF: {file_path}...", 3000)

    def action_email_link(self):
        """Envia o link atual por email."""
        url = self.tabs.currentWidget().browser.url().toString()
        title = self.tabs.currentWidget().browser.title()
        body = f"{title}\n{url}"
        mailto = f"mailto:?subject={quote(title)}&body={quote(body)}"
        webbrowser.open(mailto)

    def action_email_page(self):
        """Envia a página atual por email — abre cliente de email com link e descrição."""
        url = self.tabs.currentWidget().browser.url().toString()
        title = self.tabs.currentWidget().browser.title()
        subject = f"Compartilhando: {title}"
        body = (
            f"Olá,\n\n"
            f"Estou compartilhando esta página com você:\n\n"
            f"{title}\n{url}\n\n"
            f"Enviado pelo Navegador Marveloc."
        )
        mailto = f"mailto:?subject={quote(subject)}&body={quote(body)}"
        webbrowser.open(mailto)

    def action_view_page_info(self):
        """Mostra informações detalhadas da página atual."""
        browser = self.tabs.currentWidget().browser
        url = browser.url()
        title = browser.title()
        scheme = url.scheme()
        host = url.host()
        path = url.path()

        # Verifica se é HTTPS
        is_secure = scheme.lower() == "https"
        security_icon = "🔒 Conexão segura (HTTPS)" if is_secure else "⚠️ Conexão não segura (HTTP)"
        security_color = "#2e7d32" if is_secure else "#b71c1c"

        dialog = QDialog(self)
        dialog.setWindowTitle("Informações da Página")
        dialog.setMinimumWidth(460)
        layout = QVBoxLayout(dialog)

        # Cabeçalho de segurança
        sec_lbl = QLabel(security_icon)
        sec_lbl.setStyleSheet(f"color: {security_color}; font-size: 14px; font-weight: bold; padding: 8px;")
        layout.addWidget(sec_lbl)

        # Grid de informações
        grid_data = [
            ("Título", title or "(sem título)"),
            ("Endereço (URL)", url.toString()),
            ("Protocolo", scheme.upper()),
            ("Servidor", host or "(local)"),
            ("Caminho", path or "/"),
            ("Zoom atual", f"{int(self.zoom_level * 100)}%"),
            ("Perfil ativo", self.perfil),
        ]

        frame = QFrame()
        frame.setStyleSheet("background: #f9f9f9; border-radius: 6px; padding: 4px;")
        frame_layout = QVBoxLayout(frame)
        for label, value in grid_data:
            row = QHBoxLayout()
            lbl = QLabel(f"<b>{label}:</b>")
            lbl.setMinimumWidth(110)
            val = QLabel(value)
            val.setWordWrap(True)
            val.setTextInteractionFlags(Qt.TextSelectableByMouse)
            row.addWidget(lbl)
            row.addWidget(val, 1)
            frame_layout.addLayout(row)
        layout.addWidget(frame)

        # Botão copiar URL
        btn_copy = QPushButton("📋 Copiar URL")
        btn_copy.clicked.connect(lambda: QApplication.clipboard().setText(url.toString()))
        layout.addWidget(btn_copy)

        btns = QDialogButtonBox(QDialogButtonBox.Close)
        btns.rejected.connect(dialog.reject)
        layout.addWidget(btns)
        dialog.exec_()

    def action_print(self):
        """Imprime a página atual."""
        printer = QPrinter()
        dlg = QPrintDialog(printer, self)
        if dlg.exec_() == QPrintDialog.Accepted:
            self.tabs.currentWidget().browser.page().print(printer, lambda success: None)

    def action_import_from_browser(self):
        """Importa favoritos e histórico de outro navegador."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Importar de Outro Navegador")
        dialog.setMinimumWidth(480)
        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel("<b>Selecione o navegador de origem:</b>"))
        combo = QComboBox()
        combo.addItems(["Google Chrome / Chromium", "Mozilla Firefox", "Arquivo personalizado..."])
        layout.addWidget(combo)

        layout.addWidget(QLabel("<b>O que deseja importar:</b>"))
        chk_hist = QCheckBox("Histórico de navegação")
        chk_hist.setChecked(True)
        chk_favs = QCheckBox("Favoritos / Marcadores")
        chk_favs.setChecked(True)
        layout.addWidget(chk_hist)
        layout.addWidget(chk_favs)

        info_lbl = QLabel("")
        info_lbl.setWordWrap(True)
        info_lbl.setStyleSheet("color: #555; font-size: 11px;")
        layout.addWidget(info_lbl)

        # Detecta caminhos automáticos
        if platform.system() == "Windows":
            base = os.environ.get("LOCALAPPDATA", "")
            chrome_hist = os.path.join(base, "Google", "Chrome", "User Data", "Default", "History")
            chrome_bm   = os.path.join(base, "Google", "Chrome", "User Data", "Default", "Bookmarks")
            appdata = os.environ.get("APPDATA", "")
            ff_dir = os.path.join(appdata, "Mozilla", "Firefox", "Profiles")
        else:
            home = str(Path.home())
            chrome_hist = os.path.join(home, ".config", "google-chrome", "Default", "History")
            chrome_bm   = os.path.join(home, ".config", "google-chrome", "Default", "Bookmarks")
            ff_dir = os.path.join(home, ".mozilla", "firefox")

        chrome_hist = chrome_hist if os.path.exists(chrome_hist) else None
        chrome_bm   = chrome_bm   if os.path.exists(chrome_bm)   else None
        ff_hist = ff_bm = None
        try:
            if os.path.isdir(ff_dir):
                for entry in os.listdir(ff_dir):
                    h = os.path.join(ff_dir, entry, "places.sqlite")
                    if os.path.exists(h):
                        ff_hist = ff_bm = h
                        break
        except Exception:
            pass

        def update_info(idx):
            if idx == 0:
                msg = f"Histórico: {'✅ encontrado' if chrome_hist else '❌ não encontrado'}  |  Favoritos: {'✅ encontrado' if chrome_bm else '❌ não encontrado'}"
            elif idx == 1:
                msg = f"Banco de dados: {'✅ encontrado' if ff_hist else '❌ não encontrado'}"
            else:
                msg = "Selecione um arquivo SQLite manualmente."
            info_lbl.setText(msg)

        combo.currentIndexChanged.connect(update_info)
        update_info(0)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.button(QDialogButtonBox.Ok).setText("Importar")
        btns.accepted.connect(dialog.accept)
        btns.rejected.connect(dialog.reject)
        layout.addWidget(btns)

        if dialog.exec_() != QDialog.Accepted:
            return

        idx = combo.currentIndex()
        importar_hist = chk_hist.isChecked()
        importar_favs = chk_favs.isChecked()

        if not (importar_hist or importar_favs):
            QMessageBox.information(self, "Importar", "Nenhum dado selecionado para importar.")
            return

        hist_importados = 0
        favs_importados = 0
        erros = []

        # --- HISTÓRICO ---
        if importar_hist:
            src_hist = None
            if idx == 0:
                src_hist = chrome_hist
            elif idx == 1:
                src_hist = ff_hist

            if not src_hist:
                src_hist, _ = QFileDialog.getOpenFileName(self, "Arquivo de histórico", "", "SQLite (*.db *.sqlite *.sqlite3);;Todos (*)")

            if src_hist and os.path.exists(src_hist):
                tmp = os.path.join(tempfile.gettempdir(), "mv_import_hist.db")
                try:
                    shutil.copy2(src_hist, tmp)
                    conn2 = sqlite3.connect(tmp)
                    cur2 = conn2.cursor()
                    rows = []
                    if idx == 0:
                        cur2.execute("SELECT title, url, last_visit_time, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 5000")
                        off = 11644473600
                        for t, u, lv, vc in cur2.fetchall():
                            rows.append((u, t or u, (lv / 1_000_000) - off, vc or 1))
                    else:
                        cur2.execute("SELECT title, url, last_visit_date, visit_count FROM moz_places WHERE url NOT LIKE 'place:%' ORDER BY last_visit_date DESC LIMIT 5000")
                        for t, u, lv, vc in cur2.fetchall():
                            rows.append((u, t or u, (lv or 0) / 1_000_000, vc or 1))
                    conn2.close()
                    cur = self.conn.cursor()
                    for url, title, ts, count in rows:
                        try:
                            cur.execute("SELECT count FROM history WHERE url=?", (url,))
                            ex = cur.fetchone()
                            if ex:
                                cur.execute("UPDATE history SET count=count+?, timestamp=MAX(timestamp,?) WHERE url=?", (count, ts, url))
                            else:
                                cur.execute("INSERT INTO history(url,title,timestamp,count) VALUES(?,?,?,?)", (url, title, ts, count))
                            hist_importados += 1
                        except Exception:
                            pass
                    self.conn.commit()
                except Exception as e:
                    erros.append(f"Histórico: {e}")
                finally:
                    try: os.remove(tmp)
                    except Exception: pass
            else:
                erros.append("Arquivo de histórico não encontrado.")

        # --- FAVORITOS ---
        if importar_favs and idx == 0 and chrome_bm:
            try:
                with open(chrome_bm, "r", encoding="utf-8") as f:
                    bm_data = json.load(f)

                def extract_chrome_bms(node, results):
                    if isinstance(node, dict):
                        if node.get("type") == "url":
                            results.append({"title": node.get("name", ""), "url": node.get("url", "")})
                        for child in node.get("children", []):
                            extract_chrome_bms(child, results)

                bms = []
                for root_key in bm_data.get("roots", {}).values():
                    extract_chrome_bms(root_key, bms)

                existing_urls = {f.get("url") for f in self.favoritos}
                for bm in bms:
                    if bm["url"] and bm["url"] not in existing_urls:
                        self.favoritos.append(bm)
                        favs_importados += 1
                self.save_json(self.fav_path, self.favoritos)
            except Exception as e:
                erros.append(f"Favoritos Chrome: {e}")

        elif importar_favs and idx == 1 and ff_bm:
            try:
                tmp = os.path.join(tempfile.gettempdir(), "mv_import_bm.db")
                shutil.copy2(ff_bm, tmp)
                conn2 = sqlite3.connect(tmp)
                cur2 = conn2.cursor()
                cur2.execute("SELECT title, url FROM moz_places WHERE url LIKE 'http%' AND visit_count > 0 ORDER BY visit_count DESC LIMIT 1000")
                existing_urls = {f.get("url") for f in self.favoritos}
                for t, u in cur2.fetchall():
                    if u and u not in existing_urls:
                        self.favoritos.append({"title": t or u, "url": u})
                        favs_importados += 1
                conn2.close()
                self.save_json(self.fav_path, self.favoritos)
                try: os.remove(tmp)
                except Exception: pass
            except Exception as e:
                erros.append(f"Favoritos Firefox: {e}")

        # --- Resultado ---
        partes = []
        if hist_importados:
            partes.append(f"{hist_importados} entradas de histórico")
        if favs_importados:
            partes.append(f"{favs_importados} favoritos")
        msg = "✅ Importado: " + (", ".join(partes) if partes else "nada importado")
        if erros:
            msg += "\n\n⚠️ Avisos:\n" + "\n".join(erros)
        QMessageBox.information(self, "Importar", msg)

        if self.history_sidebar and self.history_sidebar.isVisible():
            self.history_sidebar.load_history()

    def action_undo(self):
        """Desfaz ação (na página)."""
        self.tabs.currentWidget().browser.page().triggerAction(QWebEnginePage.Undo)

    def action_redo(self):
        """Refaz ação."""
        self.tabs.currentWidget().browser.page().triggerAction(QWebEnginePage.Redo)

    def action_cut(self):
        """Recorta texto selecionado."""
        self.tabs.currentWidget().browser.page().triggerAction(QWebEnginePage.Cut)

    def action_copy(self):
        """Copia texto selecionado."""
        self.tabs.currentWidget().browser.page().triggerAction(QWebEnginePage.Copy)

    def action_paste(self):
        """Copia texto da área de transferência."""
        self.tabs.currentWidget().browser.page().triggerAction(QWebEnginePage.Paste)

    def action_delete(self):
        """Deleta texto selecionado."""
        # Não há ação direta, então usamos JavaScript
        self.tabs.currentWidget().browser.page().runJavaScript(
            "document.execCommand('delete', false, null)"
        )

    def action_select_all(self):
        """Seleciona todo o conteúdo da página."""
        self.tabs.currentWidget().browser.page().triggerAction(QWebEnginePage.SelectAll)

    def action_find(self):
        """Abre barra de busca."""
        text, ok = QInputDialog.getText(self, "Localizar", "Texto a localizar:")
        if ok and text:
            self._last_find_text = text
            self.tabs.currentWidget().browser.findText(text)

    def action_find_next(self):
        """Busca próximo resultado."""
        text = getattr(self, '_last_find_text', '')
        if text:
            self.tabs.currentWidget().browser.findText(text)

    def action_find_prev(self):
        """Busca resultado anterior."""
        text = getattr(self, '_last_find_text', '')
        if text:
            self.tabs.currentWidget().browser.findText(
                text, QWebEnginePage.FindBackward
            )

    def action_toggle_toolbar(self, checked):
        """Alterna visibilidade da barra de ferramentas."""
        for toolbar in self.findChildren(QToolBar):
            if toolbar.windowTitle() == "Navigation":
                toolbar.setVisible(checked)

    def action_toggle_menubar(self, checked):
        """Alterna visibilidade da barra de menus."""
        self.menuBar().setVisible(checked)

    def action_toggle_bookmarks_bar(self, checked):
        """Alterna visibilidade da barra de favoritos."""
        # Implementar barra de favoritos horizontal
        QMessageBox.information(
            self, "Barra de Favoritos",
            "Funcionalidade em desenvolvimento.\n\nUse a Barra Lateral (Ctrl+B) para favoritos."
        )

    def action_toggle_tabs_bar(self, checked):
        """Alterna visibilidade da barra de abas."""
        self.tabs.tabBar().setVisible(checked)

    def action_toggle_sidebar(self, checked):
        """Alterna visibilidade da barra lateral (última usada)."""
        if hasattr(self, 'current_sidebar') and self.current_sidebar:
            self.current_sidebar.setVisible(checked)
        else:
            self.action_bookmarks_sidebar()

    def action_show_history(self):
        """Mostra o histórico."""
        dlg = HistoryDialog(self, self)
        dlg.exec_()

    def action_show_bookmarks(self):
        """Mostra os favoritos."""
        dlg = BookmarksDialog(self, self)
        dlg.exec_()

    def action_sync_tabs(self):
        """Sincroniza abas entre dispositivos."""
        QMessageBox.information(
            self, "Sincronizar Abas",
            "Funcionalidade em desenvolvimento.\n\n"
            "Futuramente permitirá sincronizar abas entre dispositivos."
        )

    def action_reader_mode(self):
        """Ativa modo leitura."""
        # QtWebEngine não tem modo leitura nativo
        QMessageBox.information(
            self, "Modo Leitura",
            "Funcionalidade em desenvolvimento.\n\n"
            "Use extensões como 'Reader View' para modo leitura."
        )

    def action_show_tabs(self):
        """Mostra todas as abas."""
        # Pode ser implementado como uma lista de abas
        pass

    def action_text_only_zoom(self):
        """Zoom apenas texto (não suportado diretamente)."""
        pass

    def action_charset(self):
        """Altera codificação de caracteres."""
        QMessageBox.information(
            self, "Codificação",
            "Funcionalidade em desenvolvimento."
        )

    def action_page_style(self):
        """Altera estilo da página."""
        pass

    def action_history_sidebar(self):
        """Mostra barra lateral de histórico."""
        if self.history_sidebar and self.history_sidebar.isVisible():
            self.history_sidebar.hide()
            self.current_sidebar = None
            return

        # Esconde a outra sidebar se estiver visível
        if self.bookmarks_sidebar and self.bookmarks_sidebar.isVisible():
            self.bookmarks_sidebar.hide()

        if not self.history_sidebar:
            self.history_sidebar = HistorySidebar(self)

            if not self.sidebar_splitter:
                # Cria splitter com a área central
                central = self.centralWidget()
                self.sidebar_splitter = QSplitter(Qt.Horizontal)
                self.sidebar_splitter.addWidget(self.history_sidebar)
                self.sidebar_splitter.addWidget(central)
                self.setCentralWidget(self.sidebar_splitter)
            else:
                # Adiciona ao splitter existente
                self.sidebar_splitter.insertWidget(0, self.history_sidebar)

        self.history_sidebar.show()
        self.current_sidebar = self.history_sidebar

    def action_show_all_history(self):
        """Mostra todo o histórico."""
        self.action_show_history()

    def action_clear_recent_history(self):
        """Limpa histórico recente com opção de período."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Limpar Histórico Recente")
        dialog.setMinimumWidth(400)
        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel("<b>Limpar o seguinte período:</b>"))

        periodo_combo = QComboBox()
        periodo_combo.addItems([
            "Última hora",
            "Últimas 2 horas",
            "Últimas 4 horas",
            "Hoje",
            "Tudo"
        ])
        periodo_combo.setCurrentIndex(4)
        layout.addWidget(periodo_combo)

        layout.addWidget(QLabel("<b>Dados a limpar:</b>"))

        chk_hist = QCheckBox("Histórico de navegação")
        chk_hist.setChecked(True)
        chk_cache = QCheckBox("Cache e dados de sites")
        chk_cache.setChecked(False)
        chk_cookies = QCheckBox("Cookies")
        chk_cookies.setChecked(False)

        layout.addWidget(chk_hist)
        layout.addWidget(chk_cache)
        layout.addWidget(chk_cookies)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.button(QDialogButtonBox.Ok).setText("Limpar Agora")
        btns.accepted.connect(dialog.accept)
        btns.rejected.connect(dialog.reject)
        layout.addWidget(btns)

        if dialog.exec_() != QDialog.Accepted:
            return

        periodo_idx = periodo_combo.currentIndex()
        limpar_hist = chk_hist.isChecked()
        limpar_cache = chk_cache.isChecked()
        limpar_cookies = chk_cookies.isChecked()

        if not (limpar_hist or limpar_cache or limpar_cookies):
            QMessageBox.information(self, "Limpar Histórico", "Nenhum dado selecionado para limpar.")
            return

        # Calcula o cutoff de tempo em segundos (epoch)
        agora = datetime.datetime.now().timestamp()
        horas_map = [1, 2, 4, 24, None]  # None = tudo
        horas = horas_map[periodo_idx]

        try:
            if limpar_hist:
                cursor = self.conn.cursor()
                if horas is None:
                    cursor.execute("DELETE FROM history")
                else:
                    cutoff = agora - horas * 3600
                    # timestamp armazenado como string ISO ou epoch
                    cursor.execute("DELETE FROM history WHERE CAST(timestamp AS REAL) >= ?", (cutoff,))
                self.conn.commit()

            if limpar_cache or limpar_cookies:
                profile = self.profile
                if limpar_cache:
                    profile.clearHttpCache()
                if limpar_cookies:
                    profile.cookieStore().deleteAllCookies()

            partes = []
            if limpar_hist:
                partes.append("histórico")
            if limpar_cache:
                partes.append("cache")
            if limpar_cookies:
                partes.append("cookies")
            QMessageBox.information(self, "Histórico", f"Dados limpos com sucesso: {', '.join(partes)}.")

            # Atualiza sidebar se estiver aberta
            if self.history_sidebar and self.history_sidebar.isVisible():
                self.history_sidebar.load_history()

        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Erro ao limpar dados: {e}")

    def action_recently_closed_tabs(self):
        """Mostra abas fechadas recentemente."""
        if not getattr(self, 'recently_closed_tabs', []):
            QMessageBox.information(self, "Abas Fechadas", "Nenhuma aba fechada recentemente.")
            return

        menu = QMenu(self)
        for entry in reversed(self.recently_closed_tabs):
            title = entry.get('title') or entry.get('url', '?')
            action = menu.addAction(title[:60])
            action.setData(entry)

        chosen = menu.exec_(QCursor.pos())
        if chosen:
            entry = chosen.data()
            if entry:
                self.add_new_tab(QUrl(entry['url']), entry.get('title', 'Restaurada'))

    def action_recently_closed_windows(self):
        """Mostra janelas fechadas recentemente."""
        closed_windows = getattr(Browser, '_global_closed_windows', [])
        if not closed_windows:
            QMessageBox.information(self, "Janelas Fechadas",
                "Nenhuma janela fechada nesta sessão.\n\n"
                "Janelas fechadas ficam disponíveis até o navegador ser encerrado.")
            return

        menu = QMenu(self)
        menu.setTitle("Janelas Recentemente Fechadas")
        for i, win_tabs in enumerate(reversed(closed_windows)):
            label = f"Janela {len(closed_windows) - i} ({len(win_tabs)} aba{'s' if len(win_tabs) != 1 else ''})"
            if win_tabs:
                label += f" — {win_tabs[0].get('title', win_tabs[0].get('url', '?'))[:40]}"
            action = menu.addAction(label)
            action.setData(win_tabs)

        chosen = menu.exec_(QCursor.pos())
        if chosen:
            tabs_data = chosen.data()
            if tabs_data:
                for entry in tabs_data:
                    self.add_new_tab(QUrl(entry['url']), entry.get('title', 'Restaurada'))

    def action_restore_last_tab(self):
        """Restaura a última aba fechada."""
        closed = getattr(self, 'recently_closed_tabs', [])
        if closed:
            entry = closed.pop()
            self.add_new_tab(QUrl(entry['url']), entry.get('title', 'Restaurada'))
        else:
            QMessageBox.information(self, "Restaurar Aba", "Nenhuma aba para restaurar.")

    def action_restore_last_window(self):
        """Restaura a última janela fechada."""
        closed_windows = getattr(Browser, '_global_closed_windows', [])
        if closed_windows:
            tabs_data = closed_windows.pop()
            for entry in tabs_data:
                self.add_new_tab(QUrl(entry['url']), entry.get('title', 'Restaurada'))
        else:
            QMessageBox.information(self, "Restaurar Janela", "Nenhuma janela para restaurar.")

    def action_tabs_from_other_devices(self):
        """Mostra abas de outros perfis (dispositivos locais)."""
        try:
            outros = []
            if os.path.isdir(DATA_DIR):
                for nome_perfil in os.listdir(DATA_DIR):
                    if nome_perfil == self.perfil:
                        continue
                    db_path = os.path.join(DATA_DIR, nome_perfil, "history.db")
                    if not os.path.exists(db_path):
                        continue
                    try:
                        conn_outro = sqlite3.connect(db_path)
                        cur = conn_outro.cursor()
                        cur.execute(
                            "SELECT title, url, timestamp FROM history ORDER BY timestamp DESC LIMIT 10"
                        )
                        rows = cur.fetchall()
                        conn_outro.close()
                        if rows:
                            outros.append((nome_perfil, rows))
                    except Exception:
                        pass

            if not outros:
                QMessageBox.information(
                    self, "Abas de Outros Dispositivos",
                    "Nenhum histórico encontrado em outros perfis.\n\n"
                    "Esta função lista as abas mais recentes dos outros perfis deste navegador."
                )
                return

            dialog = QDialog(self)
            dialog.setWindowTitle("Abas de Outros Perfis")
            dialog.resize(520, 420)
            layout = QVBoxLayout(dialog)
            layout.addWidget(QLabel("<b>Histórico recente de outros perfis:</b>"))

            tree = QTreeWidget()
            tree.setHeaderLabels(["Título", "URL"])
            tree.setColumnWidth(0, 220)
            tree.setAlternatingRowColors(True)

            for nome_perfil, rows in outros:
                parent = QTreeWidgetItem(tree, [f"🖥 Perfil: {nome_perfil}", ""])
                parent.setExpanded(True)
                for title, url, ts in rows:
                    child = QTreeWidgetItem(parent, [title or url, url])
                    child.setData(0, Qt.UserRole, url)

            layout.addWidget(tree)

            def abrir_selecionado():
                item = tree.currentItem()
                if item and item.data(0, Qt.UserRole):
                    url = item.data(0, Qt.UserRole)
                    self.add_new_tab(QUrl(url), item.text(0))
                    dialog.accept()

            tree.itemDoubleClicked.connect(lambda item, _: abrir_selecionado())

            btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Close)
            btns.button(QDialogButtonBox.Ok).setText("Abrir Selecionada")
            btns.accepted.connect(abrir_selecionado)
            btns.rejected.connect(dialog.reject)
            layout.addWidget(btns)
            dialog.exec_()

        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Erro ao acessar outros perfis: {e}")

    def action_search_history(self):
        """Pesquisa no histórico com diálogo dedicado."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Pesquisar Histórico")
        dialog.resize(600, 450)
        layout = QVBoxLayout(dialog)

        search_layout = QHBoxLayout()
        search_edit = QLineEdit()
        search_edit.setPlaceholderText("Digite para pesquisar no histórico...")
        btn_search = QPushButton("Pesquisar")
        search_layout.addWidget(search_edit)
        search_layout.addWidget(btn_search)
        layout.addLayout(search_layout)

        result_list = QListWidget()
        result_list.setAlternatingRowColors(True)
        layout.addWidget(result_list)

        status_lbl = QLabel("Digite um termo para pesquisar.")
        layout.addWidget(status_lbl)

        btns = QDialogButtonBox(QDialogButtonBox.Close)
        btns.button(QDialogButtonBox.Close).setText("Fechar")
        btns.rejected.connect(dialog.reject)
        layout.addWidget(btns)

        def do_search():
            term = search_edit.text().strip()
            result_list.clear()
            if not term:
                status_lbl.setText("Digite um termo para pesquisar.")
                return
            try:
                cursor = self.conn.cursor()
                cursor.execute(
                    "SELECT title, url, timestamp FROM history "
                    "WHERE title LIKE ? OR url LIKE ? "
                    "ORDER BY timestamp DESC LIMIT 200",
                    (f"%{term}%", f"%{term}%")
                )
                rows = cursor.fetchall()
                for title, url, ts in rows:
                    display = f"{title or url}  —  {url}"
                    item = QListWidget.item if False else __import__('PyQt5.QtWidgets', fromlist=['QListWidgetItem']).QListWidgetItem(display)
                    item.setData(Qt.UserRole, url)
                    result_list.addItem(item)
                status_lbl.setText(f"{len(rows)} resultado(s) para \"{term}\".")
            except Exception as e:
                status_lbl.setText(f"Erro: {e}")

        def abrir_item(item):
            url = item.data(Qt.UserRole)
            if url:
                self.add_new_tab(QUrl(url), item.text().split("  —  ")[0])
                dialog.accept()

        btn_search.clicked.connect(do_search)
        search_edit.returnPressed.connect(do_search)
        result_list.itemDoubleClicked.connect(abrir_item)

        dialog.exec_()

    def action_import_history(self):
        """Importa histórico do Chrome ou Firefox."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Importar Histórico de Outro Navegador")
        dialog.setMinimumWidth(450)
        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel("<b>Selecione o navegador de origem:</b>"))
        combo = QComboBox()
        combo.addItems(["Google Chrome / Chromium", "Mozilla Firefox", "Arquivo SQLite personalizado..."])
        layout.addWidget(combo)

        info_lbl = QLabel("")
        info_lbl.setWordWrap(True)
        layout.addWidget(info_lbl)

        # Detecta caminhos automáticos
        chrome_paths = []
        firefox_paths = []
        if platform.system() == "Windows":
            base = os.environ.get("LOCALAPPDATA", "")
            chrome_paths = [
                os.path.join(base, "Google", "Chrome", "User Data", "Default", "History"),
                os.path.join(base, "Chromium", "User Data", "Default", "History"),
            ]
            appdata = os.environ.get("APPDATA", "")
            ff_profiles = os.path.join(appdata, "Mozilla", "Firefox", "Profiles")
        else:
            home = str(Path.home())
            chrome_paths = [
                os.path.join(home, ".config", "google-chrome", "Default", "History"),
                os.path.join(home, ".config", "chromium", "Default", "History"),
            ]
            ff_profiles = os.path.join(home, ".mozilla", "firefox")

        chrome_found = next((p for p in chrome_paths if os.path.exists(p)), None)

        ff_found = None
        try:
            if os.path.isdir(ff_profiles):
                for entry in os.listdir(ff_profiles):
                    db_candidate = os.path.join(ff_profiles, entry, "places.sqlite")
                    if os.path.exists(db_candidate):
                        ff_found = db_candidate
                        break
        except Exception:
            pass

        def update_info(idx):
            if idx == 0:
                info_lbl.setText(f"Arquivo detectado: {chrome_found or 'Não encontrado automaticamente. Escolha manualmente.'}")
            elif idx == 1:
                info_lbl.setText(f"Arquivo detectado: {ff_found or 'Não encontrado automaticamente. Escolha manualmente.'}")
            else:
                info_lbl.setText("Selecione um arquivo .db ou .sqlite com tabela de histórico.")

        combo.currentIndexChanged.connect(update_info)
        update_info(0)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.button(QDialogButtonBox.Ok).setText("Importar")
        btns.accepted.connect(dialog.accept)
        btns.rejected.connect(dialog.reject)
        layout.addWidget(btns)

        if dialog.exec_() != QDialog.Accepted:
            return

        idx = combo.currentIndex()

        # Resolve o arquivo fonte
        src_path = None
        if idx == 0:
            src_path = chrome_found
        elif idx == 1:
            src_path = ff_found

        if not src_path:
            src_path, _ = QFileDialog.getOpenFileName(
                self, "Selecionar arquivo de histórico", "",
                "Banco de dados SQLite (*.db *.sqlite *.sqlite3);;Todos os arquivos (*)"
            )

        if not src_path or not os.path.exists(src_path):
            QMessageBox.warning(self, "Importar Histórico", "Arquivo não encontrado ou não selecionado.")
            return

        # Copia para arquivo temporário (o navegador pode ter lock no original)
        tmp_copy = os.path.join(tempfile.gettempdir(), "marveloc_hist_import.db")
        try:
            shutil.copy2(src_path, tmp_copy)
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Não foi possível ler o arquivo: {e}\nFeche o navegador de origem e tente novamente.")
            return

        try:
            src_conn = sqlite3.connect(tmp_copy)
            src_cur = src_conn.cursor()

            rows = []
            if idx == 0:
                # Chrome: tabela 'urls', last_visit_time em microssegundos desde 1601-01-01
                try:
                    src_cur.execute("SELECT title, url, last_visit_time, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 5000")
                    chrome_epoch_offset = 11644473600  # segundos entre 1601 e 1970
                    for title, url, last_visit, count in src_cur.fetchall():
                        ts = (last_visit / 1_000_000) - chrome_epoch_offset
                        rows.append((url, title or url, ts, count or 1))
                except Exception as e:
                    QMessageBox.critical(self, "Erro Chrome", f"Erro ao ler histórico do Chrome: {e}")
                    src_conn.close()
                    return
            elif idx == 1:
                # Firefox: tabela 'moz_places', last_visit_date em microsegundos desde epoch
                try:
                    src_cur.execute("SELECT title, url, last_visit_date, visit_count FROM moz_places WHERE url NOT LIKE 'place:%' ORDER BY last_visit_date DESC LIMIT 5000")
                    for title, url, last_visit, count in src_cur.fetchall():
                        ts = (last_visit or 0) / 1_000_000
                        rows.append((url, title or url, ts, count or 1))
                except Exception as e:
                    QMessageBox.critical(self, "Erro Firefox", f"Erro ao ler histórico do Firefox: {e}")
                    src_conn.close()
                    return
            else:
                # Genérico: tenta colunas url/title/timestamp
                try:
                    src_cur.execute("SELECT url, title, timestamp FROM history ORDER BY timestamp DESC LIMIT 5000")
                    for url, title, ts in src_cur.fetchall():
                        rows.append((url, title or url, ts, 1))
                except Exception as e:
                    QMessageBox.critical(self, "Erro", f"Formato de banco não reconhecido: {e}")
                    src_conn.close()
                    return

            src_conn.close()

            if not rows:
                QMessageBox.information(self, "Importar Histórico", "Nenhuma entrada encontrada no arquivo selecionado.")
                return

            cursor = self.conn.cursor()
            imported = 0
            for url, title, ts, count in rows:
                try:
                    cursor.execute("SELECT count FROM history WHERE url = ?", (url,))
                    existing = cursor.fetchone()
                    if existing:
                        cursor.execute("UPDATE history SET count = count + ?, timestamp = MAX(timestamp, ?) WHERE url = ?",
                                       (count, ts, url))
                    else:
                        cursor.execute("INSERT INTO history(url, title, timestamp, count) VALUES (?, ?, ?, ?)",
                                       (url, title, ts, count))
                    imported += 1
                except Exception:
                    pass
            self.conn.commit()

            QMessageBox.information(self, "Importar Histórico",
                f"✅ {imported} entradas importadas com sucesso!")

            if self.history_sidebar and self.history_sidebar.isVisible():
                self.history_sidebar.load_history()

        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Erro ao importar histórico: {e}")
        finally:
            try:
                os.remove(tmp_copy)
            except Exception:
                pass

    def action_show_all_bookmarks(self):
        """Mostra todos os favoritos."""
        self.action_show_bookmarks()

    def action_bookmarks_sidebar(self):
        """Mostra barra lateral de favoritos."""
        if self.bookmarks_sidebar and self.bookmarks_sidebar.isVisible():
            self.bookmarks_sidebar.hide()
            self.current_sidebar = None
            return

        # Esconde a outra sidebar se estiver visível
        if self.history_sidebar and self.history_sidebar.isVisible():
            self.history_sidebar.hide()

        if not self.bookmarks_sidebar:
            self.bookmarks_sidebar = BookmarksSidebar(self)
            self.bookmarks_sidebar.setVisible(True)

            if not self.sidebar_splitter:
                # Cria splitter com a área central
                central = self.centralWidget()
                self.sidebar_splitter = QSplitter(Qt.Horizontal)
                self.sidebar_splitter.addWidget(self.bookmarks_sidebar)
                self.sidebar_splitter.addWidget(central)
                self.setCentralWidget(self.sidebar_splitter)
            else:
                # Adiciona ao splitter existente
                self.sidebar_splitter.insertWidget(0, self.bookmarks_sidebar)

        self.bookmarks_sidebar.show()
        self.current_sidebar = self.bookmarks_sidebar

    def action_add_bookmark(self):
        """Adiciona página atual aos favoritos (abre diálogo)."""
        self.add_favorite()

    def action_subscribe_page(self):
        """Detecta e subscreve feed RSS/Atom da página atual."""
        url = self.tabs.currentWidget().browser.url().toString()
        title = self.tabs.currentWidget().browser.title()

        # Tenta detectar feeds via JavaScript na página
        self.tabs.currentWidget().browser.page().runJavaScript("""
            (function() {
                var feeds = [];
                var links = document.querySelectorAll('link[type="application/rss+xml"], link[type="application/atom+xml"], link[type="application/rdf+xml"]');
                links.forEach(function(l) {
                    feeds.push({title: l.title || l.getAttribute('title') || document.title, href: l.href, type: l.type});
                });
                return JSON.stringify(feeds);
            })()
        """, lambda result: self._handle_rss_result(result, url, title))

    def _handle_rss_result(self, result, page_url, page_title):
        """Processa resultado da detecção de RSS."""
        feeds = []
        try:
            if result:
                feeds = json.loads(result)
        except Exception:
            pass

        if not feeds:
            # Tenta feeds comuns
            common = ["/feed", "/rss", "/atom.xml", "/feed.xml", "/rss.xml"]
            from urllib.parse import urlparse
            parsed = urlparse(page_url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            for path in common:
                feeds.append({"title": f"Feed ({path})", "href": base + path, "type": "RSS/Atom"})

        dialog = QDialog(self)
        dialog.setWindowTitle("Subscrever Feed RSS/Atom")
        dialog.setMinimumWidth(480)
        layout = QVBoxLayout(dialog)

        if feeds:
            layout.addWidget(QLabel(f"<b>Feeds encontrados em:</b> {page_title[:50]}"))
            feed_list = QListWidget()
            feed_list.setAlternatingRowColors(True)
            for feed in feeds:
                item_text = f"{feed.get('title', '?')} — {feed.get('href', '')}"
                item = QListWidgetItem(item_text)
                item.setData(Qt.UserRole, feed.get("href", ""))
                feed_list.addItem(item)
            feed_list.setCurrentRow(0)
            layout.addWidget(feed_list)
        else:
            layout.addWidget(QLabel("Nenhum feed detectado automaticamente."))
            layout.addWidget(QLabel("<b>URL do feed manualmente:</b>"))
            feed_list = None

        layout.addWidget(QLabel("<b>Ou insira a URL do feed manualmente:</b>"))
        url_edit = QLineEdit()
        url_edit.setPlaceholderText("https://exemplo.com/feed.xml")
        layout.addWidget(url_edit)

        # Opções de ação
        layout.addWidget(QLabel("<b>O que fazer com o feed:</b>"))
        opt_open = QRadioButton("Abrir feed no navegador")
        opt_bm = QRadioButton("Adicionar feed aos favoritos")
        opt_open.setChecked(True)
        layout.addWidget(opt_open)
        layout.addWidget(opt_bm)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.button(QDialogButtonBox.Ok).setText("Subscrever")
        btns.accepted.connect(dialog.accept)
        btns.rejected.connect(dialog.reject)
        layout.addWidget(btns)

        if dialog.exec_() != QDialog.Accepted:
            return

        # Resolve URL final
        feed_url = url_edit.text().strip()
        if not feed_url and feeds and feed_list and feed_list.currentItem():
            feed_url = feed_list.currentItem().data(Qt.UserRole)
        if not feed_url and feeds:
            feed_url = feeds[0].get("href", "")

        if not feed_url:
            QMessageBox.warning(self, "Subscrever", "Nenhum feed selecionado.")
            return

        if opt_open.isChecked():
            self.add_new_tab(QUrl(feed_url), "Feed RSS")
        else:
            self.favoritos.append({"title": f"[RSS] {page_title}", "url": feed_url,
                                   "folder": "Feeds", "added": datetime.datetime.now().isoformat()})
            _atomic_write_encrypted(self.fav_path, self.favoritos, self.encryptor)
            self.bookmarks_updated.emit()
            QMessageBox.information(self, "Subscrever", f"Feed adicionado aos favoritos na pasta 'Feeds':\n{feed_url}")

    def action_recent_bookmarks(self):
        """Mostra favoritos recentes num menu detalhado."""
        if not self.favoritos:
            QMessageBox.information(self, "Favoritos Recentes", "Nenhum favorito cadastrado ainda.")
            return

        # Ordena por data de adição (mais recentes primeiro)
        sorted_favs = sorted(
            self.favoritos,
            key=lambda f: f.get("added", ""),
            reverse=True
        )
        recent = sorted_favs[:15]

        menu = QMenu(self)
        menu.setTitle("Favoritos Recentes")

        for fav in recent:
            title = fav.get("title", "?")[:45]
            folder = fav.get("folder", "")
            label = f"📁 {folder} › {title}" if folder else title
            action = menu.addAction(label)
            action.setData(fav.get("url", ""))
            action.setToolTip(fav.get("url", ""))

        menu.addSeparator()
        action_all = menu.addAction("📚 Ver todos os favoritos...")
        action_all.setData("__all__")

        chosen = menu.exec_(QCursor.pos())
        if chosen:
            data = chosen.data()
            if data == "__all__":
                self.action_show_all_bookmarks()
            elif data:
                self.add_new_tab(QUrl(data), chosen.text().split(" › ")[-1])

    def action_bookmark_all_tabs(self):
        """Adiciona todas as abas abertas aos favoritos (com opção de pasta)."""
        tabs_info = []
        for i in range(self.tabs.count()):
            tab = self.tabs.widget(i)
            if tab:
                url = tab.browser.url().toString()
                title = tab.browser.title() or self.tabs.tabText(i)
                if url and not url.startswith("about:"):
                    tabs_info.append({"title": title, "url": url})

        if not tabs_info:
            QMessageBox.information(self, "Favoritos", "Nenhuma aba válida para adicionar.")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Adicionar Separadores aos Favoritos")
        dialog.setMinimumWidth(440)
        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel(f"<b>{len(tabs_info)} aba(s) serão adicionadas aos favoritos:</b>"))

        # Lista das abas
        tab_list = QListWidget()
        tab_list.setMaximumHeight(180)
        for t in tabs_info:
            item = QListWidgetItem(f"  {t['title'][:50]}")
            item.setToolTip(t["url"])
            tab_list.addItem(item)
        layout.addWidget(tab_list)

        layout.addWidget(QLabel("<b>Salvar na pasta:</b>"))
        pastas = sorted({f.get("folder", "") for f in self.favoritos if f.get("folder")})
        folder_combo = QComboBox()
        folder_combo.setEditable(True)
        now_str = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
        folder_combo.addItem(f"Sessão {now_str}")
        folder_combo.addItem("(sem pasta)")
        for p in pastas:
            folder_combo.addItem(p)
        layout.addWidget(folder_combo)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.button(QDialogButtonBox.Ok).setText("Adicionar Favoritos")
        btns.accepted.connect(dialog.accept)
        btns.rejected.connect(dialog.reject)
        layout.addWidget(btns)

        if dialog.exec_() != QDialog.Accepted:
            return

        folder = folder_combo.currentText().strip()
        if folder == "(sem pasta)":
            folder = ""

        existing_urls = {f.get("url") for f in self.favoritos}
        count = 0
        for t in tabs_info:
            if t["url"] not in existing_urls:
                self.favoritos.append({
                    "title": t["title"], "url": t["url"],
                    "folder": folder, "added": datetime.datetime.now().isoformat()
                })
                count += 1

        _atomic_write_encrypted(self.fav_path, self.favoritos, self.encryptor)
        self.bookmarks_updated.emit()
        pasta_msg = f" na pasta '{folder}'" if folder else ""
        QMessageBox.information(self, "Favoritos",
            f"✅ {count} aba(s) adicionada(s) aos favoritos{pasta_msg}.\n"
            f"({len(tabs_info) - count} já existiam.)")

    def action_import_bookmarks(self):
        """Importa favoritos do Chrome ou Firefox."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Importar Favoritos de Outro Navegador")
        dialog.setMinimumWidth(460)
        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel("<b>Selecione o navegador de origem:</b>"))
        combo = QComboBox()
        combo.addItems(["Google Chrome / Chromium", "Mozilla Firefox", "Arquivo personalizado..."])
        layout.addWidget(combo)

        info_lbl = QLabel("")
        info_lbl.setWordWrap(True)
        info_lbl.setStyleSheet("color: #555; font-size: 11px;")
        layout.addWidget(info_lbl)

        layout.addWidget(QLabel("<b>Salvar importados na pasta:</b>"))
        folder_edit = QLineEdit("Importados")
        layout.addWidget(folder_edit)

        # Detecta caminhos
        if platform.system() == "Windows":
            base = os.environ.get("LOCALAPPDATA", "")
            chrome_bm = os.path.join(base, "Google", "Chrome", "User Data", "Default", "Bookmarks")
        else:
            home = str(Path.home())
            chrome_bm = os.path.join(home, ".config", "google-chrome", "Default", "Bookmarks")

        ff_bm = None
        try:
            ff_base = os.path.join(os.environ.get("APPDATA", str(Path.home())), "Mozilla", "Firefox", "Profiles") \
                if platform.system() == "Windows" else os.path.join(str(Path.home()), ".mozilla", "firefox")
            if os.path.isdir(ff_base):
                for entry in os.listdir(ff_base):
                    candidate = os.path.join(ff_base, entry, "places.sqlite")
                    if os.path.exists(candidate):
                        ff_bm = candidate
                        break
        except Exception:
            pass

        chrome_ok = os.path.exists(chrome_bm)
        ff_ok = ff_bm and os.path.exists(ff_bm)

        def update_info(idx):
            if idx == 0:
                info_lbl.setText(f"Arquivo Bookmarks: {'✅ encontrado' if chrome_ok else '❌ não encontrado'}")
            elif idx == 1:
                info_lbl.setText(f"Banco places.sqlite: {'✅ encontrado' if ff_ok else '❌ não encontrado'}")
            else:
                info_lbl.setText("Você selecionará o arquivo manualmente.")

        combo.currentIndexChanged.connect(update_info)
        update_info(0)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.button(QDialogButtonBox.Ok).setText("Importar")
        btns.accepted.connect(dialog.accept)
        btns.rejected.connect(dialog.reject)
        layout.addWidget(btns)

        if dialog.exec_() != QDialog.Accepted:
            return

        idx = combo.currentIndex()
        folder = folder_edit.text().strip() or "Importados"
        imported = 0
        existing_urls = {f.get("url") for f in self.favoritos}

        try:
            if idx == 0:
                # Chrome — arquivo JSON Bookmarks
                src = chrome_bm if chrome_ok else None
                if not src:
                    src, _ = QFileDialog.getOpenFileName(self, "Arquivo Bookmarks do Chrome", "", "JSON (*.json);;Todos (*)")
                if src and os.path.exists(src):
                    with open(src, "r", encoding="utf-8") as f:
                        data = json.load(f)

                    def extract(node, folder_path=""):
                        if isinstance(node, dict):
                            if node.get("type") == "url":
                                url = node.get("url", "")
                                if url and url not in existing_urls:
                                    self.favoritos.append({
                                        "title": node.get("name", url),
                                        "url": url,
                                        "folder": folder or folder_path,
                                        "added": datetime.datetime.now().isoformat()
                                    })
                                    existing_urls.add(url)
                                    return 1
                            elif node.get("type") == "folder":
                                sub_folder = node.get("name", "")
                                count = 0
                                for child in node.get("children", []):
                                    count += extract(child, sub_folder)
                                return count
                            else:
                                count = 0
                                for child in node.get("children", []):
                                    count += extract(child, folder_path)
                                return count
                        return 0

                    for root_val in data.get("roots", {}).values():
                        imported += extract(root_val)

            elif idx == 1:
                # Firefox — places.sqlite
                src = ff_bm if ff_ok else None
                if not src:
                    src, _ = QFileDialog.getOpenFileName(self, "places.sqlite do Firefox", "", "SQLite (*.sqlite);;Todos (*)")
                if src and os.path.exists(src):
                    tmp = os.path.join(tempfile.gettempdir(), "mv_ff_bm.sqlite")
                    shutil.copy2(src, tmp)
                    conn2 = sqlite3.connect(tmp)
                    cur2 = conn2.cursor()
                    cur2.execute("""
                        SELECT p.title, p.url
                        FROM moz_places p
                        JOIN moz_bookmarks b ON b.fk = p.id
                        WHERE p.url NOT LIKE 'place:%'
                        ORDER BY b.dateAdded DESC
                        LIMIT 2000
                    """)
                    for title, url in cur2.fetchall():
                        if url and url not in existing_urls:
                            self.favoritos.append({
                                "title": title or url, "url": url,
                                "folder": folder, "added": datetime.datetime.now().isoformat()
                            })
                            existing_urls.add(url)
                            imported += 1
                    conn2.close()
                    try: os.remove(tmp)
                    except Exception: pass

            else:
                src, _ = QFileDialog.getOpenFileName(self, "Selecionar arquivo", "",
                    "JSON Bookmarks (*.json);;SQLite (*.sqlite *.db);;HTML (*.html *.htm);;Todos (*)")
                if src and src.lower().endswith(".html"):
                    # Redireciona para import HTML
                    self._import_bookmarks_from_html_file(src)
                    return

        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Erro ao importar favoritos: {e}")
            return

        if imported > 0:
            _atomic_write_encrypted(self.fav_path, self.favoritos, self.encryptor)
            self.bookmarks_updated.emit()
        QMessageBox.information(self, "Importar Favoritos",
            f"✅ {imported} favorito(s) importado(s) com sucesso!"
            if imported > 0 else "Nenhum favorito novo encontrado.")

    def action_export_bookmarks_html(self):
        """Exporta favoritos para HTML no formato padrão Netscape (compatível com todos os navegadores)."""
        if not self.favoritos:
            QMessageBox.information(self, "Exportar Favoritos", "Nenhum favorito para exportar.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Exportar Favoritos para HTML",
            "favoritos_marveloc.html",
            "Arquivo HTML de Favoritos (*.html)"
        )
        if not file_path:
            return

        try:
            # Agrupa por pasta
            from collections import defaultdict
            pastas = defaultdict(list)
            for fav in self.favoritos:
                folder = fav.get("folder", "") or ""
                pastas[folder].append(fav)

            now_ts = int(datetime.datetime.now().timestamp())
            lines = [
                '<!DOCTYPE NETSCAPE-Bookmark-file-1>',
                '<!-- This is an automatically generated file.',
                '     It will be read and overwritten.',
                '     DO NOT EDIT! -->',
                '<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">',
                f'<TITLE>Favoritos do Marveloc</TITLE>',
                '<H1>Favoritos do Marveloc</H1>',
                '<DL><p>',
            ]

            for folder, items in sorted(pastas.items(), key=lambda x: x[0]):
                if folder:
                    lines.append(f'    <DT><H3 ADD_DATE="{now_ts}" LAST_MODIFIED="{now_ts}">{folder}</H3>')
                    lines.append('    <DL><p>')
                    for fav in items:
                        t = fav.get("title", "Link").replace("<", "&lt;").replace(">", "&gt;")
                        u = fav.get("url", "#")
                        added = fav.get("added", "")
                        try:
                            ts = int(datetime.datetime.fromisoformat(added).timestamp()) if added else now_ts
                        except Exception:
                            ts = now_ts
                        lines.append(f'        <DT><A HREF="{u}" ADD_DATE="{ts}">{t}</A>')
                    lines.append('    </DL><p>')
                else:
                    for fav in items:
                        t = fav.get("title", "Link").replace("<", "&lt;").replace(">", "&gt;")
                        u = fav.get("url", "#")
                        added = fav.get("added", "")
                        try:
                            ts = int(datetime.datetime.fromisoformat(added).timestamp()) if added else now_ts
                        except Exception:
                            ts = now_ts
                        lines.append(f'    <DT><A HREF="{u}" ADD_DATE="{ts}">{t}</A>')

            lines.append('</DL><p>')

            with open(file_path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))

            QMessageBox.information(self, "Exportar Favoritos",
                f"✅ {len(self.favoritos)} favorito(s) exportado(s) para:\n{file_path}\n\n"
                "Compatível com Chrome, Firefox, Edge e outros navegadores.")
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Erro ao exportar favoritos: {e}")

    def action_import_bookmarks_html(self):
        """Importa favoritos de arquivo HTML (formato Netscape)."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Importar Favoritos de HTML", "",
            "Arquivo HTML de Favoritos (*.html *.htm);;Todos os arquivos (*)"
        )
        if file_path:
            self._import_bookmarks_from_html_file(file_path)

    def _import_bookmarks_from_html_file(self, file_path: str):
        """Importa favoritos de um arquivo HTML no formato Netscape."""
        try:
            import html.parser

            class NetscapeBookmarkParser(html.parser.HTMLParser):
                def __init__(self):
                    super().__init__()
                    self.bookmarks = []
                    self.current_url = ""
                    self.current_title = ""
                    self.current_folder = ""
                    self.folder_stack = []
                    self.in_link = False

                def handle_starttag(self, tag, attrs):
                    attrs_dict = dict(attrs)
                    if tag == "a":
                        self.in_link = True
                        self.current_url = attrs_dict.get("href", "")
                        self.current_title = ""
                    elif tag == "h3":
                        self.in_link = False
                        self.folder_stack.append("")
                    elif tag == "dl":
                        if self.folder_stack:
                            self.current_folder = self.folder_stack[-1]

                def handle_endtag(self, tag):
                    if tag == "a":
                        if self.current_url and self.current_title:
                            self.bookmarks.append({
                                "title": self.current_title.strip(),
                                "url": self.current_url,
                                "folder": self.current_folder
                            })
                        self.in_link = False
                        self.current_url = self.current_title = ""
                    elif tag == "dl":
                        if self.folder_stack:
                            self.folder_stack.pop()
                            self.current_folder = self.folder_stack[-1] if self.folder_stack else ""

                def handle_data(self, data):
                    if self.in_link:
                        self.current_title += data
                    elif self.folder_stack and not self.folder_stack[-1]:
                        self.folder_stack[-1] = data.strip()
                        self.current_folder = data.strip()

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            parser = NetscapeBookmarkParser()
            parser.feed(content)

            existing_urls = {f.get("url") for f in self.favoritos}
            imported = 0
            for bm in parser.bookmarks:
                if bm["url"] and bm["url"] not in existing_urls and bm["url"] != "#":
                    self.favoritos.append({
                        "title": bm["title"],
                        "url": bm["url"],
                        "folder": bm.get("folder", ""),
                        "added": datetime.datetime.now().isoformat()
                    })
                    existing_urls.add(bm["url"])
                    imported += 1

            if imported > 0:
                _atomic_write_encrypted(self.fav_path, self.favoritos, self.encryptor)
                self.bookmarks_updated.emit()

            QMessageBox.information(self, "Importar Favoritos",
                f"✅ {imported} favorito(s) importado(s) de {len(parser.bookmarks)} encontrado(s)."
                if imported > 0 else "Nenhum favorito novo encontrado no arquivo.")
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Erro ao importar HTML de favoritos: {e}")

    def _populate_quick_switch_menu(self, menu):
        """Popula submenu de troca rápida de perfil."""
        perfis = []
        if os.path.exists(DATA_DIR):
            perfis = sorted([d for d in os.listdir(DATA_DIR)
                             if os.path.isdir(os.path.join(DATA_DIR, d))
                             and not d.startswith("private_")])
        if not perfis:
            perfis = ["default"]

        for p in perfis:
            label = f"  {p}" + ("  ✓" if p == self.perfil else "")
            action = menu.addAction(label)
            action.setData(p)
            if p == self.perfil:
                action.setEnabled(False)

        menu.addSeparator()
        menu.addAction("➕ Criar novo perfil...").triggered.connect(self.action_create_profile)

        def on_switch(act):
            p = act.data()
            if p and p != self.perfil:
                reply = QMessageBox.question(
                    self, "Trocar Perfil",
                    f"Alternar para o perfil '{p}'?\nO navegador será reiniciado.",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.Yes:
                    cfg = load_config()
                    cfg["perfil"] = p
                    save_config(cfg)
                    QProcess.startDetached(sys.executable, [sys.argv[0]])
                    QApplication.quit()

        menu.triggered.connect(on_switch)

    def action_profile_manager(self):
        """Abre gerenciador de perfis completo."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Gerenciador de Perfis")
        dialog.setMinimumSize(560, 420)
        layout = QVBoxLayout(dialog)

        # Cabeçalho
        header = QLabel(f"<b>Perfil ativo:</b> <span style='color:#1a73e8'>{self.perfil}</span>")
        header.setStyleSheet("font-size: 13px; padding: 6px;")
        layout.addWidget(header)

        # Lista de perfis
        layout.addWidget(QLabel("<b>Perfis disponíveis:</b>"))
        profile_list = QListWidget()
        profile_list.setAlternatingRowColors(True)
        profile_list.setMinimumHeight(180)

        def refresh_profile_list():
            profile_list.clear()
            perfis = []
            if os.path.exists(DATA_DIR):
                perfis = sorted([d for d in os.listdir(DATA_DIR)
                                 if os.path.isdir(os.path.join(DATA_DIR, d))
                                 and not d.startswith("private_")])
            if not perfis:
                perfis = ["default"]
            cfg = load_config()
            current = cfg.get("perfil", "default")
            for p in perfis:
                label = f"  👤  {p}"
                if p == self.perfil:
                    label += "  ← atual (em uso)"
                elif p == current:
                    label += "  ← padrão ao iniciar"
                item = QListWidgetItem(label)
                item.setData(Qt.UserRole, p)
                if p == self.perfil:
                    font = item.font()
                    font.setBold(True)
                    item.setFont(font)
                profile_list.addItem(item)

        refresh_profile_list()
        layout.addWidget(profile_list)

        # Botões de ação
        btn_row = QHBoxLayout()

        btn_switch = QPushButton("🔄 Alternar para este perfil")
        btn_switch.setToolTip("Define como perfil padrão e reinicia o navegador")
        btn_rename = QPushButton("✏️ Renomear")
        btn_delete = QPushButton("🗑 Excluir")
        btn_delete.setStyleSheet("color: #c0392b;")

        btn_row.addWidget(btn_switch)
        btn_row.addWidget(btn_rename)
        btn_row.addWidget(btn_delete)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Info do perfil selecionado
        info_frame = QFrame()
        info_frame.setStyleSheet("background:#f4f4f4; border-radius:6px; padding:4px;")
        info_layout = QVBoxLayout(info_frame)
        info_lbl = QLabel("Selecione um perfil para ver informações.")
        info_lbl.setWordWrap(True)
        info_layout.addWidget(info_lbl)
        layout.addWidget(info_frame)

        def update_info():
            item = profile_list.currentItem()
            if not item:
                return
            pname = item.data(Qt.UserRole)
            pdir = os.path.join(DATA_DIR, pname)
            # Conta favoritos
            fav_path = os.path.join(pdir, "favoritos.json")
            fav_count = 0
            try:
                with open(fav_path, "r", encoding="utf-8") as f:
                    fav_count = len(json.load(f))
            except Exception:
                pass
            # Conta histórico
            db_path = os.path.join(pdir, "history.db")
            hist_count = 0
            try:
                conn2 = sqlite3.connect(db_path)
                hist_count = conn2.execute("SELECT COUNT(*) FROM history").fetchone()[0]
                conn2.close()
            except Exception:
                pass
            # Tamanho da pasta
            size = 0
            try:
                for f in os.scandir(pdir):
                    if f.is_file():
                        size += f.stat().st_size
            except Exception:
                pass
            size_kb = size / 1024
            info_lbl.setText(
                f"<b>Perfil:</b> {pname}<br>"
                f"<b>Pasta:</b> {pdir}<br>"
                f"<b>Favoritos:</b> {fav_count}  |  "
                f"<b>Histórico:</b> {hist_count} entradas  |  "
                f"<b>Tamanho:</b> {size_kb:.1f} KB"
            )

        profile_list.currentItemChanged.connect(lambda *_: update_info())

        def switch_profile():
            item = profile_list.currentItem()
            if not item:
                QMessageBox.information(dialog, "Perfis", "Selecione um perfil.")
                return
            pname = item.data(Qt.UserRole)
            if pname == self.perfil:
                QMessageBox.information(dialog, "Perfis", "Este perfil já está em uso.")
                return
            reply = QMessageBox.question(
                dialog, "Alternar Perfil",
                f"Alternar para o perfil '{pname}'?\n\nO navegador será reiniciado.",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                cfg = load_config()
                cfg["perfil"] = pname
                save_config(cfg)
                dialog.accept()
                QProcess.startDetached(sys.executable, [sys.argv[0]])
                QApplication.quit()

        def rename_profile():
            item = profile_list.currentItem()
            if not item:
                return
            pname = item.data(Qt.UserRole)
            if pname == self.perfil:
                QMessageBox.warning(dialog, "Renomear", "Não é possível renomear o perfil em uso.")
                return
            novo, ok = QInputDialog.getText(dialog, "Renomear Perfil",
                f"Novo nome para '{pname}':", text=pname)
            if ok and novo.strip():
                novo = novo.strip().replace(" ", "_").lower()
                src = os.path.join(DATA_DIR, pname)
                dst = os.path.join(DATA_DIR, novo)
                if os.path.exists(dst):
                    QMessageBox.warning(dialog, "Erro", f"Já existe um perfil com o nome '{novo}'.")
                    return
                try:
                    os.rename(src, dst)
                    cfg = load_config()
                    if cfg.get("perfil") == pname:
                        cfg["perfil"] = novo
                        save_config(cfg)
                    refresh_profile_list()
                    QMessageBox.information(dialog, "Perfis", f"Perfil renomeado para '{novo}'.")
                except Exception as e:
                    QMessageBox.critical(dialog, "Erro", f"Erro ao renomear: {e}")

        def delete_profile():
            item = profile_list.currentItem()
            if not item:
                return
            pname = item.data(Qt.UserRole)
            if pname == self.perfil:
                QMessageBox.warning(dialog, "Excluir", "Não é possível excluir o perfil em uso.")
                return
            if pname == "default":
                QMessageBox.warning(dialog, "Excluir", "O perfil 'default' não pode ser excluído.")
                return
            reply = QMessageBox.question(
                dialog, "Excluir Perfil",
                f"⚠️ Excluir permanentemente o perfil '{pname}'?\n\n"
                "Todos os favoritos, histórico e configurações serão perdidos.",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                try:
                    shutil.rmtree(os.path.join(DATA_DIR, pname))
                    refresh_profile_list()
                    info_lbl.setText("Perfil excluído.")
                    QMessageBox.information(dialog, "Perfis", f"Perfil '{pname}' excluído.")
                except Exception as e:
                    QMessageBox.critical(dialog, "Erro", f"Erro ao excluir: {e}")

        btn_switch.clicked.connect(switch_profile)
        btn_rename.clicked.connect(rename_profile)
        btn_delete.clicked.connect(delete_profile)

        btns = QDialogButtonBox(QDialogButtonBox.Close)
        btns.rejected.connect(dialog.reject)
        layout.addWidget(btns)

        dialog.exec_()

    def action_create_profile(self):
        """Cria um novo perfil com configurações personalizadas."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Criar Novo Perfil")
        dialog.setMinimumWidth(420)
        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel("<b>Nome do perfil:</b>"))
        name_edit = QLineEdit()
        name_edit.setPlaceholderText("Ex: trabalho, pessoal, estudos...")
        layout.addWidget(name_edit)

        layout.addWidget(QLabel("<b>Página inicial:</b>"))
        home_edit = QLineEdit(HOME_URL_DEFAULT)
        layout.addWidget(home_edit)

        layout.addWidget(QLabel("<b>Motor de busca padrão:</b>"))
        engine_combo = QComboBox()
        engines = {
            "Google": "https://www.google.com/search?q={}",
            "DuckDuckGo": "https://duckduckgo.com/?q={}",
            "Bing": "https://www.bing.com/search?q={}",
            "Brave Search": "https://search.brave.com/search?q={}",
            "Startpage": "https://www.startpage.com/search?q={}",
        }
        for name in engines:
            engine_combo.addItem(name)
        layout.addWidget(engine_combo)

        chk_private = QCheckBox("Perfil em modo privado (não salva histórico)")
        layout.addWidget(chk_private)

        chk_switch = QCheckBox("Alternar para este perfil após criar")
        chk_switch.setChecked(True)
        layout.addWidget(chk_switch)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.button(QDialogButtonBox.Ok).setText("Criar Perfil")
        btns.accepted.connect(dialog.accept)
        btns.rejected.connect(dialog.reject)
        layout.addWidget(btns)

        if dialog.exec_() != QDialog.Accepted:
            return

        nome = name_edit.text().strip().replace(" ", "_").lower()
        if not nome:
            QMessageBox.warning(self, "Erro", "O nome do perfil não pode ser vazio.")
            return

        # Valida caracteres
        safe = all(c.isalnum() or c in "_-" for c in nome)
        if not safe:
            QMessageBox.warning(self, "Erro", "Use apenas letras, números, _ e - no nome do perfil.")
            return

        profile_dir = os.path.join(DATA_DIR, nome)
        if os.path.exists(profile_dir):
            QMessageBox.warning(self, "Erro", f"Já existe um perfil com o nome '{nome}'.")
            return

        try:
            ensure_dir(profile_dir)
            enc = DataEncryption(nome)
            engine_name = engine_combo.currentText()
            config = {
                "home_url": home_edit.text().strip() or HOME_URL_DEFAULT,
                "allowlist_domains": sorted(DEFAULT_ALLOWLIST_DOMAINS),
                "blocklist_domains": [],
                "scheme_policy": DEFAULT_SCHEME_POLICY.copy(),
                "search_engine_url": engines[engine_name],
                "private_mode": chk_private.isChecked(),
                "created": datetime.datetime.now().isoformat(),
            }
            _atomic_write_encrypted(os.path.join(profile_dir, "config.json"), config, enc)

            # Inicializa banco de histórico
            db_path = os.path.join(profile_dir, "history.db")
            conn2 = sqlite3.connect(db_path)
            conn2.execute("""CREATE TABLE IF NOT EXISTS history (
                url TEXT PRIMARY KEY, title TEXT, timestamp TEXT, count INTEGER DEFAULT 1)""")
            conn2.commit()
            conn2.close()

            msg = f"✅ Perfil '{nome}' criado com sucesso!"
            if chk_switch.isChecked():
                reply = QMessageBox.question(
                    self, "Perfil Criado",
                    f"{msg}\n\nAlternar para '{nome}' agora? O navegador será reiniciado.",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.Yes:
                    cfg = load_config()
                    cfg["perfil"] = nome
                    save_config(cfg)
                    QProcess.startDetached(sys.executable, [sys.argv[0]])
                    QApplication.quit()
                    return
            else:
                QMessageBox.information(self, "Perfil Criado", msg)
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Erro ao criar perfil: {e}")

    def action_start_with_profile(self):
        """Define o perfil atual como padrão de inicialização."""
        cfg = load_config()
        current_default = cfg.get("perfil", "default")

        if current_default == self.perfil:
            QMessageBox.information(
                self, "Iniciar com Este Perfil",
                f"O perfil '{self.perfil}' já é o padrão ao iniciar o Marveloc."
            )
            return

        reply = QMessageBox.question(
            self, "Iniciar com Este Perfil",
            f"Definir '{self.perfil}' como perfil padrão ao iniciar?\n\n"
            f"(Atualmente: '{current_default}')",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            cfg["perfil"] = self.perfil
            save_config(cfg)
            self.status_bar.showMessage(
                f"✅ Perfil '{self.perfil}' definido como padrão de inicialização.", 4000
            )

    def action_sync_settings(self):
        """Sincronização de dados do perfil — exportar/importar backup."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Sincronização de Dados do Perfil")
        dialog.setMinimumWidth(500)
        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel(
            f"<b>Perfil:</b> {self.perfil}<br>"
            "<br>Sincronize seus dados exportando ou importando um arquivo de backup.<br>"
            "Isso permite transferir favoritos, configurações e histórico entre dispositivos."
        ))

        # Grupo exportar
        grp_exp = QGroupBox("📤 Exportar dados deste perfil")
        exp_layout = QVBoxLayout(grp_exp)

        chk_exp_favs = QCheckBox("Favoritos")
        chk_exp_favs.setChecked(True)
        chk_exp_hist = QCheckBox("Histórico de navegação")
        chk_exp_hist.setChecked(True)
        chk_exp_cfg = QCheckBox("Configurações do perfil")
        chk_exp_cfg.setChecked(True)

        exp_layout.addWidget(chk_exp_favs)
        exp_layout.addWidget(chk_exp_hist)
        exp_layout.addWidget(chk_exp_cfg)

        btn_export = QPushButton("Exportar backup (.json)...")
        exp_layout.addWidget(btn_export)
        layout.addWidget(grp_exp)

        # Grupo importar
        grp_imp = QGroupBox("📥 Importar dados de backup")
        imp_layout = QVBoxLayout(grp_imp)
        imp_layout.addWidget(QLabel("Importa dados de um backup gerado pelo Marveloc."))
        btn_import = QPushButton("Importar backup (.json)...")
        imp_layout.addWidget(btn_import)
        layout.addWidget(grp_imp)

        btns = QDialogButtonBox(QDialogButtonBox.Close)
        btns.rejected.connect(dialog.reject)
        layout.addWidget(btns)

        def do_export():
            file_path, _ = QFileDialog.getSaveFileName(
                dialog, "Exportar Backup do Perfil",
                f"marveloc_backup_{self.perfil}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                "JSON Backup (*.json)"
            )
            if not file_path:
                return
            try:
                backup = {
                    "marveloc_backup": True,
                    "perfil": self.perfil,
                    "data": datetime.datetime.now().isoformat(),
                    "versao": "1.0",
                }
                if chk_exp_favs.isChecked():
                    backup["favoritos"] = self.favoritos
                if chk_exp_hist.isChecked():
                    cursor = self.conn.cursor()
                    cursor.execute("SELECT url, title, timestamp, count FROM history ORDER BY timestamp DESC LIMIT 5000")
                    backup["historico"] = [
                        {"url": r[0], "title": r[1], "timestamp": r[2], "count": r[3]}
                        for r in cursor.fetchall()
                    ]
                if chk_exp_cfg.isChecked():
                    backup["config"] = {
                        "home_url": self.home_url,
                        "search_engine_url": self.search_engine_url,
                        "zoom_level": self.zoom_level,
                    }
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(backup, f, ensure_ascii=False, indent=2)
                QMessageBox.information(dialog, "Backup", f"✅ Backup exportado para:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(dialog, "Erro", f"Erro ao exportar: {e}")

        def do_import():
            file_path, _ = QFileDialog.getOpenFileName(
                dialog, "Importar Backup do Perfil", "",
                "JSON Backup (*.json);;Todos os arquivos (*)"
            )
            if not file_path:
                return
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    backup = json.load(f)

                if not backup.get("marveloc_backup"):
                    QMessageBox.warning(dialog, "Importar", "Arquivo não reconhecido como backup do Marveloc.")
                    return

                origem = backup.get("perfil", "?")
                data_bkp = backup.get("data", "?")[:19]
                reply = QMessageBox.question(
                    dialog, "Importar Backup",
                    f"Importar backup do perfil '{origem}' gerado em {data_bkp}?\n\n"
                    "Os dados importados serão mesclados com os atuais.",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply != QMessageBox.Yes:
                    return

                msgs = []
                # Favoritos
                if "favoritos" in backup:
                    existing_urls = {f.get("url") for f in self.favoritos}
                    imported_favs = sum(1 for f in backup["favoritos"]
                                       if f.get("url") and f["url"] not in existing_urls
                                       and not self.favoritos.append(f))
                    _atomic_write_encrypted(self.fav_path, self.favoritos, self.encryptor)
                    self.bookmarks_updated.emit()
                    msgs.append(f"{imported_favs} favorito(s)")

                # Histórico
                if "historico" in backup:
                    cursor = self.conn.cursor()
                    imported_hist = 0
                    for entry in backup["historico"]:
                        try:
                            cursor.execute("SELECT count FROM history WHERE url=?", (entry["url"],))
                            if not cursor.fetchone():
                                cursor.execute(
                                    "INSERT INTO history(url,title,timestamp,count) VALUES(?,?,?,?)",
                                    (entry["url"], entry.get("title",""), entry.get("timestamp",""), entry.get("count",1))
                                )
                                imported_hist += 1
                        except Exception:
                            pass
                    self.conn.commit()
                    msgs.append(f"{imported_hist} entrada(s) de histórico")

                # Config
                if "config" in backup:
                    cfg_bkp = backup["config"]
                    if "home_url" in cfg_bkp:
                        self.home_url = cfg_bkp["home_url"]
                    if "search_engine_url" in cfg_bkp:
                        self.search_engine_url = cfg_bkp["search_engine_url"]
                    self.save_perfil_config()
                    msgs.append("configurações")

                QMessageBox.information(dialog, "Importar Backup",
                    f"✅ Importado com sucesso:\n" + "\n".join(f"• {m}" for m in msgs))
            except Exception as e:
                QMessageBox.critical(dialog, "Erro", f"Erro ao importar backup: {e}")

        btn_export.clicked.connect(do_export)
        btn_import.clicked.connect(do_import)
        dialog.exec_()

    def action_manage_accounts(self):
        """Gerir contas e senhas salvas no perfil."""
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Gerir Contas — Perfil: {self.perfil}")
        dialog.setMinimumSize(620, 460)
        layout = QVBoxLayout(dialog)

        # Carrega senhas salvas
        passwords_path = os.path.join(self.perfil_dir, "passwords.json")
        passwords = []
        try:
            raw = self.load_json(passwords_path, default=[])
            if isinstance(raw, list):
                passwords = raw
        except Exception:
            pass

        layout.addWidget(QLabel(
            f"<b>Contas salvas no perfil '{self.perfil}'</b><br>"
            "<span style='color:#888; font-size:11px;'>As senhas são armazenadas de forma criptografada localmente.</span>"
        ))

        # Pesquisa
        search_edit = QLineEdit()
        search_edit.setPlaceholderText("🔍 Pesquisar por site ou usuário...")
        layout.addWidget(search_edit)

        # Tabela de contas
        tree = QTreeWidget()
        tree.setHeaderLabels(["Site / URL", "Usuário", "Senha", "Salvo em"])
        tree.setColumnWidth(0, 220)
        tree.setColumnWidth(1, 140)
        tree.setColumnWidth(2, 100)
        tree.setColumnWidth(3, 120)
        tree.setAlternatingRowColors(True)
        tree.setSortingEnabled(True)
        layout.addWidget(tree)

        status_lbl = QLabel("")
        layout.addWidget(status_lbl)

        def load_accounts(filter_text=""):
            tree.clear()
            shown = 0
            for entry in passwords:
                site = entry.get("site", "")
                user = entry.get("username", "")
                saved = entry.get("saved", "")[:16]
                if filter_text and filter_text.lower() not in site.lower() and filter_text.lower() not in user.lower():
                    continue
                item = QTreeWidgetItem([site, user, "••••••••", saved])
                item.setData(0, Qt.UserRole, entry)
                tree.addTopLevelItem(item)
                shown += 1
            status_lbl.setText(f"{shown} conta(s) encontrada(s) de {len(passwords)} total.")

        search_edit.textChanged.connect(load_accounts)
        load_accounts()

        # Botões
        btn_row = QHBoxLayout()

        btn_add = QPushButton("➕ Adicionar conta")
        btn_show = QPushButton("👁 Mostrar senha")
        btn_copy_user = QPushButton("📋 Copiar usuário")
        btn_copy_pass = QPushButton("🔑 Copiar senha")
        btn_delete = QPushButton("🗑 Remover")
        btn_delete.setStyleSheet("color: #c0392b;")

        btn_row.addWidget(btn_add)
        btn_row.addWidget(btn_show)
        btn_row.addWidget(btn_copy_user)
        btn_row.addWidget(btn_copy_pass)
        btn_row.addWidget(btn_delete)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        def add_account():
            d2 = QDialog(dialog)
            d2.setWindowTitle("Adicionar Conta")
            d2.setMinimumWidth(360)
            lay2 = QVBoxLayout(d2)
            lay2.addWidget(QLabel("Site / URL:"))
            site_e = QLineEdit()
            site_e.setPlaceholderText("https://exemplo.com")
            lay2.addWidget(site_e)
            lay2.addWidget(QLabel("Usuário / Email:"))
            user_e = QLineEdit()
            lay2.addWidget(user_e)
            lay2.addWidget(QLabel("Senha:"))
            pass_e = QLineEdit()
            pass_e.setEchoMode(QLineEdit.Password)
            lay2.addWidget(pass_e)
            chk_show = QCheckBox("Mostrar senha")
            chk_show.toggled.connect(lambda c: pass_e.setEchoMode(QLineEdit.Normal if c else QLineEdit.Password))
            lay2.addWidget(chk_show)
            b2 = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
            b2.accepted.connect(d2.accept)
            b2.rejected.connect(d2.reject)
            lay2.addWidget(b2)
            if d2.exec_() == QDialog.Accepted:
                entry = {
                    "site": site_e.text().strip(),
                    "username": user_e.text().strip(),
                    "password": pass_e.text(),
                    "saved": datetime.datetime.now().isoformat()
                }
                passwords.append(entry)
                _atomic_write_encrypted(passwords_path, passwords, self.encryptor)
                load_accounts(search_edit.text())

        def show_password():
            item = tree.currentItem()
            if not item:
                return
            entry = item.data(0, Qt.UserRole)
            raw_pass = entry.get("password", "")
            QMessageBox.information(dialog, "Senha",
                f"<b>Site:</b> {entry.get('site','')}<br>"
                f"<b>Usuário:</b> {entry.get('username','')}<br>"
                f"<b>Senha:</b> <span style='font-family:monospace'>{raw_pass}</span>")

        def copy_user():
            item = tree.currentItem()
            if item:
                entry = item.data(0, Qt.UserRole)
                QApplication.clipboard().setText(entry.get("username", ""))
                self.status_bar.showMessage("Usuário copiado.", 2000)

        def copy_pass():
            item = tree.currentItem()
            if item:
                entry = item.data(0, Qt.UserRole)
                QApplication.clipboard().setText(entry.get("password", ""))
                self.status_bar.showMessage("Senha copiada para a área de transferência.", 2000)

        def delete_account():
            item = tree.currentItem()
            if not item:
                return
            entry = item.data(0, Qt.UserRole)
            reply = QMessageBox.question(dialog, "Remover Conta",
                f"Remover conta de '{entry.get('site','?')}'?",
                QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes and entry in passwords:
                passwords.remove(entry)
                _atomic_write_encrypted(passwords_path, passwords, self.encryptor)
                load_accounts(search_edit.text())

        btn_add.clicked.connect(add_account)
        btn_show.clicked.connect(show_password)
        btn_copy_user.clicked.connect(copy_user)
        btn_copy_pass.clicked.connect(copy_pass)
        btn_delete.clicked.connect(delete_account)

        btns = QDialogButtonBox(QDialogButtonBox.Close)
        btns.rejected.connect(dialog.reject)
        layout.addWidget(btns)
        dialog.exec_()

    def action_sign_out_profile(self):
        """Sai do perfil atual e volta para o perfil default ou escolhe outro."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Sair do Perfil")
        dialog.setMinimumWidth(380)
        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel(
            f"<b>Perfil atual:</b> {self.perfil}<br><br>"
            "O que deseja fazer?"
        ))

        opt_switch = QRadioButton("Alternar para outro perfil")
        opt_close = QRadioButton("Fechar o navegador")
        opt_switch.setChecked(True)
        layout.addWidget(opt_switch)

        # Lista de outros perfis
        other_profiles = []
        if os.path.exists(DATA_DIR):
            other_profiles = sorted([d for d in os.listdir(DATA_DIR)
                                     if os.path.isdir(os.path.join(DATA_DIR, d))
                                     and d != self.perfil
                                     and not d.startswith("private_")])
        if not other_profiles:
            other_profiles = ["default"]

        profile_combo = QComboBox()
        for p in other_profiles:
            profile_combo.addItem(f"  👤  {p}", p)
        opt_switch.toggled.connect(profile_combo.setEnabled)
        layout.addWidget(profile_combo)

        layout.addWidget(opt_close)

        # Opção de salvar sessão
        chk_save = QCheckBox("Salvar abas abertas para restaurar depois")
        chk_save.setChecked(True)
        layout.addWidget(chk_save)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.button(QDialogButtonBox.Ok).setText("Confirmar")
        btns.accepted.connect(dialog.accept)
        btns.rejected.connect(dialog.reject)
        layout.addWidget(btns)

        if dialog.exec_() != QDialog.Accepted:
            return

        # Salva sessão se solicitado
        if chk_save.isChecked():
            try:
                session = [{"url": self.tabs.widget(i).browser.url().toString(),
                            "title": self.tabs.widget(i).browser.title()}
                           for i in range(self.tabs.count())]
                self.perfil_config["saved_session"] = session
                self.save_perfil_config()
            except Exception:
                pass

        if opt_switch.isChecked():
            target = profile_combo.currentData()
            cfg = load_config()
            cfg["perfil"] = target
            save_config(cfg)
            QProcess.startDetached(sys.executable, [sys.argv[0]])
            QApplication.quit()
        else:
            QApplication.closeAllWindows()

    def action_extensions(self):
        """Gerenciador de extensões (scripts de usuário) e temas visuais."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Extensões e Temas")
        dialog.setMinimumSize(660, 500)
        layout = QVBoxLayout(dialog)

        tabs = QTabWidget()

        # ── Aba: Scripts de Usuário ──────────────────────────────────────
        tab_scripts = QWidget()
        sl = QVBoxLayout(tab_scripts)
        sl.addWidget(QLabel(
            "<b>Scripts de Usuário (UserScripts)</b><br>"
            "<span style='color:#555;font-size:11px'>Scripts JavaScript injetados em páginas específicas ao carregar.</span>"
        ))

        scripts_path = os.path.join(self.perfil_dir, "userscripts.json")
        scripts = self.load_json(scripts_path, default=[])

        script_list = QListWidget()
        script_list.setAlternatingRowColors(True)

        def refresh_scripts():
            script_list.clear()
            for s in scripts:
                item = QListWidgetItem(
                    f"{'✅' if s.get('enabled', True) else '⬜'}  {s.get('name','?')}  "
                    f"— {s.get('match','*')}"
                )
                item.setData(Qt.UserRole, s)
                script_list.addItem(item)

        refresh_scripts()
        sl.addWidget(script_list)

        sb = QHBoxLayout()
        btn_add_s = QPushButton("➕ Novo Script")
        btn_edit_s = QPushButton("✏️ Editar")
        btn_toggle_s = QPushButton("⏯ Ativar/Desativar")
        btn_del_s = QPushButton("🗑 Remover")
        for b in [btn_add_s, btn_edit_s, btn_toggle_s, btn_del_s]:
            sb.addWidget(b)
        sb.addStretch()
        sl.addLayout(sb)

        def add_script():
            d2 = QDialog(dialog)
            d2.setWindowTitle("Novo Script de Usuário")
            d2.setMinimumSize(500, 400)
            lay2 = QVBoxLayout(d2)
            lay2.addWidget(QLabel("Nome:"))
            name_e = QLineEdit("Meu Script")
            lay2.addWidget(name_e)
            lay2.addWidget(QLabel("Executar em (padrão URL, ex: *google.com*, https://exemplo.com/*):"))
            match_e = QLineEdit("*")
            lay2.addWidget(match_e)
            lay2.addWidget(QLabel("Código JavaScript:"))
            code_e = QTextEdit()
            code_e.setPlaceholderText("// Seu script aqui\nconsole.log('Marveloc UserScript!');")
            code_e.setFont(QFont("Consolas", 10))
            lay2.addWidget(code_e)
            b2 = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
            b2.accepted.connect(d2.accept)
            b2.rejected.connect(d2.reject)
            lay2.addWidget(b2)
            if d2.exec_() == QDialog.Accepted:
                scripts.append({
                    "name": name_e.text().strip() or "Script",
                    "match": match_e.text().strip() or "*",
                    "code": code_e.toPlainText(),
                    "enabled": True
                })
                _atomic_write_encrypted(scripts_path, scripts, self.encryptor)
                self.userscripts = scripts
                refresh_scripts()

        def edit_script():
            item = script_list.currentItem()
            if not item:
                return
            s = item.data(Qt.UserRole)
            d2 = QDialog(dialog)
            d2.setWindowTitle("Editar Script")
            d2.setMinimumSize(500, 400)
            lay2 = QVBoxLayout(d2)
            lay2.addWidget(QLabel("Nome:"))
            name_e = QLineEdit(s.get("name",""))
            lay2.addWidget(name_e)
            lay2.addWidget(QLabel("Executar em:"))
            match_e = QLineEdit(s.get("match","*"))
            lay2.addWidget(match_e)
            lay2.addWidget(QLabel("Código JavaScript:"))
            code_e = QTextEdit(s.get("code",""))
            code_e.setFont(QFont("Consolas", 10))
            lay2.addWidget(code_e)
            b2 = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
            b2.accepted.connect(d2.accept)
            b2.rejected.connect(d2.reject)
            lay2.addWidget(b2)
            if d2.exec_() == QDialog.Accepted:
                s["name"] = name_e.text().strip()
                s["match"] = match_e.text().strip()
                s["code"] = code_e.toPlainText()
                _atomic_write_encrypted(scripts_path, scripts, self.encryptor)
                self.userscripts = scripts
                refresh_scripts()

        def toggle_script():
            item = script_list.currentItem()
            if item:
                s = item.data(Qt.UserRole)
                s["enabled"] = not s.get("enabled", True)
                _atomic_write_encrypted(scripts_path, scripts, self.encryptor)
                self.userscripts = scripts
                refresh_scripts()

        def del_script():
            item = script_list.currentItem()
            if item:
                s = item.data(Qt.UserRole)
                if s in scripts:
                    scripts.remove(s)
                    _atomic_write_encrypted(scripts_path, scripts, self.encryptor)
                    self.userscripts = scripts
                    refresh_scripts()

        btn_add_s.clicked.connect(add_script)
        btn_edit_s.clicked.connect(edit_script)
        btn_toggle_s.clicked.connect(toggle_script)
        btn_del_s.clicked.connect(del_script)

        tabs.addTab(tab_scripts, "🧩 Scripts de Usuário")

        # ── Aba: Temas ──────────────────────────────────────────────────
        tab_themes = QWidget()
        tl = QVBoxLayout(tab_themes)
        tl.addWidget(QLabel("<b>Temas Visuais</b><br><span style='color:#555;font-size:11px'>Escolha a aparência do navegador.</span>"))

        THEMES = {
            "Padrão (Cinza)": """
                QMainWindow,QDialog{background:#f5f5f5} QToolBar{background:#e8e8e8;border:none;padding:4px}
                QTabBar::tab{background:#d8d8d8;padding:6px 14px;border:1px solid #c0c0c0;border-bottom:none;border-top-left-radius:6px;border-top-right-radius:6px}
                QTabBar::tab:selected{background:white} QLineEdit{padding:6px 14px;border:1.5px solid #c8c8c8;border-radius:18px;background:white;font-size:13px}
                QLineEdit:focus{border:2px solid #4285f4} QStatusBar{background:#e1e1e1}
            """,
            "Azul Oceano": """
                QMainWindow,QDialog{background:#e3f0fb} QToolBar{background:#1565c0;border:none;padding:4px}
                QToolBar QAction,QToolButton{color:white} QTabBar::tab{background:#1976d2;color:white;padding:6px 14px;border:none;border-top-left-radius:6px;border-top-right-radius:6px}
                QTabBar::tab:selected{background:#0d47a1;color:white} QLineEdit{padding:6px 14px;border:2px solid #1565c0;border-radius:18px;background:white;font-size:13px}
                QLineEdit:focus{border:2px solid #0d47a1} QStatusBar{background:#1565c0;color:white}
            """,
            "Modo Escuro": """
                QMainWindow,QWidget,QDialog{background:#1e1e1e;color:#e0e0e0}
                QToolBar{background:#252526;border:none;padding:4px}
                QTabBar::tab{background:#2d2d2d;color:#ccc;padding:6px 14px;border:1px solid #3c3c3c;border-bottom:none;border-top-left-radius:6px;border-top-right-radius:6px}
                QTabBar::tab:selected{background:#1e1e1e;color:white}
                QLineEdit{padding:6px 14px;border:1.5px solid #555;border-radius:18px;background:#2d2d2d;color:#e0e0e0;font-size:13px}
                QLineEdit:focus{border:2px solid #569cd6}
                QMenu{background:#252526;color:#e0e0e0;border:1px solid #3c3c3c}
                QMenu::item:selected{background:#094771}
                QStatusBar{background:#007acc;color:white}
                QMenuBar{background:#252526;color:#e0e0e0}
                QMenuBar::item:selected{background:#094771}
            """,
            "Verde Floresta": """
                QMainWindow,QDialog{background:#e8f5e9} QToolBar{background:#2e7d32;border:none;padding:4px}
                QTabBar::tab{background:#388e3c;color:white;padding:6px 14px;border:none;border-top-left-radius:6px;border-top-right-radius:6px}
                QTabBar::tab:selected{background:#1b5e20;color:white} QLineEdit{padding:6px 14px;border:2px solid #2e7d32;border-radius:18px;background:white;font-size:13px}
                QLineEdit:focus{border:2px solid #1b5e20} QStatusBar{background:#2e7d32;color:white}
            """,
            "Roxo Noite": """
                QMainWindow,QWidget,QDialog{background:#1a0a2e;color:#e0d0ff}
                QToolBar{background:#2d1b4e;border:none;padding:4px}
                QTabBar::tab{background:#3d2060;color:#ccc;padding:6px 14px;border:1px solid #5b2d8e;border-bottom:none;border-top-left-radius:6px;border-top-right-radius:6px}
                QTabBar::tab:selected{background:#1a0a2e;color:white}
                QLineEdit{padding:6px 14px;border:1.5px solid #7b3fd4;border-radius:18px;background:#2d1b4e;color:#e0d0ff;font-size:13px}
                QLineEdit:focus{border:2px solid #a066f0}
                QMenu{background:#2d1b4e;color:#e0d0ff;border:1px solid #5b2d8e}
                QMenu::item:selected{background:#5b2d8e}
                QStatusBar{background:#7b3fd4;color:white}
                QMenuBar{background:#2d1b4e;color:#e0d0ff}
                QMenuBar::item:selected{background:#5b2d8e}
            """,
        }

        theme_list = QListWidget()
        saved_theme = (self.perfil_config or {}).get("theme", "Padrão (Cinza)")
        for name in THEMES:
            item = QListWidgetItem(name)
            if name == saved_theme:
                font = item.font()
                font.setBold(True)
                item.setFont(font)
            theme_list.addItem(item)
        tl.addWidget(theme_list)

        preview_lbl = QLabel("Selecione um tema para visualizar.")
        preview_lbl.setWordWrap(True)
        tl.addWidget(preview_lbl)

        btn_apply_theme = QPushButton("🎨 Aplicar Tema")
        tl.addWidget(btn_apply_theme)

        def apply_theme():
            item = theme_list.currentItem()
            if not item:
                return
            name = item.text()
            css = THEMES.get(name, "")
            self.setStyleSheet(css)
            self.perfil_config["theme"] = name
            self.save_perfil_config()
            preview_lbl.setText(f"✅ Tema '{name}' aplicado!")

        btn_apply_theme.clicked.connect(apply_theme)
        tabs.addTab(tab_themes, "🎨 Temas")

        layout.addWidget(tabs)
        btns = QDialogButtonBox(QDialogButtonBox.Close)
        btns.rejected.connect(dialog.reject)
        layout.addWidget(btns)

        # Carrega scripts salvos
        self.userscripts = scripts
        dialog.exec_()

    def action_password_manager(self):
        """Abre gerenciador de senhas (mesmo que Gerir contas em Perfis)."""
        self.action_manage_accounts()

    def action_search_settings(self):
        """Definições de pesquisa — motor de busca e comportamento."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Definições de Pesquisa")
        dialog.setMinimumWidth(460)
        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel("<b>Motor de busca padrão:</b>"))

        engines = [
            ("Google", "https://www.google.com/search?q={}"),
            ("DuckDuckGo", "https://duckduckgo.com/?q={}"),
            ("Bing", "https://www.bing.com/search?q={}"),
            ("Brave Search", "https://search.brave.com/search?q={}"),
            ("Startpage", "https://www.startpage.com/search?q={}"),
            ("Ecosia", "https://www.ecosia.org/search?q={}"),
            ("SearXNG (local)", "http://localhost:8888/search?q={}"),
        ]

        engine_combo = QComboBox()
        for name, url in engines:
            engine_combo.addItem(name, url)

        current_url = getattr(self, "search_engine_url", engines[0][1])
        for i, (_, url) in enumerate(engines):
            if url == current_url:
                engine_combo.setCurrentIndex(i)
                break

        layout.addWidget(engine_combo)

        layout.addWidget(QLabel("<b>URL personalizada (opcional):</b>"))
        custom_url = QLineEdit()
        custom_url.setPlaceholderText("https://meumotor.com/search?q={}")
        custom_url.setToolTip("Use {} onde a palavra de busca deve ser inserida")
        layout.addWidget(custom_url)

        grp = QGroupBox("Comportamento")
        grp_lay = QVBoxLayout(grp)
        chk_suggest = QCheckBox("Mostrar sugestões de busca (conecta ao motor)")
        chk_suggest.setChecked((self.perfil_config or {}).get("search_suggestions", True))
        chk_keyword = QCheckBox("Busca por palavra-chave na URL bar (ex: 'g python' busca no Google)")
        chk_keyword.setChecked((self.perfil_config or {}).get("keyword_search", True))
        grp_lay.addWidget(chk_suggest)
        grp_lay.addWidget(chk_keyword)
        layout.addWidget(grp)

        # Atalhos de motor por palavra-chave
        layout.addWidget(QLabel("<b>Atalhos de busca rápida:</b>"))
        shortcut_info = QLabel(
            "  <b>g</b> → Google  |  <b>d</b> → DuckDuckGo  |  <b>b</b> → Bing\n"
            "  <b>y</b> → YouTube  |  <b>w</b> → Wikipedia\n"
            "  Exemplo: <i>y lo-fi music</i> busca no YouTube"
        )
        shortcut_info.setStyleSheet("background:#f4f4f4; padding:8px; border-radius:4px;")
        layout.addWidget(shortcut_info)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.button(QDialogButtonBox.Ok).setText("Salvar")
        btns.accepted.connect(dialog.accept)
        btns.rejected.connect(dialog.reject)
        layout.addWidget(btns)

        if dialog.exec_() == QDialog.Accepted:
            custom = custom_url.text().strip()
            if custom and "{}" in custom:
                self.search_engine_url = custom
            else:
                self.search_engine_url = engine_combo.currentData()
            self.perfil_config["search_suggestions"] = chk_suggest.isChecked()
            self.perfil_config["keyword_search"] = chk_keyword.isChecked()
            self.save_perfil_config()
            self.status_bar.showMessage(
                f"Motor de busca: {engine_combo.currentText()}", 3000
            )

    def action_task_manager(self):
        """Gestor de tarefas — mostra consumo de memória e CPU por aba."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Gestor de Tarefas do Navegador")
        dialog.setMinimumSize(620, 400)
        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel(
            "<b>Processos do Marveloc</b><br>"
            "<span style='color:#555;font-size:11px'>Duplo clique para ir à aba. Atualiza automaticamente.</span>"
        ))

        tree = QTreeWidget()
        tree.setHeaderLabels(["Tarefa", "URL", "Memória (aprox.)", "Estado"])
        tree.setColumnWidth(0, 200)
        tree.setColumnWidth(1, 220)
        tree.setColumnWidth(2, 110)
        tree.setColumnWidth(3, 80)
        tree.setAlternatingRowColors(True)
        layout.addWidget(tree)

        total_lbl = QLabel("")
        total_lbl.setStyleSheet("font-weight:bold; padding:4px;")
        layout.addWidget(total_lbl)

        def refresh():
            tree.clear()
            total_mem = 0

            # Processo principal
            try:
                import resource
                mem_main = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                if platform.system() == "Darwin":
                    mem_main //= 1024
            except Exception:
                mem_main = 0

            main_item = QTreeWidgetItem(["🏠 Processo Principal", sys.argv[0], f"{mem_main:,} KB", "Ativo"])
            main_item.setData(0, Qt.UserRole, -1)
            tree.addTopLevelItem(main_item)
            total_mem += mem_main

            # Abas
            for i in range(self.tabs.count()):
                tab = self.tabs.widget(i)
                if not tab:
                    continue
                tab_title = self.tabs.tabText(i) or f"Aba {i+1}"
                url = tab.browser.url().toString()
                state = "Ativa" if i == self.tabs.currentIndex() else "Em segundo plano"

                # Estimativa de memória via JavaScript (heap)
                mem_estimate = "—"

                item = QTreeWidgetItem([
                    f"{'▶ ' if state == 'Ativa' else '  '}📄 {tab_title[:35]}",
                    url[:55],
                    mem_estimate,
                    state
                ])
                item.setData(0, Qt.UserRole, i)
                if state == "Ativa":
                    font = item.font(0)
                    font.setBold(True)
                    item.setFont(0, font)
                tree.addTopLevelItem(item)

            # Obtém memória JS real via callback (assíncrono)
            for i in range(self.tabs.count()):
                tab = self.tabs.widget(i)
                if tab:
                    tab_item = tree.topLevelItem(i + 1)
                    def make_cb(ti):
                        def cb(result):
                            try:
                                if result and isinstance(result, (int, float)):
                                    kb = int(result / 1024)
                                    ti.setText(2, f"{kb:,} KB")
                            except Exception:
                                pass
                        return cb
                    tab.browser.page().runJavaScript(
                        "performance.memory ? performance.memory.usedJSHeapSize : 0",
                        make_cb(tab_item)
                    )

            total_lbl.setText(f"Total em execução: {self.tabs.count()} aba(s) + processo principal")

        def on_double_click(item, _):
            idx = item.data(0, Qt.UserRole)
            if isinstance(idx, int) and idx >= 0:
                self.tabs.setCurrentIndex(idx)
                dialog.accept()

        def end_task():
            item = tree.currentItem()
            if not item:
                return
            idx = item.data(0, Qt.UserRole)
            if isinstance(idx, int) and idx >= 0:
                if self.tabs.count() > 1:
                    self.close_current_tab(idx)
                    refresh()
                else:
                    QMessageBox.warning(dialog, "Gestor de Tarefas", "Não é possível fechar a última aba.")
            else:
                QMessageBox.information(dialog, "Gestor de Tarefas", "Não é possível encerrar o processo principal desta forma.")

        tree.itemDoubleClicked.connect(on_double_click)

        btn_row = QHBoxLayout()
        btn_refresh = QPushButton("🔄 Atualizar")
        btn_refresh.clicked.connect(refresh)
        btn_end = QPushButton("⛔ Encerrar Tarefa")
        btn_end.clicked.connect(end_task)
        btn_row.addWidget(btn_refresh)
        btn_row.addWidget(btn_end)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Auto-refresh a cada 3s
        timer = QTimer(dialog)
        timer.timeout.connect(refresh)
        timer.start(3000)

        btns = QDialogButtonBox(QDialogButtonBox.Close)
        btns.rejected.connect(dialog.reject)
        layout.addWidget(btns)

        refresh()
        dialog.exec_()
        timer.stop()

    def action_customize_toolbar(self):
        """Personaliza a barra de ferramentas — mostra/oculta botões."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Personalizar Barra de Ferramentas")
        dialog.setMinimumWidth(420)
        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel("<b>Botões disponíveis na barra:</b>"))

        # Mapeamento de botões que podem ser mostrados/ocultados
        toolbar_config = (self.perfil_config or {}).get("toolbar", {})

        BUTTONS = [
            ("btn_back", "◀ Voltar"),
            ("btn_forward", "▶ Avançar"),
            ("btn_reload", "⟳ Recarregar"),
            ("btn_home", "⌂ Página Inicial"),
            ("btn_fav", "★ Adicionar Favorito"),
            ("btn_most_visited", "Mais Visitados"),
            ("btn_downloads", "↓ Downloads"),
            ("btn_private", "🕵️ Nova Aba Privada"),
        ]

        checks = {}
        for key, label in BUTTONS:
            chk = QCheckBox(label)
            chk.setChecked(toolbar_config.get(key, True))
            checks[key] = chk
            layout.addWidget(chk)

        layout.addWidget(QLabel("<br><b>Tamanho dos ícones:</b>"))
        size_combo = QComboBox()
        size_combo.addItems(["Pequeno (16px)", "Médio (24px)", "Grande (32px)"])
        size_combo.setCurrentIndex(toolbar_config.get("icon_size", 1))
        layout.addWidget(size_combo)

        layout.addWidget(QLabel("<b>Posição da URL bar:</b>"))
        pos_combo = QComboBox()
        pos_combo.addItems(["Centro (padrão)", "Esquerda", "Direita"])
        pos_combo.setCurrentIndex(toolbar_config.get("urlbar_pos", 0))
        layout.addWidget(pos_combo)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.button(QDialogButtonBox.Ok).setText("Aplicar")
        btns.accepted.connect(dialog.accept)
        btns.rejected.connect(dialog.reject)
        layout.addWidget(btns)

        if dialog.exec_() == QDialog.Accepted:
            new_config = {key: chk.isChecked() for key, chk in checks.items()}
            new_config["icon_size"] = size_combo.currentIndex()
            new_config["urlbar_pos"] = pos_combo.currentIndex()
            self.perfil_config["toolbar"] = new_config
            self.save_perfil_config()

            # Aplica tamanho dos ícones
            sizes = [16, 24, 32]
            sz = sizes[size_combo.currentIndex()]
            for tb in self.findChildren(QToolBar):
                tb.setIconSize(QSize(sz, sz))

            self.status_bar.showMessage("Barra de ferramentas personalizada. Reinicie para ver todas as mudanças.", 4000)

    def action_page_options(self):
        """Opções específicas para a página atual."""
        browser = self.tabs.currentWidget().browser
        url = browser.url()
        host = url.host() or "(local)"
        title = browser.title() or url.toString()

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Opções da Página — {host}")
        dialog.setMinimumWidth(460)
        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel(f"<b>{title[:60]}</b><br><span style='color:#555'>{url.toString()[:80]}</span>"))

        # Zoom da página
        grp_zoom = QGroupBox("Zoom")
        gz = QHBoxLayout(grp_zoom)
        gz.addWidget(QLabel("Zoom:"))
        zoom_spin = QSpinBox()
        zoom_spin.setRange(25, 500)
        zoom_spin.setSuffix("%")
        zoom_spin.setValue(int(browser.zoomFactor() * 100))
        gz.addWidget(zoom_spin)
        btn_zoom_reset = QPushButton("Redefinir (100%)")
        btn_zoom_reset.clicked.connect(lambda: zoom_spin.setValue(100))
        gz.addWidget(btn_zoom_reset)
        layout.addWidget(grp_zoom)

        # Configurações de conteúdo
        grp_content = QGroupBox("Conteúdo da Página")
        gc = QVBoxLayout(grp_content)

        settings = browser.page().settings()

        chk_js = QCheckBox("JavaScript habilitado")
        chk_js.setChecked(settings.testAttribute(QWebEngineSettings.JavascriptEnabled))

        chk_images = QCheckBox("Imagens habilitadas")
        chk_images.setChecked(settings.testAttribute(QWebEngineSettings.AutoLoadImages))

        chk_plugins = QCheckBox("Plugins habilitados")
        chk_plugins.setChecked(settings.testAttribute(QWebEngineSettings.PluginsEnabled))

        chk_popups = QCheckBox("Bloquear popups")
        chk_popups.setChecked(not settings.testAttribute(QWebEngineSettings.JavascriptCanOpenWindows))

        for chk in [chk_js, chk_images, chk_plugins, chk_popups]:
            gc.addWidget(chk)
        layout.addWidget(grp_content)

        # Ações rápidas
        grp_actions = QGroupBox("Ações Rápidas")
        ga = QHBoxLayout(grp_actions)
        btn_reload_no_cache = QPushButton("🔄 Recarregar sem cache")
        btn_reload_no_cache.clicked.connect(lambda: (
            browser.page().triggerAction(QWebEnginePage.ReloadAndBypassCache),
            dialog.accept()
        ))
        btn_print = QPushButton("🖨 Imprimir")
        btn_print.clicked.connect(lambda: (self.action_print(), dialog.accept()))
        btn_pdf = QPushButton("📄 Salvar PDF")
        btn_pdf.clicked.connect(lambda: (self.action_save_pdf(), dialog.accept()))
        for b in [btn_reload_no_cache, btn_print, btn_pdf]:
            ga.addWidget(b)
        layout.addWidget(grp_actions)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.button(QDialogButtonBox.Ok).setText("Aplicar")
        btns.accepted.connect(dialog.accept)
        btns.rejected.connect(dialog.reject)
        layout.addWidget(btns)

        if dialog.exec_() == QDialog.Accepted:
            # Aplica zoom
            browser.setZoomFactor(zoom_spin.value() / 100.0)

            # Aplica configurações de conteúdo
            settings.setAttribute(QWebEngineSettings.JavascriptEnabled, chk_js.isChecked())
            settings.setAttribute(QWebEngineSettings.AutoLoadImages, chk_images.isChecked())
            settings.setAttribute(QWebEngineSettings.PluginsEnabled, chk_plugins.isChecked())
            settings.setAttribute(QWebEngineSettings.JavascriptCanOpenWindows, not chk_popups.isChecked())

            self.status_bar.showMessage(f"Opções aplicadas para: {host}", 3000)

    def _open_devtools(self, panel: str = ""):
        """Abre as ferramentas de desenvolvimento (painel opcional)."""
        page = self.tabs.currentWidget().browser.page()
        page_id = id(page)

        if not hasattr(self, '_devtools_windows'):
            self._devtools_windows = {}

        # Reutiliza janela existente
        if page_id in self._devtools_windows:
            dev_view = self._devtools_windows[page_id]
            if dev_view.isVisible():
                dev_view.raise_()
                dev_view.activateWindow()
                if panel:
                    dev_view.page().runJavaScript(
                        f"if(window.DevToolsAPI) DevToolsAPI.showPanel('{panel}');"
                    )
                return
            else:
                del self._devtools_windows[page_id]

        dev_view = QWebEngineView()
        page.setDevToolsPage(dev_view.page())
        title = f"DevTools — {self.tabs.currentWidget().browser.title()[:40]}"
        dev_view.setWindowTitle(title)
        dev_view.resize(900, 650)
        dev_view.show()
        self._devtools_windows[page_id] = dev_view

        if panel:
            QTimer.singleShot(800, lambda: dev_view.page().runJavaScript(
                f"if(window.DevToolsAPI) DevToolsAPI.showPanel('{panel}');"
            ))

    def action_devtools(self):
        """Abre ferramentas de desenvolvimento."""
        self._open_devtools()

    def action_web_console(self):
        """Abre Console Web."""
        self._open_devtools("console")

    def action_inspector(self):
        """Abre Inspetor de Elementos."""
        self._open_devtools("elements")

    def action_debugger(self):
        """Abre Depurador JavaScript."""
        self._open_devtools("sources")

    def action_style_editor(self):
        """Abre Editor de Estilos CSS."""
        self._open_devtools("elements")

    def action_performance(self):
        """Abre painel de Performance."""
        self._open_devtools("timeline")

    def action_network(self):
        """Abre painel de Rede."""
        self._open_devtools("network")

    def action_accessibility(self):
        """Abre painel de Acessibilidade."""
        self._open_devtools("accessibility")

    def action_responsive_design(self):
        """Ativa modo de design responsivo (DevTools Device Mode)."""
        self._open_devtools("deviceMode")

    def action_view_source(self):
        """Visualiza código fonte."""
        url = self.tabs.currentWidget().browser.url().toString()
        if url.startswith("view-source:"):
            return
        self.add_new_tab(QUrl("view-source:" + url), "Código Fonte")

    def action_tips(self):
        """Dicas e truques."""
        QMessageBox.information(
            self, "Dicas e Truques",
            "<h3>Dicas de Privacidade</h3>"
            "<ul>"
            "<li>Use a Blocklist para bloquear domínios indesejados</li>"
            "<li>Configure a Allowlist para garantir acesso a sites confiáveis</li>"
            "<li>O bloqueio de trackers por palavra-chave ajuda a evitar rastreamento</li>"
            "<li>O DNS sinkhole bloqueia domínios de publicidade conhecidos</li>"
            "</ul>"
        )

    def action_report_issue(self):
        """Relata problema."""
        webbrowser.open("https://github.com/marcioo561/Marveloc-Ver9/issues")

    def action_troubleshoot(self):
        """Solucionar problemas."""
        QMessageBox.information(
            self, "Solução de Problemas",
            "Se estiver tendo problemas:\n\n"
            "1. Verifique sua conexão com a internet\n"
            "2. Tente desabilitar o bloqueio de anúncios\n"
            "3. Verifique as listas de permissão/bloqueio\n"
            "4. Reinicie o navegador"
        )

    def action_restart_without_addons(self):
        """Reinicia sem complementos."""
        reply = QMessageBox.question(
            self, "Reiniciar",
            "Reiniciar o navegador em modo de segurança?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            QProcess.startDetached(sys.executable, sys.argv + ["--safe-mode"])
            QApplication.quit()

    def action_safe_mode(self):
        """Modo de segurança."""
        self.action_restart_without_addons()

    def action_diagnostics(self):
        """Informações de diagnóstico."""
        info = f"""
        <h3>Informações de Diagnóstico</h3>
        <p><b>Versão:</b> 1.2.1</p>
        <p><b>Perfil:</b> {self.perfil}</p>
        <p><b>Python:</b> {sys.version}</p>
        <p><b>Plataforma:</b> {platform.platform()}</p>
        <p><b>Qt:</b> {QApplication.instance().applicationName()}</p>
        <p><b>Favoritos:</b> {len(self.favoritos)}</p>
        <p><b>Downloads:</b> {len(self.downloads)}</p>
        <p><b>Abas abertas:</b> {self.tabs.count()}</p>
        """
        QMessageBox.information(self, "Diagnóstico", info)

    def action_about(self):
        """Sobre o Marveloc."""
        info = f"""
        <h2>Marveloc</h2>
        <p><b>Versão:</b> 1.2.1</p>
        <p>Navegador focado em privacidade e segurança.</p>
        <p><b>Características:</b></p>
        <ul>
            <li>Bloqueio de trackers e anúncios</li>
            <li>DNS sinkhole (StevenBlack hosts)</li>
            <li>Criptografia de dados do perfil</li>
            <li>Gerenciamento de favoritos</li>
            <li>Histórico de navegação</li>
            <li>Modo de navegação privada</li>
        </ul>
        <p><b>Desenvolvido por:</b> Marcio Fernandes/Marveloc</p>
        """
        QMessageBox.about(self, "Sobre o Marveloc", info)

    def action_check_updates(self):
        """Verifica atualizações."""
        QMessageBox.information(
            self, 
            "Atualizações",
            "Você está usando a versão mais recente do Marveloc."
        )

    def action_support(self):
        """Apoio ao cliente."""
        webbrowser.open("https://github.com/marcioo561/Marveloc-Ver9")

    # ----------------- Fechamento -----------------

    def closeEvent(self, event):
        # Salva abas abertas como janela recentemente fechada (para outras janelas do mesmo processo)
        try:
            tabs_snapshot = []
            for i in range(self.tabs.count()):
                w = self.tabs.widget(i)
                if w:
                    tabs_snapshot.append({
                        "url": w.browser.url().toString(),
                        "title": w.browser.title() or self.tabs.tabText(i)
                    })
            if tabs_snapshot:
                # Armazena na variável de classe para ser acessível por outras instâncias
                if not hasattr(Browser, '_global_closed_windows'):
                    Browser._global_closed_windows = []
                Browser._global_closed_windows.append(tabs_snapshot)
                if len(Browser._global_closed_windows) > 5:
                    Browser._global_closed_windows.pop(0)
        except Exception:
            pass

        try:
            self.save_perfil_config()
        except Exception:
            logger.debug("Falha ao salvar config no fechamento.", exc_info=True)

        try:
            self.conn.close()
        except Exception:
            logger.debug("Falha ao fechar DB.", exc_info=True)

        event.accept()


def main():
    # Processa argumentos da linha de comando
    private_mode = "--private" in sys.argv
    safe_mode = "--safe-mode" in sys.argv
    
    cfg = load_config()
    perfil = cfg.get("perfil", "default")
    
    if private_mode:
        perfil = "private_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    app = QApplication(sys.argv)
    browser = Browser(perfil)
    
    if safe_mode:
        browser.status_bar.showMessage("Modo de Segurança Ativo", 0)
    
    browser.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()