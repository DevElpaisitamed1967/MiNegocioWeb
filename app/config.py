"""Configuración de la aplicación, leída desde variables de entorno / archivo .env."""
import os

from dotenv import load_dotenv

# override=True: el .env del proyecto manda sobre variables de Windows con el mismo nombre (p. ej. DB_USER).
load_dotenv(override=True)

# Tenant de Microsoft para cuentas personales (Outlook.com, Hotmail, Live)
MS_TENANT_PERSONAL = "9188040d-6c67-4c5b-b112-36a304b66dad"


def _lista(nombre: str, defecto: str = "") -> list[str]:
    return [x.strip() for x in os.getenv(nombre, defecto).split(",") if x.strip()]


class Config:
    # --- Entorno -----------------------------------------------------------
    # "desarrollo" desactiva cookies Secure/HSTS y permite imprimir correos en consola.
    ENTORNO = os.getenv("ENTORNO", "produccion")
    DESARROLLO = ENTORNO == "desarrollo"
    URL_BASE = os.getenv("URL_BASE", "http://localhost:5000")
    CONFIAR_PROXY = os.getenv("CONFIAR_PROXY", "0") == "1"

    # --- Base de datos -----------------------------------------------------
    DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
    DB_PORT = int(os.getenv("DB_PORT", "3306"))
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_NAME = os.getenv("DB_NAME", "minegocioweb")

    # --- Secretos (obligatorios, la app no arranca sin ellos) ----------------
    SECRET_KEY = os.getenv("SECRET_KEY")
    TOTP_CLAVE_CIFRADO = os.getenv("TOTP_CLAVE_CIFRADO")  # clave Fernet

    # --- Sesión y bloqueo ----------------------------------------------------
    SESION_INACTIVIDAD_MIN = int(os.getenv("SESION_INACTIVIDAD_MIN", "30"))
    SESION_MAXIMA_MIN = int(os.getenv("SESION_MAXIMA_MIN", "480"))
    MAX_INTENTOS = int(os.getenv("MAX_INTENTOS", "5"))
    BLOQUEO_MIN = int(os.getenv("BLOQUEO_MIN", "15"))
    LIMITER_STORAGE = os.getenv("LIMITER_STORAGE", "memory://")

    # --- Correo (SMTP) -------------------------------------------------------
    SMTP_HOST = os.getenv("SMTP_HOST")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USUARIO = os.getenv("SMTP_USUARIO")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
    SMTP_REMITENTE = os.getenv("SMTP_REMITENTE", "no-responder@localhost")

    # --- OAuth ---------------------------------------------------------------
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
    MS_CLIENT_ID = os.getenv("MS_CLIENT_ID")
    MS_CLIENT_SECRET = os.getenv("MS_CLIENT_SECRET")
    # Tenants de Microsoft aceptados: cuentas personales + los de tu organización.
    MS_TENANTS_PERMITIDOS = _lista("MS_TENANTS_PERMITIDOS", MS_TENANT_PERSONAL)
