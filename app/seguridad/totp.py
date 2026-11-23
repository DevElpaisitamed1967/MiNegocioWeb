"""Segundo factor (TOTP, RFC 6238): secretos cifrados, verificación y códigos de respaldo."""
import hashlib
import hmac
import io
import secrets
import time

import pyotp
import qrcode
from cryptography.fernet import Fernet
from qrcode.image.svg import SvgPathImage

from app.config import Config

PASO_SEG = 30
EMISOR = "MiNegocioWeb"
_ALFABETO = "abcdefghjkmnpqrstuvwxyz23456789"  # sin caracteres ambiguos (i, l, o, 0, 1)


def _fernet() -> Fernet:
    return Fernet(Config.TOTP_CLAVE_CIFRADO.encode())


def generar_secreto() -> str:
    return pyotp.random_base32()  # 160 bits


def cifrar(secreto: str) -> bytes:
    """El secreto TOTP nunca se guarda en claro en la base de datos."""
    return _fernet().encrypt(secreto.encode())


def descifrar(cifrado) -> str:
    return _fernet().decrypt(bytes(cifrado)).decode()


def uri_aprovisionamiento(secreto: str, email: str) -> str:
    return pyotp.TOTP(secreto).provisioning_uri(name=email, issuer_name=EMISOR)


def qr_svg(texto: str) -> str:
    """Código QR como SVG en línea (sin servicios externos ni JavaScript)."""
    imagen = qrcode.make(texto, image_factory=SvgPathImage, box_size=8, border=2)
    buf = io.BytesIO()
    imagen.save(buf)
    svg = buf.getvalue().decode()
    return svg[svg.index("<svg"):]  # quita la declaración <?xml ...?>


def verificar(secreto: str, codigo: str, ultimo_paso: int | None) -> int | None:
    """Valida un código de 6 dígitos con tolerancia de ±1 intervalo.

    Devuelve el número de paso aceptado o None. Rechaza pasos ya usados
    (`ultimo_paso`) para impedir la reutilización de un mismo código.
    """
    if len(codigo) != 6 or not codigo.isdigit():
        return None
    totp = pyotp.TOTP(secreto)
    actual = int(time.time() // PASO_SEG)
    for paso in (actual - 1, actual, actual + 1):
        if ultimo_paso is not None and paso <= ultimo_paso:
            continue
        if hmac.compare_digest(totp.at(paso * PASO_SEG), codigo):
            return paso
    return None


# --- Códigos de respaldo -----------------------------------------------------

def generar_codigos_respaldo(cantidad: int = 10) -> list[str]:
    def uno():
        return "".join(secrets.choice(_ALFABETO) for _ in range(5)) + "-" + \
               "".join(secrets.choice(_ALFABETO) for _ in range(5))
    return [uno() for _ in range(cantidad)]


def normalizar_codigo(codigo: str) -> str:
    return codigo.replace("-", "").replace(" ", "").strip().lower()


def hash_codigo(codigo: str) -> str:
    return hashlib.sha256(normalizar_codigo(codigo).encode()).hexdigest()
