"""Contraseñas: hash Argon2id y política de calidad."""
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

# Argon2id con los parámetros por defecto de argon2-cffi (perfil RFC 9106 reducido).
_ph = PasswordHasher()

# Hash de relleno: se verifica cuando el usuario no existe para que el tiempo de
# respuesta no revele qué correos están registrados.
_HASH_RELLENO = _ph.hash("relleno-para-igualar-tiempos")

LONGITUD_MIN = 12
LONGITUD_MAX = 128

_COMUNES = {
    "123456789012", "password1234", "contraseña123", "qwertyuiop12",
    "administrador", "administrador1", "iloveyou1234", "welcome12345",
    "abcdefghijkl", "1234567890ab", "passw0rd1234", "letmein12345",
}


def hashear(password: str) -> str:
    return _ph.hash(password)


def verificar(hash_guardado: str | None, password: str) -> bool:
    """True solo si la contraseña coincide. Nunca lanza excepciones de hash."""
    if not hash_guardado:
        verificar_relleno(password)
        return False
    try:
        return _ph.verify(hash_guardado, password)
    except (VerificationError, InvalidHashError):
        return False


def verificar_relleno(password: str) -> None:
    try:
        _ph.verify(_HASH_RELLENO, password)
    except (VerificationError, InvalidHashError):
        pass


def necesita_rehash(hash_guardado: str) -> bool:
    return _ph.check_needs_rehash(hash_guardado)


def validar_politica(password: str, email: str = "") -> list[str]:
    """Devuelve la lista de problemas de la contraseña (vacía si es aceptable)."""
    errores = []
    if len(password) < LONGITUD_MIN:
        errores.append(f"La contraseña debe tener al menos {LONGITUD_MIN} caracteres.")
    if len(password) > LONGITUD_MAX:
        errores.append(f"La contraseña no puede superar {LONGITUD_MAX} caracteres.")
    if len(set(password)) < 5:
        errores.append("La contraseña es demasiado repetitiva.")
    bajo = password.lower()
    parte_local = email.split("@")[0].lower() if email else ""
    if parte_local and len(parte_local) >= 4 and parte_local in bajo:
        errores.append("La contraseña no debe contener tu correo.")
    if bajo in _COMUNES:
        errores.append("La contraseña es demasiado común.")
    return errores
