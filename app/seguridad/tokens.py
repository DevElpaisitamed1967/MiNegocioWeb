"""Enlaces y códigos de un solo uso. En la base de datos solo se guarda su hash."""
import hashlib
import secrets
from datetime import timedelta

from app.database import cursor
from app.util import utcahora


def _hash(valor: str) -> str:
    return hashlib.sha256(valor.encode()).hexdigest()


def crear_enlace(usuario_id: int, tipo: str, minutos: int) -> str:
    """Genera un token aleatorio de 256 bits (se envía por correo, no se guarda)."""
    token = secrets.token_urlsafe(32)
    _insertar(usuario_id, _hash(token), tipo, minutos)
    return token


def consumir_enlace(token: str, tipo: str) -> int | None:
    """Marca el token como usado y devuelve el usuario, o None si no es válido."""
    h = _hash(token)
    ahora = utcahora()
    with cursor() as cur:
        cur.execute(
            "UPDATE tokens_email SET usado_en=%s "
            "WHERE token_hash=%s AND tipo=%s AND usado_en IS NULL AND expira_en>%s",
            (ahora, h, tipo, ahora),
        )
        if cur.rowcount < 1:
            return None
        cur.execute("SELECT usuario_id FROM tokens_email WHERE token_hash=%s AND tipo=%s",
                    (h, tipo))
        fila = cur.fetchone()
    return fila["usuario_id"] if fila else None


def usuario_de_enlace(token: str, tipo: str) -> int | None:
    """Usuario al que pertenece un enlace vigente, SIN consumirlo (para mostrar el formulario)."""
    with cursor() as cur:
        cur.execute(
            "SELECT usuario_id FROM tokens_email "
            "WHERE token_hash=%s AND tipo=%s AND usado_en IS NULL AND expira_en>%s",
            (_hash(token), tipo, utcahora()),
        )
        fila = cur.fetchone()
    return fila["usuario_id"] if fila else None


def hay_enlace_reciente(usuario_id: int, tipo: str, vida_min: int, espera_min: int) -> bool:
    """True si ya se emitió un enlace sin usar hace menos de `espera_min` minutos (anti spam)."""
    limite = utcahora() + timedelta(minutes=vida_min - espera_min)
    with cursor() as cur:
        cur.execute(
            "SELECT 1 FROM tokens_email "
            "WHERE usuario_id=%s AND tipo=%s AND usado_en IS NULL AND expira_en>%s LIMIT 1",
            (usuario_id, tipo, limite),
        )
        return cur.fetchone() is not None


def invalidar_pendientes(usuario_id: int, tipo: str) -> None:
    with cursor() as cur:
        cur.execute(
            "UPDATE tokens_email SET usado_en=%s WHERE usuario_id=%s AND tipo=%s AND usado_en IS NULL",
            (utcahora(), usuario_id, tipo),
        )


def crear_codigo(usuario_id: int, tipo: str, minutos: int) -> str:
    """Código numérico de 6 dígitos; invalida los anteriores del mismo tipo."""
    with cursor() as cur:
        cur.execute(
            "UPDATE tokens_email SET usado_en=%s WHERE usuario_id=%s AND tipo=%s AND usado_en IS NULL",
            (utcahora(), usuario_id, tipo),
        )
    codigo = f"{secrets.randbelow(10**6):06d}"
    _insertar(usuario_id, _hash(f"{usuario_id}:{codigo}"), tipo, minutos)
    return codigo


def consumir_codigo(usuario_id: int, tipo: str, codigo: str) -> bool:
    ahora = utcahora()
    with cursor() as cur:
        cur.execute(
            "UPDATE tokens_email SET usado_en=%s "
            "WHERE usuario_id=%s AND token_hash=%s AND tipo=%s AND usado_en IS NULL AND expira_en>%s",
            (ahora, usuario_id, _hash(f"{usuario_id}:{codigo}"), tipo, ahora),
        )
        return cur.rowcount >= 1


def _insertar(usuario_id: int, token_hash: str, tipo: str, minutos: int) -> None:
    with cursor() as cur:
        cur.execute(
            "INSERT INTO tokens_email (usuario_id, token_hash, tipo, expira_en) VALUES (%s,%s,%s,%s)",
            (usuario_id, token_hash, tipo, utcahora() + timedelta(minutes=minutos)),
        )
