"""Sesiones en el servidor.

La cookie solo contiene un identificador aleatorio (256 bits) dentro de la cookie
firmada de Flask; en la base de datos se guarda su hash SHA-256. Así una sesión se
puede revocar (cierre de sesión, cambio de roles) y un volcado de la tabla no
permite suplantar a nadie.
"""
import hashlib
import secrets
from datetime import timedelta

from flask import g, request, session

from app.config import Config
from app.database import cursor
from app.util import utcahora


def _hash(sid: str) -> str:
    return hashlib.sha256(sid.encode()).hexdigest()


def crear(usuario_id: int, rol_id: int) -> None:
    """Abre una sesión nueva. Descarta todo lo previo de la cookie (anti fijación)."""
    sid = secrets.token_urlsafe(32)
    ahora = utcahora()
    with cursor() as cur:
        cur.execute(
            "INSERT INTO sesiones (id, usuario_id, rol_id, creado_en, ultimo_acceso, expira_en, ip, user_agent) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (_hash(sid), usuario_id, rol_id, ahora, ahora,
             ahora + timedelta(minutes=Config.SESION_MAXIMA_MIN),
             request.remote_addr, (request.user_agent.string or "")[:255]),
        )
    session.clear()
    session.permanent = True
    session["sid"] = sid


def cargar() -> bool:
    """Rellena `g.usuario` si la cookie corresponde a una sesión vigente."""
    if getattr(g, "_sesion_cargada", False):
        return g.usuario is not None
    g._sesion_cargada = True
    g.usuario = None

    sid = session.get("sid")
    if not sid or not isinstance(sid, str):
        return False

    ahora = utcahora()
    with cursor() as cur:
        cur.execute(
            "SELECT s.ultimo_acceso, s.expira_en, s.revocada, u.id, u.nombre, u.email, u.activo, "
            "       r.id AS rol_id, r.nombre AS rol, r.requiere_2fa "
            "FROM sesiones s "
            "JOIN usuarios u ON u.id = s.usuario_id "
            "JOIN roles r ON r.id = s.rol_id "
            "JOIN usuario_roles ur ON ur.usuario_id = s.usuario_id AND ur.rol_id = s.rol_id "
            "WHERE s.id = %s",
            (_hash(sid),),
        )
        fila = cur.fetchone()
        vigente = (
            fila is not None
            and not fila["revocada"]
            and fila["activo"]
            and fila["expira_en"] > ahora
            and fila["ultimo_acceso"] > ahora - timedelta(minutes=Config.SESION_INACTIVIDAD_MIN)
        )
        if vigente:
            if fila["ultimo_acceso"] < ahora - timedelta(seconds=60):
                cur.execute("UPDATE sesiones SET ultimo_acceso=%s WHERE id=%s", (ahora, _hash(sid)))
            g.usuario = {
                "id": fila["id"], "nombre": fila["nombre"], "email": fila["email"],
                "rol_id": fila["rol_id"], "rol": fila["rol"],
                "requiere_2fa": bool(fila["requiere_2fa"]),
            }
            return True

    session.clear()
    return False


def cerrar() -> None:
    sid = session.get("sid")
    if isinstance(sid, str):
        with cursor() as cur:
            cur.execute("UPDATE sesiones SET revocada=1 WHERE id=%s", (_hash(sid),))
    session.clear()


def revocar_todas(usuario_id: int) -> None:
    with cursor() as cur:
        cur.execute("UPDATE sesiones SET revocada=1 WHERE usuario_id=%s AND revocada=0", (usuario_id,))


def revocar_otras(usuario_id: int) -> None:
    """Cierra todas las sesiones del usuario excepto la actual (p. ej. tras cambiar la clave)."""
    sid = session.get("sid")
    actual = _hash(sid) if isinstance(sid, str) else ""
    with cursor() as cur:
        cur.execute("UPDATE sesiones SET revocada=1 WHERE usuario_id=%s AND revocada=0 AND id<>%s",
                    (usuario_id, actual))
