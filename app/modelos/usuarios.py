"""Consultas de usuarios, 2FA e identidades externas."""
from datetime import timedelta

import mysql.connector

from app.config import Config
from app.database import cursor
from app.util import utcahora


# --- Lectura -----------------------------------------------------------------

def obtener(usuario_id: int) -> dict | None:
    with cursor() as cur:
        cur.execute("SELECT * FROM usuarios WHERE id=%s", (usuario_id,))
        return cur.fetchone()


def obtener_por_email(email: str) -> dict | None:
    with cursor() as cur:
        cur.execute("SELECT * FROM usuarios WHERE email=%s", (email,))
        return cur.fetchone()


def tiene_rol(usuario_id: int, rol_id: int) -> bool:
    with cursor() as cur:
        cur.execute("SELECT 1 FROM usuario_roles WHERE usuario_id=%s AND rol_id=%s",
                    (usuario_id, rol_id))
        return cur.fetchone() is not None


def esta_bloqueado(usuario: dict) -> bool:
    return bool(usuario["bloqueado_hasta"] and usuario["bloqueado_hasta"] > utcahora())


# --- Alta y estado ---------------------------------------------------------

def crear(nombre: str, email: str, password_hash: str | None,
          email_verificado: bool = False, rol: str = "Consultor") -> int | None:
    """Crea un usuario con un rol. Devuelve su id, o None si el correo ya existe."""
    try:
        with cursor() as cur:
            cur.execute(
                "INSERT INTO usuarios (nombre, email, password_hash, email_verificado) "
                "VALUES (%s,%s,%s,%s)",
                (nombre, email, password_hash, int(email_verificado)),
            )
            uid = cur.lastrowid
            cur.execute("INSERT INTO usuario_roles (usuario_id, rol_id) "
                        "SELECT %s, id FROM roles WHERE nombre=%s", (uid, rol))
        return uid
    except mysql.connector.IntegrityError:
        return None


def marcar_email_verificado(usuario_id: int, anular_password: bool = False) -> None:
    """Con anular_password se descarta la contraseña previa (evita 'pre-hijacking':
    alguien registra el correo de otra persona y luego esa persona entra con Google)."""
    with cursor() as cur:
        if anular_password:
            cur.execute("UPDATE usuarios SET email_verificado=1, password_hash=NULL WHERE id=%s",
                        (usuario_id,))
        else:
            cur.execute("UPDATE usuarios SET email_verificado=1 WHERE id=%s", (usuario_id,))


def actualizar_hash(usuario_id: int, nuevo_hash: str) -> None:
    with cursor() as cur:
        cur.execute("UPDATE usuarios SET password_hash=%s WHERE id=%s", (nuevo_hash, usuario_id))


def cambiar_password(usuario_id: int, nuevo_hash: str) -> None:
    """Fija la nueva contraseña. Haber recibido el enlace prueba que el correo es suyo,
    así que se marca verificado; también se levanta cualquier bloqueo por intentos."""
    with cursor() as cur:
        cur.execute("UPDATE usuarios SET password_hash=%s, email_verificado=1, "
                    "intentos_fallidos=0, bloqueado_hasta=NULL WHERE id=%s",
                    (nuevo_hash, usuario_id))


def registrar_login(usuario_id: int) -> None:
    with cursor() as cur:
        cur.execute("UPDATE usuarios SET ultimo_login=%s WHERE id=%s", (utcahora(), usuario_id))


# --- Bloqueo por intentos fallidos ---------------------------------------------

def registrar_fallo(usuario_id: int) -> bool:
    """Suma un intento fallido; devuelve True si la cuenta queda bloqueada."""
    with cursor() as cur:
        cur.execute("UPDATE usuarios SET intentos_fallidos = intentos_fallidos + 1 WHERE id=%s",
                    (usuario_id,))
        cur.execute("SELECT intentos_fallidos FROM usuarios WHERE id=%s", (usuario_id,))
        if cur.fetchone()["intentos_fallidos"] >= Config.MAX_INTENTOS:
            cur.execute("UPDATE usuarios SET bloqueado_hasta=%s, intentos_fallidos=0 WHERE id=%s",
                        (utcahora() + timedelta(minutes=Config.BLOQUEO_MIN), usuario_id))
            return True
    return False


def limpiar_fallos(usuario_id: int) -> None:
    with cursor() as cur:
        cur.execute("UPDATE usuarios SET intentos_fallidos=0, bloqueado_hasta=NULL WHERE id=%s",
                    (usuario_id,))


# --- Segundo factor ------------------------------------------------------------

def guardar_secreto_totp(usuario_id: int, secreto_cifrado: bytes) -> None:
    with cursor() as cur:
        cur.execute("UPDATE usuarios SET totp_secreto_cifrado=%s, totp_confirmado=0, "
                    "totp_ultimo_paso=NULL WHERE id=%s AND totp_confirmado=0",
                    (secreto_cifrado, usuario_id))


def confirmar_totp(usuario_id: int, paso: int) -> bool:
    with cursor() as cur:
        cur.execute("UPDATE usuarios SET totp_confirmado=1, totp_ultimo_paso=%s "
                    "WHERE id=%s AND totp_confirmado=0", (paso, usuario_id))
        return cur.rowcount == 1


def consumir_paso_totp(usuario_id: int, paso: int) -> bool:
    """Registra el paso usado de forma atómica; False si ya se había usado (replay)."""
    with cursor() as cur:
        cur.execute("UPDATE usuarios SET totp_ultimo_paso=%s "
                    "WHERE id=%s AND (totp_ultimo_paso IS NULL OR totp_ultimo_paso < %s)",
                    (paso, usuario_id, paso))
        return cur.rowcount == 1


def guardar_codigos_respaldo(usuario_id: int, hashes: list[str]) -> None:
    with cursor() as cur:
        cur.execute("DELETE FROM codigos_respaldo WHERE usuario_id=%s", (usuario_id,))
        cur.executemany("INSERT INTO codigos_respaldo (usuario_id, codigo_hash) VALUES (%s,%s)",
                        [(usuario_id, h) for h in hashes])


def contar_codigos_respaldo(usuario_id: int) -> int:
    with cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM codigos_respaldo WHERE usuario_id=%s AND usado_en IS NULL",
                    (usuario_id,))
        return int(cur.fetchone()["n"])


def consumir_codigo_respaldo(usuario_id: int, codigo_hash: str) -> bool:
    with cursor() as cur:
        cur.execute("UPDATE codigos_respaldo SET usado_en=%s "
                    "WHERE usuario_id=%s AND codigo_hash=%s AND usado_en IS NULL LIMIT 1",
                    (utcahora(), usuario_id, codigo_hash))
        return cur.rowcount == 1


# --- Identidades externas (OAuth) ----------------------------------------------

def buscar_identidad(proveedor: str, sujeto: str) -> dict | None:
    with cursor() as cur:
        cur.execute("SELECT * FROM identidades_oauth WHERE proveedor=%s AND sujeto=%s",
                    (proveedor, sujeto))
        return cur.fetchone()


def crear_identidad(usuario_id: int, proveedor: str, sujeto: str, email: str) -> None:
    with cursor() as cur:
        cur.execute("INSERT IGNORE INTO identidades_oauth (usuario_id, proveedor, sujeto, email) "
                    "VALUES (%s,%s,%s,%s)", (usuario_id, proveedor, sujeto, email))


# --- Administración ----------------------------------------------------------

def listar_con_roles() -> list[dict]:
    with cursor() as cur:
        cur.execute(
            "SELECT u.id, u.nombre, u.email, u.activo, u.email_verificado, u.totp_confirmado, "
            "       GROUP_CONCAT(ur.rol_id) AS rol_ids "
            "FROM usuarios u LEFT JOIN usuario_roles ur ON ur.usuario_id = u.id "
            "GROUP BY u.id ORDER BY u.id"
        )
        filas = cur.fetchall()
    for f in filas:
        f["rol_ids"] = {int(x) for x in (f["rol_ids"] or "").split(",") if x}
    return filas


def establecer_roles(usuario_id: int, rol_ids: set[int]) -> None:
    with cursor() as cur:
        cur.execute("DELETE FROM usuario_roles WHERE usuario_id=%s", (usuario_id,))
        if rol_ids:
            cur.executemany("INSERT INTO usuario_roles (usuario_id, rol_id) VALUES (%s,%s)",
                            [(usuario_id, r) for r in rol_ids])
