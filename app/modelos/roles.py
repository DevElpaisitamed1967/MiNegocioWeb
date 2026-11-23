"""Consultas de roles."""
from app.database import cursor


def listar() -> list[dict]:
    with cursor() as cur:
        cur.execute("SELECT id, nombre, requiere_2fa FROM roles ORDER BY id")
        return cur.fetchall()


def obtener(rol_id) -> dict | None:
    if rol_id is None:
        return None
    with cursor() as cur:
        cur.execute("SELECT id, nombre, requiere_2fa FROM roles WHERE id=%s", (rol_id,))
        return cur.fetchone()
