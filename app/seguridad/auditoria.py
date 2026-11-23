"""Bitácora de eventos de autenticación (nunca debe romper el flujo principal)."""
from flask import current_app, request

from app.database import cursor


def registrar(evento: str, exito: bool, usuario_id: int | None = None,
              email: str | None = None, detalle: str | None = None) -> None:
    try:
        with cursor() as cur:
            cur.execute(
                "INSERT INTO auditoria_auth (usuario_id, email, evento, exito, ip, detalle) "
                "VALUES (%s,%s,%s,%s,%s,%s)",
                (usuario_id, (email or None) and email[:254], evento, int(exito),
                 request.remote_addr, (detalle or None) and detalle[:255]),
            )
    except Exception:
        current_app.logger.exception("No se pudo registrar el evento de auditoría %s", evento)
