"""Utilidades pequeñas compartidas."""
from datetime import datetime, timezone


def utcahora() -> datetime:
    """Fecha/hora actual en UTC, sin zona (formato que se guarda en DATETIME)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
