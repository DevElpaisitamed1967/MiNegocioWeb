"""Crea la base de datos y las tablas ejecutando sql/schema.sql.

Uso:
    python init_db.py
"""
from pathlib import Path

from app.config import Config
from app.database import get_connection

SCHEMA = Path(__file__).parent / "sql" / "schema.sql"


def _sentencias(sql: str):
    """Divide el script en sentencias (el esquema no usa ';' dentro de textos)."""
    limpio = "\n".join(
        linea for linea in sql.splitlines() if not linea.strip().startswith("--")
    )
    return [s.strip() for s in limpio.split(";") if s.strip()]


def main() -> None:
    conn = get_connection(con_base_de_datos=False)
    cur = conn.cursor()
    try:
        for sentencia in _sentencias(SCHEMA.read_text(encoding="utf-8")):
            cur.execute(sentencia)
        conn.commit()
        print(f"Base de datos '{Config.DB_NAME}' creada/actualizada correctamente.")
    finally:
        cur.close()
        conn.close()


if __name__ == "__main__":
    main()
