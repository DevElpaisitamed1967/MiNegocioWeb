"""Conexión a MySQL usando mysql-connector-python."""
from contextlib import contextmanager

import mysql.connector

from app.config import Config


def get_connection(con_base_de_datos: bool = True):
    """Devuelve una conexión nueva a MySQL.

    Con `con_base_de_datos=False` se conecta solo al servidor
    (útil para crear la base de datos la primera vez).
    """
    params = {
        "host": Config.DB_HOST,
        "port": Config.DB_PORT,
        "user": Config.DB_USER,
        "password": Config.DB_PASSWORD,
        "charset": "utf8mb4",
    }
    if con_base_de_datos:
        params["database"] = Config.DB_NAME
    return mysql.connector.connect(**params)


@contextmanager
def cursor(dictionary: bool = True):
    """Context manager transaccional: commit al terminar, rollback si hay error.

    Todo lo ejecutado dentro de un mismo `with` es una sola transacción.
    """
    conn = get_connection()
    cur = conn.cursor(dictionary=dictionary, buffered=True)
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()
