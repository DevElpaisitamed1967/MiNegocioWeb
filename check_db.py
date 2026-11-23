"""Verifica la conexión y lista las tablas creadas.

Uso:
    python check_db.py
"""
from app.database import cursor


def main() -> None:
    with cursor(dictionary=False) as cur:
        cur.execute("SELECT VERSION()")
        print("MySQL versión:", cur.fetchone()[0])
        cur.execute("SHOW TABLES")
        print("Tablas:")
        for (tabla,) in cur.fetchall():
            print(" -", tabla)


if __name__ == "__main__":
    main()
