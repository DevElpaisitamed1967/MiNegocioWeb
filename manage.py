"""Comandos de administración.

    python manage.py crear-admin correo@dominio.com "Nombre Apellido"
    python manage.py asignar-rol correo@dominio.com Asistente
    python manage.py generar-claves        (imprime SECRET_KEY y TOTP_CLAVE_CIFRADO para el .env)
"""
import argparse
import getpass
import secrets
import sys


def generar_claves(args) -> int:
    """No necesita base de datos ni .env: solo imprime dos secretos nuevos."""
    from cryptography.fernet import Fernet
    print(f"SECRET_KEY={secrets.token_hex(32)}")
    print(f"TOTP_CLAVE_CIFRADO={Fernet.generate_key().decode()}")
    print("\nCópialas en tu .env. Si cambias TOTP_CLAVE_CIFRADO, los 2FA ya configurados dejan de funcionar.")
    return 0


def crear_admin(args) -> int:
    from app.modelos import usuarios
    from app.seguridad import passwords
    email = args.email.strip().lower()
    password = getpass.getpass("Contraseña: ")
    if password != getpass.getpass("Repite la contraseña: "):
        print("Las contraseñas no coinciden.")
        return 1
    errores = passwords.validar_politica(password, email)
    if errores:
        print("\n".join(errores))
        return 1
    uid = usuarios.crear(args.nombre, email, passwords.hashear(password),
                         email_verificado=True, rol="Administrador")
    if uid is None:
        print("Ese correo ya está registrado.")
        return 1
    print(f"Administrador creado (id {uid}). Al iniciar sesión se le pedirá configurar el 2FA.")
    return 0


def asignar_rol(args) -> int:
    from app.database import cursor
    from app.modelos import usuarios
    usuario = usuarios.obtener_por_email(args.email.strip().lower())
    if usuario is None:
        print("No existe ese usuario.")
        return 1
    with cursor() as cur:
        cur.execute("INSERT IGNORE INTO usuario_roles (usuario_id, rol_id) "
                    "SELECT %s, id FROM roles WHERE nombre=%s", (usuario["id"], args.rol))
        if cur.rowcount == 0:
            cur.execute("SELECT 1 FROM roles WHERE nombre=%s", (args.rol,))
            if cur.fetchone() is None:
                print("Rol inexistente. Opciones: Administrador, Asistente, Colaborador, Consultor.")
                return 1
    print("Rol asignado.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = parser.add_subparsers(dest="comando", required=True)
    a = sub.add_parser("crear-admin")
    a.add_argument("email")
    a.add_argument("nombre")
    a.set_defaults(func=crear_admin)
    r = sub.add_parser("asignar-rol")
    r.add_argument("email")
    r.add_argument("rol")
    r.set_defaults(func=asignar_rol)
    g = sub.add_parser("generar-claves")
    g.set_defaults(func=generar_claves)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
