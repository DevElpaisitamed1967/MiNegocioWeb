"""Flujo de inicio de sesión: pasos intermedios (2FA) y apertura de la sesión final."""
import time
from urllib.parse import urlsplit

from flask import redirect, session, url_for

from app.modelos import usuarios
from app.seguridad import auditoria, sesiones

PRE2FA_VIDA_SEG = 600  # tiempo máximo entre contraseña/OAuth y el segundo factor


def destino_seguro(valor) -> str:
    """Solo permite redirecciones internas (evita open redirect)."""
    por_defecto = url_for("panel.panel")
    if not valor or not isinstance(valor, str):
        return por_defecto
    partes = urlsplit(valor)
    if (partes.scheme or partes.netloc or not valor.startswith("/")
            or valor.startswith("//") or "\\" in valor):
        return por_defecto
    return valor


def iniciar_pre2fa(usuario_id: int, rol_id: int, metodo: str) -> None:
    """Guarda el estado 'credenciales correctas, falta el segundo factor'.

    Este estado NO da acceso a nada: el guard solo reconoce sesiones del servidor.
    """
    session.pop("pre2fa", None)
    session["pre2fa"] = {"uid": usuario_id, "rid": rol_id, "metodo": metodo,
                         "ts": int(time.time()), "codigo_enviado": False}


def pre2fa_actual() -> dict | None:
    pre = session.get("pre2fa")
    if not isinstance(pre, dict) or int(time.time()) - pre.get("ts", 0) > PRE2FA_VIDA_SEG:
        session.pop("pre2fa", None)
        return None
    return pre


def abrir_sesion(usuario: dict, rol: dict, metodo: str) -> str:
    """Crea la sesión definitiva y devuelve la URL de destino."""
    destino = destino_seguro(session.get("next"))
    sesiones.crear(usuario["id"], rol["id"])
    usuarios.limpiar_fallos(usuario["id"])
    usuarios.registrar_login(usuario["id"])
    auditoria.registrar("login", True, usuario["id"], usuario["email"],
                        f"rol={rol['nombre']};metodo={metodo}")
    return destino


def continuar_tras_credenciales(usuario: dict, rol: dict, metodo: str):
    """Decide el siguiente paso una vez validada la contraseña o la identidad OAuth."""
    if rol["requiere_2fa"]:
        iniciar_pre2fa(usuario["id"], rol["id"], metodo)
        if usuario["totp_confirmado"]:
            return redirect(url_for("auth.verificar_2fa"))
        return redirect(url_for("auth.configurar_2fa"))
    return redirect(abrir_sesion(usuario, rol, metodo))
