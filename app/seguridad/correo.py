"""Envío de correo por SMTP (STARTTLS). En desarrollo sin SMTP, se imprime en consola."""
import smtplib
import ssl
import threading
from email.message import EmailMessage

from flask import current_app

from app.config import Config


def enviar(destino: str, asunto: str, cuerpo: str) -> None:
    if not Config.SMTP_HOST:
        # create_app() impide llegar aquí fuera del entorno de desarrollo.
        current_app.logger.warning("[CORREO-DEV] Para: %s | %s\n%s", destino, asunto, cuerpo)
        return

    msg = EmailMessage()
    msg["From"] = Config.SMTP_REMITENTE
    msg["To"] = destino
    msg["Subject"] = asunto
    msg.set_content(cuerpo)
    try:
        with smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT, timeout=10) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            if Config.SMTP_USUARIO:
                smtp.login(Config.SMTP_USUARIO, Config.SMTP_PASSWORD or "")
            smtp.send_message(msg)
    except Exception:  # no filtrar detalles del servidor al usuario
        current_app.logger.exception("No se pudo enviar el correo a %s", destino)


def enviar_async(destino: str, asunto: str, cuerpo: str) -> None:
    """Envía en segundo plano. Así la respuesta HTTP tarda igual exista o no el correo
    (si no, el tiempo de respuesta delataría qué cuentas están registradas)."""
    app = current_app._get_current_object()

    def _tarea():
        with app.app_context():
            enviar(destino, asunto, cuerpo)

    threading.Thread(target=_tarea, daemon=True).start()
