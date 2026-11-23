"""Fábrica de la aplicación Flask."""
from datetime import timedelta

from flask import Flask, flash, redirect, render_template, url_for
from flask_wtf.csrf import CSRFError
from werkzeug.middleware.proxy_fix import ProxyFix

from app.config import Config
from app.extensions import csrf, limiter, oauth


def create_app() -> Flask:
    # La aplicación se niega a arrancar si faltan los secretos o la configuración es insegura.
    if not Config.SECRET_KEY or len(Config.SECRET_KEY) < 32:
        raise RuntimeError("Define SECRET_KEY (mínimo 32 caracteres) en el archivo .env")
    if not Config.TOTP_CLAVE_CIFRADO:
        raise RuntimeError("Define TOTP_CLAVE_CIFRADO (clave Fernet) en el archivo .env")
    if not Config.DESARROLLO and not Config.SMTP_HOST:
        raise RuntimeError("Configura SMTP_HOST: en producción los correos deben enviarse de verdad")

    app = Flask(__name__)
    app.config.from_object(Config)
    seguro = not Config.DESARROLLO
    app.config.update(
        SESSION_COOKIE_NAME="__Host-sesion" if seguro else "sesion",
        SESSION_COOKIE_SECURE=seguro,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",  # Lax (no Strict) para que funcione el retorno de OAuth
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=Config.SESION_MAXIMA_MIN),
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    if Config.CONFIAR_PROXY:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    csrf.init_app(app)
    limiter.init_app(app)
    oauth.init_app(app)

    from app.controladores import admin, auth, cuenta, panel, tema
    from app.controladores import oauth as oauth_ctrl
    from app.seguridad import guard

    oauth_ctrl.registrar_proveedores()
    guard.instalar(app)
    for modulo in (auth, oauth_ctrl, panel, cuenta, admin, tema):
        app.register_blueprint(modulo.bp)

    @app.errorhandler(CSRFError)
    def _csrf(e):
        # Formulario abierto demasiado tiempo (el token vence a la hora) o petición ajena.
        flash("La página caducó. Inténtalo de nuevo.", "error")
        return redirect(url_for("panel.panel"))  # si no hay sesión, el guard lleva al login

    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(429)
    def _error(e):
        mensajes = {403: "No tienes permiso para ver esta página.",
                    404: "La página no existe.",
                    429: "Demasiados intentos. Espera un momento e inténtalo de nuevo."}
        return render_template("error.html", codigo=e.code, mensaje=mensajes[e.code]), e.code

    return app
