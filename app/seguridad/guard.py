"""Control de acceso: TODO es privado por defecto.

Una ruta solo es accesible sin sesión si su vista está decorada con @publica.
Si alguien añade un controlador nuevo y olvida protegerlo, queda protegido igual.
"""
from flask import abort, current_app, g, jsonify, redirect, request, session, url_for

from app.config import Config
from app.seguridad import sesiones

CSP = (
    "default-src 'self'; script-src 'none'; style-src 'self'; img-src 'self' data:; "
    "base-uri 'none'; frame-ancestors 'none'; "
    "form-action 'self' https://accounts.google.com https://login.microsoftonline.com"
)


def publica(vista):
    """Marca una vista como accesible sin autenticación (login, registro, etc.)."""
    vista._es_publica = True
    return vista


def es_publica(endpoint: str, app=None) -> bool:
    if endpoint == "static":
        return True
    vistas = (app or current_app).view_functions
    return bool(getattr(vistas.get(endpoint), "_es_publica", False))


def exigir_roles(*nombres: str):
    """before_request de blueprint: solo deja pasar a los roles indicados."""
    def _hook():
        if g.get("usuario") is None or g.usuario["rol"] not in nombres:
            abort(403)
    return _hook


def instalar(app) -> None:
    @app.before_request
    def _guardia():
        endpoint = request.endpoint
        if endpoint is None or es_publica(endpoint):
            return None
        if sesiones.cargar():
            return None
        # Sin sesión válida
        if request.accept_mimetypes.best == "application/json":
            return jsonify(error="No autenticado"), 401
        if request.method == "GET":
            session["next"] = request.full_path.rstrip("?")
        return redirect(url_for("auth.login"))

    @app.after_request
    def _cabeceras(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        if not Config.DESARROLLO:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    @app.context_processor
    def _contexto():
        tema = request.cookies.get("tema")
        return {"usuario": g.get("usuario"),
                "tema": tema if tema in ("system", "light", "dark") else "system"}
