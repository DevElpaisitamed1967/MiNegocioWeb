"""Inicio de sesión con Google y Microsoft (Outlook/Hotmail/cuentas de organización).

Reglas de seguridad:
- Se usa el flujo de código con PKCE, `state` y `nonce` (Authlib).
- Solo se confía en el correo si el proveedor garantiza que está verificado:
    * Google: claim `email_verified`.
    * Microsoft: el claim `email` NO es fiable en tenants ajenos (ataque "nOAuth"), así que
      solo se aceptan cuentas personales y los tenants de MS_TENANTS_PERMITIDOS.
- El usuario elige un rol antes de entrar y debe tenerlo asignado. Si el rol exige 2FA,
  se pide igualmente el segundo factor aunque haya entrado con Google/Microsoft.
"""
from flask import Blueprint, abort, current_app, flash, redirect, request, session, url_for

from app.config import Config
from app.extensions import limiter, oauth
from app.modelos import roles as roles_modelo
from app.modelos import usuarios
from app.seguridad import auditoria, flujo
from app.seguridad.guard import publica

bp = Blueprint("oauth", __name__)

NOMBRES = {"google": "Google", "microsoft": "Outlook / Microsoft"}


def registrar_proveedores() -> None:
    """Registra solo los proveedores que tengan credenciales configuradas."""
    if Config.GOOGLE_CLIENT_ID and Config.GOOGLE_CLIENT_SECRET:
        oauth.register(
            name="google",
            client_id=Config.GOOGLE_CLIENT_ID,
            client_secret=Config.GOOGLE_CLIENT_SECRET,
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile", "code_challenge_method": "S256"},
        )
    if Config.MS_CLIENT_ID and Config.MS_CLIENT_SECRET:
        oauth.register(
            name="microsoft",
            client_id=Config.MS_CLIENT_ID,
            client_secret=Config.MS_CLIENT_SECRET,
            server_metadata_url="https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile", "code_challenge_method": "S256"},
        )


def proveedores_activos() -> list[dict]:
    return [{"id": k, "nombre": v} for k, v in NOMBRES.items() if hasattr(oauth, k)]


def _cliente(proveedor: str):
    if proveedor not in NOMBRES or not hasattr(oauth, proveedor):
        abort(404)
    return getattr(oauth, proveedor)


def _redirigir_login(mensaje: str):
    flash(mensaje, "error")
    return redirect(url_for("auth.login"))


@bp.route("/oauth/<proveedor>", methods=["POST"])
@publica
@limiter.limit("20 per minute")
def iniciar(proveedor):
    cliente = _cliente(proveedor)
    rol = roles_modelo.obtener(request.form.get("rol", type=int))
    if rol is None:
        return _redirigir_login("Selecciona un rol válido.")
    session["oauth_rol"] = rol["id"]
    redirect_uri = Config.URL_BASE.rstrip("/") + url_for("oauth.callback", proveedor=proveedor)
    return cliente.authorize_redirect(redirect_uri)


@bp.route("/oauth/<proveedor>/callback")
@publica
@limiter.limit("20 per minute")
def callback(proveedor):
    cliente = _cliente(proveedor)
    rol_id = session.pop("oauth_rol", None)
    rol = roles_modelo.obtener(rol_id)
    if rol is None:
        return _redirigir_login("La sesión expiró. Inténtalo de nuevo.")

    try:
        if proveedor == "microsoft":
            # El emisor depende del tenant del usuario; se valida a mano más abajo.
            token = cliente.authorize_access_token(claims_options={"iss": {"essential": True}})
        else:
            token = cliente.authorize_access_token()
        claims = token.get("userinfo") or {}
    except Exception:
        current_app.logger.exception("Error en el callback de %s", proveedor)
        auditoria.registrar("oauth", False, None, None, f"{proveedor}: error de autorización")
        return _redirigir_login("No se pudo completar el inicio de sesión con " + NOMBRES[proveedor] + ".")

    sujeto, email = claims.get("sub"), (claims.get("email") or "").strip().lower()
    if not sujeto or not email or not _correo_verificado(proveedor, claims):
        auditoria.registrar("oauth", False, None, email or None, f"{proveedor}: correo no verificado/permitido")
        return _redirigir_login("Esa cuenta no es válida para ingresar. Usa otra o regístrate con correo.")

    usuario = _resolver_usuario(proveedor, sujeto, email, claims.get("name") or "")
    if usuario is None or not usuario["activo"] or usuarios.esta_bloqueado(usuario) \
            or not usuarios.tiene_rol(usuario["id"], rol["id"]):
        auditoria.registrar("oauth", False, usuario["id"] if usuario else None, email,
                            f"{proveedor}: rol {rol['nombre']} no permitido o cuenta inactiva")
        return _redirigir_login("Credenciales o rol incorrectos.")

    return flujo.continuar_tras_credenciales(usuario, rol, proveedor)


def _correo_verificado(proveedor: str, claims: dict) -> bool:
    if proveedor == "google":
        return claims.get("email_verified") is True
    if proveedor == "microsoft":
        tid = claims.get("tid")
        return bool(
            tid in Config.MS_TENANTS_PERMITIDOS
            and claims.get("iss") == f"https://login.microsoftonline.com/{tid}/v2.0"
        )
    return False


def _resolver_usuario(proveedor: str, sujeto: str, email: str, nombre: str):
    identidad = usuarios.buscar_identidad(proveedor, sujeto)
    if identidad:
        return usuarios.obtener(identidad["usuario_id"])

    usuario = usuarios.obtener_por_email(email)
    if usuario:
        if not usuario["email_verificado"]:
            # El proveedor acaba de demostrar que el correo es de quien entra: se verifica
            # y se descarta la contraseña que pudo fijar quien registró ese correo antes.
            usuarios.marcar_email_verificado(usuario["id"], anular_password=True)
    else:
        uid = usuarios.crear(nombre.strip()[:100] or email.split("@")[0], email, None,
                             email_verificado=True)
        usuario = usuarios.obtener(uid) if uid else usuarios.obtener_por_email(email)
    if usuario is None:
        return None
    usuarios.crear_identidad(usuario["id"], proveedor, sujeto, email)
    return usuarios.obtener(usuario["id"])
