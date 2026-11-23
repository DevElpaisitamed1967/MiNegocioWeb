"""Mi cuenta: cambiar la contraseña y regenerar los códigos de respaldo del 2FA.

Sin @publica: el guard global exige sesión. Cada acción vuelve a pedir una prueba
(contraseña actual o código TOTP) para que una sesión abierta y desatendida no baste.
"""
from flask import Blueprint, flash, g, redirect, render_template, url_for

from app.extensions import limiter
from app.modelos import usuarios
from app.seguridad import auditoria, correo, passwords, sesiones, totp
from flask import request

bp = Blueprint("cuenta", __name__, url_prefix="/cuenta")


def _vista(codigos=None):
    u = usuarios.obtener(g.usuario["id"])
    return render_template(
        "cuenta.html", u=u, codigos=codigos,
        tiene_clave=bool(u["password_hash"]),
        restantes=usuarios.contar_codigos_respaldo(u["id"]) if u["totp_confirmado"] else 0,
    )


def _prueba_fallida(u, evento: str, motivo: str):
    """Cuenta el fallo para el bloqueo; si se llega al límite, cierra la sesión."""
    bloqueada = usuarios.registrar_fallo(u["id"])
    auditoria.registrar(evento, False, u["id"], u["email"], motivo)
    if bloqueada:
        sesiones.cerrar()
        flash("Demasiados intentos fallidos. Cuenta bloqueada temporalmente.", "error")
        return redirect(url_for("auth.login"))
    return None


@bp.route("/")
def inicio():
    return _vista()


@bp.route("/password", methods=["POST"])
@limiter.limit("10 per hour", methods=["POST"])
def cambiar_password():
    u = usuarios.obtener(g.usuario["id"])
    if not u["password_hash"]:
        flash("Tu cuenta entra con Google/Microsoft. Para crear una contraseña usa «¿Olvidaste tu contraseña?».", "error")
        return redirect(url_for("cuenta.inicio"))

    actual = (request.form.get("actual") or "")[: passwords.LONGITUD_MAX]
    nueva = request.form.get("nueva") or ""
    if not passwords.verificar(u["password_hash"], actual):
        bloqueo = _prueba_fallida(u, "cambio_password", "contraseña actual incorrecta")
        if bloqueo:
            return bloqueo
        flash("La contraseña actual no es correcta.", "error")
        return redirect(url_for("cuenta.inicio"))

    errores = []
    if nueva != (request.form.get("confirmar") or ""):
        errores.append("Las contraseñas nuevas no coinciden.")
    if nueva == actual:
        errores.append("La nueva contraseña debe ser distinta de la actual.")
    errores += passwords.validar_politica(nueva, u["email"])
    if errores:
        for e in errores:
            flash(e, "error")
        return redirect(url_for("cuenta.inicio"))

    usuarios.cambiar_password(u["id"], passwords.hashear(nueva))
    sesiones.revocar_otras(u["id"])  # esta sesión sigue; las demás se cierran
    correo.enviar_async(
        u["email"], "Tu contraseña fue cambiada",
        "La contraseña de tu cuenta acaba de cambiar y se cerraron tus otras sesiones.\n"
        "Si no fuiste tú, restablécela de inmediato desde «¿Olvidaste tu contraseña?» y avisa al administrador.",
    )
    auditoria.registrar("password_cambiada", True, u["id"], u["email"])
    flash("Contraseña actualizada. Se cerraron tus otras sesiones.", "ok")
    return redirect(url_for("cuenta.inicio"))


@bp.route("/codigos", methods=["POST"])
@limiter.limit("10 per hour", methods=["POST"])
def regenerar_codigos():
    u = usuarios.obtener(g.usuario["id"])
    if not u["totp_confirmado"]:
        flash("Aún no has activado la verificación en dos pasos.", "error")
        return redirect(url_for("cuenta.inicio"))

    codigo = (request.form.get("codigo") or "").strip().replace(" ", "")
    paso = totp.verificar(totp.descifrar(u["totp_secreto_cifrado"]), codigo, u["totp_ultimo_paso"])
    if paso is None or not usuarios.consumir_paso_totp(u["id"], paso):
        bloqueo = _prueba_fallida(u, "regenerar_codigos", "código TOTP incorrecto")
        if bloqueo:
            return bloqueo
        flash("Código incorrecto.", "error")
        return redirect(url_for("cuenta.inicio"))

    codigos = totp.generar_codigos_respaldo()
    usuarios.guardar_codigos_respaldo(u["id"], [totp.hash_codigo(c) for c in codigos])
    auditoria.registrar("codigos_regenerados", True, u["id"], u["email"])
    # Se muestran en esta respuesta y no se vuelven a mostrar; los anteriores quedan anulados.
    return _vista(codigos=codigos)
