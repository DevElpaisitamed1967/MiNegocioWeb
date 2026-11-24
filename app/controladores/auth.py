"""Registro, inicio de sesión con correo y contraseña, 2FA y cierre de sesión."""
import re

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from app.config import Config
from app.extensions import limiter
from app.modelos import roles as roles_modelo
from app.modelos import usuarios
from app.seguridad import auditoria, correo, flujo, passwords, sesiones, tokens, totp
from app.seguridad.guard import publica

bp = Blueprint("auth", __name__)

ERROR_GENERICO = "Credenciales o rol incorrectos."
_RE_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")


def _email(valor) -> str | None:
    v = (valor or "").strip().lower()
    return v if len(v) <= 254 and _RE_EMAIL.match(v) else None


def _enlace(ruta: str) -> str:
    # Se usa URL_BASE (configurada) y no el Host de la petición: evita envenenar los enlaces.
    return Config.URL_BASE.rstrip("/") + ruta


def _proveedores():
    from app.controladores.oauth import proveedores_activos
    return proveedores_activos()


def _correo_en_pantalla() -> bool:
    """True solo en desarrollo y sin SMTP: ahí el correo no sale a ningún sitio (solo se
    imprime en la consola del servidor), así que el código se muestra en la propia página.
    create_app() impide arrancar en producción sin SMTP, por lo que nunca se activa allí."""
    return Config.DESARROLLO and not Config.SMTP_HOST


# --- Registro ------------------------------------------------------------------

@bp.route("/registro", methods=["GET", "POST"])
@publica
@limiter.limit("5 per hour", methods=["POST"])
def registro():
    if request.method == "POST":
        nombre = (request.form.get("nombre") or "").strip()[:100]
        email = _email(request.form.get("email"))
        password = request.form.get("password") or ""
        errores = []
        if not nombre:
            errores.append("Escribe tu nombre.")
        if not email:
            errores.append("Escribe un correo válido.")
        if password != (request.form.get("confirmar") or ""):
            errores.append("Las contraseñas no coinciden.")
        errores += passwords.validar_politica(password, email or "")
        if errores:
            for e in errores:
                flash(e, "error")
            return render_template("registro.html", nombre=nombre, email=email or ""), 400

        # El hash se calcula siempre, exista o no el correo, para igualar los tiempos.
        uid = usuarios.crear(nombre, email, passwords.hashear(password))
        if uid:
            token = tokens.crear_enlace(uid, "verificar_email", minutos=60 * 24)
            correo.enviar(
                email, "Verifica tu correo",
                "Hola " + nombre + ",\n\nConfirma tu correo con este enlace (vence en 24 horas):\n"
                + _enlace(url_for("auth.verificar_email", token=token))
                + "\n\nSi no creaste esta cuenta, ignora este mensaje.",
            )
            auditoria.registrar("registro", True, uid, email)
        else:
            auditoria.registrar("registro", False, None, email, "correo ya registrado")
        # Misma respuesta en ambos casos: no revela si el correo ya existía.
        flash("Si los datos son válidos, te enviamos un enlace para verificar tu correo.", "ok")
        return redirect(url_for("auth.login"))
    return render_template("registro.html", nombre="", email="")


@bp.route("/verificar/<token>")
@publica
@limiter.limit("20 per hour")
def verificar_email(token):
    uid = tokens.consumir_enlace(token[:100], "verificar_email")
    if uid:
        usuarios.marcar_email_verificado(uid)
        auditoria.registrar("email_verificado", True, uid)
        flash("Correo verificado. Ya puedes iniciar sesión.", "ok")
    else:
        flash("El enlace no es válido o ya venció.", "error")
    return redirect(url_for("auth.login"))


# --- Login ---------------------------------------------------------------------

@bp.route("/login", methods=["GET", "POST"])
@publica
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if request.method == "GET":
        if sesiones.cargar():
            return redirect(url_for("panel.panel"))
        return render_template("login.html", roles=roles_modelo.listar(),
                               proveedores=_proveedores(), email="", rol_sel=None)

    email = _email(request.form.get("email"))
    password = (request.form.get("password") or "")[: passwords.LONGITUD_MAX]
    rol = roles_modelo.obtener(request.form.get("rol", type=int))
    usuario = usuarios.obtener_por_email(email) if email else None

    def rechazar(motivo: str, mensaje: str = ERROR_GENERICO):
        auditoria.registrar("login", False, usuario["id"] if usuario else None, email, motivo)
        flash(mensaje, "error")
        return render_template("login.html", roles=roles_modelo.listar(),
                               proveedores=_proveedores(), email=email or "",
                               rol_sel=rol["id"] if rol else None), 401

    if usuario is None or rol is None:
        passwords.verificar_relleno(password)  # mismo coste que un intento real
        return rechazar("usuario o rol inexistente")

    if usuarios.esta_bloqueado(usuario):
        return rechazar("cuenta bloqueada")

    if not passwords.verificar(usuario["password_hash"], password):
        bloqueada = usuarios.registrar_fallo(usuario["id"])
        return rechazar("contraseña incorrecta" + (" (cuenta bloqueada)" if bloqueada else ""))

    if not usuarios.tiene_rol(usuario["id"], rol["id"]):
        usuarios.registrar_fallo(usuario["id"])
        return rechazar(f"no tiene el rol {rol['nombre']}")

    # A partir de aquí la contraseña es correcta, así que ya se pueden dar detalles.
    if not usuario["activo"]:
        return rechazar("cuenta inactiva", "Tu cuenta está desactivada. Contacta al administrador.")
    if not usuario["email_verificado"]:
        return rechazar("correo sin verificar", "Debes verificar tu correo antes de ingresar.")

    if passwords.necesita_rehash(usuario["password_hash"]):
        usuarios.actualizar_hash(usuario["id"], passwords.hashear(password))

    return flujo.continuar_tras_credenciales(usuario, rol, "password")


@bp.route("/logout", methods=["POST"])
def logout():
    sesiones.cerrar()
    flash("Sesión cerrada.", "ok")
    return redirect(url_for("auth.login"))


# --- Recuperación de contraseña ------------------------------------------------

VIDA_ENLACE_RESET_MIN = 30
ESPERA_ENTRE_ENVIOS_MIN = 5


@bp.route("/recuperar", methods=["GET", "POST"])
@publica
@limiter.limit("5 per hour", methods=["POST"])
def recuperar():
    if request.method == "POST":
        email = _email(request.form.get("email"))
        usuario = usuarios.obtener_por_email(email) if email else None
        if (usuario and usuario["activo"]
                and not tokens.hay_enlace_reciente(usuario["id"], "recuperar_password",
                                                   VIDA_ENLACE_RESET_MIN, ESPERA_ENTRE_ENVIOS_MIN)):
            token = tokens.crear_enlace(usuario["id"], "recuperar_password", VIDA_ENLACE_RESET_MIN)
            correo.enviar_async(
                usuario["email"], "Restablece tu contraseña",
                "Recibimos una solicitud para restablecer la contraseña de tu cuenta.\n\n"
                f"Usa este enlace (vence en {VIDA_ENLACE_RESET_MIN} minutos y sirve una sola vez):\n"
                + _enlace(url_for("auth.restablecer", token=token))
                + "\n\nSi no fuiste tú, ignora este mensaje: tu contraseña no cambiará.",
            )
            auditoria.registrar("recuperar_solicitud", True, usuario["id"], email)
        else:
            auditoria.registrar("recuperar_solicitud", False, usuario["id"] if usuario else None,
                                email, "sin envío")
        # Misma respuesta exista o no la cuenta: no revela qué correos están registrados.
        flash("Si ese correo está registrado, te enviamos un enlace para restablecer la contraseña.", "ok")
        return redirect(url_for("auth.login"))
    return render_template("recuperar.html")


@bp.route("/restablecer/<token>", methods=["GET", "POST"])
@publica
@limiter.limit("10 per hour", methods=["POST"])
def restablecer(token):
    token = token[:100]

    def enlace_invalido():
        flash("El enlace no es válido o ya venció. Solicita uno nuevo.", "error")
        return redirect(url_for("auth.recuperar"))

    if request.method == "GET":
        if tokens.usuario_de_enlace(token, "recuperar_password") is None:
            return enlace_invalido()
        return render_template("restablecer.html", token=token)

    password = request.form.get("password") or ""
    if password != (request.form.get("confirmar") or ""):
        flash("Las contraseñas no coinciden.", "error")
        return render_template("restablecer.html", token=token), 400

    uid = tokens.usuario_de_enlace(token, "recuperar_password")
    usuario = usuarios.obtener(uid) if uid else None
    if usuario is None:
        return enlace_invalido()
    errores = passwords.validar_politica(password, usuario["email"])
    if errores:
        for e in errores:
            flash(e, "error")
        return render_template("restablecer.html", token=token), 400

    # El enlace se gasta aquí, de forma atómica: dos envíos simultáneos no pueden usarlo a la vez.
    if tokens.consumir_enlace(token, "recuperar_password") is None:
        return enlace_invalido()
    usuarios.cambiar_password(usuario["id"], passwords.hashear(password))
    tokens.invalidar_pendientes(usuario["id"], "recuperar_password")
    sesiones.revocar_todas(usuario["id"])  # expulsa a quien tuviera la sesión abierta
    correo.enviar_async(
        usuario["email"], "Tu contraseña fue cambiada",
        "La contraseña de tu cuenta acaba de cambiar y se cerraron tus sesiones abiertas.\n"
        "Si no fuiste tú, solicita otro restablecimiento de inmediato y avisa al administrador.",
    )
    auditoria.registrar("password_restablecida", True, usuario["id"], usuario["email"])
    flash("Contraseña actualizada. Ya puedes iniciar sesión.", "ok")
    return redirect(url_for("auth.login"))


# --- Segundo factor ------------------------------------------------------------

def _contexto_2fa():
    """Devuelve (pre, usuario, rol) del paso intermedio, o None si no es válido."""
    pre = flujo.pre2fa_actual()
    if not pre:
        return None
    usuario = usuarios.obtener(pre["uid"])
    rol = roles_modelo.obtener(pre["rid"])
    if not usuario or not rol or not usuario["activo"] or usuarios.esta_bloqueado(usuario):
        session.pop("pre2fa", None)
        return None
    return pre, usuario, rol


def _sesion_2fa_caducada():
    flash("La verificación expiró. Inicia sesión de nuevo.", "error")
    return redirect(url_for("auth.login"))


def _fallo_2fa(usuario, motivo):
    bloqueada = usuarios.registrar_fallo(usuario["id"])
    auditoria.registrar("2fa", False, usuario["id"], usuario["email"], motivo)
    if bloqueada:
        session.pop("pre2fa", None)
        flash("Demasiados intentos. Cuenta bloqueada temporalmente.", "error")
        return redirect(url_for("auth.login"))
    flash("Código incorrecto.", "error")
    return None


@bp.route("/2fa/configurar", methods=["GET", "POST"])
@publica
@limiter.limit("10 per minute", methods=["POST"])
def configurar_2fa():
    """Primer uso: enlaza la app autenticadora.

    Además del código de la app se exige un código enviado al correo: así, quien solo
    conozca la contraseña no puede registrar su propio autenticador en la cuenta.
    """
    ctx = _contexto_2fa()
    if not ctx:
        return _sesion_2fa_caducada()
    pre, usuario, rol = ctx
    if usuario["totp_confirmado"]:
        return redirect(url_for("auth.verificar_2fa"))

    if usuario["totp_secreto_cifrado"]:
        secreto = totp.descifrar(usuario["totp_secreto_cifrado"])
    else:
        secreto = totp.generar_secreto()
        usuarios.guardar_secreto_totp(usuario["id"], totp.cifrar(secreto))

    if request.method == "POST":
        codigo_correo = (request.form.get("codigo_correo") or "").strip()
        codigo_app = (request.form.get("codigo") or "").strip().replace(" ", "")
        paso = totp.verificar(secreto, codigo_app, None)
        # El código del correo solo se gasta si el de la app ya era correcto. Al usuario siempre
        # se le dice lo mismo ("Código incorrecto"), pero la bitácora distingue cuál falló.
        if paso is None:
            motivo = "enrolamiento: código de la app incorrecto"
        elif not tokens.consumir_codigo(usuario["id"], "enrolar_2fa", codigo_correo):
            motivo = "enrolamiento: código del correo incorrecto o vencido"
        elif not usuarios.confirmar_totp(usuario["id"], paso):
            motivo = "enrolamiento: el 2FA ya estaba confirmado"
        else:
            motivo = None
        if motivo is None:
            codigos = totp.generar_codigos_respaldo()
            usuarios.guardar_codigos_respaldo(usuario["id"], [totp.hash_codigo(c) for c in codigos])
            auditoria.registrar("2fa_enrolado", True, usuario["id"], usuario["email"])
            destino = flujo.abrir_sesion(usuario, rol, pre["metodo"])
            return render_template("codigos_respaldo.html", codigos=codigos, destino=destino)
        respuesta = _fallo_2fa(usuario, motivo)
        if respuesta:
            return respuesta

    en_pantalla = _correo_en_pantalla()
    if not pre["codigo_enviado"] or (en_pantalla and not pre.get("codigo_dev")):
        codigo = tokens.crear_codigo(usuario["id"], "enrolar_2fa", minutos=10)
        correo.enviar(usuario["email"], "Código para activar la verificación en dos pasos",
                      f"Tu código es {codigo}. Vence en 10 minutos.\n"
                      "Si no intentaste iniciar sesión, cambia tu contraseña.")
        pre["codigo_enviado"] = True
        if en_pantalla:
            pre["codigo_dev"] = codigo
        session["pre2fa"] = pre
    uri = totp.uri_aprovisionamiento(secreto, usuario["email"])
    return render_template("2fa_configurar.html", qr=totp.qr_svg(uri), secreto=secreto,
                           rol=rol["nombre"], codigo_dev=pre.get("codigo_dev") if en_pantalla else None)


@bp.route("/2fa/verificar", methods=["GET", "POST"])
@publica
@limiter.limit("10 per minute", methods=["POST"])
def verificar_2fa():
    ctx = _contexto_2fa()
    if not ctx:
        return _sesion_2fa_caducada()
    pre, usuario, rol = ctx
    if not usuario["totp_confirmado"]:
        return redirect(url_for("auth.configurar_2fa"))

    if request.method == "POST":
        codigo = (request.form.get("codigo") or "").strip()
        secreto = totp.descifrar(usuario["totp_secreto_cifrado"])
        paso = totp.verificar(secreto, codigo.replace(" ", ""), usuario["totp_ultimo_paso"])
        if paso is not None and usuarios.consumir_paso_totp(usuario["id"], paso):
            return redirect(flujo.abrir_sesion(usuario, rol, pre["metodo"]))
        if usuarios.consumir_codigo_respaldo(usuario["id"], totp.hash_codigo(codigo)):
            auditoria.registrar("codigo_respaldo_usado", True, usuario["id"], usuario["email"])
            return redirect(flujo.abrir_sesion(usuario, rol, pre["metodo"]))
        respuesta = _fallo_2fa(usuario, "verificación: código incorrecto")
        if respuesta:
            return respuesta
    return render_template("2fa_verificar.html", rol=rol["nombre"])
