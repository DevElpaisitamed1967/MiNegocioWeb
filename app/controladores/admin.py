"""Administración de usuarios y roles (solo rol Administrador)."""
from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from app.modelos import roles as roles_modelo
from app.modelos import usuarios
from app.seguridad import auditoria, sesiones
from app.seguridad.guard import exigir_roles

bp = Blueprint("admin", __name__, url_prefix="/admin")
# Cualquier ruta nueva de este blueprint queda restringida a Administrador.
bp.before_request(exigir_roles("Administrador"))


@bp.route("/usuarios")
def listar():
    return render_template("admin_usuarios.html", filas=usuarios.listar_con_roles(),
                           roles=roles_modelo.listar())


@bp.route("/usuarios/<int:usuario_id>/roles", methods=["POST"])
def asignar_roles(usuario_id):
    todos = roles_modelo.listar()
    validos = {r["id"] for r in todos}
    elegidos = {int(x) for x in request.form.getlist("roles") if x.isdigit()} & validos
    admin_id = next(r["id"] for r in todos if r["nombre"] == "Administrador")

    if usuario_id == g.usuario["id"] and admin_id not in elegidos:
        flash("No puedes quitarte a ti mismo el rol de Administrador.", "error")
        return redirect(url_for("admin.listar"))
    if usuarios.obtener(usuario_id) is None:
        flash("Usuario no encontrado.", "error")
        return redirect(url_for("admin.listar"))

    usuarios.establecer_roles(usuario_id, elegidos)
    if usuario_id != g.usuario["id"]:
        sesiones.revocar_todas(usuario_id)  # el cambio de roles aplica de inmediato
    auditoria.registrar("roles_actualizados", True, usuario_id, None,
                        f"por={g.usuario['email']};roles={sorted(elegidos)}")
    flash("Roles actualizados.", "ok")
    return redirect(url_for("admin.listar"))
