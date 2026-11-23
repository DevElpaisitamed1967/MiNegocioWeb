"""Preferencia de tema (Sistema / Claro / Oscuro).

Se guarda en una cookie y la lee el servidor, así no hace falta JavaScript y la política
de seguridad de contenido (CSP) puede seguir prohibiendo scripts. Es pública porque el
selector también aparece en las pantallas de inicio de sesión.
"""
from flask import Blueprint, redirect, request

from app.config import Config
from app.seguridad.flujo import destino_seguro
from app.seguridad.guard import publica

bp = Blueprint("tema", __name__)

VALORES = ("system", "light", "dark")
UN_ANO = 60 * 60 * 24 * 365


@bp.route("/tema", methods=["POST"])
@publica
def cambiar():
    resp = redirect(destino_seguro(request.form.get("volver")))
    valor = request.form.get("tema")
    if valor in VALORES:
        resp.set_cookie("tema", valor, max_age=UN_ANO, samesite="Lax",
                        secure=not Config.DESARROLLO, httponly=True)
    return resp
