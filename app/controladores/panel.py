"""Páginas internas (requieren sesión; no llevan @publica, así que el guard las protege)."""
from flask import Blueprint, redirect, render_template, url_for

bp = Blueprint("panel", __name__)


@bp.route("/")
def inicio():
    return redirect(url_for("panel.panel"))


@bp.route("/panel")
def panel():
    return render_template("panel.html")
