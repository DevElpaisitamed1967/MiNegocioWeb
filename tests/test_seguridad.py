"""Pruebas de las garantías de seguridad que no dependen de MySQL.

    pytest tests/
"""
import os
import re

from cryptography.fernet import Fernet

os.environ.setdefault("ENTORNO", "desarrollo")
os.environ.setdefault("SECRET_KEY", "x" * 64)
os.environ.setdefault("TOTP_CLAVE_CIFRADO", Fernet.generate_key().decode())

import pytest  # noqa: E402

from app import create_app  # noqa: E402
from app.seguridad import guard  # noqa: E402

# Lista cerrada de rutas públicas. Si añades una nueva con @publica, debes
# añadirla aquí a propósito: así nadie abre una ruta por accidente.
PUBLICAS_ESPERADAS = {
    "static",
    "auth.login", "auth.registro", "auth.verificar_email",
    "auth.configurar_2fa", "auth.verificar_2fa",
    "auth.recuperar", "auth.restablecer",
    "oauth.iniciar", "oauth.callback",
    "tema.cambiar",
}
# (cuenta.* es privada a propósito: no aparece aquí.)


@pytest.fixture(scope="module")
def app():
    a = create_app()
    a.config.update(TESTING=True, WTF_CSRF_ENABLED=False, RATELIMIT_ENABLED=False)
    return a


def test_solo_las_rutas_esperadas_son_publicas(app):
    publicas = {r.endpoint for r in app.url_map.iter_rules() if guard.es_publica(r.endpoint, app)}
    assert publicas == PUBLICAS_ESPERADAS


def test_toda_ruta_privada_exige_autenticacion(app):
    cliente = app.test_client()
    revisadas = 0
    for regla in app.url_map.iter_rules():
        if regla.endpoint in PUBLICAS_ESPERADAS:
            continue
        ruta = re.sub(r"<[^>]+>", "1", regla.rule)
        for metodo in regla.methods - {"HEAD", "OPTIONS"}:
            resp = cliente.open(ruta, method=metodo)
            assert resp.status_code in (302, 401), f"{metodo} {ruta} respondió {resp.status_code}"
            if resp.status_code == 302:
                assert "/login" in resp.headers["Location"], f"{metodo} {ruta}"
            revisadas += 1
    assert revisadas >= 4  # panel, inicio, logout, admin...


def test_cookie_falsa_no_da_acceso_a_nada(app):
    cliente = app.test_client()
    with cliente.session_transaction() as s:
        s["sid"] = 12345  # tipo inválido: se descarta sin consultar la base de datos
    assert cliente.get("/panel").status_code == 302


def test_cabeceras_de_seguridad(app):
    resp = app.test_client().get("/panel")
    assert "script-src 'none'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("valor", [
    "//evil.com", "https://evil.com/x", "/\\evil.com", "javascript:alert(1)", "panel", "", None,
])
def test_redireccion_abierta_bloqueada(app, valor):
    from app.seguridad.flujo import destino_seguro
    with app.test_request_context():
        assert destino_seguro(valor) == "/panel"


def test_redireccion_interna_permitida(app):
    from app.seguridad.flujo import destino_seguro
    with app.test_request_context():
        assert destino_seguro("/admin/usuarios?x=1") == "/admin/usuarios?x=1"


# --- Tema (Sistema / Claro / Oscuro) -------------------------------------------

@pytest.mark.parametrize("valor", ["system", "light", "dark"])
def test_tema_guarda_cookie_y_redirige_a_sitio_seguro(app, valor):
    resp = app.test_client().post("/tema", data={"tema": valor, "volver": "//evil.com"})
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/panel"  # el destino externo se descarta
    assert f"tema={valor}" in resp.headers["Set-Cookie"]
    assert "HttpOnly" in resp.headers["Set-Cookie"]


def test_tema_invalido_no_crea_cookie(app):
    resp = app.test_client().post("/tema", data={"tema": "<script>", "volver": "/login"})
    assert "Set-Cookie" not in resp.headers


@pytest.mark.parametrize("cookie, esperado", [("dark", "dark"), ("light", "light"),
                                              ("system", "system"), ("raro", "system"), (None, "system")])
def test_pagina_aplica_el_tema_de_la_cookie(app, cookie, esperado):
    cliente = app.test_client()
    if cookie:
        cliente.set_cookie("tema", cookie)
    html = cliente.get("/no-existe").get_data(as_text=True)  # página de error: no usa la base de datos
    assert f'data-tema="{esperado}"' in html
    assert 'name="tema"' in html and html.count("aria-pressed") == 3


# --- Recuperación de contraseña (sin base de datos) --------------------------------

def test_formulario_de_recuperacion_se_muestra_sin_sesion(app):
    resp = app.test_client().get("/recuperar")
    assert resp.status_code == 200
    assert 'name="email"' in resp.get_data(as_text=True)


def test_recuperar_con_correo_invalido_responde_igual_que_siempre(app, monkeypatch):
    monkeypatch.setattr("app.seguridad.auditoria.registrar", lambda *a, **k: None)
    resp = app.test_client().post("/recuperar", data={"email": "no-es-un-correo"})
    assert resp.status_code == 302 and "/login" in resp.headers["Location"]


def test_restablecer_rechaza_contrasenas_distintas(app):
    resp = app.test_client().post("/restablecer/cualquier-token",
                                  data={"password": "una-clave-larga-1", "confirmar": "otra-distinta-2"})
    assert resp.status_code == 400
    assert "no coinciden" in resp.get_data(as_text=True)


def _simular_restablecimiento(monkeypatch, consumir):
    """Sustituye la base de datos por registros en memoria para probar la lógica de la ruta."""
    llamadas = []
    usuario = {"id": 7, "email": "ana@x.co"}
    monkeypatch.setattr("app.seguridad.tokens.usuario_de_enlace", lambda t, tipo: 7)
    monkeypatch.setattr("app.seguridad.tokens.consumir_enlace", lambda t, tipo: consumir)
    monkeypatch.setattr("app.seguridad.tokens.invalidar_pendientes", lambda *a: llamadas.append("invalidar"))
    monkeypatch.setattr("app.modelos.usuarios.obtener", lambda uid: usuario)
    monkeypatch.setattr("app.modelos.usuarios.cambiar_password", lambda uid, h: llamadas.append("cambiar"))
    monkeypatch.setattr("app.seguridad.sesiones.revocar_todas", lambda uid: llamadas.append("revocar"))
    monkeypatch.setattr("app.seguridad.correo.enviar_async", lambda *a: llamadas.append("aviso"))
    monkeypatch.setattr("app.seguridad.auditoria.registrar", lambda *a, **k: None)
    return llamadas


def test_restablecer_cambia_la_clave_cierra_sesiones_y_avisa(app, monkeypatch):
    llamadas = _simular_restablecimiento(monkeypatch, consumir=7)
    clave = "caballo-bateria-grapa-luna"
    resp = app.test_client().post("/restablecer/tok", data={"password": clave, "confirmar": clave})
    assert resp.status_code == 302 and "/login" in resp.headers["Location"]
    assert llamadas == ["cambiar", "invalidar", "revocar", "aviso"]


def test_restablecer_no_cambia_nada_si_el_enlace_ya_se_uso(app, monkeypatch):
    llamadas = _simular_restablecimiento(monkeypatch, consumir=None)  # otro envío lo gastó antes
    clave = "caballo-bateria-grapa-luna"
    resp = app.test_client().post("/restablecer/tok", data={"password": clave, "confirmar": clave})
    assert resp.status_code == 302 and "/recuperar" in resp.headers["Location"]
    assert llamadas == []


def test_restablecer_rechaza_clave_debil_sin_gastar_el_enlace(app, monkeypatch):
    llamadas = _simular_restablecimiento(monkeypatch, consumir=7)
    resp = app.test_client().post("/restablecer/tok", data={"password": "corta", "confirmar": "corta"})
    assert resp.status_code == 400 and llamadas == []


@pytest.mark.parametrize("password, correo, fragmento", [
    ("corta", "ana@x.co", "al menos 12"),
    ("aaaaaaaaaaaaaaaa", "ana@x.co", "repetitiva"),
    ("mi-clave-ana.lopez-2026", "ana.lopez@x.co", "tu correo"),
    ("administrador", "ana@x.co", "demasiado común"),
])
def test_politica_de_contrasenas(password, correo, fragmento):
    from app.seguridad.passwords import validar_politica
    assert any(fragmento in e for e in validar_politica(password, correo))


def test_contrasena_buena_pasa_la_politica():
    from app.seguridad.passwords import validar_politica
    assert validar_politica("caballo-bateria-grapa-luna", "ana@x.co") == []


# --- Mi cuenta y control por rol (sin base de datos) -------------------------------

def _con_sesion(monkeypatch, rol="Administrador", **extra):
    """Simula una sesión válida sin tocar MySQL."""
    from flask import g

    def cargar():
        g.usuario = {"id": 7, "nombre": "Ana", "email": "ana@ejemplo.com",
                     "rol_id": 1, "rol": rol, "requiere_2fa": rol != "Consultor"}
        return True

    monkeypatch.setattr("app.seguridad.sesiones.cargar", cargar)
    usuario = {"id": 7, "nombre": "Ana", "email": "ana@ejemplo.com", "password_hash": "h",
               "totp_confirmado": 1, "totp_secreto_cifrado": b"x", "totp_ultimo_paso": 0}
    usuario.update(extra)
    monkeypatch.setattr("app.modelos.usuarios.obtener", lambda uid: usuario)
    monkeypatch.setattr("app.modelos.usuarios.contar_codigos_respaldo", lambda uid: 4)
    monkeypatch.setattr("app.seguridad.auditoria.registrar", lambda *a, **k: None)
    return usuario


def test_consultor_no_puede_entrar_a_administracion(app, monkeypatch):
    _con_sesion(monkeypatch, rol="Consultor")
    assert app.test_client().get("/admin/usuarios").status_code == 403


def test_mi_cuenta_se_muestra_con_sesion(app, monkeypatch):
    _con_sesion(monkeypatch)
    html = app.test_client().get("/cuenta/").get_data(as_text=True)
    assert "Cambiar contraseña" in html and "4</strong> código(s)" in html


def test_mi_cuenta_sin_sesion_redirige_al_login(app):
    resp = app.test_client().get("/cuenta/")
    assert resp.status_code == 302 and "/login" in resp.headers["Location"]


def test_cambio_de_clave_exige_la_clave_actual(app, monkeypatch):
    _con_sesion(monkeypatch)
    llamadas = []
    monkeypatch.setattr("app.seguridad.passwords.verificar", lambda h, p: False)
    monkeypatch.setattr("app.modelos.usuarios.registrar_fallo", lambda uid: False)
    monkeypatch.setattr("app.modelos.usuarios.cambiar_password", lambda *a: llamadas.append("cambiar"))
    app.test_client().post("/cuenta/password", data={
        "actual": "mala", "nueva": "Una-clave-larga-9137!", "confirmar": "Una-clave-larga-9137!"})
    assert llamadas == []


def test_cambio_de_clave_correcto_cierra_las_otras_sesiones(app, monkeypatch):
    _con_sesion(monkeypatch)
    llamadas = []
    monkeypatch.setattr("app.seguridad.passwords.verificar", lambda h, p: True)
    monkeypatch.setattr("app.seguridad.passwords.hashear", lambda p: "nuevo")
    monkeypatch.setattr("app.modelos.usuarios.cambiar_password", lambda *a: llamadas.append("cambiar"))
    monkeypatch.setattr("app.seguridad.sesiones.revocar_otras", lambda uid: llamadas.append("otras"))
    monkeypatch.setattr("app.seguridad.correo.enviar_async", lambda *a: llamadas.append("aviso"))
    app.test_client().post("/cuenta/password", data={
        "actual": "Vieja-clave-1234!", "nueva": "Una-clave-larga-9137!", "confirmar": "Una-clave-larga-9137!"})
    assert llamadas == ["cambiar", "otras", "aviso"]


def test_cambio_de_clave_rechaza_clave_debil(app, monkeypatch):
    _con_sesion(monkeypatch)
    llamadas = []
    monkeypatch.setattr("app.seguridad.passwords.verificar", lambda h, p: True)
    monkeypatch.setattr("app.modelos.usuarios.cambiar_password", lambda *a: llamadas.append("cambiar"))
    app.test_client().post("/cuenta/password", data={"actual": "x", "nueva": "corta", "confirmar": "corta"})
    assert llamadas == []


def test_regenerar_codigos_exige_un_totp_valido(app, monkeypatch):
    _con_sesion(monkeypatch)
    llamadas = []
    monkeypatch.setattr("app.seguridad.totp.descifrar", lambda b: "SECRETO")
    monkeypatch.setattr("app.seguridad.totp.verificar", lambda *a: None)
    monkeypatch.setattr("app.modelos.usuarios.registrar_fallo", lambda uid: False)
    monkeypatch.setattr("app.modelos.usuarios.guardar_codigos_respaldo", lambda *a: llamadas.append("guardar"))
    app.test_client().post("/cuenta/codigos", data={"codigo": "000000"})
    assert llamadas == []


def test_regenerar_codigos_con_totp_valido_muestra_los_nuevos(app, monkeypatch):
    _con_sesion(monkeypatch)
    monkeypatch.setattr("app.seguridad.totp.descifrar", lambda b: "SECRETO")
    monkeypatch.setattr("app.seguridad.totp.verificar", lambda *a: 55)
    monkeypatch.setattr("app.modelos.usuarios.consumir_paso_totp", lambda uid, paso: True)
    monkeypatch.setattr("app.seguridad.totp.generar_codigos_respaldo", lambda: ["AAAA-1111", "BBBB-2222"])
    monkeypatch.setattr("app.seguridad.totp.hash_codigo", lambda c: "h" + c)
    guardados = []
    monkeypatch.setattr("app.modelos.usuarios.guardar_codigos_respaldo", lambda uid, hs: guardados.append(hs))
    html = app.test_client().post("/cuenta/codigos", data={"codigo": "123456"}).get_data(as_text=True)
    assert "AAAA-1111" in html and guardados == [["hAAAA-1111", "hBBBB-2222"]]


# --- Segundo factor: verificación y activación (códigos TOTP reales, sin MySQL) ------------

def _preparar_2fa(monkeypatch, confirmado=True):
    """Simula a un usuario en el paso intermedio del 2FA. Devuelve (secreto, llamadas, cliente_factory)."""
    import time

    import pyotp

    from app.seguridad import totp

    secreto = pyotp.random_base32()
    usuario = {"id": 7, "nombre": "Ana", "email": "ana@ejemplo.com", "activo": 1,
               "bloqueado_hasta": None, "totp_confirmado": int(confirmado),
               "totp_secreto_cifrado": totp.cifrar(secreto), "totp_ultimo_paso": None}
    llamadas = []
    monkeypatch.setattr("app.modelos.usuarios.obtener", lambda uid: usuario)
    monkeypatch.setattr("app.modelos.roles.obtener",
                        lambda rid: {"id": 1, "nombre": "Administrador", "requiere_2fa": 1})
    monkeypatch.setattr("app.seguridad.auditoria.registrar",
                        lambda evento, ok, uid=None, email=None, detalle=None: llamadas.append((evento, ok, detalle)))
    monkeypatch.setattr("app.seguridad.sesiones.crear", lambda uid, rid: llamadas.append(("sesion", uid, rid)))
    monkeypatch.setattr("app.modelos.usuarios.limpiar_fallos", lambda uid: None)
    monkeypatch.setattr("app.modelos.usuarios.registrar_login", lambda uid: None)
    monkeypatch.setattr("app.modelos.usuarios.registrar_fallo", lambda uid: False)
    monkeypatch.setattr("app.seguridad.correo.enviar", lambda *a: None)
    # Ninguna prueba debe tocar MySQL: el código del correo se simula siempre.
    monkeypatch.setattr("app.seguridad.tokens.crear_codigo", lambda uid, tipo, minutos: "000000")

    def cliente(app):
        c = app.test_client()
        with c.session_transaction() as s:
            s["pre2fa"] = {"uid": 7, "rid": 1, "metodo": "password",
                           "ts": int(time.time()), "codigo_enviado": False}
        return c
    return secreto, llamadas, cliente


def test_verificar_2fa_acepta_el_codigo_de_la_app_y_abre_sesion(app, monkeypatch):
    import pyotp
    secreto, llamadas, cliente = _preparar_2fa(monkeypatch)
    monkeypatch.setattr("app.modelos.usuarios.consumir_paso_totp", lambda uid, paso: True)
    resp = cliente(app).post("/2fa/verificar", data={"codigo": pyotp.TOTP(secreto).now()})
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/panel")
    assert ("sesion", 7, 1) in llamadas


def test_verificar_2fa_acepta_el_codigo_escrito_con_espacio(app, monkeypatch):
    # Google/Microsoft Authenticator muestran el código como "123 456".
    import pyotp
    secreto, llamadas, cliente = _preparar_2fa(monkeypatch)
    monkeypatch.setattr("app.modelos.usuarios.consumir_paso_totp", lambda uid, paso: True)
    codigo = pyotp.TOTP(secreto).now()
    resp = cliente(app).post("/2fa/verificar", data={"codigo": f"{codigo[:3]} {codigo[3:]}"})
    assert resp.status_code == 302 and ("sesion", 7, 1) in llamadas


def test_verificar_2fa_rechaza_un_codigo_ya_usado(app, monkeypatch):
    import pyotp
    secreto, llamadas, cliente = _preparar_2fa(monkeypatch)
    monkeypatch.setattr("app.modelos.usuarios.consumir_paso_totp", lambda uid, paso: False)  # replay
    monkeypatch.setattr("app.modelos.usuarios.consumir_codigo_respaldo", lambda uid, h: False)
    resp = cliente(app).post("/2fa/verificar", data={"codigo": pyotp.TOTP(secreto).now()})
    assert resp.status_code == 200 and "Código incorrecto" in resp.get_data(as_text=True)
    assert not any(x[0] == "sesion" for x in llamadas)


def test_activar_2fa_muestra_el_codigo_del_correo_si_no_hay_smtp(app, monkeypatch):
    _, _, cliente = _preparar_2fa(monkeypatch, confirmado=False)
    monkeypatch.setattr("app.config.Config.DESARROLLO", True)
    monkeypatch.setattr("app.config.Config.SMTP_HOST", None)
    monkeypatch.setattr("app.seguridad.tokens.crear_codigo", lambda uid, tipo, minutos: "654321")
    c = cliente(app)
    html = c.get("/2fa/configurar").get_data(as_text=True)
    assert "654321" in html
    # El código sigue visible al recargar la página (no se pierde tras el primer envío).
    assert "654321" in c.get("/2fa/configurar").get_data(as_text=True)


def test_activar_2fa_no_muestra_el_codigo_cuando_hay_smtp(app, monkeypatch):
    _, _, cliente = _preparar_2fa(monkeypatch, confirmado=False)
    monkeypatch.setattr("app.config.Config.SMTP_HOST", "smtp.ejemplo.com")
    monkeypatch.setattr("app.seguridad.tokens.crear_codigo", lambda uid, tipo, minutos: "654321")
    assert "654321" not in cliente(app).get("/2fa/configurar").get_data(as_text=True)


def test_activar_2fa_completo_confirma_el_autenticador_y_abre_sesion(app, monkeypatch):
    import pyotp
    secreto, llamadas, cliente = _preparar_2fa(monkeypatch, confirmado=False)
    confirmados = []
    monkeypatch.setattr("app.seguridad.tokens.consumir_codigo", lambda uid, tipo, c: c == "654321")
    monkeypatch.setattr("app.modelos.usuarios.confirmar_totp", lambda uid, paso: confirmados.append(paso) or True)
    monkeypatch.setattr("app.modelos.usuarios.guardar_codigos_respaldo", lambda uid, hashes: None)
    resp = cliente(app).post("/2fa/configurar",
                             data={"codigo": pyotp.TOTP(secreto).now(), "codigo_correo": "654321"})
    assert resp.status_code == 200 and len(confirmados) == 1
    assert ("sesion", 7, 1) in llamadas and ("2fa_enrolado", True, None) in llamadas


def test_activar_2fa_registra_cual_de_los_dos_codigos_fallo(app, monkeypatch):
    import pyotp
    secreto, llamadas, cliente = _preparar_2fa(monkeypatch, confirmado=False)
    monkeypatch.setattr("app.seguridad.tokens.consumir_codigo", lambda uid, tipo, c: False)
    c = cliente(app)
    c.post("/2fa/configurar", data={"codigo": "000000", "codigo_correo": "111111"})
    c.post("/2fa/configurar", data={"codigo": pyotp.TOTP(secreto).now(), "codigo_correo": "111111"})
    detalles = [d for (e, ok, d) in llamadas if e == "2fa" and not ok]
    assert detalles == ["enrolamiento: código de la app incorrecto",
                        "enrolamiento: código del correo incorrecto o vencido"]
