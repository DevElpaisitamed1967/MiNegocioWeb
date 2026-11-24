# minegocioweb

Aplicación web en Python (Flask) con MySQL. Incluye un sistema de autenticación con
roles, verificación en dos pasos (TOTP) e inicio de sesión con Google y Microsoft/Outlook.

## Estructura

```
app/
├── __init__.py            # create_app(): configuración segura y arranque
├── config.py              # variables de entorno
├── database.py            # conexión a MySQL (transaccional)
├── extensions.py          # CSRF, rate limiting, OAuth
├── seguridad/
│   ├── guard.py           # TODO es privado salvo lo marcado con @publica
│   ├── sesiones.py        # sesiones en el servidor, revocables
│   ├── flujo.py           # login -> 2FA -> sesión
│   ├── passwords.py       # Argon2id + política de contraseñas
│   ├── totp.py            # 2FA: secretos cifrados, QR, códigos de respaldo
│   ├── tokens.py          # enlaces y códigos de un solo uso (hash en BD)
│   ├── correo.py          # SMTP
│   └── auditoria.py       # bitácora de eventos
├── modelos/               # consultas SQL (usuarios, roles)
├── controladores/         # auth, oauth, panel, admin
├── templates/ y static/   # pantallas
sql/schema.sql             # base de datos completa
manage.py                  # crear-admin, asignar-rol
tests/test_seguridad.py
```

## Puesta en marcha (Windows / PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

Edita `.env` y completa, como mínimo, `DB_PASSWORD`, `SECRET_KEY` y `TOTP_CLAVE_CIFRADO`
(el propio archivo indica el comando para generar cada una). Después:

```powershell
python init_db.py                                    # crea la base y las tablas
python manage.py crear-admin tu@correo.com "Tu Nombre"
python run.py                                        # http://localhost:5000
```

> Si ya habías ejecutado la primera versión de `init_db.py`, la tabla `usuarios` cambió:
> elimina la base (`DROP DATABASE minegocioweb;`) y vuelve a ejecutar `init_db.py`.

### Crear la base desde MySQL Workbench (alternativa a `init_db.py`)

1. Abre tu conexión local y elige **File ▸ Open SQL Script…** ▸ `sql/schema.sql`.
2. Ejecuta todo el script con el rayo (**Ctrl+Shift+Enter**). Crea la base, las tablas y los 4 roles.
3. Pulsa **Refresh** en el panel *Schemas* para ver `minegocioweb`.
4. En `.env`, `DB_USER` y `DB_PASSWORD` deben ser los de esa misma conexión.

Después solo falta `python manage.py crear-admin ...` y `python run.py`.

En `ENTORNO=desarrollo` sin `SMTP_HOST`, los enlaces y códigos de correo salen por la consola del
servidor, y el código para activar el 2FA además se muestra en la propia página de activación.

## Cómo funciona

**Roles:** Administrador, Asistente, Colaborador y Consultor. Un usuario puede tener varios y
elige con cuál entra; el sistema comprueba que lo tenga asignado. Administrador, Asistente y
Colaborador exigen segundo factor; Consultor no. Quien se registra recibe Consultor; los demás
roles los asigna un Administrador en `/admin/usuarios`.

**Control de acceso:** un `before_request` global bloquea toda ruta que no esté marcada con
`@publica`. Un controlador nuevo queda protegido por defecto. Las rutas por rol se restringen
con `exigir_roles(...)` (ver `controladores/admin.py`). `tests/test_seguridad.py` recorre todas
las rutas y falla si alguna privada responde sin sesión, o si aparece una pública no prevista.

**Medidas de seguridad:** Argon2id; bloqueo de cuenta tras 5 intentos; mensajes de error
genéricos y tiempos igualados (no revela qué correos existen); verificación de correo;
TOTP con secreto cifrado (Fernet), sin reutilización de códigos y con códigos de respaldo de un
solo uso; el alta del autenticador exige además un código enviado al correo; sesiones en el
servidor con cierre por inactividad (30 min) y duración máxima (8 h); cookies `HttpOnly`,
`SameSite=Lax` y `Secure`; CSRF en todos los formularios; límite de peticiones; cabeceras CSP,
HSTS y anti-clickjacking; bitácora en `auditoria_auth`.

## Tema: Sistema / Claro / Oscuro

El selector aparece en todas las pantallas. La elección se guarda en la cookie `tema` (1 año) y la
lee el servidor, así que no hace falta JavaScript. "Sistema" sigue la preferencia del dispositivo.
Los colores están como variables CSS al inicio de `app/static/css/auth.css`.

## Google y Microsoft / Outlook

Crea las credenciales y pega `*_CLIENT_ID` / `*_CLIENT_SECRET` en `.env`; el botón aparece solo
cuando están configuradas. URIs de redirección: `{URL_BASE}/oauth/google/callback` y
`{URL_BASE}/oauth/microsoft/callback`. Para cuentas corporativas de Microsoft añade el ID de tu
tenant en `MS_TENANTS_PERMITIDOS`: el correo de otros tenants no es fiable y se rechaza.
Entrar con Google/Microsoft no sustituye al 2FA en los roles que lo exigen.

## Pruebas

```powershell
pytest tests/
```

## Recuperación de contraseña

`/recuperar` pide el correo y envía un enlace a `/restablecer/<token>`. Medidas: la respuesta es
idéntica exista o no la cuenta y el correo sale en segundo plano (no se puede averiguar qué correos
están registrados); el token tiene 256 bits, vence en 30 minutos, sirve una vez y solo se guarda su
hash; máximo un correo cada 5 minutos por cuenta; el enlace no se gasta al abrirlo (los antivirus de
correo lo "visitan") sino al guardar la contraseña. Al cambiarla se cierran todas las sesiones, se
levanta el bloqueo y se avisa por correo. **No salta el 2FA**: los roles que lo exigen lo siguen
pidiendo al entrar.

> Si tu base ya estaba creada, vuelve a ejecutar `sql/schema.sql` (Workbench o `init_db.py`): el
> final del script añade el nuevo tipo de token sin tocar tus datos.

## Mi cuenta

En `/cuenta/` el usuario cambia su contraseña (pide la actual; cierra sus otras sesiones y avisa por correo) y
regenera sus códigos de respaldo (pide un código TOTP vigente; los anteriores quedan anulados).

## Visual Studio Code

La carpeta `.vscode/` ya trae la configuración:

1. `File > Open Folder` y abre `D:\VSC\minegocioweb`. Acepta instalar las extensiones recomendadas.
2. Terminal: `py -m venv .venv`, luego `.venv\Scripts\Activate.ps1` y `pip install -r requirements.txt`.
   Si PowerShell bloquea el script: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.
3. `Ctrl+Shift+P > Python: Select Interpreter` y elige `.venv`.
4. `python manage.py generar-claves`, copia `.env.example` a `.env` y pega las claves y tu `DB_PASSWORD`.
5. Panel *Run and Debug* (`Ctrl+Shift+D`): **Crear base de datos**, **Crear administrador**, **Servidor Flask**, **Pruebas**.
6. Abre `http://localhost:5000` (el mismo host que `URL_BASE`).

## Pendiente (a propósito)

En producción: HTTPS, `ENTORNO=produccion`, SMTP real y `LIMITER_STORAGE` con Redis.
