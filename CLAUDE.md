# minegocioweb

Aplicación Flask + MySQL con autenticación, roles, 2FA (TOTP) y OAuth (Google/Microsoft).
La arquitectura y las medidas de seguridad están descritas en @README.md.

## Idioma

Responde en español. El código del proyecto también usa español: nombres de funciones,
variables, comentarios, docstrings y mensajes al usuario.

## Comandos

Usa siempre el Python del entorno virtual, sin necesidad de activarlo:

- Pruebas: `.venv/Scripts/python.exe -m pytest tests -q` (simulan la base; no tocan MySQL)
- Una prueba: `.venv/Scripts/python.exe -m pytest tests/test_seguridad.py -k nombre`
- Ver tablas (solo lectura): `.venv/Scripts/python.exe check_db.py`
- Servidor: `.venv/Scripts/python.exe run.py` → http://localhost:5000. Antes de lanzarlo,
  comprueba si el puerto 5000 ya está en uso: suele estar abierto desde VS Code.
- Dependencias: `.venv/Scripts/python.exe -m pip install -r requirements.txt`

## Reglas

- **Secretos:** no leas ni muestres `.env`, `acceso.txt` ni `admin_clave.txt`. Para saber qué
  variables existen, mira `app/config.py`.
- **Base de datos:** es la real del equipo. No ejecutes `init_db.py`, `manage.py crear-admin`,
  `manage.py asignar-rol` ni SQL que modifique datos sin confirmación.
- **No cambies `TOTP_CLAVE_CIFRADO`:** inutiliza los 2FA ya configurados.
- **Rutas:** todo es privado por defecto (`app/seguridad/guard.py`). Una ruta pública requiere
  `@publica` y añadirse a `PUBLICAS_ESPERADAS` en `tests/test_seguridad.py`. Las rutas por rol
  usan `exigir_roles(...)`.
- **Sin JavaScript:** la CSP impone `script-src 'none'` y `style-src 'self'`. Nada de `<script>`,
  ni `style=` o `<style>` en línea; los estilos van en `app/static/css/`.
- **SQL:** consultas parametrizadas con `%s`, dentro de `with cursor()` (un `with` = una transacción).
  Van en `app/modelos/` o `app/seguridad/`, no en los controladores.
- **Esquema:** `sql/schema.sql` debe poder ejecutarse de nuevo sin perder datos. `init_db.py`
  separa sentencias por `;`, así que no uses `;` dentro de textos.
- Formularios POST con token CSRF. Mensajes de error genéricos en autenticación.
- Fin de línea LF.
- Después de cambiar código Python o plantillas, ejecuta las pruebas.
