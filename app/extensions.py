"""Extensiones de Flask compartidas (se inicializan en create_app)."""
from authlib.integrations.flask_client import OAuth
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

from app.config import Config

csrf = CSRFProtect()
limiter = Limiter(
    get_remote_address,
    default_limits=["300 per hour"],
    storage_uri=Config.LIMITER_STORAGE,
)
oauth = OAuth()
