"""Punto de entrada: python run.py"""
from app import create_app
from app.config import Config

app = create_app()

if __name__ == "__main__":
    # El depurador de Werkzeug solo se activa en desarrollo.
    app.run(host="127.0.0.1", port=5000, debug=Config.DESARROLLO)
