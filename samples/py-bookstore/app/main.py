"""Application entrypoint: wires blueprints and runs on port 5050."""

import os

from flask import Flask, render_template, session, redirect, url_for
from flask_cors import CORS

from app.config import ActiveConfig
from app.models import list_books
from app.auth import auth_bp
from app.search import search_bp
from app.orders import orders_bp
from app.reviews import reviews_bp
from app.admin import admin_bp


def create_app():
    app = Flask(__name__)
    app.config.from_object(ActiveConfig)
    app.secret_key = ActiveConfig.SECRET_KEY

    # VULN: CWE-942 — permissive CORS: any origin is allowed to make
    # credentialed cross-origin requests (origins from config.CORS_ORIGINS="*").
    CORS(app, resources={r"/*": {"origins": ActiveConfig.CORS_ORIGINS}},
         supports_credentials=True)

    app.register_blueprint(auth_bp)
    app.register_blueprint(search_bp)
    app.register_blueprint(orders_bp)
    app.register_blueprint(reviews_bp)
    app.register_blueprint(admin_bp)

    @app.route("/")
    def index():
        books = [dict(b) for b in list_books()]
        # username comes from the session and is rendered unescaped in
        # base.html (see the |safe usage there) — CWE-79.
        username = session.get("username", "")
        return render_template("search.html", books=books, query="",
                               username=username)

    return app


app = create_app()


if __name__ == "__main__":
    # Ensure the DB exists on first run inside the container.
    if not os.path.exists(ActiveConfig.DATABASE):
        from app.db_init import init_db
        init_db()

    # Port 5050 (not 5000). debug pulled from the "production" config (True).
    app.run(host="0.0.0.0", port=5050, debug=ActiveConfig.DEBUG)
