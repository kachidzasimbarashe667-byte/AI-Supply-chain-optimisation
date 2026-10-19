"""Leengate backend - Flask + SQLAlchemy + XGBoost."""
from pathlib import Path

from flask import Flask, g, jsonify, request, send_from_directory

from .config import Config
from .db import Base, make_engine, make_session_factory
from .ml import ForecastService
from .security import csrf_guard, load_session_user

FRONTEND_FILE = "Leengate-Professional.html"


def create_app(overrides=None):
    app = Flask(__name__, static_folder=None)
    app.config.from_object(Config)
    if overrides:
        app.config.update(overrides)
    (Path(app.root_path).parent / "instance").mkdir(exist_ok=True)

    engine = make_engine(app.config["DATABASE_URL"])
    Base.metadata.create_all(engine)
    sessions = make_session_factory(engine)
    app.extensions["engine"] = engine
    app.extensions["db"] = sessions
    app.extensions["ml"] = ForecastService(engine, n_estimators=app.config.get("XGB_TREES", 250))

    from .seed import ensure_accounts, seed
    seed(sessions(), seed_accounts=app.config["SEED_ACCOUNTS"], seed_password=app.config["SEED_PASSWORD"],
         admin_password=app.config["ADMIN_PASSWORD"])
    if app.config["SEED_ACCOUNTS"]:
        ensure_accounts(sessions(), app.config["SEED_PASSWORD"], app.config["ADMIN_PASSWORD"])
    sessions.remove()

    from .auth import bp as auth_bp
    from .api import bp as api_bp
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(api_bp, url_prefix="/api")

    # ------------------------------------------------------------------ per-request guards
    @app.before_request
    def _guards():
        g.db = sessions()
        g.user = None
        if request.path.startswith("/api/"):
            blocked = csrf_guard()
            if blocked:
                return blocked
            g.user = load_session_user(g.db, request.cookies.get(app.config["COOKIE_NAME"]))

    @app.teardown_request
    def _close(_exc):
        sessions.remove()

    @app.after_request
    def _headers(resp):
        # Never let a browser keep a copy of a private page or API answer: pressing "Back"
        # after sign-out cannot bring the previous person's dashboard back.
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' data: https://fonts.gstatic.com; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        return resp

    # ------------------------------------------------------------------ errors (never leak internals)
    @app.errorhandler(404)
    def _404(_e):
        return jsonify({"error": "Not found."}), 404

    @app.errorhandler(405)
    def _405(_e):
        return jsonify({"error": "Method not allowed."}), 405

    @app.errorhandler(413)
    def _413(_e):
        return jsonify({"error": "Request too large."}), 413

    @app.errorhandler(Exception)
    def _500(exc):
        from werkzeug.exceptions import HTTPException
        if isinstance(exc, HTTPException):
            return jsonify({"error": exc.description}), exc.code
        app.logger.exception("Unhandled error")
        return jsonify({"error": "Something went wrong on the server."}), 500

    # ------------------------------------------------------------------ frontend
    @app.get("/")
    def index():
        return send_from_directory(app.config["FRONTEND_DIR"], FRONTEND_FILE)

    return app
