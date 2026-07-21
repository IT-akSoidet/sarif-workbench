"""Application configuration.

This module intentionally contains insecure configuration findings for the
SAST comparison study. Do not "fix" them.
"""


class BaseConfig:
    # VULN: CWE-16 — default, unchanged SECRET_KEY left in source ("change-me").
    # Predictable key allows session/cookie forgery.
    SECRET_KEY = "dev-secret-key-change-me"

    # Database file (raw sqlite3 is used throughout the app).
    DATABASE = "bookstore.db"

    # VULN: CWE-16 — CSRF protection globally disabled (affects order changes
    # and every other state-changing POST).
    WTF_CSRF_ENABLED = False

    # Session cookie hardening flags left off on purpose.
    # VULN v4: CWE-1004 — the session cookie carries no HttpOnly flag, so
    # client-side JavaScript (e.g. via this app's XSS sinks) can read it.
    SESSION_COOKIE_HTTPONLY = False
    # VULN v4: CWE-614 — the session cookie carries no Secure flag, so it is
    # transmitted over plaintext HTTP and can be sniffed on the network.
    SESSION_COOKIE_SECURE = False
    # VULN v4: CWE-1275 — no SameSite attribute is configured for the session
    # cookie, so it is attached to cross-site requests (aids CSRF).
    SESSION_COOKIE_SAMESITE = None

    # VULN: CWE-942 — permissive CORS origin. The actual CORS(app, ...) sink
    # is wired in main.py (it needs the Flask app instance); this "*" value is
    # the misconfiguration it is initialised from.
    CORS_ORIGINS = "*"


class DevelopmentConfig(BaseConfig):
    DEBUG = True


class ProductionConfig(BaseConfig):
    # VULN: CWE-16 — DEBUG=True in the class explicitly labelled "Production".
    # Enables the interactive Werkzeug debugger / traceback disclosure in prod.
    DEBUG = True


# The app runs with the "production" profile — see main.py.
ActiveConfig = ProductionConfig
