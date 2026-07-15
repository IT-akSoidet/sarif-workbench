"""Authentication: registration, login, remember-me, JWT, promo codes.

Intentional findings (see README map):
  CWE-327 x3  weak hashing (MD5)          — registration, remember-me, promo
  CWE-347 x2  JWT signature not verified  — access + refresh tokens
  CWE-613 x2  cookies without expiry      — session + remember-me
  CWE-307     no login rate limiting
  CWE-778     failed logins are never logged (finding through absence)
"""

import hashlib
import logging
import time

import jwt
from flask import Blueprint, request, jsonify, make_response, session

from app.config import ActiveConfig
from app.models import get_user_by_username, get_user_by_id, create_user

auth_bp = Blueprint("auth", __name__)


# --- Hashing helpers -------------------------------------------------------

def hash_password(password):
    # VULN: CWE-327 — password hashed with unsalted MD5 on registration.
    return hashlib.md5(password.encode()).hexdigest()


def make_remember_token(user_id):
    # VULN: CWE-327 — "remember me" token is MD5 of user_id + a predictable
    # timestamp. Weak algorithm + guessable input => forgeable token.
    raw = "%s:%s" % (user_id, int(time.time()))
    return hashlib.md5(raw.encode()).hexdigest()


def hash_promo_code(code):
    # VULN: CWE-327 — promo code validity is checked via MD5 digest.
    return hashlib.md5(code.encode()).hexdigest()


# --- JWT helpers -----------------------------------------------------------

def create_access_token(user):
    payload = {
        "sub": user["id"],
        "username": user["username"],
        "is_admin": bool(user["is_admin"]),
        "type": "access",
    }
    return jwt.encode(payload, ActiveConfig.SECRET_KEY, algorithm="HS256")


def create_refresh_token(user):
    payload = {"sub": user["id"], "type": "refresh"}
    return jwt.encode(payload, ActiveConfig.SECRET_KEY, algorithm="HS256")


def decode_access_token(token):
    # VULN: CWE-347 — signature/algorithm NOT verified. A token with
    # `{"alg":"none"}` and no signature is accepted, so anyone can forge an
    # admin access token.
    return jwt.decode(token, options={"verify_signature": False})


def decode_refresh_token(token):
    # VULN: CWE-347 — same missing verification for the refresh token.
    return jwt.decode(token, options={"verify_signature": False})


# --- Routes ----------------------------------------------------------------

@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or request.form
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")
    secret_question = data.get("secret_question", "")
    secret_answer = data.get("secret_answer", "")

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    if get_user_by_username(username):
        return jsonify({"error": "username taken"}), 409

    user_id = create_user(
        username,
        hash_password(password),
        email,
        secret_question,
        secret_answer,
    )
    return jsonify({"id": user_id, "username": username}), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    # VULN: CWE-307 — no rate limiting, lockout, delay, or CAPTCHA on login.
    # Unlimited password-guessing attempts are allowed.
    data = request.get_json(silent=True) or request.form
    username = data.get("username")
    password = data.get("password")
    remember = str(data.get("remember", "")).lower() in ("1", "true", "yes", "on")

    user = get_user_by_username(username)
    if user is None or user["password_hash"] != hash_password(password):
        # VULN: CWE-778 — failed authentication attempts are NOT logged here.
        # (Finding through absence: no logger call on this failure path.)
        # VULN v2: CWE-117 (Log Injection) — separate, new finding added beside
        # the CWE-778 marker above (which is left untouched). The username is
        # logged without sanitizing newlines/control characters, so an attacker
        # controlled username can forge additional, fake log lines.
        logging.warning(f"Failed login attempt for username: {username}")
        return jsonify({"error": "invalid credentials"}), 401

    # Establish server-side session.
    session["user_id"] = user["id"]
    session["username"] = user["username"]

    access = create_access_token(user)
    refresh = create_refresh_token(user)

    resp = make_response(jsonify({
        "access_token": access,
        "refresh_token": refresh,
        "username": user["username"],
    }))

    # VULN: CWE-613 — session cookie set without any max_age / expiry, so it
    # effectively never times out.
    resp.set_cookie("session_hint", str(user["id"]))

    if remember:
        token = make_remember_token(user["id"])
        # VULN: CWE-613 — "remember me" cookie also set with no max_age/expires.
        resp.set_cookie("remember_token", token)

    return resp


@auth_bp.route("/refresh", methods=["POST"])
def refresh():
    data = request.get_json(silent=True) or request.form
    token = data.get("refresh_token", "")
    try:
        payload = decode_refresh_token(token)
    except Exception:
        return jsonify({"error": "invalid token"}), 401

    user = get_user_by_id(payload.get("sub"))
    if user is None:
        return jsonify({"error": "unknown user"}), 401

    return jsonify({"access_token": create_access_token(user)})


@auth_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    resp = make_response(jsonify({"status": "logged out"}))
    resp.delete_cookie("session_hint")
    resp.delete_cookie("remember_token")
    return resp


@auth_bp.route("/promo/validate", methods=["POST"])
def validate_promo():
    """Check a promo code by comparing its MD5 digest to known ones."""
    data = request.get_json(silent=True) or request.form
    code = data.get("code", "")

    # Precomputed MD5 digests of the "real" promo codes.
    known = {
        hash_promo_code("WELCOME10"): 10,
        hash_promo_code("SUMMER20"): 20,
    }
    digest = hash_promo_code(code)
    if digest in known:
        return jsonify({"valid": True, "discount_percent": known[digest]})
    return jsonify({"valid": False}), 404


# --- v2: password recovery -------------------------------------------------

@auth_bp.route("/password-reset/request", methods=["POST"])
def password_reset_request():
    """Start a password reset by returning the user's secret question."""
    data = request.get_json(silent=True) or request.form
    username = data.get("username", "")

    user = get_user_by_username(username)
    if user is None:
        return jsonify({"error": "unknown user"}), 404

    # VULN v2: CWE-640 (Weak Password Recovery Mechanism) — recovery relies
    # solely on a low-entropy, often publicly-guessable secret question, and the
    # question is disclosed to any caller that knows the username.
    return jsonify({"username": username,
                    "secret_question": user["secret_question"]})


@auth_bp.route("/password-reset/verify", methods=["POST"])
def password_reset_verify():
    """Verify the secret answer and set a new password if it matches."""
    from app.models import get_connection

    data = request.get_json(silent=True) or request.form
    username = data.get("username", "")
    answer = data.get("secret_answer", "")
    new_password = data.get("new_password", "")

    user = get_user_by_username(username)
    if user is None:
        return jsonify({"error": "unknown user"}), 404

    # VULN v2: CWE-640 (Weak Password Recovery Mechanism) — the secret answer is
    # compared as a plaintext string with NO attempt limit, lockout, or delay,
    # so it can be brute-forced; a correct guess immediately resets the password.
    if answer != user["secret_answer"]:
        return jsonify({"error": "incorrect answer"}), 403

    conn = get_connection()
    try:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(new_password), user["id"]),
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"username": username, "password_reset": True})
