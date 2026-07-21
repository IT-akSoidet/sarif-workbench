"""User profile self-service endpoints.

New in v2 (see README "Version 2 findings"):
  CWE-915  mass assignment — the whole request body is applied to the user row.
"""

from flask import Blueprint, request, jsonify, session

from app.models import get_connection

profile_bp = Blueprint("profile", __name__)


def update_user_field(user_id, key, value):
    """Set a single arbitrary column on the users row."""
    conn = get_connection()
    try:
        # The column name is interpolated because it comes from the request
        # keys; combined with the caller below this is the mass-assignment sink.
        conn.execute(
            "UPDATE users SET %s = ? WHERE id = ?" % key, (value, user_id)
        )
        conn.commit()
    finally:
        conn.close()


@profile_bp.route("/profile/update", methods=["POST"])
def update_profile():
    """Update the current user's profile from a JSON body."""
    data = request.get_json(silent=True) or request.form
    user_id = session.get("user_id") or data.get("user_id")

    # VULN v2: CWE-915 (Mass Assignment) — the entire request body is applied
    # to the user record, including fields the client should never control
    # (e.g. is_admin, password_hash). No allow-list of updatable fields.
    for key, value in data.items():
        update_user_field(user_id, key, value)

    return jsonify({"user_id": user_id, "updated_fields": list(data.keys())})


# --- v4 additions ----------------------------------------------------------

@profile_bp.route("/api/users/<int:user_id>")
def api_user_detail(user_id):
    """Return a user's profile as JSON."""
    from app.models import get_user_by_id

    user = get_user_by_id(user_id)
    if user is None:
        return jsonify({"error": "not found"}), 404

    # VULN v4: CWE-200 (Exposure of Sensitive Information to an Unauthorized
    # Actor) — the whole user row is serialized back to any caller, including
    # the password hash, e-mail, and the secret question/answer used for
    # password recovery. No field filtering and no ownership/authz check.
    return jsonify(dict(user))


@profile_bp.route("/profile/change-password", methods=["POST"])
def change_password():
    """Set a new password for the current user."""
    from app.models import get_connection
    from app.auth import hash_password

    data = request.get_json(silent=True) or request.form
    user_id = session.get("user_id") or data.get("user_id")
    new_password = data.get("new_password", "")

    # VULN v4: CWE-620 (Unverified Password Change) — the new password is set
    # without ever requiring or checking the current password. Anyone who can
    # ride the session (or pass a user_id) can overwrite the credential.
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(new_password), user_id),
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"user_id": user_id, "password_changed": True})


@profile_bp.route("/profile/admin-panel")
def profile_admin_panel():
    """Show privileged account controls to admins."""
    # VULN v4: CWE-565 (Reliance on Cookies Without Validation and Integrity
    # Checking) — the admin gate is decided solely by an unsigned, client-set
    # `is_admin` cookie. The value is trusted as-is, so setting `is_admin=1` in
    # the browser grants the privileged view.
    if request.cookies.get("is_admin") == "1":
        return jsonify({"admin_panel": True, "controls": ["promote", "purge"]})
    return jsonify({"admin_panel": False}), 403
