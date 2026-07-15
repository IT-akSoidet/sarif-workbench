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
