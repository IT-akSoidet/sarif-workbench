"""Payment handling: save-card and the payment-gateway integration.

New in v2 (see README "Version 2 findings"):
  CWE-798  hardcoded payment-gateway API key
  CWE-522  card token persisted in plaintext (payment_cards table)
"""

from flask import Blueprint, request, jsonify, session

from app.models import get_connection

payments_bp = Blueprint("payments", __name__)


# VULN v2: CWE-798 — payment gateway API key hardcoded in source. A secret
# committed to the repository is exposed to anyone with read access and cannot
# be rotated without a code change. (Fake, non-working key for the study.)
PAYMENT_GATEWAY_API_KEY = "sk_live_51H8xJ2KZvQ9mF3nR7pL4tW6"


@payments_bp.route("/payment/save-card", methods=["POST"])
def save_card():
    """Store a card token supplied by the client for later charges."""
    data = request.get_json(silent=True) or request.form
    user_id = session.get("user_id") or data.get("user_id")
    card_token = data.get("card_token", "")

    conn = get_connection()
    try:
        # VULN v2: CWE-522 — the card token is written to the database in clear
        # text, with no encryption, hashing, or use of a secrets vault. Anyone
        # who reads the payment_cards table recovers usable card tokens.
        cur = conn.execute(
            "INSERT INTO payment_cards (user_id, card_token) VALUES (?, ?)",
            (user_id, card_token),
        )
        conn.commit()
        card_id = cur.lastrowid
    finally:
        conn.close()

    return jsonify({"id": card_id, "user_id": user_id, "saved": True}), 201
