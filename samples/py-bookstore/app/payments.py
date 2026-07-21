"""Payment handling: save-card and the payment-gateway integration.

New in v2 (see README "Version 2 findings"):
  CWE-798  hardcoded payment-gateway API key
  CWE-522  card token persisted in plaintext (payment_cards table)

New in v3 (see README "Version 3 findings"):
  CWE-532  full card token written to the application log
  CWE-353  gateway webhook accepted without any signature/integrity check
"""

import logging

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

    # VULN v3: CWE-532 — the full, unmasked card token is written to the
    # application log. Sensitive payment data ends up in log files / aggregators
    # that are backed up and read by people who should never see raw tokens.
    logging.info("Saving card for user %s with token %s", user_id, card_token)

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


@payments_bp.route("/payment/webhook", methods=["POST"])
def payment_webhook():
    """Receive an asynchronous payment-status callback from the gateway."""
    data = request.get_json(silent=True) or request.form
    order_id = data.get("order_id")
    new_status = data.get("status", "paid")

    # VULN v3: CWE-353 (Missing Support for Integrity Check) — the webhook body
    # is trusted and acted upon with NO verification of the gateway's HMAC
    # signature. The `X-Signature` header (if any) is ignored entirely, so
    # anyone who can reach this endpoint can mark arbitrary orders as paid.
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE orders SET status = ? WHERE id = ?", (new_status, order_id)
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"order_id": order_id, "status": new_status})


# --- v4 additions ----------------------------------------------------------

# VULN v4: CWE-321 (Use of Hard-coded Cryptographic Key) — the key used to
# "protect" stored card data is a fixed constant embedded in source. It cannot
# be rotated without a code change and is identical across every deployment, so
# anyone with the source can decrypt every stored token.
CARD_ENCRYPTION_KEY = b"0123456789abcdef0123456789abcdef"


def _encrypt_token(token):
    """Reversibly obfuscate a card token with the hard-coded key."""
    import base64

    key = CARD_ENCRYPTION_KEY
    raw = token.encode()
    # XOR against the hard-coded key (reversible, keyed on a constant).
    xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
    return base64.b64encode(xored).decode()


@payments_bp.route("/payment/save-card-encrypted", methods=["POST"])
def save_card_encrypted():
    """Store a card token 'encrypted' with the hard-coded key."""
    data = request.get_json(silent=True) or request.form
    user_id = session.get("user_id") or data.get("user_id")
    card_token = data.get("card_token", "")

    protected = _encrypt_token(card_token)

    conn = get_connection()
    try:
        cur = conn.execute(
            "INSERT INTO payment_cards (user_id, card_token) VALUES (?, ?)",
            (user_id, protected),
        )
        conn.commit()
        card_id = cur.lastrowid
    finally:
        conn.close()

    return jsonify({"id": card_id, "user_id": user_id, "saved": True}), 201
