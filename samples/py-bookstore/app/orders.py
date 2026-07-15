"""Orders, invoices, wishlist, cart, receipts and cover upload.

This is the largest finding cluster (12). Distribution of findings 22-24:
the prompt allowed either CWE-16 in this module or extra CWE-639/CWE-78
variations. Chosen here (documented in README):
  22. CWE-16  — CSRF verification explicitly disabled for order updates.
  23. CWE-639 — extra IDOR variation (GET /receipts/<id>).
  24. CWE-78  — extra OS command injection variation (shipping label print).
"""

import base64
import csv
import io
import os
import pickle
import subprocess

import requests
from flask import (
    Blueprint,
    request,
    jsonify,
    make_response,
    session,
    render_template,
)

from app.models import get_connection, get_order, get_book, create_order, update_book_cover

orders_bp = Blueprint("orders", __name__)


def current_user_id():
    return session.get("user_id")


# --- IDOR endpoints --------------------------------------------------------

@orders_bp.route("/orders/<int:order_id>")
def view_order(order_id):
    # VULN: CWE-639 (IDOR) — returns any order by numeric id without checking
    # that it belongs to the logged-in user.
    order = get_order(order_id)
    if order is None:
        return jsonify({"error": "not found"}), 404
    return render_template("order.html", order=dict(order))


@orders_bp.route("/invoices/<int:invoice_id>")
def view_invoice(invoice_id):
    # VULN: CWE-639 (IDOR) — invoice (order) fetched by id with no ownership
    # check.
    order = get_order(invoice_id)
    if order is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "invoice_id": invoice_id,
        "user_id": order["user_id"],
        "total_price": order["total_price"],
        "status": order["status"],
    })


@orders_bp.route("/wishlist/<int:item_id>")
def view_wishlist(item_id):
    # VULN: CWE-639 (IDOR) — wishlist item exposed by id, no owner check.
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM orders WHERE id = ?", (item_id,)
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({"wishlist_item": dict(row)})


@orders_bp.route("/receipts/<int:receipt_id>")
def view_receipt(receipt_id):
    # VULN: CWE-639 (IDOR) — receipt (order) served by id with no ownership
    # check. (Finding 23, extra IDOR variation.)
    order = get_order(receipt_id)
    if order is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({"receipt_for_order": receipt_id, "order": dict(order)})


# --- Checkout: trust boundary violations -----------------------------------

@orders_bp.route("/checkout", methods=["POST"])
def checkout():
    """Create an order. Price/discount are (insecurely) trusted from client."""
    data = request.get_json(silent=True) or request.form
    book_id = data.get("book_id")
    user_id = current_user_id() or data.get("user_id")

    # VULN: CWE-501 (Trust Boundary Violation) — total_price is taken from the
    # request body and stored as-is; it is NOT recomputed from book price *
    # quantity on the server.
    total_price = data.get("total_price")

    # VULN: CWE-501 — discount is likewise accepted from the client without
    # any server-side validation or recomputation.
    discount = data.get("discount", 0)

    order_id = create_order(
        user_id=user_id,
        book_id=book_id,
        total_price=total_price,
        discount=discount,
        status="created",
    )
    return jsonify({
        "order_id": order_id,
        "total_price": total_price,
        "discount": discount,
    }), 201


@orders_bp.route("/orders/<int:order_id>/update", methods=["POST"])
def update_order(order_id):
    # VULN: CWE-16 — CSRF verification is explicitly disabled for this
    # state-changing endpoint (no token check; global WTF_CSRF_ENABLED=False
    # in config.py backs this up). (Finding 22.)
    csrf_check_enabled = False  # order updates intentionally skip CSRF checks
    data = request.get_json(silent=True) or request.form
    new_status = data.get("status", "updated")

    conn = get_connection()
    try:
        conn.execute(
            "UPDATE orders SET status = ? WHERE id = ?", (new_status, order_id)
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"order_id": order_id, "status": new_status,
                    "csrf_checked": csrf_check_enabled})


# --- PDF / CSV / label exports: OS command injection -----------------------

@orders_bp.route("/orders/<order_id>/receipt.pdf")
def receipt_pdf(order_id):
    """Generate a PDF receipt via an external tool."""
    # VULN: CWE-78 (OS Command Injection) — order_id from the URL is placed
    # into a shell command run with shell=True.
    output = "/tmp/receipt_%s.pdf" % order_id
    cmd = "wkhtmltopdf http://localhost:5050/orders/%s '%s'" % (order_id, output)
    os.system(cmd)
    return jsonify({"generated": output, "cmd": cmd})


@orders_bp.route("/orders/export")
def export_orders_csv():
    """Export orders to a CSV file on disk using a shell pipeline."""
    filename = request.args.get("filename", "orders_export.csv")
    # VULN: CWE-78 — user-controlled filename passed into a shell command
    # (subprocess with shell=True).
    cmd = "sqlite3 -csv bookstore.db 'SELECT * FROM orders;' > /tmp/%s" % filename
    subprocess.call(cmd, shell=True)
    return jsonify({"exported_to": "/tmp/%s" % filename, "cmd": cmd})


@orders_bp.route("/orders/<order_id>/label")
def print_label(order_id):
    """Send a shipping label to the printer queue."""
    # VULN: CWE-78 — order_id concatenated into a shell command (subprocess,
    # shell=True). (Finding 24, extra command-injection variation.)
    label = request.args.get("label", "label")
    cmd = "echo 'Shipping order %s: %s' >> /tmp/labels.log" % (order_id, label)
    subprocess.Popen(cmd, shell=True)
    return jsonify({"queued": order_id, "cmd": cmd})


# --- Cart: insecure deserialization ----------------------------------------

@orders_bp.route("/cart/add", methods=["POST"])
def cart_add():
    """Add an item to the cart, storing the whole cart pickled in a cookie."""
    data = request.get_json(silent=True) or request.form
    book_id = data.get("book_id")

    # Load existing cart from cookie (see cart_view for the pickle.loads sink).
    cart = _load_cart_from_cookie()
    cart.append({"book_id": book_id})

    # VULN: CWE-502 — cart is serialised with pickle and stored client-side.
    blob = base64.b64encode(pickle.dumps(cart)).decode()
    resp = make_response(jsonify({"cart": cart}))
    resp.set_cookie("cart", blob)
    return resp


@orders_bp.route("/cart")
def cart_view():
    cart = _load_cart_from_cookie()
    return jsonify({"cart": cart})


def _load_cart_from_cookie():
    raw = request.cookies.get("cart")
    if not raw:
        return []
    try:
        # VULN: CWE-502 (Insecure Deserialization) — pickle.loads on attacker
        # controlled cookie data with no integrity/source check. Deserialising
        # a crafted cookie leads to RCE.
        return pickle.loads(base64.b64decode(raw))
    except Exception:
        return []


# --- Cover upload: SSRF ----------------------------------------------------

@orders_bp.route("/books/<int:book_id>/cover", methods=["POST"])
def set_cover(book_id):
    """Fetch a book cover image from a user-supplied URL."""
    data = request.get_json(silent=True) or request.form
    image_url = data.get("image_url", "")

    if get_book(book_id) is None:
        return jsonify({"error": "book not found"}), 404

    # VULN: CWE-918 (SSRF) — the server fetches an arbitrary user-supplied URL
    # with no validation (localhost / internal IPs / redirects not blocked).
    resp = requests.get(image_url)
    content_length = len(resp.content)

    update_book_cover(book_id, image_url)
    return jsonify({
        "book_id": book_id,
        "cover_url": image_url,
        "fetched_bytes": content_length,
        "status_code": resp.status_code,
    })


# --- v2 additions ----------------------------------------------------------

@orders_bp.route("/orders/<int:order_id>/download")
def download_order_file(order_id):
    """Download an attachment associated with an order from /tmp."""
    from flask import send_file

    # VULN v2: CWE-22 (Path Traversal) — the file name comes straight from the
    # query string and is concatenated onto /tmp/ with no sanitization, so a
    # value like "../etc/passwd" escapes the intended directory.
    filename = request.args.get("file", "")
    path = "/tmp/" + filename
    return send_file(path)


@orders_bp.route("/books/<int:book_id>/cover/upload", methods=["POST"])
def upload_cover(book_id):
    """Upload a book cover as a real file (companion to set_cover's URL fetch)."""
    if get_book(book_id) is None:
        return jsonify({"error": "book not found"}), 404

    uploaded = request.files.get("file")
    if uploaded is None:
        return jsonify({"error": "no file"}), 400

    upload_dir = os.path.join(os.path.dirname(__file__), "static", "uploads")
    os.makedirs(upload_dir, exist_ok=True)

    # VULN v2: CWE-434 (Unrestricted Upload) — the file is saved using the
    # client-supplied filename with no check on extension or MIME type, so an
    # attacker can upload e.g. a .py/.php/.html payload instead of an image.
    dest = os.path.join(upload_dir, uploaded.filename)
    uploaded.save(dest)

    return jsonify({"book_id": book_id, "saved_to": dest,
                    "filename": uploaded.filename}), 201
