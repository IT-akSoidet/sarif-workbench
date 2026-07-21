"""Admin panel: manage books. Renders product description without escaping."""

from flask import Blueprint, request, render_template_string, jsonify

from app.models import list_books, get_book

admin_bp = Blueprint("admin", __name__)


# Inline admin template. The description is injected with the `|safe` filter.
ADMIN_BOOK_TEMPLATE = """
<!doctype html>
<title>Admin — {{ book.title }}</title>
<h1>{{ book.title }}</h1>
<p>Author: {{ book.author }}</p>
<p>Price: {{ book.price }}</p>
<div class="description">
  <!-- VULN: CWE-79 — product description rendered unescaped in admin panel -->
  {{ book.description|safe }}
</div>
"""


@admin_bp.route("/admin/books")
def admin_books():
    books = [dict(b) for b in list_books()]
    return jsonify({"books": books})


@admin_bp.route("/admin/books/<int:book_id>")
def admin_book_detail(book_id):
    book = get_book(book_id)
    if book is None:
        return jsonify({"error": "not found"}), 404
    # VULN: CWE-79 — description passed through `|safe`, disabling escaping
    # in the admin view (stored XSS reflected to the admin).
    return render_template_string(ADMIN_BOOK_TEMPLATE, book=dict(book))


# --- v2 additions ----------------------------------------------------------

@admin_bp.route("/admin/books/bulk-delete", methods=["POST"])
def admin_books_bulk_delete():
    """Delete every book whose id is in the supplied list."""
    from app.models import get_connection

    # VULN v2: CWE-306 (Missing Authentication for Critical Function) — this
    # destructive admin endpoint performs no authentication or is_admin check
    # whatsoever (no @login_required, no session inspection); any anonymous
    # caller can wipe the catalog.
    data = request.get_json(silent=True) or request.form
    ids = data.get("ids") or []
    if isinstance(ids, str):
        ids = [i for i in ids.split(",") if i]

    conn = get_connection()
    try:
        for book_id in ids:
            conn.execute("DELETE FROM books WHERE id = ?", (book_id,))
        conn.commit()
    finally:
        conn.close()

    return jsonify({"deleted": ids, "count": len(ids)})


@admin_bp.route("/admin/books/import", methods=["POST"])
def admin_books_import():
    """Bulk-import books from an uploaded XML document."""
    import xml.etree.ElementTree as ET

    uploaded = request.files.get("file")
    if uploaded is None:
        return jsonify({"error": "no file"}), 400

    # VULN v2: CWE-611 (XXE) — the XML is parsed with the stdlib
    # xml.etree.ElementTree parser, which resolves external entities and does
    # not use defusedxml. A document with a crafted <!DOCTYPE ... SYSTEM ...>
    # can read local files or trigger SSRF.
    tree = ET.parse(uploaded)
    root = tree.getroot()

    titles = [node.findtext("title") for node in root.findall("book")]
    return jsonify({"imported": titles, "count": len(titles)})


# --- v3 additions ----------------------------------------------------------

@admin_bp.route("/admin/promote", methods=["POST"])
def admin_promote_user():
    """Grant admin rights to a user (privileged operation)."""
    from app.models import get_connection

    # VULN v3: CWE-863 (Incorrect Authorization) — the authorization decision
    # trusts a client-supplied request header instead of the server-side
    # session / stored role. Any caller can send `X-Is-Admin: true` and pass
    # the check, so the gate is trivially bypassed.
    if request.headers.get("X-Is-Admin", "").lower() != "true":
        return jsonify({"error": "forbidden"}), 403

    data = request.get_json(silent=True) or request.form
    target_id = data.get("user_id")

    conn = get_connection()
    try:
        conn.execute(
            "UPDATE users SET is_admin = 1 WHERE id = ?", (target_id,)
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"user_id": target_id, "is_admin": True})


@admin_bp.route("/admin/books/preview", methods=["POST"])
def admin_book_preview():
    """Render a live preview of a book blurb supplied by the editor."""
    data = request.get_json(silent=True) or request.form
    blurb = data.get("blurb", "")

    # VULN v3: CWE-94 (Code Injection / SSTI) — user-controlled text is placed
    # directly into the template string compiled by render_template_string.
    # Jinja2 evaluates `{{ ... }}` in the input, so a payload like
    # `{{ 7*7 }}` or `{{ config }}` executes server-side (Server-Side Template
    # Injection leading to RCE).
    template = "<h1>Preview</h1><div>" + blurb + "</div>"
    return render_template_string(template)


@admin_bp.route("/admin/books/purge", methods=["POST"])
def admin_books_purge():
    """Permanently delete the entire book catalog."""
    from app.models import get_connection

    # VULN v3: CWE-778 (Insufficient Logging) — this destructive, security
    # relevant action leaves no audit trail at all: there is no logger call
    # recording who purged the catalog, when, or from where. (Explicit finding,
    # distinct from the v1 CWE-778 "by absence" marker in auth.py.)
    conn = get_connection()
    try:
        conn.execute("DELETE FROM books")
        conn.commit()
    finally:
        conn.close()

    return jsonify({"purged": True})


@admin_bp.route("/admin/books/import.yaml", methods=["POST"])
def admin_books_import_yaml():
    """Bulk-import books from an uploaded YAML document."""
    import yaml

    uploaded = request.files.get("file")
    if uploaded is None:
        return jsonify({"error": "no file"}), 400

    # VULN v3: CWE-1395 / CWE-502 — the YAML is parsed with the unsafe
    # yaml.load() full loader (PyYAML 5.3.1, CVE-2020-14343). A crafted document
    # using `!!python/object/apply:` tags executes arbitrary code on load.
    parsed = yaml.load(uploaded.read())
    titles = [b.get("title") for b in (parsed or [])]
    return jsonify({"imported": titles, "count": len(titles)})


# --- v4 additions ----------------------------------------------------------

@admin_bp.route("/admin/users")
def admin_list_users():
    """List every user account."""
    from app.models import get_connection

    # VULN v4: CWE-862 (Missing Authorization) — this admin-only listing has no
    # authentication or authorization check at all (no session inspection, no
    # is_admin gate). Any anonymous caller dumps the full user table, including
    # password hashes and secret answers.
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM users").fetchall()
    finally:
        conn.close()
    return jsonify([dict(r) for r in rows])


@admin_bp.route("/admin/report/<name>")
def admin_report(name):
    """Run a named reporting routine from the reports module."""
    import app.models as models

    # VULN v4: CWE-470 (Unsafe Reflection) — the callable to invoke is selected
    # by a user-controlled name via getattr with no allow-list, so an attacker
    # can reach arbitrary attributes/functions of the module (e.g.
    # /admin/report/get_connection) rather than only intended reports.
    func = getattr(models, name)
    result = func()
    return jsonify({"report": name, "rows": len(list(result))})


@admin_bp.route("/admin/metrics")
def admin_metrics():
    """Expose internal metrics to operators on the local network."""
    # VULN v4: CWE-291 (Reliance on IP Address for Authentication) — access is
    # granted purely because the request appears to originate from localhost.
    # `remote_addr` is trivially spoofable behind a proxy / via X-Forwarded-For,
    # so this is not a real authentication decision.
    if request.remote_addr in ("127.0.0.1", "::1"):
        return jsonify({"secret_metrics": {"revenue": 12345, "users": 3}})
    return jsonify({"error": "forbidden"}), 403


@admin_bp.route("/admin/plugins/install", methods=["POST"])
def admin_install_plugin():
    """Install a plugin by fetching and executing it from a URL."""
    import requests

    data = request.get_json(silent=True) or request.form
    plugin_url = data.get("url", "")

    # VULN v4: CWE-494 (Download of Code Without Integrity Check) — remote code
    # is fetched over the network and executed with no signature, checksum, or
    # TLS-pinning verification, so a MITM or malicious host achieves RCE.
    code = requests.get(plugin_url).text
    exec(code, {})
    return jsonify({"installed_from": plugin_url})


@admin_bp.route("/debug/env")
def debug_env():
    """Dump the process environment for debugging."""
    import os

    # VULN v4: CWE-526 (Exposure of Sensitive Information Through Environmental
    # Variables) — the entire process environment (which routinely holds
    # secrets, DB URLs, API keys) is serialized straight to the HTTP response.
    return jsonify(dict(os.environ))
