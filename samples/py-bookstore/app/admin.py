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
