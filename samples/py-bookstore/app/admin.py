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
