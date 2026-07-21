"""Search & lookup endpoints.

All four database accesses here build SQL by string concatenation / f-strings
from user input on purpose (CWE-89). Parameterised queries are deliberately
NOT used in this module.
"""

from flask import Blueprint, request, jsonify, render_template

from app.models import get_connection

search_bp = Blueprint("search", __name__)


@search_bp.route("/search")
def search_books():
    """Search books by title."""
    title = request.args.get("q", "")

    conn = get_connection()
    try:
        # VULN: CWE-89 — user input concatenated straight into the SQL string.
        query = "SELECT * FROM books WHERE title LIKE '%" + title + "%'"
        rows = conn.execute(query).fetchall()
    finally:
        conn.close()

    books = [dict(r) for r in rows]
    if request.args.get("format") == "json":
        return jsonify(books)
    return render_template("search.html", books=books, query=title)


@search_bp.route("/books/by-author")
def books_by_author():
    """Filter books by author name."""
    author = request.args.get("author", "")

    conn = get_connection()
    try:
        # VULN: CWE-89 — f-string interpolation of user input into SQL.
        query = f"SELECT * FROM books WHERE author = '{author}'"
        rows = conn.execute(query).fetchall()
    finally:
        conn.close()

    return jsonify([dict(r) for r in rows])


@search_bp.route("/reviews/search")
def search_reviews_by_book():
    """Look up reviews for a given book id."""
    book_id = request.args.get("book_id", "")

    conn = get_connection()
    try:
        # VULN: CWE-89 — book_id taken from the query string is concatenated
        # directly, allowing injection despite "looking" numeric.
        query = "SELECT * FROM reviews WHERE book_id = " + book_id
        rows = conn.execute(query).fetchall()
    finally:
        conn.close()

    return jsonify([dict(r) for r in rows])


@search_bp.route("/promo/lookup")
def lookup_promo():
    """Look up a promo code row by its raw code value."""
    code = request.args.get("code", "")

    conn = get_connection()
    try:
        # VULN: CWE-89 — promo code interpolated into SQL via f-string.
        # (promo_codes may not exist as a table; the tainted query is the point.)
        query = f"SELECT * FROM promo_codes WHERE code = '{code}'"
        try:
            rows = conn.execute(query).fetchall()
        except Exception as exc:  # table may be absent; injection sink still present
            # VULN v4: CWE-550/CWE-209 (Server-generated Error Message Containing
            # Sensitive Information) — the raw DB exception text AND the fully
            # built SQL query are returned to the client, disclosing schema and
            # internal query structure.
            return jsonify({"error": str(exc), "query": query}), 400
    finally:
        conn.close()

    return jsonify([dict(r) for r in rows])
