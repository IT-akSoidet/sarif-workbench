"""Book reviews. Review text is rendered without escaping (stored XSS)."""

from flask import Blueprint, request, jsonify, render_template, session

from app.models import add_review, list_reviews, get_book

reviews_bp = Blueprint("reviews", __name__)


@reviews_bp.route("/books/<int:book_id>/reviews", methods=["POST"])
def create_review(book_id):
    data = request.get_json(silent=True) or request.form
    text = data.get("text", "")
    user_id = session.get("user_id", 0)

    if get_book(book_id) is None:
        return jsonify({"error": "book not found"}), 404

    # Stored verbatim; it is rendered unescaped in book.html (see the |safe
    # filter there) — that is the CWE-79 sink.
    add_review(book_id, user_id, text)
    return jsonify({"status": "created"}), 201


@reviews_bp.route("/books/<int:book_id>")
def book_detail(book_id):
    book = get_book(book_id)
    if book is None:
        return jsonify({"error": "not found"}), 404
    reviews = [dict(r) for r in list_reviews(book_id)]
    # VULN: CWE-79 — review text is rendered via `{{ r.text|safe }}` in
    # book.html, bypassing Jinja2 autoescaping (stored XSS).
    return render_template("book.html", book=dict(book), reviews=reviews)
