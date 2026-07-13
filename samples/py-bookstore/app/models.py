"""Data access helpers over a raw sqlite3 database.

Only thin row/connection helpers live here. The intentional SQL-injection
findings live in search.py (per the vulnerability map); this module uses
parameterised queries so the injection findings stay concentrated where the
study expects them.

Schema
------
User:   id, username, password_hash, email, is_admin, secret_question, secret_answer
Book:   id, title, author, description, price, cover_url
Order:  id, user_id, book_id, total_price, discount, status, created_at
Review: id, book_id, user_id, text, created_at
"""

import sqlite3

from app.config import ActiveConfig


def get_connection():
    """Open a new sqlite3 connection with row access by name."""
    conn = sqlite3.connect(ActiveConfig.DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# --- Users -----------------------------------------------------------------

def get_user_by_username(username):
    conn = get_connection()
    try:
        cur = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        )
        return cur.fetchone()
    finally:
        conn.close()


def get_user_by_id(user_id):
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cur.fetchone()
    finally:
        conn.close()


def create_user(username, password_hash, email, secret_question, secret_answer):
    conn = get_connection()
    try:
        cur = conn.execute(
            """INSERT INTO users
               (username, password_hash, email, is_admin,
                secret_question, secret_answer)
               VALUES (?, ?, ?, 0, ?, ?)""",
            (username, password_hash, email, secret_question, secret_answer),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


# --- Books -----------------------------------------------------------------

def get_book(book_id):
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM books WHERE id = ?", (book_id,))
        return cur.fetchone()
    finally:
        conn.close()


def list_books():
    conn = get_connection()
    try:
        return conn.execute("SELECT * FROM books ORDER BY id").fetchall()
    finally:
        conn.close()


def update_book_cover(book_id, cover_url):
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE books SET cover_url = ? WHERE id = ?", (cover_url, book_id)
        )
        conn.commit()
    finally:
        conn.close()


# --- Orders ----------------------------------------------------------------

def get_order(order_id):
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
        return cur.fetchone()
    finally:
        conn.close()


def create_order(user_id, book_id, total_price, discount, status):
    conn = get_connection()
    try:
        cur = conn.execute(
            """INSERT INTO orders
               (user_id, book_id, total_price, discount, status, created_at)
               VALUES (?, ?, ?, ?, ?, datetime('now'))""",
            (user_id, book_id, total_price, discount, status),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


# --- Reviews ---------------------------------------------------------------

def add_review(book_id, user_id, text):
    conn = get_connection()
    try:
        conn.execute(
            """INSERT INTO reviews (book_id, user_id, text, created_at)
               VALUES (?, ?, ?, datetime('now'))""",
            (book_id, user_id, text),
        )
        conn.commit()
    finally:
        conn.close()


def list_reviews(book_id):
    conn = get_connection()
    try:
        return conn.execute(
            "SELECT * FROM reviews WHERE book_id = ? ORDER BY id DESC",
            (book_id,),
        ).fetchall()
    finally:
        conn.close()
