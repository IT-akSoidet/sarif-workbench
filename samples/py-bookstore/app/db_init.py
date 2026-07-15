"""Create tables and seed the database.

Run with:  python -m app.db_init   (or `make seed`).

Seeds: 3 users (one admin), 12 books, a few starter reviews.
NOTE: passwords are stored as unsalted MD5 to match the auth.py findings
(CWE-327). This is intentional for the study.
"""

import hashlib
import sqlite3

from app.config import ActiveConfig


SCHEMA = """
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS books;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS reviews;

CREATE TABLE users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    email           TEXT,
    is_admin        INTEGER NOT NULL DEFAULT 0,
    secret_question TEXT,
    secret_answer   TEXT
);

CREATE TABLE books (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    author      TEXT NOT NULL,
    description TEXT,
    price       REAL NOT NULL,
    cover_url   TEXT
);

CREATE TABLE orders (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    book_id     INTEGER NOT NULL,
    total_price REAL NOT NULL,
    discount    REAL NOT NULL DEFAULT 0,
    status      TEXT NOT NULL DEFAULT 'created',
    created_at  TEXT NOT NULL
);

CREATE TABLE reviews (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    book_id    INTEGER NOT NULL,
    user_id    INTEGER NOT NULL,
    text       TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


# v2 additions: extra schema created alongside the v1 tables (the existing
# SCHEMA above is left untouched). See app/payments.py.
SCHEMA_V2 = """
DROP TABLE IF EXISTS payment_cards;

CREATE TABLE payment_cards (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    card_token TEXT NOT NULL
);
"""


def md5(value):
    # Unsalted MD5 — matches the registration hashing finding in auth.py.
    return hashlib.md5(value.encode()).hexdigest()


USERS = [
    # username, password, email, is_admin, secret_question, secret_answer
    ("admin", "admin123", "admin@bookstore.local", 1,
     "Favourite color?", "blue"),
    ("alice", "password1", "alice@example.com", 0,
     "First pet?", "rex"),
    ("bob", "hunter2", "bob@example.com", 0,
     "City of birth?", "prague"),
]

BOOKS = [
    ("The Pragmatic Programmer", "Andrew Hunt", "Classic on software craft.",
     39.99, "https://covers.local/pragmatic.jpg"),
    ("Clean Code", "Robert C. Martin", "A handbook of agile craftsmanship.",
     34.50, "https://covers.local/cleancode.jpg"),
    ("The Mythical Man-Month", "Fred Brooks", "Essays on software engineering.",
     29.00, "https://covers.local/mmm.jpg"),
    ("Refactoring", "Martin Fowler", "Improving the design of existing code.",
     44.99, "https://covers.local/refactoring.jpg"),
    ("Design Patterns", "Erich Gamma", "Elements of reusable OO software.",
     49.99, "https://covers.local/gof.jpg"),
    ("Introduction to Algorithms", "Thomas H. Cormen", "CLRS, the algorithms bible.",
     79.99, "https://covers.local/clrs.jpg"),
    ("Structure and Interpretation of Computer Programs", "Harold Abelson",
     "SICP.", 55.00, "https://covers.local/sicp.jpg"),
    ("Code Complete", "Steve McConnell", "A practical guide to construction.",
     42.00, "https://covers.local/codecomplete.jpg"),
    ("The Art of Computer Programming", "Donald Knuth", "TAOCP volume set.",
     199.99, "https://covers.local/taocp.jpg"),
    ("Effective Python", "Brett Slatkin", "90 ways to write better Python.",
     38.75, "https://covers.local/effectivepython.jpg"),
    ("Fluent Python", "Luciano Ramalho", "Clear, concise, effective programming.",
     52.30, "https://covers.local/fluentpython.jpg"),
    ("Programming Pearls", "Jon Bentley", "Insight into problem solving.",
     27.50, "https://covers.local/pearls.jpg"),
]

REVIEWS = [
    # book_id, user_id, text
    (1, 2, "Absolutely loved it, changed how I code."),
    (2, 3, "Solid principles, a must-read."),
    (5, 2, "Timeless patterns, still relevant today."),
]


def init_db():
    conn = sqlite3.connect(ActiveConfig.DATABASE)
    try:
        conn.executescript(SCHEMA)
        conn.executescript(SCHEMA_V2)  # v2: payment_cards table

        for username, password, email, is_admin, question, answer in USERS:
            conn.execute(
                """INSERT INTO users
                   (username, password_hash, email, is_admin,
                    secret_question, secret_answer)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (username, md5(password), email, is_admin, question, answer),
            )

        for title, author, description, price, cover in BOOKS:
            conn.execute(
                """INSERT INTO books (title, author, description, price, cover_url)
                   VALUES (?, ?, ?, ?, ?)""",
                (title, author, description, price, cover),
            )

        for book_id, user_id, text in REVIEWS:
            conn.execute(
                """INSERT INTO reviews (book_id, user_id, text, created_at)
                   VALUES (?, ?, ?, datetime('now'))""",
                (book_id, user_id, text),
            )

        conn.commit()
        print("Database seeded: %d users, %d books, %d reviews."
              % (len(USERS), len(BOOKS), len(REVIEWS)))
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
