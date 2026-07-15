# py-bookstore — intentionally vulnerable Flask app (SAST benchmark)

A **deliberately insecure** Flask + SQLite bookstore, built as a controlled
reference set of known CWEs in fixed locations. Its purpose is to compare the
output of SAST analyzers (**Bandit, Semgrep, CodeQL**) inside SARIF Workbench.

> ⚠️ This is **not** a product and must never be exposed to a real network.
> Every intentional weakness is marked in source with a `# VULN: CWE-XXX`
> comment. Do not "fix" them — the vulnerabilities are the point.

- **Stack:** Flask + raw `sqlite3` + Docker
- **Port:** `5050` (not 5000)
- **DB layer:** plain `sqlite3` (chosen so the CWE-89 injection sinks read as
  natural string-built SQL for the analyzers)

## Run

```bash
make run        # docker compose up --build  → http://localhost:5050
make seed       # recreate + reseed the SQLite database
make scan       # semgrep scan --config auto --sarif --output report.sarif .
```

Without Docker (local venv):

```bash
pip install -r requirements.txt
python -m app.db_init          # seed
python -m app.main             # serve on :5050
```

Seed data: 3 users (`admin` is `is_admin=1`), 12 books, 3 starter reviews.
Seed logins: `admin/admin123`, `alice/password1`, `bob/hunter2` (passwords
stored as unsalted MD5, per the CWE-327 finding).

## Vulnerability map (30 findings)

Line numbers are approximate (the `# VULN:` marker line) and will shift if the
files are edited; grep `VULN: CWE` to re-locate.

| # | CWE | File | ~Line | Description |
|---|-----|------|-------|-------------|
| 1 | CWE-327 | app/auth.py | 26 | Registration password hashed with unsalted `hashlib.md5()` |
| 2 | CWE-327 | app/auth.py | 31 | "Remember me" token = MD5(user_id + timestamp) |
| 3 | CWE-327 | app/auth.py | 38 | Promo code validity checked via MD5 digest |
| 4 | CWE-347 | app/auth.py | 60 | Access-token JWT decoded with `verify_signature=False` (accepts `alg:none`) |
| 5 | CWE-347 | app/auth.py | 67 | Refresh-token JWT decoded without signature verification |
| 6 | CWE-613 | app/auth.py | 126 | Session hint cookie set with no `max_age`/expiry |
| 7 | CWE-613 | app/auth.py | 132 | "Remember me" cookie set with no `max_age`/expiry |
| 8 | CWE-307 | app/auth.py | 100 | Login endpoint has no rate limit / lockout / delay / CAPTCHA |
| — | CWE-778 | app/auth.py | 109 | **By absence:** failed logins are never logged (no logger on the failure path) |
| 9 | CWE-89 | app/search.py | 22 | SQLi — book title search, string concatenation |
| 10 | CWE-89 | app/search.py | 41 | SQLi — filter by author, f-string |
| 11 | CWE-89 | app/search.py | 57 | SQLi — review lookup by `book_id`, concatenation |
| 12 | CWE-89 | app/search.py | 74 | SQLi — promo code lookup, f-string |
| 13 | CWE-639 | app/orders.py | 41 | IDOR — `GET /orders/<id>`, no ownership check |
| 14 | CWE-639 | app/orders.py | 51 | IDOR — `GET /invoices/<id>`, no ownership check |
| 15 | CWE-639 | app/orders.py | 66 | IDOR — `GET /wishlist/<id>`, no ownership check |
| 16 | CWE-501 | app/orders.py | 98 | Trust boundary — `total_price` taken from request body, not recomputed |
| 17 | CWE-501 | app/orders.py | 103 | Trust boundary — `discount` accepted from client, not validated |
| 18 | CWE-78 | app/orders.py | 147 | OS command injection — PDF receipt via `os.system()` (order_id) |
| 19 | CWE-78 | app/orders.py | 159 | OS command injection — CSV export via `subprocess(..., shell=True)` (filename) |
| 20 | CWE-502 | app/orders.py | 207 | Insecure deserialization — cart `pickle.loads()` from cookie (dumps at 189) |
| 21 | CWE-918 | app/orders.py | 226 | SSRF — `requests.get(image_url)` on unvalidated user URL |
| 22 | CWE-16 | app/orders.py | 123 | CSRF verification explicitly disabled for order-update route |
| 23 | CWE-639 | app/orders.py | 81 | IDOR (extra variation) — `GET /receipts/<id>`, no ownership check |
| 24 | CWE-78 | app/orders.py | 169 | OS command injection (extra variation) — shipping-label `subprocess(..., shell=True)` |
| 25 | CWE-79 | app/reviews.py / templates/book.html | 31 / 19 | Stored XSS — review text via `{{ r.text\|safe }}` |
| 26 | CWE-79 | app/admin.py | 18 / 35 | Stored XSS — product description via `{{ book.description\|safe }}` |
| 27 | CWE-79 | app/templates/base.html | 16 | Reflected/stored XSS — `{{ username\|safe }}` in header |
| 28 | CWE-16 | app/config.py | 30 | `DEBUG=True` in the class named `ProductionConfig` |
| 29 | CWE-16 | app/config.py | 9 | Default unchanged `SECRET_KEY = "dev-secret-key-change-me"` |
| 30 | CWE-942 | app/config.py / app/main.py | (CORS_ORIGINS) / 22 | Permissive CORS `origins="*"` (value in config, sink in `main.py`) |
| + | CWE-1104 | requirements.txt | 1 | Pinned old `Flask==1.1.4` and `Pillow==8.0.0` |

## How findings 22–24 were distributed (per the prompt's instruction)

The prompt allowed the last three `orders.py` findings to be either a CWE-16
configuration issue in this module or extra CWE-639/CWE-78 variations, as long
as the module total stayed at 12. Chosen distribution:

- **22 — CWE-16:** CSRF verification explicitly disabled on the order-update
  endpoint (`/orders/<id>/update`), backed by the global
  `WTF_CSRF_ENABLED = False` in `config.py`.
- **23 — CWE-639:** an extra IDOR variation, `GET /receipts/<id>`.
- **24 — CWE-78:** an extra OS command-injection variation, the shipping-label
  printer route.

This keeps `orders.py` at exactly 12 findings while the three dedicated
`config.py` findings (28–30) remain separate.

## CWE-1104 — vulnerable components

`requirements.txt` pins **`Flask==1.1.4`** (old Werkzeug/Jinja2 stack) and
**`Pillow==8.0.0`**. Confirmed illustrative CVEs:

- **Flask 1.1.4 / Werkzeug 1.0.x — CVE-2023-30861:** session cookie leakage due
  to a missing `Vary: Cookie` header (a cached response carrying one user's
  cookie can be served to another user).
- **Pillow 8.0.0 — CVE-2021-25293 (primary):** out-of-bounds / buffer overflow
  in `Convert.c`.
  - Additional: CVE-2021-25287, CVE-2021-25288 (OOB read in J2K),
    CVE-2021-25289, CVE-2021-25290, CVE-2021-27921, CVE-2021-27922,
    CVE-2021-27923 (DoS via crafted images).

## Notes / deviations from the spec

1. **CWE-942 sink location.** The permissive-CORS value (`CORS_ORIGINS = "*"`)
   lives in `config.py` as requested, but the actual `flask_cors.CORS(app, …)`
   call — the thing an analyzer flags — is in `main.py:create_app()` because it
   needs the Flask app instance. Both are marked.
2. **Bonus marker.** `config.py` also disables CSRF globally
   (`WTF_CSRF_ENABLED = False`, CWE-16). This is an *additional* marker
   supporting finding 22, not a substitute for any of the 30.
3. **DB layer.** Raw `sqlite3` is used everywhere; `models.py` deliberately uses
   parameterised queries so the four CWE-89 sinks stay concentrated in
   `search.py` exactly where the study expects them.
4. All findings are `vulnerable`-only; no safe/fixed variants are included yet
   (that is a later task).

## Version 2 findings (10 new, additive)

Version 2 adds **10 more, separate vulnerabilities** on top of the 30 v1
findings. **None of the 30 v1 findings were modified** — v2 is pure addition
(new functions, new routes, two new files, plus one added `CSRFProtect(app)`
line in `main.py`). Each v2 finding is marked with a `# VULN v2: CWE-XXX`
comment so reviewers can tell the new batch apart from the original 30.

Line numbers are approximate (grep `VULN v2: CWE` to re-locate).

| # | CWE | File | ~Line | Description |
|---|-----|------|-------|-------------|
| 31 | CWE-352 | app/main.py (+ app/config.py) | 24 | CSRF: `CSRFProtect(app)` is now initialised, so the previously-dead `WTF_CSRF_ENABLED = False` takes real effect; forms carry no `csrf_token`, so state-changing POSTs are CSRF-exploitable |
| 32 | CWE-22 | app/orders.py | 247 | Path traversal — `GET /orders/<id>/download?file=` reads `"/tmp/" + filename` via `send_file`, no `../` sanitization |
| 33 | CWE-434 | app/orders.py | 268 | Unrestricted upload — `POST /books/<id>/cover/upload` saves the uploaded file under its client-supplied name with no extension/MIME check |
| 34 | CWE-522 | app/payments.py (+ payment_cards table) | 30 | Insufficiently protected credentials — `POST /payment/save-card` stores the card token in plaintext |
| 35 | CWE-798 | app/payments.py | 15 | Hardcoded credentials — `PAYMENT_GATEWAY_API_KEY` (fake `sk_live_…` key) hardcoded in source |
| 36 | CWE-640 | app/auth.py | 198 / 219 | Weak password recovery — `POST /password-reset/request` + `/verify` use a low-entropy secret question/answer, plaintext string compare, no attempt limit/lockout/delay |
| 37 | CWE-306 | app/admin.py | 47 | Missing authentication — `POST /admin/books/bulk-delete` deletes books with no auth/`is_admin` check at all |
| 38 | CWE-915 | app/profile.py | 34 | Mass assignment — `POST /profile/update` applies the entire request body to the user row (including `is_admin`, `password_hash`) |
| 39 | CWE-611 | app/admin.py | 76 | XXE — `POST /admin/books/import` parses uploaded XML with `xml.etree.ElementTree.parse()` (external entities not disabled, no `defusedxml`) |
| 40 | CWE-117 | app/auth.py | 112 | Log injection — failed-login `username` logged via f-string without sanitizing newlines/control chars, enabling forged log lines |

### CWE-778 (v1) vs CWE-117 (v2)

CWE-778 (v1, in `auth.py`, "failed logins are never logged — finding through
absence") is **deliberately left untouched**: its `# VULN: CWE-778` comment and
the surrounding failure path are byte-for-byte unchanged. CWE-117 (v2) is a
**separate, new finding** added *beside* it: it shows that if you do add logging
without thinking, the logging itself can be vulnerable (unsanitized,
attacker-controlled `username` written to the log). The two coexist on purpose
as distinct study fixtures.

### v2 notes / deviations

1. **`main.py` is the only v1 file whose in-function logic gains a line beyond
   pure route/table appends** — the `CSRFProtect(app)` init for finding 31, plus
   the two new blueprint registrations (`payments_bp`, `profile_bp`). As
   explicitly required by the spec, new routes/tables were also *appended* to
   `orders.py`, `auth.py`, `admin.py` and `db_init.py`, and a dependency was
   appended to `requirements.txt`. In every case the change is **additive
   only**: `git diff` over the v1 files shows insertions and **zero deletions**,
   so no existing finding was altered. (The spec's summary line "the only change
   is `CSRFProtect` in `main.py`" is read as "no existing finding modified", not
   "no v1 file touched", since the per-finding instructions require adding code
   to those files.)
2. **`Flask-WTF==0.14.3`** is pinned as the CSRF dependency with an explicit
   `# TODO: verify compatibility with Flask 1.1.4` marker, per the spec.
3. **New files:** `app/payments.py` (findings 34, 35) and `app/profile.py`
   (finding 38); both register their blueprint in `main.py`. `db_init.py` gains
   a `payment_cards` table via a new `SCHEMA_V2` executed alongside the untouched
   `SCHEMA`.
4. **CWE-640 uses two routes** (`/password-reset/request` and `/verify`) for one
   finding; it reuses the existing, previously-unused `secret_question` /
   `secret_answer` columns already seeded in `db_init.py`.
