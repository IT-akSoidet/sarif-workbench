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
