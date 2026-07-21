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

## Version 3 findings (14 new, additive)

Version 3 adds **14 more, separate vulnerabilities** on top of the 30 v1 + 10 v2
findings, chosen to close gaps against the **OWASP Top 10:2025** taxonomy
(A01/A03/A04/A05/A06/A07/A08/A09/A10 previously had thin or no coverage). **None
of the earlier 40 findings were modified** — v3 is pure addition (new routes in
existing blueprints, two appended template/dependency lines). Each v3 finding is
marked with a `# VULN v3: CWE-XXX` comment.

Line numbers are approximate (grep `VULN v3: CWE` to re-locate).

| # | CWE | OWASP 2025 | File | Description |
|---|-----|-----------|------|-------------|
| 41 | CWE-829 | A03 Supply Chain | app/templates/base.html | External CDN `<script>` loaded with no Subresource Integrity (`integrity`/`crossorigin`) |
| 42 | CWE-1395 | A03 Supply Chain | requirements.txt | Extra known-vulnerable pin `PyYAML==5.3.1` (CVE-2020-14343, unsafe `yaml.load`) |
| 43 | CWE-1395 / CWE-502 | A03 / A08 | app/admin.py | `POST /admin/books/import.yaml` parses uploaded YAML with unsafe `yaml.load()` |
| 44 | CWE-532 | A09 Logging | app/payments.py | `POST /payment/save-card` logs the full, unmasked card token |
| 45 | CWE-353 | A08 Integrity | app/payments.py | `POST /payment/webhook` acts on gateway callback with no HMAC/signature check |
| 46 | CWE-863 | A01 Access Control | app/admin.py | `POST /admin/promote` authorizes on the client-supplied `X-Is-Admin` header |
| 47 | CWE-94 | A05 Injection | app/admin.py | `POST /admin/books/preview` — SSTI via `render_template_string` on user input |
| 48 | CWE-778 | A09 Logging | app/admin.py | `POST /admin/books/purge` deletes the whole catalog with no audit logging (explicit) |
| 49 | CWE-521 | A07 Auth | app/auth.py | `POST /account/register` enforces no password length/complexity requirements |
| 50 | CWE-384 | A07 Auth | app/auth.py | `POST /login/legacy` reuses a client-pinned session id (session fixation) |
| 51 | CWE-601 | A01 Access Control | app/auth.py | `GET /redirect?next=` — open redirect, no allow-list/same-origin check |
| 52 | CWE-330/338 | A04 Crypto | app/auth.py | `GET /password-reset/token` builds the reset token with the `random` module |
| 53 | CWE-598 | A06 Insecure Design | app/auth.py | Same route passes the reset token as a sensitive GET query parameter |
| 54 | CWE-799 | A06 Insecure Design | app/auth.py | `POST /promo/redeem` has no rate limit / attempt cap (brute-forceable) |
| 55 | CWE-209 | A10 Exceptional Conditions | app/orders.py | `GET /orders/<id>/total` returns raw exception text + full traceback |

### v3 notes / deviations

1. **Additive only.** `git diff` over every v1/v2 file shows insertions and zero
   deletions of existing findings. New routes are appended under `--- v3
   additions ---` banners; `base.html` gains one `<script>` line and
   `requirements.txt` one pinned dependency, neither of which alters an existing
   finding.
2. **Two CWE-1395-related entries.** #42 is the dependency pin itself (mirrors
   the v1 CWE-1104 style); #43 is the actual `yaml.load` sink that consumes it.
   The sink also reads as CWE-502 (unsafe deserialization) — noted in both
   columns — but is kept distinct from the v2 pickle CWE-502 finding.
3. **CWE-778 appears three times on purpose, as distinct fixtures:** v1 "by
   absence" (auth.py failed-login path), v2 CWE-117 log-injection beside it, and
   v3 #48 an *explicit* missing-audit-log on a destructive admin action.
4. **#52 + #53 share one route** (`/password-reset/token`): the weak-RNG token
   generation (CWE-330/338) and its transport as a GET query string (CWE-598)
   are two separate findings on the same handler.
5. **No new files or tables** were needed for v3 — all findings live in existing
   blueprints (`auth`, `admin`, `payments`, `orders`) and templates.

## Version 4 findings (21 new, additive)

Version 4 adds **21 more, separate vulnerabilities** on top of the 55 v1+v2+v3
findings, filling the remaining thin spots against **OWASP Top 10:2025** and
formally marking several weaknesses that were already latent (but unmarked) in
the codebase. **None of the earlier 55 findings were modified** — v4 is pure
addition: new routes in existing blueprints, one `after_request` in `main.py`,
and comment-only markers on pre-existing latent sinks (no behavior change). Each
v4 finding is marked `# VULN v4: CWE-XXX`.

Line numbers are approximate (grep `VULN v4: CWE` to re-locate).

### Latent findings (already present in code, now marked; comment-only)

| # | CWE | OWASP 2025 | File | Description |
|---|-----|-----------|------|-------------|
| 56 | CWE-1004 | A02 | app/config.py | Session cookie has no `HttpOnly` flag (`SESSION_COOKIE_HTTPONLY = False`) |
| 57 | CWE-614 | A02 | app/config.py | Session cookie has no `Secure` flag (`SESSION_COOKIE_SECURE = False`) |
| 58 | CWE-1275 | A01 | app/config.py | No `SameSite` attribute on the session cookie |
| 59 | CWE-1392/1393 | A07 | app/db_init.py | Default credentials seeded (`admin` / `admin123`) |
| 60 | CWE-550/209 | A10 | app/search.py | `/promo/lookup` returns the raw DB error text **and** the built SQL query |

### New-code findings

| # | CWE | OWASP 2025 | File | Description |
|---|-----|-----------|------|-------------|
| 61 | CWE-200 | A01 | app/profile.py | `GET /api/users/<id>` serializes the whole user row (hash, e-mail, secret Q/A) |
| 62 | CWE-620 | A07 | app/profile.py | `POST /profile/change-password` sets a new password with no current-password check |
| 63 | CWE-565 | A08 | app/profile.py | `GET /profile/admin-panel` trusts an unsigned client-set `is_admin` cookie |
| 64 | CWE-862 | A01 | app/admin.py | `GET /admin/users` dumps all users with no auth/authz check |
| 65 | CWE-470 | A05 | app/admin.py | `GET /admin/report/<name>` — unsafe reflection via `getattr()`, no allow-list |
| 66 | CWE-291 | A07 | app/admin.py | `GET /admin/metrics` authenticates purely on `remote_addr` being localhost |
| 67 | CWE-494 | A08 | app/admin.py | `POST /admin/plugins/install` fetches a URL and `exec()`s it, no integrity check |
| 68 | CWE-526 | A02 | app/admin.py | `GET /debug/env` returns the full process environment (`os.environ`) |
| 69 | CWE-95 | A05 | app/orders.py | `POST /orders/discount/apply` `eval()`s a client-supplied rule expression |
| 70 | CWE-377 | A01 | app/orders.py | `GET /orders/<id>/export-receipt` writes a predictable `/tmp` file (no mkstemp) |
| 71 | CWE-732 | A01 | app/orders.py | Same route `chmod(path, 0o777)` — world-readable/writable receipt |
| 72 | CWE-113 | A05 | app/orders.py | `GET /orders/track` writes user input into a response header (CRLF/splitting) |
| 73 | CWE-636 | A10 | app/auth.py | `is_authorized()` returns `True` on token-decode exception (fails open) |
| 74 | CWE-337 | A04 | app/auth.py | `POST /api-key/issue` seeds `random` with a constant before key generation |
| 75 | CWE-321 | A04 | app/payments.py | `POST /payment/save-card-encrypted` uses a hard-coded XOR key constant |
| 76 | CWE-1021 | A06 | app/main.py | `after_request` sets `X-Frame-Options: ALLOWALL` (clickjacking) |

### v4 notes / deviations

1. **Additive only.** `git diff` over all v1–v3 files shows the only removed line
   is the v3 `auth.py` import statement (extended with `redirect`/`random` for
   the v3 routes); no finding's code or behavior was altered. The five "latent"
   entries (#56–#60) are **comment-only** — the flagged code (cookie flags,
   default creds, the promo error leak) already existed unchanged.
2. **CWE-209 appears twice** intentionally: v3 #55 (traceback from a new route)
   and v4 #60 (the pre-existing `/promo/lookup` SQL-error+query leak, also read
   as CWE-550). Kept as distinct fixtures.
3. **#70 + #71 share one route** (`/orders/<id>/export-receipt`): the predictable
   temp path (CWE-377) and the `chmod 0o777` (CWE-732) are two separate findings
   on the same handler.
4. **`main.py` gains an `after_request`** for the clickjacking header (#76),
   analogous to the v2 `CSRFProtect(app)` addition — a legitimate additive hook,
   not an edit of existing logic.
5. **Not covered on purpose:** taxonomy entries specific to Java/Struts/Hibernate
   (CWE-103/104/382/493/500/564), ASP.NET (CWE-11/13/1174), Android (CWE-926),
   PHP RFI (CWE-98), LDAP (CWE-90), and C/C++ memory-safety (CWE-476/478/484) are
   not applicable to this Python/Flask/SQLite stack.

## Version 5 findings (front-end)

Versions 1–4 concentrated on the Python back end, leaving the front end almost
empty: four thin Jinja templates with no JavaScript. A Semgrep scan scoped to
`app/templates` therefore returned only **2** findings. Version 5 builds a real
front-end attack surface — **2 → 20 findings** on the same scope.

**Key lesson for the study:** Semgrep does **not** analyze inline `<script>`
blocks inside `.html` files — its JavaScript rules (153 of them here) only run
against real `.js` files. The vulnerable client logic therefore lives in
`app/static/js/`, not inline in the templates.

Each finding is marked `VULN v5: CWE-XXX`.

### Templates (`app/templates/`)

| CWE | OWASP 2025 | File | Description |
|---|---|---|---|
| CWE-829/353 | A03/A08 | base.html | Two more CDN resources (JS + CSS) with no `integrity` attribute |
| CWE-319 | A04 | base.html | Analytics script and footer links loaded over plaintext `http://` |
| CWE-1022 | A06 | base.html, order.html | `target="_blank"` with no `rel="noopener noreferrer"` (reverse tabnabbing) |
| CWE-1021 | A06 | base.html | Third-party widget `<iframe>` with no `sandbox` attribute |
| CWE-352 | A01 | search.html, book.html, order.html | Six state-changing POST forms with no `csrf_token` |
| CWE-598 | A06 | search.html | Login form submitted via **GET** — password lands in URL/history/logs |
| CWE-525 | A06 | search.html, order.html | `autocomplete="on"` on password and card-number inputs |
| CWE-79 | A05 | search.html, book.html | `javascript:` URL and inline handlers built from untrusted values |

### Client-side JavaScript (`app/static/js/`)

| CWE | OWASP 2025 | File | Description |
|---|---|---|---|
| CWE-79 | A05 | app.js, checkout.js | DOM XSS: `innerHTML`, `document.write`, jQuery `.html()` from URL/API data |
| CWE-95 | A05 | app.js, checkout.js | `eval()`, `new Function()`, and `setTimeout("string")` on untrusted input |
| CWE-346 | A07 | app.js, order.html | `postMessage(..., "*")` wildcard origin + `message` handler with no `event.origin` check |
| CWE-601 | A01 | app.js | `window.location = params.get("next")` — client-side open redirect |
| CWE-338 | A04 | app.js | `Math.random()` used to mint a session/idempotency key |
| CWE-922 | A01 | app.js, checkout.js | Access token, cookies, card token and CVV cached in `localStorage` |
| CWE-798 | A07 | checkout.js | Payment key and a support override token hard-coded in the shipped bundle |
| CWE-602 | A06 | checkout.js | Discount/total validated only in the browser, then trusted by `/checkout` |
| CWE-1004/1275 | A02/A01 | checkout.js | `document.cookie` written with no `Secure`/`HttpOnly`/`SameSite` |
| CWE-915 | A08 | checkout.js | Recursive merge without `__proto__` guard (prototype pollution) |

### Verified scan results

| Scope | Before v5 | After v5 |
|---|---|---|
| `app/templates` + `app/static` (Semgrep) | 2 | **20** (12 HTML, 8 JS) |
| Whole project (Semgrep `--config auto`) | — | **69** |
| `app/` (Bandit `-f sarif`) | — | **34** |

### v5 notes

1. **`git add` matters.** Semgrep only scans files tracked by git
   (`Scan was limited to files tracked by git`). New files under
   `app/static/js/` must be `git add`-ed (even with `-N`) or they are silently
   skipped — otherwise the JS findings never appear.
2. **Bandit has no native SARIF output.** Its formatters are
   `csv,custom,html,json,screen,txt,xml,yaml`; SARIF requires the
   `bandit-sarif-formatter` plugin, after which `-f sarif` becomes available.
3. **Bandit is Python-only** — it contributes nothing to the front-end scope.
   Front-end coverage comes from Semgrep's `html` and `js` rulesets.
