# Authority Bridged — Implementation Plan (CSE447)

**Source of truth:** [`project-context.md`](./project-context.md), [`crypto-plan.md`](./crypto-plan.md), and the locked implementation decisions in [Locked Decisions Before Implementation](#locked-decisions-before-implementation). This document turns those sources into an ordered, checkbox-level development roadmap. Where the original source files were silent, ambiguous, or contradictory, the locked decisions in this plan now control implementation.

**Stack (frozen):** Python + Flask, SQLite, HTML/CSS/Jinja2 (Bootstrap optional), pytest, a transactional email API (Resend or Brevo) for OTP delivery only. From-scratch RSA and EC-ElGamal for application-data confidentiality, from-scratch HMAC-SHA256 for integrity, SHA-256 + salt for passwords. No AES/DES/3DES/ChaCha20/Fernet, no Docker/Redis/Celery/React/Next.js/microservices/cloud DB.

---

## Table of Contents

1. [Final Repository Structure](#1-final-repository-structure)
2. [Modularity Rules](#2-modularity-rules)
3. [Development Phases (overview)](#3-development-phases-overview)
4. [Phase Details](#4-phase-details)
5. [Cryptography Dependency Map](#5-cryptography-dependency-map)
6. [Database Planning](#6-database-planning)
7. [Key Versioning Rules](#7-key-versioning-rules)
8. [RBAC Planning](#8-rbac-planning)
9. [Secure Session Planning](#9-secure-session-planning)
10. [API / OTP Integration Planning](#10-api--otp-integration-planning)
11. [Testing Structure](#11-testing-structure)
12. [Report Evidence Checklist](#12-report-evidence-checklist)
13. [Git Workflow / Team Modularity](#13-git-workflow--team-modularity)
14. [Interface Contracts](#14-interface-contracts)
15. [Locked Decisions Before Implementation](#locked-decisions-before-implementation)
16. [Project Definition of Done](#project-definition-of-done)

---

## 1. Final Repository Structure

```text
authority-bridged/
├── app.py
├── config.py
├── requirements.txt
├── README.md
├── .env.example
├── .gitignore
│
├── crypto/
│   ├── __init__.py
│   ├── bigint_utils.py
│   ├── rsa.py
│   ├── ecc_curve.py
│   ├── ecc.py
│   ├── ecc_encoding.py
│   ├── hashing.py
│   ├── hmac_custom.py
│   └── key_manager.py
│
├── auth/
│   ├── __init__.py
│   ├── routes.py
│   ├── otp.py
│   ├── sessions.py
│   ├── decorators.py
│   └── rbac.py
│
├── posts/
│   ├── __init__.py
│   ├── routes.py
│   └── services.py
│
├── chat/
│   ├── __init__.py
│   ├── routes.py
│   └── services.py
│
├── evidence/
│   ├── __init__.py
│   ├── routes.py
│   └── services.py
│
├── admin/
│   ├── __init__.py
│   └── routes.py
│
├── services/
│   ├── __init__.py
│   └── email_service.py
│
├── database/
│   ├── __init__.py
│   ├── db.py
│   ├── schema.sql
│   └── seed.py
│
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── verify_otp.html
│   ├── dashboard.html
│   ├── posts.html
│   ├── post_detail.html
│   ├── create_post.html
│   ├── profile.html
│   ├── chat.html
│   └── admin/
│       ├── posts.html
│       ├── post_detail.html
│       └── keys.html
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── app.js
│
├── encrypted_uploads/          # gitignored, created at runtime
│
└── tests/
    ├── conftest.py
    ├── unit/
    │   ├── test_rsa.py
    │   ├── test_ecc.py
    │   ├── test_ecc_encoding.py
    │   ├── test_hashing.py
    │   ├── test_hmac.py
    │   └── test_key_manager.py
    └── integration/
        ├── test_auth_flow.py
        ├── test_sessions.py
        ├── test_posts.py
        ├── test_upvotes.py
        ├── test_evidence.py
        ├── test_chat.py
        ├── test_rbac.py
        └── test_key_rotation.py
```

### File/Directory Responsibilities

**`app.py`** — Flask application factory. Creates the app, loads `config.py`, registers blueprints (`auth`, `posts`, `chat`, `evidence`, `admin`), registers the `database/db.py` teardown hook, sets cookie flags. **Must not** contain route logic, SQL, or cryptography. Depends on: `config.py`, every blueprint's `routes.py`, `database/db.py`.

**`config.py`** — Reads environment variables (`.env`) into typed config objects: `ROOT_RSA_N`, `ROOT_RSA_E`, `ROOT_RSA_D`, `RSA_PRIME_BITS`, `RSA_PUBLIC_EXPONENT`, `DATABASE_PATH`, `EMAIL_API_KEY`, `EMAIL_API_PROVIDER`, `SESSION_COOKIE_*`, `OTP_EXPIRY_SECONDS`, `MAX_EVIDENCE_SIZE_BYTES`. No secrets hard-coded. No business logic. Local development/demo sets `SESSION_COOKIE_SECURE=False`; production/HTTPS may set it `True`.

**`.env.example` / `.env`** — `.env` holds the decimal root RSA key integers (`ROOT_RSA_N`, `ROOT_RSA_E`, `ROOT_RSA_D`), `RSA_PRIME_BITS=128`, `RSA_PUBLIC_EXPONENT=11`, email API key, Flask `SECRET_KEY` (used only for CSRF/Flask session cookie signing if used, **not** for crypto). `.env` is git-ignored; `.env.example` documents required variable names with placeholder values. Root private material is never stored in SQLite or Git.

**`crypto/bigint_utils.py`** — Shared number-theory primitives used by both RSA and ECC: modular exponentiation (`mod_pow`), extended Euclidean algorithm / modular inverse (`mod_inverse`), probabilistic primality test (Miller–Rabin), random prime generation, `gcd`. **Must not** import Flask, SQLite, or any route/template code. Pure math only, so it is trivially unit-testable and reusable by `rsa.py` and `ecc.py` without duplication.

**`crypto/rsa.py`** — Educational textbook RSA key generation (`p`, `q`, `n`, `φ(n)`, `e=11`, `d`), raw operations, and `TBR1` safe byte chunking. Depends only on `crypto/bigint_utils.py`. It intentionally has no modern padding and must not know about SQLite, Flask, or which purpose (profile vs evidence) it is being used for — purpose is the caller's concern (`key_manager.py`).

**`crypto/ecc_curve.py`** — The chosen elliptic curve domain parameters (`p`, `a`, `b`, `G`, curve order `n`) and the raw point arithmetic: point addition, point doubling, scalar multiplication (double-and-add), point validity check. No encoding, no encryption, no Flask/SQLite.

**`crypto/ecc.py`** — EC-ElGamal key generation (`d`, `Q = dG`), `ecc_encrypt_point`, `ecc_decrypt_point` operating on curve points from `ecc_curve.py`. Depends on `ecc_curve.py` and `bigint_utils.py` (for the ephemeral scalar `k` and modular inverse used in decryption arithmetic). Must not contain byte/text encoding logic.

**`crypto/ecc_encoding.py`** — The byte ↔ curve-point mapping table (`byte_to_point`, `point_to_byte`) and the higher-level `ecc_encrypt_bytes` / `ecc_decrypt_bytes` helpers that apply `ecc.py` per byte. This is the only place the "text becomes a sequence of points" concept lives, keeping `ecc.py` a pure algorithm module.

**`crypto/hashing.py`** — Password hashing: `generate_salt`, `hash_password(password, salt)`, `verify_password(password, salt, hash)`. Uses SHA-256. Must not use RSA/ECC. Must not be reachable from anywhere except `auth/`.

**`crypto/hmac_custom.py`** — Manual HMAC-SHA256 construction (key normalization, `ipad`/`opad`, inner hash, outer hash): `generate_mac(key, message)`, `verify_mac(key, message, received_mac)`. May depend on a SHA-256 implementation/library for the underlying hash primitive (per `project-context.md` §23) but the HMAC construction itself must be hand-written — never call `hmac.new()`.

**`crypto/key_manager.py`** — The only module allowed to decide *which* key version to use for a given `purpose` (`RSA_PROFILE`, `RSA_EVIDENCE`, `ECC_POSTS`, `ECC_CHAT`, `HMAC_CHAT`, `HMAC_SESSION`) and the only module allowed to unwrap (RSA-decrypt) a stored private key using the root key. It reads/writes the `keys` table (via `database/db.py`) and calls into `rsa.py`/`ecc.py` for key generation and root-key wrapping. Routes and services never touch the `keys` table directly or read `.env` for the root key — they call `key_manager.get_active_key(purpose)` / `get_key_by_version(purpose, version)`.

**`auth/routes.py`** — Registration, login, OTP verification, logout HTTP endpoints. Calls `crypto/hashing.py` (password), `crypto/key_manager.py` + `crypto/rsa.py` (profile field encryption), `auth/otp.py`, `auth/sessions.py`. **Must not** contain raw SQL or cryptographic algorithm code inline — those live in `crypto/` and `database/`.

**`auth/otp.py`** — OTP generation, salted hashing, expiry check, verification, invalidation, and the call to `services/email_service.py` to deliver the code. Each OTP gets a fresh `otp_salt` and stores `SHA256(salt || OTP)`; the raw OTP is never persisted. If email delivery fails, the newly generated OTP is invalidated/deleted before the user sees a generic failure message.

**`auth/sessions.py`** — Session creation, validation, HMAC signing/verification of the session token, expiration checks, revocation, logout invalidation, cookie construction. Uses `crypto/hmac_custom.py` + `crypto/key_manager.py` (purpose `HMAC_SESSION`). This is the **only** module that reads/writes the `sessions` table and the **only** module that builds or parses the session cookie. See [Secure Session Planning](#9-secure-session-planning).

**`auth/decorators.py`** — Reusable `@login_required`, `@role_required("admin")` decorators that wrap Flask view functions. Delegate the actual check to `auth/sessions.py` (is there a valid session?) and `auth/rbac.py` (does the role/ownership check pass?). No decorator anywhere else in the codebase re-implements this logic.

**`auth/rbac.py`** — Central authorization rules: `is_admin(user)`, `is_owner(user, resource)`, `can_view_evidence(user, evidence)`, `can_access_chat(user, chat_message_or_post)`, etc. Every blueprint imports from here instead of writing its own `if user.role == "admin"` checks inline. See [RBAC Planning](#8-rbac-planning).

**`posts/routes.py`** — HTTP endpoints for creating/editing/listing/viewing posts and upvoting. Calls `posts/services.py` for business logic; calls `auth/decorators.py` for auth; never calls `crypto/ecc.py` directly.

**`posts/services.py`** — Encrypts/decrypts post title/description via `crypto/key_manager.py` + `crypto/ecc_encoding.py`, applies the anonymous-display rule, computes/records upvotes, changes status (status-change authorization itself enforced by `auth/rbac.py`, invoked from `admin/routes.py`). Talks to `database/db.py` for `posts`/`upvotes` tables.

**`chat/routes.py`** — HTTP endpoints for viewing/sending private Admin ↔ owner messages. No crypto or SQL inline.

**`chat/services.py`** — Encrypt → MAC → store, and Retrieve → verify MAC → decrypt flows described in `project-context.md` §21–22. Uses `crypto/ecc_encoding.py`, `crypto/hmac_custom.py`, `crypto/key_manager.py` (purposes `ECC_CHAT` and `HMAC_CHAT`). Talks to `database/db.py` for `chat_messages`.

**`evidence/routes.py`** — Upload/view/download HTTP endpoints. Validates file type/size at the HTTP boundary, delegates everything else to `evidence/services.py`.

**`evidence/services.py`** — RSA block-encrypts uploaded files and original filenames, writes ciphertext under `encrypted_uploads/`, and stores only plaintext id-derived `file_path` metadata; decrypts on authorized read and streams bytes back without writing a plaintext copy to disk. Uses `crypto/rsa.py` + `crypto/key_manager.py` (purpose `RSA_EVIDENCE`). Talks to `database/db.py` for the `evidence` table.

**`admin/routes.py`** — Admin-only endpoints: acknowledge/change post status, key-management operations (trigger rotation, view key status), and the admin-side chat/evidence views that reuse `chat/services.py`, `evidence/services.py`, `posts/services.py`. Every route here is wrapped in `@role_required("admin")` from `auth/decorators.py`. **Must not** duplicate business logic that already lives in `posts/services.py`, `evidence/services.py`, `chat/services.py`, or `crypto/key_manager.py` — it only orchestrates calls into them.

**`services/email_service.py`** — Thin wrapper around the transactional email API (Resend or Brevo). Exposes one function, e.g. `send_otp_email(to_address, otp_code)`, so `auth/otp.py` never touches provider-specific SDK/HTTP code. Swapping providers means editing only this file. See [API / OTP Integration Planning](#10-api--otp-integration-planning).

**`database/db.py`** — SQLite connection management (`get_db()`, `close_db()`, Flask `teardown_appcontext` hook), `init_db()` that runs `schema.sql`. Exposes small generic helpers (`execute`, `query_one`, `query_all`) that every `*/services.py` and `key_manager.py` use. **Must not** contain business rules, cryptography, or Flask route/template logic.

**`database/schema.sql`** — Full `CREATE TABLE` statements for all tables (see [Database Planning](#6-database-planning)), created once in Phase 1 even though some columns are not used until later phases.

**`database/seed.py`** — Optional CLI script to create a default admin account and a couple of demo students for local development/demo purposes. Never run automatically in production-like flows; must not hard-code real secrets.

**`templates/*.html`** — Presentation only. May contain `{% if user.role == 'admin' %}`-style *display* conditionals for convenience (e.g., hide a button), but this is **never** the authorization mechanism — the corresponding route must independently enforce the same rule server-side via `auth/decorators.py`/`auth/rbac.py`. Templates must not compute cryptographic values or make security decisions (e.g., must not decide whether a MAC is valid — that decision is made in `chat/services.py` and passed to the template as a boolean).

**`static/`** — CSS/JS only, no secrets, no inline crypto.

**`encrypted_uploads/`** — Runtime directory for encrypted evidence blobs (`evidence_<id>.enc`). Git-ignored. Never holds plaintext.

**`tests/`** — See [Testing Structure](#11-testing-structure).

---

## 2. Modularity Rules

1. **Flask routes never contain cryptographic algorithms.** `*/routes.py` files call into `*/services.py` or `crypto/`; they must not compute `mod_pow`, curve arithmetic, or HMAC inline.
2. **Database functions never contain Flask/UI logic.** `database/db.py` and the SQL inside `*/services.py` must not `render_template`, read `request`, or set cookies.
3. **RSA logic stays inside `crypto/rsa.py`** (plus the shared primitives in `crypto/bigint_utils.py`). No other file implements modular exponentiation for RSA.
4. **ECC logic stays inside `crypto/ecc_curve.py` and `crypto/ecc.py`.** No other file implements point addition/doubling/scalar multiplication.
5. **HMAC logic stays inside `crypto/hmac_custom.py`.** No route or service re-implements the ipad/opad construction; they only call `generate_mac`/`verify_mac`.
6. **All key retrieval and rotation goes through `crypto/key_manager.py`.** No blueprint, service, or template reads the `keys` table or `.env` root key directly.
7. **Authorization is centralized, not duplicated.** All role/ownership checks funnel through `auth/decorators.py` + `auth/rbac.py`. A route that needs a custom rule (e.g., "post owner or admin") calls a named function in `auth/rbac.py`, it does not inline a new `if` chain.
8. **Evidence encryption/decryption lives in a service layer** (`evidence/services.py`), never in `evidence/routes.py` or in a template.
9. **Templates never make security decisions.** They render values already computed and authorized by the Python layer (e.g., `is_owner`, `mac_valid`, `display_name` for anonymous posts are all pre-computed booleans/strings passed into the template context).

### Avoiding Circular Dependencies

- Dependency direction is **one-way**, top to bottom: `crypto/` → `database/` → `auth/` → (`posts/`, `chat/`, `evidence/`) → `admin/` → `app.py`. A module may depend on anything strictly above it in this list, never below or sideways within the same layer.
- `crypto/*` modules depend only on each other and on the Python standard library (plus, where explicitly allowed, `secrets`/`os` for randomness). They must never import `database/`, `auth/`, `flask`, or any blueprint.
- `database/db.py` depends only on `sqlite3`/`config.py`. It never imports `crypto/` or any blueprint.
- `crypto/key_manager.py` is the one place allowed to depend on **both** `crypto/` (for algorithms) and `database/` (to persist key rows) — it is the bridge between them, so nothing else needs to import both.
- `auth/rbac.py` depends only on `database/` (to look up ownership) and plain Python — it must not import `posts/`, `chat/`, or `evidence/`, so those blueprints can safely import `auth/rbac.py` without a cycle.
- `posts/`, `chat/`, `evidence/` never import from each other directly. If chat needs to know a post's owner, it calls a small read-only function exposed by `posts/services.py` (or a shared `database/db.py` query), not the whole `posts` blueprint.
- `admin/routes.py` may import `posts/services.py`, `evidence/services.py`, `chat/services.py`, `crypto/key_manager.py` — but those modules never import `admin/`.
- `app.py` is the only file allowed to import every blueprint; nothing imports `app.py`.

---

## 3. Development Phases (overview)

| Phase | Name |
|---|---|
| 0 | Repository initialization |
| 1 | Database foundation |
| 2 | RSA implementation |
| 3 | ECC implementation |
| 4 | HMAC implementation |
| 5 | Key Management Module |
| 6 | Registration and password security |
| 7 | Login and 2FA |
| 8 | Secure session system |
| 9 | Profile module |
| 10 | Complaint/post module |
| 11 | Upvotes |
| 12 | Evidence upload/encryption |
| 13 | Admin acknowledgement/status |
| 14 | Private Admin ↔ Owner chat |
| 15 | MAC tamper detection (demo/verification hardening) |
| 16 | RBAC hardening |
| 17 | Key rotation demonstration |
| 18 | Testing |
| 19 | Final report evidence collection |

This sequence keeps the order given in the prompt. It is already dependency-correct: primitives (RSA/ECC/HMAC) exist before the Key Manager wraps them (Phase 5); the Key Manager exists before any feature that calls `get_active_key()` (Phases 6, 9–14); passwords/OTP/sessions (6–8) exist before any authenticated feature; posts (10) exist before upvotes (11), evidence (12), admin actions (13), and chat (14) since all four reference a `post_id`. Phase 15 is listed separately from Phase 4 because building the *tamper-detection demonstration* (deliberately corrupting a row and showing the warning) is meaningfully separate from writing the HMAC primitive, and it can only be demonstrated once chat (14) exists. Phase 16 revisits RBAC after every route exists, because it is a horizontal hardening pass across all blueprints, not a single vertical feature. Testing (18) is listed last only because it is where *cross-cutting* pytest suites are assembled from fixtures spanning every module — the plan below still asks for tests to be written phase-by-phase as each module lands (see each phase's **Tests** subsection); Phase 18 is the pass to fill any coverage gaps and run the full suite together.

---

## 4. Phase Details

### Phase 0 — Repository initialization

**Goal:** A running (empty) Flask app, dependency list, git hygiene, and the directory skeleton so every later phase has somewhere to put its files.

**Files Created or Modified:**
`app.py`, `config.py`, `requirements.txt`, `.env.example`, `.gitignore`, `README.md`, empty package `__init__.py` files for `crypto/`, `auth/`, `posts/`, `chat/`, `evidence/`, `admin/`, `services/`, `database/`, `templates/base.html`, `static/css/style.css`.

**Implementation Tasks:**
- [ ] Create the directory tree from [Section 1](#1-final-repository-structure).
- [ ] Add `requirements.txt` (Flask, pytest, python-dotenv, the chosen email SDK/`requests`).
- [ ] Write `config.py` reading `DATABASE_PATH`, `ROOT_RSA_N`, `ROOT_RSA_E`, `ROOT_RSA_D`, `RSA_PRIME_BITS` (default/locked application value: 128), `RSA_PUBLIC_EXPONENT` (default 11), `EMAIL_API_KEY`, `EMAIL_API_PROVIDER`, `OTP_EXPIRY_SECONDS`, `MAX_EVIDENCE_SIZE_BYTES` (default 200 KB), `SESSION_COOKIE_*` from environment variables via `python-dotenv`.
- [ ] Write a minimal `app.py` application factory with a `/health` route returning `200 OK`, so the phase has something demonstrable.
- [ ] Write `.env.example` listing every variable name `config.py` expects, with placeholder (non-real) values.
- [ ] Write `.gitignore` covering `.env`, `*.db`, `encrypted_uploads/`, `__pycache__/`, `.pytest_cache/`.
- [ ] Initialize git repository and make the first commit.

**Dependencies:** None.

**Completion Criteria:** Phase complete only if:
- `flask run` (or `python app.py`) starts without error,
- `GET /health` returns `200`,
- `.env` is confirmed **not** tracked by git (`git status` shows it ignored),
- `pytest` runs (even with zero tests) without import errors.

**Tests:** `tests/integration/test_auth_flow.py` is not started yet; add a placeholder `tests/unit/test_app_boots.py` asserting the Flask app factory returns an app instance and `/health` returns 200.

**Report Evidence:** Screenshot of `git log` showing the first commit; screenshot of the running app's `/health` response; final repository tree (for report section 12, GitHub Structure).

---

### Phase 1 — Database foundation

**Goal:** All tables exist with their final columns (per [Database Planning](#6-database-planning)) even though most are unused until later phases, so no later phase needs a destructive migration.

**Files Created or Modified:**
`database/db.py`, `database/schema.sql`, `database/seed.py`.

**Implementation Tasks:**
- [ ] Write `database/schema.sql` with `CREATE TABLE IF NOT EXISTS` statements for `keys`, `users`, `sessions`, `otp_codes`, `posts`, `upvotes`, `evidence`, `chat_messages` (columns per [Section 6](#6-database-planning)).
- [ ] Write `database/db.py`: `get_db()` (opens/reuses a per-request SQLite connection with `row_factory = sqlite3.Row`), `close_db(e=None)` registered via `app.teardown_appcontext`, `init_db()` (executes `schema.sql`), `execute(query, params)`, `query_one(query, params)`, `query_all(query, params)`.
- [ ] Add a `flask init-db` CLI command (or a `python -m database.db` entry point) that calls `init_db()`.
- [ ] Create `database/seed.py` as an empty controlled setup entry point with no demo account creation yet. Do **not** create a placeholder Admin password in Phase 1; Admin seeding is implemented after password hashing and RSA profile encryption exist.
- [ ] Enable SQLite foreign key enforcement (`PRAGMA foreign_keys = ON`) on every connection.

**Dependencies:** Phase 0.

**Completion Criteria:** Phase complete only if:
- `flask init-db` creates `authority_bridged.db` (or configured path) with all eight tables,
- `sqlite3 authority_bridged.db ".schema"` shows every column listed in Section 6,
- foreign key pragma is confirmed ON (`PRAGMA foreign_keys` returns `1`),
- re-running `init-db` does not error or duplicate tables.

**Tests:** `tests/integration/test_db_schema.py` — asserts all 8 tables exist after `init_db()`; asserts foreign key pragma is on; asserts re-running `init_db()` is idempotent; asserts no Admin user is seeded in Phase 1.

**Report Evidence:** Terminal output of `.schema` for each table; screenshot of an empty-but-structured database in a SQLite browser (for report section 12).

---

### Phase 2 — RSA implementation

**Goal:** A from-scratch, unit-tested educational textbook RSA module: key generation, raw encryption/decryption, and metadata-bearing safe chunking so arbitrary-length byte data can round-trip.

**Files Created or Modified:**
`crypto/bigint_utils.py`, `crypto/rsa.py`, `tests/unit/test_rsa.py`.

**Implementation Tasks:**
- [ ] Implement `mod_pow(base, exp, mod)` (square-and-multiply) in `bigint_utils.py`.
- [ ] Implement `mod_inverse(a, m)` (extended Euclidean algorithm) in `bigint_utils.py`.
- [ ] Implement `is_probable_prime(n, rounds=...)` (Miller–Rabin) in `bigint_utils.py`.
- [ ] Implement `generate_prime(bit_length)` in `bigint_utils.py` using `secrets.randbits` + `is_probable_prime`.
- [ ] Implement `rsa_generate_keypair(prime_bits=128, public_exponent=11)` in `rsa.py`: pick distinct `p`, `q`, compute `n = p*q`, `φ(n) = (p-1)(q-1)`, verify `gcd(e, φ(n)) == 1`, and compute `d = mod_inverse(e, φ(n))`. Returns `{"public": (e, n), "private": (d, n)}`.
- [ ] Implement textbook RSA directly as `C = M^e mod n` and `M = C^d mod n`, using Python's three-argument modular `pow()` operation as demonstrated in the course lab. No OAEP, MGF1, PKCS#1, or replacement padding is used.
- [ ] Implement `rsa_encrypt_bytes(data: bytes, public_key)` and `rsa_decrypt_bytes(container, private_key)` using `TBR1` metadata (`length`, `chunk_size`, `block_count`, and ciphertext blocks), with chunk size `(n.bit_length() - 1) // 8`.
- [ ] Implement `rsa_encrypt(m_int, public_key) -> int` and `rsa_decrypt(c_int, private_key) -> int` as the raw single-integer primitives the byte-level functions build on.
- [ ] Add docstring/comments on every function explaining the cryptographic step for report section 3.

**Dependencies:** Phase 0.

**Completion Criteria:** Phase complete only if:
- `rsa_decrypt(rsa_encrypt(M)) == M` for a range of integers up to `n-1`,
- `rsa_decrypt_bytes(rsa_encrypt_bytes(data)) == data` for empty, 1-byte, exactly-one-block, and multi-block inputs,
- ciphertext integers differ from the plaintext integers,
- a corrupted/truncated block list raises a handled exception rather than silently returning wrong bytes,
- all unit tests pass.

**Tests (`tests/unit/test_rsa.py`):**
- `test_roundtrip_single_integer` — encrypt/decrypt a known integer, assert equality.
- `test_roundtrip_bytes_various_lengths` — parametrized over `b""`, `b"A"`, a full block, and several blocks.
- `test_ciphertext_differs_from_plaintext` — asserts `C != M`.
- `test_invalid_ciphertext_raises` — feed malformed metadata or an out-of-range block and assert decryption rejects it with a handled exception.
- `test_key_generation_produces_valid_keypair` — asserts `e*d ≡ 1 (mod φ(n))`, `e=11`, and an approximately 256-bit modulus.

**Report Evidence:** Terminal output of the RSA round-trip test passing; a printed example showing `M`, `C`, and recovered `M` side by side (for report section 3); the `rsa_generate_keypair` output for a demo key (public parts only) to illustrate `(e, n)`/`(d, n)`.

---

### Phase 3 — ECC implementation

**Goal:** A from-scratch elliptic curve with point arithmetic and an EC-ElGamal encryption/decryption scheme operating on curve points.

**Files Created or Modified:**
`crypto/ecc_curve.py`, `crypto/ecc.py`, `tests/unit/test_ecc.py`.

**Implementation Tasks:**
- [ ] Define one fixed educational curve as module-level constants in `ecc_curve.py`: `P` (field prime), `A`, `B` (curve coefficients for `y² = x³ + Ax + B mod P`), `G` (generator point tuple), `N` (order of `G`). The selected generator order must be greater than 256 so every byte can be mapped to a distinct point-domain value, and the exact `P`/`A`/`B`/`G`/`N` values must be documented in the file and report.
- [ ] Implement `is_on_curve(point)`.
- [ ] Implement `point_add(p1, p2)` handling the point-at-infinity identity and the doubling case (`p1 == p2`).
- [ ] Implement `point_double(p)` using the tangent-line formula.
- [ ] Implement `scalar_multiply(k, point)` via double-and-add, using `bigint_utils.mod_inverse` for the slope's modular division.
- [ ] Implement `ecc_generate_keypair()` in `ecc.py`: pick random `d` in `[1, N-1]`, compute `Q = scalar_multiply(d, G)`. Returns `{"public": Q, "private": d}`.
- [ ] Implement `ecc_encrypt_point(M_point, public_key_Q) -> (C1, C2)`: pick random ephemeral `k`, `C1 = scalar_multiply(k, G)`, `C2 = point_add(M_point, scalar_multiply(k, public_key_Q))`.
- [ ] Implement `ecc_decrypt_point(C1, C2, private_key_d) -> M_point`: compute `scalar_multiply(d, C1)`, negate it (point negation: `(x, -y mod P)`), `point_add` with `C2`.
- [ ] Add docstring/comments tying each function to the `dC1 = kQ` identity from `project-context.md` §17, for report section 3.

**Dependencies:** Phase 0. (Independent of Phase 2 — RSA and ECC can be built in parallel by different team members; see [Git Workflow](#13-git-workflow--team-modularity).)

**Completion Criteria:** Phase complete only if:
- `ecc_decrypt_point(*ecc_encrypt_point(M, Q), d) == M` for several sample points `M` on the curve,
- `is_on_curve(G)` is true and `scalar_multiply(N, G)` returns the point at infinity,
- ciphertext points differ from the plaintext point,
- all unit tests pass.

**Tests (`tests/unit/test_ecc.py`):**
- `test_point_on_curve` — generator and derived points satisfy the curve equation.
- `test_generator_order_is_valid` — asserts `N > 256`, `scalar_multiply(N, G)` is the point at infinity, and smaller sanity-check multiples do not invalidate the chosen generator.
- `test_point_addition_associativity` — `(P1+P2)+P3 == P1+(P2+P3)` for sample points.
- `test_scalar_multiplication_matches_repeated_addition` — `scalar_multiply(3, P) == P+P+P`.
- `test_encrypt_decrypt_roundtrip` — parametrized over multiple plaintext points and multiple keypairs.
- `test_ciphertext_differs_from_plaintext_point`.
- `test_decrypt_with_wrong_key_fails` — decrypting `(C1, C2)` with a different private key does **not** return the original point (expected-failure/security test).

**Report Evidence:** Terminal output of the ECC round-trip; a diagram (already sketched in `project-context.md` §17) reproduced with the team's actual `P`, `a`, `b`, `G`; sample `Q = dG` printed for report section 3.

---

### Phase 4 — HMAC implementation

**Goal:** A hand-built HMAC-SHA256 construction (not `hmac.new()`), independently testable, including a deliberate tamper-detection test.

**Files Created or Modified:**
`crypto/hmac_custom.py`, `tests/unit/test_hmac.py`.

**Implementation Tasks:**
- [ ] Implement `_normalize_key(key: bytes, block_size=64) -> bytes` (hash the key down if longer than block size, right-pad with zero bytes if shorter).
- [ ] Implement the `ipad`/`opad` XOR step explicitly (`bytes(b ^ 0x36 for b in key_block)` / `0x5c`).
- [ ] Implement `generate_mac(key: bytes, message: bytes) -> bytes` computing `H((K' xor opad) || H((K' xor ipad) || message))` using Python's `hashlib.sha256` purely as the underlying hash primitive. The HMAC *construction* is hand-written and must never call `hmac.new()`.
- [ ] Implement `verify_mac(key: bytes, message: bytes, received_mac: bytes) -> bool` using a constant-time comparison. `hmac.compare_digest` is allowed because it is comparison-only, not the MAC construction; `hmac.new()` remains forbidden.
- [ ] Add comments mapping each step to `project-context.md` §23 for report section 9.

**Dependencies:** Phase 0. (Independent of Phases 2–3.)

**Completion Criteria:** Phase complete only if:
- `verify_mac(key, message, generate_mac(key, message)) is True`,
- changing a single byte of `message` or `key` makes `verify_mac` return `False`,
- `generate_mac` output is 32 bytes (SHA-256 digest size) and differs from a naive `sha256(key + message)`,
- all unit tests pass.

**Tests (`tests/unit/test_hmac.py`):**
- `test_mac_verifies_for_unmodified_message`.
- `test_mac_fails_for_tampered_message` — flip one byte of the message, assert `verify_mac` returns `False`.
- `test_mac_fails_for_tampered_key`.
- `test_mac_differs_from_plain_sha256_concat` — guards against accidentally implementing the insecure `H(key || message)` construction instead of real HMAC.
- `test_mac_is_deterministic` — same key+message always produces the same MAC.

**Report Evidence:** Terminal output of the tamper test failing verification with the exact warning-style message planned for report section 9; a short code excerpt of the `ipad`/`opad` XOR step.

---

### Phase 5 — Key Management Module

**Goal:** A single module that generates, wraps (encrypts with the root key), stores, retrieves, versions, rotates, and retires cryptographic keys for every purpose in the system.

**Files Created or Modified:**
`crypto/key_manager.py`, `tests/unit/test_key_manager.py`.

**Implementation Tasks:**
- [ ] Load the root RSA key pair from decimal integer environment variables via `config.py` at process start: `ROOT_RSA_N`, `ROOT_RSA_E`, `ROOT_RSA_D`. The root RSA modulus is 2048 bits. Root private material is never stored in SQLite or Git.
- [ ] Implement `_wrap_private_key(private_key_material: bytes) -> bytes` — RSA-encrypts the private key material (RSA or ECC private scalar, or HMAC secret) using the root RSA public key, via `crypto/rsa.py`'s byte-chunking functions.
- [ ] Implement `_unwrap_private_key(wrapped: bytes) -> bytes` — RSA-decrypts using the root private key.
- [ ] Implement `generate_key(purpose: str, algorithm: str) -> dict` — calls `rsa.rsa_generate_keypair()` or `ecc.ecc_generate_keypair()` depending on `algorithm`, wraps the private part, inserts a new row into `keys` with `status="ACTIVE"`, `version = previous_max_version_for_purpose + 1`, and flips any prior `ACTIVE` row for that purpose to `RETIRED`.
- [ ] Implement `get_active_key(purpose: str) -> dict` — reads the `keys` row where `purpose=? AND status='ACTIVE'`, unwraps the private key, returns `{"version", "public_key", "private_key"}`.
- [ ] Implement `get_key_by_version(purpose: str, version: int) -> dict` — same as above but for a specific (possibly `RETIRED`) version; raises if the row is `REVOKED`.
- [ ] Implement `rotate_key(purpose: str) -> dict` — thin wrapper around `generate_key` documented as the operator-facing entry point (used by `admin/routes.py` in Phase 17).
- [ ] Implement `retire_key(purpose, version)` and `revoke_key(purpose, version)` for completeness of the lifecycle described in `project-context.md` §28, even though revocation is only exercised conceptually in this course project.
- [ ] Bootstrap: on first `init-db`/app start, if no `ACTIVE` key exists for `RSA_PROFILE`, `RSA_EVIDENCE`, `ECC_POSTS`, `ECC_CHAT`, `HMAC_CHAT`, `HMAC_SESSION`, call `generate_key` for each so the app has a usable key set out of the box.

**Dependencies:** Phases 1 (`keys` table), 2 (RSA, for wrapping and for `RSA_*` purposes), 3 (ECC, for `ECC_*` purposes), 4 (HMAC, for generating/using `HMAC_*` secrets — an HMAC "key" here is just random bytes, no asymmetric math needed to generate it, but it is still wrapped with the root RSA key before storage).

**Completion Criteria:** Phase complete only if:
- calling `get_active_key("RSA_PROFILE")` after bootstrap returns a usable key whose `private_key` matches what `generate_key` produced (round-trip through wrap/unwrap),
- `rotate_key("ECC_POSTS")` results in exactly one `ACTIVE` and the rest `RETIRED` for that purpose, with version numbers strictly increasing,
- the raw (unwrapped) private key material is never present in the `keys` table — only `encrypted_private_key` — verified by direct SQL inspection in a test,
- all unit tests pass.

**Tests (`tests/unit/test_key_manager.py`):**
- `test_generate_key_creates_active_row`.
- `test_wrap_unwrap_roundtrip` — wrap then unwrap returns original private key bytes.
- `test_private_key_never_stored_plaintext` — query the `keys` table directly, assert the stored blob does not equal/contain the raw private key.
- `test_get_active_key_returns_latest`.
- `test_rotate_key_retires_previous_version`.
- `test_get_key_by_version_after_rotation_still_works` — old version still retrievable for decryption after a new version becomes active.
- `test_revoked_key_is_not_retrievable` (expected-failure test).

**Report Evidence:** SQLite screenshot of the `keys` table showing `encrypted_private_key` as unreadable ciphertext next to a plaintext `public_key`; terminal output of a rotation showing version 1 → RETIRED, version 2 → ACTIVE (feeds report section 6 directly).

---

### Phase 6 — Registration and password security

**Goal:** Public registration creates student accounts only; profile fields are RSA-encrypted at rest; passwords are salted-and-hashed, never encrypted or recoverable. Admin accounts are created only by the controlled seed/setup process after this phase's hashing and RSA profile encryption exist.

**Files Created or Modified:**
`crypto/hashing.py`, `auth/routes.py` (registration endpoint), `templates/register.html`, `tests/unit/test_hashing.py`, `tests/integration/test_auth_flow.py` (registration cases).

**Implementation Tasks:**
- [ ] Implement `generate_salt(length_bytes=16) -> bytes` in `crypto/hashing.py` using `secrets.token_bytes`.
- [ ] Implement `hash_password(password: str, salt: bytes) -> bytes` as `SHA256(salt || password.encode())`.
- [ ] Implement `verify_password(password: str, salt: bytes, expected_hash: bytes) -> bool`.
- [ ] Write `GET/POST /register` in `auth/routes.py`: validate form input, normalize email with trim + lowercase, compute `email_lookup_hash = SHA256(normalized_email)`, generate password salt + hash, RSA-encrypt `name`/normalized `email`/`contact` via `key_manager.get_active_key("RSA_PROFILE")` + `crypto/rsa.py`, insert into `users` with `profile_key_version` set and forced `role="student"`.
- [ ] Ensure the public registration form and route never accept or render role selection. Any submitted `role` field is ignored or rejected; only `student` is stored from `/register`.
- [ ] Implement `database/seed.py::create_demo_admin()` now, using the same password hashing and RSA profile-encryption path as registration, but forcing `role="admin"` from the controlled setup script.
- [ ] Write `templates/register.html` (plain HTML/Jinja form, no client-side crypto).
- [ ] Reject duplicate emails by enforcing and checking the `UNIQUE` index on `users.email_lookup_hash`.

**Dependencies:** Phases 1 (users table), 2 (RSA), 5 (Key Manager).

**Completion Criteria:** Phase complete only if:
- registering a user results in a `users` row whose `encrypted_name`/`encrypted_email`/`encrypted_contact` are not human-readable,
- `password_hash`/`password_salt` are stored, and the raw password is not present anywhere in the database,
- re-encrypting the same plaintext with the same key on two different calls produces identical ciphertext bytes under deterministic textbook RSA,
- public registration cannot create an Admin even if a crafted request submits `role=admin`,
- the controlled seed/setup process can create an Admin only after hashing and RSA profile encryption are available,
- registering with an already-used email is rejected.

**Tests:**
- Unit (`test_hashing.py`): `test_hash_verify_roundtrip`, `test_wrong_password_fails_verification`, `test_same_password_different_salt_different_hash`.
- Integration (`test_auth_flow.py`): `test_register_creates_encrypted_profile_row`, `test_register_rejects_duplicate_email`, `test_password_never_stored_plaintext`, `test_public_register_forces_student_role`, `test_seed_creates_admin_with_hashed_password_and_encrypted_profile` (query DB directly and assert).

**Report Evidence:** SQLite screenshot of a `users` row showing ciphertext name/email/contact next to `password_hash`/`password_salt` (this is Demo 1 from `project-context.md` §45 and feeds report sections 2–4 directly).

---

### Phase 7 — Login and 2FA

**Goal:** Password verification followed by mandatory email-OTP verification before any session is created.

**Files Created or Modified:**
`auth/otp.py`, `services/email_service.py`, `auth/routes.py` (login + verify-otp endpoints), `templates/login.html`, `templates/verify_otp.html`, `tests/integration/test_auth_flow.py` (login/OTP cases).

**Implementation Tasks:**
- [ ] Implement `services/email_service.py::send_otp_email(to_address, otp_code)` calling the chosen provider's HTTP API (see [Section 10](#10-api--otp-integration-planning)).
- [ ] Implement `auth/otp.py::generate_otp() -> str` (6 random digits via `secrets.choice`).
- [ ] Implement `auth/otp.py::store_otp(user_id, otp_code)` — generates a fresh random `otp_salt`, stores `otp_hash = SHA256(otp_salt || otp_code.encode())`, inserts into `otp_codes` with `expires_at = now + OTP_EXPIRY_SECONDS`, `used=False`.
- [ ] Implement `auth/otp.py::verify_otp(user_id, submitted_code) -> bool` — fetch latest unused, unexpired row for `user_id`, hash the submitted code with the stored `otp_salt`, compare, mark `used=True` on success.
- [ ] Implement `auth/otp.py::invalidate_latest_otp(user_id)` (or equivalent) so failed email delivery cannot leave a valid OTP behind.
- [ ] Write `GET/POST /login` in `auth/routes.py`: normalize submitted email with trim + lowercase, compute `SHA256(normalized_email)`, look up `users.email_lookup_hash`, verify password via `crypto/hashing.py`, on success generate+store+send OTP and create only a pending-auth state for `/verify-otp`; do **not** create an authenticated session yet.
- [ ] If `send_otp_email` raises, invalidate/delete the newly generated OTP, clear the pending-auth state, and show only `"Verification code could not be sent. Please try again."`.
- [ ] Write `GET/POST /verify-otp`: require the pending-auth state, call `auth/otp.py::verify_otp`; on success, Phase 8 will call `auth/sessions.py::create_session(user)` and redirect to dashboard; on failure, show an error without revealing whether the code was wrong vs. expired vs. already used (avoid an information-leak side channel).
- [ ] Write `templates/login.html`, `templates/verify_otp.html`.

**Dependencies:** Phases 1 (otp_codes/users tables), 5, 6 (`crypto/hashing.py` exists from registration/password work).

**Completion Criteria:** Phase complete only if:
- correct password + correct, unexpired OTP reaches the OTP-success handoff point, with final session creation completed in Phase 8,
- correct password + expired OTP is rejected,
- correct password + wrong OTP is rejected,
- an OTP is single-use (reusing an already-`used` OTP is rejected),
- the raw OTP is never persisted — only `otp_hash` and `otp_salt`,
- no authenticated session exists before OTP succeeds,
- failed email delivery invalidates/deletes the OTP and cannot be verified later.

**Tests (`tests/integration/test_auth_flow.py`):**
- `test_login_with_correct_password_sends_otp` (mock `email_service.send_otp_email`).
- `test_login_uses_email_lookup_hash`.
- `test_login_with_wrong_password_rejected`.
- `test_verify_otp_success_path`.
- `test_verify_otp_expired_rejected` (expected-failure/security test — freeze/mock time or set an already-past `expires_at`).
- `test_verify_otp_reused_rejected` (expected-failure/security test).
- `test_verify_otp_wrong_code_rejected`.
- `test_raw_otp_not_persisted` — query `otp_codes`, assert no column equals the plaintext code.
- `test_otp_uses_fresh_salt`.
- `test_email_delivery_failure_invalidates_otp`.
- `test_no_session_before_otp_success`.

**Report Evidence:** Terminal/screenshot of the OTP email payload (from a test double or provider dashboard) alongside the `otp_codes` row showing only `otp_hash` and `otp_salt` (Demo 2, report section 5).

---

### Phase 8 — Secure session system

**Goal:** Sessions are created only after both factors succeed, are HMAC-protected, expire, can be revoked server-side, and use safe cookie flags.

**Files Created or Modified:**
`auth/sessions.py`, `auth/decorators.py`, `app.py` (cookie config), `tests/integration/test_sessions.py`.

**Implementation Tasks:**
- [ ] Implement `auth/sessions.py::create_session(user) -> str` (returns the cookie value): generate a cryptographically random `session_id` (`secrets.token_urlsafe`), compute `expires_at`, build the token payload `session_id || user_id || expires_at`, sign it with `crypto/hmac_custom.generate_mac(key_manager.get_active_key("HMAC_SESSION")..., payload)`, store `sha256(session_id)` (`session_id_hash`) + `user_id` + `expires_at` + `active=True` in `sessions`, return the full cookie value (`session_id.expires_at.signature`, base64/urlsafe-joined).
- [ ] Implement `auth/sessions.py::validate_session(cookie_value) -> Optional[user]`: parse the cookie, recompute HMAC over the parsed fields, `verify_mac`, check `expires_at` not passed, check the DB row for `session_id_hash` is `active=True`, return the associated user or `None`.
- [ ] Implement `auth/sessions.py::invalidate_session(cookie_value)` — sets `active=False` in `sessions` (logout).
- [ ] Finalize Phase 7's OTP-success path: after `verify_otp` returns true, call `auth/sessions.py::create_session(user)`, insert the server-side session row, set the signed cookie, clear the pending-auth state, and redirect to dashboard. There is no pre-OTP authenticated session to regenerate.
- [ ] Set cookie flags in `app.py`/`auth/routes.py`: `HttpOnly=True`, `SameSite="Lax"`, `SESSION_COOKIE_SECURE=False` for local development/demo, and configurable `True` for production/HTTPS.
- [ ] Implement `auth/decorators.py::login_required` — reads the cookie, calls `validate_session`, aborts `401`/redirects to `/login` on failure, else attaches `g.current_user`.
- [ ] Implement `/logout` route calling `invalidate_session` and clearing the cookie.

**Dependencies:** Phases 1 (sessions table), 4 (HMAC), 5 (Key Manager, purpose `HMAC_SESSION`), 7 (this is invoked from the OTP-success path).

**Completion Criteria:** Phase complete only if:
- no session exists in the `sessions` table before OTP success,
- a tampered cookie (any byte of `session_id`, `expires_at`, or signature changed) fails `validate_session`,
- an expired session is rejected even with a valid signature,
- `/logout` flips `active` to `False` and a subsequent request with the same cookie is rejected,
- no requirement exists to regenerate a pre-OTP authenticated session, because no authenticated session exists before OTP succeeds,
- cookie is set with `HttpOnly` (verified via response headers in a test).

**Tests (`tests/integration/test_sessions.py`):**
- `test_session_created_only_after_otp`.
- `test_valid_session_grants_access`.
- `test_tampered_signature_rejected` (security test).
- `test_tampered_expiry_rejected` (security test).
- `test_expired_session_rejected` (security test).
- `test_logout_invalidates_session` — reuse the old cookie after logout, expect rejection.
- `test_cookie_has_httponly_flag`.
- `test_dev_cookie_secure_false`.

**Report Evidence:** Terminal output of a tampered-cookie request being rejected with the signature-mismatch reason (report section 11); a diagram of the session flow (can reuse `project-context.md` §32–34 wording).

---

### Phase 9 — Profile module

**Goal:** Authenticated users can view/update their own (RSA-encrypted) profile.

**Files Created or Modified:**
`auth/routes.py` (profile endpoints) or a small `profile` blueprint reusing `auth/`, `templates/profile.html`, `tests/integration/test_profile.py` (or folded into `test_auth_flow.py`).

**Implementation Tasks:**
- [ ] Write `GET /profile`: `login_required`, fetch the current user's row, decrypt `encrypted_name`/`encrypted_email`/`encrypted_contact` via `key_manager.get_key_by_version("RSA_PROFILE", user.profile_key_version)` + `crypto/rsa.py`, render plaintext to the owner only.
- [ ] Write `POST /profile`: re-encrypt updated fields with the **current active** `RSA_PROFILE` key, update `profile_key_version` to the active version if it changed (this is itself a small "opportunistic re-encryption on write" — consistent with [Section 7](#7-key-versioning-rules)).
- [ ] Ensure no other user's profile is reachable through this route (ownership check via `auth/rbac.py`).

**Dependencies:** Phases 2, 5, 6, 8.

**Completion Criteria:** Phase complete only if:
- the owner sees correct decrypted plaintext,
- another logged-in student requesting `/profile?user_id=<other>` (or equivalent) is denied,
- updating the profile changes the ciphertext and, if the active key rotated since registration, the `profile_key_version`.

**Tests:** `test_profile_view_shows_decrypted_data_to_owner`, `test_profile_view_denies_other_user` (RBAC/security test), `test_profile_update_reencrypts_with_active_key`.

**Report Evidence:** Screenshot of the profile page showing decrypted plaintext next to the raw DB row showing ciphertext (report section 3).

---

### Phase 10 — Complaint/post module

**Goal:** Students can create/edit their own complaints; authenticated Students and Admins can view the public list; ECC protects title/description at rest; anonymous display works without breaking ownership.

**Files Created or Modified:**
`posts/routes.py`, `posts/services.py`, `templates/posts.html`, `templates/post_detail.html`, `templates/create_post.html`, `tests/integration/test_posts.py`.

**Implementation Tasks:**
- [ ] Implement `posts/services.py::create_post(owner_id, title, description, anonymous) -> post_id` — validates title length ≤ 120 characters and description length ≤ 500 characters, ECC-encrypts `title`/`description` via `key_manager.get_active_key("ECC_POSTS")` + `crypto/ecc_encoding.py`, inserts into `posts` with `status="Pending"`, `ecc_key_version` set.
- [ ] Implement `posts/services.py::get_post_for_display(post_id, viewer) -> dict` — requires an authenticated viewer, decrypts title/description server-side for authenticated Students/Admins, applies the anonymous-display rule (`display_owner = "Anonymous Student"` if `anonymous` else the owner's decrypted name).
- [ ] Implement `posts/services.py::list_public_posts(viewer) -> list[dict]` — same decryption + anonymization per row.
- [ ] Implement `posts/services.py::update_post(post_id, editor_id, **fields)` — ownership check (`auth/rbac.py`), re-encrypts with the currently active `ECC_POSTS` key, updates `updated_at`.
- [ ] Write `posts/routes.py`: `GET /posts` (list, `login_required`), `GET /posts/<id>` (detail, `login_required`), `GET/POST /posts/new` (create, logged-in student), `GET/POST /posts/<id>/edit` (owner only).
- [ ] Write the three templates, passing only pre-decrypted, pre-authorized data into context (Rule 9 from [Section 2](#2-modularity-rules)).

**Dependencies:** Phases 1, 3, 5, 8.

**Completion Criteria:** Phase complete only if:
- creating a post stores ECC ciphertext (not plaintext) for title/description,
- the owner can edit their own post; a different student attempting to edit it is denied,
- an anonymous post shows "Anonymous Student" to other students but the true `owner_id` is unchanged in the database,
- the public list is visible to authenticated Students and Admins,
- unauthenticated visitors are redirected or rejected before post content is decrypted.

**Tests (`tests/integration/test_posts.py`):**
- `test_create_post_stores_ciphertext`.
- `test_owner_can_edit_own_post`.
- `test_non_owner_cannot_edit_post` (security test).
- `test_anonymous_post_hides_owner_name_but_keeps_owner_id`.
- `test_public_post_listing_decrypts_for_authorized_viewer`.
- `test_public_post_listing_requires_login`.
- `test_post_title_and_description_length_limits`.

**Report Evidence:** SQLite screenshot of a post row showing ECC ciphertext for title/description (Demo 3); screenshot of the same post rendered as "Anonymous Student" to a second logged-in student (Demo 4).

---

### Phase 11 — Upvotes

**Goal:** Students can upvote complaints they don't own, at most once per post; no commenting capability exists anywhere.

**Files Created or Modified:**
`posts/services.py` (upvote functions), `posts/routes.py` (upvote endpoint), `templates/post_detail.html` (upvote button + count), `tests/integration/test_upvotes.py`.

**Implementation Tasks:**
- [ ] Add a `UNIQUE(user_id, post_id)` constraint on `upvotes` in `database/schema.sql` (should already be present from Phase 1; verify here).
- [ ] Implement `posts/services.py::upvote_post(user_id, post_id)` — `INSERT`, catching/translating the `UNIQUE` constraint violation into a clean "already upvoted" response rather than a raw DB error.
- [ ] Implement `posts/services.py::get_upvote_count(post_id)` and `has_user_upvoted(user_id, post_id)`.
- [ ] Write `POST /posts/<id>/upvote` in `posts/routes.py`, `login_required`.
- [ ] Confirm (do not implement — confirm by omission) that no comment table, route, or template exists anywhere in the codebase.

**Dependencies:** Phase 10.

**Completion Criteria:** Phase complete only if:
- a student can upvote another student's post once,
- a second upvote attempt by the same student on the same post is rejected without a server error,
- the upvote count displayed matches the row count in `upvotes`,
- there is no code path allowing a text comment to be attached to a post.

**Tests (`tests/integration/test_upvotes.py`):**
- `test_upvote_increments_count`.
- `test_duplicate_upvote_rejected` (security/integrity test).
- `test_owner_cannot_upvote_own_post` — owners cannot upvote their own complaints.

**Report Evidence:** Screenshot of the upvote count incrementing and a rejected duplicate-upvote attempt (Demo 5).

---

### Phase 12 — Evidence upload/encryption

**Goal:** Post owners can upload PDF/PNG/JPG/JPEG evidence (≤ 200 KB); files and original filenames are RSA block-encrypted at rest; only the owner and Admin can decrypt/view; no plaintext copies persist on disk.

**Files Created or Modified:**
`evidence/routes.py`, `evidence/services.py`, `templates/post_detail.html` (upload form + evidence link), `tests/integration/test_evidence.py`.

**Implementation Tasks:**
- [ ] Implement `evidence/routes.py::POST /posts/<id>/evidence` — owner-only, validates MIME/extension against an allow-list (`.pdf`, `.png`, `.jpg`, `.jpeg`) and `Content-Length` against `MAX_EVIDENCE_SIZE_BYTES` (200 KB) before reading the body.
- [ ] Implement `evidence/services.py::store_evidence(post_id, owner_id, filename, file_bytes) -> evidence_id` — RSA-encrypts `file_bytes` in blocks via `crypto/rsa.py` (using `key_manager.get_active_key("RSA_EVIDENCE")`), writes the resulting ciphertext to `encrypted_uploads/evidence_<id>.enc`, RSA-encrypts the original filename using `RSA_EVIDENCE`, inserts into `evidence` with plaintext metadata `file_path = encrypted_uploads/evidence_<id>.enc` and `rsa_key_version`.
- [ ] Implement `evidence/services.py::read_evidence(evidence_id, requester) -> (decrypted_filename, decrypted_bytes, mimetype)` — RBAC check first (`auth/rbac.py::can_view_evidence`), then read the `.enc` file, `key_manager.get_key_by_version("RSA_EVIDENCE", row.rsa_key_version)`, decrypt in memory, return bytes without ever writing them to disk.
- [ ] Implement `evidence/routes.py::GET /evidence/<id>` streaming the decrypted bytes as a Flask response with the correct `Content-Type` and `Content-Disposition`, never caching them on disk.
- [ ] Confirm `encrypted_uploads/` is git-ignored and that no route ever calls `send_from_directory` on a plaintext path.

**Dependencies:** Phases 1, 2, 5, 8, 10.

**Completion Criteria:** Phase complete only if:
- uploading a valid PDF/PNG/JPG/JPEG under 200 KB succeeds and the file on disk under `encrypted_uploads/` is not renderable as the original format (i.e., it is ciphertext),
- the post owner can retrieve and view the original file correctly,
- the Admin can retrieve and view it,
- a different (non-owner, non-admin) student is denied with a `403`,
- an oversized or wrong-type upload is rejected before encryption,
- the original filename is encrypted, while the on-disk `file_path` is plaintext non-sensitive metadata derived from the evidence id,
- no plaintext file ever appears anywhere under the project directory after an upload/view cycle.

**Tests (`tests/integration/test_evidence.py`):**
- `test_owner_can_upload_and_view_evidence`.
- `test_admin_can_view_evidence`.
- `test_other_student_denied_evidence` (security test).
- `test_oversized_file_rejected`.
- `test_wrong_file_type_rejected`.
- `test_filename_encrypted_but_file_path_plain_id_derived`.
- `test_stored_file_is_not_plaintext` — read the `.enc` file's raw bytes, assert they do not match known JPEG/PNG/PDF magic-byte signatures of the original.
- `test_view_does_not_leave_plaintext_on_disk` — after a `GET /evidence/<id>`, assert `encrypted_uploads/` contains only `.enc` files.

**Report Evidence:** Screenshot of the `encrypted_uploads/` directory showing only `.enc` files; a failed attempt to open one directly as an image/PDF; the three-way access matrix demonstrated live (Demo 6, report section 8).

---

### Phase 13 — Admin acknowledgement/status

**Goal:** Admins can acknowledge complaints and move them through `Pending → Acknowledged → Resolved`, server-side enforced.

**Files Created or Modified:**
`admin/routes.py`, `posts/services.py` (status-change function), `templates/admin/posts.html`, `templates/admin/post_detail.html`, `tests/integration/test_rbac.py` (status-change cases).

**Implementation Tasks:**
- [ ] Implement `posts/services.py::change_status(post_id, new_status, actor)` — validates `new_status` is one of the three allowed values and enforces forward-only transitions: `Pending → Acknowledged → Resolved`, then updates `updated_at`.
- [ ] Implement `posts/services.py::acknowledge_post(post_id, actor)` — convenience wrapper setting `status = "Acknowledged"`. Acknowledgement is not a separate database concept and no `acknowledged_at`/`acknowledged_by` field is added.
- [ ] Write `admin/routes.py::GET /admin/posts` (list all posts with owner-identifying info, since Admin is authorized to see it even on anonymous posts), `GET /admin/posts/<id>`, `POST /admin/posts/<id>/status`, `POST /admin/posts/<id>/acknowledge`, all wrapped in `@role_required("admin")`.
- [ ] Write `templates/admin/posts.html`, `templates/admin/post_detail.html`.

**Dependencies:** Phases 8, 10, plus Phase 12 to show evidence inline on the admin detail page.

**Completion Criteria:** Phase complete only if:
- a non-admin cannot reach any `/admin/*` route (`403`/redirect),
- an admin can move a post from `Pending` to `Acknowledged` to `Resolved`,
- status changes are visible to the post owner and in the public list,
- the admin view of an anonymous post still shows the true owner identity (per `project-context.md` §6, "Admin can view complaint owner information where authorized").

**Tests:** `test_admin_can_change_status`, `test_student_cannot_change_status` (security test), `test_admin_sees_true_owner_on_anonymous_post`, `test_status_change_reflected_in_public_view`.

**Report Evidence:** Screenshots of the three status states and the admin panel (Demo 7, report section 7).

---

### Phase 14 — Private Admin ↔ Owner chat

**Goal:** ECC-encrypted, HMAC-integrity-protected private messaging restricted to the complaint owner and Admin.

**Files Created or Modified:**
`chat/routes.py`, `chat/services.py`, `templates/chat.html`, `tests/integration/test_chat.py`.

**Implementation Tasks:**
- [ ] Implement `chat/services.py::send_message(post_id, sender_id, plaintext) -> message_id` implementing the Encrypt → MAC → Store flow from `project-context.md` §21: validate private chat message length ≤ 300 characters, ECC-encrypt `plaintext` (`key_manager.get_active_key("ECC_CHAT")` + `crypto/ecc_encoding.py`), serialize ciphertext as JSON TEXT using centralized ECC serialization helpers, compute `mac = generate_mac(hmac_key, post_id || sender_id || timestamp || ciphertext)` using `key_manager.get_active_key("HMAC_CHAT")`, insert into `chat_messages` with `ecc_key_version` and `hmac_key_version`. There is no `receiver_id`; conversation membership is derived from the post.
- [ ] Implement `chat/services.py::get_conversation(post_id, requester) -> list[dict]` implementing the Retrieve → Verify MAC → Decrypt flow from §22: for each message, recompute the MAC over the same field concatenation, compare; on match decrypt and include plaintext + `integrity_ok=True`; on mismatch include `integrity_ok=False` and the warning text `"Message integrity verification failed. Possible unauthorized modification detected."` **without** attempting decryption.
- [ ] Implement authorization in `auth/rbac.py::can_access_chat(user, post)` — true only for the post's owner or any Admin; wire it into `chat/routes.py`.
- [ ] Write `chat/routes.py::GET /posts/<id>/chat` (view conversation), `POST /posts/<id>/chat` (send message). The post owner may access their own conversation; any Admin may access any post conversation; everyone else is denied.
- [ ] Write `templates/chat.html`, rendering `integrity_ok` as a pre-computed boolean (never computing MAC logic in the template).

**Dependencies:** Phases 3, 4, 5, 8, 10, 13 (chat is reached from a post's detail/admin page).

**Completion Criteria:** Phase complete only if:
- the post owner and Admin can exchange messages and read them correctly,
- a different logged-in student cannot reach the conversation at all (`403`, not just a hidden UI element),
- old messages continue verifying after `HMAC_CHAT` rotation because each row stores `hmac_key_version`,
- manually corrupting a stored `ciphertext` or `mac` value in SQLite and reloading the conversation shows the tamper warning instead of garbled/incorrect plaintext,
- an untouched message never shows the tamper warning (no false positives).

**Tests (`tests/integration/test_chat.py`):**
- `test_owner_and_admin_can_exchange_messages`.
- `test_other_student_denied_chat_access` (security test).
- `test_tampered_ciphertext_detected` — directly `UPDATE chat_messages SET ciphertext=?`, then assert `get_conversation` reports `integrity_ok=False` and does not return decrypted plaintext.
- `test_tampered_mac_detected`.
- `test_untampered_message_not_flagged` (regression against false positives).
- `test_message_moved_to_different_post_context_fails_mac` — copy a valid `(ciphertext, mac)` pair into a row with a different `post_id`, assert MAC verification fails (validates the anti-replay-across-conversations property from §21).
- `test_hmac_chat_rotation_preserves_old_message_verification`.
- `test_private_chat_message_length_limit`.

**Report Evidence:** Live demo screenshot sequence: normal message → manually edited SQLite value → reload showing the integrity-failure warning (Demo 8 & Demo 9, report section 9).

---

### Phase 15 — MAC tamper detection (demonstration hardening)

**Goal:** Turn the tamper-detection behavior already built in Phase 14 into a clean, repeatable, presentation-ready demonstration, and confirm it also protects session tokens end-to-end (session HMAC was built in Phase 8; this phase is where both are validated together for the report).

**Files Created or Modified:**
`tests/integration/test_chat.py` (add a scripted end-to-end tamper scenario if not already present), `tests/integration/test_sessions.py` (cross-check), possibly a small `database/seed.py` helper or a documented manual SQL snippet for the live demo (not application code).

**Implementation Tasks:**
- [ ] Write a documented, copy-pasteable SQL snippet (kept in `README.md` or a `docs/demo-script.md`) that corrupts one byte of a chosen `chat_messages.ciphertext` for the live faculty demonstration.
- [ ] Verify the exact warning string matches `project-context.md` §22's example (`"Message integrity verification failed. Possible unauthorized modification detected."`) so the report and the live app are consistent.
- [ ] Add a combined integration test that (a) sends a message, (b) reads it back successfully, (c) corrupts it via raw SQL, (d) reads it again and asserts the warning, in one scripted flow mirroring the presentation.
- [ ] Cross-check that a tampered **session** cookie (already tested in Phase 8) produces an analogous, clearly worded rejection, so both integrity mechanisms are presented consistently in the report.

**Dependencies:** Phases 4, 8, 14.

**Completion Criteria:** Phase complete only if the scripted end-to-end test passes reliably (not flaky) and the demo SQL snippet has been manually run once against a real dev database with the expected result captured.

**Tests:** `test_chat.py::test_full_tamper_detection_demo_flow` (as described above).

**Report Evidence:** The exact terminal/UI sequence captured as the primary artifact for report section 9 (Message Authentication Code).

---

### Phase 16 — RBAC hardening

**Goal:** A horizontal audit pass confirming every sensitive route enforces authentication, role, and ownership server-side — closing any gaps left by earlier phases moving quickly.

**Files Created or Modified:**
`auth/rbac.py` (fill in any missing rule), possibly small fixes across `posts/routes.py`, `evidence/routes.py`, `chat/routes.py`, `admin/routes.py`; `tests/integration/test_rbac.py` (comprehensive matrix).

**Implementation Tasks:**
- [ ] Walk every route registered in `app.py` and classify it as public, login-required, or login+role/ownership-required, cross-referencing the [Permission Matrix](#8-rbac-planning).
- [ ] For every login-or-higher route, confirm it is decorated with `@login_required` and, where applicable, `@role_required("admin")` or an explicit `auth/rbac.py` ownership check — not a template-only guard.
- [ ] Add any missing check found during the audit; do not add new features here.
- [ ] Write a single comprehensive `tests/integration/test_rbac.py` that iterates the full [Permission Matrix](#8-rbac-planning) programmatically (one parametrized test per matrix cell where feasible) rather than relying only on the scattered per-feature security tests from earlier phases.

**Dependencies:** Every route-producing phase (6–14).

**Completion Criteria:** Phase complete only if every cell of the [Permission Matrix](#8-rbac-planning) has a corresponding passing test, and no route is found during the audit that relies solely on hidden UI for protection.

**Tests:** `tests/integration/test_rbac.py` — parametrized matrix test as described above.

**Report Evidence:** The completed permission matrix plus a summary of the audit (report section 10); note any gap that was found and fixed, since "we found and closed a gap" is strong report material.

---

### Phase 17 — Key rotation demonstration

**Goal:** Show a key purpose being rotated live, with old data still decrypting correctly under its original version and new data using the new version.

**Files Created or Modified:**
`admin/routes.py` (rotation trigger endpoint), `templates/admin/keys.html`, `tests/integration/test_key_rotation.py`.

**Implementation Tasks:**
- [ ] Write `admin/routes.py::GET /admin/keys` — lists all rows in `keys` (public parts + status/version only, never decrypted private material) grouped by purpose.
- [ ] Write `admin/routes.py::POST /admin/keys/<purpose>/rotate` — `@role_required("admin")`, calls `key_manager.rotate_key(purpose)`.
- [ ] Write `templates/admin/keys.html` showing purpose, version, status (ACTIVE/RETIRED/REVOKED), created/retired timestamps.
- [ ] Write the demo test/script: create a post under the current `ECC_POSTS` version, rotate `ECC_POSTS`, create a second post, assert both are readable and each row's `ecc_key_version` matches the version active at creation time.

**Dependencies:** Phases 5, 10 (or 12/14, whichever purpose the team demos — the plan below assumes `ECC_POSTS`, but the same test pattern applies to `RSA_EVIDENCE` or `ECC_CHAT`).

**Completion Criteria:** Phase complete only if, after rotation, the pre-rotation record decrypts correctly using its stored `key_version`, the post-rotation record decrypts correctly using the new version, and the `keys` table shows exactly one `ACTIVE` row per purpose at all times.

**Tests (`tests/integration/test_key_rotation.py`):**
- `test_rotate_key_updates_active_status`.
- `test_old_data_decrypts_after_rotation` (the critical test named explicitly in the prompt's testing list).
- `test_new_data_uses_new_version_after_rotation`.
- `test_only_one_active_key_per_purpose_at_any_time`.

**Report Evidence:** Demo 10 exactly as scripted in `project-context.md` §45 — a screenshot sequence of v1 ACTIVE → rotate → v1 RETIRED/v2 ACTIVE → both old and new posts decrypting correctly (report section 6).

---

### Phase 18 — Testing

**Goal:** Consolidate, fill gaps in, and run the full test suite end-to-end; this is a coverage/quality pass, not where testing starts (each phase above already ships its own tests).

**Files Created or Modified:**
`tests/conftest.py` (shared fixtures: temp SQLite DB per test, test Flask app/client, factory functions for a student/admin user, a post, an evidence row, a chat message), any test file needing additions to reach the full list in [Testing Structure](#11-testing-structure).

**Implementation Tasks:**
- [ ] Write `tests/conftest.py` fixtures: `app`, `client`, `db`, `student_user`, `admin_user`, `authenticated_client(role)`.
- [ ] Cross-check the full required test list in [Section 11](#11-testing-structure) against what exists after Phases 2–17; add any missing test.
- [ ] Run `pytest --maxfail=1 -q` and fix any failure.
- [ ] Add a coverage report (`pytest-cov` or `coverage.py`) run, purely informational — 100% is not required, but every module in `crypto/` should be exercised.
- [ ] Confirm test isolation: no test writes to the real dev `.db` file or the real `encrypted_uploads/` directory (use a temp path fixture).

**Dependencies:** All prior phases.

**Completion Criteria:** Phase complete only if the entire suite passes in one run from a clean checkout (`pip install -r requirements.txt && flask init-db && pytest`), and every test named across Phases 2–17 exists and is green.

**Tests:** The full suite itself is the deliverable.

**Report Evidence:** Terminal output of a full green `pytest` run; coverage summary table.

---

### Phase 19 — Final report evidence collection

**Goal:** Assemble the screenshots, DB records, terminal outputs, and diagrams gathered throughout Phases 0–18 into the structure the CSE447 report template expects.

**Files Created or Modified:** No application code. A `docs/report-evidence/` folder (screenshots, exported SQL, terminal logs) and/or direct insertion into the report document, organized per [Report Evidence Checklist](#12-report-evidence-checklist).

**Implementation Tasks:**
- [ ] Re-run each phase's demo (registration, login/OTP, post creation, upvote, evidence upload, acknowledgement, chat, tamper detection, key rotation) once, end-to-end, on a freshly seeded database, capturing evidence in one continuous pass so all screenshots reflect a mutually consistent state (same user IDs, same post, etc.) — this avoids a report with inconsistent-looking mismatched screenshots from different sessions.
- [ ] File every artifact under the report section it belongs to per [Section 12](#12-report-evidence-checklist).
- [ ] Cross-check `README.md` documents setup/run instructions accurately (used for report section 12, GitHub Structure).

**Dependencies:** All prior phases complete and passing.

**Completion Criteria:** Phase complete only if every row in the [Report Evidence Checklist](#12-report-evidence-checklist) has a corresponding captured artifact.

**Tests:** None (documentation phase).

**Report Evidence:** This phase *is* the report evidence collection — its output is the checklist itself, filled in.

---

## 5. Cryptography Dependency Map

```text
RSA (crypto/rsa.py)
 ├─→ user/profile data                      (users.encrypted_name/email/contact)
 ├─→ evidence files                         (evidence, RSA block/chunk encryption)
 └─→ key protection                          (key_manager wraps RSA/ECC/HMAC key
                                               material with the root RSA key)

ECC / EC-ElGamal (crypto/ecc.py, ecc_curve.py, ecc_encoding.py)
 ├─→ complaint title/description             (posts.encrypted_title/description)
 ├─→ Admin responses                          (Admin-authored private chat messages)
 └─→ private chat                             (chat_messages.ciphertext)

HMAC-SHA256 (crypto/hmac_custom.py)
 ├─→ private-chat integrity                   (chat_messages.mac)
 └─→ session integrity                        (session cookie signature; sessions
                                               table tracks revocation, not the MAC
                                               itself)

SHA-256 + salt (crypto/hashing.py)
 └─→ password storage                         (users.password_hash/password_salt)
     └─→ OTP hashing                           (otp_codes.otp_hash/otp_salt)

Email OTP (auth/otp.py + services/email_service.py)
 └─→ second authentication factor              (gates session creation in
                                               auth/sessions.py)

Key Manager (crypto/key_manager.py)
 ├─→ owns RSA key versions/lifecycle           (purposes: RSA_PROFILE, RSA_EVIDENCE)
 ├─→ owns ECC key versions/lifecycle           (purposes: ECC_POSTS, ECC_CHAT)
 └─→ owns HMAC key versions/lifecycle          (purposes: HMAC_CHAT, HMAC_SESSION)
```

No AES or any other symmetric cipher appears anywhere in this map, consistent with `project-context.md` §12–13 and `crypto-plan.md` §2/§4/§6.

---

## 6. Database Planning

Implementation order matches Phase 1 (all tables are created together in `schema.sql`), but logically `keys` and `users` are the two tables everything else references, so they are described first.

### `keys`
- **Purpose:** Stores every versioned cryptographic key (RSA, ECC, HMAC) for every purpose, with the private material wrapped by the root key.
- **Primary key:** `id` (surrogate integer).
- **Important columns:** `algorithm` (`RSA`/`ECC`/`HMAC`), `purpose` (`RSA_PROFILE`, `RSA_EVIDENCE`, `ECC_POSTS`, `ECC_CHAT`, `HMAC_CHAT`, `HMAC_SESSION`), `version` (integer, unique per `purpose`), `public_key` (plaintext — public by definition; empty/null for HMAC secrets, which have no public half), `encrypted_private_key` (RSA-wrapped blob — this *is* the sensitive column), `status` (`ACTIVE`/`RETIRED`/`REVOKED`), `created_at`, `retired_at`.
- **No foreign keys** — this table is referenced *by version number*, not by row id, from `users.profile_key_version`, `posts.ecc_key_version`, `evidence.rsa_key_version`, `chat_messages.ecc_key_version` (composite logical reference: `purpose` is implied by which column is referencing it, `version` is the value stored).

### `users`
- **Purpose:** Account + RSA-encrypted profile data + password credential.
- **Primary key:** `id`.
- **Encrypted fields:** `encrypted_name`, `encrypted_email`, `encrypted_contact` (RSA ciphertext, stored as `BLOB`).
- **Plaintext metadata fields:** `role` (`student`/`admin`), `created_at`, `profile_key_version` (int, references a `keys` row logically), `password_hash`, `password_salt`, `email_lookup_hash` (`SHA256(trim(lowercase(email)))`, deterministic lookup/uniqueness value; not reversible plaintext).
- **Constraints:** `email_lookup_hash` has a `UNIQUE` index. Public `/register` always creates `role="student"`; admin rows are created only by controlled seed/setup code after Phase 6.

### `sessions`
- **Purpose:** Server-side session registry enabling revocation independent of the signed cookie.
- **Primary key:** `id`.
- **Important columns:** `session_id_hash` (SHA-256 of the raw session id — never store the raw id, only the client's signed cookie has it), `user_id` (FK → `users.id`), `expires_at`, `active` (boolean), `created_at`.
- **Plaintext metadata:** all of the above are metadata, not sensitive content, per §44.
- **Key-version field:** none. `HMAC_SESSION` rotation intentionally invalidates existing sessions; users log in again after a session-key rotation.

### `otp_codes`
- **Purpose:** Short-lived, single-use second-factor codes.
- **Primary key:** `id`.
- **Important columns:** `user_id` (FK → `users.id`), `otp_hash`, `otp_salt`, `expires_at`, `used` (boolean), `created_at`. No encrypted/content field — the code itself is never stored in recoverable form (§42).

### `posts`
- **Purpose:** Complaints/suggestions.
- **Primary key:** `id`.
- **Important foreign keys:** `owner_id` → `users.id`.
- **Encrypted fields:** `encrypted_title`, `encrypted_description` (ECC ciphertext serialized as JSON TEXT; each encrypted byte entry is `[c1_x, c1_y, c2_x, c2_y]` via centralized helpers).
- **Plaintext metadata fields:** `anonymous` (boolean), `status` (`Pending`/`Acknowledged`/`Resolved`), `created_at`, `updated_at`.
- **Key-version field:** `ecc_key_version`.
- **Application limits:** title ≤ 120 characters; description ≤ 500 characters.

### `upvotes`
- **Purpose:** One-per-student-per-post support signal.
- **Primary key:** `id` (or a composite PK on `(user_id, post_id)` — either works; a `UNIQUE(user_id, post_id)` constraint is mandatory regardless).
- **Important foreign keys:** `user_id` → `users.id`, `post_id` → `posts.id`.
- **No encrypted fields** — nothing sensitive here.

### `evidence`
- **Purpose:** Metadata for RSA-encrypted uploaded files; the file bytes themselves live under `encrypted_uploads/`, not in SQLite.
- **Primary key:** `id`.
- **Important foreign keys:** `post_id` → `posts.id`, `owner_id` → `users.id`.
- **Encrypted fields:** `encrypted_filename` (RSA ciphertext of the original filename).
- **Plaintext metadata fields:** `file_path` (`encrypted_uploads/evidence_<id>.enc`, non-sensitive id-derived path), `created_at`.
- **Key-version field:** `rsa_key_version`.
- **Application limits:** allowed file types are PDF, PNG, JPG/JPEG; maximum size is 200 KB.

### `chat_messages`
- **Purpose:** Private Admin ↔ owner conversation tied to a complaint.
- **Primary key:** `id`.
- **Important foreign keys:** `post_id` → `posts.id`, `sender_id` → `users.id`. There is no `receiver_id`; conversation membership is derived from the post.
- **Encrypted fields:** `ciphertext` (ECC JSON TEXT; each encrypted byte entry is `[c1_x, c1_y, c2_x, c2_y]`).
- **Plaintext metadata fields:** `created_at` (used as the `timestamp` input to the MAC — must be captured *before* MAC computation and never altered afterward without invalidating the MAC, by design).
- **Integrity field:** `mac` (HMAC-SHA256 output over `post_id || sender_id || timestamp || ciphertext`).
- **Key-version fields:** `ecc_key_version`, `hmac_key_version`. Old messages must continue verifying after `HMAC_CHAT` rotation.
- **Application limits:** private chat message ≤ 300 characters.

**Implementation order within Phase 1:** `keys`, `users`, `sessions`, `otp_codes`, `posts`, `upvotes`, `evidence`, `chat_messages` — this is the order `schema.sql` defines them in, respecting foreign-key dependency direction (a table is defined after every table it references).

---

## 7. Key Versioning Rules

- **No module ever assumes a single permanent key.** Every encrypted record stores the `version` that was `ACTIVE` at the moment of encryption (`profile_key_version`, `ecc_key_version`, `rsa_key_version`, and for chat integrity `hmac_key_version`), and every decryption/verification path looks that version up explicitly — it never asks the Key Manager for "the key," only for "the active key" (writes) or "the key for version N" (reads).
- **Encryption path:** `service.py` function → `key_manager.get_active_key(purpose)` → returns `{version, public_key, private_key}` → service encrypts with `public_key` → service stores ciphertext **and** `version` together in the same `INSERT`/`UPDATE`. The version is never looked up in a second query after the encryption call — same call, same version, to avoid a race where rotation happens between "ask for the key" and "write the row."
- **Decryption path:** `service.py` function reads the row (which already contains its own `*_key_version`) → `key_manager.get_key_by_version(purpose, stored_version)` → decrypts with the returned `private_key`. This works identically whether the stored version is currently `ACTIVE` or `RETIRED`; it only breaks if the version is `REVOKED` (by design — revocation is meant to be terminal, reached only after data using that version has been migrated).
- **Rotation:** `key_manager.rotate_key(purpose)` generates version `N+1`, marks it `ACTIVE`, flips the previous `ACTIVE` row for that `purpose` to `RETIRED`. It does **not** touch any existing data row — no bulk re-encryption happens automatically. Re-encryption onto a new version only happens opportunistically when a record is next *written* through its normal update path (e.g., Phase 9's profile update re-encrypts with whatever is active at that moment), never as a background job (keeping with "no Celery/Redis," Rule 5 in [Section 2](#2-modularity-rules)).
- **Multiple simultaneously-valid versions are expected and correct** — this is exactly what makes Phase 17's demonstration possible (old post still decrypts under v1 while new posts use v2).
- **Exception for sessions:** `HMAC_SESSION` rotation intentionally invalidates existing sessions. The `sessions` table does not store historical session HMAC key versions; users must log in again after session-key rotation.

---

## 8. RBAC Planning

### Student can:
- view/update own profile,
- create a post, edit **own** post,
- view any public post after authentication (title/description decrypted for display),
- upvote another student's post at most once,
- upload evidence to **own** post,
- view evidence only on **own** post,
- access private chat only on **own** post, only with Admin.

### Student cannot:
- create an Admin account through public registration,
- edit another student's post,
- view another student's evidence,
- access another student's private Admin chat,
- change a post's status or acknowledge it,
- perform any key-management operation,
- reach any `/admin/*` route.

### Admin can:
- be created only by controlled seed/setup, not by public registration,
- view any post (including true owner identity even when `anonymous=True`),
- view any evidence,
- acknowledge a post / change its status,
- chat privately with any post's owner,
- perform key-management operations (view key status, trigger rotation).

### Ownership checks required, by route:

| Route | Check |
|---|---|
| `GET/POST /register` | public, but always creates `role="student"` and rejects/ignores role selection |
| `GET /posts`, `GET /posts/<id>` | `login_required`; authenticated Students/Admins may view public posts |
| `GET/POST /profile` | requester's `user_id == users.id` being viewed/edited |
| `GET/POST /posts/<id>/edit` | requester's `user_id == posts.owner_id` |
| `POST /posts/<id>/upvote` | requester is authenticated, is not the post owner, and has not already upvoted the post |
| `POST /posts/<id>/evidence` (upload) | requester's `user_id == posts.owner_id` |
| `GET /evidence/<id>` | requester's `user_id == evidence.owner_id` **or** requester's `role == "admin"` |
| `GET/POST /posts/<id>/chat` | requester's `user_id == posts.owner_id` **or** requester's `role == "admin"` |
| `POST /admin/posts/<id>/status`, `/acknowledge` | requester's `role == "admin"` (no ownership dimension — any admin may act on any post) |
| `GET/POST /admin/keys*` | requester's `role == "admin"` |

Every check in this table is implemented once in `auth/rbac.py` and invoked from the corresponding route via `auth/decorators.py`, never re-implemented inline (Rule 7, [Section 2](#2-modularity-rules)). Frontend visibility (hiding an "Edit" button) is a UX nicety layered on top of, never a substitute for, this table.

---

## 9. Secure Session Planning

Session handling is fully isolated inside `auth/sessions.py`; no other module builds, parses, or trusts a session value on its own.

- **Session generation:** happens exclusively inside `auth/sessions.py::create_session(user)`, called exclusively from the OTP-success branch finalized in Phase 8 — never from the plain-password-success branch, and never from anywhere else in the codebase.
- **Session validation:** happens exclusively inside `auth/sessions.py::validate_session(cookie_value)`, called exclusively from `auth/decorators.py::login_required`. Route handlers never parse the cookie themselves.
- **HMAC verification:** the cookie payload (`session_id || user_id || expires_at`) is signed with `crypto/hmac_custom.py` using the `HMAC_SESSION` purpose key from `crypto/key_manager.py`; `validate_session` recomputes and compares before trusting any field, including `user_id` (Rule 6, [Section 2](#2-modularity-rules) — never trust a client-supplied user id without server-side verification).
- **Expiry:** `expires_at` is part of the signed payload (so it cannot be silently extended by the client) and is checked against the current server time on every `validate_session` call, independent of the DB row's own bookkeeping.
- **Logout invalidation:** `auth/sessions.py::invalidate_session` sets the DB row's `active=False`; this is checked on every subsequent `validate_session` call even if the signature and expiry are still technically valid — this is what makes logout a real server-side revocation rather than just deleting a cookie.
- **Pending-auth state:** Phase 7 may keep only a pending-auth marker between password success and OTP verification. It is not an authenticated session and must not grant access to `login_required` routes.
- **No pre-OTP session regeneration:** no authenticated session exists before OTP succeeds, so the OTP-success path creates the first authenticated session instead of regenerating a pre-OTP session.
- **Session-key rotation:** rotating `HMAC_SESSION` intentionally invalidates existing sessions because validation uses the currently active session HMAC key and the `sessions` table has no historical key-version column.
- **Cookie settings:** `HttpOnly=True` always; `SameSite="Lax"` always; `SESSION_COOKIE_SECURE=False` for local development/demo, configurable `True` for production/HTTPS.
- **Owning module:** `auth/sessions.py` is the single owner of all of the above. `auth/decorators.py` is a thin consumer of it. `app.py` only sets process-wide cookie defaults (name, path) and delegates value construction entirely to `auth/sessions.py`.

---

## 10. API / OTP Integration Planning

The external email API's role is strictly limited to *delivering* an OTP email; the application owns generation, hashing, expiration, verification, and invalidation end-to-end, per `project-context.md` §5 and `crypto-plan.md` §9.

```text
auth/otp.py                          services/email_service.py
─────────────                        ──────────────────────────
generate_otp()          ──calls──▶   send_otp_email(to, code)
store_otp() [hash+expiry]                    │
verify_otp() [compare+invalidate]            ▼
                                      Resend or Brevo HTTP API
                                      (delivery only — no crypto,
                                       no verification logic)
```

- **Where the integration lives:** exclusively `services/email_service.py`. It exposes exactly one function used by the rest of the app: `send_otp_email(to_address: str, otp_code: str) -> None` (raises on delivery failure).
- **Delivery failure behavior:** if email delivery fails, the login route invalidates/deletes the newly generated OTP, clears pending-auth state, does not allow verification against that failed issuance, and shows only `"Verification code could not be sent. Please try again."`.
- **Switching providers later** means editing only the internals of `send_otp_email` (the HTTP call, auth header, payload shape) — its signature and every caller stay identical. This is the concrete mechanism satisfying `project-context.md` §10's "switch providers without rewriting authentication."
- **Provider choice:** only one transactional email provider needs to be implemented. Resend or Brevo is acceptable; swapping providers later must still affect only `services/email_service.py`.
- **Secrets:** `EMAIL_API_KEY` lives only in `.env`/`config.py`; `services/email_service.py` reads it from `config.py`, never hard-codes it, never logs it.
- **Testing:** every test that exercises `auth/otp.py` mocks/monkeypatches `services/email_service.send_otp_email` — no test suite makes a real network call to the email provider (this must be explicit in `tests/conftest.py`).

---

## 11. Testing Structure

```text
tests/
├── conftest.py            # shared fixtures: temp db, flask test client,
│                           # student/admin user factories, authenticated client
├── unit/                  # crypto primitives — no Flask app, no DB
│   ├── test_rsa.py
│   ├── test_ecc.py
│   ├── test_ecc_encoding.py
│   ├── test_hashing.py
│   ├── test_hmac.py
│   └── test_key_manager.py   # touches a temp DB (key storage), still "unit"-scale
└── integration/            # Flask app + real (temp) SQLite DB, via test client
    ├── test_auth_flow.py     # registration, login, OTP
    ├── test_sessions.py      # session lifecycle, tampering, expiry
    ├── test_posts.py         # create/edit/list/anonymous
    ├── test_upvotes.py       # upvote + duplicate rejection
    ├── test_evidence.py      # upload/view/deny/oversize/type
    ├── test_chat.py          # send/read/tamper detection
    ├── test_rbac.py          # full permission-matrix sweep
    └── test_key_rotation.py  # rotate + old/new decrypt correctly
```

Required coverage, mapped to where it lives (all named explicitly in the prompt):

| Requirement | Test(s) |
|---|---|
| RSA round-trip | `unit/test_rsa.py::test_roundtrip_*` |
| RSA invalid/corrupt ciphertext | `unit/test_rsa.py::test_invalid_ciphertext_raises` |
| ECC point operations | `unit/test_ecc.py::test_point_*`, `test_scalar_multiplication_*` |
| ECC encryption/decryption | `unit/test_ecc.py::test_encrypt_decrypt_roundtrip`, `test_decrypt_with_wrong_key_fails` |
| HMAC generation | `unit/test_hmac.py::test_mac_verifies_for_unmodified_message` |
| HMAC tamper detection | `unit/test_hmac.py::test_mac_fails_for_tampered_message`; `integration/test_chat.py::test_tampered_*` |
| Password verification | `unit/test_hashing.py::test_hash_verify_roundtrip`, `test_wrong_password_fails_verification` |
| Public registration student-only | `integration/test_auth_flow.py::test_public_register_forces_student_role` |
| Admin controlled seeding | `integration/test_auth_flow.py::test_seed_creates_admin_with_hashed_password_and_encrypted_profile` |
| Email lookup hash uniqueness | `integration/test_auth_flow.py::test_login_uses_email_lookup_hash`, `test_register_rejects_duplicate_email` |
| OTP expiry | `integration/test_auth_flow.py::test_verify_otp_expired_rejected` |
| OTP salted storage | `integration/test_auth_flow.py::test_otp_uses_fresh_salt`, `test_raw_otp_not_persisted` |
| OTP email failure invalidation | `integration/test_auth_flow.py::test_email_delivery_failure_invalidates_otp` |
| RBAC denial | `integration/test_rbac.py` (matrix), plus per-feature denial tests in `test_posts.py`/`test_evidence.py`/`test_chat.py` |
| Evidence access denial | `integration/test_evidence.py::test_other_student_denied_evidence` |
| Session expiry | `integration/test_sessions.py::test_expired_session_rejected` |
| Session tampering | `integration/test_sessions.py::test_tampered_signature_rejected`, `test_tampered_expiry_rejected` |
| Key rotation | `integration/test_key_rotation.py::test_rotate_key_updates_active_status` |
| Old ciphertext after rotation | `integration/test_key_rotation.py::test_old_data_decrypts_after_rotation` |
| Duplicate upvotes | `integration/test_upvotes.py::test_duplicate_upvote_rejected` |
| Private-chat ownership | `integration/test_chat.py::test_other_student_denied_chat_access` |
| Public post auth required | `integration/test_posts.py::test_public_post_listing_requires_login` |
| Chat HMAC key rotation | `integration/test_chat.py::test_hmac_chat_rotation_preserves_old_message_verification` |
| Application limits | `integration/test_posts.py::test_post_title_and_description_length_limits`; `integration/test_chat.py::test_private_chat_message_length_limit`; `integration/test_evidence.py::test_oversized_file_rejected` |
| Evidence path/filename handling | `integration/test_evidence.py::test_filename_encrypted_but_file_path_plain_id_derived` |

Unit tests (`tests/unit/`) never import `flask` or hit HTTP; integration tests (`tests/integration/`) always go through the Flask test client so route-level auth/RBAC wiring is exercised, not just the underlying service function.

---

## 12. Report Evidence Checklist

| # | Report Section | Evidence to Preserve | Captured In |
|---|---|---|---|
| 1 | Introduction/System Overview | Architecture diagram (Section 50 of `project-context.md`, reproduced with final repo structure) | Phase 19 |
| 2 | Login and Registration | Screenshot: public register form with no role selector → `users` row with `role=student`, `email_lookup_hash`, and ciphertext profile fields; controlled Admin seed output; screenshot: login → OTP email → success | Phases 6, 7, 8 |
| 3 | RSA/ECC Encryption | Textbook RSA round-trip terminal output + sample keypair; ECC round-trip terminal output + chosen `P`/`A`/`B`/`G`/`N` and sample `Q=dG`; `posts` row showing ECC JSON ciphertext; `evidence/*.enc` file | Phases 2, 3, 9, 10 |
| 4 | Password Hashing/Salting | `users.password_hash`/`password_salt` screenshot; unit test output for hash/verify | Phase 6 |
| 5 | 2FA | OTP email content (test double or provider log); `otp_codes` row showing only `otp_hash`/`otp_salt`; email-failure invalidation test; expiry test output | Phase 7 |
| 6 | Key Management | `keys` table screenshot (ciphertext private keys); rotation before/after screenshot (Demo 10) | Phases 5, 17 |
| 7 | Post/Profile Management | Post creation/edit screenshots; anonymous-display screenshot; status transition screenshots (Demo 3, 4, 7) | Phases 9, 10, 13 |
| 8 | Encrypted Storage | `encrypted_uploads/` directory listing showing only `.enc` files; DB row showing encrypted filename and plaintext id-derived `file_path`; three-way access matrix demo (Demo 6) | Phase 12 |
| 9 | MAC | Chat message send/verify flow using `post_id || sender_id || timestamp || ciphertext`; `hmac_key_version` rotation proof; tamper-and-reload demonstration (Demo 8, 9) | Phases 14, 15 |
| 10 | RBAC | Completed permission matrix; audit summary from Phase 16 | Phase 16 |
| 11 | Secure Sessions | Tampered-cookie rejection terminal output; cookie flags screenshot (dev tools) | Phase 8 |
| 12 | GitHub Structure | Final repo tree; `README.md`; commit history screenshot | Phases 0, 19 |
| 13 | Conclusion | Summary pulling from every artifact above — no new capture needed | Phase 19 |

---

## 13. Git Workflow / Team Modularity

### Suggested division of work

| Member | Owns |
|---|---|
| **Member A** | `crypto/rsa.py`, `crypto/bigint_utils.py` (shared with B), profile encryption wiring in `auth/routes.py`/Phase 9, evidence encryption in `evidence/` |
| **Member B** | `crypto/ecc_curve.py`, `crypto/ecc.py`, `crypto/ecc_encoding.py`, post encryption in `posts/`, chat encryption in `chat/` |
| **Member C** | `app.py`, `config.py`, `database/`, `auth/sessions.py`, `auth/otp.py`, `auth/decorators.py`, `auth/rbac.py`, `templates/`, `static/` |

This mirrors the source material's own example (RSA+profile/evidence vs. ECC+posts/chat vs. Flask/DB/auth/UI). `crypto/hmac_custom.py` and `crypto/key_manager.py` are natural shared-ownership modules (both A and B depend on them) — assign one primary owner (suggest Member C, since Key Manager sits at the Flask/DB boundary) but expect either A or B to submit the first draft once their algorithm work exists to wrap.

### Why this split avoids conflicts
- `crypto/rsa.py` and `crypto/ecc*.py` never both change in the same commit by design (Rule 3/4 of [Section 2](#2-modularity-rules): each algorithm lives in its own file).
- `posts/`, `chat/`, `evidence/` are separate directories with no cross-imports (per the circular-dependency rules), so B (posts/chat) and A (evidence) rarely touch the same file.
- Member C owns every file under `auth/`, `database/`, `templates/`, `app.py` — the files most likely to see frequent small edits — while A and B stay in `crypto/` and their respective feature directories.

### Branch naming
`feature/<phase-number>-<short-name>`, e.g. `feature/02-rsa`, `feature/10-posts`, `feature/14-chat`. One branch per phase (or per sub-task if a phase is split between two people), never one long-lived branch per person.

### When to merge
Merge to `main` only when a phase's **Completion Criteria** (as defined in [Phase Details](#4-phase-details)) are met and its tests pass locally. Do not merge partial phases — the next phase's dependency assumptions rely on the previous phase actually being complete.

### Avoiding multiple people editing `app.py`
`app.py` should only ever need edits to register a new blueprint (one line) or adjust global config (rare). Whoever finishes a phase that introduces a new blueprint adds that one registration line in their own branch and flags it clearly in the PR description so merge conflicts are a single obvious line, not a structural conflict.

### Keeping interfaces stable between modules
Once a function signature is listed in [Section 14 — Interface Contracts](#14-interface-contracts), changing it requires notifying whichever teammate's module calls it, in the same PR or immediately before it — never a silent breaking change merged without a heads-up, since another person's already-written code may call it with the old signature.

---

## 14. Interface Contracts

These are the function signatures other modules are expected to rely on. Treat this list as frozen once a phase implementing it is merged — see the note at the end of [Section 13](#13-git-workflow--team-modularity).

```python
# crypto/bigint_utils.py
def mod_pow(base: int, exp: int, mod: int) -> int: ...
def mod_inverse(a: int, m: int) -> int: ...
def is_probable_prime(n: int, rounds: int = 20) -> bool: ...
def generate_prime(bit_length: int) -> int: ...

# crypto/rsa.py
def rsa_generate_keypair(bit_length: int) -> dict:
    """Returns {"public": (e, n), "private": (d, n)}."""
def rsa_encrypt(m_int: int, public_key: tuple[int, int]) -> int: ...
def rsa_decrypt(c_int: int, private_key: tuple[int, int]) -> int: ...
def rsa_encrypt_bytes(data: bytes, public_key: tuple[int, int]) -> list[int]: ...
def rsa_decrypt_bytes(blocks: list[int], private_key: tuple[int, int]) -> bytes: ...

# crypto/ecc_curve.py
Point = tuple[int, int] | None  # None == point at infinity
def is_on_curve(point: Point) -> bool: ...
def point_add(p1: Point, p2: Point) -> Point: ...
def point_double(p: Point) -> Point: ...
def scalar_multiply(k: int, point: Point) -> Point: ...

# crypto/ecc.py
def ecc_generate_keypair() -> dict:
    """Returns {"public": Point, "private": int}."""
def ecc_encrypt_point(m_point: Point, public_key: Point) -> tuple[Point, Point]:
    """Returns (C1, C2)."""
def ecc_decrypt_point(c1: Point, c2: Point, private_key: int) -> Point: ...

# crypto/ecc_encoding.py
def byte_to_point(byte_value: int) -> Point: ...
def point_to_byte(point: Point) -> int: ...
def ecc_encrypt_bytes(data: bytes, public_key: Point) -> list[tuple[Point, Point]]: ...
def ecc_decrypt_bytes(ciphertext: list[tuple[Point, Point]], private_key: int) -> bytes: ...
def serialize_ecc_ciphertext(ciphertext: list[tuple[Point, Point]]) -> str:
    """Returns JSON TEXT entries as [c1_x, c1_y, c2_x, c2_y]."""
def deserialize_ecc_ciphertext(serialized: str) -> list[tuple[Point, Point]]: ...

# crypto/hashing.py
def generate_salt(length_bytes: int = 16) -> bytes: ...
def hash_password(password: str, salt: bytes) -> bytes: ...
def verify_password(password: str, salt: bytes, expected_hash: bytes) -> bool: ...

# crypto/hmac_custom.py
def generate_mac(key: bytes, message: bytes) -> bytes: ...
def verify_mac(key: bytes, message: bytes, received_mac: bytes) -> bool: ...

# crypto/key_manager.py
def generate_key(purpose: str, algorithm: str) -> dict:
    """Returns {"version": int, "public_key": ..., "private_key": ...}."""
def get_active_key(purpose: str) -> dict:
    """Returns {"version": int, "public_key": ..., "private_key": ...}."""
def get_key_by_version(purpose: str, version: int) -> dict: ...
def rotate_key(purpose: str) -> dict: ...
def retire_key(purpose: str, version: int) -> None: ...
def revoke_key(purpose: str, version: int) -> None: ...

# auth/otp.py
def generate_otp() -> str: ...
def store_otp(user_id: int, otp_code: str) -> None: ...
def verify_otp(user_id: int, submitted_code: str) -> bool: ...
def invalidate_latest_otp(user_id: int) -> None: ...

# services/email_service.py
def send_otp_email(to_address: str, otp_code: str) -> None: ...

# auth/sessions.py
def create_session(user) -> str:
    """Returns the full cookie value."""
def validate_session(cookie_value: str):
    """Returns the associated user, or None."""
def invalidate_session(cookie_value: str) -> None: ...

# auth/rbac.py
def is_admin(user) -> bool: ...
def is_owner(user, resource) -> bool: ...
def can_view_evidence(user, evidence_row) -> bool: ...
def can_access_chat(user, post_row) -> bool: ...

# chat/services.py
def send_message(post_id: int, sender_id: int, plaintext: str) -> int: ...
def get_conversation(post_id: int, requester) -> list[dict]: ...

# evidence/services.py
def store_evidence(post_id: int, owner_id: int, filename: str, file_bytes: bytes) -> int: ...
def read_evidence(evidence_id: int, requester) -> tuple[str, bytes, str]: ...

# auth/decorators.py
def login_required(view_func): ...
def role_required(role: str): ...  # returns a decorator
```

---

## Locked Decisions Before Implementation

These decisions resolve the ambiguities in the original source files. Implementation must follow them unless this plan is explicitly revised again.

### 1. Public registration and Admin seeding
Public `/register` creates `student` accounts only. The form must not show role selection, and crafted role submissions must not create Admin accounts. Admin accounts are created only through the controlled seed/setup process, after password hashing and RSA profile encryption exist. Phase 1 creates schema and setup scaffolding only; it does not create a placeholder Admin password.

### 2. Login, OTP, and session boundary
Phase 7 implements password verification, OTP generation/storage/email/verification, and a pending-auth state. No authenticated session exists before OTP succeeds. Phase 8 implements `create_session()` and finalizes the OTP-success path by creating the first authenticated session. There is no requirement to regenerate a pre-OTP authenticated session.

### 3. RSA educational alignment
RSA uses textbook RSA for this CSE447 demonstration: approximately 128-bit primes, a roughly 256-bit modulus, and `e=11`. Arbitrary bytes are split into safe chunks and stored in the `TBR1` container with length/chunk/block metadata. No padding is used. This is deterministic and not suitable for production deployment. Existing OAEP ciphertext is incompatible and must be discarded during the documented development-data reset.

### 4. RSA key size
Application RSA key pairs and the preferred root RSA key use approximately 128-bit primes, yielding approximately 256-bit moduli, with `e=11`. Configuration uses `RSA_PRIME_BITS=128` and `RSA_PUBLIC_EXPONENT=11`. The implementation is intentionally educational and is not suitable for production deployment.

### 5. ECC parameters
Use one fixed educational elliptic curve for the whole project. Its generator order `N` must be greater than 256, and `P`/`A`/`B`/`G`/`N` must be documented in `crypto/ecc_curve.py`, tests, and the report. Tests must validate the curve equation and generator order. The EC-ElGamal design remains unchanged.

### 6. Authenticated public post viewing
Public complaint viewing requires authentication. Students and Admins can view public posts; unauthenticated visitors cannot.

### 7. Root RSA environment representation
The root RSA key is represented by decimal integer environment variables: `ROOT_RSA_N`, `ROOT_RSA_E`, and `ROOT_RSA_D`. Root private material is never stored in SQLite or Git.

### 8. Email lookup hash
Add `users.email_lookup_hash`. Registration and login normalize email with trim + lowercase, compute `SHA256(normalized_email)`, and use that deterministic hash for lookup and uniqueness. The actual email remains RSA encrypted. Add a `UNIQUE` index on `email_lookup_hash`.

### 9. OTP salted hashing
Add `otp_codes.otp_salt`. Every OTP gets a fresh random salt and stores `SHA256(salt || OTP)`. Raw OTP is never persisted.

### 10. SHA-256 allowance and HMAC restriction
Python `hashlib.sha256` is allowed as the underlying SHA-256 primitive. RSA, ECC, and the HMAC construction itself remain implemented manually. Do not call `hmac.new()`.

### 11. Cookie flags
Local development/demo uses `SESSION_COOKIE_SECURE=False`. Production/HTTPS config may set it `True`. `HttpOnly` and `SameSite` remain enabled.

### 12. Status and acknowledgement
Acknowledgement is not a separate database concept. It means `status = "Acknowledged"`. Valid statuses are `Pending`, `Acknowledged`, and `Resolved`.

### 13. Private chat schema and MAC input
`chat_messages` contains `id`, `post_id`, `sender_id`, `ciphertext`, `mac`, `ecc_key_version`, `hmac_key_version`, and `created_at`. There is no `receiver_id`. Conversation membership is derived from the post: the post owner may access, Admin may access, everyone else is denied. MAC input is `post_id || sender_id || timestamp || ciphertext`.

### 14. Admin response meaning
"Admin response" means Admin-authored private chat messages. Do not add a separate `admin_response` field to `posts`.

### 15. Chat HMAC key rotation
`chat_messages.hmac_key_version` is required. Old messages must continue verifying after `HMAC_CHAT` rotation.

### 16. Session HMAC key rotation
`HMAC_SESSION` rotation intentionally invalidates existing sessions. Do not add historical HMAC session-key support; users must log in again after session-key rotation.

### 17. ECC ciphertext serialization and limits
ECC ciphertext serialization uses JSON stored as SQLite `TEXT`. Each encrypted byte entry is `[c1_x, c1_y, c2_x, c2_y]`, handled by centralized serialize/deserialize helpers. Application limits are: post title 120 characters, post description 500 characters, private chat message 300 characters.

### 18. Evidence storage
Evidence allows PDF, PNG, JPG/JPEG with a maximum size of 200 KB. Evidence contents are RSA encrypted. Original filename is RSA encrypted. On-disk path is not encrypted because it is non-sensitive metadata derived from the evidence id. Use `file_path = encrypted_uploads/evidence_<id>.enc`, and name the schema field `file_path`.

### 19. OTP email failure
If OTP email delivery fails, invalidate/delete the newly generated OTP, do not allow OTP verification using that failed issuance, and show a generic `"Verification code could not be sent. Please try again."` message.

### 20. Email provider boundary
Keep the external email integration behind `services/email_service.py`. Only one provider needs to be implemented.

---

## Project Definition of Done

The project is complete only when:

- [ ] RSA encryption/decryption works from scratch.
- [ ] ECC / EC-ElGamal encryption/decryption works from scratch.
- [ ] RSA and ECC are used for their assigned, different purposes.
- [ ] Sensitive profile information is encrypted at rest.
- [ ] Complaint title/description are encrypted at rest.
- [ ] Evidence files and original filenames are encrypted at rest.
- [ ] Password hashing with random salts works.
- [ ] Email OTP 2FA works and OTPs expire after use/time.
- [ ] Public registration cannot create Admin accounts.
- [ ] Private Admin ↔ post-owner chat works.
- [ ] HMAC detects modified chat messages.
- [ ] Old chat MACs continue verifying after HMAC_CHAT rotation.
- [ ] RBAC is enforced server-side.
- [ ] Secure sessions expire, invalidate on logout, and reject tampered tokens.
- [ ] Key rotation preserves access to old encrypted records.
- [ ] Raw private application keys are not stored plaintext in SQLite.
- [ ] Upvotes work without duplicate voting.
- [ ] Unauthorized students cannot access another student's evidence/chat.
- [ ] All required pytest tests pass.
- [ ] Required screenshots/evidence for every report section are collected.
- [ ] README setup instructions work from a clean environment.

---

*End of implementation plan. This document should be re-read alongside `project-context.md` and `crypto-plan.md` before starting any phase, per the "Additional Claude Code Instruction" in `project-context.md` §54.*
