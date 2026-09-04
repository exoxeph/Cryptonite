# Authority Bridged

Authority Bridged is a CSE447 cryptography demonstration web application.

This repository currently includes the Phase 5 key-management infrastructure. Application features are added phase by phase.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(32))"
pytest
flask --app app:create_app run
```

Put the generated value in `.env` as `SECRET_KEY`. Do not use the example
placeholder or commit `.env`; the application rejects known placeholders and
requires a generated value at least 32 characters long.

After placing a locally generated 2048-bit root RSA key in `.env` as the decimal
`ROOT_RSA_N`, `ROOT_RSA_E`, and `ROOT_RSA_D` values, initialize the operational
keys with:

```powershell
flask --app app:create_app bootstrap-keys
```

Generate the root values with the project's `rsa_generate_keypair(2048)`
implementation and manually copy only the decimal values into `.env`. Never
commit `.env` or print the private exponent in shared evidence. The bootstrap
command initializes SQLite and creates one active key for each configured
purpose; repeated runs are idempotent.

## Health Check

```text
GET /health
```

Expected response:

```json
{"status":"ok"}
```

## Phase Boundary

Do not implement database schema, cryptography, authentication, sessions, OTP, posts, evidence, chat, or key management until the corresponding later phase is approved.
