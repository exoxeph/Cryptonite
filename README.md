# Cryptonite

Cryptonite is a CSE447 cryptography demonstration web application.

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

## Testing

Run the full suite with:

```powershell
python -m pytest --maxfail=1 -q
```

For an informational coverage report:

```powershell
python -m pytest --cov=crypto --cov=auth --cov=posts --cov=evidence --cov=chat --cov=admin --cov-report=term-missing -q
```

## Local UI

Start the development server with `flask --app app:create_app run --debug`,
then open `http://127.0.0.1:5000/`. Set `UI_PREVIEW_ENABLED=False` to disable
the development-only in-memory page gallery at `/ui-preview`.

Tests use temporary SQLite databases and evidence directories. OTP email
delivery is mocked; the test suite does not require provider credentials or
make external email calls.

## Health Check

```text
GET /health
```

Expected response:

```json
{"status":"ok"}
```

## Docker: One-Computer Setup

Docker Desktop is the only prerequisite. These steps work on Windows,
macOS, and Linux and keep the database and encrypted uploads in the local
`docker-data/` directory.

The Compose volume mapping is `./docker-data:/data`. To move an existing
installation to another computer, copy the entire `docker-data/` folder beside
the cloned repository before starting Docker. Also copy the matching `.env`
values, especially `SECRET_KEY` and `ROOT_RSA_N`, `ROOT_RSA_E`, and
`ROOT_RSA_D`; changing the root RSA values makes existing encrypted records
unreadable. These files are intentionally ignored by Git because they contain
local application state and encrypted user data.

1. Copy the environment template:

   ```powershell
   Copy-Item .env.example .env
   ```

2. Generate a random Flask secret without installing Python locally:

   ```powershell
   docker run --rm python:3.12-slim python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

   Put the printed value after `SECRET_KEY=` in `.env`. Do not use the
   placeholder and do not commit `.env`.

3. Build the image:

   ```powershell
   docker compose build
   ```

4. Generate the required 2048-bit root RSA values inside the image:

   ```powershell
   docker compose run --rm --entrypoint python cryptonite -c "from crypto.rsa import rsa_generate_keypair; k=rsa_generate_keypair(2048); print('ROOT_RSA_E='+str(k['public'][0])); print('ROOT_RSA_N='+str(k['public'][1])); print('ROOT_RSA_D='+str(k['private'][0]))"
   ```

   Copy the three printed lines into `.env`. Keep `ROOT_RSA_D` private. The
   root values are environment configuration and are never stored in SQLite
   or Git.

5. Start Cryptonite:

   ```powershell
   docker compose up
   ```

   The container automatically initializes SQLite and bootstraps missing
   operational keys. Open `http://localhost:5000/`.

6. Create the controlled Admin account in a second terminal:

   ```powershell
   docker compose exec cryptonite flask --app app:create_app seed-admin
   ```

   Local OTP delivery is configured for console development mode, so no email
   provider or API quota is required. Read the verification code with:

   ```powershell
   docker compose logs -f cryptonite
   ```

To stop the app, press `Ctrl+C`. To reset the local database, keys, and
encrypted evidence, stop the app and remove `docker-data/`. Do not remove it
if you want the data to survive the next `docker compose up`.

## Phase Boundary

Do not implement database schema, cryptography, authentication, sessions, OTP, posts, evidence, chat, or key management until the corresponding later phase is approved.
