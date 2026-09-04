# Authority Bridged

Authority Bridged is a CSE447 cryptography demonstration web application.

This repository is currently at Phase 0 only: repository initialization, minimal Flask app factory, configuration placeholders, and a `/health` endpoint.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
pytest
flask --app app:create_app run
```

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
