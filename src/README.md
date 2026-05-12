# VulnStore

VulnStore is a small Flask webstore used for local security and DevSecOps exercises. This branch has been remediated so the original demo vulnerabilities are no longer present in the application flow.

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export FLASK_SECRET_KEY="replace-this-in-real-deployments"
python app.py
```

Open `http://localhost:5000`.

## Docker

```bash
docker compose up --build
```

For HTTPS deployments, set `SESSION_COOKIE_SECURE=1` and provide a strong `FLASK_SECRET_KEY`.

## Security changes

- Parameterized login query with hashed passwords.
- CSRF protection added to state-changing forms.
- Server-side authorization for account and admin access.
- Safer download and outbound fetch validation.
- Debug output reduced to a minimal admin-only status view.
- Container updated to `python:3.12-slim-bookworm`, non-root runtime, and `gunicorn`.
