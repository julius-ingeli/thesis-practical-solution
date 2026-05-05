# VulnStore

VulnStore is an intentionally vulnerable dummy webstore for local DevSecOps demonstrations. It is built to provide realistic targets for SAST, DAST, OWASP ZAP, and Trivy.

Do not deploy this application to the internet. The weaknesses are deliberate.

## Run Locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000`.

Docker:

```bash
docker compose up --build
```

## Demo Accounts

| Username | Password |
| --- | --- |
| alice | password123 |
| bob | qwerty |
| admin | admin |

## Intentional Vulnerabilities

| Area | Route | Example |
| --- | --- | --- |
| SQL injection | `POST /login` | username: `' OR '1'='1' --` |
| Reflected XSS | `GET /search?q=` | `/search?q=<script>alert(1)</script>` |
| Stored XSS | `POST /product/1` | review: `<script>alert(1)</script>` |
| IDOR | `GET /account/<id>` | login as Alice, browse `/account/2` |
| Command injection | `GET /tools/ping?host=` | `/tools/ping?host=127.0.0.1;id` |
| Path traversal | `GET /download?file=` | `/download?file=../requirements.txt` |
| SSRF | `GET /fetch-image?url=` | `/fetch-image?url=http://127.0.0.1:5000/debug` |
| Missing CSRF | `POST /checkout` | no CSRF token required |
| Secret exposure | `GET /debug` | exposes secret and environment |
| Weak auth/session design | `/admin`, `app.py` | hard-coded secret and client-side session role |

## SAST Examples

Bandit:

```bash
bandit -r .
```

Semgrep:

```bash
semgrep scan --config auto
```

Expected findings include hard-coded secrets, SQL injection, shell command injection, unsafe URL fetch, debug mode, and unsafe template rendering.

## DAST and OWASP ZAP

Quick ZAP baseline scan with Docker:

```bash
docker run --rm --network host -t zaproxy/zap-stable zap-baseline.py -t http://127.0.0.1:5000 -r zap-report.html
```

Manual ZAP workflow:

1. Start VulnStore.
2. Open ZAP and proxy a browser through it.
3. Browse the shop, login, product review, account, checkout, debug, and tool routes.
4. Run Active Scan against `http://127.0.0.1:5000`.

## Trivy Examples

Scan the repository filesystem:

```bash
trivy fs .
```

Scan the container image:

```bash
docker build -t vulnstore:local .
trivy image vulnstore:local
```

The `requirements.txt` and `Dockerfile` intentionally use old packages/base image choices so dependency and image scanners have material to report.
