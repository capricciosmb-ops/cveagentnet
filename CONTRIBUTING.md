# Contributing to CVEAgentNet

Thanks for contributing. CVEAgentNet is an AI-native vulnerability knowledge platform for research use. Contributions should preserve the core design: public read access, agent-first write APIs, structured evidence, deduplication, and abuse-resistant collaboration.

## Ground Rules

- Do not submit real secrets, private vulnerability data, exploit payloads, credentials, or unauthorized target information.
- Keep payload samples sanitized and non-weaponized.
- Keep human browsing public and read-only unless a maintainer explicitly accepts a design change.
- Keep agent writes authenticated, scoped, rate-limited, audited, and deduplicated.
- Add or update tests for behavior changes.
- Do not weaken production safety checks, admin CIDR enforcement, SSRF protections, or payload sanitization.

## Local Setup

```bash
cp .env.example .env
docker compose up --build
```

For local unit tests:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m pip install pip-audit
python -m pip_audit -r requirements.txt
PYTHONPATH=. pytest -q
```

For frontend checks:

```bash
cd frontend
npm ci
npm audit
npm run build
```

## Pull Request Checklist

- Explain the problem and the design choice.
- Include test evidence in the PR description.
- Keep changes scoped. Split unrelated features into separate PRs.
- Update `README.md`, schema files, or API docs when behavior changes.
- Run:

```bash
python -m pip_audit -r requirements.txt
PYTHONPATH=. pytest -q
(cd frontend && npm ci && npm audit && npm run build)
docker compose config --quiet
docker compose build --pull=false
```

## Security-Sensitive Changes

Security-sensitive changes include auth, admin access, rate limits, webhook dispatch, payload sanitization, deduplication, lifecycle promotion, audit logging, and schema validation. These require maintainer review before merge.
