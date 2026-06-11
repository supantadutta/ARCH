# AutoBugHunter

**Authorized-only** automated bug bounty & vulnerability management platform.

AutoBugHunter helps security teams manage programs, scope, assets, scans,
findings, AI triage, reports and retests — with safety controls baked in as
**hard requirements**, not afterthoughts.

> ⚠️ **AUTHORIZED TARGETS ONLY.** You may scan **only** systems you own or have
> explicit, written permission to test. This platform is designed to scan
> **only explicitly authorized assets** added to a program's scope allowlist.
> It performs **passive, non-destructive** checks by default and will never
> perform destructive exploitation, DoS testing, credential attacks, phishing,
> malware actions, authentication-bypass attempts or data exfiltration. Any
> risky validation is flagged **"manual review required."** Scanning systems
> without authorization is illegal and unethical — do not do it. The scope
> allowlist, kill switch, authorization layer and audit log exist to keep you
> within authorization; do not attempt to bypass them.

---

## Safety model (read this first)

| Control | How it works |
| --- | --- |
| **Authorization** | Every API request requires a valid `X-API-Key` header (`AUTH_ENABLED=true` by default). Actions are attributed to the caller in the audit log. |
| **Scope allowlist** | `backend/app/policy/scope_guard.py` is the single source of truth. Default-deny: a target is out of scope unless an explicit allow entry matches. Explicit deny entries always win. Enforced at the API **and** re-checked in the Celery worker. |
| **Private/internal guard** | Private, loopback, link-local and reserved ranges are rejected unless explicitly scoped (loopback) or `ALLOW_PRIVATE_TARGETS=true`. |
| **Forbidden scan types** | DoS, brute force, exploitation, phishing, auth-bypass, exfiltration, etc. are categorically rejected by the policy engine. |
| **Dry-run by default** | `DRY_RUN=true` — scanners log the command they *would* run but never execute external tooling or touch the network unless deliberately disabled in an authorized lab. |
| **Global kill switch** | One toggle (Settings page / API), persisted in `SystemSetting`. Halts all queued and running scans. Re-checked at enqueue *and* execution time. |
| **Rate limiting** | Scanner execution is throttled to a configurable requests/second budget. |
| **Command allowlist** | Scanner wrappers can only invoke their one allowed binary, with shell metacharacters refused. `shell=False` always. |
| **Audit logging** | Every program/scope/scan/finding/report action and every scope decision is recorded in an immutable `audit_logs` table (see below). |
| **AI must not invent evidence** | The triage layer only reasons over existing finding data; high/critical or low-confidence findings always require manual review. |

### Audited events

The following are written to the `audit_logs` table (viewable on the **Audit Log**
page and via `GET /api/v1/audit`):

- `program.create` — program created
- `scope.add` — scope entry added (records allow/deny)
- `scan.launch` / `scan.started` — scan queued and execution started
- `scan.completed` / `scan.rejected` — scan finished / blocked (scope, type, kill switch)
- `finding.create` — finding created
- `finding.status_changed` — finding status transition (`old -> new`)
- `report.generate` — report generated
- `killswitch.update` — kill switch engaged/released

---

## Architecture

```
┌──────────┐     REST      ┌───────────┐    Celery    ┌───────────────┐
│ Next.js  │ ───────────▶ │  FastAPI  │ ───────────▶ │ celery_worker │
│ frontend │              │  backend  │   (Redis)    │  (scanners)   │
└──────────┘              └─────┬─────┘              └───────┬───────┘
                                │ SQLAlchemy                 │
                                ▼                            ▼
                          ┌───────────┐            /evidence  /reports
                          │ PostgreSQL│
                          └───────────┘
```

**Tech stack:** FastAPI · PostgreSQL · Redis + Celery · Next.js + Tailwind ·
Python subprocess scanner wrappers · local `/evidence` & `/reports` storage ·
pluggable AI triage (mock provider first).

### Modules
Program Management · Scope Management · Asset Inventory · Recon Jobs ·
Scanner Jobs · Findings · AI Triage · Reports · Retesting · Audit Logs ·
Global Kill Switch.

---

## Quick start (Docker Compose)

```bash
cp .env.example .env
docker compose up --build
```

Then open:

- **Frontend dashboard:** http://localhost:3000
- **API + Swagger docs:** http://localhost:8000/docs
- **Health check:** http://localhost:8000/health

The backend container automatically waits for Postgres, runs Alembic
migrations, and seeds the **localhost-only demo program**.

---

## Safe demo flow

The seed data already creates an **authorized localhost-only program**. To walk
the full lifecycle:

1. **Create / pick a program** — the seeded *"Localhost Demo Program"* is ready,
   or create your own on the Programs page.
2. **Add localhost scope** — already seeded (`domain: localhost`, `ip: 127.0.0.1`).
   Add more on the Scope page; note the seeded **deny** entry for `example.com`.
3. **Run recon (dry-run)** — Scan Jobs page → type `recon`, target `localhost`,
   *dry-run on* → Launch. (Out-of-scope targets are rejected with HTTP 403.)
4. **Create a sample finding** — a demo finding is seeded; or `POST` one via the
   API / Findings page.
5. **Run AI triage** — open the finding → *Run AI Triage*. The mock provider
   enriches severity/CWE/OWASP/impact/remediation from existing data only and
   flags manual review where appropriate.
6. **Generate a report** — *Generate Report* produces a Markdown report (also
   written to `./reports/finding_<id>.md`).

### Same flow via API

Every request must send the API key (`X-API-Key`). The default dev key is
`dev-local-key` — change it in `.env` for any real use.

```bash
API=http://localhost:8000/api/v1
KEY="dev-local-key"
AUTH=(-H "X-API-Key: $KEY" -H 'Content-Type: application/json')

# 1. Create a program
PID=$(curl -s -XPOST $API/programs "${AUTH[@]}" \
  -d '{"name":"My Authorized Program"}' | python -c 'import sys,json;print(json.load(sys.stdin)["id"])')

# 2. Authorize localhost
curl -s -XPOST $API/programs/$PID/scope "${AUTH[@]}" \
  -d '{"scope_type":"domain","value":"localhost","is_allowed":true}'

# 3. Run recon (dry-run). Out-of-scope targets return 403.
curl -s -XPOST $API/programs/$PID/scans "${AUTH[@]}" \
  -d '{"job_type":"recon","target":"localhost","dry_run":true}'

# (rejected example)
curl -s -XPOST $API/programs/$PID/scans "${AUTH[@]}" \
  -d '{"job_type":"recon","target":"example.com"}'   # -> 403 out of scope

# 4. Create a finding
FID=$(curl -s -XPOST $API/programs/$PID/findings "${AUTH[@]}" \
  -d '{"title":"Missing CSP header","severity":"low","confidence":"medium","category":"misconfiguration","evidence_summary":"No CSP header observed"}' \
  | python -c 'import sys,json;print(json.load(sys.stdin)["id"])')

# 5. AI triage
curl -s -XPOST $API/findings/$FID/triage "${AUTH[@]}"

# 6. Generate report
curl -s -XPOST $API/findings/$FID/report "${AUTH[@]}"
```

---

## Optional local vulnerable target (disabled by default)

For demos you can run a tiny, self-contained, **intentionally-misconfigured**
local web app as a safe scan target. It is **off by default** and contains
**no exploitable vulnerabilities** — only passive misconfigurations (missing
security headers, verbose banner) that a baseline scan can flag.

```bash
# Start ONLY in an isolated lab, against your own machine:
docker compose --profile vuln up --build
```

It listens on `http://localhost:9000`. Add it to a program's scope before
scanning. See `vulnerable-target/README.md`. **Never expose it to a network you
do not control, and only scan it because you own it.**

---

## Local development (without Docker)

### Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Point at a local Postgres (or use SQLite for quick experiments)
export DATABASE_URL=postgresql://abh:abh@localhost:5432/autobughunter
alembic upgrade head
python -m app.seed
uvicorn app.main:app --reload
```

Run the worker in another shell:

```bash
celery -A app.celery_app.celery_app worker --loglevel=info
```

### Frontend

```bash
cd frontend
npm install
NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1 \
NEXT_PUBLIC_API_KEY=dev-local-key \
npm run dev
```

> The dashboard sends `NEXT_PUBLIC_API_KEY` as the `X-API-Key` header on every
> request; it must match the backend `API_KEY`.

---

## Tests

```bash
cd backend
pip install -r requirements.txt
pytest
```

Covered safety controls and core flows:

- **Authorization** — requests without / with an invalid API key are rejected (401).
- **Scope enforcement** — in-scope allowed, out-of-scope rejected (403), explicit
  deny overrides wildcard allow, private IPs rejected unless scoped.
- **Forbidden / unknown scan types** rejected by the policy engine.
- **Global kill switch** blocks both scan *launch* (423) and task *execution*
  (job cancelled).
- **Dry-run** makes no network calls (recon) and never executes binaries (nuclei).
- **Command allowlist** rejects non-allowed binaries and shell metacharacters.
- **Audit logging** records program/scope/scan/finding/report events and
  rejected attempts.
- Finding creation, AI triage mock response, and report generation.

---

## Scanners

Wrappers live in `backend/app/scanners/`. Each one enforces scope, rate limits,
command logging, stdout/stderr capture, result normalization and dry-run.

| Scanner | Tool | Mode |
| --- | --- | --- |
| `recon_scanner.py` | pure Python (requests) | passive HTTP/HTTPS probing |
| `nuclei_scanner.py` | nuclei | templates, intrusive tags excluded |
| `zap_scanner.py` | zap-baseline.py | **baseline/passive only** |
| `semgrep_scanner.py` | semgrep | static analysis (read-only) |
| `gitleaks_scanner.py` | gitleaks | secret detection (records location, not secret) |
| `trivy_scanner.py` | trivy | dependency/vuln scan (read-only) |

For the MVP, recon runs with no external tools. `subfinder` / `httpx` /
`katana` are noted as future, still scope-gated, passive integrations. Other
scanners only execute when their binary is installed *and* `DRY_RUN=false`.

---

## AI triage abstraction

`backend/app/ai_triage/` defines a provider interface (`base.py`), a deterministic
`MockTriageProvider` (`mock_provider.py`) and a `TriageService` (`triage_service.py`).
To plug in a real LLM, implement `AITriageProvider.triage()` and inject it into
`TriageService`. The contract forbids inventing evidence — providers reason only
over the supplied read-only `FindingContext`.

---

## Project layout

```
.
├── docker-compose.yml
├── .env.example
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI app + Swagger + error handlers
│   │   ├── config.py          # safe-by-default settings
│   │   ├── auth.py            # API-key authorization
│   │   ├── models/            # SQLAlchemy models
│   │   ├── schemas/           # Pydantic schemas
│   │   ├── policy/            # scope_guard.py (hard control)
│   │   ├── scanners/          # safe scanner wrappers
│   │   ├── ai_triage/         # provider abstraction + mock
│   │   ├── reports/           # Markdown report generator
│   │   ├── routes/            # REST API
│   │   ├── tasks/             # Celery scan tasks
│   │   ├── services/          # audit + kill switch
│   │   └── seed.py            # localhost demo seed
│   ├── alembic/               # migrations
│   └── tests/                 # pytest suite
├── frontend/                  # Next.js + Tailwind dashboard
├── vulnerable-target/         # optional safe demo target (disabled by default)
├── evidence/                  # local evidence store
└── reports/                   # generated reports
```

---

## License & responsible use

Use AutoBugHunter only against systems you are **explicitly authorized** to
test. The scope allowlist, kill switch and audit log exist to keep you within
authorization — do not attempt to bypass them.
