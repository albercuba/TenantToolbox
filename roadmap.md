# TenantToolbox — Product & Engineering Roadmap

## 1. What this is

TenantToolbox is a **self-hosted, Docker-deployable, multi-tenant Microsoft 365 security and management platform for MSPs**. It lets an MSP manage security baselines, monitor for drift and breaches, run user and device lifecycle actions, and generate branded reports for every client tenant from one screen, without re-authenticating per tenant.

This document is the build roadmap. It is organized into phases so an agent can implement incrementally, with each phase producing a working, testable slice of the product.

---

## 2. Core architecture decisions

| Concern | Decision | Rationale |
|---|---|---|
| Deployment | Docker Compose (single-host) first; design for future k8s | Self-hosted MSP tooling, easy to `docker compose up` |
| Backend | Python (FastAPI) or Node.js (NestJS) — pick one, be consistent | Async-friendly for Graph API polling/webhooks |
| DB | PostgreSQL | Relational, multi-tenant row scoping, JSONB for policy blobs |
| Cache/Queue | Redis + a task queue (Celery for Python, BullMQ for Node) | Needed for scheduled polling, report generation, remediation jobs |
| Frontend | React + TypeScript, Vite | SPA dashboard, component reuse across tenant views |
| Auth (app → user) | OIDC/local auth + optional SSO (Entra ID as IdP) for MSP staff logins | MSP technicians log into TenantToolbox itself |
| Auth (app → M365 tenants) | Azure AD **multi-tenant app registration** + **GDAP** (Granular Delegated Admin Privileges) via Microsoft Partner Center, falling back to per-tenant admin consent for non-CSP relationships | This provides delegated access across client tenants without shared credentials |
| Background jobs | Scheduled polling (Graph API has limited webhook/change-notification coverage) + Graph change notifications where available | Drift detection and alerting need near-real-time signal |
| Secrets | Vault or Docker secrets / `.env` + encryption at rest for tenant tokens | Refresh tokens per tenant are highly sensitive |
| Multi-tenancy model in DB | `organization` (the MSP) → `client_tenant` (each M365 tenant) → all resources scoped by `client_tenant_id` | Supports the MSP-to-client-tenant data model |

Decide early whether TenantToolbox is single-MSP-per-deployment (simplest for self-hosted installations) or supports multiple MSP organizations in one instance. Recommend **single-MSP-per-deployment** for v1 — it simplifies authentication and billing entirely.

---

## 3. Feature inventory

### 3.1 Platform / foundation
- [ ] Multi-tenant dashboard — switch between client tenants without re-authenticating
- [x] Tenant onboarding via direct Microsoft Entra admin consent (single tenant connection)
- [x] Tenant onboarding via CSV import (interim bulk-import path)
- [ ] Tenant onboarding via Microsoft Partner Center / CSP import
- [ ] Tenant onboarding via "Magic Link" (self-service admin consent flow sent to the client)
- [ ] PSA integration (ConnectWise, Autotask, Halo, etc.) for ticket creation from alerts
- [x] Local MSP staff authentication with owner/tech roles and owner-only tenant disconnect guardrail
- [ ] Role-based access for MSP staff (owner, L1/L2/L3 tech) with guardrails on what each role can execute
- [ ] Public API for pulling reporting data into other tools
- [ ] Audit log of every action taken by every technician, per tenant

### 3.2 Secure Autopilot (security & compliance) — the core module
- [x] Built-in security baseline templates with JSON control definitions
- [x] Security baseline template custom builder
- [ ] 1-click baseline deployment to a tenant (Conditional Access, MFA enforcement, session policies, Defender policies)
- [ ] Policy drift detection (poll/compare current tenant config vs. assigned baseline)
- [ ] 1-click drift rollback / re-apply baseline
- [ ] Auto-remediation: block high-risk sign-ins / suspicious actions automatically, on a schedule or real-time
- [ ] Real-time breach/security alerts (impossible travel, leaked credentials, risky sign-in, mass file download, etc.) via email and PSA ticket
- [ ] 1-click remediation directly from an alert/ticket
- [ ] Alert noise controls (customizable severity thresholds, suppress low-value events)
- [ ] Compliance framework mapping: HIPAA, NIST/CIS, CMMC — show which controls are satisfied by which baseline
- [ ] Automatic evidence/audit trail generation (every policy state, drift event, remediation logged with timestamp) for insurer/auditor handoff
- [ ] Free-form security risk assessment mode for prospects (read-only scan via Magic Link, no shared credentials, used to sell new business)

### 3.3 Engage Autopilot (user/identity management)
- [ ] Unified user view across tenants (search a user, see all tenant memberships)
- [ ] Bulk actions: reset password, block/unblock user, assign/remove license, force MFA re-registration
- [ ] Full offboarding workflow: revoke sessions, remove licenses, convert to shared mailbox, remove from groups/Teams, disable account — as one guided action
- [ ] User groups (MSP-defined, not just AD groups) for bulk targeting during rollout/offboarding
- [ ] Distribution list management

### 3.4 Intune Autopilot (device management)
- [ ] Baseline device compliance policy templates, deployable per tenant
- [ ] Device compliance dashboard across tenants (compliant / non-compliant / stale check-in)
- [ ] Bulk device actions (retire, wipe, sync)

### 3.5 Discover (SaaS / Shadow IT)
- [ ] SaaS app inventory per tenant (via OAuth app consent grants + sign-in logs, optionally augmented by an RMM-deployed browser/agent-based discovery agent — treat as a stretch feature)
- [ ] Shadow IT risk scoring (unsanctioned apps with broad permissions)
- [ ] Compliance audit view of discovered apps

### 3.6 Reporting
- [ ] Branded, white-label report templates (MSP logo, colors)
- [ ] Report contents: posture score, threats caught, policies enforced, MFA status, license usage, timeline of events
- [ ] Scheduled report generation + delivery (email, on a per-client cadence: weekly/monthly/quarterly)
- [ ] On-demand report generation and PDF export
- [ ] License usage / cost reporting to support end-of-month billing

### 3.7 Licensing / billing awareness (internal to the MSP, not selling seats)
- [ ] Track M365 license SKUs per tenant, flag underused/overused licenses
- [ ] Feature availability gating in-app based on each tenant's actual M365 license tier; fall back gracefully when Conditional Access or other premium features are not licensed

---

## 4. Frontend design system

The frontend must use the shared `../Templates/PharmaPMS/ui-template` as its visual reference. Preserve its Desk-style layout, Inter typography, compact spacing, card/table patterns, and status color semantics while replacing pharmacy-specific content with TenantToolbox concepts. Copy only the reusable style system into this repository; do not make TenantToolbox depend on the template project at runtime.

## 5. Phased build plan

### Phase 0 — Foundations (infra & auth skeleton)
1. [x] Repo scaffold: monorepo with `/backend`, `/frontend`, `/infra` (docker-compose, migrations)
2. [x] Docker Compose: app server, Postgres, Redis, worker, frontend (dev + prod compose files)
3. [x] MSP staff auth: local email/password + session/JWT; basic RBAC (owner/tech roles)
4. [x] Azure AD app registration setup docs + admin-consent flow (single tenant first, no GDAP yet)
5. [x] `client_tenant` model: store tenant ID, name, delegated auth tokens (encrypted), connection status
6. [x] "Connect a tenant" flow: admin-consent URL generation → callback → store refresh token
7. [x] Minimal dashboard: list of connected tenants, connection health indicator

**Exit criteria:** Can connect one real M365 tenant via OAuth and call Graph API `/me` or `/organization` successfully from the backend, store the token securely, and see it listed in the frontend.

**Implementation note:** The OAuth and Graph code path is implemented, but this exit criterion still requires a live Entra configuration and real-tenant verification.

### Phase 1 — Multi-tenant core + basic Graph read access

**Progress:** The authenticated tenant list API and frontend tenant management view are complete. CSV tenant import, Graph synchronization, refresh-token handling, normalized user/license/Secure Score snapshots, and a scheduled worker are now implemented. The remaining Phase 1 items below are intentionally not marked complete until the full switching UI, live views, and audit trail are finished.

1. [x] CSV tenant import interim path; GDAP / Partner Center bulk-import flow remains open
2. [x] Tenant switcher UI (no re-auth needed once connected)
3. [x] Background worker: scheduled Graph polling per tenant (users, licenses, sign-in logs, security defaults/CA policies) into normalized DB tables
4. [x] Basic per-tenant views: users list, licenses list, Secure Score
5. Audit logging middleware (every write action logged)

**Exit criteria:** MSP tech can switch between 2+ connected tenants and see live user/license/Secure Score data pulled on a schedule.

### Phase 2 — Secure Autopilot v1 (baselines + drift)

**Progress:** Baseline CRUD, assignments, explicit Graph deployment, drift detection, rollback, and in-app drift alerts are implemented. Scheduled drift polling, dashboard actions, and email delivery remain open until completed and tested.

1. [x] Baseline template schema (JSON describing target Conditional Access / MFA / Defender settings)
2. [x] Ship 2-3 out-of-box templates (e.g., "CIS Level 1", "Basic MFA Enforcement")
3. [x] Custom template builder UI
4. "Deploy baseline to tenant" action — writes policies via Graph API
5. Drift detection job: compare live tenant policy state to assigned baseline on schedule, flag deltas
6. Drift dashboard + 1-click rollback (re-apply baseline)
7. Alerting: drift found → in-app notification + email

**Exit criteria:** Deploy a baseline to a test tenant, manually break a policy in the M365 admin center, see TenantToolbox detect and flag drift within one polling cycle, and roll it back with one click.

### Phase 3 — Alerting & auto-remediation
1. Ingest Microsoft Graph security alerts / Identity Protection risk events per tenant
2. Alert rules engine (severity thresholds, noise suppression, per-tenant customization)
3. Email + webhook delivery of alerts
4. PSA integration (start with one connector, e.g., ConnectWise Manage or Autotask REST API) — create ticket on alert, resolve ticket on remediation
5. Auto-remediation rules: e.g., auto-disable user on impossible-travel risk event, auto-block sign-in
6. 1-click manual remediation from alert/ticket view

**Exit criteria:** A simulated risky sign-in produces an alert, opens a PSA ticket, and can be remediated with one click from either TenantToolbox or the PSA ticket link.

### Phase 4 — Compliance mapping & reporting
1. Map each baseline control to HIPAA / NIST-CIS / CMMC control IDs (static reference data + tagging on templates)
2. Compliance coverage view per tenant ("62% of CMMC Level 1 controls satisfied")
3. Audit trail export (CSV/PDF) of policy states, drift events, remediations for a date range
4. Report template engine (HTML → PDF), brandable with MSP logo/colors stored in org settings
5. Scheduled report generation + email delivery per tenant, configurable cadence
6. On-demand report generation from UI

**Exit criteria:** Generate a branded PDF report for a tenant showing posture score, events, and policy status, and schedule it to auto-send monthly.

### Phase 5 — Engage Autopilot (user/identity lifecycle)
1. Cross-tenant user search
2. Bulk user actions (reset password, block, license assign/remove) via Graph API, with confirmation + audit log
3. Guided offboarding workflow (multi-step: revoke sessions → remove licenses → convert mailbox → remove from groups → disable)
4. MSP-defined user groups for bulk targeting
5. Distribution list CRUD

**Exit criteria:** Fully offboard a test user across mailbox conversion, license removal, and account disable in one guided flow, with every step logged.

### Phase 6 — Intune Autopilot (device management)
1. Device inventory sync per tenant (compliant/non-compliant/stale)
2. Baseline compliance policy templates, deployable per tenant
3. Bulk device actions: retire, wipe, sync

**Exit criteria:** Deploy a compliance policy template to a tenant and see device compliance status reflected in the dashboard.

### Phase 7 — Discover (SaaS / Shadow IT)
1. Enumerate OAuth app consent grants per tenant via Graph API
2. Risk-score apps by permission scope (e.g., mail.read+files.readwrite = high risk)
3. Shadow IT dashboard per tenant with risk-sorted app list
4. (Stretch) Optional lightweight browser-extension or RMM-deployed agent for deeper SaaS usage discovery beyond OAuth grants

**Exit criteria:** View a ranked list of OAuth-connected third-party apps per tenant with a risk score.

### Phase 8 — Prospect / sales-enablement flow
1. Read-only "Magic Link" flow: generate a link, prospect grants read-only consent, TenantToolbox runs a security assessment without persisting full write access
2. Free assessment report generation (reuses Phase 4 reporting engine)
3. Convert prospect → managed tenant flow (upgrade consent to full management scope)

**Exit criteria:** Send yourself a Magic Link, grant read-only consent from a test tenant, and receive a generated risk-assessment report.

### Phase 9 — Hardening & polish
1. Rate-limit and backoff handling for Graph API throttling across many tenants
2. Token refresh failure handling + reconnect flow when a tenant revokes consent
3. Secrets encryption audit (tokens at rest, TLS everywhere)
4. Multi-tech guardrails: confirm-before-destructive-action, permission scoping by role
5. Backup/restore for Postgres in the Docker Compose setup
6. Load testing polling jobs against tenant count targets (e.g., 50, 200 tenants)
7. Documentation: setup guide, Azure AD app registration walkthrough, GDAP walkthrough

---

## 6. Suggested initial repo structure

```
tenanttoolbox/
├── docker-compose.yml
├── docker-compose.dev.yml
├── backend/
│   ├── app/
│   │   ├── api/                # route handlers
│   │   ├── core/                # config, security, auth
│   │   ├── graph/                # Microsoft Graph API client wrapper
│   │   ├── models/               # ORM models (org, client_tenant, baseline, alert, ...)
│   │   ├── workers/               # scheduled jobs (polling, drift detection, reports)
│   │   ├── services/              # business logic per module (secure, engage, intune, discover)
│   │   └── main.py / main.ts
│   ├── migrations/
│   └── tests/
├── frontend/
│   ├── src/
│   │   ├── pages/                 # dashboard, tenant view, baseline builder, reports, users
│   │   ├── components/
│   │   ├── api/                    # typed API client
│   │   └── state/
│   └── tests/
└── docs/
    ├── azure-ad-setup.md
    ├── gdap-setup.md
    └── architecture.md
```

## 7. Key data model sketch (early Postgres tables)

- `organization` — the MSP itself (name, branding for reports)
- `staff_user` — MSP technicians (role: owner/l1/l2/l3)
- `client_tenant` — connected M365 tenant (tenant_id, display_name, connection status, license tier)
- `tenant_credential` — encrypted refresh/access tokens per client_tenant
- `baseline_template` — JSONB policy definition, compliance tags
- `tenant_baseline_assignment` — which template is assigned to which tenant
- `drift_event` — detected deviation, resolved/unresolved, timestamp
- `alert` — security alert, severity, source, linked PSA ticket ID, remediation status
- `audit_log` — actor, action, target tenant, timestamp, payload
- `report` — generated report metadata, storage path, schedule reference
- `report_schedule` — cadence, recipient, tenant
- `discovered_app` — per-tenant OAuth app grant, permission scopes, risk score

## 8. Open decisions to make before Phase 0 (flag to the user, don't guess silently)

- Backend language: Python/FastAPI vs Node/NestJS
- PSA integrations to prioritize (ConnectWise, Autotask, Halo, other)
- Whether GDAP/Partner Center integration is in scope for v1, or start with plain per-tenant admin consent and add GDAP later
- Whether multi-MSP-org support is ever needed, or this is permanently single-tenant-org deployment
