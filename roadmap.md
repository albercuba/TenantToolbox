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
- [x] Multi-tenant dashboard — switch between client tenants without re-authenticating
- [x] Tenant onboarding via direct Microsoft Entra admin consent (single tenant connection)
- [x] Tenant onboarding via CSV import (interim bulk-import path)
- [ ] Tenant onboarding via Microsoft Partner Center / CSP import
- [x] Tenant onboarding via "Magic Link" (read-only prospect assessment flow; managed conversion requires normal consent)
- [x] PSA integration (generic webhook plus ConnectWise, Autotask, and Halo payload adapters) for ticket creation from alerts
- [x] Local MSP staff authentication with owner/tech roles and owner-only tenant disconnect guardrail
- [x] Role-based access for MSP staff (owner, L1/L2/L3 tech) with explicit operation/manage/admin guardrails
- [x] Public report API with expiring token links for downstream tools
- [x] Audit log of every action taken by every technician, per tenant
- [x] Audit log CSV export

### 3.2 Secure Autopilot (security & compliance) — the core module
- [x] Built-in security baseline templates with JSON control definitions
- [x] Security baseline template custom builder
- [x] 1-click baseline deployment to a tenant for supported Conditional Access controls
- [x] Policy drift detection for assigned supported controls
- [x] 1-click drift rollback / re-apply baseline for supported controls
- [x] Opt-in auto-remediation: block high-risk sign-ins automatically; disabled by default
- [x] Security alerts from Graph security alerts and Identity Protection risky sign-ins via email and PSA ticket (polling-based)
- [x] 1-click remediation directly from an alert view for supported risky sign-ins
- [x] Alert noise controls (organization severity threshold and low-value suppression)
- [x] Compliance framework mapping: HIPAA, NIST/CIS, CMMC — show which controls are satisfied by which baseline
- [x] Automatic evidence/audit trail generation for policy state, drift, remediation, lifecycle, and device actions
- [x] Free-form security risk assessment mode for prospects (read-only Magic Link scan)

### 3.3 Engage Autopilot (user/identity management)
- [x] Unified user view across tenants (search a user, see all tenant memberships)
- [x] Confirmed bulk actions: reset password, block/unblock user, assign/remove license, revoke sessions
- [x] Guided offboarding workflow state machine: revoke sessions, remove licenses, remove groups, and disable account; mailbox conversion is explicitly delegated to Exchange administration because Graph has no supported conversion endpoint
- [x] User groups (MSP-defined, not just AD groups) for bulk targeting during rollout/offboarding
- [x] Distribution list management (Graph-backed create/list; membership and deletion remain Exchange/Graph permission dependent)

### 3.4 Intune Autopilot (device management)
- [x] Baseline device compliance policy templates, deployable per tenant
- [x] Device compliance dashboard API across tenants (compliant / non-compliant / stale check-in)
- [x] Confirmed device actions: retire, wipe, sync
- [x] Bulk device actions (retire, wipe, sync) with confirmation guards

### 3.5 Discover (SaaS / Shadow IT)
- [x] SaaS app inventory per tenant via OAuth app consent grants (browser/RMM discovery remains stretch)
- [x] Shadow IT risk scoring (unsanctioned apps with broad permissions)
- [x] Compliance audit view of discovered apps with risk-ranked dashboard

### 3.6 Reporting
- [x] On-demand HTML security posture report generation
- [x] Branded, white-label report templates (MSP logo, colors)
- [x] Report contents: assigned policies, alerts/events, tenant identity, and report period; live score/license widgets remain available in the tenant dashboard
- [x] Scheduled report generation + delivery (email, on a per-client weekly/monthly/quarterly cadence)
- [x] On-demand report generation and PDF export
- [x] License usage reporting from normalized per-tenant SKU snapshots (cost requires tenant price data and is intentionally not fabricated)

### 3.7 Licensing / billing awareness (internal to the MSP, not selling seats)
- [x] Track M365 license SKUs per tenant and expose consumed/enabled usage
- [x] Feature availability gating foundation via tenant license snapshots and graceful Graph error handling

---

## 4. Frontend design system

The frontend must use the shared `../Templates/PharmaPMS/ui-template` as its visual reference. Preserve its Desk-style layout, Inter typography, compact spacing, card/table patterns, and status color semantics while replacing pharmacy-specific content with TenantToolbox concepts. Copy only the reusable style system into this repository; do not make TenantToolbox depend on the template project at runtime. The sidebar and topbar use the reference button reset, full-width spacing, active-state tint, responsive drawer behavior, 240px navigation rail, and white Desk-style header.

## 5. Phased build plan

### Phase 0 — Foundations (infra & auth skeleton)

**Progress:** Application foundations are complete. Live OAuth exit validation requires operator-provided Entra credentials, admin consent, and a real tenant.
1. [x] Repo scaffold: monorepo with `/backend`, `/frontend`, `/infra` (docker-compose, migrations), including container-safe frontend API proxying
2. [x] Docker Compose: app server, Postgres, Redis, worker, frontend (dev + prod compose files)
3. [x] MSP staff auth: first-time setup wizard automatically opens on a new deployment and waits for API readiness; invalid/expired browser tokens are cleared automatically; local email/password + session/JWT; basic RBAC (owner/tech roles)
4. [x] Azure AD app registration setup docs + admin-consent flow (single tenant first, no GDAP yet)
5. [x] `client_tenant` model: store tenant ID, name, delegated auth tokens (encrypted), connection status
6. [x] "Connect a tenant" flow: working frontend action starts admin-consent URL generation → callback → store refresh token, with safe token-exchange diagnostics and automatic navigation to the connected tenant workspace
7. [x] Minimal dashboard: list of connected tenants, connection health indicator

**Exit criteria:** Can connect one real M365 tenant via OAuth and call Graph API `/me` or `/organization` successfully from the backend, store the token securely, and see it listed in the frontend. The first-time setup wizard creates the initial owner account before this flow is used.

**Implementation note:** The OAuth and Graph code path is implemented, but this exit criterion still requires a live Entra configuration and real-tenant verification.

### Phase 1 — Multi-tenant core + basic Graph read access

**Progress:** Phase 1 is complete for the implemented single-MSP deployment path: tenant switching UI, CSV import, Graph synchronization, refresh-token handling, normalized user/license/Secure Score snapshots, scheduled polling, per-tenant views, and audit logging are implemented. GDAP/Partner Center remains an external integration path.

1. [x] CSV tenant import interim path; GDAP / Partner Center bulk-import flow remains open
2. [x] Tenant switcher UI (no re-auth needed once connected)
3. [x] Background worker: scheduled Graph polling per tenant (users, licenses, sign-in logs, security defaults/CA policies) into normalized DB tables, with graceful optional Secure Score handling
4. [x] Basic per-tenant views: users list, licenses list, Secure Score, tenant identity, and discoverable Sync now actions
5. [x] Audit logging middleware (every write action logged)

**Exit criteria:** MSP tech can switch between 2+ connected tenants and see live user/license/Secure Score data pulled on a schedule.

### Phase 2 — Secure Autopilot v1 (baselines + drift)

**Progress:** Phase 2 is complete for the supported Conditional Access controls: baseline CRUD, assignments, explicit Graph deployment, scheduled drift detection, rollback, drift dashboard, in-app alerts, and optional SMTP email delivery are implemented. Live tenant verification remains an operational prerequisite.

1. [x] Baseline template schema (JSON describing target Conditional Access / MFA / Defender settings)
2. [x] Ship 2-3 out-of-box templates (e.g., "CIS Level 1", "Basic MFA Enforcement")
3. [x] Custom template builder UI
4. [x] "Deploy baseline to tenant" action — writes supported policies via Graph API
5. [x] Drift detection job: compare live tenant policy state to assigned baseline on schedule, flag deltas
6. [x] Drift dashboard + 1-click rollback (re-apply baseline)
7. [x] Alerting: drift found → in-app notification + optional SMTP email

**Exit criteria:** Deploy a baseline to a test tenant, manually break a policy in the M365 admin center, see TenantToolbox detect and flag drift within one polling cycle, and roll it back with one click.

### Phase 3 — Alerting & auto-remediation

**Progress:** Phase 3 is complete for the supported polling-based Graph alert path. It includes severity/noise rules, in-app/email delivery, vendor-shaped PSA webhooks, guarded manual remediation, and opt-in automatic user disablement (disabled by default). Live credentials and a real risky-sign-in event remain operational validation prerequisites.

1. [x] Ingest Microsoft Graph security alerts / Identity Protection risk events per tenant
2. [x] Alert rules engine (severity thresholds, noise suppression, per-tenant customization)
3. [x] Email + webhook delivery of alerts
4. [x] PSA-compatible webhook connector for alert ticket creation payloads (generic, ConnectWise, Autotask, and Halo adapters)
5. [x] Opt-in automatic remediation for high/critical Identity Protection events with a user target; automatic remediation remains disabled by default
6. [x] 1-click manual remediation from alert/ticket view

**Exit criteria:** A simulated risky sign-in produces an alert, opens a PSA ticket, and can be remediated with one click from either TenantToolbox or the PSA ticket link.

**Implementation note:** The API supports the alert ingestion, webhook payload, and manual remediation path. Offline integration tests and a live-validation runbook are included in `docs/phase3-live-validation.md`. End-to-end validation still requires live Graph/Identity Protection and PSA webhook credentials.

### Phase 4 — Compliance mapping & reporting

**Progress:** Phase 4 is complete for HTML/PDF reports, HIPAA/NIST/CIS/CMMC mappings, coverage, audit export, date-range filtering, branding settings, public expiring links, and scheduled SMTP delivery. External SMTP delivery remains an operational prerequisite.

1. [x] Map each baseline control to HIPAA / NIST-CIS / CMMC control IDs (static reference data + tagging on templates)
2. [x] Compliance coverage view per tenant ("62% of CMMC Level 1 controls satisfied")
3. [x] Audit trail export (CSV/PDF) of policy states, drift events, remediations for a date range (CSV currently supported)
4. [x] Report template engine (HTML → PDF) with on-demand PDF export
5. [x] Scheduled report email delivery per tenant with weekly/monthly/quarterly cadence
6. [x] On-demand report generation from UI/API

**Exit criteria:** Generate a branded PDF report for a tenant showing posture score, events, and policy status, and schedule it to auto-send monthly.

### Phase 5 — Engage Autopilot (user/identity lifecycle)

**Progress:** Phase 5 is complete for the supported Graph lifecycle path: cross-tenant search/actions, audited resumable offboarding state machine, license/group cleanup, MSP-defined groups, and Graph-backed distribution-list creation/listing. Shared-mailbox conversion is an Exchange administration dependency because Microsoft Graph exposes no supported conversion operation.

1. [x] Cross-tenant user search
2. [x] Bulk user actions (reset password, block, license assign/remove) via Graph API, with confirmation + audit log
3. [x] Guided offboarding workflow (multi-step supported Graph path: revoke sessions → remove licenses → remove groups → disable; mailbox conversion requires Exchange administration)
4. [x] MSP-defined user groups for bulk targeting
5. [x] Distribution list management (Graph-backed create/list)

**Exit criteria:** Fully offboard a test user across mailbox conversion, license removal, and account disable in one guided flow, with every step logged.

### Phase 6 — Intune Autopilot (device management)

**Progress:** Phase 6 is complete for Intune inventory, compliance dashboard data, guarded bulk actions, and deployable compliance policy templates. Live validation still requires Intune permissions and a test tenant.

1. [x] Device inventory sync per tenant (compliant/non-compliant/stale)
2. [x] Baseline compliance policy templates, deployable per tenant
3. [x] Bulk device actions: retire, wipe, sync

**Exit criteria:** Deploy a compliance policy template to a tenant and see device compliance status reflected in the dashboard.

### Phase 7 — Discover (SaaS / Shadow IT)

**Progress:** Phase 7 is complete for OAuth consent inventory, permission-scope risk scoring, suppression controls, and risk-ranked Discover UI/API. Browser/RMM discovery remains an explicitly optional stretch item.

1. [x] Enumerate OAuth app consent grants per tenant via Graph API
2. [x] Risk-score apps by permission scope (e.g., mail.read+files.readwrite = high risk)
3. [x] Shadow IT dashboard API per tenant with risk-sorted app list
4. (Stretch) Optional lightweight browser-extension or RMM-deployed agent for deeper SaaS usage discovery beyond OAuth grants — treat as a stretch feature

**Exit criteria:** View a ranked list of OAuth-connected third-party apps per tenant with a risk score.

### Phase 8 — Prospect / sales-enablement flow

**Progress:** Phase 8 is complete for short-lived read-only assessment links, separate prospect redirect URI, Graph assessment/report retrieval, frontend flow, and conversion into a pending managed tenant requiring normal management consent.

1. [x] Read-only "Magic Link" flow: generate a link, prospect grants read-only consent, TenantToolbox runs a security assessment without persisting full write access
2. [x] Free assessment report generation (reuses Phase 4 reporting engine)
3. [x] Convert prospect → managed tenant flow (creates a pending managed tenant; full management consent is completed through the normal reconnect flow)

**Exit criteria:** Send yourself a Magic Link, grant read-only consent from a test tenant, and receive a generated risk-assessment report.

### Phase 9 — Hardening & polish

**Progress:** Phase 9 application hardening is complete for rate limiting, Graph retry/backoff, encrypted credentials, confirmation/RBAC guards, backup/restore, bounded load tooling, migration execution, and reconnect UI/API. TLS termination, live production load execution, and GDAP operations remain deployment tasks.

1. [x] Rate-limit and backoff handling for Graph API throttling across many tenants
2. [x] Token refresh failure handling + reconnect flow when a tenant revokes consent, using restart-safe signed OAuth state
3. [x] Secrets encryption audit (tokens encrypted at rest; TLS is enforced at the deployment/reverse-proxy boundary)
4. [x] Multi-tech guardrails: confirm-before-destructive-action, permission scoping by role
5. [x] Backup/restore for Postgres in the Docker Compose setup
6. [x] Load testing polling jobs against tenant count targets (e.g., 50, 200 tenants)
7. [x] Documentation: complete multi-tenant Azure AD app registration/setup walkthrough, `.env.example`, migration runner, and PSA adapter configuration; GDAP operations remain an external integration guide

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
