# Phase 3 live validation

This runbook validates Phase 3 against real services. Do not enable automatic remediation until the MSP has approved the policy and tested it in a non-production tenant.

## 1. Configure Graph permissions

In the Entra app registration, grant admin consent for:

- `SecurityAlert.Read.All`
- `AuditLog.Read.All`
- `User.Read.All` and `User.ReadWrite.All` for the supported disable-user remediation

Keep the existing `Organization.Read.All`, `Policy.Read.All`, and `Policy.ReadWrite.ConditionalAccess` permissions.

## 2. Configure environment

Copy `.env.example` to `.env`, then set the Entra values and a real encryption key. For delivery, set:

- `PSA_WEBHOOK_URL` to the PSA connector/webhook endpoint.
- `SMTP_HOST`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, and `ALERT_EMAIL` for email.

Validate the worker configuration with:

```sh
docker compose config
```

## 3. Connect and sync a tenant

Start the stack and create an owner account. Use the authenticated API to generate the Entra admin-consent URL:

```sh
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/auth/microsoft/start
```

Complete consent in a test tenant, then trigger alert ingestion:

```sh
curl -X POST -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/tenants/$CLIENT_TENANT_ID/alerts/ingest
```

## 4. Test a risky sign-in

Trigger or wait for a test Identity Protection risk event. The ingestion endpoint should create an in-app alert, send the configured email, and send the PSA webhook payload. Confirm with:

```sh
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/alerts
```

## 5. Test manual remediation

Only after confirming the target user and approval, execute the explicit confirmation endpoint:

```sh
curl -X POST -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/alerts/$ALERT_ID/remediate?confirm=true"
```

## 6. Automatic remediation

Automatic remediation is disabled by default. Enable `AUTO_REMEDIATION_ENABLED=true` only in a controlled test environment. When enabled, high-risk Identity Protection events with a `userId` disable that user and resolve the alert; failures remain visible in the alert details.
