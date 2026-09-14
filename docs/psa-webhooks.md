# PSA webhook integration

TenantToolbox sends security-alert tickets to the configured `PSA_WEBHOOK_URL`.
Set `PSA_VENDOR` to `generic` (default), `connectwise`, `autotask`, or `halo`.
The adapter changes field names to the vendor's webhook conventions; transport
and authentication are intentionally left to the deployment's webhook gateway.

```env
PSA_VENDOR=connectwise
PSA_WEBHOOK_URL=https://example.invalid/tenanttoolbox-hook
```

The generic payload is `{vendor,title,description,severity,tenant_id,source}`.
ConnectWise uses `summary`, `initialDescription`, `priority`, and
`companyIdentifier`; Autotask uses `title`, `description`, `priority`, and
`companyID`; Halo uses `summary`, `details`, `priority`, and `client_id`.
Validate the mapping against the receiving PSA API and keep the webhook behind
TLS and an authenticated gateway. Delivery is optional and never prevents an
alert from being persisted locally.
