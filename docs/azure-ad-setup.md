# Microsoft Entra ID setup

TenantToolbox uses **one multi-tenant Microsoft Entra web application** for
all client tenants. The application ID and secret identify the TenantToolbox
backend. They are configured once; client tenant IDs and delegated tokens are
not placed in `.env`.

## 1. Create the application

1. Open the [Microsoft Entra admin center](https://entra.microsoft.com).
2. Go to **Identity → Applications → App registrations → New registration**.
3. Use a name such as `TenantToolbox`.
4. Under **Supported account types**, select:
   `Accounts in any organizational directory (Any Microsoft Entra ID tenant - Multitenant)`.
5. Under **Redirect URI**, select **Web** and add:

   ```text
   http://localhost:8000/api/auth/microsoft/callback
   ```

6. Select **Register**.
7. On the application **Overview** page, copy **Application (client) ID**.
   This is `ENTRA_CLIENT_ID`.
8. Open **Certificates & secrets → Client secrets → New client secret**.
   Choose an expiry appropriate for your security policy.
9. Copy the secret **Value** immediately after creation, not the Secret ID.
   This is `ENTRA_CLIENT_SECRET`. Microsoft displays the value only once.

For production, use HTTPS redirect URIs and a secret-management system or
Docker secrets rather than storing the secret in a plain `.env` file.

## 2. Add the prospect redirect URI

If prospect assessments are enabled, add a second **Web** redirect URI:

```text
http://localhost:8000/api/prospect/callback
```

The URI must exactly match `ENTRA_PROSPECT_REDIRECT_URI`, including protocol,
host, port, path, and trailing slash behavior.

## 3. Add Microsoft Graph permissions

Open **API permissions → Add a permission → Microsoft Graph → Delegated
permissions** and add the permissions required by the features you will use:

| Feature | Delegated permissions |
|---|---|
| Tenant connection and organization verification | `User.Read`, `Organization.Read.All`, `offline_access`, `openid`, `profile` |
| User and license snapshots | `User.Read.All`, `Directory.Read.All` |
| Secure Score | `SecurityEvents.Read.All` |
| Conditional Access baseline deployment | `Policy.Read.All`, `Policy.ReadWrite.ConditionalAccess` |
| Security alerts and risky sign-ins | `SecurityAlert.Read.All`, `AuditLog.Read.All`, `IdentityRiskEvent.Read.All` |
| User directory details (departments, groups, MFA methods) | `GroupMember.Read.All`, `UserAuthenticationMethod.Read.All` |
| User lifecycle actions | `User.ReadWrite.All`, `Directory.ReadWrite.All`, `GroupMember.ReadWrite.All`, `UserAuthenticationMethod.ReadWrite.All`, `MailboxSettings.ReadWrite` |
| Intune inventory/actions | `DeviceManagementManagedDevices.ReadWrite.All` |
| OAuth app discovery | `DelegatedPermissionGrant.Read.All`, `Application.Read.All` |
| CSP/GDAP onboarding | Microsoft Graph application `DelegatedAdminRelationship.ReadWrite.All`, `DelegatedAdminRelationship.Read.All` in the Partner tenant |

Microsoft may rename or split permissions over time. Review the permission
 descriptions in the portal and grant only the scopes required by the features
 enabled in your deployment.

Select **Grant admin consent for your organization** only for the MSP's own
tenant if appropriate. Each client administrator grants consent for their own
tenant during the connection flow. Do not grant client access by sharing the
client secret.

## 4. Configure the local deployment

From the repository root:

```sh
cp .env.example .env
```

Generate the two required application secrets. `JWT_SECRET` can be any long,
random deployment secret. Generate the Fernet key with:

```sh
backend/.venv/bin/python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Edit `.env`:

```env
JWT_SECRET=replace-with-a-long-random-value
CREDENTIAL_ENCRYPTION_KEY=the-generated-fernet-key
ENTRA_CLIENT_ID=the-application-client-id
ENTRA_CLIENT_SECRET=the-secret-value
PARTNER_TENANT_ID=<CSP partner tenant ID>
ENTRA_REDIRECT_URI=http://localhost:8000/api/auth/microsoft/callback
ENTRA_PROSPECT_REDIRECT_URI=http://localhost:8000/api/prospect/callback
FRONTEND_URL=http://localhost:5173
AUTO_REMEDIATION_ENABLED=false
EXCHANGE_AUTOMATION_URL=http://exchange-worker:8080
EXCHANGE_AUTOMATION_TOKEN=replace-with-a-long-random-worker-token
```

The Entra values appear once in this file because they belong to the shared
TenantToolbox application. Do not add a separate block for each client tenant.
Never commit `.env` or send the client secret to a client.

## 5. Configure Exchange Online automation

Global Address List visibility, external forwarding, and shared-mailbox
permissions are Exchange Online operations. TenantToolbox calls a separate
worker so Exchange credentials and PowerShell sessions never enter the API
container. The worker must expose these authenticated endpoints:

```text
POST /v1/user-actions/global-address-list
POST /v1/user-actions/mail-forwarding
POST /v1/user-actions/shared-mailbox-permissions
```

Each request includes `tenant_id`, `user_id`, and the operation-specific payload.
The worker must validate the tenant allowlist and return a non-2xx response on
failure. By default the worker uses **interactive delegated authentication**:
the Exchange administrator supplied in the action wizard signs in explicitly
when the Exchange PowerShell operation starts. Configure the API with a private
network URL and a random bearer token:

```env
EXCHANGE_AUTOMATION_URL=http://exchange-worker:8080
EXCHANGE_AUTOMATION_TOKEN=replace-with-a-long-random-worker-token
```

The worker's Entra app registration needs Exchange Online application
permissions appropriate to the runbook and admin consent. Store its certificate
in the worker's secret store or Docker secret, never in this repository or in
TenantToolbox's `.env`. Do not expose the worker publicly; restrict its network
access to the TenantToolbox backend and require the bearer token.

The repository includes an optional PowerShell-based worker in
`exchange-worker/`. For Model B, configure interactive mode and no certificate
or Partner Center account is required:

```env
EXCHANGE_AUTH_MODE=interactive
EXCHANGE_AUTOMATION_TOKEN=<random-private-worker-token>
```

In interactive mode, the tenant allowlist is managed through TenantToolbox:
when an owner imports/maps a CSP customer or adds a tenant through the web UI,
the backend authorizes that mapped tenant before forwarding an Exchange action
to the private worker. No customer tenant IDs need to be added to `.env` and no
worker restart is required when customers are added or removed.

The Exchange administrator must have the required Exchange RBAC role and
complete the Microsoft sign-in when an Exchange action runs. The worker also
supports optional unattended certificate mode for deployments that explicitly
need background automation. Certificate mode retains a static environment
allowlist because it is not driven by an interactive MSP session:

```env
EXCHANGE_AUTH_MODE=certificate
EXCHANGE_APP_ID=<Exchange app registration client ID>
EXCHANGE_CERTIFICATE_FILE=./secrets/exchange.pfx
EXCHANGE_CERTIFICATE_PASSWORD=<certificate password>
EXCHANGE_ALLOWED_TENANT_IDS=<comma-separated tenant IDs>
```

Place the PFX file at the configured path with restrictive permissions, then
start the optional service:

```sh
mkdir -p secrets
chmod 700 secrets
chmod 600 secrets/exchange.pfx
docker compose up -d --build exchange-worker
```

In interactive mode the worker uses `Connect-ExchangeOnline` with the
administrator's delegated sign-in. In certificate mode it uses app-only auth.
Grant only the Exchange permissions required by your organization and restrict
the tenant allowlist to tenants authorized for automation. Interactive mode is
intended for explicit, operator-triggered actions; it is not an unattended job
runner.

Start or restart the stack:

```sh
docker compose up -d --build
```

The first-time wizard at `http://localhost:5173` creates the initial
TenantToolbox owner account.

## 6. CSP/GDAP testing with a Partner Center integration sandbox

For software testing, do not begin with a production CSP account unless you
intend to onboard real customers. Microsoft provides a separate **Partner
Center integration sandbox** for testing Partner Center API integrations. The
sandbox is independent from the primary partner account and has its own users,
customers, subscriptions, and API credentials.

Important limitations:

- You must have a Microsoft CSP partner tenant. Partner Center API access is
  available to direct-bill partners and indirect providers.
- The sandbox is for integration testing, not production customer management.
- Sandbox data is separate from the primary Partner Center account.
- Sandbox transactions may appear on invoices, but the sandbox invoice is
  marked as not payable.
- GDAP approval still requires a customer/test tenant administrator to approve
  the relationship request.

### Get a Partner Center account for testing

1. Create or use a Microsoft Entra tenant for your software company/MSP.
2. Apply to become a Microsoft Cloud Solution Provider partner through the
   [Microsoft AI Cloud Partner Program](https://partner.microsoft.com/partnership).
3. Complete Microsoft’s business verification and partner enrollment steps.
   Microsoft may request legal business information, domains, contact details,
   and verification documents.
4. In Partner Center, use **Account settings** to confirm your partner profile
   and whether you are a direct-bill partner or an indirect provider.
5. Create an **integration sandbox** from the Partner Center sandbox/account
   settings flow. Do not use the primary partner account for initial API tests.
6. In the sandbox, open **Settings → Account settings → App management** and
   register the application used for Partner Center API access. Record the App
   ID, key/secret, and sandbox domain in a secret manager.
7. Enable the required Partner Center/GDAP API access and complete admin
   consent in the partner tenant.
8. Configure TenantToolbox with the sandbox partner tenant ID:

   ```env
   PARTNER_TENANT_ID=<sandbox partner tenant ID>
   ```

9. Use a separate Microsoft 365 test customer tenant. In TenantToolbox open
   **Clients → CSP / GDAP onboarding**, refresh Partner Center, and use **Map**
   to import the customer into a local client workspace.
10. Select **Request GDAP**, enter role-definition IDs copied from the current
    Partner Center/GDAP role catalog, and create the request. TenantToolbox
    stores the returned relationship and approval URL; send that URL to a
    Global Administrator of the test customer tenant.
11. Refresh the onboarding page after approval. Verify that the relationship is
    active, the requested roles are least-privilege, and the delegated security
    group/integrated user is present before testing user actions.

Microsoft’s current API setup guidance is available at:

- [Set up API access in Partner Center](https://learn.microsoft.com/en-us/partner-center/develop/set-up-api-access-in-partner-center)
- [Microsoft AI Cloud Partner Program](https://partner.microsoft.com/partnership)
- [GDAP overview](https://learn.microsoft.com/en-us/partner-center/security/gdap-introduction)

A normal Microsoft 365 developer tenant by itself is not a Partner Center
account and does not provide CSP/GDAP customer-management APIs. TenantToolbox
therefore presents **CSP/GDAP onboarding as the primary path** and labels the
existing per-tenant delegated OAuth flow as **Direct OAuth fallback**. Use the
fallback only for a tenant that cannot yet be managed through your Partner
Center relationship; it does not create a CSP customer or GDAP relationship.

The onboarding page deliberately asks for verified GDAP role-definition IDs
instead of guessing IDs. Microsoft’s role catalog and least-privilege
requirements can change, so copy the IDs from the Partner Center/GDAP setup
used by your test account. Customer mapping and relationship creation are
owner-only operations and are recorded in the TenantToolbox audit log.

## 7. Connect multiple client tenants

### Preferred: CSP / GDAP

1. Sign in to TenantToolbox as the owner and open **Clients**.
2. In **CSP / GDAP onboarding**, select **Refresh Partner Center**.
3. Map each returned CSP customer to a local client workspace.
4. Create a GDAP request with verified role-definition IDs and an optional
   delegated security group.
5. Send the generated **Customer approval** link to the customer administrator.
6. Refresh until the relationship is active, then verify roles and delegated
   access before running management actions.

TenantToolbox uses the Partner Center customer and GDAP relationship records
for onboarding. It does not silently turn a CSP customer into a direct OAuth
connection. Relationship creation, customer mapping, and approval-link data
are auditable.

### Fallback: direct delegated OAuth

For a tenant that is not available through Partner Center, select the relevant
local client and choose **Direct OAuth fallback**. The client administrator
signs in and consents to the requested delegated Microsoft Graph permissions.
TenantToolbox verifies the tenant with Graph `/organization` and stores its
access/refresh credentials encrypted in PostgreSQL. Reconnect is available when
consent expires or permissions are expanded. This fallback is intentionally
secondary to CSP/GDAP and does not grant access to other tenants.

Each tenant gets its own encrypted credential record. The browser never
receives refresh tokens, and no client credentials are written to `.env`.
If consent is revoked, the tenant shows a connection warning and can be
repaired with **Reconnect**. OAuth state is short-lived, signed, and bound to
the initiating staff user/tenant, so normal backend restarts do not invalidate
a consent flow.

## Troubleshooting

- **`ENTRA_CLIENT_ID is not configured`**: confirm `.env` exists in the
  repository root and recreate the backend container.
- **Redirect URI mismatch**: compare the Entra portal URI with
  `ENTRA_REDIRECT_URI` character-for-character.
- **Admin consent or Graph 403**: add the required delegated permission and
  grant consent in the affected client tenant.
- **Microsoft token exchange failed (`invalid_client`)**: use the client secret
  **Value**, not Secret ID; check that it has not expired; confirm the client
  ID belongs to this app; then recreate the backend container. Never reuse an
  old authorization URL after changing the secret.
- **Microsoft token exchange failed (`invalid_grant`)**: start a fresh Connect
  tenant flow. Authorization codes are single-use and short-lived; also verify
  the redirect URI is identical in Entra and `.env`.
- **Connect button returns 502 in Docker**: ensure the frontend container is
  using the Compose backend proxy target and restart with `--build`. The API
  now includes Microsoft's safe error code and description in the response.

The callback exchanges the authorization code, calls Graph organization
verification, and stores only encrypted tokens. The API never returns tokens
to the frontend.
