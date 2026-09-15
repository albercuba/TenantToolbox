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

TenantToolbox uses delegated permissions for the initial tenant connection and
uses Microsoft Graph application permissions for unattended tenant operations.
Configure both permission types on the same multi-tenant app registration.

### Delegated permissions for tenant connection

Open **API permissions → Add a permission → Microsoft Graph → Delegated
permissions** and add the permissions required by the connection flow:

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


### Application permissions for unattended operations

Also add the Microsoft Graph **Application permissions** required by the
TenantToolbox operations. The backend requests the tenant-specific
client-credentials token with `https://graph.microsoft.com/.default`:

```text
User.ReadWrite.All
Group.ReadWrite.All
GroupMember.ReadWrite.All
Directory.ReadWrite.All
Application.ReadWrite.All
AppRoleAssignment.ReadWrite.All
RoleManagement.ReadWrite.Directory
Policy.ReadWrite.ConditionalAccess
UserAuthenticationMethod.ReadWrite.All
DeviceManagementManagedDevices.ReadWrite.All
DeviceManagementConfiguration.ReadWrite.All
Organization.ReadWrite.All
AuditLog.Read.All
SecurityEvents.Read.All
SecurityAlert.ReadWrite.All
MailboxSettings.ReadWrite
```

Microsoft may rename, split, or restrict permissions over time. Review each
permission in the portal and grant the set required by the features enabled in
your deployment. Do not add privileged application permissions merely because a
future feature may eventually need them.

Grant admin consent for the application permissions in **every customer tenant**
that TenantToolbox will manage. The same `ENTRA_CLIENT_ID` and secret are used
for all tenants; the token endpoint is selected from the stored customer tenant
ID. Delegated consent remains necessary for the initial connection flow. Do not
grant client access by sharing the client secret.

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
The backend verifies that the requested tenant is mapped to the authenticated
TenantToolbox staff member before calling the worker. The worker returns a
non-2xx response on failure. In the PFX mode used by this deployment, Exchange
PowerShell runs app-only and unattended. Configure the API with a private
network URL and a random bearer token:

```env
EXCHANGE_AUTOMATION_URL=http://exchange-worker:8080
EXCHANGE_AUTOMATION_TOKEN=replace-with-a-long-random-worker-token
```

The worker's Entra app registration needs the Exchange Online application
permission `Exchange.ManageAsApp`, an Exchange role assignment, and admin
consent in every customer tenant where it will operate. Store the PFX in the
worker's secret store or protected Docker-mounted file, never in this repository
or in TenantToolbox's `.env`. Do not expose the worker publicly; restrict its
network access to the TenantToolbox backend and require the bearer token.

### Create and register the Exchange certificate

For testing, create a self-signed RSA certificate on a secure workstation. The
private key stays in the PFX and must never be committed:

```sh
mkdir -p exchange-cert
cd exchange-cert
openssl req -x509 -newkey rsa:2048 -keyout exchange.key -out exchange.crt -days 365 -nodes -subj "/CN=TenantToolbox Exchange Automation"
openssl pkcs12 -export -out exchange.pfx -inkey exchange.key -in exchange.crt -name TenantToolbox-Exchange
openssl x509 -in exchange.crt -outform der -out exchange.cer
```

In the Exchange automation app registration:

1. Open **Certificates & secrets → Upload certificate**.
2. Upload `exchange.cer`; never upload `exchange.pfx`.
3. Record the application/client ID.
4. Under **API permissions**, add **Office 365 Exchange Online → Application
   permissions → Exchange.ManageAsApp**.
5. Grant admin consent.
6. Assign the app an Exchange role, preferably a custom role group limited to
   the required cmdlets. `Exchange Administrator` is suitable for initial
   testing but is highly privileged.
7. Repeat tenant admin consent and Exchange role assignment in every customer
   tenant. Each customer tenant is authorized directly through its own tenant
   consent and app permissions.

The repository includes a PowerShell worker in `exchange-worker/`. This
configuration uses PFX app-only authentication and does not require a device
code or an administrator UPN at action time:

```env
EXCHANGE_AUTH_MODE=certificate
EXCHANGE_AUTOMATION_TOKEN=<random-private-worker-token>
EXCHANGE_APP_ID=<Exchange app registration client ID>
EXCHANGE_CERTIFICATE_FILE=./secrets/exchange.pfx
EXCHANGE_CERTIFICATE_PASSWORD=<certificate password>
```

Customer tenant authorization is managed through TenantToolbox. When an owner
adds or maps a tenant in the web UI, the backend authorizes that mapped tenant
for the authenticated staff member before calling the private worker. No
customer tenant IDs need to be added to `.env`, and adding a tenant does not
require a worker restart. The worker accepts requests only from the backend
through the private network and shared bearer token.

Place the PFX file at the configured path with restrictive permissions, then
start the normal stack:

```sh
mkdir -p secrets
chmod 700 secrets
chmod 600 secrets/exchange.pfx
# The Compose service reads the mode-600 file as its isolated root worker user.
docker compose up -d --build exchange-worker
```

The worker uses:

```powershell
Connect-ExchangeOnline -AppId <app-id> -Certificate <certificate> -Organization <tenant>.onmicrosoft.com
```

It then executes the requested Exchange cmdlet, such as
`Set-Mailbox -HiddenFromAddressListsEnabled`, and disconnects. Grant only the
Exchange permissions required by your organization. Tenant access is controlled
by the mapped-tenant authorization in TenantToolbox; customer tenant IDs do not
need to be maintained in `.env`.

Start or restart the stack:

```sh
docker compose up -d --build
```

The first-time wizard at `http://localhost:5173` creates the initial
TenantToolbox owner account.

### Running user actions

User actions are opened from **Users & lifecycle → Actions**. Configure the
operation, use **Next** to move through the workflow, and review the final
summary in the styled action drawer. The final review step is the confirmation:
clicking **Continue & Run** starts the operation immediately and does not show a
second browser-native confirmation dialog. While the request is running, the
button changes to **Running…**. A successful operation is reported in the
application notice and recorded in the audit log; failures are shown there with
the returned error message.

For Exchange-backed actions such as **Global Address List**, **Manage Email
Forwarding**, and **Manage Shared Mailboxes**, the final review also identifies
that the request runs through the certificate-authenticated Exchange worker.
The drawer loads the current tenant state before editing Global Address List,
automatic replies, groups, licenses, or shared-mailbox selections. Group and
license changes submit Microsoft Graph IDs, and shared-mailbox permissions use
a real mailbox identity returned by Exchange Online. Offboarding executes only
the selected steps and reports failure without claiming the remaining steps were
completed.

## 6. Connect multiple client tenants

TenantToolbox connects tenants directly through Microsoft Entra consent. Delegated administration relationships are not required.

1. Sign in to TenantToolbox as the owner and open **Clients**.
2. Create or select a client workspace.
3. Choose **Direct OAuth fallback** for that workspace.
4. Have an administrator from the customer tenant complete the Microsoft consent
   flow.
5. TenantToolbox verifies the tenant with Microsoft Graph and stores the tenant
   relationship in PostgreSQL.
6. Grant the TenantToolbox app the required Graph application permissions and
   admin consent in that customer tenant.
7. Assign the required Exchange app-only role in that customer tenant.

The same TenantToolbox app credentials are used for all customer tenants. The
backend requests app-only Graph tokens using each stored customer tenant ID;
there is no customer tenant list to maintain in `.env`. Each tenant must grant
consent once, and additional tenants can be added without changing deployment
configuration.

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
