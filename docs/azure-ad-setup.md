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
| User directory details (departments, groups, MFA methods) | `GroupMember.Read.All`, `UserAuthenticationMethod.Read.All` |\n| User lifecycle actions | `User.ReadWrite.All`, `Directory.ReadWrite.All` |
| Intune inventory/actions | `DeviceManagementManagedDevices.ReadWrite.All` |
| OAuth app discovery | `DelegatedPermissionGrant.Read.All`, `Application.Read.All` |

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
ENTRA_REDIRECT_URI=http://localhost:8000/api/auth/microsoft/callback
ENTRA_PROSPECT_REDIRECT_URI=http://localhost:8000/api/prospect/callback
FRONTEND_URL=http://localhost:5173
AUTO_REMEDIATION_ENABLED=false
```

The Entra values appear once in this file because they belong to the shared
TenantToolbox application. Do not add a separate block for each client tenant.
Never commit `.env` or send the client secret to a client.

Start or restart the stack:

```sh
docker compose up -d --build
```

The first-time wizard at `http://localhost:5173` creates the initial
TenantToolbox owner account.

## 5. Connect multiple client tenants

For every client tenant:

1. Sign in to TenantToolbox as the owner.
2. Open **Client tenants → Connect tenant**.
3. The client administrator signs in to Microsoft and accepts the requested
   delegated permissions for that tenant.
4. TenantToolbox verifies the tenant with Graph `/organization`.
5. TenantToolbox stores the tenant ID and encrypted access/refresh tokens in
   PostgreSQL.
6. Repeat for the next client tenant.

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
