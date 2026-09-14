# Microsoft Entra ID setup

TenantToolbox uses one multi-tenant Microsoft Entra application with delegated admin consent. Configure the application ID and secret once in the TenantToolbox deployment environment; do not add client-tenant IDs, passwords, or tokens to `.env`. Each client tenant is connected separately through the dashboard consent flow. GDAP and Partner Center import remain future integration work.

1. In **Microsoft Entra admin center → App registrations**, create a Web application.
2. Add the redirect URI from `ENTRA_REDIRECT_URI` (the development default is `http://localhost:8000/api/auth/microsoft/callback`).
3. Create a client secret and set the application-wide `ENTRA_CLIENT_ID` and `ENTRA_CLIENT_SECRET` in the backend environment. These are not per-customer credentials. Never commit these values.
4. Add delegated Microsoft Graph permissions:
   - `openid`, `profile`, `offline_access`
   - `User.Read`
   - `Organization.Read.All`
   - `Policy.Read.All` and `Policy.ReadWrite.ConditionalAccess` for baseline drift/deployment
   - `SecurityAlert.Read.All` and `AuditLog.Read.All` for Phase 3 security events
   - `User.Read.All` and `User.ReadWrite.All` for supported user remediation
5. Select **Accounts in any organizational directory** as the supported account type, then grant admin consent in each client tenant when it is connected.
6. While logged in, use the dashboard **Connect tenant** action. Repeat this action for every client tenant; each consent callback stores that tenant's encrypted delegated token in PostgreSQL and associates it with the MSP organization.

For Phase 2 deployment and drift operations, configure the optional SMTP variables in `.env` if email alert delivery is required. Without SMTP configuration, drift events remain available through the in-app alerts API.

The callback exchanges the authorization code, obtains the tenant ID from the token response, calls Microsoft Graph `/organization`, and stores only encrypted refresh/access tokens per connected tenant. The API never returns tokens to the frontend. Revoked consent can be repaired with the tenant reconnect action.

Phase 2 supports explicit Conditional Access policy deployment, drift detection, and rollback for the `require_mfa` and `block_legacy_auth` controls. Unsupported controls are reported and are never silently applied.
