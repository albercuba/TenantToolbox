# Microsoft Entra ID setup

Phase 0 uses a single multi-tenant Microsoft Entra application with delegated admin consent. GDAP and Partner Center import remain Phase 1 work.

1. In **Microsoft Entra admin center → App registrations**, create a Web application.
2. Add the redirect URI from `ENTRA_REDIRECT_URI` (the development default is `http://localhost:8000/api/auth/microsoft/callback`).
3. Create a client secret and set `ENTRA_CLIENT_ID` and `ENTRA_CLIENT_SECRET` in the backend environment. Never commit these values.
4. Add delegated Microsoft Graph permissions:
   - `openid`, `profile`, `offline_access`
   - `User.Read`
   - `Organization.Read.All`
   - `Policy.Read.All` and `Policy.ReadWrite.ConditionalAccess` for baseline drift/deployment
5. Grant admin consent in the connected client tenant.
6. Generate a connection URL from `GET /api/auth/microsoft/start` while logged in, or use the dashboard Connect tenant action when that UI is wired to the endpoint.

For Phase 2 deployment and drift operations, configure the optional SMTP variables in `.env` if email alert delivery is required. Without SMTP configuration, drift events remain available through the in-app alerts API.

The callback exchanges the authorization code, obtains the tenant ID from the token response, calls Microsoft Graph `/organization`, and stores only encrypted refresh/access tokens. The API never returns tokens to the frontend.

Phase 2 supports explicit Conditional Access policy deployment, drift detection, and rollback for the `require_mfa` and `block_legacy_auth` controls. Unsupported controls are reported and are never silently applied.
