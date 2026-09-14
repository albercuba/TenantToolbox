from datetime import datetime, timedelta, timezone

import httpx

from app.config import settings
from app.models import ClientTenant, TenantCredential
from app.security import decrypt_credential, encrypt_credential

GRAPH_URL = "https://graph.microsoft.com/v1.0"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"


class GraphAPIError(RuntimeError):
    pass


class GraphClient:
    def __init__(self, tenant: ClientTenant, credential: TenantCredential):
        self.tenant = tenant
        self.credential = credential

    def _access_token(self) -> str:
        now = datetime.now(timezone.utc)
        if self.credential.encrypted_access_token and self.credential.access_token_expires_at:
            expires_at = self.credential.access_token_expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at > now + timedelta(minutes=2):
                return decrypt_credential(self.credential.encrypted_access_token)
        if not settings.entra_client_id or not settings.entra_client_secret:
            raise GraphAPIError("Microsoft OAuth is not configured")
        response = httpx.post(
            TOKEN_URL,
            data={
                "client_id": settings.entra_client_id,
                "client_secret": settings.entra_client_secret,
                "grant_type": "refresh_token",
                "refresh_token": decrypt_credential(self.credential.encrypted_refresh_token),
                "scope": "openid profile offline_access User.Read Organization.Read.All",
            },
            timeout=15,
        )
        if response.is_error:
            raise GraphAPIError("Microsoft token refresh failed")
        payload = response.json()
        token = payload.get("access_token")
        if not token:
            raise GraphAPIError("Microsoft token refresh returned no access token")
        self.credential.encrypted_access_token = encrypt_credential(token)
        self.credential.access_token_expires_at = now + timedelta(seconds=int(payload.get("expires_in", 3600)))
        if payload.get("refresh_token"):
            self.credential.encrypted_refresh_token = encrypt_credential(payload["refresh_token"])
        return token

    def get(self, path: str, params: dict[str, str] | None = None) -> dict:
        response = httpx.get(
            f"{GRAPH_URL}/{path.lstrip('/')}",
            headers={"Authorization": f"Bearer {self._access_token()}"},
            params=params,
            timeout=30,
        )
        if response.is_error:
            raise GraphAPIError(f"Microsoft Graph request failed: {response.status_code}")
        return response.json()

    def all_pages(self, path: str, params: dict[str, str] | None = None) -> list[dict]:
        items: list[dict] = []
        next_url: str | None = f"{GRAPH_URL}/{path.lstrip('/')}"
        query = params
        while next_url:
            response = httpx.get(next_url, headers={"Authorization": f"Bearer {self._access_token()}"}, params=query, timeout=30)
            if response.is_error:
                raise GraphAPIError(f"Microsoft Graph request failed: {response.status_code}")
            payload = response.json()
            items.extend(payload.get("value", []))
            next_url = payload.get("@odata.nextLink")
            query = None
        return items

    def users(self) -> list[dict]:
        return self.all_pages("users", {"$select": "id,displayName,userPrincipalName,accountEnabled"})

    def licenses(self) -> list[dict]:
        return self.all_pages("subscribedSkus", {"$select": "skuId,skuPartNumber,consumedUnits,prepaidUnits"})

    def secure_score(self) -> dict | None:
        scores = self.get("security/secureScores", {"$top": "1"}).get("value", [])
        return scores[0] if scores else None

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict:
        response = httpx.request(method, f"{GRAPH_URL}/{path.lstrip('/')}", headers={"Authorization": f"Bearer {self._access_token()}", "Content-Type": "application/json"}, json=payload, timeout=30)
        if response.is_error:
            raise GraphAPIError(f"Microsoft Graph request failed: {response.status_code}")
        return response.json() if response.content else {}

    def conditional_access_policies(self) -> list[dict]:
        return self.all_pages("identity/conditionalAccess/policies")

    def apply_baseline(self, definition: dict) -> dict[str, list[str]]:
        applied: list[str] = []
        unsupported: list[str] = []
        existing = {item.get("displayName"): item for item in self.conditional_access_policies()}
        for control in definition.get("controls", []):
            name = control.get("name")
            if control.get("type") != "conditional_access" or name not in {"require_mfa", "block_legacy_auth"}:
                unsupported.append(name or "unnamed_control")
                continue
            policy_name = f"TenantToolbox - {name}"
            policy = {"displayName": policy_name, "state": control.get("state", "enabled"), "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]}, "clientAppTypes": ["all"]}, "grantControls": {"operator": "OR", "builtInControls": ["mfa"] if name == "require_mfa" else ["block"]}}
            if existing.get(policy_name):
                self._request("PATCH", f"identity/conditionalAccess/policies/{existing[policy_name]['id']}", policy)
            else:
                self._request("POST", "identity/conditionalAccess/policies", policy)
            applied.append(name)
        return {"applied": applied, "unsupported": unsupported}

    def baseline_differences(self, definition: dict) -> list[dict]:
        policies = {item.get("displayName"): item for item in self.conditional_access_policies()}
        differences = []
        for control in definition.get("controls", []):
            if control.get("type") != "conditional_access":
                differences.append({"control": control.get("name"), "reason": "unsupported_control"})
                continue
            expected = control.get("state", "enabled")
            actual = policies.get(f"TenantToolbox - {control.get('name')}")
            if not actual:
                differences.append({"control": control.get("name"), "reason": "missing_policy", "expected_state": expected})
            elif actual.get("state") != expected:
                differences.append({"control": control.get("name"), "reason": "state_mismatch", "expected_state": expected, "actual_state": actual.get("state")})
        return differences
