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
