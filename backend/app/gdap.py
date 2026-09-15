from datetime import datetime, timedelta, timezone

import httpx

from app.config import settings

GRAPH_URL = "https://graph.microsoft.com/v1.0"
TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"


class GdapError(RuntimeError):
    pass


class GdapClient:
    def __init__(self) -> None:
        if not settings.partner_tenant_id or not settings.entra_client_id or not settings.entra_client_secret:
            raise GdapError("CSP/GDAP is not configured; set PARTNER_TENANT_ID, ENTRA_CLIENT_ID, and ENTRA_CLIENT_SECRET")

    def _token(self) -> str:
        response = httpx.post(TOKEN_URL.format(tenant=settings.partner_tenant_id), data={"client_id": settings.entra_client_id, "client_secret": settings.entra_client_secret, "grant_type": "client_credentials", "scope": "https://graph.microsoft.com/.default"}, timeout=15)
        if response.is_error or not response.json().get("access_token"):
            raise GdapError("CSP/GDAP app-only token acquisition failed")
        return response.json()["access_token"]

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict:
        response = httpx.request(method, f"{GRAPH_URL}/{path.lstrip('/')}", headers={"Authorization": f"Bearer {self._token()}", "Content-Type": "application/json"}, json=payload, timeout=30)
        if response.is_error:
            try: detail = response.json().get("error", {}).get("message")
            except ValueError: detail = None
            raise GdapError(f"GDAP request failed: {response.status_code} {detail or ''}".strip())
        return response.json() if response.content else {}

    def customers(self) -> list[dict]:
        return self._request("GET", "tenantRelationships/delegatedAdminCustomers").get("value", [])

    def relationships(self, customer_tenant_id: str | None = None) -> list[dict]:
        path = "tenantRelationships/delegatedAdminRelationships"
        relationships = self._request("GET", path).get("value", [])
        if customer_tenant_id:
            relationships = [item for item in relationships if (item.get("customer") or {}).get("tenantId") == customer_tenant_id]
        return relationships

    def create_relationship(self, customer_tenant_id: str, display_name: str, duration_days: int, auto_extend_days: int, role_definition_ids: list[str], security_group_id: str | None = None) -> dict:
        payload = {"displayName": display_name, "duration": f"P{max(1, duration_days)}D", "autoExtendDuration": f"P{max(0, auto_extend_days)}D", "customer": {"tenantId": customer_tenant_id}, "accessDetails": {"unifiedRoles": [{"roleDefinitionId": role_id} for role_id in role_definition_ids]}}
        if security_group_id:
            payload["accessDetails"]["securityGroup"] = {"id": security_group_id}
        return self._request("POST", "tenantRelationships/delegatedAdminRelationships", payload)
