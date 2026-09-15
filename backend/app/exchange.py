from typing import Any

import httpx

from app.config import settings


class ExchangeAutomationError(RuntimeError):
    pass


class ExchangeAutomationClient:
    """Calls the separately hosted Exchange Online automation worker.

    The worker owns the Exchange certificate/session and must never receive the
    TenantToolbox database or delegated Graph refresh tokens.
    """

    def _call(self, operation: str, tenant_id: str, user_id: str, data: dict[str, Any], organization: str | None = None) -> dict:
        if not settings.exchange_automation_url or not settings.exchange_automation_token:
            raise ExchangeAutomationError("Exchange automation is not configured; set EXCHANGE_AUTOMATION_URL and EXCHANGE_AUTOMATION_TOKEN")
        try:
            response = httpx.post(
                f"{settings.exchange_automation_url.rstrip('/')}/v1/user-actions/{operation}",
                headers={"Authorization": f"Bearer {settings.exchange_automation_token}", "Content-Type": "application/json"},
                json={"tenant_id": tenant_id, "user_id": user_id, "organization": organization or tenant_id, **data},
                timeout=60,
            )
        except httpx.HTTPError as exc:
            raise ExchangeAutomationError("Exchange automation worker is unreachable") from exc
        if response.is_error:
            try:
                detail = response.json().get("detail")
            except ValueError:
                detail = None
            raise ExchangeAutomationError(f"Exchange automation failed for {operation}: {detail or response.status_code}")
        return response.json() if response.content else {}

    def hide_from_global_address_list(self, tenant_id: str, user_id: str, hidden: bool, organization: str) -> dict:
        return self._call("global-address-list", tenant_id, user_id, {"hidden": hidden}, organization)

    def set_forwarding(self, tenant_id: str, user_id: str, recipient: str | None, keep_copy: bool, organization: str | None = None) -> dict:
        return self._call("mail-forwarding", tenant_id, user_id, {"recipient": recipient}, organization)

    def set_shared_mailbox_permissions(self, tenant_id: str, user_id: str, permissions: list[dict], organization: str | None = None) -> dict:
        return self._call("shared-mailbox-permissions", tenant_id, user_id, {"permissions": permissions}, organization)
