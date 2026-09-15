import time
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
                "scope": "openid profile offline_access User.Read User.Read.All User.ReadWrite.All Directory.Read.All Directory.ReadWrite.All GroupMember.Read.All GroupMember.ReadWrite.All UserAuthenticationMethod.Read.All UserAuthenticationMethod.ReadWrite.All MailboxSettings.ReadWrite Organization.Read.All",
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
        response = self._http("GET", f"{GRAPH_URL}/{path.lstrip('/')}", headers={"Authorization": f"Bearer {self._access_token()}"}, params=params, timeout=30)
        if response.is_error:
            raise GraphAPIError(self._error_message(response, path))
        return response.json()

    @staticmethod
    def _error_message(response: httpx.Response, path: str) -> str:
        try:
            error = response.json().get("error", {})
            code = error.get("code")
            message = error.get("message")
            if code or message:
                return f"Microsoft Graph request failed for {path}: {response.status_code} {code or ''} {message or ''}".strip()
        except (ValueError, AttributeError):
            pass
        return f"Microsoft Graph request failed for {path}: {response.status_code}"

    def all_pages(self, path: str, params: dict[str, str] | None = None) -> list[dict]:
        items: list[dict] = []
        next_url: str | None = f"{GRAPH_URL}/{path.lstrip('/')}"
        query = params
        while next_url:
            response = self._http("GET", next_url, headers={"Authorization": f"Bearer {self._access_token()}"}, params=query, timeout=30)
            if response.is_error:
                raise GraphAPIError(self._error_message(response, path))
            payload = response.json()
            items.extend(payload.get("value", []))
            next_url = payload.get("@odata.nextLink")
            query = None
        return items

    def organization(self) -> dict:
        return self.get("organization", {"$select": "displayName,verifiedDomains"}).get("value", [{}])[0]

    def users(self) -> list[dict]:
        return self.all_pages("users", {"$select": "id,displayName,userPrincipalName,accountEnabled,department,assignedLicenses"})

    def user_groups(self, user_id: str) -> list[str]:
        return [item.get("displayName", "") for item in self.all_pages(f"users/{user_id}/memberOf/microsoft.graph.group", {"$select": "displayName"}) if item.get("displayName")]

    def user_mfa_methods(self, user_id: str) -> list[dict]:
        return self.get(f"users/{user_id}/authentication/methods").get("value", [])

    def licenses(self) -> list[dict]:
        return self.all_pages("subscribedSkus", {"$select": "skuId,skuPartNumber,consumedUnits,prepaidUnits"})

    def tenant_license_ids(self) -> set[str]:
        return {item["skuId"] for item in self.licenses() if isinstance(item.get("skuId"), str)}

    def secure_score(self) -> dict | None:
        scores = self.get("security/secureScores", {"$top": "1"}).get("value", [])
        return scores[0] if scores else None

    def _http(self, method: str, url: str, **kwargs):
        for attempt in range(4):
            response = httpx.request(method, url, **kwargs)
            if response.status_code not in {429, 500, 502, 503, 504} or attempt == 3:
                return response
            delay = int(response.headers.get("Retry-After", "0")) or 2**attempt
            time.sleep(min(delay, 30))
        raise GraphAPIError("Microsoft Graph retry limit exceeded")

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict:
        response = self._http("POST" if method == "POST" else method, f"{GRAPH_URL}/{path.lstrip('/')}", headers={"Authorization": f"Bearer {self._access_token()}", "Content-Type": "application/json"}, json=payload, timeout=30)
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

    def security_alerts(self) -> list[dict]:
        return self.all_pages("security/alerts_v2", {"$top": "100"})

    def risky_sign_ins(self) -> list[dict]:
        return self.all_pages("auditLogs/signIns", {"$top": "100", "$orderby": "createdDateTime desc"})

    def disable_user(self, user_id: str) -> None:
        self._request("PATCH", f"users/{user_id}", {"accountEnabled": False})

    def set_user_enabled(self, user_id: str, enabled: bool) -> None:
        self._request("PATCH", f"users/{user_id}", {"accountEnabled": enabled})

    def revoke_sessions(self, user_id: str) -> None:
        self._request("POST", f"users/{user_id}/revokeSignInSessions")

    def add_user_to_group(self, group_id: str, user_id: str) -> None:
        self._request("POST", f"groups/{group_id}/members/$ref", {"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"})

    def clear_authentication_method(self, user_id: str, method: dict) -> None:
        method_types: dict[str, str] = {"#microsoft.graph.microsoftAuthenticatorAuthenticationMethod": "microsoftAuthenticatorMethods", "#microsoft.graph.phoneAuthenticationMethod": "phoneMethods", "#microsoft.graph.fido2AuthenticationMethod": "fido2Methods", "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod": "windowsHelloForBusinessMethods", "#microsoft.graph.emailAuthenticationMethod": "emailMethods", "#microsoft.graph.temporaryAccessPassAuthenticationMethod": "temporaryAccessPassMethods"}
        method_type = str(method.get("@odata.type") or "")
        method_id = method.get("id")
        collection = method_types.get(method_type)
        if not collection or not isinstance(method_id, str) or not method_id:
            raise GraphAPIError("Unsupported or incomplete authentication method")
        self._request("DELETE", f"users/{user_id}/authentication/{collection}/{method_id}")

    def create_temporary_access_pass(self, user_id: str, lifetime_minutes: int, start_date_time: str | None = None, usable_once: bool = True) -> dict:
        from datetime import datetime, timezone
        return self._request("POST", f"users/{user_id}/authentication/temporaryAccessPassMethods", {"startDateTime": start_date_time or datetime.now(timezone.utc).isoformat(), "lifetimeInMinutes": lifetime_minutes, "isUsableOnce": usable_once})

    def automatic_replies(self, user_id: str) -> dict:
        return self.get(f"users/{user_id}/mailboxSettings", {"$select": "automaticRepliesSetting"}).get("automaticRepliesSetting", {})

    def update_automatic_replies(self, user_id: str, setting: dict) -> None:
        self._request("PATCH", f"users/{user_id}/mailboxSettings", {"automaticRepliesSetting": setting})

    def groups(self, user_id: str | None = None) -> list[dict]:
        groups = self.all_pages("groups", {"$select": "id,displayName,description,mail,mailEnabled,securityEnabled,groupTypes"})
        member_ids: set[str] = set()
        if user_id:
            member_ids = {item["id"] for item in self.all_pages(f"users/{user_id}/memberOf/microsoft.graph.group", {"$select": "id"}) if isinstance(item.get("id"), str)}
        return [{**group, "isMember": group.get("id") in member_ids} for group in groups]

    def user_licenses(self, user_id: str) -> list[dict]:
        return self.all_pages(f"users/{user_id}/licenseDetails", {"$select": "skuId,skuPartNumber,servicePlans"})

    def assign_licenses(self, user_id: str, add_licenses: list[dict], remove_sku_ids: list[str]) -> dict:
        return self._request("POST", f"users/{user_id}/assignLicense", {"addLicenses": add_licenses, "removeLicenses": remove_sku_ids})

    def reset_password(self, user_id: str, password: str, force_change: bool = True) -> None:
        self._request("PATCH", f"users/{user_id}", {"passwordProfile": {"password": password, "forceChangePasswordNextSignIn": force_change}})

    def update_license(self, user_id: str, sku_id: str, assign: bool) -> None:
        payload = {"addLicenses": [{"skuId": sku_id, "disabledPlans": []}], "removeLicenses": []} if assign else {"addLicenses": [], "removeLicenses": [sku_id]}
        self._request("POST", f"users/{user_id}/assignLicense", payload)

    def oauth_grants(self) -> list[dict]:
        return self.all_pages("oauth2PermissionGrants", {"$expand": "clientServicePrincipal($select=id,displayName,appId,publisherName)"})

    def create_distribution_list(self, display_name: str, email: str) -> str:
        mail_nickname = "".join(character for character in email.split("@", 1)[0] if character.isalnum() or character in "-_")[:64] or "distribution-list"
        result = self._request("POST", "groups", {"displayName": display_name, "mailEnabled": True, "mailNickname": mail_nickname, "securityEnabled": False, "groupTypes": []})
        graph_id = result.get("id")
        if not graph_id:
            raise GraphAPIError("Microsoft Graph did not return a distribution list id")
        return graph_id

    def compliance_policies(self) -> list[dict]:
        return self.all_pages("deviceManagement/deviceCompliancePolicies")

    def upsert_compliance_policy(self, display_name: str, definition: dict) -> str:
        existing = next((item for item in self.compliance_policies() if item.get("displayName") == display_name), None)
        payload = {"displayName": display_name, **definition}
        if existing:
            self._request("PATCH", f"deviceManagement/deviceCompliancePolicies/{existing['id']}", payload)
            return existing["id"]
        result = self._request("POST", "deviceManagement/deviceCompliancePolicies", payload)
        graph_id = result.get("id")
        if not graph_id:
            raise GraphAPIError("Microsoft Graph did not return a compliance policy id")
        return graph_id

    def remove_user_from_group(self, group_id: str, user_id: str) -> None:
        self._request("DELETE", f"groups/{group_id}/members/{user_id}/$ref")

    def devices(self) -> list[dict]:
        return self.all_pages("deviceManagement/managedDevices", {"$select": "id,deviceName,operatingSystem,complianceState,lastSyncDateTime"})

    def device_action(self, device_id: str, action: str) -> None:
        if action not in {"sync", "retire", "wipe"}:
            raise GraphAPIError("Unsupported device action")
        self._request("POST", f"deviceManagement/managedDevices/{device_id}/{action}")

    def baseline_differences(self, definition: dict):
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
