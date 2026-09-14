from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.graph import GraphClient


class FakeResponse:
    content = b"{}"
    is_error = False
    status_code = 200

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def client_with_token():
    tenant = SimpleNamespace()
    credential = SimpleNamespace(
        encrypted_access_token="encrypted",
        access_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    return GraphClient(tenant, credential)


def test_distribution_list_payload_does_not_try_to_write_graph_mail(monkeypatch):
    captured = {}
    monkeypatch.setattr("app.graph.decrypt_credential", lambda value: "access-token")

    def request(method, url, **kwargs):
        captured.update(method=method, url=url, payload=kwargs["json"])
        return FakeResponse({"id": "graph-group-1"})

    monkeypatch.setattr("app.graph.httpx.request", request)

    result = client_with_token().create_distribution_list("Support", "support@example.test")

    assert result == "graph-group-1"
    assert captured["url"].endswith("/groups")
    assert captured["payload"]["mailEnabled"] is True
    assert "mail" not in captured["payload"]


def test_compliance_policy_update_reuses_existing_graph_policy(monkeypatch):
    calls = []
    client = client_with_token()
    monkeypatch.setattr(client, "compliance_policies", lambda: [{"id": "policy-1", "displayName": "Windows baseline"}])
    monkeypatch.setattr(client, "_request", lambda method, path, payload=None: calls.append((method, path, payload)) or {})

    result = client.upsert_compliance_policy("Windows baseline", {"platforms": ["windows10"]})

    assert result == "policy-1"
    assert calls == [("PATCH", "deviceManagement/deviceCompliancePolicies/policy-1", {"displayName": "Windows baseline", "platforms": ["windows10"]})]


def test_group_member_removal_uses_graph_reference_endpoint(monkeypatch):
    calls = []
    client = client_with_token()
    monkeypatch.setattr(client, "_request", lambda method, path, payload=None: calls.append((method, path)))

    client.remove_user_from_group("group-1", "user-1")

    assert calls == [("DELETE", "groups/group-1/members/user-1/$ref")]
