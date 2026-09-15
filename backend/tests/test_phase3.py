from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.graph import GraphClient
from app.notifications import send_psa_webhook
from app.sync import friendly_license_name


class FakeResponse:
    content = b"{}"
    is_error = False
    status_code = 200

    def __init__(self, payload):
        self._payload = payload
        self.content = b"{}"

    def json(self):
        return self._payload


def test_license_sku_names_are_friendly_with_unknown_fallback():
    assert friendly_license_name("DEVELOPERPACK_E5") == "Microsoft 365 E5 Developer"
    assert friendly_license_name("CONTOSO_CUSTOM_PLAN") == "Contoso Custom Plan"


def test_graph_security_alerts_are_paginated(monkeypatch):
    responses = iter([
        FakeResponse({"value": [{"id": "a1", "severity": "high"}], "@odata.nextLink": "next"}),
        FakeResponse({"value": [{"id": "a2", "severity": "critical"}]}),
    ])
    monkeypatch.setattr("app.graph.decrypt_credential", lambda value: "access-token")
    monkeypatch.setattr("app.graph.httpx.request", lambda *args, **kwargs: next(responses))
    tenant = SimpleNamespace()
    credential = SimpleNamespace(encrypted_access_token="encrypted", access_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1))

    alerts = GraphClient(tenant, credential).security_alerts()

    assert [item["id"] for item in alerts] == ["a1", "a2"]


def test_psa_webhook_is_disabled_without_configuration(monkeypatch):
    monkeypatch.setattr("app.notifications.settings", SimpleNamespace(psa_webhook_url=None))

    assert send_psa_webhook({"event": "test"}) is False
