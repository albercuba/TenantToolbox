import pytest

from app.psa import ticket_payload


def test_connectwise_ticket_payload_uses_expected_fields():
    payload = ticket_payload("connectwise", title="Risk", description="Details", severity="high", tenant_id="tenant-1", source="graph")
    assert payload["summary"] == "Risk"
    assert payload["companyIdentifier"] == "tenant-1"
    assert payload["initialDescription"] == "Details"


def test_unknown_psa_vendor_is_rejected():
    with pytest.raises(ValueError):
        ticket_payload("unknown", title="Risk", description="Details", severity="high", tenant_id="tenant-1", source="graph")
