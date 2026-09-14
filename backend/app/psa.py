"""Vendor-neutral PSA ticket payload adapters.

Adapters deliberately keep transport in notifications.py so deployments can use
ConnectWise, Autotask, or Halo webhook receivers without vendor SDKs.
"""

from typing import Any


def ticket_payload(vendor: str, *, title: str, description: str, severity: str, tenant_id: str, source: str) -> dict[str, Any]:
    """Build the documented webhook shape for a configured PSA vendor."""
    normalized = vendor.lower().strip()
    if normalized not in {"connectwise", "autotask", "halo", "generic"}:
        raise ValueError("Unsupported PSA vendor")
    common = {
        "title": title,
        "description": description,
        "severity": severity,
        "tenant_id": tenant_id,
        "source": source,
    }
    if normalized == "connectwise":
        return {"vendor": normalized, "summary": title, "initialDescription": description, "priority": severity, "companyIdentifier": tenant_id, "source": source}
    if normalized == "autotask":
        return {"vendor": normalized, "title": title, "description": description, "priority": severity, "companyID": tenant_id, "source": source}
    if normalized == "halo":
        return {"vendor": normalized, "summary": title, "details": description, "priority": severity, "client_id": tenant_id, "source": source}
    return {"vendor": normalized, **common}
