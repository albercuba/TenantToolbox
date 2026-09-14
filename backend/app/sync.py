from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.graph import GraphAPIError, GraphClient
from app.models import (
    Alert,
    BaselineTemplate,
    ClientTenant,
    DriftEvent,
    TenantBaselineAssignment,
    TenantCredential,
    TenantLicenseSnapshot,
    TenantSecureScoreSnapshot,
    TenantUserSnapshot,
)


def sync_tenant(db: Session, tenant: ClientTenant) -> dict[str, int | str]:
    if not tenant.credential:
        raise GraphAPIError("Tenant has no delegated credential")
    client = GraphClient(tenant, tenant.credential)
    synced_at = datetime.now(timezone.utc)
    users = client.users()
    licenses = client.licenses()
    try:
        score = client.secure_score()
    except GraphAPIError:
        # Secure Score is a premium/optional permission; preserve the useful
        # user and license snapshots when it is unavailable.
        score = None

    db.query(TenantUserSnapshot).filter_by(client_tenant_id=tenant.id).delete()
    db.query(TenantLicenseSnapshot).filter_by(client_tenant_id=tenant.id).delete()
    for user in users:
        db.add(TenantUserSnapshot(client_tenant_id=tenant.id, graph_id=user.get("id", ""), display_name=user.get("displayName", ""), user_principal_name=user.get("userPrincipalName", ""), account_enabled=user.get("accountEnabled"), synced_at=synced_at))
    for license_item in licenses:
        prepaid = license_item.get("prepaidUnits") or {}
        db.add(TenantLicenseSnapshot(client_tenant_id=tenant.id, sku_id=license_item.get("skuId", ""), sku_part_number=license_item.get("skuPartNumber", ""), consumed_units=license_item.get("consumedUnits", 0), enabled_units=prepaid.get("enabled", 0), synced_at=synced_at))
    if score:
        db.add(TenantSecureScoreSnapshot(client_tenant_id=tenant.id, score=score.get("currentScore"), max_score=score.get("maxScore"), control_states=score, synced_at=synced_at))
    tenant.connection_status = "connected"
    tenant.last_connected_at = synced_at
    tenant.last_error = None
    db.commit()
    return {"status": "synced", "users": len(users), "licenses": len(licenses), "secure_score": "updated" if score else "unavailable"}


def sync_connected_tenants(db: Session) -> int:
    tenants = db.scalars(select(ClientTenant).where(ClientTenant.connection_status == "connected")).all()
    synced = 0
    for tenant in tenants:
        try:
            sync_tenant(db, tenant)
            synced += 1
        except GraphAPIError as exc:
            tenant.connection_status = "needs_attention"
            tenant.last_error = str(exc)
            db.commit()
    return synced


def detect_scheduled_drift(db: Session) -> int:
    assignments = db.scalars(select(TenantBaselineAssignment)).all()
    detected = 0
    for assignment in assignments:
        tenant = db.get(ClientTenant, assignment.client_tenant_id)
        baseline = db.get(BaselineTemplate, assignment.baseline_template_id)
        if not tenant or not baseline or not tenant.credential:
            continue
        try:
            differences = GraphClient(tenant, tenant.credential).baseline_differences(baseline.definition)
        except GraphAPIError as exc:
            tenant.connection_status = "needs_attention"
            tenant.last_error = str(exc)
            db.commit()
            continue
        if not differences:
            continue
        existing = db.scalar(select(DriftEvent).where(DriftEvent.client_tenant_id == tenant.id, DriftEvent.baseline_template_id == baseline.id, DriftEvent.resolved_at.is_(None)).order_by(DriftEvent.detected_at.desc()))
        if existing and existing.differences == differences:
            continue
        event = DriftEvent(client_tenant_id=tenant.id, baseline_template_id=baseline.id, differences=differences)
        db.add(event)
        db.flush()
        db.add(Alert(client_tenant_id=tenant.id, drift_event_id=event.id, severity="high", title="Baseline drift detected", message=f"{len(differences)} control(s) differ from {baseline.name}."))
        db.commit()
        detected += 1
    return detected
