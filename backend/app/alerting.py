from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.graph import GraphAPIError, GraphClient
from app.models import Alert, AlertRule, ClientTenant

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def minimum_severity(db: Session, organization_id: str) -> int:
    rule = db.scalar(select(AlertRule).where(AlertRule.organization_id == organization_id, AlertRule.enabled.is_(True)).order_by(AlertRule.min_severity.desc()))
    return SEVERITY_RANK.get(rule.min_severity, 2) if rule else 2


def ingest_tenant_alerts(db: Session, tenant: ClientTenant) -> int:
    if not tenant.credential:
        raise GraphAPIError("Tenant has no delegated credential")
    events = GraphClient(tenant, tenant.credential).security_alerts()
    created = 0
    threshold = minimum_severity(db, tenant.organization_id)
    for event in events:
        severity = str(event.get("severity", "medium")).lower()
        if SEVERITY_RANK.get(severity, 2) < threshold:
            continue
        external_id = event.get("id")
        if external_id and db.scalar(select(Alert).where(Alert.source == "graph", Alert.external_id == external_id)):
            continue
        db.add(Alert(client_tenant_id=tenant.id, severity=severity, title=event.get("displayName") or event.get("title") or "Microsoft security alert", message=event.get("description") or "Microsoft Graph reported a security alert.", source="graph", external_id=external_id, details=event))
        created += 1
    db.commit()
    return created


def ingest_risky_signins(db: Session, tenant: ClientTenant) -> int:
    if not tenant.credential:
        raise GraphAPIError("Tenant has no delegated credential")
    events = GraphClient(tenant, tenant.credential).risky_sign_ins()
    created = 0
    threshold = minimum_severity(db, tenant.organization_id)
    for event in events:
        risk = str(event.get("riskLevelDuringSignIn") or event.get("riskLevel") or "none").lower()
        if risk in {"none", "low"} or threshold > SEVERITY_RANK["high"]:
            continue
        external_id = event.get("id")
        if external_id and db.scalar(select(Alert).where(Alert.source == "identity_protection", Alert.external_id == external_id)):
            continue
        user = event.get("userPrincipalName") or event.get("userId") or "unknown user"
        db.add(Alert(client_tenant_id=tenant.id, severity="high" if risk == "medium" else "critical", title="Risky sign-in detected", message=f"Identity Protection reported a {risk} risk sign-in for {user}.", source="identity_protection", external_id=external_id, details=event))
        created += 1
    db.commit()
    return created


def suppress_recent_duplicate(db: Session, tenant_id: str, title: str, minutes: int) -> bool:
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    return bool(db.scalar(select(Alert).where(Alert.client_tenant_id == tenant_id, Alert.title == title, Alert.created_at >= since)))
