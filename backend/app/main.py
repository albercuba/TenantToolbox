import csv
import hashlib
import html
import io
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx
from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.db import Base, engine, get_db
from app.models import (Alert, AlertRule, AuditLog, BaselineTemplate, Client, ClientTenant, ComplianceControl, DiscoveredApp, DriftEvent, GdapRelationship,
                        Organization, ProspectAssessment, Report, ReportSchedule, StaffGroup, StaffGroupMembership, StaffUser,
                        TenantBaselineAssignment, TenantCredential, TenantDeviceSnapshot, TenantLicenseSnapshot, TenantSecureScoreSnapshot,
                        TenantUserSnapshot)
from app.alerting import ingest_risky_signins, ingest_tenant_alerts
from app.graph import GraphAPIError, GraphClient
from app.exchange import ExchangeAutomationClient, ExchangeAutomationError
from app.gdap import GdapClient, GdapError
from app.sync import friendly_license_name, sync_tenant
from app.notifications import send_alert_email, send_psa_ticket, send_psa_webhook
from app.rate_limit import RateLimitMiddleware
from app.lifecycle import router as lifecycle_router
from app.security import (create_access_token, create_oauth_state, encrypt_credential, get_current_user,
                          hash_password, require_owner, verify_oauth_state, verify_password)
from app.rbac import require_permission, role_permissions

COMPLIANCE_CONTROLS = {
    "HIPAA": [
        {"control_id": "164.308(a)(3)", "title": "Workforce access management", "baseline_control": "require_mfa"},
        {"control_id": "164.312(a)(1)", "title": "Access control", "baseline_control": "require_mfa"},
        {"control_id": "164.312(e)(1)", "title": "Transmission security", "baseline_control": "block_legacy_auth"},
    ],
    "NIST": [
        {"control_id": "AC-2", "title": "Account Management", "baseline_control": "require_mfa"},
        {"control_id": "IA-2", "title": "Identification and Authentication", "baseline_control": "require_mfa"},
        {"control_id": "SC-8", "title": "Transmission Confidentiality", "baseline_control": "block_legacy_auth"},
    ],
    "CIS": [
        {"control_id": "6.3", "title": "Require MFA for externally exposed applications", "baseline_control": "require_mfa"},
        {"control_id": "3.1", "title": "Establish and maintain a data management process", "baseline_control": "block_legacy_auth"},
    ],
    "CMMC": [
        {"control_id": "IA.L2-3.5.3", "title": "Use multifactor authentication", "baseline_control": "require_mfa"},
        {"control_id": "AC.L2-3.1.16", "title": "Authorize wireless access", "baseline_control": "block_legacy_auth"},
    ],
}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Migrations are the deployment source of truth; this keeps a fresh local checkout usable.
    Base.metadata.create_all(bind=engine)
    with Session(engine) as db:
        if not db.scalar(select(BaselineTemplate)):
            db.add_all([
                BaselineTemplate(name="Basic MFA Enforcement", description="Require strong authentication for staff accounts.", is_builtin=True, definition={"controls": [{"type": "conditional_access", "name": "require_mfa", "target": "all_users", "state": "enabled"}]}),
                BaselineTemplate(name="CIS Level 1 Foundation", description="Foundational identity and session controls aligned to a conservative CIS-style posture.", is_builtin=True, definition={"controls": [{"type": "conditional_access", "name": "require_mfa", "target": "all_users", "state": "enabled"}, {"type": "conditional_access", "name": "block_legacy_auth", "target": "all_users", "state": "enabled"}]}),
            ])
            db.commit()
    yield


app = FastAPI(title="TenantToolbox API", version="0.2.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_url],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware)
app.include_router(lifecycle_router)

# The state is short-lived and process-local for this initial single-instance flow.
_oauth_states: dict[str, str] = {}
_prospect_states: dict[str, str] = {}
_reconnect_states: dict[str, tuple[str, str]] = {}



class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    organization_name: str


class ClientRequest(BaseModel):
    name: str
    description: str = ""


class StaffUserRequest(BaseModel):
    email: EmailStr
    password: str | None = None
    role: str = "technician"


class StaffGroupRequest(BaseModel):
    name: str
    description: str = ""


class TenantResponse(BaseModel):
    id: str
    tenant_id: str
    client_id: str | None = None
    primary_domain: str | None = None
    display_name: str
    connection_status: str
    last_connected_at: datetime | None
    last_error: str | None


class BaselineRequest(BaseModel):
    name: str
    description: str
    definition: dict


class AlertRuleRequest(BaseModel):
    name: str
    min_severity: str = "medium"
    enabled: bool = True
    suppress_minutes: int = 0


class ReportScheduleRequest(BaseModel):
    cadence: str
    recipient_email: EmailStr


class ReportRequest(BaseModel):
    start_date: datetime | None = None
    end_date: datetime | None = None


class BrandingRequest(BaseModel):
    color: str
    logo_url: str | None = None


class ProspectConversionRequest(BaseModel):
    display_name: str | None = None


class GdapRelationshipRequest(BaseModel):
    customer_tenant_id: str
    display_name: str
    duration_days: int = 730
    auto_extend_days: int = 180
    role_definition_ids: list[str] = Field(default_factory=list)
    security_group_id: str | None = None


class GdapCustomerImportRequest(BaseModel):
    customer_tenant_id: str
    display_name: str
    client_id: str | None = None


class UserActionRequest(BaseModel):
    tenant_id: str
    user_id: str
    action: str
    confirm: bool = False
    password: str | None = None
    sku_id: str | None = None
    action_data: dict = Field(default_factory=dict)



def write_audit(db: Session, user: StaffUser, action: str, tenant_id: str | None = None, payload: dict | None = None) -> None:
    db.add(AuditLog(organization_id=user.organization_id, actor_id=user.id, client_tenant_id=tenant_id, action=action, target_type="client_tenant" if tenant_id else None, target_id=tenant_id, payload=payload or {}))


@app.get("/api/audit-log")
def audit_log(user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    entries = db.scalars(select(AuditLog).where(AuditLog.organization_id == user.organization_id).order_by(AuditLog.created_at.desc()).limit(100)).all()
    return [{"id": item.id, "action": item.action, "tenant_id": item.client_tenant_id, "actor_id": item.actor_id, "payload": item.payload, "created_at": item.created_at} for item in entries]

def app_risk_score(scopes: list[str]) -> int:
    normalized = {scope.lower() for scope in scopes}
    score = len(normalized)
    if any("mail" in scope or "files" in scope for scope in normalized): score += 3
    if any("write" in scope or "full_access" in scope for scope in normalized): score += 4
    return min(score, 10)


@app.post("/api/tenants/{tenant_id}/discover/sync")
def sync_discovered_apps(tenant_id: str, user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> dict[str, int]:
    tenant = ensure_tenant_access(tenant_id, user, db)
    if not tenant.credential:
        raise HTTPException(status_code=409, detail="Tenant has no delegated credential")
    try:
        grants = GraphClient(tenant, tenant.credential).oauth_grants()
    except GraphAPIError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    db.query(DiscoveredApp).filter_by(client_tenant_id=tenant.id).delete()
    now = datetime.now(timezone.utc)
    for grant in grants:
        principal = grant.get("clientServicePrincipal") or {}
        scopes = [scope for scope in (grant.get("scope") or "").split() if scope]
        db.add(DiscoveredApp(client_tenant_id=tenant.id, graph_id=principal.get("id") or grant.get("clientId", ""), display_name=principal.get("displayName") or "Unknown application", publisher=principal.get("publisherName"), permission_scopes=scopes, risk_score=app_risk_score(scopes), last_seen_at=now))
    write_audit(db, user, "discover.sync", tenant.id, {"count": len(grants)})
    db.commit()
    return {"synced": len(grants)}


@app.get("/api/tenants/{tenant_id}/discover/apps")
def discovered_apps(tenant_id: str, user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    ensure_tenant_access(tenant_id, user, db)
    return [{"id": item.graph_id, "display_name": item.display_name, "publisher": item.publisher, "permission_scopes": item.permission_scopes, "risk_score": item.risk_score, "last_seen_at": item.last_seen_at} for item in db.scalars(select(DiscoveredApp).where(DiscoveredApp.client_tenant_id == tenant_id).order_by(DiscoveredApp.risk_score.desc(), DiscoveredApp.display_name)).all()]


@app.post("/api/tenants/{tenant_id}/devices/sync")
def sync_devices(tenant_id: str, user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> dict[str, int]:
    tenant = ensure_tenant_access(tenant_id, user, db)
    if not tenant.credential:
        raise HTTPException(status_code=409, detail="Tenant has no delegated credential")
    try:
        devices = GraphClient(tenant, tenant.credential).devices()
    except GraphAPIError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    now = datetime.now(timezone.utc)
    db.query(TenantDeviceSnapshot).filter_by(client_tenant_id=tenant.id).delete()
    for device in devices:
        db.add(TenantDeviceSnapshot(client_tenant_id=tenant.id, graph_id=device.get("id", ""), device_name=device.get("deviceName", ""), operating_system=device.get("operatingSystem"), compliance_state=device.get("complianceState"), last_sync_at=datetime.fromisoformat(device["lastSyncDateTime"].replace("Z", "+00:00")) if device.get("lastSyncDateTime") else None, synced_at=now))
    write_audit(db, user, "device.sync", tenant.id, {"count": len(devices)})
    db.commit()
    return {"synced": len(devices)}


@app.get("/api/tenants/{tenant_id}/devices")
def list_devices(tenant_id: str, user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    ensure_tenant_access(tenant_id, user, db)
    return [{"id": item.graph_id, "device_name": item.device_name, "operating_system": item.operating_system, "compliance_state": item.compliance_state, "last_sync_at": item.last_sync_at} for item in db.scalars(select(TenantDeviceSnapshot).where(TenantDeviceSnapshot.client_tenant_id == tenant_id).order_by(TenantDeviceSnapshot.device_name)).all()]


@app.post("/api/tenants/{tenant_id}/devices/{device_id}/action")
def device_action(tenant_id: str, device_id: str, action: str = Query(...), confirm: bool = Query(False), user: StaffUser = Depends(require_permission("operate")), db: Session = Depends(get_db)) -> dict[str, str]:
    if not confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to execute this action")
    tenant = ensure_tenant_access(tenant_id, user, db)
    if not tenant.credential:
        raise HTTPException(status_code=409, detail="Tenant has no delegated credential")
    try:
        GraphClient(tenant, tenant.credential).device_action(device_id, action)
    except GraphAPIError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    write_audit(db, user, f"device.{action}", tenant.id, {"device_id": device_id})
    db.commit()
    return {"status": "completed", "action": action}


@app.get("/api/gdap/customers")
def gdap_customers(user: StaffUser = Depends(get_current_user)) -> list[dict]:
    try:
        return GdapClient().customers()
    except GdapError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/gdap/customers/import", status_code=status.HTTP_201_CREATED)
def import_gdap_customer(payload: GdapCustomerImportRequest, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict:
    tenant_id = payload.customer_tenant_id.strip()
    display_name = payload.display_name.strip() or tenant_id
    if not tenant_id:
        raise HTTPException(status_code=400, detail="Customer tenant ID is required")
    client = None
    if payload.client_id:
        client = db.scalar(select(Client).where(Client.id == payload.client_id, Client.organization_id == user.organization_id))
        if not client:
            raise HTTPException(status_code=404, detail="Client not found")
    existing = db.scalar(select(ClientTenant).where(ClientTenant.tenant_id == tenant_id))
    if existing:
        if existing.organization_id != user.organization_id:
            raise HTTPException(status_code=409, detail="A tenant ID belongs to another organization")
        if client and existing.client_id and existing.client_id != client.id:
            raise HTTPException(status_code=409, detail="Tenant is already assigned to another client")
        if client:
            existing.client_id = client.id
        existing.display_name = display_name
        tenant = existing
        created = False
    else:
        tenant = ClientTenant(organization_id=user.organization_id, client_id=client.id if client else None, tenant_id=tenant_id, display_name=display_name, connection_status="pending")
        db.add(tenant)
        db.flush()
        created = True
    write_audit(db, user, "gdap.customer.import", tenant.id, {"customer_tenant_id": tenant_id, "client_id": client.id if client else None, "created": created})
    db.commit()
    return {"id": tenant.id, "tenant_id": tenant.tenant_id, "display_name": tenant.display_name, "client_id": tenant.client_id, "created": created}


@app.get("/api/gdap/relationships")
def gdap_relationships(customer_tenant_id: str | None = Query(default=None), user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    try:
        relationships = GdapClient().relationships(customer_tenant_id)
    except GdapError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    local = {item.customer_tenant_id: item for item in db.scalars(select(GdapRelationship).where(GdapRelationship.organization_id == user.organization_id)).all()}
    normalized = []
    for item in relationships:
        customer = item.get("customer") or {}
        tenant_id = customer.get("tenantId") or item.get("customerTenantId")
        local_relationship = local.get(tenant_id) if tenant_id else None
        normalized.append({**item, "customerTenantId": tenant_id, "relationshipStatus": item.get("status") or item.get("relationshipStatus") or "unknown", "localId": local_relationship.id if local_relationship else None, "approvalUrl": item.get("approvalUrl") or item.get("approvalUrlWithConsent")})
    return normalized


@app.post("/api/gdap/relationships")
def create_gdap_relationship(payload: GdapRelationshipRequest, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict:
    client_tenant = db.scalar(select(ClientTenant).where(ClientTenant.tenant_id == payload.customer_tenant_id, ClientTenant.organization_id == user.organization_id))
    try:
        result = GdapClient().create_relationship(payload.customer_tenant_id, payload.display_name.strip(), payload.duration_days, payload.auto_extend_days, payload.role_definition_ids, payload.security_group_id)
    except GdapError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    relationship = GdapRelationship(organization_id=user.organization_id, client_tenant_id=client_tenant.id if client_tenant else None, customer_tenant_id=payload.customer_tenant_id, graph_id=result.get("id"), display_name=payload.display_name.strip(), status=result.get("status", "pending"), approval_url=result.get("approvalUrl") or result.get("approvalUrlWithConsent"), details=result)
    db.add(relationship)
    write_audit(db, user, "gdap.relationship.create", client_tenant.id if client_tenant else None, {"customer_tenant_id": payload.customer_tenant_id, "relationship_id": relationship.id, "role_definition_ids": payload.role_definition_ids})
    db.commit()
    return {"id": relationship.id, "graph_id": relationship.graph_id, "status": relationship.status, "approval_url": relationship.approval_url, "details": relationship.details}


@app.get("/api/users/search")
def search_users(query: str = Query(default=""), user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    statement = select(TenantUserSnapshot, ClientTenant).join(ClientTenant, TenantUserSnapshot.client_tenant_id == ClientTenant.id).where(ClientTenant.organization_id == user.organization_id)
    if query.strip():
        pattern = f"%{query.lower()}%"
        statement = statement.where(TenantUserSnapshot.display_name.ilike(pattern) | TenantUserSnapshot.user_principal_name.ilike(pattern))
    rows = db.execute(statement.order_by(ClientTenant.display_name, TenantUserSnapshot.display_name)).all()
    return [{"tenant_id": tenant.id, "tenant_name": tenant.display_name, "user_id": item.graph_id, "display_name": item.display_name, "user_principal_name": item.user_principal_name, "account_enabled": item.account_enabled, "license_types": [friendly_license_name(value) for value in (item.license_types or [])], "department": item.department or "", "groups": item.groups or [], "mfa_settings": item.mfa_settings} for item, tenant in rows]


@app.get("/api/users/global-address-list")
def global_address_list_status(tenant_id: str, user_id: str, user: StaffUser = Depends(require_permission("operate")), db: Session = Depends(get_db)) -> dict:
    tenant = ensure_tenant_access(tenant_id, user, db)
    if not tenant.credential:
        raise HTTPException(status_code=409, detail="Tenant has no delegated credential")
    if not (tenant.primary_domain or "").lower().endswith(".onmicrosoft.com"):
        raise HTTPException(status_code=409, detail="Tenant needs a verified .onmicrosoft.com domain; run Sync now before using Exchange actions")
    try:
        return ExchangeAutomationClient().global_address_list_status(tenant.tenant_id, user_id, tenant.primary_domain)
    except ExchangeAutomationError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/api/users/action")
def user_action(payload: UserActionRequest, user: StaffUser = Depends(require_permission("operate")), db: Session = Depends(get_db)) -> dict[str, str]:
    if not payload.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to execute this action")
    tenant = ensure_tenant_access(payload.tenant_id, user, db)
    if not tenant.credential or payload.action not in {"block", "unblock", "reset_password", "assign_license", "remove_license", "revoke_sessions", "register_mfa", "create_tap", "out_of_office", "m365_groups", "security_groups", "distribution_groups", "licenses", "global_address_list", "email_forwarding", "shared_mailboxes"}:
        raise HTTPException(status_code=409, detail="Unsupported user action or unavailable tenant credential")
    if payload.action == "reset_password" and (not payload.password or len(payload.password) < 12):
        raise HTTPException(status_code=400, detail="A password of at least 12 characters is required")
    if payload.action in {"assign_license", "remove_license"} and not payload.sku_id:
        raise HTTPException(status_code=400, detail="sku_id is required for license actions")
    exchange_actions = {"global_address_list", "email_forwarding", "shared_mailboxes"}
    if payload.action in exchange_actions and not (tenant.primary_domain or "").lower().endswith(".onmicrosoft.com"):
        raise HTTPException(status_code=409, detail="Tenant needs a verified .onmicrosoft.com domain; run Sync now before using Exchange actions")
    client = GraphClient(tenant, tenant.credential)
    result: dict = {}
    try:
        if payload.action == "block": client.set_user_enabled(payload.user_id, False)
        elif payload.action == "unblock": client.set_user_enabled(payload.user_id, True)
        elif payload.action == "reset_password": client.reset_password(payload.user_id, payload.password or "")
        elif payload.action == "assign_license": client.update_license(payload.user_id, payload.sku_id or "", True)
        elif payload.action == "remove_license": client.update_license(payload.user_id, payload.sku_id or "", False)
        elif payload.action == "register_mfa":
            methods = payload.action_data.get("methods") or client.user_mfa_methods(payload.user_id)
            for method in methods: client.clear_authentication_method(payload.user_id, method)
        elif payload.action == "create_tap":
            lifetime = max(10, min(int(payload.action_data.get("lifetime_minutes", 60)), 480))
            result = client.create_temporary_access_pass(payload.user_id, lifetime, payload.action_data.get("start_date_time"), bool(payload.action_data.get("usable_once", True)))
        elif payload.action == "out_of_office":
            client.update_automatic_replies(payload.user_id, payload.action_data.get("automatic_replies_setting") or {"status": "disabled"})
        elif payload.action in {"m365_groups", "security_groups", "distribution_groups"}:
            for group_id in payload.action_data.get("remove_group_ids", []): client.remove_user_from_group(group_id, payload.user_id)
            for group_id in payload.action_data.get("add_group_ids", []): client.add_user_to_group(group_id, payload.user_id)
        elif payload.action == "licenses":
            result = client.assign_licenses(payload.user_id, payload.action_data.get("add_licenses", []), payload.action_data.get("remove_sku_ids", []))
        elif payload.action == "global_address_list":
            exchange_organization = tenant.primary_domain
            result = ExchangeAutomationClient().hide_from_global_address_list(tenant.tenant_id, payload.user_id, bool(payload.action_data.get("hidden", True)), exchange_organization)
        elif payload.action == "email_forwarding":
            result = ExchangeAutomationClient().set_forwarding(tenant.tenant_id, payload.user_id, payload.action_data.get("recipient"), bool(payload.action_data.get("keep_copy", True)), tenant.primary_domain)
        elif payload.action == "shared_mailboxes":
            result = ExchangeAutomationClient().set_shared_mailbox_permissions(tenant.tenant_id, payload.user_id, payload.action_data.get("permissions", []), tenant.primary_domain)
        else: client.revoke_sessions(payload.user_id)
    except (GraphAPIError, ExchangeAutomationError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    write_audit(db, user, f"user.{payload.action}", tenant.id, {"user_id": payload.user_id, "action_data": payload.action_data, "execution": "powershell" if payload.action in exchange_actions else "graph"})
    db.commit()
    response = {"status": "completed", "action": payload.action}
    if payload.action == "create_tap": response["temporary_access_pass"] = result.get("temporaryAccessPass", "")
    return response



@app.post("/api/users/offboard")
def offboard_user(payload: UserActionRequest, user: StaffUser = Depends(require_permission("manage")), db: Session = Depends(get_db)) -> dict[str, list[str]]:
    if not payload.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to execute offboarding")
    tenant = ensure_tenant_access(payload.tenant_id, user, db)
    if not tenant.credential:
        raise HTTPException(status_code=409, detail="Tenant has no delegated credential")
    client = GraphClient(tenant, tenant.credential)
    completed: list[str] = []
    try:
        client.revoke_sessions(payload.user_id); completed.append("revoke_sessions")
        client.disable_user(payload.user_id); completed.append("disable_account")
    except GraphAPIError as exc:
        raise HTTPException(status_code=502, detail={"completed": completed, "error": str(exc)}) from exc
    write_audit(db, user, "user.offboard", tenant.id, {"user_id": payload.user_id, "completed": completed})
    db.commit()
    return {"completed": completed, "remaining": ["remove_licenses", "convert_mailbox", "remove_groups"]}


@app.get("/api/compliance/frameworks")
def compliance_frameworks(user: StaffUser = Depends(get_current_user)) -> dict[str, int]:
    return {name: len(controls) for name, controls in COMPLIANCE_CONTROLS.items()}


@app.get("/api/tenants/{tenant_id}/compliance/{framework}")
def compliance_coverage(tenant_id: str, framework: str, user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    ensure_tenant_access(tenant_id, user, db)
    controls = COMPLIANCE_CONTROLS.get(framework.upper())
    if controls is None:
        raise HTTPException(status_code=404, detail="Framework not found")
    assignments = db.scalars(select(TenantBaselineAssignment).where(TenantBaselineAssignment.client_tenant_id == tenant_id)).all()
    assigned_names = set()
    for assignment in assignments:
        baseline = db.get(BaselineTemplate, assignment.baseline_template_id)
        if baseline:
            assigned_names.update(control.get("name") for control in baseline.definition.get("controls", []))
    satisfied = [control for control in controls if control["baseline_control"] in assigned_names]
    return {"framework": framework.upper(), "satisfied": len(satisfied), "total": len(controls), "percentage": round(len(satisfied) / len(controls) * 100) if controls else 0, "controls": [{**control, "satisfied": control in satisfied} for control in controls]}


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "tenanttoolbox-api"}


@app.get("/api/audit-log/export")
def export_audit_log(user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> StreamingResponse:
    entries = db.scalars(select(AuditLog).where(AuditLog.organization_id == user.organization_id).order_by(AuditLog.created_at.desc())).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["created_at", "action", "actor_id", "tenant_id", "payload"])
    for item in entries:
        writer.writerow([item.created_at.isoformat(), item.action, item.actor_id or "", item.client_tenant_id or "", item.payload])
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=tenanttoolbox-audit.csv"})


@app.post("/api/tenants/{tenant_id}/reports", status_code=status.HTTP_201_CREATED)
def generate_report(tenant_id: str, payload: ReportRequest | None = None, user: StaffUser = Depends(require_permission("operate")), db: Session = Depends(get_db)) -> dict[str, str]:
    tenant = ensure_tenant_access(tenant_id, user, db)
    payload = payload or ReportRequest()
    if payload.start_date and payload.end_date and payload.start_date > payload.end_date:
        raise HTTPException(status_code=400, detail="start_date must be before end_date")
    alert_query = select(Alert).where(Alert.client_tenant_id == tenant.id)
    if payload.start_date:
        alert_query = alert_query.where(Alert.created_at >= payload.start_date)
    if payload.end_date:
        alert_query = alert_query.where(Alert.created_at <= payload.end_date)
    alerts = db.scalars(alert_query.order_by(Alert.created_at.desc()).limit(100)).all()
    assignments = db.scalars(select(TenantBaselineAssignment).where(TenantBaselineAssignment.client_tenant_id == tenant.id)).all()
    organization = db.get(Organization, user.organization_id)
    generated = datetime.now(timezone.utc)
    period = f"{payload.start_date.date().isoformat() if payload.start_date else 'all time'} to {payload.end_date.date().isoformat() if payload.end_date else generated.date().isoformat()}"
    logo = f'<img src="{html.escape(organization.branding_logo_url)}" alt="Organization logo" />' if organization and organization.branding_logo_url else ""
    color = organization.branding_color if organization else "#2490ef"
    content = f'<article style="--brand-color:{html.escape(color)}">{logo}<h1>{html.escape(tenant.display_name)} security report</h1><p>Reporting period: {html.escape(period)}</p><p>Generated {generated.isoformat()}</p><h2>Assigned baselines</h2><p>{len(assignments)}</p><h2>Alerts</h2><ul>{"".join(f"<li>{html.escape(item.title)} ({html.escape(item.severity)})</li>" for item in alerts) or "<li>No alerts</li>"}</ul></article>'
    report = Report(organization_id=user.organization_id, client_tenant_id=tenant.id, report_type="security_posture", title=f"{tenant.display_name} security report", content=content, created_by=user.id)
    db.add(report)
    db.flush()
    write_audit(db, user, "report.generate", tenant.id, {"report_id": report.id})
    db.commit()
    return {"id": report.id, "title": report.title, "format": "html"}


@app.get("/api/reports/{report_id}", response_class=HTMLResponse)
def get_report(report_id: str, user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> str:
    report = db.get(Report, report_id)
    if not report or report.organization_id != user.organization_id:
        raise HTTPException(status_code=404, detail="Report not found")
    return report.content


@app.post("/api/reports/{report_id}/public-link")
def publish_report(report_id: str, user: StaffUser = Depends(require_permission("manage")), db: Session = Depends(get_db)) -> dict[str, str]:
    report = db.get(Report, report_id)
    if not report or report.organization_id != user.organization_id:
        raise HTTPException(status_code=404, detail="Report not found")
    raw_token = secrets.token_urlsafe(32)
    report.public_token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    report.public_expires_at = datetime.now(timezone.utc) + timedelta(days=30)
    db.commit()
    return {"url": f"/api/public/reports/{raw_token}", "expires_at": report.public_expires_at.isoformat()}


@app.get("/api/public/reports/{token}", response_class=HTMLResponse)
def public_report(token: str, db: Session = Depends(get_db)) -> str:
    report = db.scalar(select(Report).where(Report.public_token_hash == hashlib.sha256(token.encode()).hexdigest()))
    if not report or not report.public_expires_at or report.public_expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=404, detail="Report not found")
    return report.content


@app.get("/api/reports/{report_id}/pdf")
def get_report_pdf(report_id: str, user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> StreamingResponse:
    report = db.get(Report, report_id)
    if not report or report.organization_id != user.organization_id:
        raise HTTPException(status_code=404, detail="Report not found")
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    pdf.setTitle(report.title)
    y = 750
    for line in [report.title, "", f"Generated: {report.created_at.isoformat()}", "", "This report is generated from TenantToolbox security snapshots."]:
        pdf.drawString(54, y, line[:110])
        y -= 18
    pdf.save()
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename={report.id}.pdf"})


@app.post("/api/tenants/{tenant_id}/report-schedules", status_code=status.HTTP_201_CREATED)
def create_report_schedule(tenant_id: str, payload: ReportScheduleRequest, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict:
    if payload.cadence not in {"weekly", "monthly", "quarterly"}:
        raise HTTPException(status_code=400, detail="Cadence must be weekly, monthly, or quarterly")
    tenant = ensure_tenant_access(tenant_id, user, db)
    schedule = ReportSchedule(organization_id=user.organization_id, client_tenant_id=tenant.id, cadence=payload.cadence, recipient_email=str(payload.recipient_email), next_run_at=datetime.now(timezone.utc))
    db.add(schedule)
    db.flush()
    write_audit(db, user, "report_schedule.create", tenant.id, {"schedule_id": schedule.id})
    db.commit()
    return {"id": schedule.id, "tenant_id": tenant.id, "cadence": schedule.cadence, "recipient_email": schedule.recipient_email, "enabled": schedule.enabled}


@app.get("/api/report-schedules")
def list_report_schedules(user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    return [{"id": item.id, "tenant_id": item.client_tenant_id, "cadence": item.cadence, "recipient_email": item.recipient_email, "enabled": item.enabled, "next_run_at": item.next_run_at} for item in db.scalars(select(ReportSchedule).where(ReportSchedule.organization_id == user.organization_id)).all()]


def create_owner(payload: SignupRequest, db: Session) -> dict[str, str]:
    if len(payload.password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters")
    if not payload.organization_name.strip():
        raise HTTPException(status_code=400, detail="Organization name is required")
    if db.scalar(select(StaffUser)):
        raise HTTPException(status_code=409, detail="Initial setup has already been completed")
    organization = Organization(name=payload.organization_name.strip())
    user = StaffUser(email=payload.email.lower(), password_hash=hash_password(payload.password), role="owner", organization=organization)
    organization.staff_groups = [
        StaffGroup(name="Administrator", description="Staff with administrative operational permissions."),
        StaffGroup(name="Technician", description="Staff with day-to-day tenant operational permissions."),
    ]
    db.add(user)
    db.commit()
    db.refresh(user)
    write_audit(db, user, "staff.setup")
    db.commit()
    return {"access_token": create_access_token(user), "token_type": "bearer", "role": user.role}


@app.get("/api/setup/status")
def setup_status(db: Session = Depends(get_db)) -> dict[str, bool]:
    return {"setup_required": db.scalar(select(StaffUser)) is None}


@app.post("/api/setup", status_code=status.HTTP_201_CREATED)
def setup(payload: SignupRequest, db: Session = Depends(get_db)) -> dict[str, str]:
    return create_owner(payload, db)


@app.post("/api/auth/signup", status_code=status.HTTP_201_CREATED)
def signup(payload: SignupRequest, db: Session = Depends(get_db)) -> dict[str, str]:
    # Keep the legacy endpoint safe: it can only initialize an empty deployment.
    return create_owner(payload, db)


@app.post("/api/auth/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)) -> dict[str, str]:
    user = db.scalar(select(StaffUser).where(StaffUser.email == form.username.lower()))
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password", headers={"WWW-Authenticate": "Bearer"})
    return {"access_token": create_access_token(user), "token_type": "bearer", "role": user.role}


@app.get("/api/auth/me")
def me(user: StaffUser = Depends(get_current_user)) -> dict:
    return {"id": user.id, "email": user.email, "role": user.role, "organization_id": user.organization_id, "permissions": role_permissions(user)}


@app.get("/api/auth/permissions")
def permissions(user: StaffUser = Depends(get_current_user)) -> dict[str, bool]:
    return role_permissions(user)


def client_to_response(client: Client, db: Session | None = None) -> dict:
    response = {"id": client.id, "name": client.name, "description": client.description, "created_at": client.created_at}
    if db is not None:
        response["tenants"] = [
            {
                "id": tenant.id,
                "name": tenant.display_name,
                "domain": tenant.primary_domain or tenant.tenant_id,
                "tenant_id": tenant.tenant_id,
                "status": "Connected" if tenant.connection_status == "connected" else "Needs attention",
                "connection_status": tenant.connection_status,
                "last_connected_at": tenant.last_connected_at,
                "last_error": tenant.last_error,
            }
            for tenant in db.scalars(
                select(ClientTenant)
                .where(ClientTenant.client_id == client.id)
                .order_by(ClientTenant.display_name)
            ).all()
        ]
    return response


@app.post("/api/clients", status_code=status.HTTP_201_CREATED)
def create_client(payload: ClientRequest, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Client name is required")
    if db.scalar(select(Client).where(Client.organization_id == user.organization_id, Client.name == name)):
        raise HTTPException(status_code=409, detail="Client name already exists")
    client = Client(organization_id=user.organization_id, name=name, description=payload.description.strip())
    db.add(client)
    db.flush()
    write_audit(db, user, "client.create", payload={"client_id": client.id})
    db.commit()
    return client_to_response(client)


@app.get("/api/clients")
def list_clients(user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    return [client_to_response(item, db) for item in db.scalars(select(Client).where(Client.organization_id == user.organization_id).order_by(Client.name)).all()]


@app.put("/api/clients/{client_id}")
def update_client(client_id: str, payload: ClientRequest, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict:
    client = db.scalar(select(Client).where(Client.id == client_id, Client.organization_id == user.organization_id))
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Client name is required")
    duplicate = db.scalar(select(Client).where(Client.organization_id == user.organization_id, Client.name == name, Client.id != client.id))
    if duplicate:
        raise HTTPException(status_code=409, detail="Client name already exists")
    client.name = name
    client.description = payload.description.strip()
    write_audit(db, user, "client.update", payload={"client_id": client.id})
    db.commit()
    return client_to_response(client)


@app.delete("/api/clients/{client_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_client(client_id: str, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> None:
    client = db.scalar(select(Client).where(Client.id == client_id, Client.organization_id == user.organization_id))
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    if db.scalar(select(ClientTenant).where(ClientTenant.client_id == client.id)):
        raise HTTPException(status_code=409, detail="Cannot delete a client with assigned tenants")
    write_audit(db, user, "client.delete", payload={"client_id": client.id})
    db.delete(client)
    db.commit()


def staff_to_response(staff: StaffUser, db: Session) -> dict:
    memberships = db.scalars(select(StaffGroup).join(StaffGroupMembership, StaffGroupMembership.staff_group_id == StaffGroup.id).where(StaffGroupMembership.staff_user_id == staff.id)).all()
    return {"id": staff.id, "email": staff.email, "role": staff.role, "organization_id": staff.organization_id, "groups": [{"id": group.id, "name": group.name} for group in memberships]}


@app.get("/api/staff/users")
def list_staff_users(user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> list[dict]:
    return [staff_to_response(item, db) for item in db.scalars(select(StaffUser).where(StaffUser.organization_id == user.organization_id).order_by(StaffUser.email)).all()]


@app.post("/api/staff/users", status_code=status.HTTP_201_CREATED)
def create_staff_user(payload: StaffUserRequest, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict:
    role = payload.role.lower()
    if role not in {"owner", "administrator", "technician", "l1", "l2", "l3"}:
        raise HTTPException(status_code=400, detail="Invalid staff role")
    if not payload.password or len(payload.password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters")
    email = str(payload.email).lower()
    if db.scalar(select(StaffUser).where(StaffUser.email == email)):
        raise HTTPException(status_code=409, detail="Email is already in use")
    staff = StaffUser(organization_id=user.organization_id, email=email, password_hash=hash_password(payload.password), role=role)
    db.add(staff)
    db.flush()
    write_audit(db, user, "staff.create", payload={"staff_id": staff.id, "role": role})
    db.commit()
    return staff_to_response(staff, db)


@app.put("/api/staff/users/{staff_id}")
def update_staff_user(staff_id: str, payload: StaffUserRequest, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict:
    staff = db.scalar(select(StaffUser).where(StaffUser.id == staff_id, StaffUser.organization_id == user.organization_id))
    if not staff:
        raise HTTPException(status_code=404, detail="Staff user not found")
    role = payload.role.lower()
    if role not in {"owner", "administrator", "technician", "l1", "l2", "l3"}:
        raise HTTPException(status_code=400, detail="Invalid staff role")
    if staff.role == "owner" and role != "owner" and db.scalar(select(StaffUser).where(StaffUser.organization_id == user.organization_id, StaffUser.role == "owner", StaffUser.id != staff.id)) is None:
        raise HTTPException(status_code=409, detail="Cannot remove the last owner")
    email = str(payload.email).lower()
    if db.scalar(select(StaffUser).where(StaffUser.email == email, StaffUser.id != staff.id)):
        raise HTTPException(status_code=409, detail="Email is already in use")
    staff.email = email
    staff.role = role
    if payload.password is not None:
        if len(payload.password) < 12:
            raise HTTPException(status_code=400, detail="Password must be at least 12 characters")
        staff.password_hash = hash_password(payload.password)
    write_audit(db, user, "staff.update", payload={"staff_id": staff.id, "role": role})
    db.commit()
    return staff_to_response(staff, db)


@app.delete("/api/staff/users/{staff_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_staff_user(staff_id: str, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> None:
    staff = db.scalar(select(StaffUser).where(StaffUser.id == staff_id, StaffUser.organization_id == user.organization_id))
    if not staff:
        raise HTTPException(status_code=404, detail="Staff user not found")
    if staff.role == "owner" and db.scalar(select(StaffUser).where(StaffUser.organization_id == user.organization_id, StaffUser.role == "owner", StaffUser.id != staff.id)) is None:
        raise HTTPException(status_code=409, detail="Cannot remove the last owner")
    write_audit(db, user, "staff.delete", payload={"staff_id": staff.id})
    db.delete(staff)
    db.commit()


@app.get("/api/groups")
def list_staff_groups(user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    groups = db.scalars(select(StaffGroup).where(StaffGroup.organization_id == user.organization_id).order_by(StaffGroup.name)).all()
    return [{"id": group.id, "name": group.name, "description": group.description} for group in groups]


@app.post("/api/groups", status_code=status.HTTP_201_CREATED)
def create_staff_group(payload: StaffGroupRequest, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Group name is required")
    if db.scalar(select(StaffGroup).where(StaffGroup.organization_id == user.organization_id, StaffGroup.name == name)):
        raise HTTPException(status_code=409, detail="Group name already exists")
    group = StaffGroup(organization_id=user.organization_id, name=name, description=payload.description.strip())
    db.add(group)
    db.flush()
    write_audit(db, user, "staff_group.create", payload={"group_id": group.id})
    db.commit()
    return {"id": group.id, "name": group.name, "description": group.description}


@app.put("/api/groups/{group_id}")
def update_staff_group(group_id: str, payload: StaffGroupRequest, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict:
    group = db.scalar(select(StaffGroup).where(StaffGroup.id == group_id, StaffGroup.organization_id == user.organization_id))
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Group name is required")
    if db.scalar(select(StaffGroup).where(StaffGroup.organization_id == user.organization_id, StaffGroup.name == name, StaffGroup.id != group.id)):
        raise HTTPException(status_code=409, detail="Group name already exists")
    group.name, group.description = name, payload.description.strip()
    write_audit(db, user, "staff_group.update", payload={"group_id": group.id})
    db.commit()
    return {"id": group.id, "name": group.name, "description": group.description}


@app.delete("/api/groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_staff_group(group_id: str, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> None:
    group = db.scalar(select(StaffGroup).where(StaffGroup.id == group_id, StaffGroup.organization_id == user.organization_id))
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    write_audit(db, user, "staff_group.delete", payload={"group_id": group.id})
    db.delete(group)
    db.commit()


@app.put("/api/groups/{group_id}/members/{staff_id}", status_code=status.HTTP_204_NO_CONTENT)
def assign_staff_group(group_id: str, staff_id: str, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> None:
    group = db.scalar(select(StaffGroup).where(StaffGroup.id == group_id, StaffGroup.organization_id == user.organization_id))
    staff = db.scalar(select(StaffUser).where(StaffUser.id == staff_id, StaffUser.organization_id == user.organization_id))
    if not group or not staff:
        raise HTTPException(status_code=404, detail="Group or staff user not found")
    if not db.scalar(select(StaffGroupMembership).where(StaffGroupMembership.staff_group_id == group.id, StaffGroupMembership.staff_user_id == staff.id)):
        db.add(StaffGroupMembership(staff_group_id=group.id, staff_user_id=staff.id, assigned_by=user.id))
        write_audit(db, user, "staff_group.assign", payload={"group_id": group.id, "staff_id": staff.id})
        db.commit()


@app.delete("/api/groups/{group_id}/members/{staff_id}", status_code=status.HTTP_204_NO_CONTENT)
def unassign_staff_group(group_id: str, staff_id: str, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> None:
    group = db.scalar(select(StaffGroup).where(StaffGroup.id == group_id, StaffGroup.organization_id == user.organization_id))
    membership = db.scalar(select(StaffGroupMembership).where(StaffGroupMembership.staff_group_id == group_id, StaffGroupMembership.staff_user_id == staff_id))
    if not group or not membership:
        raise HTTPException(status_code=404, detail="Group membership not found")
    db.delete(membership)
    write_audit(db, user, "staff_group.unassign", payload={"group_id": group.id, "staff_id": staff_id})
    db.commit()


@app.put("/api/organization/branding")
def update_branding(payload: BrandingRequest, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict[str, str | None]:
    color = payload.color.strip()
    if not color.startswith("#") or len(color) not in {4, 7}:
        raise HTTPException(status_code=400, detail="Branding color must be a short or full hexadecimal color")
    organization = db.get(Organization, user.organization_id)
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")
    organization.branding_color = color
    organization.branding_logo_url = payload.logo_url.strip() if payload.logo_url else None
    db.commit()
    return {"color": organization.branding_color, "logo_url": organization.branding_logo_url}


@app.get("/api/auth/microsoft/start")
def microsoft_start(client_id: str | None = Query(default=None), user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> dict[str, str]:
    if client_id and not db.scalar(select(Client).where(Client.id == client_id, Client.organization_id == user.organization_id)):
        raise HTTPException(status_code=404, detail="Client not found")
    if not settings.entra_client_id:
        raise HTTPException(status_code=503, detail="ENTRA_CLIENT_ID is not configured")
    state = create_oauth_state(user.id, client_id=client_id)
    params = {"client_id": settings.entra_client_id, "response_type": "code", "redirect_uri": settings.entra_redirect_uri, "response_mode": "query", "scope": "openid profile offline_access User.Read User.Read.All User.ReadWrite.All Directory.Read.All Directory.ReadWrite.All GroupMember.Read.All GroupMember.ReadWrite.All UserAuthenticationMethod.Read.All UserAuthenticationMethod.ReadWrite.All MailboxSettings.ReadWrite Organization.Read.All", "state": state}
    return {"authorization_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?" + urlencode(params)}


@app.post("/api/prospect/assessments", status_code=status.HTTP_201_CREATED)
def create_prospect_assessment(user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict[str, str]:
    raw_token = secrets.token_urlsafe(32)
    assessment = ProspectAssessment(organization_id=user.organization_id, token_hash=hashlib.sha256(raw_token.encode()).hexdigest(), expires_at=datetime.now(timezone.utc) + timedelta(hours=24))
    db.add(assessment)
    db.flush()
    state = secrets.token_urlsafe(32)
    _prospect_states[state] = assessment.id
    db.commit()
    params = {"client_id": settings.entra_client_id or "", "response_type": "code", "redirect_uri": settings.entra_prospect_redirect_uri, "response_mode": "query", "scope": "openid profile User.Read Organization.Read.All", "state": state}
    return {"assessment_id": assessment.id, "magic_link": f"{settings.frontend_url}/prospect/{raw_token}", "authorization_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?" + urlencode(params)}


@app.get("/api/prospect/callback")
def prospect_callback(code: str, state: str, db: Session = Depends(get_db)) -> HTMLResponse:
    assessment_id = _prospect_states.pop(state, None)
    assessment = db.get(ProspectAssessment, assessment_id) if assessment_id else None
    if not assessment or assessment.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired assessment link")
    if not settings.entra_client_id or not settings.entra_client_secret:
        raise HTTPException(status_code=503, detail="Microsoft OAuth is not configured")
    response = httpx.post("https://login.microsoftonline.com/common/oauth2/v2.0/token", data={"client_id": settings.entra_client_id, "client_secret": settings.entra_client_secret, "code": code, "redirect_uri": settings.entra_prospect_redirect_uri, "grant_type": "authorization_code", "scope": "openid profile User.Read Organization.Read.All"}, timeout=15)
    if response.is_error or not response.json().get("access_token"):
        raise HTTPException(status_code=502, detail="Read-only consent exchange failed")
    access_token = response.json()["access_token"]
    org_response = httpx.get("https://graph.microsoft.com/v1.0/organization", headers={"Authorization": f"Bearer {access_token}"}, timeout=15)
    users_response = httpx.get("https://graph.microsoft.com/v1.0/users?$top=1&$count=true", headers={"Authorization": f"Bearer {access_token}", "ConsistencyLevel": "eventual"}, timeout=15)
    if org_response.is_error or users_response.is_error:
        raise HTTPException(status_code=502, detail="Read-only assessment Graph request failed")
    organization = (org_response.json().get("value") or [{}])[0]
    report = f"<h1>Microsoft 365 security assessment</h1><p>Organization: {html.escape(organization.get('displayName', 'Unknown'))}</p><p>Tenant ID: {html.escape(organization.get('id', 'Unknown'))}</p><p>Directory user count: {html.escape(str(users_response.json().get('@odata.count', 'Unavailable')))}</p><p>This assessment used read-only delegated access and did not persist tenant credentials.</p>"
    assessment.status = "completed"
    assessment.tenant_id = organization.get("id")
    assessment.report_content = report
    db.commit()
    return HTMLResponse(report)


@app.post("/api/prospect/assessments/{assessment_id}/convert")
def convert_prospect(assessment_id: str, payload: ProspectConversionRequest | None = None, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict:
    assessment = db.get(ProspectAssessment, assessment_id)
    if not assessment or assessment.organization_id != user.organization_id:
        raise HTTPException(status_code=404, detail="Assessment not found")
    if assessment.status != "completed" or not assessment.tenant_id:
        raise HTTPException(status_code=409, detail="Only a completed assessment can be converted")
    tenant = db.scalar(select(ClientTenant).where(ClientTenant.organization_id == user.organization_id, ClientTenant.tenant_id == assessment.tenant_id))
    if not tenant:
        tenant = ClientTenant(organization_id=user.organization_id, tenant_id=assessment.tenant_id, display_name=(payload.display_name.strip() if payload and payload.display_name else assessment.tenant_id), connection_status="pending")
        db.add(tenant)
    assessment.status = "converted"
    db.flush()
    write_audit(db, user, "prospect.convert", tenant.id, {"assessment_id": assessment.id})
    db.commit()
    return {"tenant_id": tenant.id, "status": assessment.status, "connection_status": tenant.connection_status}


@app.get("/api/prospect/{token}/report", response_class=HTMLResponse)
def prospect_report(token: str, db: Session = Depends(get_db)) -> str:
    assessment = db.scalar(select(ProspectAssessment).where(ProspectAssessment.token_hash == hashlib.sha256(token.encode()).hexdigest(), ProspectAssessment.status == "completed"))
    if not assessment or assessment.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=404, detail="Assessment not found")
    return assessment.report_content or ""


@app.post("/api/tenants/{tenant_id}/reconnect")
def reconnect_tenant(tenant_id: str, user: StaffUser = Depends(require_permission("operate")), db: Session = Depends(get_db)) -> dict[str, str]:
    tenant = ensure_tenant_access(tenant_id, user, db)
    if not settings.entra_client_id:
        raise HTTPException(status_code=503, detail="ENTRA_CLIENT_ID is not configured")
    state = create_oauth_state(user.id, tenant.id, tenant.client_id)
    params = {"client_id": settings.entra_client_id, "response_type": "code", "redirect_uri": settings.entra_redirect_uri, "response_mode": "query", "scope": "openid profile offline_access User.Read User.Read.All User.ReadWrite.All Directory.Read.All Directory.ReadWrite.All GroupMember.Read.All GroupMember.ReadWrite.All UserAuthenticationMethod.Read.All UserAuthenticationMethod.ReadWrite.All MailboxSettings.ReadWrite Organization.Read.All", "state": state}
    return {"authorization_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?" + urlencode(params), "tenant_id": tenant.id}


@app.get("/api/auth/microsoft/callback")
def microsoft_callback(code: str | None = Query(default=None), state: str | None = Query(default=None), error: str | None = Query(default=None), client_id: str | None = Query(default=None), db: Session = Depends(get_db)):
    try:
        state_payload = verify_oauth_state(state or "")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=error or "Invalid or expired OAuth state") from exc
    user_id = state_payload["sub"]
    state_client_id = state_payload.get("client_id")
    if client_id and state_client_id and client_id != state_client_id:
        raise HTTPException(status_code=400, detail="OAuth client does not match the signed state")
    requested_client_id = state_client_id or client_id
    reconnect = (user_id, state_payload.get("tenant_id")) if state_payload.get("tenant_id") else None
    if error or not code:
        raise HTTPException(status_code=400, detail=error or "Microsoft authorization was not completed")
    if not settings.entra_client_id or not settings.entra_client_secret:
        raise HTTPException(status_code=503, detail="Microsoft OAuth is not configured")
    token_response = httpx.post("https://login.microsoftonline.com/common/oauth2/v2.0/token", data={"client_id": settings.entra_client_id, "client_secret": settings.entra_client_secret, "code": code, "redirect_uri": settings.entra_redirect_uri, "grant_type": "authorization_code", "scope": "openid profile offline_access User.Read User.Read.All User.ReadWrite.All Directory.Read.All Directory.ReadWrite.All GroupMember.Read.All GroupMember.ReadWrite.All UserAuthenticationMethod.Read.All UserAuthenticationMethod.ReadWrite.All MailboxSettings.ReadWrite Organization.Read.All"}, timeout=15)
    if token_response.is_error:
        try:
            error_payload = token_response.json()
        except ValueError:
            error_payload = {}
        error_code = error_payload.get("error", "unknown_error")
        error_description = error_payload.get("error_description", "Microsoft rejected the authorization code")
        raise HTTPException(status_code=502, detail=f"Microsoft token exchange failed ({error_code}): {error_description}")
    tokens = token_response.json()
    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    if not access_token or not refresh_token:
        raise HTTPException(status_code=502, detail="Microsoft did not return required tokens")
    graph_response = httpx.get("https://graph.microsoft.com/v1.0/organization", headers={"Authorization": f"Bearer {access_token}"}, timeout=15)
    if graph_response.is_error:
        raise HTTPException(status_code=502, detail="Microsoft Graph organization lookup failed")
    organization_items = graph_response.json().get("value", [])
    if not organization_items:
        raise HTTPException(status_code=502, detail="Microsoft Graph returned no organization")
    graph_org = organization_items[0]
    tenant_id = tokens.get("id_token_claims", {}).get("tid") or graph_org.get("id")
    if not tenant_id:
        raise HTTPException(status_code=502, detail="Microsoft response did not include a tenant ID")
    user = db.get(StaffUser, user_id)
    if not user:
        raise HTTPException(status_code=400, detail="OAuth owner no longer exists")
    tenant = db.scalar(select(ClientTenant).where(ClientTenant.tenant_id == tenant_id, ClientTenant.organization_id == user.organization_id))
    if requested_client_id and not db.scalar(select(Client).where(Client.id == requested_client_id, Client.organization_id == user.organization_id)):
        raise HTTPException(status_code=404, detail="Client not found")
    if reconnect and (not tenant or tenant.id != reconnect[1]):
        raise HTTPException(status_code=409, detail="OAuth tenant does not match the reconnect request")
    if not tenant:
        if not requested_client_id:
            legacy_client = db.scalar(select(Client).where(Client.organization_id == user.organization_id, Client.name == "Unassigned"))
            if not legacy_client:
                legacy_client = Client(organization_id=user.organization_id, name="Unassigned", description="Legacy tenant connections")
                db.add(legacy_client)
                db.flush()
            requested_client_id = legacy_client.id
        verified_domains = graph_org.get("verifiedDomains") or []
        primary_domain = next((item.get("name") for item in verified_domains if item.get("isDefault") and item.get("name")), None) or next((item.get("name") for item in verified_domains if item.get("name")), None)
        tenant = ClientTenant(organization_id=user.organization_id, client_id=requested_client_id, tenant_id=tenant_id, primary_domain=primary_domain, display_name=graph_org.get("displayName", tenant_id))
        db.add(tenant)
        db.flush()
    elif requested_client_id and not reconnect and tenant.client_id != requested_client_id:
        raise HTTPException(status_code=409, detail="Tenant is already assigned to another client")
    tenant.connection_status = "connected"
    tenant.last_connected_at = datetime.now(timezone.utc)
    tenant.last_error = None
    tenant.credential = TenantCredential(encrypted_refresh_token=encrypt_credential(refresh_token), encrypted_access_token=encrypt_credential(access_token), access_token_expires_at=datetime.now(timezone.utc) + timedelta(seconds=int(tokens.get("expires_in", 3600))))
    db.flush()
    write_audit(db, user, "tenant.connect", tenant.id, {"tenant_id": tenant.tenant_id})
    db.commit()
    return RedirectResponse(url=f"{settings.frontend_url}/?connected=1")


def tenant_to_response(tenant: ClientTenant) -> TenantResponse:
    return TenantResponse(id=tenant.id, tenant_id=tenant.tenant_id, client_id=tenant.client_id, primary_domain=tenant.primary_domain, display_name=tenant.display_name, connection_status=tenant.connection_status, last_connected_at=tenant.last_connected_at, last_error=tenant.last_error)


@app.post("/api/tenants/import", status_code=status.HTTP_201_CREATED)
def import_tenants(file: UploadFile = File(...), user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict[str, int]:
    if file.content_type not in {"text/csv", "application/csv", "application/vnd.ms-excel"}:
        raise HTTPException(status_code=415, detail="Upload a CSV file")
    try:
        rows = csv.DictReader(io.StringIO(file.file.read().decode("utf-8-sig")))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise HTTPException(status_code=400, detail="CSV must be UTF-8 encoded") from exc
    if not rows.fieldnames or "tenant_id" not in rows.fieldnames:
        raise HTTPException(status_code=400, detail="CSV must contain a tenant_id column")
    created = 0
    skipped = 0
    for row in rows:
        tenant_id = (row.get("tenant_id") or "").strip()
        display_name = (row.get("display_name") or tenant_id).strip()
        if not tenant_id:
            continue
        existing = db.scalar(select(ClientTenant).where(ClientTenant.tenant_id == tenant_id))
        if existing:
            if existing.organization_id == user.organization_id:
                skipped += 1
                continue
            raise HTTPException(status_code=409, detail="A tenant ID belongs to another organization")
        db.add(ClientTenant(organization_id=user.organization_id, tenant_id=tenant_id, display_name=display_name, connection_status="pending"))
        created += 1
    write_audit(db, user, "tenant.import", payload={"created": created, "skipped": skipped})
    db.commit()
    return {"created": created, "skipped": skipped}


@app.get("/api/tenants", response_model=list[TenantResponse])
def list_tenants(user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> list[TenantResponse]:
    tenants = db.scalars(select(ClientTenant).where(ClientTenant.organization_id == user.organization_id).order_by(ClientTenant.display_name)).all()
    return [tenant_to_response(tenant) for tenant in tenants]


@app.post("/api/baselines", status_code=status.HTTP_201_CREATED)
def create_baseline(payload: BaselineRequest, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict:
    name = payload.name.strip()
    if not name or not payload.definition.get("controls"):
        raise HTTPException(status_code=400, detail="Name and at least one control are required")
    if db.scalar(select(BaselineTemplate).where(BaselineTemplate.name == name)):
        raise HTTPException(status_code=409, detail="Baseline name already exists")
    baseline = BaselineTemplate(name=name, description=payload.description.strip(), definition=payload.definition, is_builtin=False)
    db.add(baseline)
    db.flush()
    write_audit(db, user, "baseline.create", payload={"baseline_id": baseline.id})
    db.commit()
    db.refresh(baseline)
    return {"id": baseline.id, "name": baseline.name, "description": baseline.description, "definition": baseline.definition, "is_builtin": baseline.is_builtin}


@app.put("/api/baselines/{baseline_id}")
def update_baseline(baseline_id: str, payload: BaselineRequest, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict:
    baseline = db.get(BaselineTemplate, baseline_id)
    if not baseline or baseline.is_builtin:
        raise HTTPException(status_code=404, detail="Editable custom baseline not found")
    if not payload.name.strip() or not payload.definition.get("controls"):
        raise HTTPException(status_code=400, detail="Name and at least one control are required")
    baseline.name = payload.name.strip()
    baseline.description = payload.description.strip()
    baseline.definition = payload.definition
    write_audit(db, user, "baseline.update", payload={"baseline_id": baseline.id})
    db.commit()
    return {"id": baseline.id, "name": baseline.name, "description": baseline.description, "definition": baseline.definition, "is_builtin": baseline.is_builtin}


@app.delete("/api/baselines/{baseline_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_baseline(baseline_id: str, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> None:
    baseline = db.get(BaselineTemplate, baseline_id)
    if not baseline or baseline.is_builtin:
        raise HTTPException(status_code=404, detail="Editable custom baseline not found")
    if db.scalar(select(TenantBaselineAssignment).where(TenantBaselineAssignment.baseline_template_id == baseline_id)):
        raise HTTPException(status_code=409, detail="Cannot delete an assigned baseline")
    write_audit(db, user, "baseline.delete", payload={"baseline_id": baseline.id})
    db.delete(baseline)
    db.commit()


@app.get("/api/baselines")
def list_baselines(user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    return [{"id": item.id, "name": item.name, "description": item.description, "definition": item.definition, "is_builtin": item.is_builtin} for item in db.scalars(select(BaselineTemplate).order_by(BaselineTemplate.name)).all()]


@app.post("/api/tenants/{tenant_id}/baselines/{baseline_id}", status_code=status.HTTP_201_CREATED)
def assign_baseline(tenant_id: str, baseline_id: str, user: StaffUser = Depends(require_permission("operate")), db: Session = Depends(get_db)) -> dict[str, str]:
    tenant = ensure_tenant_access(tenant_id, user, db)
    if not db.get(BaselineTemplate, baseline_id):
        raise HTTPException(status_code=404, detail="Baseline not found")
    assignment = db.scalar(select(TenantBaselineAssignment).where(TenantBaselineAssignment.client_tenant_id == tenant.id, TenantBaselineAssignment.baseline_template_id == baseline_id))
    if assignment:
        return {"id": assignment.id, "status": "already_assigned"}
    assignment = TenantBaselineAssignment(client_tenant_id=tenant.id, baseline_template_id=baseline_id, assigned_by=user.id)
    db.add(assignment)
    db.flush()
    write_audit(db, user, "baseline.assign", tenant.id, {"baseline_id": baseline_id})
    db.commit()
    return {"id": assignment.id, "status": "assigned"}


@app.post("/api/tenants/{tenant_id}/baselines/{baseline_id}/deploy")
def deploy_baseline(tenant_id: str, baseline_id: str, user: StaffUser = Depends(require_permission("operate")), db: Session = Depends(get_db)) -> dict:
    tenant = ensure_tenant_access(tenant_id, user, db)
    baseline = db.get(BaselineTemplate, baseline_id)
    if not baseline:
        raise HTTPException(status_code=404, detail="Baseline not found")
    if not tenant.credential:
        raise HTTPException(status_code=409, detail="Tenant has no delegated credential")
    try:
        result = GraphClient(tenant, tenant.credential).apply_baseline(baseline.definition)
        write_audit(db, user, "baseline.deploy", tenant.id, {"baseline_id": baseline.id, **result})
        db.commit()
        return result
    except GraphAPIError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/api/tenants/{tenant_id}/baselines/{baseline_id}/drift")
def detect_baseline_drift(tenant_id: str, baseline_id: str, user: StaffUser = Depends(require_permission("operate")), db: Session = Depends(get_db)) -> dict:
    tenant = ensure_tenant_access(tenant_id, user, db)
    baseline = db.get(BaselineTemplate, baseline_id)
    if not baseline:
        raise HTTPException(status_code=404, detail="Baseline not found")
    if not tenant.credential:
        raise HTTPException(status_code=409, detail="Tenant has no delegated credential")
    try:
        differences = GraphClient(tenant, tenant.credential).baseline_differences(baseline.definition)
    except GraphAPIError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    if differences:
        event = DriftEvent(client_tenant_id=tenant.id, baseline_template_id=baseline.id, differences=differences)
        db.add(event)
        db.flush()
        db.add(Alert(client_tenant_id=tenant.id, drift_event_id=event.id, severity="high", title="Baseline drift detected", message=f"{len(differences)} control(s) differ from {baseline.name}."))
        write_audit(db, user, "baseline.drift_detected", tenant.id, {"baseline_id": baseline.id, "differences": differences})
        db.commit()
    return {"drift": bool(differences), "differences": differences}


@app.post("/api/alert-rules", status_code=status.HTTP_201_CREATED)
def create_alert_rule(payload: AlertRuleRequest, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict:
    if payload.min_severity not in {"low", "medium", "high", "critical"} or payload.suppress_minutes < 0:
        raise HTTPException(status_code=400, detail="Invalid alert rule")
    rule = AlertRule(organization_id=user.organization_id, name=payload.name.strip(), min_severity=payload.min_severity, enabled=payload.enabled, suppress_minutes=payload.suppress_minutes)
    db.add(rule)
    db.flush()
    write_audit(db, user, "alert_rule.create", payload={"rule_id": rule.id})
    db.commit()
    return {"id": rule.id, "name": rule.name, "min_severity": rule.min_severity, "enabled": rule.enabled, "suppress_minutes": rule.suppress_minutes}


@app.get("/api/alert-rules")
def list_alert_rules(user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    return [{"id": item.id, "name": item.name, "min_severity": item.min_severity, "enabled": item.enabled, "suppress_minutes": item.suppress_minutes} for item in db.scalars(select(AlertRule).where(AlertRule.organization_id == user.organization_id)).all()]


@app.post("/api/tenants/{tenant_id}/alerts/ingest")
def ingest_alerts(tenant_id: str, user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> dict[str, int]:
    tenant = ensure_tenant_access(tenant_id, user, db)
    try:
        created = ingest_tenant_alerts(db, tenant) + ingest_risky_signins(db, tenant)
    except GraphAPIError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    write_audit(db, user, "alert.ingest", tenant.id, {"created": created})
    db.commit()
    if created:
        try:
            send_alert_email("TenantToolbox security alerts", f"{created} new security alert(s) were detected for {tenant.display_name}.")
            send_psa_ticket(title="TenantToolbox security alerts", description=f"{created} new security alert(s) were detected for {tenant.display_name}.", severity="high", tenant_id=tenant.id, source="tenanttoolbox")
        except httpx.HTTPError:
            # Alert persistence must not fail because an optional delivery target is unavailable.
            pass
    return {"created": created}


@app.post("/api/alerts/{alert_id}/remediate")
def remediate_alert(alert_id: str, confirm: bool = Query(False), user: StaffUser = Depends(require_permission("operate")), db: Session = Depends(get_db)) -> dict[str, str]:
    if not confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to execute remediation")
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    tenant = ensure_tenant_access(alert.client_tenant_id, user, db)
    graph_user_id = alert.details.get("userId") or alert.details.get("user_id")
    if alert.source != "graph" or not graph_user_id or not tenant.credential:
        raise HTTPException(status_code=409, detail="This alert has no supported user remediation target")
    try:
        GraphClient(tenant, tenant.credential).disable_user(graph_user_id)
    except GraphAPIError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    alert.remediation_status = "completed"
    alert.status = "resolved"
    alert.resolved_at = datetime.now(timezone.utc)
    write_audit(db, user, "alert.remediate", tenant.id, {"alert_id": alert.id, "action": "disable_user"})
    db.commit()
    return {"status": "remediated", "action": "disable_user"}


@app.get("/api/alerts")
def list_alerts(user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    items = db.scalars(select(Alert).join(ClientTenant).where(ClientTenant.organization_id == user.organization_id).order_by(Alert.created_at.desc()).limit(100)).all()
    return [{"id": item.id, "tenant_id": item.client_tenant_id, "baseline_id": db.get(DriftEvent, item.drift_event_id).baseline_template_id if item.drift_event_id and db.get(DriftEvent, item.drift_event_id) else None, "severity": item.severity, "source": item.source, "remediation_status": item.remediation_status, "title": item.title, "message": item.message, "status": item.status, "created_at": item.created_at} for item in items]


@app.post("/api/tenants/{tenant_id}/baselines/{baseline_id}/rollback")
def rollback_baseline(tenant_id: str, baseline_id: str, user: StaffUser = Depends(require_permission("operate")), db: Session = Depends(get_db)) -> dict:
    result = deploy_baseline(tenant_id, baseline_id, user, db)
    tenant = ensure_tenant_access(tenant_id, user, db)
    open_events = db.scalars(select(DriftEvent).where(DriftEvent.client_tenant_id == tenant.id, DriftEvent.baseline_template_id == baseline_id, DriftEvent.resolved_at.is_(None))).all()
    now = datetime.now(timezone.utc)
    for event in open_events:
        event.resolved_at = now
    db.query(Alert).filter(Alert.client_tenant_id == tenant.id, Alert.status == "open").update({"status": "resolved", "resolved_at": now})
    write_audit(db, user, "baseline.rollback", tenant.id, {"baseline_id": baseline_id})
    db.commit()
    return {"status": "reapplied", **result}


@app.get("/api/tenants/{tenant_id}/baselines")
def tenant_baselines(tenant_id: str, user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    ensure_tenant_access(tenant_id, user, db)
    assignments = db.scalars(select(TenantBaselineAssignment).where(TenantBaselineAssignment.client_tenant_id == tenant_id)).all()
    return [{"id": item.baseline_template_id, "assigned_at": item.assigned_at} for item in assignments]


@app.post("/api/tenants/{tenant_id}/sync")
def synchronize_tenant(tenant_id: str, user: StaffUser = Depends(require_permission("operate")), db: Session = Depends(get_db)) -> dict:
    tenant = db.scalar(select(ClientTenant).where(ClientTenant.id == tenant_id, ClientTenant.organization_id == user.organization_id))
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    try:
        result = sync_tenant(db, tenant)
        write_audit(db, user, "tenant.sync", tenant.id, result)
        db.commit()
        return result
    except RuntimeError as exc:
        tenant.connection_status = "needs_attention"
        tenant.last_error = str(exc)
        db.commit()
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/api/tenants/{tenant_id}/users")
def list_tenant_users(tenant_id: str, user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    ensure_tenant_access(tenant_id, user, db)
    return [{"id": item.graph_id, "display_name": item.display_name, "user_principal_name": item.user_principal_name, "account_enabled": item.account_enabled, "synced_at": item.synced_at} for item in db.scalars(select(TenantUserSnapshot).where(TenantUserSnapshot.client_tenant_id == tenant_id).order_by(TenantUserSnapshot.display_name)).all()]


@app.get("/api/tenants/{tenant_id}/licenses")
def list_tenant_licenses(tenant_id: str, user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    ensure_tenant_access(tenant_id, user, db)
    return [{"sku_id": item.sku_id, "sku_part_number": item.sku_part_number, "display_name": friendly_license_name(item.sku_part_number), "consumed_units": item.consumed_units, "enabled_units": item.enabled_units, "synced_at": item.synced_at} for item in db.scalars(select(TenantLicenseSnapshot).where(TenantLicenseSnapshot.client_tenant_id == tenant_id).order_by(TenantLicenseSnapshot.sku_part_number)).all()]


@app.get("/api/tenants/{tenant_id}/secure-score")
def tenant_secure_score(tenant_id: str, user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> dict | None:
    ensure_tenant_access(tenant_id, user, db)
    item = db.scalar(select(TenantSecureScoreSnapshot).where(TenantSecureScoreSnapshot.client_tenant_id == tenant_id).order_by(TenantSecureScoreSnapshot.synced_at.desc()))
    if not item:
        return None
    return {"score": item.score, "max_score": item.max_score, "control_states": item.control_states, "synced_at": item.synced_at}


def ensure_tenant_access(tenant_id: str, user: StaffUser, db: Session) -> ClientTenant:
    tenant = db.scalar(select(ClientTenant).where(ClientTenant.id == tenant_id, ClientTenant.organization_id == user.organization_id))
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


@app.delete("/api/tenants/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT)
def disconnect_tenant(tenant_id: str, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> None:
    tenant = db.scalar(select(ClientTenant).where(ClientTenant.id == tenant_id, ClientTenant.organization_id == user.organization_id))
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    write_audit(db, user, "tenant.disconnect", tenant.id)
    db.delete(tenant)
    db.commit()
