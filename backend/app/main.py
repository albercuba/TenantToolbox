import csv
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
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.db import Base, engine, get_db
from app.models import (Alert, AlertRule, AuditLog, BaselineTemplate, ClientTenant, ComplianceControl, DriftEvent,
                        Report, ReportSchedule, StaffUser, TenantBaselineAssignment, TenantCredential,
                        TenantLicenseSnapshot, TenantSecureScoreSnapshot,
                        TenantUserSnapshot)
from app.alerting import ingest_risky_signins, ingest_tenant_alerts
from app.graph import GraphAPIError, GraphClient
from app.sync import sync_tenant
from app.notifications import send_alert_email, send_psa_webhook
from app.security import (create_access_token, encrypt_credential, get_current_user,
                          hash_password, require_owner, verify_password)

COMPLIANCE_CONTROLS = {
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

# The state is short-lived and process-local for this initial single-instance flow.
_oauth_states: dict[str, str] = {}


class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    organization_name: str


class TenantResponse(BaseModel):
    id: str
    tenant_id: str
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



def write_audit(db: Session, user: StaffUser, action: str, tenant_id: str | None = None, payload: dict | None = None) -> None:
    db.add(AuditLog(organization_id=user.organization_id, actor_id=user.id, client_tenant_id=tenant_id, action=action, target_type="client_tenant" if tenant_id else None, target_id=tenant_id, payload=payload or {}))


@app.get("/api/audit-log")
def audit_log(user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    entries = db.scalars(select(AuditLog).where(AuditLog.organization_id == user.organization_id).order_by(AuditLog.created_at.desc()).limit(100)).all()
    return [{"id": item.id, "action": item.action, "tenant_id": item.client_tenant_id, "actor_id": item.actor_id, "payload": item.payload, "created_at": item.created_at} for item in entries]

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
def generate_report(tenant_id: str, user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> dict[str, str]:
    tenant = ensure_tenant_access(tenant_id, user, db)
    alerts = db.scalars(select(Alert).where(Alert.client_tenant_id == tenant.id).order_by(Alert.created_at.desc()).limit(20)).all()
    assignments = db.scalars(select(TenantBaselineAssignment).where(TenantBaselineAssignment.client_tenant_id == tenant.id)).all()
    content = f"<h1>{html.escape(tenant.display_name)} security report</h1><p>Generated {datetime.now(timezone.utc).isoformat()}</p><h2>Assigned baselines</h2><p>{len(assignments)}</p><h2>Recent alerts</h2><ul>{''.join(f'<li>{html.escape(item.title)} ({html.escape(item.severity)})</li>' for item in alerts) or '<li>No alerts</li>'}</ul>"
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


@app.post("/api/auth/signup", status_code=status.HTTP_201_CREATED)
def signup(payload: SignupRequest, db: Session = Depends(get_db)) -> dict[str, str]:
    if len(payload.password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters")
    if db.scalar(select(StaffUser).where(StaffUser.email == payload.email.lower())):
        raise HTTPException(status_code=409, detail="Email is already registered")
    organization = Organization(name=payload.organization_name.strip())
    user = StaffUser(email=payload.email.lower(), password_hash=hash_password(payload.password), role="owner", organization=organization)
    db.add(user)
    db.commit()
    db.refresh(user)
    write_audit(db, user, "staff.signup")
    db.commit()
    return {"access_token": create_access_token(user), "token_type": "bearer", "role": user.role}


@app.post("/api/auth/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)) -> dict[str, str]:
    user = db.scalar(select(StaffUser).where(StaffUser.email == form.username.lower()))
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password", headers={"WWW-Authenticate": "Bearer"})
    return {"access_token": create_access_token(user), "token_type": "bearer", "role": user.role}


@app.get("/api/auth/me")
def me(user: StaffUser = Depends(get_current_user)) -> dict[str, str]:
    return {"id": user.id, "email": user.email, "role": user.role, "organization_id": user.organization_id}


@app.get("/api/auth/microsoft/start")
def microsoft_start(user: StaffUser = Depends(get_current_user)) -> dict[str, str]:
    if not settings.entra_client_id:
        raise HTTPException(status_code=503, detail="ENTRA_CLIENT_ID is not configured")
    state = secrets.token_urlsafe(32)
    _oauth_states[state] = user.id
    params = {"client_id": settings.entra_client_id, "response_type": "code", "redirect_uri": settings.entra_redirect_uri, "response_mode": "query", "scope": "openid profile offline_access User.Read Organization.Read.All", "state": state}
    return {"authorization_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?" + urlencode(params)}


@app.get("/api/auth/microsoft/callback")
def microsoft_callback(code: str | None = Query(default=None), state: str | None = Query(default=None), error: str | None = Query(default=None), db: Session = Depends(get_db)):
    user_id = _oauth_states.pop(state or "", None)
    if error or not code or not user_id:
        raise HTTPException(status_code=400, detail=error or "Invalid or expired OAuth state")
    if not settings.entra_client_id or not settings.entra_client_secret:
        raise HTTPException(status_code=503, detail="Microsoft OAuth is not configured")
    token_response = httpx.post("https://login.microsoftonline.com/common/oauth2/v2.0/token", data={"client_id": settings.entra_client_id, "client_secret": settings.entra_client_secret, "code": code, "redirect_uri": settings.entra_redirect_uri, "grant_type": "authorization_code", "scope": "openid profile offline_access User.Read Organization.Read.All"}, timeout=15)
    if token_response.is_error:
        raise HTTPException(status_code=502, detail="Microsoft token exchange failed")
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
    tenant = db.scalar(select(ClientTenant).where(ClientTenant.tenant_id == tenant_id))
    if not tenant:
        tenant = ClientTenant(organization_id=user.organization_id, tenant_id=tenant_id, display_name=graph_org.get("displayName", tenant_id))
        db.add(tenant)
        db.flush()
    tenant.connection_status = "connected"
    tenant.last_connected_at = datetime.now(timezone.utc)
    tenant.last_error = None
    tenant.credential = TenantCredential(encrypted_refresh_token=encrypt_credential(refresh_token), encrypted_access_token=encrypt_credential(access_token), access_token_expires_at=datetime.now(timezone.utc) + timedelta(seconds=int(tokens.get("expires_in", 3600))))
    db.flush()
    write_audit(db, user, "tenant.connect", tenant.id, {"tenant_id": tenant.tenant_id})
    db.commit()
    return RedirectResponse(url=f"{settings.frontend_url}/?connected=1")


def tenant_to_response(tenant: ClientTenant) -> TenantResponse:
    return TenantResponse(id=tenant.id, tenant_id=tenant.tenant_id, display_name=tenant.display_name, connection_status=tenant.connection_status, last_connected_at=tenant.last_connected_at, last_error=tenant.last_error)


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
def assign_baseline(tenant_id: str, baseline_id: str, user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> dict[str, str]:
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
def deploy_baseline(tenant_id: str, baseline_id: str, user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
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
def detect_baseline_drift(tenant_id: str, baseline_id: str, user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
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
        payload = {"event": "security_alerts_created", "tenant_id": tenant.id, "count": created}
        try:
            send_alert_email("TenantToolbox security alerts", f"{created} new security alert(s) were detected for {tenant.display_name}.")
            send_psa_webhook(payload)
        except httpx.HTTPError:
            # Alert persistence must not fail because an optional delivery target is unavailable.
            pass
    return {"created": created}


@app.post("/api/alerts/{alert_id}/remediate")
def remediate_alert(alert_id: str, confirm: bool = Query(False), user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> dict[str, str]:
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
def rollback_baseline(tenant_id: str, baseline_id: str, user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
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
def synchronize_tenant(tenant_id: str, user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
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
    return [{"sku_id": item.sku_id, "sku_part_number": item.sku_part_number, "consumed_units": item.consumed_units, "enabled_units": item.enabled_units, "synced_at": item.synced_at} for item in db.scalars(select(TenantLicenseSnapshot).where(TenantLicenseSnapshot.client_tenant_id == tenant_id).order_by(TenantLicenseSnapshot.sku_part_number)).all()]


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
