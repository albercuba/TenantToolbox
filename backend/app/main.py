import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.db import Base, engine, get_db
from app.models import (AuditLog, ClientTenant, Organization, StaffUser, TenantCredential,
                        TenantLicenseSnapshot, TenantSecureScoreSnapshot,
                        TenantUserSnapshot)
from app.sync import sync_tenant
from app.security import (create_access_token, encrypt_credential, get_current_user,
                          hash_password, require_owner, verify_password)

@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Migrations are the deployment source of truth; this keeps a fresh local checkout usable.
    Base.metadata.create_all(bind=engine)
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



def write_audit(db: Session, user: StaffUser, action: str, tenant_id: str | None = None, payload: dict | None = None) -> None:
    db.add(AuditLog(organization_id=user.organization_id, actor_id=user.id, client_tenant_id=tenant_id, action=action, target_type="client_tenant" if tenant_id else None, target_id=tenant_id, payload=payload or {}))


@app.get("/api/audit-log")
def audit_log(user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    entries = db.scalars(select(AuditLog).where(AuditLog.organization_id == user.organization_id).order_by(AuditLog.created_at.desc()).limit(100)).all()
    return [{"id": item.id, "action": item.action, "tenant_id": item.client_tenant_id, "actor_id": item.actor_id, "payload": item.payload, "created_at": item.created_at} for item in entries]

@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "tenanttoolbox-api"}


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
    db.commit()
    return RedirectResponse(url=f"{settings.frontend_url}/?connected=1")


def tenant_to_response(tenant: ClientTenant) -> TenantResponse:
    return TenantResponse(id=tenant.id, tenant_id=tenant.tenant_id, display_name=tenant.display_name, connection_status=tenant.connection_status, last_connected_at=tenant.last_connected_at, last_error=tenant.last_error)


@app.get("/api/tenants", response_model=list[TenantResponse])
def list_tenants(user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> list[TenantResponse]:
    tenants = db.scalars(select(ClientTenant).where(ClientTenant.organization_id == user.organization_id).order_by(ClientTenant.display_name)).all()
    return [tenant_to_response(tenant) for tenant in tenants]


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
