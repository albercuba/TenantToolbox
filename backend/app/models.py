from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class Organization(Base):
    __tablename__ = "organization"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    staff_users: Mapped[list["StaffUser"]] = relationship(back_populates="organization")
    tenants: Mapped[list["ClientTenant"]] = relationship(back_populates="organization")


class StaffUser(Base):
    __tablename__ = "staff_user"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organization.id"), index=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="tech")
    organization: Mapped[Organization] = relationship(back_populates="staff_users")


class ClientTenant(Base):
    __tablename__ = "client_tenant"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organization.id"), index=True)
    tenant_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(200))
    connection_status: Mapped[str] = mapped_column(String(30), default="pending")
    last_connected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    organization: Mapped[Organization] = relationship(back_populates="tenants")
    credential: Mapped["TenantCredential | None"] = relationship(back_populates="tenant", uselist=False, cascade="all, delete-orphan")


class TenantCredential(Base):
    __tablename__ = "tenant_credential"
    __table_args__ = (UniqueConstraint("client_tenant_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    client_tenant_id: Mapped[str] = mapped_column(ForeignKey("client_tenant.id"), index=True)
    encrypted_refresh_token: Mapped[str] = mapped_column(Text)
    encrypted_access_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    access_token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    tenant: Mapped[ClientTenant] = relationship(back_populates="credential")


class TenantUserSnapshot(Base):
    __tablename__ = "tenant_user_snapshot"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    client_tenant_id: Mapped[str] = mapped_column(ForeignKey("client_tenant.id", ondelete="CASCADE"), index=True)
    graph_id: Mapped[str] = mapped_column(String(100))
    display_name: Mapped[str] = mapped_column(String(200))
    user_principal_name: Mapped[str] = mapped_column(String(320))
    account_enabled: Mapped[bool | None]
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class TenantLicenseSnapshot(Base):
    __tablename__ = "tenant_license_snapshot"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    client_tenant_id: Mapped[str] = mapped_column(ForeignKey("client_tenant.id", ondelete="CASCADE"), index=True)
    sku_id: Mapped[str] = mapped_column(String(100))
    sku_part_number: Mapped[str] = mapped_column(String(200))
    consumed_units: Mapped[int] = mapped_column(default=0)
    enabled_units: Mapped[int] = mapped_column(default=0)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organization.id"), index=True)
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("staff_user.id"), nullable=True)
    client_tenant_id: Mapped[str | None] = mapped_column(ForeignKey("client_tenant.id", ondelete="SET NULL"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(100))
    target_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)


class TenantSecureScoreSnapshot(Base):
    __tablename__ = "tenant_secure_score_snapshot"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    client_tenant_id: Mapped[str] = mapped_column(ForeignKey("client_tenant.id", ondelete="CASCADE"), index=True)
    score: Mapped[float | None]
    max_score: Mapped[float | None]
    control_states: Mapped[dict] = mapped_column(JSON)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class BaselineTemplate(Base):
    __tablename__ = "baseline_template"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(200), unique=True)
    description: Mapped[str] = mapped_column(Text)
    definition: Mapped[dict] = mapped_column(JSON)
    is_builtin: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class TenantBaselineAssignment(Base):
    __tablename__ = "tenant_baseline_assignment"
    __table_args__ = (UniqueConstraint("client_tenant_id", "baseline_template_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    client_tenant_id: Mapped[str] = mapped_column(ForeignKey("client_tenant.id", ondelete="CASCADE"), index=True)
    baseline_template_id: Mapped[str] = mapped_column(ForeignKey("baseline_template.id"), index=True)
    assigned_by: Mapped[str] = mapped_column(ForeignKey("staff_user.id"))
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class DriftEvent(Base):
    __tablename__ = "drift_event"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    client_tenant_id: Mapped[str] = mapped_column(ForeignKey("client_tenant.id", ondelete="CASCADE"), index=True)
    baseline_template_id: Mapped[str] = mapped_column(ForeignKey("baseline_template.id"))
    differences: Mapped[list] = mapped_column(JSON)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)


class Alert(Base):
    __tablename__ = "alert"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    client_tenant_id: Mapped[str] = mapped_column(ForeignKey("client_tenant.id", ondelete="CASCADE"), index=True)
    drift_event_id: Mapped[str | None] = mapped_column(ForeignKey("drift_event.id", ondelete="SET NULL"), nullable=True)
    severity: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(200))
    message: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
