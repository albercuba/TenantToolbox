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
    branding_color: Mapped[str] = mapped_column(String(20), default="#2490ef")
    branding_logo_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    staff_users: Mapped[list["StaffUser"]] = relationship(back_populates="organization")
    clients: Mapped[list["Client"]] = relationship(back_populates="organization")
    tenants: Mapped[list["ClientTenant"]] = relationship(back_populates="organization")
    staff_groups: Mapped[list["StaffGroup"]] = relationship(back_populates="organization")


class Client(Base):
    __tablename__ = "client"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organization.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    organization: Mapped[Organization] = relationship(back_populates="clients")
    tenants: Mapped[list["ClientTenant"]] = relationship(back_populates="client")


class StaffGroup(Base):
    __tablename__ = "staff_group"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organization.id"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    organization: Mapped[Organization] = relationship(back_populates="staff_groups")


class StaffGroupMembership(Base):
    __tablename__ = "staff_group_membership"
    __table_args__ = (UniqueConstraint("staff_group_id", "staff_user_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    staff_group_id: Mapped[str] = mapped_column(ForeignKey("staff_group.id", ondelete="CASCADE"), index=True)
    staff_user_id: Mapped[str] = mapped_column(ForeignKey("staff_user.id", ondelete="CASCADE"), index=True)
    assigned_by: Mapped[str] = mapped_column(ForeignKey("staff_user.id"))
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


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
    client_id: Mapped[str | None] = mapped_column(ForeignKey("client.id"), index=True, nullable=True)
    tenant_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    primary_domain: Mapped[str | None] = mapped_column(String(320), nullable=True)
    display_name: Mapped[str] = mapped_column(String(200))
    connection_status: Mapped[str] = mapped_column(String(30), default="pending")
    last_connected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    organization: Mapped[Organization] = relationship(back_populates="tenants")
    client: Mapped["Client | None"] = relationship(back_populates="tenants")
    credential: Mapped["TenantCredential | None"] = relationship(back_populates="tenant", uselist=False, cascade="all, delete-orphan")


class GdapRelationship(Base):
    __tablename__ = "gdap_relationship"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organization.id"), index=True)
    client_tenant_id: Mapped[str | None] = mapped_column(ForeignKey("client_tenant.id", ondelete="SET NULL"), index=True, nullable=True)
    customer_tenant_id: Mapped[str] = mapped_column(String(36), index=True)
    graph_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    display_name: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(30), default="pending")
    approval_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)


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
    department: Mapped[str | None] = mapped_column(String(200), nullable=True)
    license_types: Mapped[list] = mapped_column(JSON, default=list)
    groups: Mapped[list] = mapped_column(JSON, default=list)
    mfa_settings: Mapped[str] = mapped_column(String(100), default="Unavailable")
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
    source: Mapped[str] = mapped_column(String(50), default="drift")
    external_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    psa_ticket_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    remediation_status: Mapped[str] = mapped_column(String(30), default="not_requested")


class AlertRule(Base):
    __tablename__ = "alert_rule"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organization.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    min_severity: Mapped[str] = mapped_column(String(20), default="medium")
    enabled: Mapped[bool] = mapped_column(default=True)
    suppress_minutes: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class ComplianceControl(Base):
    __tablename__ = "compliance_control"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    framework: Mapped[str] = mapped_column(String(50), index=True)
    control_id: Mapped[str] = mapped_column(String(100))
    title: Mapped[str] = mapped_column(String(200))
    baseline_control: Mapped[str] = mapped_column(String(100))


class Report(Base):
    __tablename__ = "report"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organization.id"), index=True)
    client_tenant_id: Mapped[str] = mapped_column(ForeignKey("client_tenant.id", ondelete="CASCADE"), index=True)
    report_type: Mapped[str] = mapped_column(String(50))
    title: Mapped[str] = mapped_column(String(200))
    content: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(ForeignKey("staff_user.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    public_token_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True)
    public_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ReportSchedule(Base):
    __tablename__ = "report_schedule"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organization.id"), index=True)
    client_tenant_id: Mapped[str] = mapped_column(ForeignKey("client_tenant.id", ondelete="CASCADE"), index=True)
    cadence: Mapped[str] = mapped_column(String(20))
    recipient_email: Mapped[str] = mapped_column(String(320))
    enabled: Mapped[bool] = mapped_column(default=True)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class TenantDeviceSnapshot(Base):
    __tablename__ = "tenant_device_snapshot"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    client_tenant_id: Mapped[str] = mapped_column(ForeignKey("client_tenant.id", ondelete="CASCADE"), index=True)
    graph_id: Mapped[str] = mapped_column(String(100))
    device_name: Mapped[str] = mapped_column(String(200))
    operating_system: Mapped[str | None] = mapped_column(String(100), nullable=True)
    compliance_state: Mapped[str | None] = mapped_column(String(50), nullable=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class DiscoveredApp(Base):
    __tablename__ = "discovered_app"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    client_tenant_id: Mapped[str] = mapped_column(ForeignKey("client_tenant.id", ondelete="CASCADE"), index=True)
    graph_id: Mapped[str] = mapped_column(String(100))
    display_name: Mapped[str] = mapped_column(String(200))
    publisher: Mapped[str | None] = mapped_column(String(200), nullable=True)
    permission_scopes: Mapped[list] = mapped_column(JSON)
    risk_score: Mapped[int] = mapped_column(default=0)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ProspectAssessment(Base):
    __tablename__ = "prospect_assessment"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organization.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True)
    status: Mapped[str] = mapped_column(String(30), default="pending")
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    report_content: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class UserGroup(Base):
    __tablename__ = "user_group"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organization.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class GroupMembership(Base):
    __tablename__ = "group_membership"
    __table_args__ = (UniqueConstraint("user_group_id", "client_tenant_id", "graph_user_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_group_id: Mapped[str] = mapped_column(ForeignKey("user_group.id", ondelete="CASCADE"), index=True)
    client_tenant_id: Mapped[str] = mapped_column(ForeignKey("client_tenant.id", ondelete="CASCADE"), index=True)
    graph_user_id: Mapped[str] = mapped_column(String(100))
    added_by: Mapped[str] = mapped_column(ForeignKey("staff_user.id"))
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class DistributionList(Base):
    __tablename__ = "distribution_list"
    __table_args__ = (UniqueConstraint("organization_id", "client_tenant_id", "email"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organization.id"), index=True)
    client_tenant_id: Mapped[str] = mapped_column(ForeignKey("client_tenant.id", ondelete="CASCADE"), index=True)
    graph_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    display_name: Mapped[str] = mapped_column(String(200))
    email: Mapped[str] = mapped_column(String(320))
    created_by: Mapped[str] = mapped_column(ForeignKey("staff_user.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class OffboardingWorkflow(Base):
    __tablename__ = "offboarding_workflow"
    __table_args__ = (UniqueConstraint("client_tenant_id", "graph_user_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    client_tenant_id: Mapped[str] = mapped_column(ForeignKey("client_tenant.id", ondelete="CASCADE"), index=True)
    graph_user_id: Mapped[str] = mapped_column(String(100))
    state: Mapped[str] = mapped_column(String(30), default="pending")
    completed_steps: Mapped[list] = mapped_column(JSON, default=list)
    created_by: Mapped[str] = mapped_column(ForeignKey("staff_user.id"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class OffboardingHistory(Base):
    __tablename__ = "offboarding_history"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    workflow_id: Mapped[str] = mapped_column(ForeignKey("offboarding_workflow.id", ondelete="CASCADE"), index=True)
    action: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(30))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    actor_id: Mapped[str] = mapped_column(ForeignKey("staff_user.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class DeviceCompliancePolicyTemplate(Base):
    __tablename__ = "device_compliance_policy_template"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organization.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    definition: Mapped[dict] = mapped_column(JSON)
    is_builtin: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class DeviceCompliancePolicyAssignment(Base):
    __tablename__ = "device_compliance_policy_assignment"
    __table_args__ = (UniqueConstraint("client_tenant_id", "template_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    client_tenant_id: Mapped[str] = mapped_column(ForeignKey("client_tenant.id", ondelete="CASCADE"), index=True)
    template_id: Mapped[str] = mapped_column(ForeignKey("device_compliance_policy_template.id", ondelete="CASCADE"), index=True)
    assigned_by: Mapped[str] = mapped_column(ForeignKey("staff_user.id"))
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
