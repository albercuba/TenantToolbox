from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.graph import GraphAPIError, GraphClient
from app.models import (
    AuditLog,
    ClientTenant,
    DeviceCompliancePolicyAssignment,
    DeviceCompliancePolicyTemplate,
    DistributionList,
    GroupMembership,
    OffboardingHistory,
    OffboardingWorkflow,
    StaffUser,
    UserGroup,
)
from app.security import get_current_user, require_owner

router = APIRouter()


class GroupRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = ""


class MemberRequest(BaseModel):
    tenant_id: str
    user_id: str
    confirm: bool = False


class DistributionListRequest(BaseModel):
    display_name: str = Field(min_length=1, max_length=200)
    email: str = Field(min_length=3, max_length=320)
    confirm: bool = False


class OffboardingRequest(BaseModel):
    action: str = "start"
    confirm: bool = False
    sku_ids: list[str] = Field(default_factory=list)
    group_ids: list[str] = Field(default_factory=list)


class PolicyTemplateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    definition: dict


class PolicyAssignmentRequest(BaseModel):
    template_id: str
    confirm: bool = False


def tenant_access(tenant_id: str, user: StaffUser, db: Session) -> ClientTenant:
    tenant = db.scalar(select(ClientTenant).where(ClientTenant.id == tenant_id, ClientTenant.organization_id == user.organization_id))
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


def audit(db: Session, user: StaffUser, action: str, tenant_id: str | None, payload: dict) -> None:
    db.add(AuditLog(organization_id=user.organization_id, actor_id=user.id, client_tenant_id=tenant_id, action=action, target_type="client_tenant" if tenant_id else None, target_id=tenant_id, payload=payload))


def group_access(group_id: str, user: StaffUser, db: Session) -> UserGroup:
    group = db.scalar(select(UserGroup).where(UserGroup.id == group_id, UserGroup.organization_id == user.organization_id))
    if not group:
        raise HTTPException(status_code=404, detail="User group not found")
    return group


@router.get("/api/user-groups")
def list_groups(user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    groups = db.scalars(select(UserGroup).where(UserGroup.organization_id == user.organization_id).order_by(UserGroup.name)).all()
    return [{"id": item.id, "name": item.name, "description": item.description, "created_at": item.created_at} for item in groups]


@router.post("/api/user-groups", status_code=status.HTTP_201_CREATED)
def create_group(payload: GroupRequest, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict:
    if db.scalar(select(UserGroup).where(UserGroup.organization_id == user.organization_id, UserGroup.name == payload.name.strip())):
        raise HTTPException(status_code=409, detail="User group already exists")
    group = UserGroup(organization_id=user.organization_id, name=payload.name.strip(), description=payload.description.strip())
    db.add(group)
    db.flush()
    audit(db, user, "user_group.create", None, {"group_id": group.id})
    db.commit()
    return {"id": group.id, "name": group.name, "description": group.description}


@router.get("/api/user-groups/{group_id}/members")
def list_group_members(group_id: str, user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    group_access(group_id, user, db)
    rows = db.scalars(select(GroupMembership).where(GroupMembership.user_group_id == group_id).order_by(GroupMembership.added_at)).all()
    return [{"id": row.id, "tenant_id": row.client_tenant_id, "user_id": row.graph_user_id, "added_at": row.added_at} for row in rows]


@router.post("/api/user-groups/{group_id}/members", status_code=status.HTTP_201_CREATED)
def add_group_member(group_id: str, payload: MemberRequest, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict:
    if not payload.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to change group membership")
    group_access(group_id, user, db)
    tenant = tenant_access(payload.tenant_id, user, db)
    if db.scalar(select(GroupMembership).where(GroupMembership.user_group_id == group_id, GroupMembership.client_tenant_id == tenant.id, GroupMembership.graph_user_id == payload.user_id)):
        raise HTTPException(status_code=409, detail="User is already in this group")
    membership = GroupMembership(user_group_id=group_id, client_tenant_id=tenant.id, graph_user_id=payload.user_id, added_by=user.id)
    db.add(membership)
    db.flush()
    audit(db, user, "user_group.member_add", tenant.id, {"group_id": group_id, "user_id": payload.user_id})
    db.commit()
    return {"id": membership.id, "tenant_id": tenant.id, "user_id": membership.graph_user_id}


@router.delete("/api/user-groups/{group_id}/members/{membership_id}")
def remove_group_member(group_id: str, membership_id: str, confirm: bool = Query(False), user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict[str, str]:
    if not confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to change group membership")
    group_access(group_id, user, db)
    membership = db.scalar(select(GroupMembership).where(GroupMembership.id == membership_id, GroupMembership.user_group_id == group_id))
    if not membership:
        raise HTTPException(status_code=404, detail="Group membership not found")
    audit(db, user, "user_group.member_remove", membership.client_tenant_id, {"group_id": group_id, "user_id": membership.graph_user_id})
    db.delete(membership)
    db.commit()
    return {"status": "removed"}


@router.get("/api/tenants/{tenant_id}/distribution-lists")
def list_distribution_lists(tenant_id: str, user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    tenant_access(tenant_id, user, db)
    rows = db.scalars(select(DistributionList).where(DistributionList.client_tenant_id == tenant_id, DistributionList.organization_id == user.organization_id).order_by(DistributionList.display_name)).all()
    return [{"id": row.id, "graph_id": row.graph_id, "display_name": row.display_name, "email": row.email, "created_at": row.created_at} for row in rows]


@router.post("/api/tenants/{tenant_id}/distribution-lists", status_code=status.HTTP_201_CREATED)
def create_distribution_list(tenant_id: str, payload: DistributionListRequest, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict:
    if not payload.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to create a distribution list")
    tenant = tenant_access(tenant_id, user, db)
    if not tenant.credential:
        raise HTTPException(status_code=409, detail="Tenant has no delegated credential")
    try:
        graph_id = GraphClient(tenant, tenant.credential).create_distribution_list(payload.display_name.strip(), str(payload.email).lower())
    except GraphAPIError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    row = DistributionList(organization_id=user.organization_id, client_tenant_id=tenant.id, graph_id=graph_id, display_name=payload.display_name.strip(), email=str(payload.email).lower(), created_by=user.id)
    db.add(row)
    db.flush()
    audit(db, user, "distribution_list.create", tenant.id, {"distribution_list_id": row.id, "graph_id": graph_id})
    db.commit()
    return {"id": row.id, "graph_id": row.graph_id, "display_name": row.display_name, "email": row.email}


@router.get("/api/tenants/{tenant_id}/offboarding/{user_id}")
def get_offboarding(tenant_id: str, user_id: str, user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    tenant_access(tenant_id, user, db)
    workflow = db.scalar(select(OffboardingWorkflow).where(OffboardingWorkflow.client_tenant_id == tenant_id, OffboardingWorkflow.graph_user_id == user_id))
    if not workflow:
        raise HTTPException(status_code=404, detail="Offboarding workflow not found")
    history = db.scalars(select(OffboardingHistory).where(OffboardingHistory.workflow_id == workflow.id).order_by(OffboardingHistory.created_at)).all()
    return {"id": workflow.id, "tenant_id": tenant_id, "user_id": user_id, "state": workflow.state, "completed_steps": workflow.completed_steps, "history": [{"action": item.action, "status": item.status, "details": item.details, "created_at": item.created_at} for item in history]}


@router.post("/api/tenants/{tenant_id}/offboarding/{user_id}")
def run_offboarding(tenant_id: str, user_id: str, payload: OffboardingRequest, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict:
    if not payload.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to execute offboarding")
    if payload.action not in {"start", "revoke_sessions", "remove_licenses", "remove_groups", "disable_account"}:
        raise HTTPException(status_code=400, detail="Unsupported offboarding action")
    if payload.action == "remove_licenses" and not payload.sku_ids:
        raise HTTPException(status_code=400, detail="sku_ids is required when removing licenses")
    if payload.action == "remove_groups" and not payload.group_ids:
        raise HTTPException(status_code=400, detail="group_ids is required when removing groups")
    tenant = tenant_access(tenant_id, user, db)
    if not tenant.credential:
        raise HTTPException(status_code=409, detail="Tenant has no delegated credential")
    workflow = db.scalar(select(OffboardingWorkflow).where(OffboardingWorkflow.client_tenant_id == tenant.id, OffboardingWorkflow.graph_user_id == user_id))
    if not workflow:
        workflow = OffboardingWorkflow(client_tenant_id=tenant.id, graph_user_id=user_id, created_by=user.id)
        db.add(workflow)
        db.flush()
    action = "revoke_sessions" if payload.action == "start" else payload.action
    if action in workflow.completed_steps:
        return {"id": workflow.id, "state": workflow.state, "completed_steps": workflow.completed_steps}
    client = GraphClient(tenant, tenant.credential)
    try:
        if action == "revoke_sessions":
            client.revoke_sessions(user_id)
        elif action == "remove_licenses":
            for sku_id in payload.sku_ids:
                client.update_license(user_id, sku_id, False)
        elif action == "remove_groups":
            for group_id in payload.group_ids:
                client.remove_user_from_group(group_id, user_id)
        else:
            client.disable_user(user_id)
    except GraphAPIError as exc:
        workflow.state = "failed"
        db.add(OffboardingHistory(workflow_id=workflow.id, action=action, status="failed", details={"error": str(exc)}, actor_id=user.id))
        audit(db, user, "offboarding.step_failed", tenant.id, {"workflow_id": workflow.id, "action": action})
        db.commit()
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    workflow.completed_steps = [*workflow.completed_steps, action]
    workflow.state = "completed" if "revoke_sessions" in workflow.completed_steps and "disable_account" in workflow.completed_steps else "in_progress"
    workflow.updated_at = datetime.now(timezone.utc)
    db.add(OffboardingHistory(workflow_id=workflow.id, action=action, status="completed", details={}, actor_id=user.id))
    audit(db, user, "offboarding.step_completed", tenant.id, {"workflow_id": workflow.id, "action": action})
    db.commit()
    return {"id": workflow.id, "state": workflow.state, "completed_steps": workflow.completed_steps}


@router.get("/api/device-compliance-policy-templates")
def list_policy_templates(user: StaffUser = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    rows = db.scalars(select(DeviceCompliancePolicyTemplate).where(DeviceCompliancePolicyTemplate.organization_id == user.organization_id).order_by(DeviceCompliancePolicyTemplate.name)).all()
    return [{"id": row.id, "name": row.name, "description": row.description, "definition": row.definition, "is_builtin": row.is_builtin} for row in rows]


@router.post("/api/device-compliance-policy-templates", status_code=status.HTTP_201_CREATED)
def create_policy_template(payload: PolicyTemplateRequest, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict:
    if db.scalar(select(DeviceCompliancePolicyTemplate).where(DeviceCompliancePolicyTemplate.organization_id == user.organization_id, DeviceCompliancePolicyTemplate.name == payload.name.strip())):
        raise HTTPException(status_code=409, detail="Policy template already exists")
    row = DeviceCompliancePolicyTemplate(organization_id=user.organization_id, name=payload.name.strip(), description=payload.description.strip(), definition=payload.definition)
    db.add(row)
    db.flush()
    audit(db, user, "device_policy_template.create", None, {"template_id": row.id})
    db.commit()
    return {"id": row.id, "name": row.name, "description": row.description, "definition": row.definition}


@router.post("/api/tenants/{tenant_id}/device-compliance-policies")
def assign_policy_template(tenant_id: str, payload: PolicyAssignmentRequest, user: StaffUser = Depends(require_owner), db: Session = Depends(get_db)) -> dict:
    if not payload.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to assign a device compliance policy")
    tenant = tenant_access(tenant_id, user, db)
    template = db.scalar(select(DeviceCompliancePolicyTemplate).where(DeviceCompliancePolicyTemplate.id == payload.template_id, DeviceCompliancePolicyTemplate.organization_id == user.organization_id))
    if not template:
        raise HTTPException(status_code=404, detail="Policy template not found")
    if not tenant.credential:
        raise HTTPException(status_code=409, detail="Tenant has no delegated credential")
    try:
        graph_id = GraphClient(tenant, tenant.credential).upsert_compliance_policy(template.name, template.definition)
    except GraphAPIError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    assignment = db.scalar(select(DeviceCompliancePolicyAssignment).where(DeviceCompliancePolicyAssignment.client_tenant_id == tenant.id, DeviceCompliancePolicyAssignment.template_id == template.id))
    if not assignment:
        assignment = DeviceCompliancePolicyAssignment(client_tenant_id=tenant.id, template_id=template.id, assigned_by=user.id)
        db.add(assignment)
    audit(db, user, "device_policy_template.assign", tenant.id, {"template_id": template.id, "graph_id": graph_id})
    db.commit()
    return {"template_id": template.id, "tenant_id": tenant.id, "graph_id": graph_id, "status": "assigned"}
