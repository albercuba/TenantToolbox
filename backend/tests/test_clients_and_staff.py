from typing import cast

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db import Base
from app.main import StaffUserRequest, client_to_response, create_staff_user, delete_client, delete_staff_user, update_staff_user
from app.models import Client, ClientTenant, Organization, StaffUser
from app.security import create_oauth_state, verify_oauth_state


def make_session() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_client_delete_is_blocked_when_tenant_is_assigned():
    with make_session() as db:
        organization = Organization(name="Org")
        owner = StaffUser(email="owner@example.com", password_hash="hash", role="owner", organization=organization)
        client = Client(name="Acme", organization=organization)
        db.add_all([organization, owner, client])
        db.flush()
        db.add(ClientTenant(organization_id=organization.id, client_id=client.id, tenant_id="tenant-1", display_name="Acme M365"))
        db.commit()

        with pytest.raises(HTTPException) as error:
            delete_client(client.id, cast(StaffUser, owner), db)
        assert error.value.status_code == 409


def test_client_response_contains_frontend_tenant_summary():
    with make_session() as db:
        organization = Organization(name="Org")
        client = Client(name="Acme", organization=organization)
        db.add_all([organization, client])
        db.flush()
        tenant = ClientTenant(
            organization_id=organization.id,
            client_id=client.id,
            tenant_id="tenant-1",
            display_name="Acme M365",
            connection_status="connected",
        )
        db.add(tenant)
        db.commit()

        response = client_to_response(client, db)
        assert response["tenants"] == [
            {
                "id": tenant.id,
                "name": "Acme M365",
                "domain": "tenant-1",
                "status": "Connected",
                "connection_status": "connected",
                "last_connected_at": None,
                "last_error": None,
            }
        ]


def test_local_user_creation_requires_password_and_accepts_requested_roles():
    with make_session() as db:
        organization = Organization(name="Org")
        owner = StaffUser(email="owner@example.com", password_hash="hash", role="owner", organization=organization)
        db.add_all([organization, owner])
        db.flush()

        with pytest.raises(HTTPException) as error:
            create_staff_user(StaffUserRequest(email="tech@example.com", password="short", role="technician"), owner, db)
        assert error.value.status_code == 400

        created = create_staff_user(StaffUserRequest(email="tech@example.com", password="a-secure-password", role="technician"), owner, db)
        assert created["email"] == "tech@example.com"
        assert created["role"] == "technician"


def test_last_owner_cannot_be_deleted_or_demoted():
    with make_session() as db:
        organization = Organization(name="Org")
        owner = StaffUser(email="owner@example.com", password_hash="hash", role="owner", organization=organization)
        db.add_all([organization, owner])
        db.commit()

        with pytest.raises(HTTPException) as error:
            delete_staff_user(owner.id, owner, db)
        assert error.value.status_code == 409

        with pytest.raises(HTTPException) as error:
            update_staff_user(owner.id, StaffUserRequest(email=owner.email, role="technician"), owner, db)
        assert error.value.status_code == 409


def test_tenant_disconnect_removes_tenant_record():
    from app.main import disconnect_tenant

    with make_session() as db:
        organization = Organization(name="Org")
        owner = StaffUser(email="owner@example.com", password_hash="hash", role="owner", organization=organization)
        tenant = ClientTenant(organization=organization, tenant_id="tenant-1", display_name="Acme M365")
        db.add_all([organization, owner, tenant])
        db.commit()

        disconnect_tenant(tenant.id, owner, db)
        assert db.get(ClientTenant, tenant.id) is None


def test_oauth_state_carries_client_context_without_exposing_credentials():
    state = create_oauth_state("user-1", client_id="client-1")
    payload = verify_oauth_state(state)
    assert payload["sub"] == "user-1"
    assert payload["client_id"] == "client-1"
    assert "password" not in payload
    assert "secret" not in payload
