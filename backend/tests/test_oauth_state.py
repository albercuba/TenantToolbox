
import jwt
import pytest

from app.security import create_oauth_state, verify_oauth_state


def test_oauth_state_is_signed_and_contains_tenant_context():
    state = create_oauth_state("user-1", "tenant-1")
    payload = verify_oauth_state(state)
    assert payload["sub"] == "user-1"
    assert payload["tenant_id"] == "tenant-1"
    assert payload["purpose"] == "oauth"


def test_oauth_state_rejects_tampering():
    state = create_oauth_state("user-1")
    with pytest.raises(jwt.PyJWTError):
        verify_oauth_state(state + "tampered")
