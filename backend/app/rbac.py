"""Role and permission policy for the staff API."""

from collections.abc import Callable

from fastapi import Depends, HTTPException, status

from app.models import StaffUser
from app.security import get_current_user

ROLES = ("owner", "l1", "l2", "l3")

# Higher numbered support levels are intentionally read-only. Owners retain
# administrative access; L1/L2/L3 permissions are explicit rather than inferred.
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "owner": frozenset({"read", "operate", "manage", "admin"}),
    "l1": frozenset({"read", "operate"}),
    "l2": frozenset({"read", "operate"}),
    "l3": frozenset({"read"}),
}


def has_permission(user: StaffUser, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(user.role.lower(), frozenset())


def require_permission(permission: str) -> Callable:
    def dependency(user: StaffUser = Depends(get_current_user)) -> StaffUser:
        if not has_permission(user, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission required: {permission}",
            )
        return user

    return dependency


def role_permissions(user: StaffUser) -> dict[str, bool]:
    return {
        permission: has_permission(user, permission)
        for permission in ("read", "operate", "manage", "admin")
    }
