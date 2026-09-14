from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from cryptography.fernet import Fernet
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.models import StaffUser

password_hasher = PasswordHasher()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except VerificationError:
        return False


def create_access_token(user: StaffUser) -> str:
    expires = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    return jwt.encode({"sub": user.id, "role": user.role, "exp": expires}, settings.jwt_secret, algorithm="HS256")


def create_oauth_state(user_id: str, tenant_id: str | None = None) -> str:
    expires = datetime.now(timezone.utc) + timedelta(minutes=10)
    return jwt.encode({"sub": user_id, "tenant_id": tenant_id, "purpose": "oauth", "exp": expires}, settings.jwt_secret, algorithm="HS256")


def verify_oauth_state(state: str) -> dict:
    payload = jwt.decode(state, settings.jwt_secret, algorithms=["HS256"])
    if payload.get("purpose") != "oauth" or not payload.get("sub"):
        raise jwt.InvalidTokenError("Invalid OAuth state purpose")
    return payload


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> StaffUser:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
        user_id = payload.get("sub")
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token") from exc
    user = db.get(StaffUser, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def require_owner(user: StaffUser = Depends(get_current_user)) -> StaffUser:
    if user.role != "owner":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Owner role required")
    return user


def credential_cipher() -> Fernet:
    key = settings.credential_key
    if not key:
        raise RuntimeError("CREDENTIAL_ENCRYPTION_KEY must be configured before storing tenant credentials")
    return Fernet(key.encode())


def encrypt_credential(value: str) -> str:
    return credential_cipher().encrypt(value.encode()).decode()


def decrypt_credential(value: str) -> str:
    return credential_cipher().decrypt(value.encode()).decode()
