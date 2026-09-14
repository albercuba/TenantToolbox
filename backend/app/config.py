import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./tenanttoolbox.db")
    jwt_secret: str = os.getenv("JWT_SECRET", "development-secret-change-before-deploy-32")
    jwt_expire_minutes: int = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
    credential_key: str | None = os.getenv("CREDENTIAL_ENCRYPTION_KEY")
    entra_client_id: str | None = os.getenv("ENTRA_CLIENT_ID")
    entra_client_secret: str | None = os.getenv("ENTRA_CLIENT_SECRET")
    entra_redirect_uri: str = os.getenv("ENTRA_REDIRECT_URI", "http://localhost:8000/api/auth/microsoft/callback")
    frontend_url: str = os.getenv("FRONTEND_URL", "http://localhost:5173")


settings = Settings()
