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
    entra_prospect_redirect_uri: str = os.getenv("ENTRA_PROSPECT_REDIRECT_URI", "http://localhost:8000/api/prospect/callback")
    frontend_url: str = os.getenv("FRONTEND_URL", "http://localhost:5173")
    smtp_host: str | None = os.getenv("SMTP_HOST")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_tls: bool = os.getenv("SMTP_TLS", "true").lower() == "true"
    smtp_username: str | None = os.getenv("SMTP_USERNAME")
    smtp_password: str | None = os.getenv("SMTP_PASSWORD")
    smtp_from: str | None = os.getenv("SMTP_FROM")
    alert_email: str | None = os.getenv("ALERT_EMAIL")
    psa_webhook_url: str | None = os.getenv("PSA_WEBHOOK_URL")
    auto_remediation_enabled: bool = os.getenv("AUTO_REMEDIATION_ENABLED", "false").lower() == "true"


settings = Settings()
