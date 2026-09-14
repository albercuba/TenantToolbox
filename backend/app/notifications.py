import smtplib
from email.message import EmailMessage

import httpx

from app.config import settings
from app.psa import ticket_payload


def send_alert_email(subject: str, body: str, recipient: str | None = None) -> bool:
    recipient = recipient or settings.alert_email
    if not settings.smtp_host or not recipient:
        return False
    message = EmailMessage()
    message["From"] = settings.smtp_from or recipient
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
        if settings.smtp_tls:
            smtp.starttls()
        if settings.smtp_username and settings.smtp_password:
            smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(message)
    return True


def send_report_email(recipient: str, title: str, body: str) -> bool:
    return send_alert_email(title, body, recipient)


def send_psa_webhook(payload: dict) -> bool:
    if not settings.psa_webhook_url:
        return False
    response = httpx.post(settings.psa_webhook_url, json=payload, timeout=15)
    response.raise_for_status()
    return True


def send_psa_ticket(*, title: str, description: str, severity: str, tenant_id: str, source: str) -> bool:
    """Send a vendor-shaped ticket payload to the configured PSA webhook."""
    payload = ticket_payload(settings.psa_vendor, title=title, description=description, severity=severity, tenant_id=tenant_id, source=source)
    return send_psa_webhook(payload)
