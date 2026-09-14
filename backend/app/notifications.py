import smtplib
from email.message import EmailMessage

from app.config import settings


def send_alert_email(subject: str, body: str) -> bool:
    if not settings.smtp_host or not settings.alert_email:
        return False
    message = EmailMessage()
    message["From"] = settings.smtp_from or settings.alert_email
    message["To"] = settings.alert_email
    message["Subject"] = subject
    message.set_content(body)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
        if settings.smtp_tls:
            smtp.starttls()
        if settings.smtp_username and settings.smtp_password:
            smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(message)
    return True
