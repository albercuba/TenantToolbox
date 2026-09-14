import os
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.db import SessionLocal
from app.models import ClientTenant, ReportSchedule
from app.notifications import send_alert_email, send_report_email
from app.sync import detect_scheduled_drift, sync_connected_tenants


def deliver_due_reports() -> int:
    db = SessionLocal()
    delivered = 0
    try:
        now = datetime.now(timezone.utc)
        schedules = db.scalars(select(ReportSchedule).where(ReportSchedule.enabled.is_(True), ReportSchedule.next_run_at <= now)).all()
        for schedule in schedules:
            tenant = db.get(ClientTenant, schedule.client_tenant_id)
            if not tenant:
                continue
            if send_report_email(schedule.recipient_email, f"{tenant.display_name} security report", f"TenantToolbox scheduled security report for {tenant.display_name}. Generated {now.isoformat()}."):
                days = {"weekly": 7, "monthly": 30, "quarterly": 90}[schedule.cadence]
                schedule.next_run_at = now + timedelta(days=days)
                delivered += 1
        db.commit()
        return delivered
    finally:
        db.close()


def run_graph_sync() -> int:
    db = SessionLocal()
    try:
        return sync_connected_tenants(db)
    finally:
        db.close()


if __name__ == "__main__":
    interval = int(os.getenv("GRAPH_SYNC_INTERVAL_SECONDS", "900"))
    while True:
        synced = run_graph_sync()
        db = SessionLocal()
        try:
            drifted = detect_scheduled_drift(db)
        finally:
            db.close()
        if drifted:
            send_alert_email("TenantToolbox baseline drift detected", f"{drifted} baseline drift event(s) require review.")
        delivered = deliver_due_reports()
        print(f"Synchronized {synced} tenants; detected {drifted} drift event(s); delivered {delivered} report(s)", flush=True)
        time.sleep(interval)
