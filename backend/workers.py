import os
import time

from app.db import SessionLocal
from app.notifications import send_alert_email
from app.sync import detect_scheduled_drift, sync_connected_tenants


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
        print(f"Synchronized {synced} tenants; detected {drifted} drift event(s)", flush=True)
        time.sleep(interval)
