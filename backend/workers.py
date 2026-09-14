import os
import time

from app.db import SessionLocal
from app.sync import sync_connected_tenants


def run_graph_sync() -> int:
    db = SessionLocal()
    try:
        return sync_connected_tenants(db)
    finally:
        db.close()


if __name__ == "__main__":
    interval = int(os.getenv("GRAPH_SYNC_INTERVAL_SECONDS", "900"))
    while True:
        print(f"Synchronized {run_graph_sync()} connected tenants", flush=True)
        time.sleep(interval)
