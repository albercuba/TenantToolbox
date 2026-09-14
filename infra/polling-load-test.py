"""Bounded polling-load helper; run against an already configured API."""
import argparse
import concurrent.futures
import time

import httpx


def poll(base_url: str, token: str, tenant_id: str) -> tuple[str, int, float]:
    started = time.perf_counter()
    response = httpx.post(f"{base_url}/api/tenants/{tenant_id}/sync", headers={"Authorization": f"Bearer {token}"}, timeout=60)
    return tenant_id, response.status_code, time.perf_counter() - started


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--tenant", action="append", required=True)
    parser.add_argument("--workers", type=int, default=10)
    args = parser.parse_args()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        results = list(executor.map(lambda tenant: poll(args.base_url, args.token, tenant), args.tenant))
    for tenant_id, status, duration in results:
        print(f"{tenant_id} status={status} duration={duration:.2f}s")


if __name__ == "__main__":
    main()
