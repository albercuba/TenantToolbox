from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_check() -> None:
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "tenanttoolbox-api"}


def test_tenants_start_empty() -> None:
    response = client.get("/api/tenants")

    assert response.status_code == 200
    assert response.json() == []
