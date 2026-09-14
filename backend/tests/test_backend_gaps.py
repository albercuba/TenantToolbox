from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from sqlalchemy import create_engine, text

from app.migration_runner import apply_migrations
from app.rbac import has_permission, role_permissions


def test_role_permission_matrix_is_explicit():
    assert role_permissions(cast(Any, SimpleNamespace(role="owner"))) == {
        "read": True,
        "operate": True,
        "manage": True,
        "admin": True,
    }
    assert has_permission(cast(Any, SimpleNamespace(role="l1")), "operate")
    assert has_permission(cast(Any, SimpleNamespace(role="l2")), "read")
    assert not has_permission(cast(Any, SimpleNamespace(role="l3")), "operate")
    assert not has_permission(cast(Any, SimpleNamespace(role="unknown")), "read")


def test_migrations_are_ordered_and_idempotent(tmp_path: Path):
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "001_first.sql").write_text("CREATE TABLE first (id INTEGER PRIMARY KEY);", encoding="utf-8")
    (migrations / "002_second.sql").write_text("ALTER TABLE first ADD COLUMN name VARCHAR(20);", encoding="utf-8")
    engine = create_engine("sqlite://")

    assert apply_migrations(engine, migrations) == ["001_first.sql", "002_second.sql"]
    assert apply_migrations(engine, migrations) == []
    with engine.connect() as connection:
        assert connection.execute(text("SELECT version FROM schema_migrations ORDER BY version")).scalars().all() == [
            "001_first.sql",
            "002_second.sql",
        ]
        assert [column[1] for column in connection.execute(text("PRAGMA table_info(first)"))] == ["id", "name"]
