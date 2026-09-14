"""Small, dependency-free SQL migration runner for deployment environments."""

from pathlib import Path

from sqlalchemy import text
from sqlalchemy.engine import Engine


MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "migrations"


def _statements(sql: str, dialect_name: str) -> list[str]:
    if dialect_name == "sqlite":
        sql = (sql.replace("TIMESTAMPTZ", "DATETIME")
               .replace("JSONB", "JSON")
               .replace("::jsonb", "")
               .replace("DEFAULT NOW()", "DEFAULT CURRENT_TIMESTAMP"))
    return [statement.strip() for statement in sql.split(";") if statement.strip()]


def apply_migrations(engine: Engine, migrations_dir: Path = MIGRATIONS_DIR) -> list[str]:
    """Apply each unapplied numbered migration once and return applied names."""
    applied: list[str] = []
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE IF NOT EXISTS schema_migrations (version VARCHAR(100) PRIMARY KEY, applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)"))
        existing = {row[0] for row in connection.execute(text("SELECT version FROM schema_migrations"))}
        for path in sorted(migrations_dir.glob("*.sql")):
            if path.name in existing:
                continue
            for statement in _statements(path.read_text(encoding="utf-8"), engine.dialect.name):
                connection.exec_driver_sql(statement)
            connection.execute(text("INSERT INTO schema_migrations (version) VALUES (:version)"), {"version": path.name})
            applied.append(path.name)
    return applied
