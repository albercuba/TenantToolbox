from app.db import engine
from app.migration_runner import apply_migrations


if __name__ == "__main__":
    applied = apply_migrations(engine)
    print(f"Applied {len(applied)} migration(s): {', '.join(applied) or 'none'}")
