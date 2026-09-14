# Database migrations

The backend keeps deployment schema changes in `backend/migrations/` as numbered SQL
files. Apply them from the backend directory with:

```sh
python run_migrations.py
```

The runner creates `schema_migrations`, applies files in lexical/number order, and
records each filename in the same transaction. Running it again is safe and applies
only files that are not recorded. The application startup still uses SQLAlchemy's
`create_all` for local development; production deployments should run the migration
command before starting the API and worker.

Set `DATABASE_URL` to the target PostgreSQL connection string in deployment. The
runner also supports the default SQLite development database for local validation.
Do not edit an already-applied migration; add the next numbered migration instead.
