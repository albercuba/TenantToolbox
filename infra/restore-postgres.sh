#!/bin/sh
set -eu
: "${POSTGRES_HOST:=localhost}"
: "${POSTGRES_PORT:=5432}"
: "${POSTGRES_DB:=tenanttoolbox}"
: "${POSTGRES_USER:=tenanttoolbox}"
: "${BACKUP_FILE:?Set BACKUP_FILE to a pg_dump custom-format file}"
pg_restore --clean --if-exists --no-owner --host="$POSTGRES_HOST" --port="$POSTGRES_PORT" --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" "$BACKUP_FILE"
