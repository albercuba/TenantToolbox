#!/bin/sh
set -eu
: "${POSTGRES_HOST:=localhost}"
: "${POSTGRES_PORT:=5432}"
: "${POSTGRES_DB:=tenanttoolbox}"
: "${POSTGRES_USER:=tenanttoolbox}"
: "${BACKUP_DIR:=./backups}"
mkdir -p "$BACKUP_DIR"
file="$BACKUP_DIR/${POSTGRES_DB}-$(date -u +%Y%m%dT%H%M%SZ).dump"
pg_dump --format=custom --file="$file" --host="$POSTGRES_HOST" --port="$POSTGRES_PORT" --username="$POSTGRES_USER" "$POSTGRES_DB"
printf '%s\n' "$file"
