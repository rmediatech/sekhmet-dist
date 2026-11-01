#!/bin/sh
# ============================================================================
# skm_db_init.sh — Atomic Single-Schema Initialization for Sekhmet (SQLite WAL)
# Standard: SOVEREIGN-RFC-BAREMETAL-01 & OJP
# ============================================================================
set -eu

DB_PATH="${1:-./sekhmet.db}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
SCHEMA_PATH="${SCRIPT_DIR}/../../schema.sql"

if [ ! -f "$SCHEMA_PATH" ]; then
    printf '{"status":"error","error":"schema.sql not found at %s"}\n' "$SCHEMA_PATH" >&2
    exit 1
fi

sqlite3 "$DB_PATH" < "$SCHEMA_PATH"
printf '{"status":"ok","database":"%s","schema":"pristine_wal"}\n' "$DB_PATH"
