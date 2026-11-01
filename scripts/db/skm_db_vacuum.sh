#!/bin/sh
# ============================================================================
# skm_db_vacuum.sh — Zero-Downtime WAL Checkpoint & Vacuum for Sekhmet
# Standard: SOVEREIGN-RFC-BAREMETAL-01 & OJP
# ============================================================================
set -eu

DB_PATH="${1:-./sekhmet.db}"
if [ ! -f "$DB_PATH" ]; then
    printf '{"status":"error","error":"database not found: %s"}\n' "$DB_PATH" >&2
    exit 1
fi

sqlite3 "$DB_PATH" "PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA optimize;"
printf '{"status":"ok","database":"%s","action":"wal_checkpoint_truncate_and_vacuum"}\n' "$DB_PATH"
