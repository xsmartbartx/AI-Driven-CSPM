#!/usr/bin/env bash
# Restore a backup INTO the running database (it replaces what is there). Usage: ./restore.sh /var/backups/nexora-cspm/cspm-....sql.gz
set -euo pipefail
cd "$(dirname "$0")"
FILE="${1:?usage: restore.sh <backup.sql.gz>}"
DC=(docker compose ${ENV_FILE:+--env-file "$ENV_FILE"})
read -r -p "This REPLACES the current database with $FILE. Type 'restore' to continue: " OK
[ "$OK" = "restore" ] || { echo "cancelled"; exit 1; }
"${DC[@]}" stop api web
gunzip -c "$FILE" | "${DC[@]}" exec -T db psql -U cspm -d cspm -v ON_ERROR_STOP=1 -q
"${DC[@]}" start api web
echo "restored. Check the API health URL."
