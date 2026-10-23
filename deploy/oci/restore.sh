#!/usr/bin/env bash
# Restore a backup INTO the running database (it replaces what is there). Usage: ./restore.sh /var/backups/nexora-cspm/cspm-....sql.gz
# Safe by construction:
#   1. it first takes a safety backup of the current database (and aborts if that fails);
#   2. the restore runs in ONE transaction: if any statement fails nothing is changed;
#   3. the API and web containers are started again whatever happens, so a failed restore never leaves the site down.
set -euo pipefail
cd "$(dirname "$0")"
FILE="${1:?usage: restore.sh <backup.sql.gz>}"
[ -r "$FILE" ] || { echo "cannot read $FILE" >&2; exit 1; }
gzip -t "$FILE" || { echo "$FILE is not a valid gzip file" >&2; exit 1; }
DC=(docker compose ${ENV_FILE:+--env-file "$ENV_FILE"})
read -r -p "This REPLACES the current database with $FILE. Type 'restore' to continue: " OK
[ "$OK" = "restore" ] || { echo "cancelled"; exit 1; }
echo "Taking a safety backup of the current database first..."
./backup.sh
"${DC[@]}" stop api web
trap '"${DC[@]}" start api web >/dev/null' EXIT          # always bring the site back, success or failure
if gunzip -c "$FILE" | "${DC[@]}" exec -T db psql -U cspm -d cspm --single-transaction -v ON_ERROR_STOP=1 -q; then
  echo "restored. Check the API health URL."
else
  echo "RESTORE FAILED: the database was left exactly as it was (single transaction). The safety backup above is the current state." >&2
  exit 1
fi
