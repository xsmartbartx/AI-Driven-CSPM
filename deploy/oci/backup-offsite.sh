#!/usr/bin/env bash
# Nightly CSPM database backup for a host that already copies its backups to OCI Object Storage (the NEXORA host does):
# a local dump, kept for 14 days, plus an off-site copy made as the instance itself (instance principal, no keys on disk).
# The host may only create objects there, not delete them; expiry is the bucket's own rule.
# The dump format is the one restore.sh reads. Run from cron, for example:
#   20 3 * * * DB_CONTAINER=cspm-db-1 /home/opc/cspm-deploy/deploy/oci/backup-offsite.sh >> /opt/backups/cspm-backup.log 2>&1   (the NEXORA host)
#   BACKUP_DIR=... BUCKET=... PREFIX=... DB_CONTAINER=... KEEP=... ./backup-offsite.sh
# DB_CONTAINER defaults to the database container of this kit's own compose project (nexora-cspm). Started with another
# project name, as on the NEXORA host (docker compose -p cspm ...), set it: DB_CONTAINER=cspm-db-1 (the cron line does).
set -euo pipefail
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"   # cron starts with a minimal PATH; docker and oci must be found
DIR="${BACKUP_DIR:-/opt/backups/cspm}"; KEEP="${KEEP:-14}"
BUCKET="${BUCKET:-nexora-backups}"; PREFIX="${PREFIX:-cspm}"; CONTAINER="${DB_CONTAINER:-nexora-cspm-db-1}"
mkdir -p "$DIR"; umask 077
# one run at a time: an overlapping run (a slow upload, a manual run) would otherwise share files with this one
if command -v flock >/dev/null 2>&1; then exec 9>"$DIR/.lock"; flock -n 9 || { echo "$(date -u) another backup is running, skipping"; exit 0; }; fi
STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$$"
OUT="$DIR/cspm-$STAMP.sql.gz"
TMP="$(mktemp "$DIR/.cspm-XXXXXX.tmp")"
trap 'rm -f "$TMP"' EXIT

docker exec "$CONTAINER" pg_dump -U cspm -d cspm --no-owner --clean --if-exists | gzip > "$TMP"
# a nearly empty dump means something went wrong: do not keep it as a "good" backup
size="$(stat -c %s "$TMP" 2>/dev/null || stat -f %z "$TMP")"
if [ "$size" -lt 2000 ]; then echo "$(date -u) FAILED: dump looks empty ($size bytes)" >&2; exit 1; fi
mv "$TMP" "$OUT"
echo "$(date -u) OK local $OUT $(du -h "$OUT" | cut -f1)"
ls -1t "$DIR"/cspm-*.sql.gz | tail -n +"$((KEEP + 1))" | xargs -r rm -f

# --no-multipart: the instance policy allows plain object creation only; larger uploads would be refused with a misleading BucketNotFound
err="$(mktemp)"; trap 'rm -f "$TMP" "$err"' EXIT
if oci os object put --auth instance_principal --bucket-name "$BUCKET" --file "$OUT" --name "$PREFIX/$(basename "$OUT")" --no-overwrite --no-multipart >/dev/null 2>"$err"; then
  echo "$(date -u) OK off-site oci://$BUCKET/$PREFIX/$(basename "$OUT")"
  date -u +%s > "$DIR/last-success"
else
  echo "$(date -u) UPLOAD FAILED: $(grep -m1 -E '"(code|message)"' "$err" || head -c 300 "$err")" >&2
  exit 1
fi
