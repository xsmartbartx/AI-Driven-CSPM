#!/usr/bin/env bash
# Daily database backup for the single-VM deployment. Run from this directory (cron example in replica/oci-deploy.md).
#   ./backup.sh                 -> /var/backups/nexora-cspm/cspm-YYYYmmdd-HHMMSS.sql.gz, keeps the newest 14
#   BACKUP_DIR=... KEEP=30 ./backup.sh
set -euo pipefail
cd "$(dirname "$0")"
DIR="${BACKUP_DIR:-/var/backups/nexora-cspm}"; KEEP="${KEEP:-14}"
mkdir -p "$DIR"; umask 077
OUT="$DIR/cspm-$(date +%Y%m%d-%H%M%S)-$$.sql.gz"   # the PID keeps two backups in the same second apart
docker compose ${ENV_FILE:+--env-file "$ENV_FILE"} exec -T db pg_dump -U cspm -d cspm --no-owner --clean --if-exists | gzip > "$OUT.tmp"
# a dump that is nearly empty means something went wrong: do not keep it as a "good" backup
if [ "$(stat -c %s "$OUT.tmp" 2>/dev/null || stat -f %z "$OUT.tmp")" -lt 2000 ]; then rm -f "$OUT.tmp"; echo "backup looks empty, aborting" >&2; exit 1; fi
mv "$OUT.tmp" "$OUT"
ls -1t "$DIR"/cspm-*.sql.gz | tail -n +"$((KEEP + 1))" | xargs -r rm -f
echo "backup written: $OUT"
