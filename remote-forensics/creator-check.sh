#!/bin/bash
set -u

TARGET="${1:-172.30.2.2}"
BASE="http://${TARGET}:8080"
COOKIE="/tmp/wh838-creator-check.cookie"
TMPDIR="/tmp/wh838-creator-check"
PASS=0
FAIL=0

mkdir -p "$TMPDIR"
rm -f "$COOKIE"

ok(){ printf '[PASS] %s\n' "$1"; PASS=$((PASS+1)); }
bad(){ printf '[FAIL] %s\n' "$1"; FAIL=$((FAIL+1)); }

http_code(){ curl -sS --max-time 5 -o /dev/null -w '%{http_code}' "$1" 2>/dev/null || true; }
auth_code(){ curl -sS --max-time 5 -b "$COOKIE" -o /dev/null -w '%{http_code}' "$1" 2>/dev/null || true; }

echo '=== Remote Forensics Creator Check ==='
echo "Target: $TARGET"
echo

# 1. Network surface expected in this Killercoda image.
if command -v nmap >/dev/null 2>&1; then
  OPEN="$(nmap -Pn -p1-9999 --open "$TARGET" 2>/dev/null | awk '/^[0-9]+\/tcp[[:space:]]+open/{sub("/tcp","",$1); print $1}' | paste -sd, -)"
  EXPECTED='22,25,80,3306,4240,8080,8888,9090,9964'
  if [ "$OPEN" = "$EXPECTED" ]; then ok "TCP 1-9999 open ports match expected set ($EXPECTED)"; else bad "TCP port set differs: got [$OPEN], expected [$EXPECTED]"; fi

  KUBE_OPEN="$(nmap -Pn -p2379,2380,6443,10250,10255,10257,10259 --open "$TARGET" 2>/dev/null | awk '/^[0-9]+\/tcp[[:space:]]+open/{print $1}' | paste -sd, -)"
  if [ -z "$KUBE_OPEN" ]; then ok 'Kubernetes management ports are closed'; else bad "Unexpected Kubernetes ports open: $KUBE_OPEN"; fi
else
  bad 'nmap is unavailable'
fi

# 2. Public web routes.
PUBLIC_ROUTES=(/ /wallet/ /task/ /market/ /merchant/ /support/ /download/ /static/app.8f31.js /api/v2/status)
PUBLIC_BAD=0
for r in "${PUBLIC_ROUTES[@]}"; do
  code="$(http_code "$BASE$r")"
  [ "$code" = 200 ] || { printf '  route %-28s -> %s\n' "$r" "$code"; PUBLIC_BAD=1; }
done
if [ "$PUBLIC_BAD" -eq 0 ]; then ok 'Public website routes return HTTP 200'; else bad 'One or more public routes failed'; fi

# 3. Q2 discovery clue should be visible in the ordinary frontend bundle.
JS="$(curl -fsS --max-time 5 "$BASE/static/app.8f31.js" 2>/dev/null || true)"
if printf '%s' "$JS" | grep -q 'consoleBase:"/ops-center/"' && printf '%s' "$JS" | grep -q 'consoleEntry:"gateway-7f3a.php"'; then
  ok 'Frontend bundle contains the intended admin-entry clue'
else
  bad 'Frontend bundle is missing the intended admin-entry clue'
fi

# Legacy decoys should not accidentally become usable login pages.
C1="$(http_code "$BASE/admin/login.php")"
C2="$(http_code "$BASE/manage/login.php")"
if [ "$C1" = 410 ] && [ "$C2" = 410 ]; then ok 'Legacy admin decoys return HTTP 410'; else bad "Legacy decoy status unexpected: admin=$C1 manage=$C2"; fi

# 4. Admin login and authenticated routes.
LOGIN_HEADERS="$TMPDIR/login.headers"
curl -sS --max-time 5 -D "$LOGIN_HEADERS" -o /dev/null -c "$COOKIE" \
  -d 'username=admin&password=Aa123456' "$BASE/ops-center/gateway-7f3a.php" || true
if grep -qE '^HTTP/[^ ]+ 302' "$LOGIN_HEADERS" && grep -qi '^Set-Cookie: session=' "$LOGIN_HEADERS"; then
  ok 'Admin login returns redirect and session cookie'
else
  bad 'Admin login failed'
fi

ADMIN_ROUTES=(dashboard.php customers.php recharge.php withdraw.php merchant.php chat.php import-audit.php system-log.php backup.php files.php profile.php)
ADMIN_BAD=0
for r in "${ADMIN_ROUTES[@]}"; do
  code="$(auth_code "$BASE/ops-center/$r")"
  [ "$code" = 200 ] || { printf '  admin %-24s -> %s\n' "$r" "$code"; ADMIN_BAD=1; }
done
if [ "$ADMIN_BAD" -eq 0 ]; then ok 'All authenticated admin routes return HTTP 200'; else bad 'One or more admin routes failed'; fi

# 5. Downloadable evidence files.
CUSTOMER_DB="$TMPDIR/customer_relation.db"
AUDIT_DB="$TMPDIR/import_audit.db"
SCRIPT_TXT="$TMPDIR/script.txt"
PERF_CSV="$TMPDIR/performance.csv"
LEGACY_LOG="$TMPDIR/legacy-import.log"

download(){ curl -fsS --max-time 8 -b "$COOKIE" -o "$2" "$BASE$1" 2>/dev/null; }
DL_BAD=0
download /download/customer_relation.db "$CUSTOMER_DB" || DL_BAD=1
download /download/import_audit.db "$AUDIT_DB" || DL_BAD=1
download /download/script.txt "$SCRIPT_TXT" || DL_BAD=1
download /download/performance.csv "$PERF_CSV" || DL_BAD=1
download /download/legacy-import.log "$LEGACY_LOG" || DL_BAD=1
if [ "$DL_BAD" -eq 0 ] && [ -s "$CUSTOMER_DB" ] && [ -s "$AUDIT_DB" ] && [ -s "$SCRIPT_TXT" ] && [ -s "$PERF_CSV" ] && [ -s "$LEGACY_LOG" ]; then
  ok 'Evidence/download files are accessible and non-empty'
else
  bad 'One or more evidence/download files are missing or empty'
fi

# 6. SQLite integrity and expected schema/relations.
if command -v sqlite3 >/dev/null 2>&1; then
  if [ "$(sqlite3 "$CUSTOMER_DB" 'PRAGMA integrity_check;' 2>/dev/null)" = ok ]; then ok 'customer_relation.db integrity check'; else bad 'customer_relation.db is invalid'; fi
  if [ "$(sqlite3 "$AUDIT_DB" 'PRAGMA integrity_check;' 2>/dev/null)" = ok ]; then ok 'import_audit.db integrity check'; else bad 'import_audit.db is invalid'; fi

  CUST_COLS="$(sqlite3 "$CUSTOMER_DB" "PRAGMA table_info(customer_relation);" 2>/dev/null | cut -d'|' -f2 | paste -sd, -)"
  for col in customer_id phone_last4 phone_sha256 card_last4 card_sha256 event_date operator status batch_no amount note; do
    printf '%s\n' "$CUST_COLS" | tr ',' '\n' | grep -qx "$col" || { bad "customer_relation missing column: $col"; CUST_COLS=''; break; }
  done
  [ -n "$CUST_COLS" ] && ok 'customer_relation schema contains required forensic fields'

  TABLES="$(sqlite3 "$AUDIT_DB" '.tables' 2>/dev/null)"
  TABLE_BAD=0
  for t in import_jobs operator_sessions queue_events archive_index; do
    printf '%s\n' "$TABLES" | grep -qw "$t" || TABLE_BAD=1
  done
  if [ "$TABLE_BAD" -eq 0 ]; then ok 'import_audit.db contains all expected tables'; else bad 'import_audit.db schema is incomplete'; fi

  SAME_NAME="$(sqlite3 "$AUDIT_DB" "SELECT COUNT(*) FROM import_jobs WHERE archive_name='260420客户资料.xlsx';" 2>/dev/null || echo 0)"
  if [ "${SAME_NAME:-0}" -ge 3 ]; then ok 'Q4 same-filename decoys are present'; else bad "Q4 same-filename decoys are insufficient ($SAME_NAME)"; fi

  BROKEN_JOIN="$(sqlite3 "$AUDIT_DB" "SELECT COUNT(*) FROM import_jobs j LEFT JOIN operator_sessions s ON j.upload_sid=s.session_id WHERE s.session_id IS NULL;" 2>/dev/null || echo 999)"
  if [ "$BROKEN_JOIN" = 0 ]; then ok 'Q4 import-job to operator-session relation is complete'; else bad "Q4 has broken session relations: $BROKEN_JOIN"; fi
else
  bad 'sqlite3 is unavailable'
fi

# 7. Intended isolation checks.
if ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no root@"$TARGET" true >/dev/null 2>&1; then
  bad 'Root SSH shortcut is still usable'
else
  ok 'Root SSH shortcut is blocked'
fi

if timeout 4 kubectl get nodes >/dev/null 2>&1; then
  bad 'kubectl bypass is still usable'
else
  ok 'kubectl bypass is blocked'
fi

echo
echo "RESULT: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
