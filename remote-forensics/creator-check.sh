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

# Q1: number of open TCP ports in 1-9999. Final answer = 9.
if command -v nmap >/dev/null 2>&1; then
  OPEN_Q1="$(nmap -Pn -p1-9999 --open "$TARGET" 2>/dev/null | awk '/^[0-9]+\/tcp[[:space:]]+open/{sub("/tcp","",$1); print $1}' | paste -sd, -)"
  EXPECTED_Q1='22,25,80,3306,4240,8080,8888,9090,9964'
  OPEN_COUNT="$(printf '%s' "$OPEN_Q1" | awk -F, '{if ($0=="") print 0; else print NF}')"
  if [ "$OPEN_Q1" = "$EXPECTED_Q1" ] && [ "$OPEN_COUNT" = 9 ]; then ok 'Q1 has exactly 9 open TCP ports in 1-9999'; else bad "Q1 ports differ: got [$OPEN_Q1] count=$OPEN_COUNT"; fi

  KUBE_OPEN="$(nmap -Pn -p2379,2380,6443,10250,10255,10257,10259 --open "$TARGET" 2>/dev/null | awk '/^[0-9]+\/tcp[[:space:]]+open/{print $1}' | paste -sd, -)"
  if [ -z "$KUBE_OPEN" ]; then ok 'Kubernetes management ports are closed'; else bad "Unexpected Kubernetes ports open: $KUBE_OPEN"; fi
else
  bad 'nmap is unavailable'
fi

PUBLIC_ROUTES=(/ /wallet/ /task/ /market/ /merchant/ /support/ /download/ /static/app-config.js /api/v2/status)
PUBLIC_BAD=0
for r in "${PUBLIC_ROUTES[@]}"; do
  code="$(http_code "$BASE$r")"
  [ "$code" = 200 ] || { printf '  route %-28s -> %s\n' "$r" "$code"; PUBLIC_BAD=1; }
done
if [ "$PUBLIC_BAD" -eq 0 ]; then ok 'Public website routes return HTTP 200'; else bad 'One or more public routes failed'; fi

JS="$(curl -fsS --max-time 5 "$BASE/static/app-config.js" 2>/dev/null || true)"
if printf '%s' "$JS" | grep -q 'consoleBase: "/administrator/"' && printf '%s' "$JS" | grep -q 'consoleEntry: "login.php"'; then
  ok 'Q2 frontend config contains consoleBase and consoleEntry'
else
  bad 'Q2 frontend config clue is missing'
fi

C1="$(http_code "$BASE/admin/login.php")"
C2="$(http_code "$BASE/manage/login.php")"
if [ "$C1" = 410 ] && [ "$C2" = 410 ]; then ok 'Legacy admin decoys return HTTP 410'; else bad "Legacy decoy status unexpected: admin=$C1 manage=$C2"; fi

LOGIN_HEADERS="$TMPDIR/login.headers"
curl -sS --max-time 5 -D "$LOGIN_HEADERS" -o /dev/null -c "$COOKIE" \
  -d 'username=admin&password=Aa123456' "$BASE/administrator/login.php" || true
if grep -qE '^HTTP/[^ ]+ 302' "$LOGIN_HEADERS" && grep -qi '^Set-Cookie: session=' "$LOGIN_HEADERS"; then
  ok 'Administrator login returns redirect and session cookie'
else
  bad 'Administrator login failed'
fi

ADMIN_ROUTES=(dashboard.php customers.php recharge.php withdraw.php merchant.php chat.php import-audit.php system-log.php backup.php files.php profile.php)
ADMIN_BAD=0
for r in "${ADMIN_ROUTES[@]}"; do
  code="$(auth_code "$BASE/administrator/$r")"
  [ "$code" = 200 ] || { printf '  admin %-24s -> %s\n' "$r" "$code"; ADMIN_BAD=1; }
done
if [ "$ADMIN_BAD" -eq 0 ]; then ok 'All authenticated administrator routes return HTTP 200'; else bad 'One or more administrator routes failed'; fi

AUDIT_HTML="$(curl -fsS --max-time 5 -b "$COOKIE" "$BASE/administrator/import-audit.php" 2>/dev/null || true)"
Q4_HASH='0066ac9361cfe37c0cc7e42b61f34edd632fe93857f6b83fa26ab0b476b2dd14'
if printf '%s' "$AUDIT_HTML" | grep -q "$Q4_HASH" && printf '%s' "$AUDIT_HTML" | grep -q 'kf03' && printf '%s' "$AUDIT_HTML" | grep -q '>76<'; then
  ok 'Q4 audit page exposes matched hash, operator and success count'
else
  bad 'Q4 simplified audit row is incomplete'
fi

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

if command -v sqlite3 >/dev/null 2>&1; then
  if [ "$(sqlite3 "$CUSTOMER_DB" 'PRAGMA integrity_check;' 2>/dev/null)" = ok ]; then ok 'customer_relation.db integrity check'; else bad 'customer_relation.db is invalid'; fi
  if [ "$(sqlite3 "$AUDIT_DB" 'PRAGMA integrity_check;' 2>/dev/null)" = ok ]; then ok 'import_audit.db integrity check'; else bad 'import_audit.db is invalid'; fi

  SAME_NAME="$(sqlite3 "$AUDIT_DB" "SELECT COUNT(*) FROM import_jobs WHERE archive_name='260420客户资料.xlsx';" 2>/dev/null || echo 0)"
  if [ "${SAME_NAME:-0}" -ge 3 ]; then ok 'Q4 same-filename decoys remain present'; else bad "Q4 same-filename decoys are insufficient ($SAME_NAME)"; fi

  Q5_MATCH="$(sqlite3 "$CUSTOMER_DB" "SELECT operator FROM customer_relation WHERE phone_sha256='02052ee507e920ffcac1187f4b32dfbf664f558849b6821e2e42b4cf17afbba2' AND card_sha256='2f784423cb78cc6c70144c36cb9e25c49fa6eb62192a7f543422a4c25046c3fb' AND event_date='2026-04-09';" 2>/dev/null)"
  if [ "$Q5_MATCH" = 'liu07' ]; then ok 'Q5 customer correlation still resolves uniquely to liu07'; else bad "Q5 customer correlation unexpected: [$Q5_MATCH]"; fi

  if grep -q '^张总团队,liu07,3000,2026-04-20$' "$PERF_CSV"; then ok 'Q5 performance archive maps liu07 to 张总团队'; else bad 'Q5 performance mapping is missing'; fi
else
  bad 'sqlite3 is unavailable'
fi

if ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no root@"$TARGET" true >/dev/null 2>&1; then bad 'Root SSH shortcut is still usable'; else ok 'Root SSH shortcut is blocked'; fi
if timeout 4 kubectl get nodes >/dev/null 2>&1; then bad 'kubectl bypass is still usable'; else ok 'kubectl bypass is blocked'; fi

echo
echo "RESULT: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]