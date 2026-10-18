#!/usr/bin/env bash
# End-to-end security smoke test. Runs the real app on PHP's built-in server
# against a throwaway SQLite database, so no MySQL server is needed.
#   bash tests/smoke.sh
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$ROOT/tests/.tmp"
PORT=8099
BASE="http://127.0.0.1:$PORT"
rm -rf "$TMP" && mkdir -p "$TMP"
DB="$TMP/test.db"
php -r '$p = new PDO("sqlite:'"$DB"'"); $p->exec(file_get_contents("'"$ROOT"'/tests/schema.sqlite.sql"));'

HALYARD_DB_DSN="sqlite:$DB" php -S "127.0.0.1:$PORT" -t "$ROOT/public" >"$TMP/server.log" 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null' EXIT
sleep 1

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  ok    %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
expect() { # expect "<name>" "<actual>" "<expected>"
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', wanted '$3')"; fi
}
contains()     { if grep -qF -- "$3" <<<"$2"; then ok "$1"; else bad "$1 (missing: $3)"; fi; }
not_contains() { if grep -qF -- "$3" <<<"$2"; then bad "$1 (found: $3)"; else ok "$1"; fi; }

JAR="$TMP/jar"; : >"$JAR"
code()  { curl -s -o /dev/null -w '%{http_code}' -b "$JAR" -c "$JAR" "$@"; }
body()  { curl -s -b "$JAR" -c "$JAR" "$@"; }
token() { body "$BASE/$1" | grep -o 'name="csrf" value="[a-f0-9]*"' | head -1 | sed 's/.*value="//;s/"//'; }
sid()   { grep -E 'halyard_sid' "$JAR" | awk '{print $7}'; }
db()    { php -r '$p = new PDO("sqlite:'"$DB"'"); foreach ($p->query($argv[1]) as $r) { echo $r[0], "\n"; }' "$1"; }

PW='correct horse battery staple'

echo "Headers and cookies"
H="$(curl -s -D - -o /dev/null -c "$JAR" "$BASE/login.php")"
contains "CSP header present"            "$H" "Content-Security-Policy: default-src 'none'"
contains "CSP blocks inline script"      "$H" "script-src 'self'"
contains "frame-ancestors none"          "$H" "frame-ancestors 'none'"
contains "nosniff"                       "$H" "X-Content-Type-Options: nosniff"
contains "X-Frame-Options"               "$H" "X-Frame-Options: DENY"
contains "no-store caching"              "$H" "Cache-Control: no-store"
not_contains "no X-Powered-By"           "$H" "X-Powered-By"
contains "cookie HttpOnly"               "$H" "HttpOnly"
contains "cookie SameSite"               "$H" "SameSite=Lax"
contains "referrer policy same-origin"   "$H" "Referrer-Policy: same-origin"

echo "Access control"
expect "dashboard needs login"           "$(code "$BASE/dashboard.php")" "303"
expect "logout via GET refused"          "$(code "$BASE/logout.php")" "405"

echo "CSRF"
T="$(token register.php)"
expect "register without token"          "$(code -d "username=csrfuser&email=c@example.com&password=$PW&password_confirm=$PW" "$BASE/register.php")" "403"
expect "register with wrong token"       "$(code -d "csrf=deadbeef&username=csrfuser&email=c@example.com&password=$PW&password_confirm=$PW" "$BASE/register.php")" "403"
expect "register with foreign Origin"    "$(code -H 'Origin: https://evil.example' -d "csrf=$T&username=csrfuser&email=c@example.com&password=$PW&password_confirm=$PW" "$BASE/register.php")" "403"
expect "register with Origin: null"      "$(code -H 'Origin: null' -d "csrf=$T&username=csrfuser&email=c@example.com&password=$PW&password_confirm=$PW" "$BASE/register.php")" "403"
expect "no user created by those"        "$(db 'SELECT COUNT(*) FROM users')" "0"

echo "Registration validation"
T="$(token register.php)"
R="$(body -d "csrf=$T&username=ab&email=nope&password=short&password_confirm=short" "$BASE/register.php")"
contains "bad username explained"        "$R" "Use 3 to 24 letters, numbers or underscores."
contains "bad email explained"           "$R" "Enter a valid email address."
contains "short password explained"      "$R" "Use at least 10 characters."
R="$(body -d "csrf=$T&username=skipper&email=s@example.com&password=password123&password_confirm=password123" "$BASE/register.php")"
contains "common password rejected"      "$R" "too easy to guess"
R="$(body -d "csrf=$T&username=skipper&email=s@example.com&password=$PW&password_confirm=different-one-here" "$BASE/register.php")"
contains "mismatch rejected"             "$R" "Passwords don’t match."
R="$(body --data-urlencode "csrf=$T" --data-urlencode "username=x'); DROP TABLE users;--" --data-urlencode "email=a@example.com" --data-urlencode "password=$PW" --data-urlencode "password_confirm=$PW" "$BASE/register.php")"
contains "SQL in username rejected"      "$R" "Use 3 to 24 letters, numbers or underscores."
expect "users table intact"              "$(db "SELECT COUNT(*) FROM sqlite_master WHERE name='users'")" "1"
R="$(body -d "csrf=$T&username[]=a&email=a@example.com&password=$PW&password_confirm=$PW" "$BASE/register.php")"
contains "array-typed field handled"     "$R" "Use 3 to 24 letters"

echo "Registration and session"
BEFORE="$(sid)"
T="$(token register.php)"
CODE="$(code -H "Origin: $BASE" -d "csrf=$T&username=Kyuu_Test&email=Kyuu@Example.com&password=$PW&password_confirm=$PW" "$BASE/register.php")"
expect "valid registration redirects"    "$CODE" "303"
AFTER="$(sid)"
if [ -n "$AFTER" ] && [ "$BEFORE" != "$AFTER" ]; then ok "session id changed on sign-in"; else bad "session id changed on sign-in"; fi
D="$(body "$BASE/dashboard.php")"
contains "dashboard shows username"      "$D" "Welcome aboard, Kyuu_Test."
contains "email stored lowercase"        "$D" "kyuu@example.com"
not_contains "sign-in time is recorded"  "$D" "Not yet"
H2="$(db 'SELECT password_hash FROM users')"
case "$H2" in '$argon2id$'*|'$2y$'*) ok "password stored as a slow hash";; *) bad "password stored as a slow hash ($H2)";; esac
not_contains "plaintext never stored"    "$H2" "$PW"

echo "Sign out"
expect "logout without token refused"    "$(code -X POST "$BASE/logout.php")" "403"
T="$(token dashboard.php)"
expect "logout with token works"         "$(code -d "csrf=$T" "$BASE/logout.php")" "303"
expect "dashboard locked again"          "$(code "$BASE/dashboard.php")" "303"

echo "Duplicates"
T="$(token register.php)"
R="$(body -d "csrf=$T&username=kyuu_test&email=other@example.com&password=$PW&password_confirm=$PW" "$BASE/register.php")"
contains "username duplicate (any case)" "$R" "already registered"
R="$(body -d "csrf=$T&username=someoneelse&email=KYUU@example.com&password=$PW&password_confirm=$PW" "$BASE/register.php")"
contains "email duplicate (any case)"    "$R" "already registered"
expect "still one user"                  "$(db 'SELECT COUNT(*) FROM users')" "1"

echo "Sign in and injection attempts"
MSG="don’t match"
T="$(token login.php)"
R1="$(body -d "csrf=$T&identifier=Kyuu_Test&password=wrong-password-1" "$BASE/login.php")"
R2="$(body -d "csrf=$T&identifier=nobody_here&password=wrong-password-1" "$BASE/login.php")"
contains "wrong password: generic error" "$R1" "$MSG"
contains "unknown user: same error"      "$R2" "$MSG"
for payload in "' OR '1'='1' -- " "admin'--" "kyuu_test' OR 1=1 --" '" OR ""="' "kyuu_test\\"; do
  R="$(body --data-urlencode "csrf=$T" --data-urlencode "identifier=$payload" --data-urlencode "password=x" "$BASE/login.php")"
  contains "SQLi identifier refused: $payload" "$R" "$MSG"
done
R="$(body --data-urlencode "csrf=$T" --data-urlencode "identifier=kyuu_test" --data-urlencode "password=' OR '1'='1" "$BASE/login.php")"
contains "SQLi password refused"         "$R" "$MSG"
R="$(body -d "csrf=$T&identifier[]=a&password=x" "$BASE/login.php")"
contains "array identifier handled"      "$R" "Enter your username or email"
R="$(body --data-urlencode "csrf=$T" --data-urlencode 'identifier="><script>alert(1)</script>' --data-urlencode "password=x" "$BASE/login.php")"
not_contains "XSS payload not reflected raw" "$R" "<script>alert(1)"
contains "XSS payload escaped"           "$R" "&quot;&gt;&lt;script&gt;"
expect "users table still intact"        "$(db 'SELECT COUNT(*) FROM users')" "1"

echo "Session fixation"
FIX="$TMP/fix"; : >"$FIX"
curl -s -o /dev/null -c "$FIX" -b "halyard_sid=attackerchosenid1234567890abcd" "$BASE/login.php"
SET="$(grep -E 'halyard_sid' "$FIX" | awk '{print $7}')"
if [ -n "$SET" ] && [ "$SET" != "attackerchosenid1234567890abcd" ]; then ok "server ignores attacker-chosen session id"; else bad "server accepted attacker-chosen session id"; fi

echo "Valid sign in"
T="$(token login.php)"
expect "login with email works"          "$(code -d "csrf=$T&identifier=kyuu@example.com&password=$PW" "$BASE/login.php")" "303"
contains "dashboard after login"         "$(body "$BASE/dashboard.php")" "Welcome aboard, Kyuu_Test."
T="$(token dashboard.php)"; code -d "csrf=$T" "$BASE/logout.php" >/dev/null

echo "Brute-force lockout"
T="$(token login.php)"
for i in 1 2 3 4 5; do code -d "csrf=$T&identifier=Kyuu_Test&password=guess-$i" "$BASE/login.php" >/dev/null; done
expect "right password blocked while locked" "$(code -d "csrf=$T&identifier=Kyuu_Test&password=$PW" "$BASE/login.php")" "429"
RETRY="$(curl -s -D - -o /dev/null -b "$JAR" -d "csrf=$T&identifier=Kyuu_Test&password=$PW" "$BASE/login.php" | grep -i '^Retry-After')"
contains "Retry-After header sent"       "$RETRY" "900"
expect "a different account is not locked" "$(code -d "csrf=$T&identifier=someone_else&password=whatever-pw" "$BASE/login.php")" "200"

echo "Server log"
if grep -qiE 'fatal|warning|notice|deprecated|stack trace' "$TMP/server.log"; then
  bad "PHP errors in server log"; grep -iE 'fatal|warning|notice|deprecated|stack trace' "$TMP/server.log" | head
else ok "no PHP warnings or errors"; fi

echo
echo "Passed: $PASS   Failed: $FAIL"
[ "$FAIL" -eq 0 ]
