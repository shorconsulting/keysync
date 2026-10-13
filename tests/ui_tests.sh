#!/usr/bin/env bash
# Tests for `keysync ui` (the settings page). Needs only python3 and curl: a stand-in Bitwarden
# vault is used and no server is contacted. Run:  bash tests/ui_tests.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
KS="$HERE/../keysync.py"
T="$(mktemp -d)"; PORT=${KEYSYNC_UI_PORT:-28766}
trap '[ -n "${UIPID:-}" ] && { kill $UIPID 2>/dev/null; wait $UIPID 2>/dev/null; }; rm -rf "$T"' EXIT
mkdir -p "$T/home/.ssh" "$T/home/.keysync" "$T/bin"
cp "$HERE/fake_bw" "$T/bin/bw"; chmod +x "$T/bin/bw"
touch "$T/home/.ssh/keysync_ed25519"
echo "{\"account\": \"alice@mac\", \"folder\": \"keysync\", \"key_path\": \"$T/home/.ssh/keysync_ed25519\", \"bw_bin\": \"$T/bin/bw\"}" > "$T/home/.keysync/config.json"
cat > "$T/vault.json" <<'EOF'
{"folders": [{"id": "f1", "name": "keysync"}], "items": [
 {"id": "k1", "folderId": "f1", "type": 2, "name": "keysync key: alice@mac", "fields": [
   {"name": "public_key", "value": "ssh-ed25519 AAAAx keysync:alice@mac"}, {"name": "fingerprint", "value": "SHA256:aliceaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
   {"name": "machine", "value": "mac"}, {"name": "os_user", "value": "alice"}, {"name": "status", "value": "active"}, {"name": "created", "value": "2026-01-01T00:00:00"}]},
 {"id": "s1", "folderId": "f1", "type": 1, "name": "keysync server: box", "login": {"username": "root", "password": "TOPSECRETPW", "uris": [{"uri": "ssh://10.0.0.5:22"}]},
   "fields": [{"name": "alias", "value": "box"}, {"name": "host", "value": "10.0.0.5"}, {"name": "port", "value": "22"}]}]}
EOF
export HOME="$T/home" PATH="$T/bin:$PATH" BW_STUB_DB="$T/vault.json" BW_SESSION=stub-session
pass=0; fail=0
check() { if eval "$2"; then echo "  ok   $1"; pass=$((pass+1)); else echo "  FAIL $1"; fail=$((fail+1)); fi; }
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }
# POST a JSON body (kept in a variable: bash 3.2 on macOS mangles escaped quotes inside $(...))
post() { curl -s -o /dev/null -w "%{http_code}" -H "X-Page-Token: $TOK" -H "Content-Type: application/json" --data-binary "$1" "$U$2"; }
stop_ui() { kill "$UIPID" 2>/dev/null; wait "$UIPID" 2>/dev/null; }

python3 "$KS" ui --no-browser --port "$PORT" > "$T/ui.log" 2>&1 &
UIPID=$!; sleep 2
TOK=$(grep -o 't=[A-Za-z0-9_-]*' "$T/ui.log" | head -1 | cut -c3-)
U="http://127.0.0.1:$PORT"
echo "== settings page (keysync ui)"
check "page refuses a missing token"        '[ "$(code "$U/")" = 403 ]'
check "page opens with the token"           '[ "$(code "$U/?t=$TOK")" = 200 ]'
check "API needs the token header"          '[ "$(code "$U/api/state")" = 403 ]'
check "API refuses other host names"        '[ "$(code -H "X-Page-Token: $TOK" -H "Host: attacker.example:$PORT" "$U/api/state")" = 403 ]'
check "state lists servers and keys"        'curl -s -H "X-Page-Token: $TOK" "$U/api/state" | python3 -c "import json,sys; d=json.load(sys.stdin); sys.exit(0 if d[\"servers\"][0][\"alias\"]==\"box\" and d[\"keys\"][0][\"me\"] else 1)"'
check "state never includes passwords"      '! curl -s -H "X-Page-Token: $TOK" "$U/api/state" | grep -q TOPSECRETPW'
B_OPT='{"alias":"-oProxyCommand=x","target":"a@b"}'
B_CMD='{"alias":"ok","target":"a@b;rm -rf ~"}'
B_HELLO='{"text":"hello"}'
B_WHOIS='{"text":"Accepted publickey ED25519 SHA256:aliceaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
check "server names can't be options"       '[ "$(post "$B_OPT" /api/run/add-server)" = 400 ]'
check "logins can't carry commands"         '[ "$(post "$B_CMD" /api/run/add-server)" = 400 ]'
check "who-logged-in needs a fingerprint"   '[ "$(post "$B_HELLO" /api/run/whois)" = 400 ]'
post "$B_WHOIS" /api/run/whois > /dev/null; sleep 2
check "who-logged-in names the account"     'curl -s -H "X-Page-Token: $TOK" "$U/api/job" | grep -q "alice@mac"'
unset BW_SESSION
stop_ui
python3 "$KS" ui --no-browser --port "$PORT" > "$T/ui.log" 2>&1 &
UIPID=$!; sleep 2
TOK=$(grep -o 't=[A-Za-z0-9_-]*' "$T/ui.log" | head -1 | cut -c3-)
check "locked vault shows as locked"        'curl -s -H "X-Page-Token: $TOK" "$U/api/state" | grep -q "\"vault\": \"locked\""'
check "locked vault exposes no servers"     '! curl -s -H "X-Page-Token: $TOK" "$U/api/state" | grep -q "10.0.0.5"'
echo "== values from Bitwarden can't inject ssh options"
check "bad server fields are refused"       'python3 -c "
import sys; sys.path.insert(0, \"$HERE/..\"); import keysync as k
mk = lambda **f: k.Server({\"name\": \"keysync server: x\", \"login\": {\"username\": f.pop(\"user\", \"u\")}, \"fields\": [{\"name\": a, \"value\": b} for a, b in f.items()]})
assert mk(alias=\"web\", host=\"10.0.0.1\").problem is None
assert mk(alias=\"web\", host=\"[2001:db8::1]\", proxy_jump=\"ops@bastion:2222,inner\").problem is None
assert mk(alias=\"x\", host=\"h\nProxyCommand evil\").problem
assert mk(alias=\"-oProxyCommand=x\", host=\"h\").problem
assert mk(alias=\"x\", host=\"h\", proxy_jump=\"b -oProxyCommand=x\").problem
assert mk(alias=\"x\", host=\"h\", user=\"u\nProxyCommand x\").problem
assert mk(alias=\"x\", host=\"h\", host_keys=\"h ssh-ed25519 AAAA\n@cert-authority * ssh-ed25519 AAAA\").host_keys == [\"h ssh-ed25519 AAAA\"]
" 2>/dev/null'
check "bad public keys are never deployed"  'python3 -c "
import sys; sys.path.insert(0, \"$HERE/..\"); import keysync as k
mk = lambda n, p: k.Key({\"name\": \"keysync key: \" + n, \"fields\": [{\"name\": \"public_key\", \"value\": p}]})
assert mk(\"a@b\", \"ssh-ed25519 AAAAC3Nz keysync:a@b\").active
assert not mk(\"a@b\", \"command=\\\"x\\\" ssh-ed25519 AAAA\").active
assert not mk(\"a@b\", \"ssh-ed25519 AAAA\nssh-rsa AAAAevil\").active
assert not mk(\"a@b\nssh-rsa AAAA\", \"ssh-ed25519 AAAA\").active
"'
echo "== connection handling"
check "dropped connection isn't NO ACCESS"  'python3 -c "
import sys; sys.path.insert(0, \"$HERE/..\"); import keysync as k
k.ssh_run = lambda *a, **kw: (255, \"\", \"\")
s = k.Server({\"name\": \"keysync server: box\", \"login\": {\"username\": \"u\"}, \"fields\": [{\"name\": \"host\", \"value\": \"10.0.0.5\"}]})
r = k.deploy_one(s, [], {\"account\": \"a@b\"}, \"\")
assert r.status == \"unreachable\" and \"closed the connection\" in r.detail, (r.status, r.detail)
k.ssh_run = lambda *a, **kw: (255, \"\", \"u@10.0.0.5: Permission denied (publickey).\")
assert k.deploy_one(s, [], {\"account\": \"a@b\"}, \"\").status == \"no-access\"
"'
stop_ui; UIPID=
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
