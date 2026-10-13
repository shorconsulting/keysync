#!/usr/bin/env bash
# End-to-end test against a REAL sshd on 127.0.0.1, with a stand-in Bitwarden vault.
# Two simulated accounts ("alice@mac1", "bob@mac2") each get their own HOME and key.
# Needs: ssh, sshd, ssh-keygen, python3. Nothing outside a temp folder is touched,
# except the current user's ~/.ssh/authorized_keys, which the test backs up and restores
# (sshd always uses the real home directory).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
KS="$HERE/../keysync.py"
T="$(mktemp -d)"; PORT=${KEYSYNC_TEST_PORT:-22022}
# sshd always uses the real home folder (python instead of getent, which macOS doesn't have)
REAL_HOME="$(python3 -c 'import os, pwd; print(pwd.getpwuid(os.getuid()).pw_dir)')"; REAL_AK="$REAL_HOME/.ssh/authorized_keys"
mkdir -p "$REAL_HOME/.ssh"; chmod 700 "$REAL_HOME/.ssh"
[ -f "$REAL_AK" ] && cp -p "$REAL_AK" "$T/ak.orig"
cleanup() { [ -f "$T/sshd.pid" ] && kill "$(cat "$T/sshd.pid")" 2>/dev/null
            if [ -f "$T/ak.orig" ]; then cp -p "$T/ak.orig" "$REAL_AK"; else rm -f "$REAL_AK"; fi
            rm -f "$REAL_AK.keysync-bak"; rm -rf "$T"; }
trap cleanup EXIT

# ── real sshd on localhost, running as this user ──
ssh-keygen -q -t ed25519 -N "" -f "$T/hostkey"
cat > "$T/sshd_config" <<EOF
Port $PORT
ListenAddress 127.0.0.1
HostKey $T/hostkey
PidFile $T/sshd.pid
UsePAM no
StrictModes no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthorizedKeysFile .ssh/authorized_keys
EOF
# OpenSSH 9.8+ (recent macOS too) blocks an address for a while after failed logins. The test makes
# failed logins on purpose (a brand-new account), so turn that off where the setting exists.
cp "$T/sshd_config" "$T/sshd_config.try"; echo "PerSourcePenalties no" >> "$T/sshd_config.try"
/usr/sbin/sshd -t -f "$T/sshd_config.try" 2>/dev/null && mv "$T/sshd_config.try" "$T/sshd_config"
/usr/sbin/sshd -f "$T/sshd_config" -E "$T/sshd.log" || { echo "could not start sshd"; exit 1; }
sleep 1

# ── stand-in Bitwarden on PATH ──
mkdir -p "$T/bin"; cp "$HERE/fake_bw" "$T/bin/bw"; chmod +x "$T/bin/bw"
export PATH="$T/bin:$PATH" BW_STUB_DB="$T/vault.json" BW_SESSION=stub-session
unset SSH_AUTH_SOCK          # keep your own ssh-agent keys (e.g. the macOS keychain agent) out of the test
pass=0; fail=0
check() { if eval "$2"; then echo "  ok   $1"; pass=$((pass+1)); else echo "  FAIL $1"; fail=$((fail+1)); fi; }
as() { local who=$1; shift; HOME="$T/$who" KEYSYNC_ACCOUNT="$who@mac" python3 "$KS" "$@"; }
mkdir -p "$T/alice/.ssh" "$T/bob/.ssh"; chmod 700 "$T/alice/.ssh" "$T/bob/.ssh"

# Alice already has an old personal key on the server (outside keysync), Bob has nothing.
ssh-keygen -q -t ed25519 -N "" -C "alice-old" -f "$T/alice/.ssh/id_ed25519"
cat "$T/alice/.ssh/id_ed25519.pub" >> "$REAL_AK"; echo "ssh-ed25519 AAAAOTHER unrelated-key" >> "$REAL_AK"; chmod 600 "$REAL_AK"
ME="$(id -un)"

echo "== alice: setup + add server (she can log in with her old key)"
as alice setup --yes > "$T/out" 2>&1; cat "$T/out" | sed 's/^/    /'
as alice add-server box "$ME@127.0.0.1:$PORT" > "$T/out" 2>&1; cat "$T/out" | sed 's/^/    /'
check "alice's keysync key deployed"          'grep -q "keysync:alice@mac" "$REAL_AK"'
check "old + unrelated keys preserved"        'grep -q alice-old "$REAL_AK" && grep -q unrelated-key "$REAL_AK"'
check "host key learned and stored in vault"  'grep -q "ssh-ed25519" <(python3 -c "import json;print([f[\"value\"] for i in json.load(open(\"$BW_STUB_DB\"))[\"items\"] for f in i.get(\"fields\",[]) if f[\"name\"]==\"host_keys\"])")'
check "alice can ssh box with no prompt"      'HOME="$T/alice" ssh -F "$T/alice/.ssh/config" -o BatchMode=yes box true'

echo "== bob: brand-new account, has never logged into the server"
as bob setup --yes > "$T/out" 2>&1; cat "$T/out" | sed 's/^/    /'
check "bob got the server in his ssh config"  'grep -q "Host box" "$T/bob/.ssh/keysync_config"'
check "bob already trusts the host key"       '[ -s "$T/bob/.ssh/keysync_known_hosts" ]'
# If the test server already accepts YOUR OWN default key (~/.ssh/id_*), "brand new" bob gets in with it.
mkdir -p "$T/probe"
if HOME="$T/probe" ssh -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
     -o LogLevel=ERROR -p "$PORT" "$ME@127.0.0.1" true 2>/dev/null; then
  echo "  skip bob reported no-access before deploy (this server accepts your own SSH key, so bob could log in with it)"
else
  check "bob reported no-access before deploy"  'grep -q "NO ACCESS" "$T/out"'
fi

echo "== alice: daily sync pushes bob's key"
as alice sync > "$T/out" 2>&1; cat "$T/out" | sed 's/^/    /'
check "bob's key now on the server"           'grep -q "keysync:bob@mac" "$REAL_AK"'
check "bob logs in, no host-key prompt"       'HOME="$T/bob" ssh -F "$T/bob/.ssh/config" -o BatchMode=yes -o StrictHostKeyChecking=yes box true'
check "bob's login is traceable to bob"       'FP=$(ssh-keygen -lf "$T/bob/.ssh/keysync_ed25519.pub" | awk "{print \$2}"); grep -q "$FP" "$T/sshd.log" && as alice whois "$(grep "$FP" "$T/sshd.log" | tail -1)" | grep -q "bob@mac"'

echo "== second sync is a no-op"
cp -p "$REAL_AK" "$T/ak.before"; as bob sync > "$T/out" 2>&1; cat "$T/out" | sed 's/^/    /'
check "authorized_keys unchanged"             'cmp -s "$REAL_AK" "$T/ak.before"'

echo "== alice revokes bob (e.g. his laptop was stolen)"
as alice revoke bob@mac > "$T/out" 2>&1; cat "$T/out" | sed 's/^/    /'
check "bob's key removed from the server"     '! grep -q "keysync:bob@mac" "$REAL_AK"'
check "bob can no longer log in"              '! HOME="$T/bob" ssh -F "$T/bob/.ssh/config" -o BatchMode=yes box true 2>/dev/null'
check "alice still can"                       'HOME="$T/alice" ssh -F "$T/alice/.ssh/config" -o BatchMode=yes box true'
check "revoked bob can't push keys"           'as bob sync 2>&1 | grep -q "not active"'

echo "== tampered host key is refused"
ssh-keygen -q -t ed25519 -N "" -f "$T/impostor"
python3 - "$BW_STUB_DB" "$T/impostor.pub" <<'PY'
import json,sys; p=sys.argv[1]; fake=" ".join(open(sys.argv[2]).read().split()[:2]); d=json.load(open(p))
for i in d["items"]:
    for f in i.get("fields",[]):
        if f["name"]=="host_keys" and f["value"]: f["value"]=f["value"].split()[0]+" "+fake
json.dump(d,open(p,"w"))
PY
as alice sync > "$T/out" 2>&1; cat "$T/out" | sed 's/^/    /'
check "sync reports HOST KEY CHANGED"         'grep -q "HOST KEY CHANGED" "$T/out"'

echo "== schedule renders"
if [ "$(uname)" = Darwin ]; then
  check "daily launchd job at 07:30"          'as alice schedule --daily 07:30 --print | python3 -c "import plistlib,sys; c=plistlib.loads(sys.stdin.buffer.read())[\"StartCalendarInterval\"]; sys.exit(0 if (c[\"Hour\"], c[\"Minute\"]) == (7, 30) else 1)"'
else
  check "daily cron line"                     'as alice schedule --daily 07:30 --print | grep -q "^30 7 \* \* \*"'
fi

echo "== cross-platform"
check "keysync command installed"             '[ -x "$T/alice/.local/bin/keysync" ] && "$T/alice/.local/bin/keysync" --version | grep -q "1\."'
check "Windows: daily task via schtasks"      'HOME="$T/alice" python3 -c "
import sys; sys.path.insert(0, \"$HERE/..\"); import keysync as k
k.IS_WINDOWS = True; k.main([\"schedule\", \"--daily\", \"07:30\", \"--print\"])" 2>&1 | grep -q "/SC DAILY /ST 07:30"'
check "Windows: ssh paths slash+quoted"       'python3 -c "
import sys; sys.path.insert(0, \"$HERE/..\"); import keysync as k
from pathlib import PureWindowsPath as P
k.IS_WINDOWS = True; k.Path = P
assert k.ssh_path(P(\"C:/Users/David Shor/.ssh/keysync_ed25519\")) == \"\\\"C:/Users/David Shor/.ssh/keysync_ed25519\\\"\"
assert k.ssh_path(P(r\"C:\\\\Users\\\\dave\\\\.ssh\\\\config\")) == \"C:/Users/dave/.ssh/config\""'
check "Windows: hints say winget"             'python3 -c "
import sys; sys.path.insert(0, \"$HERE/..\"); import keysync as k
k.PLATFORM = \"windows\"; assert \"winget install --id Bitwarden.CLI\" in k.install_hint(\"bw\")
k.PLATFORM = \"macos\"; assert \"brew install bitwarden-cli\" in k.install_hint(\"bw\")
k.PLATFORM = \"linux\"; assert \"npm install -g @bitwarden/cli\" in k.install_hint(\"bw\")"'
check "server script sent without CRLF"       'grep -q "input=script.replace(\"\\\\r\\\\n\", \"\\\\n\").encode()" "$KS"'

echo; echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
