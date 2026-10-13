#!/usr/bin/env python3
"""
Check keysync on this computer, end to end, without touching your own setup.

Built for Windows (run:  py -3 tests\\windows_check.py ), and it also runs on Linux. On macOS use
tests/run_tests.sh instead. It never contacts a real server or your real Bitwarden vault. It makes
a throwaway home folder whose path contains spaces, uses a stand-in `bw` (a .cmd file on Windows,
like the npm install), and drives this computer's real OpenSSH client, PowerShell and Windows data
protection (DPAPI) against it.

Nothing outside the throwaway folder changes. The one exception is --real-scheduler, which
creates a real Task Scheduler task for a moment and deletes it again (skipped automatically if
you already have a keysync task).

Results are printed and also saved to keysync-test-results.txt in the current folder.
"""
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
KS = HERE.parent / "keysync.py"
WIN = os.name == "nt"
MAC = sys.platform == "darwin"
REAL_SCHEDULER = "--real-scheduler" in sys.argv
KEEP = "--keep" in sys.argv
lines, failures = [], []


def say(msg=""):
    print(msg, flush=True)
    lines.append(msg)


def check(name, ok, detail=""):
    say(f"  {'ok  ' if ok else 'FAIL'} {name}" + ("" if ok or not detail else f"\n         {detail}"))
    if not ok:
        failures.append(name)


def skip(name, why):
    say(f"  skip {name} ({why})")


if MAC:
    print("On macOS, run  bash tests/run_tests.sh  instead (it also tests against a real sshd).")
    sys.exit(0)

root = Path(tempfile.mkdtemp(prefix="keysync test "))
home = root / "Test User"
fakebin = root / "fake bin"
for d in (home / ".ssh", fakebin, home / ".local" / "bin"):
    d.mkdir(parents=True)
vault = root / "vault.json"
env = dict(os.environ)
for k in ("KEYSYNC_HOME", "SSH_AUTH_SOCK"):
    env.pop(k, None)
env.update(HOME=str(home), USERPROFILE=str(home), KEYSYNC_ACCOUNT="tester@testpc", KEYSYNC_MACHINE="testpc",
           BW_STUB_DB=str(vault), BW_SESSION="stub-session",
           # the command folder is already on PATH, so setup never edits your real PATH
           PATH=os.pathsep.join([str(fakebin), str(home / ".local" / "bin"), env.get("PATH", "")]))
shutil.copy(HERE / "fake_bw", fakebin / "fake_bw.py")
if WIN:
    (fakebin / "bw.cmd").write_text(f'@"{sys.executable}" "{fakebin / "fake_bw.py"}" %*\r\n', encoding="utf-8")
else:
    (fakebin / "bw").write_text(f'#!/bin/sh\nexec "{sys.executable}" "{fakebin / "fake_bw.py"}" "$@"\n')
    os.chmod(fakebin / "bw", 0o755)


def run(*args, extra=None, timeout=120):
    e = dict(env, **(extra or {}))
    r = subprocess.run([sys.executable, str(KS)] + list(args), env=e, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout, stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout + r.stderr


def py(code, extra=None):
    """Run a snippet with keysync imported, inside the throwaway home."""
    e = dict(env, **(extra or {}))
    r = subprocess.run([sys.executable, "-c", f"import sys; sys.path.insert(0, {str(HERE.parent)!r}); import keysync as k\n" + code],
                       env=e, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    return r.returncode, r.stdout + r.stderr


def items():
    try:
        return json.loads(vault.read_text())["items"]
    except (OSError, ValueError, KeyError):
        return []


def field(item, name):
    return next((f.get("value") for f in item.get("fields", []) if f.get("name") == name), None)


ssh, keygen = shutil.which("ssh", path=env["PATH"]), shutil.which("ssh-keygen", path=env["PATH"])
ver = subprocess.run([ssh, "-V"], capture_output=True, text=True) if ssh else None
say(f"keysync check on {platform.system()} {platform.release()} ({platform.machine()}), Python {platform.python_version()}")
say(f"OpenSSH client: {(ver.stderr or ver.stdout).strip() if ver else 'NOT FOUND'}")
say(f"Throwaway folder: {root}")
say()
if not (ssh and keygen):
    say("The OpenSSH client isn't installed, so keysync can't run here. On Windows: Settings > System >")
    say("Optional features > Add a feature > OpenSSH Client. Then run this again.")
    sys.exit(1)

say("== setup")
code, out = run("setup", "--yes", "--no-deploy")
check("setup runs", code == 0, out[-700:])
kp = home / ".ssh" / "keysync_ed25519"
check("this account's key is created", kp.exists() and Path(str(kp) + ".pub").exists())
mine = next((i for i in items() if i.get("name") == "keysync key: tester@testpc"), None)
check("its public key is published to the vault", bool(mine) and (field(mine, "public_key") or "").startswith("ssh-ed25519"))
check("only the public key is in the vault", "PRIVATE KEY" not in vault.read_text())
shim = home / ".local" / "bin" / ("keysync.cmd" if WIN else "keysync")
check("adds the keysync command", shim.exists())
if shim.exists():
    r = subprocess.run([str(shim), "--version"], env=env, capture_output=True, text=True)
    check("the keysync command runs", r.returncode == 0 and r.stdout.strip().startswith("1."), (r.stdout + r.stderr)[-300:])
cfg_text = (home / ".ssh" / "config").read_text(encoding="utf-8") if (home / ".ssh" / "config").exists() else ""
check("~/.ssh/config includes keysync's file", "Include" in cfg_text and "keysync_config" in cfg_text, cfg_text[:300])
if WIN:
    check("paths in ssh config use forward slashes and quotes", '"' in cfg_text and "\\" not in cfg_text, cfg_text[:300])

say("== servers")
code, out = run("add-server", "box", "tester@127.0.0.1:2", "--no-deploy")
check("add a server", code == 0, out[-400:])
code, out = run("add-server", "inner", "deploy@10.0.0.9", "--proxy-jump", "box", "--no-deploy")
check("add a server behind a jump host", code == 0, out[-400:])
code, out = run("servers")
check("list servers", code == 0 and "box" in out and "inner" in out, out[-400:])
code, out = run("sync", "--no-deploy")
ks_conf = (home / ".ssh" / "keysync_config")
check("sync writes the SSH config", code == 0 and ks_conf.exists() and "Host box" in ks_conf.read_text(), out[-400:])


def ssh_g(alias):
    r = subprocess.run([ssh, "-F", str(home / ".ssh" / "config"), "-G", alias], capture_output=True, text=True, env=env)
    d = {}
    for line in r.stdout.splitlines():
        k, _, v = line.partition(" ")
        d.setdefault(k.lower(), v)
    return r.returncode, d, r.stderr


code, g, err = ssh_g("box")
check("this computer's ssh reads the generated config", code == 0 and g.get("hostname") == "127.0.0.1" and g.get("port") == "2",
      (err or str(g))[-300:])
check("ssh uses this account's keysync key", "keysync_ed25519" in g.get("identityfile", ""), g.get("identityfile", ""))
check("ssh uses keysync's known-hosts file", "keysync_known_hosts" in g.get("userknownhostsfile", ""), g.get("userknownhostsfile", ""))
code, g, err = ssh_g("inner")
check("jump host is set up", g.get("proxyjump") == "box", (err or str(g))[-300:])

say("== logging in (to a closed port on this computer, so nothing is contacted)")
t0 = time.time()
code, out = run("check", "--only", "box", timeout=90)
check("a login attempt runs and reports the server as unreachable", "unreachable" in out, out[-500:])
check("it doesn't hang", time.time() - t0 < 60, f"took {time.time() - t0:.0f}s")
code, out = py("k.ensure_askpass(); import subprocess; p = k.askpass_path(); "
               "print(subprocess.run([str(p)], capture_output=True, text=True, env=dict(__import__('os').environ, KEYSYNC_PW='pw with spaces')).stdout.strip())")
check("password helper hands ssh the stored password", code == 0 and out.strip().endswith("pw with spaces"), out[-300:])
helper = home / ".keysync" / ("askpass.py" if WIN else "askpass.sh")
check("the password itself is never written to disk", helper.exists() and "pw with spaces" not in helper.read_text())

say("== Bitwarden session storage")
if WIN:
    code, out = py("where = k.save_session('sess-abc-123'); import os; os.environ.pop('BW_SESSION', None)\n"
                   "got = k.load_session(); print(where); print('ROUNDTRIP', got == 'sess-abc-123')")
    check("session saved with Windows data protection and read back", code == 0 and "ROUNDTRIP True" in out, out[-400:])
    enc = home / ".keysync" / "bw_session.dpapi"
    check("stored session is encrypted, not plain text", enc.exists() and "sess-abc-123" not in enc.read_text(errors="ignore"))
    py("k.clear_session()")
    check("lock removes the stored session", not enc.exists())
else:
    code, out = py("k.save_session('sess-abc-123'); import os; os.environ.pop('BW_SESSION', None); print('ROUNDTRIP', k.load_session() == 'sess-abc-123')")
    check("session saved (mode 600 file) and read back", "ROUNDTRIP True" in out, out[-300:])
    py("k.clear_session()")
code, out = run("servers", extra={"BW_SESSION": ""})
check("a locked vault stops with a clear message instead of prompting", code != 0 and "locked" in out.lower(), out[-300:])

say("== keys")
fp = field(mine or {}, "fingerprint") or ""
code, out = run("whois", f"Accepted publickey for tester from 10.0.0.1 port 5555 ssh2: ED25519 {fp}")
check("whois names the account behind a login", "tester@testpc" in out, out[-300:])
data = json.loads(vault.read_text())
bob = json.loads(json.dumps(mine))
bob["id"], bob["name"] = "bob-id", "keysync key: bob@testpc"
data["items"].append(bob)
vault.write_text(json.dumps(data))
code, out = run("revoke", "bob@testpc", "--no-deploy")
b = next((i for i in items() if i.get("name") == "keysync key: bob@testpc"), {})
check("revoke marks the key revoked", code == 0 and field(b, "status") == "revoked", out[-300:])
code, out = run("reactivate", "bob@testpc", "--no-deploy")
b = next((i for i in items() if i.get("name") == "keysync key: bob@testpc"), {})
check("reactivate undoes it", code == 0 and field(b, "status") == "active", out[-300:])

say("== automation")
code, out = run("schedule", "--daily", "07:30", "--print")
if WIN:
    check("daily task renders for Task Scheduler", code == 0 and "/SC DAILY /ST 07:30" in out, out[-400:])
    check("daily task runs without a console window (pythonw)", "pythonw" in out.lower(), out[-400:])
else:
    check("daily cron line renders", code == 0 and "30 7 * * *" in out, out[-300:])
if REAL_SCHEDULER and WIN:
    if subprocess.run(["schtasks", "/Query", "/TN", "keysync"], capture_output=True).returncode == 0:
        skip("real Task Scheduler entry", "you already have a keysync task, so it's left alone")
    else:
        code, out = run("schedule", "--daily", "07:30")
        q = subprocess.run(["schtasks", "/Query", "/TN", "keysync"], capture_output=True, text=True)
        check("real Task Scheduler entry created", code == 0 and q.returncode == 0, (out + q.stdout + q.stderr)[-500:])
        run("schedule", "--remove")
        check("real Task Scheduler entry removed again",
              subprocess.run(["schtasks", "/Query", "/TN", "keysync"], capture_output=True).returncode != 0)
else:
    skip("real Task Scheduler entry", "add --real-scheduler on Windows to create one for a moment and delete it")
if WIN:
    ps = ("$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($env:KS_PS1,[ref]$null,[ref]$e); "
          "if ($e.Count) { $e | ForEach-Object { $_.Message }; exit 1 }")
    r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps], capture_output=True, text=True,
                       env=dict(env, KS_PS1=str(HERE.parent / "install.ps1")))
    check("the Windows installer (install.ps1) is valid PowerShell", r.returncode == 0, (r.stdout + r.stderr)[-400:])

say("== settings page")
proc = subprocess.Popen([sys.executable, str(KS), "ui", "--no-browser"], env=env, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
base = tok = ""
t0 = time.time()
while time.time() - t0 < 20:
    m = re.search(r"(http://127\.0\.0\.1:\d+)/\?t=(\S+)", proc.stdout.readline())
    if m:
        base, tok = m.group(1), m.group(2)
        break
check("settings page starts", bool(tok))
if tok:
    def http(path, token=None, body=None):
        h = {"X-Page-Token": token} if token else {}
        data = None
        if body is not None:
            data, h["Content-Type"] = json.dumps(body).encode(), "application/json"
        try:
            with urllib.request.urlopen(urllib.request.Request(base + path, data=data, headers=h), timeout=30) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()
    check("page refuses a missing token", http("/")[0] == 403)
    check("page opens with the token", http(f"/?t={tok}")[0] == 200)
    st, body = http("/api/state", tok)
    state = json.loads(body) if st == 200 else {}
    check("page shows servers and keys", {s["alias"] for s in state.get("servers", [])} >= {"box", "inner"}
          and any(k.get("me") for k in state.get("keys", [])), body[:300])
    st, _ = http("/api/run/add-server", tok, {"alias": "-oProxyCommand=calc", "target": "a@b"})
    check("page refuses names that could inject ssh options", st == 400)
    http("/api/quit", tok, {})
try:
    proc.wait(timeout=15)
    check("settings page stops", True)
except subprocess.TimeoutExpired:
    proc.kill()
    check("settings page stops", False, "had to be killed")

say()
say(f"{len(failures)} failed" + (": " + ", ".join(failures) if failures else ". Everything passed."))
try:
    (Path.cwd() / "keysync-test-results.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Saved these results to {Path.cwd() / 'keysync-test-results.txt'}")
except OSError:
    pass
if KEEP:
    print(f"Kept the throwaway folder: {root}")
else:
    shutil.rmtree(root, ignore_errors=True)
sys.exit(1 if failures else 0)
