#!/usr/bin/env python3
"""
keysync — every Mac account gets its own SSH key, Bitwarden keeps the shared list,
and every server trusts every account.

  * Each OS account on each machine has its OWN key (comment "keysync:<user>@<machine>"),
    so a server's auth log shows exactly which account logged in.
  * Bitwarden (folder "keysync") holds:
        - one "keysync key: <user>@<machine>" secure note per account (public key + status)
        - one "keysync server: <alias>" login per server (host, user, port, jump host,
          optional password, learned host keys)
  * `keysync sync` pulls that list, writes ~/.ssh/keysync_config (+ an Include line in
    ~/.ssh/config) and ~/.ssh/keysync_known_hosts, then logs into every server and
    rewrites a marked block in ~/.ssh/authorized_keys so it holds every active key.
    Keys outside the block are never touched.
  * `keysync revoke <account>` removes one account's key from every server on the next sync.

Python 3.8+, standard library only. Needs: ssh, ssh-keygen, Bitwarden CLI (`bw`).
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures as futures
import datetime as dt
import getpass
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

VERSION = "1.0.0"
HOME = Path.home()
STATE = Path(os.environ.get("KEYSYNC_HOME", str(HOME / ".keysync"))).expanduser()
CONFIG_PATH = STATE / "config.json"
LOG_PATH = STATE / "keysync.log"
ASKPASS = STATE / "askpass.sh"
SESSION_FILE = STATE / "bw_session"
SSH_DIR = HOME / ".ssh"
SSH_CONFIG = SSH_DIR / "config"
KS_CONFIG = SSH_DIR / "keysync_config"
KS_KNOWN = SSH_DIR / "keysync_known_hosts"
KEY_PREFIX = "keysync key: "
SERVER_PREFIX = "keysync server: "
BLOCK_BEGIN = "# BEGIN keysync"
BLOCK_END = "# END keysync"
KC_SERVICE = "keysync-bw-session"
IS_MAC = sys.platform == "darwin"
IS_WINDOWS = os.name == "nt"
PLATFORM = "windows" if IS_WINDOWS else ("macos" if IS_MAC else "linux")
FP_RE = re.compile(r"SHA256:[A-Za-z0-9+/]{43}=?")
TOOL = "keysync"


# ─────────────────────────────── platform helpers ───────────────────────────────

def py_cmd():
    """How to start Python on this OS, for commands we print."""
    if IS_WINDOWS:
        return "py -3" if shutil.which("py") else "python"
    return "python3"


def shown(path):
    """A path as the user should type it in this OS's terminal."""
    s = str(path)
    if IS_WINDOWS:
        return f'"{s}"'
    home = str(HOME)
    if s == home or s.startswith(home + "/"):
        rel = s[len(home):]
        return f'"$HOME{rel}"' if " " in rel else f"~{rel}"
    return shlex.quote(s)


def install_hint(tool):
    hints = {
        "bw": {"macos": "brew install bitwarden-cli   (or: npm install -g @bitwarden/cli)",
               "windows": "winget install --id Bitwarden.CLI -e   (or: npm install -g @bitwarden/cli)",
               "linux": "npm install -g @bitwarden/cli   (or: sudo snap install bw)"},
        "ssh": {"macos": "OpenSSH ships with macOS; make sure /usr/bin is on your PATH",
                "windows": "Settings > System > Optional features > Add a feature > OpenSSH Client",
                "linux": "sudo apt install openssh-client   (or your distribution's equivalent)"},
    }
    return hints.get(tool, {}).get(PLATFORM, "")


def ssh_path(path):
    """Paths written into ssh config / -o options: forward slashes, quoted if they contain spaces."""
    s = Path(path).as_posix() if IS_WINDOWS else str(path)
    return f'"{s}"' if " " in s else s


_USER_SID = None


def windows_user_sid():
    """This Windows user's SID (e.g. S-1-5-21-…), which names the account whatever the system's language."""
    global _USER_SID
    if _USER_SID is None:
        r = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True,
                           creationflags=0x08000000)  # CREATE_NO_WINDOW: no console flash under pythonw
        sid = r.stdout.strip().rsplit(",", 1)[-1].strip().strip('"') if r.returncode == 0 else ""
        _USER_SID = sid if sid.startswith("S-1-") else ""
    return _USER_SID


def restrict_to_owner(path):
    """Windows: OpenSSH refuses a config or key file that anyone besides this user, SYSTEM and
    Administrators can access, such as an OWNER RIGHTS entry inherited from the folder. chmod can't
    express that on Windows, so replace the inherited entries with exactly those three."""
    if not IS_WINDOWS:
        return
    sid = windows_user_sid()
    if not sid:
        return
    subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"*{sid}:F", "*S-1-5-18:F", "*S-1-5-32-544:F"],
                   capture_output=True, text=True, creationflags=0x08000000)


def run_powershell(script, env_extra=None):
    env = os.environ.copy()
    env.update(env_extra or {})
    return subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                          capture_output=True, text=True, env=env)


def install_command(name, script):
    """Put a `name` command on PATH that runs `script` with this Python. Returns a note for the user."""
    bindir = HOME / ".local" / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    on_path = any(Path(p).resolve() == bindir.resolve() for p in os.environ.get("PATH", "").split(os.pathsep) if p)
    if IS_WINDOWS:
        (bindir / f"{name}.cmd").write_text(f'@"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
        if not on_path:
            r = run_powershell(
                "$p=[Environment]::GetEnvironmentVariable('Path','User'); "
                "if (-not (($p -split ';') -contains $env:KS_BIN)) { "
                "[Environment]::SetEnvironmentVariable('Path', (($p.TrimEnd(';') + ';' + $env:KS_BIN).TrimStart(';')), 'User') }",
                {"KS_BIN": str(bindir)})
            if r.returncode != 0:
                return f"Add {bindir} to your PATH to use the `{name}` command."
            return f"Added the `{name}` command. Open a new terminal window to use it."
        return f"Added the `{name}` command."
    shim = bindir / name
    shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8")
    os.chmod(shim, 0o755)
    if on_path:
        return f"Added the `{name}` command."
    shell = os.path.basename(os.environ.get("SHELL", ""))
    if shell == "fish":
        rc, line = HOME / ".config" / "fish" / "config.fish", "fish_add_path $HOME/.local/bin"
    else:
        rc = {"zsh": HOME / ".zshrc", "bash": HOME / (".bash_profile" if IS_MAC else ".bashrc")}.get(shell, HOME / ".profile")
        line = 'export PATH="$HOME/.local/bin:$PATH"'
    try:
        text = rc.read_text(encoding="utf-8") if rc.exists() else ""
        if line not in text:
            rc.parent.mkdir(parents=True, exist_ok=True)
            with open(rc, "a", encoding="utf-8") as f:
                f.write(f"\n# added by {name}\n{line}\n")
    except OSError:
        return f"Add ~/.local/bin to your PATH to use the `{name}` command."
    return f"Added the `{name}` command. Open a new terminal window to use it."


class Fail(SystemExit):
    pass


def interactive_tty():
    if sys.stdin is None or not sys.stdin.isatty():
        return False
    if IS_WINDOWS:
        # The NUL device (stdin from Task Scheduler, a pipe or DEVNULL) reports isatty() True on Windows,
        # and getpass would then wait on a prompt nobody sees. Only a real console has a console mode.
        try:
            import ctypes
            import msvcrt
            mode = ctypes.c_uint32()
            handle = msvcrt.get_osfhandle(sys.stdin.fileno())
            return bool(ctypes.windll.kernel32.GetConsoleMode(ctypes.c_void_p(handle), ctypes.byref(mode)))
        except (AttributeError, OSError, ValueError):
            return False
    return True


def die(msg):
    raise Fail(f"keysync: {msg}")


def now():
    return dt.datetime.now().isoformat(timespec="seconds")


class Out:
    quiet = False
    lines = []

    @classmethod
    def say(cls, msg=""):
        cls.lines.append(msg)
        if not cls.quiet and sys.stdout is not None:      # pythonw (Windows scheduled task) has no console
            print(msg, flush=True)

    @classmethod
    def warn(cls, msg):
        cls.lines.append("! " + msg)
        if sys.stderr is not None:
            print("! " + msg, file=sys.stderr, flush=True)


def log_run():
    try:
        STATE.mkdir(parents=True, exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"\n=== {now()} ===\n" + "\n".join(Out.lines) + "\n")
    except OSError:
        pass


def write_private(path: Path, text: str, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".tmp{os.getpid()}")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    os.chmod(tmp, mode)
    restrict_to_owner(tmp)
    os.replace(tmp, path)


# ─────────────────────────────── identity & config ───────────────────────────────

def machine_name():
    if os.environ.get("KEYSYNC_MACHINE"):
        return os.environ["KEYSYNC_MACHINE"]
    if IS_MAC:
        r = subprocess.run(["scutil", "--get", "LocalHostName"], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    return socket.gethostname().split(".")[0] or "host"


def account_name():
    return os.environ.get("KEYSYNC_ACCOUNT") or f"{getpass.getuser()}@{machine_name()}"


def default_config():
    return {
        "version": 1,
        "account": account_name(),
        "folder": "keysync",
        "key_path": str(SSH_DIR / "keysync_ed25519"),
        "bw_bin": shutil.which("bw"),
        "parallel": 8,
        "connect_timeout": 10,
    }


def load_config(required=True):
    try:
        cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        if required:
            die(f"not set up on this account yet. Run:  {py_cmd()} keysync.py setup")
        return None
    base = default_config()
    base.update(cfg)
    return base


def save_config(cfg):
    write_private(CONFIG_PATH, json.dumps(cfg, indent=2) + "\n")


# ─────────────────────────────── Bitwarden ───────────────────────────────

class BWError(Exception):
    pass


def b64(obj):
    return base64.b64encode(json.dumps(obj).encode()).decode()


def load_session():
    if os.environ.get("BW_SESSION"):
        return os.environ["BW_SESSION"]
    if IS_MAC:
        r = subprocess.run(["security", "find-generic-password", "-a", getpass.getuser(), "-s", KC_SERVICE, "-w"],
                           capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    if IS_WINDOWS and SESSION_FILE.with_suffix(".dpapi").exists():
        # Encrypted with Windows DPAPI: only this Windows user on this PC can decrypt it.
        r = run_powershell(
            "$s = Get-Content -Raw $env:KS_FILE | ConvertTo-SecureString; "
            "[Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s))",
            {"KS_FILE": str(SESSION_FILE.with_suffix(".dpapi"))})
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    try:
        return SESSION_FILE.read_text().strip() or None
    except FileNotFoundError:
        return None


def save_session(session):
    if IS_MAC:
        r = subprocess.run(["security", "add-generic-password", "-U", "-a", getpass.getuser(), "-s", KC_SERVICE,
                            "-l", "keysync Bitwarden session", "-w", session], capture_output=True, text=True)
        if r.returncode == 0:
            return "your macOS Keychain"
    if IS_WINDOWS:
        STATE.mkdir(parents=True, exist_ok=True)
        r = run_powershell(
            "$env:KS_SESSION | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | "
            "Set-Content -NoNewline $env:KS_FILE",
            {"KS_SESSION": session, "KS_FILE": str(SESSION_FILE.with_suffix(".dpapi"))})
        if r.returncode == 0:
            return "a file encrypted for your Windows account"
    write_private(SESSION_FILE, session)
    return str(SESSION_FILE)


def clear_session():
    if IS_MAC:
        subprocess.run(["security", "delete-generic-password", "-a", getpass.getuser(), "-s", KC_SERVICE],
                       capture_output=True)
    SESSION_FILE.unlink(missing_ok=True)
    SESSION_FILE.with_suffix(".dpapi").unlink(missing_ok=True)


class BW:
    def __init__(self, cfg, session=None):
        self.exe = cfg.get("bw_bin") or shutil.which("bw")
        if not self.exe:
            die("Bitwarden CLI not found. Install it with:  " + install_hint("bw"))
        self.session = session
        self.cfg = cfg
        self._folder = None

    def env(self, extra=None):
        e = os.environ.copy()
        if self.session:
            e["BW_SESSION"] = self.session
        e.update(extra or {})
        return e

    def run(self, args, check=True, extra_env=None):
        try:
            r = subprocess.run([self.exe] + args + ["--nointeraction"], env=self.env(extra_env), capture_output=True,
                               text=True, stdin=subprocess.DEVNULL, timeout=180)
        except subprocess.TimeoutExpired:
            raise BWError(f"`bw {args[0]}` timed out")
        if check and r.returncode != 0:
            raise BWError((r.stderr or r.stdout).strip() or f"bw {args[0]} failed")
        return r.stdout

    def json(self, args):
        out = self.run(args).strip()
        return json.loads(out) if out else None

    def status(self):
        try:
            return self.json(["status"]) or {}
        except (BWError, json.JSONDecodeError):
            return {}

    def unlock(self, password):
        out = self.run(["unlock", "--passwordenv", "KEYSYNC_BW_PW", "--raw"], extra_env={"KEYSYNC_BW_PW": password})
        self.session = out.strip()
        return self.session

    def sync(self):
        self.run(["sync"], check=False)

    def folder_id(self):
        if self._folder:
            return self._folder
        name = self.cfg["folder"]
        for f in self.json(["list", "folders", "--search", name]) or []:
            if f.get("name") == name:
                self._folder = f["id"]
                return self._folder
        created = self.json(["create", "folder", b64({"name": name})])
        self._folder = created["id"]
        return self._folder

    def items(self):
        return self.json(["list", "items", "--folderid", self.folder_id()]) or []

    def create(self, item):
        item = dict(item, folderId=self.folder_id())
        return self.json(["create", "item", b64(item)])

    def edit(self, item):
        return self.json(["edit", "item", item["id"], b64(item)])

    def delete(self, item_id):
        self.run(["delete", "item", item_id])


def open_vault(cfg, interactive):
    """Return an unlocked BW handle, unlocking interactively if allowed."""
    bw = BW(cfg, load_session())
    st = bw.status().get("status")
    if st == "unlocked":
        return bw
    if not interactive or not interactive_tty():
        if IS_MAC and not interactive_tty():
            subprocess.run(["osascript", "-e", 'display notification "Run: keysync unlock" '
                            'with title "keysync: Bitwarden vault is locked"'], capture_output=True)
        die("Bitwarden vault is locked. Run:  keysync unlock")
    if st == "unauthenticated" or st is None:
        print("Sign in to Bitwarden (one time on this account; supports two-step login):")
        if subprocess.run([bw.exe, "login"], env=bw.env()).returncode != 0:
            die("Bitwarden sign-in failed.")
    pw = getpass.getpass("Bitwarden master password (to unlock the vault): ")
    try:
        session = bw.unlock(pw)
    except BWError as e:
        die(f"unlock failed: {e}")
    where = save_session(session)
    print(f"Vault unlocked. The session is stored in {where} so daily syncs run unattended "
          f"until you run `keysync lock`.")
    return bw


# ─────────────────────────────── items ───────────────────────────────

def fval(item, name):
    for f in item.get("fields") or []:
        if f.get("name") == name:
            return f.get("value") or ""
    return ""


def fset(item, name, value, hidden=False):
    fields = item.setdefault("fields", []) or []
    item["fields"] = fields
    for f in fields:
        if f.get("name") == name:
            f["value"] = value
            return
    fields.append({"name": name, "value": value, "type": 1 if hidden else 0, "linkedId": None})


class Server:
    def __init__(self, item):
        self.item = item
        login = item.get("login") or {}
        uri = ((login.get("uris") or [{}])[0] or {}).get("uri") or ""
        m = re.match(r"^ssh://(?:[^@/]+@)?([^:/]+)(?::(\d+))?", uri)
        self.alias = fval(item, "alias") or item["name"][len(SERVER_PREFIX):]
        self.host = fval(item, "host") or (m.group(1) if m else self.alias)
        try:
            self.port = int(fval(item, "port") or (m.group(2) if m and m.group(2) else 22))
        except ValueError:
            self.port = -1
        self.user = login.get("username") or fval(item, "user") or getpass.getuser()
        self.password = login.get("password") or ""
        self.jump = fval(item, "proxy_jump")
        self.manage = fval(item, "manage_keys").lower() not in ("no", "false", "0")
        self.host_keys = [l.strip() for l in fval(item, "host_keys").splitlines() if l.strip()]
        self.problem = self._check()

    def _check(self):
        """Anyone who can edit the Bitwarden folder writes these values into ~/.ssh/config and onto
        ssh command lines in every account, so only plain names and addresses are accepted."""
        if not SAFE_ALIAS.fullmatch(self.alias or ""):
            return "its name may only use letters, digits, dot, dash and underscore"
        if not SAFE_HOST.fullmatch(self.host or ""):
            return f"its host {self.host!r} isn't a plain host name or address"
        if not SAFE_USER.fullmatch(self.user or ""):
            return f"its user {self.user!r} isn't a plain user name"
        if self.jump and not SAFE_JUMP.fullmatch(self.jump):
            return f"its jump host {self.jump!r} isn't a plain host list"
        if not 0 < self.port < 65536:
            return f"its port {self.port} is out of range"
        bad = [l for l in self.host_keys if not SAFE_KNOWN.fullmatch(l)]
        if bad:          # e.g. "@cert-authority *" would make every host trust one CA
            self.host_keys = [l for l in self.host_keys if SAFE_KNOWN.fullmatch(l)]
            Out.warn(f"{self.alias}: ignored {len(bad)} host key line(s) that aren't plain host keys")
        return None

    @property
    def target(self):
        return f"{self.user}@{self.host}" + (f":{self.port}" if self.port != 22 else "")


class Key:
    def __init__(self, item):
        self.item = item
        self.name = item["name"][len(KEY_PREFIX):]
        self.pub = fval(item, "public_key").strip()
        self.fp = fval(item, "fingerprint")
        self.status = fval(item, "status") or "active"
        self.created = fval(item, "created")
        self.problem = None
        if not SAFE_ALIAS_KEY.fullmatch(self.name):
            self.problem = "its name isn't a plain user@machine name"
        elif self.pub and not SAFE_PUB.fullmatch(self.pub):
            self.problem = "its public key isn't a single plain SSH public key"

    @property
    def active(self):
        return self.status == "active" and bool(self.pub) and not self.problem


SAFE_ALIAS = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,63}")
SAFE_ALIAS_KEY = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._@-]{0,127}")
SAFE_HOST = re.compile(r"[A-Za-z0-9_\[][A-Za-z0-9._:%\[\]-]{0,252}")
SAFE_USER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._@\\$-]{0,63}")
SAFE_JUMP = re.compile(r"[A-Za-z0-9_\[][A-Za-z0-9._@:,%\[\]-]{0,511}")
SAFE_PUB = re.compile(r"(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com|"
                      r"sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/]+={0,3}(?: [^\r\n]{0,200})?")
SAFE_KNOWN = re.compile(r"[^\s@#*?!][^\s*?!]* (?:ssh-|ecdsa-|sk-)[A-Za-z0-9@.-]+ [A-Za-z0-9+/]+={0,3}")


def split_items(items):
    """Keys and servers from the vault. Entries that could inject ssh options are left out, loudly."""
    keys, servers = [], []
    for i in items:
        name = i.get("name", "")
        if name.startswith(KEY_PREFIX):
            k = Key(i)
            if k.problem:
                Out.warn(f"skipped key '{name}' from Bitwarden: {k.problem}")
            keys.append(k)                       # listed (so it can be revoked) but never deployed
        elif name.startswith(SERVER_PREFIX):
            sv = Server(i)
            if sv.problem:
                Out.warn(f"skipped server '{name}' from Bitwarden: {sv.problem}")
                continue
            servers.append(sv)
    return keys, sorted(servers, key=lambda s: s.alias)


def server_item(alias, user, host, port, password="", jump="", manage=True, host_keys=None):
    item = {
        "type": 1, "name": SERVER_PREFIX + alias, "notes": "Managed by keysync. Edit host/user/port/password here; "
        "every account picks up the change on its next sync.", "favorite": False, "reprompt": 0,
        "login": {"username": user, "password": password or None, "totp": None,
                  "uris": [{"match": None, "uri": f"ssh://{host}:{port}"}]},
        "fields": [],
    }
    for k, v in (("alias", alias), ("host", host), ("port", str(port)), ("proxy_jump", jump),
                 ("manage_keys", "yes" if manage else "no"), ("host_keys", "\n".join(host_keys or []))):
        fset(item, k, v)
    return item


# ─────────────────────────────── local key ───────────────────────────────

def need(binary):
    if not shutil.which(binary):
        die(f"`{binary}` not found on PATH. " + install_hint("ssh"))


def ssh_version():
    r = subprocess.run(["ssh", "-V"], capture_output=True, text=True)
    m = re.search(r"OpenSSH\w*_(\d+)\.(\d+)", (r.stderr or "") + (r.stdout or ""))
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def key_path(cfg):
    return Path(os.path.expanduser(cfg["key_path"]))


def fingerprint_of(pub_line):
    with tempfile.NamedTemporaryFile("w", suffix=".pub", delete=False) as t:
        t.write(pub_line.strip() + "\n")
    try:
        r = subprocess.run(["ssh-keygen", "-lf", t.name], capture_output=True, text=True)
    finally:
        os.unlink(t.name)
    m = FP_RE.search(r.stdout)
    return m.group(0) if m else ""


def ensure_local_key(cfg, passphrase=False):
    kp = key_path(cfg)
    pub = Path(str(kp) + ".pub")
    if kp.exists() and pub.exists():
        return pub.read_text().strip(), False
    SSH_DIR.mkdir(mode=0o700, exist_ok=True)
    cmd = ["ssh-keygen", "-t", "ed25519", "-C", f"keysync:{cfg['account']}", "-f", str(kp), "-q"]
    if not passphrase:
        cmd += ["-N", ""]
    if subprocess.run(cmd).returncode != 0:
        die("ssh-keygen failed")
    restrict_to_owner(kp)
    if passphrase and IS_MAC:
        subprocess.run(["ssh-add", "--apple-use-keychain", str(kp)])
    return pub.read_text().strip(), True


def publish_own_key(bw, items, cfg):
    pub = Path(str(key_path(cfg)) + ".pub").read_text().strip()
    fp = fingerprint_of(pub)
    name = KEY_PREFIX + cfg["account"]
    for it in items:
        if it.get("name") == name:
            k = Key(it)
            if k.status == "revoked":
                Out.warn(f"this account's key ({cfg['account']}) is REVOKED in Bitwarden. It won't be deployed. "
                         f"If that was intentional, leave it. To restore access, generate a new key "
                         f"(delete {key_path(cfg)}*) and run `keysync reactivate {cfg['account']}` from another account.")
                return it
            if k.pub != pub:
                fset(it, "public_key", pub)
                fset(it, "fingerprint", fp)
                fset(it, "rotated", now())
                Out.say(f"Updated this account's public key in Bitwarden ({fp}).")
                return bw.edit(it)
            return it
    item = {
        "type": 2, "name": name, "favorite": False, "reprompt": 0, "secureNote": {"type": 0},
        "notes": "Public SSH key of one OS account, published by keysync. Revoke with `keysync revoke` "
                 "(or set the status field to revoked) and the next sync removes it from every server.",
        "fields": [],
    }
    for k, v in (("public_key", pub), ("fingerprint", fp), ("account", cfg["account"]),
                 ("machine", machine_name()), ("os_user", getpass.getuser()), ("created", now()),
                 ("status", "active")):
        fset(item, k, v)
    Out.say(f"Published this account's public key to Bitwarden as '{name}' ({fp}).")
    return bw.create(item)


# ─────────────────────────────── local ssh files ───────────────────────────────

def render_ssh_config(servers, cfg):
    kp = key_path(cfg)
    out = ["# Generated by keysync on every sync. Edit servers in Bitwarden (folder "
           f"\"{cfg['folder']}\"), not here."]
    if IS_MAC:
        out.append("IgnoreUnknown UseKeychain")
    out.append("")
    for s in servers:
        out += [f"Host {s.alias}", f"  HostName {s.host}", f"  User {s.user}"]
        if s.port != 22:
            out.append(f"  Port {s.port}")
        if s.jump:
            out.append(f"  ProxyJump {s.jump}")
        out += [f"  IdentityFile {ssh_path(kp)}", "  IdentitiesOnly yes"]
        if IS_MAC:
            out += ["  AddKeysToAgent yes", "  UseKeychain yes"]
        out += [f"  UserKnownHostsFile {ssh_path(KS_KNOWN)} {ssh_path(SSH_DIR / 'known_hosts')}", ""]
    return "\n".join(out)


def ensure_include():
    line = f"Include {ssh_path(KS_CONFIG)}"
    try:
        text = SSH_CONFIG.read_text(encoding="utf-8")
    except FileNotFoundError:
        text = ""
    if any(l.strip().lower().startswith("include") and "keysync_config" in l for l in text.splitlines()):
        return False
    if text:
        shutil.copy2(SSH_CONFIG, SSH_CONFIG.with_name("config.keysync-bak"))
    write_private(SSH_CONFIG, f"# keysync servers (must stay at the top)\n{line}\n\n{text}")
    return True


def write_local_files(servers, cfg):
    changed = []
    SSH_DIR.mkdir(mode=0o700, exist_ok=True)
    conf = render_ssh_config(servers, cfg)
    if not KS_CONFIG.exists() or KS_CONFIG.read_text(encoding="utf-8") != conf:
        write_private(KS_CONFIG, conf)
        changed.append("keysync_config")
    known = "".join(sorted({l + "\n" for s in servers for l in s.host_keys}))
    if not KS_KNOWN.exists() or KS_KNOWN.read_text(encoding="utf-8") != known:
        write_private(KS_KNOWN, known, mode=0o644)
        changed.append("keysync_known_hosts")
    if ensure_include():
        changed.append("config (added Include line; backup at ~/.ssh/config.keysync-bak)")
    return changed


# ─────────────────────────────── deploy ───────────────────────────────

REMOTE_SCRIPT = r"""
set -e
umask 077
D="$HOME/.ssh"; AK="$D/authorized_keys"
mkdir -p "$D"; chmod 700 "$D"; [ -f "$AK" ] || : > "$AK"
T=$(mktemp "$D/.keysync.XXXXXX")
cat > "$T.blk" <<'KEYSYNC_EOF'
__BLOCK__
KEYSYNC_EOF
awk 'index($0,"# BEGIN keysync")==1{s=1} !s{print} index($0,"# END keysync")==1{s=0}' "$AK" > "$T"
cat "$T.blk" >> "$T"; rm -f "$T.blk"
if cmp -s "$T" "$AK"; then rm -f "$T"; echo KEYSYNC_UNCHANGED
else cp -p "$AK" "$AK.keysync-bak"; chmod 600 "$T"; mv "$T" "$AK"
  command -v restorecon >/dev/null 2>&1 && restorecon "$AK" >/dev/null 2>&1 || true
  echo KEYSYNC_CHANGED; fi
"""
RESTORE_SCRIPT = 'cp -p "$HOME/.ssh/authorized_keys.keysync-bak" "$HOME/.ssh/authorized_keys" && echo KEYSYNC_RESTORED'


def authorized_block(keys):
    lines = [f"{BLOCK_BEGIN} (managed by keysync; this block is rewritten on every sync)"]
    for k in sorted(keys, key=lambda k: k.name):
        parts = k.pub.split()
        lines.append(" ".join(parts[:2] + [f"keysync:{k.name}"]))
    lines.append(BLOCK_END)
    return "\n".join(lines)


def askpass_path():
    return STATE / ("askpass.cmd" if IS_WINDOWS else "askpass.sh")


def ensure_askpass():
    """A tiny helper ssh runs to read the stored password from the environment (never from disk)."""
    if IS_WINDOWS:
        helper = STATE / "askpass.py"
        write_private(helper, 'import os, sys\nsys.stdout.write(os.environ.get("KEYSYNC_PW", "") + "\\n")\n')
        write_private(askpass_path(), f'@"{sys.executable}" "{helper}"\r\n', mode=0o700)
    elif not askpass_path().exists():
        write_private(askpass_path(), '#!/bin/sh\nprintf "%s\\n" "$KEYSYNC_PW"\n', mode=0o700)


def default_identities():
    return [p for n in ("id_ed25519", "id_ecdsa", "id_rsa") for p in [SSH_DIR / n] if p.exists()]


class Result:
    def __init__(self, server):
        self.s = server
        self.status = "?"
        self.method = ""
        self.detail = ""
        self.learned = []


def ssh_run(s, cfg, known_tmp, mode, script, password=""):
    base = ["ssh", "-F", str(SSH_CONFIG) if SSH_CONFIG.exists() else os.devnull, "-T",
            "-o", f"ConnectTimeout={cfg.get('connect_timeout', 10)}",
            "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3",
            "-o", "ControlPath=none", "-o", "RequestTTY=no", "-o", "RemoteCommand=none", "-o", "LogLevel=ERROR",
            "-o", f"UserKnownHostsFile={ssh_path(known_tmp)} {ssh_path(SSH_DIR / 'known_hosts')}",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "HashKnownHosts=no",
            "-o", f"HostName={s.host}", "-o", f"User={s.user}", "-o", f"Port={s.port}"]
    if s.jump:
        base += ["-o", f"ProxyJump={s.jump}"]
    env = os.environ.copy()
    if mode == "keysync":
        base += ["-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-i", str(key_path(cfg)),
                 "-o", "PreferredAuthentications=publickey"]
    elif mode == "existing":
        base += ["-o", "BatchMode=yes", "-o", "IdentitiesOnly=no", "-o", "PreferredAuthentications=publickey"]
        for p in default_identities():
            base += ["-i", str(p)]
    elif mode == "password":
        ensure_askpass()
        base += ["-o", "BatchMode=no", "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1",
                 "-o", "PreferredAuthentications=keyboard-interactive,password"]
        env.update(SSH_ASKPASS=str(askpass_path()), SSH_ASKPASS_REQUIRE="force", DISPLAY=env.get("DISPLAY", ":0"),
                   KEYSYNC_PW=password)
    extra = {} if IS_WINDOWS else {"start_new_session": True}
    try:
        # Send bytes, not text: on Windows, text mode would turn \n into \r\n and break the remote shell script.
        r = subprocess.run(base + [s.alias, "sh -s"], input=script.replace("\r\n", "\n").encode(),
                           capture_output=True, env=env, timeout=cfg.get("connect_timeout", 10) * 4 + 20, **extra)
        return r.returncode, r.stdout.decode(errors="replace"), r.stderr.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return 255, "", "timed out"


def fatal_ssh_error(err):
    e = err.lower()
    if "remote host identification has changed" in e or "host key verification failed" in e:
        return "host-key-changed"
    if any(x in e for x in ("could not resolve", "connection refused", "timed out", "no route", "network is unreachable",
                            "operation timed out", "connection closed by", "connection reset",
                            "kex_exchange_identification")):
        return "unreachable"
    return None


def deploy_one(s, keys, cfg, known_seed, check_only=False):
    res = Result(s)
    fd, known_tmp = tempfile.mkstemp(prefix="keysync-known-")
    with os.fdopen(fd, "w") as f:
        f.write(known_seed)
    try:
        script = "true; echo KEYSYNC_OK" if check_only else \
            REMOTE_SCRIPT.replace("__BLOCK__", authorized_block(keys))
        pw_ok = bool(s.password) and SSH_VERSION >= (8, 4)
        modes = ["keysync"] if check_only else ["keysync", "existing"] + (["password"] if pw_ok else [])
        last_err = ""
        for mode in modes:
            code, out, err = ssh_run(s, cfg, known_tmp, mode, script, s.password)
            if code == 0 and "KEYSYNC_" in out:
                res.method = {"keysync": "this account's key", "existing": "an existing key",
                              "password": "password from Bitwarden"}[mode]
                if check_only:
                    res.status = "ok"
                elif "KEYSYNC_CHANGED" in out:
                    res.status = "updated"
                    vcode, vout, verr = ssh_run(s, cfg, known_tmp, "keysync", "echo KEYSYNC_OK")
                    if vcode != 0 and keys_include_self(keys, cfg):
                        rc, ro, re_ = ssh_run(s, cfg, known_tmp, mode, RESTORE_SCRIPT, s.password)
                        res.status = "error"
                        res.detail = ("keys were written but this account's key still can't log in "
                                      "(does the server allow public-key login?). "
                                      + ("Previous authorized_keys restored." if "KEYSYNC_RESTORED" in ro
                                         else "Could NOT restore the previous file; check the server."))
                else:
                    res.status = "unchanged"
                break
            last_err = err.strip()
            fatal = fatal_ssh_error(last_err)
            if fatal:
                res.status = fatal
                res.detail = last_err.splitlines()[-1] if last_err else ""
                break
            if code == 255 and not last_err:
                # ssh says nothing at LogLevel=ERROR when the server drops the connection before login.
                # OpenSSH 9.8+ servers do that for a while after several failed logins from one address
                # (PerSourcePenalties), e.g. right after a brand-new account tried its key.
                res.status = "unreachable"
                res.detail = ("the server closed the connection before login. Newer OpenSSH servers briefly "
                              "block an address after several failed logins; try again in a few minutes.")
                break
        else:
            res.status = "no-access"
            if check_only:
                res.detail = "this account's key isn't on the server yet"
            elif s.password and not pw_ok:
                res.detail = (f"a password is stored, but this computer's OpenSSH ({'.'.join(map(str, SSH_VERSION))}) "
                              "is too old to use it unattended (needs 8.4+). Update OpenSSH, or run `keysync sync` "
                              "from an account that can already log in.")
            else:
                res.detail = ("no working key or stored password. Add the password in Bitwarden, or run "
                              "`keysync sync` once from an account that can already log in.")
            if last_err and "permission denied" not in last_err.lower():
                res.detail += f" ({last_err.splitlines()[-1]})"
        with open(known_tmp) as f:
            seeded = set(known_seed.splitlines())
            res.learned = [l.strip() for l in f.read().splitlines() if l.strip() and l.strip() not in seeded]
    finally:
        os.unlink(known_tmp)
    return res


def keys_include_self(keys, cfg):
    return any(k.name == cfg["account"] for k in keys)


# ─────────────────────────────── sync ───────────────────────────────

SSH_VERSION = (0, 0)


def do_sync(cfg, bw, only=None, deploy=True, check_only=False):
    global SSH_VERSION
    SSH_VERSION = ssh_version()
    bw.sync()
    items = bw.items()
    publish_own_key(bw, items, cfg)
    items = bw.items()
    keys, servers = split_items(items)
    active = [k for k in keys if k.active]
    me = next((k for k in keys if k.name == cfg["account"]), None)
    changed = write_local_files(servers, cfg)
    Out.say(f"Bitwarden: {len(servers)} servers, {len(active)} active keys"
            + (f", {len(keys) - len(active)} revoked" if len(keys) != len(active) else "") + ".")
    if changed:
        Out.say("Updated ~/.ssh/" + ", ~/.ssh/".join(changed))
    if only:
        missing = set(only) - {s.alias for s in servers}
        if missing:
            die("not in Bitwarden: " + ", ".join(sorted(missing)))
        servers = [s for s in servers if s.alias in only]
    if not deploy:
        return []
    if not check_only and (me is None or not me.active):
        Out.warn("this account's key is not active, so it won't push keys to servers. Local files are updated.")
        return []
    targets = servers if check_only else [s for s in servers if s.manage]
    skipped = [s for s in servers if not s.manage and not check_only]
    if not active and not check_only:
        die("no active keys in Bitwarden; refusing to empty the managed block on servers.")
    known_seed = "".join(sorted({l + "\n" for s in servers for l in s.host_keys}))
    results = []
    with futures.ThreadPoolExecutor(max_workers=max(1, int(cfg.get("parallel", 8)))) as ex:
        for r in ex.map(lambda s: deploy_one(s, active, cfg, known_seed, check_only), targets):
            results.append(r)
    for r in results:
        if r.learned:
            item = r.s.item
            merged = sorted(set(r.s.host_keys) | set(r.learned))
            fset(item, "host_keys", "\n".join(merged))
            try:
                bw.edit(item)
                r.s.host_keys = merged
            except BWError as e:
                Out.warn(f"{r.s.alias}: couldn't save its host key to Bitwarden: {e}")
    if any(r.learned for r in results):
        write_local_files(split_items(bw.items())[1], cfg)
    icon = {"updated": "updated", "unchanged": "ok", "ok": "ok", "no-access": "NO ACCESS",
            "unreachable": "unreachable", "host-key-changed": "HOST KEY CHANGED", "error": "ERROR"}
    width = max([len(r.s.alias) for r in results] + [6])
    for r in results:
        line = f"  {r.s.alias:<{width}}  {icon.get(r.status, r.status):<16} {r.s.target}"
        if r.method and r.status in ("updated", "unchanged", "ok") and r.method != "this account's key":
            line += f"  (via {r.method})"
        if r.learned:
            line += "  [learned host key]"
        Out.say(line)
        if r.detail and r.status not in ("updated", "unchanged", "ok"):
            Out.say(f"  {'':<{width}}  {r.detail}")
        if r.status == "host-key-changed":
            Out.warn(f"{r.s.alias}: the server's host key differs from the one stored in Bitwarden. This happens "
                     f"after a server rebuild, or in a man-in-the-middle attack. If you rebuilt it, clear the "
                     f"host_keys field of 'keysync server: {r.s.alias}' in Bitwarden and sync again.")
    for s in skipped:
        Out.say(f"  {s.alias:<{width}}  skipped          manage_keys is off")
    return results


# ─────────────────────────────── commands ───────────────────────────────

def cmd_setup(args):
    need("ssh")
    need("ssh-keygen")
    cfg = load_config(required=False) or default_config()
    if args.folder:
        cfg["folder"] = args.folder
    cfg["bw_bin"] = cfg.get("bw_bin") or shutil.which("bw")
    STATE.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE, 0o700)
    save_config(cfg)
    me = Path(__file__).resolve()
    if me != STATE / "keysync.py":
        shutil.copy2(me, STATE / "keysync.py")
    note = install_command(TOOL, STATE / "keysync.py")
    bw = open_vault(cfg, interactive=True)
    pub, created = ensure_local_key(cfg, passphrase=args.passphrase)
    Out.say(("Created" if created else "Using") + f" this account's key: {key_path(cfg)}  ({fingerprint_of(pub)})")
    if args.import_config:
        import_config(cfg, bw, assume_yes=args.yes)
    do_sync(cfg, bw, deploy=not args.no_deploy)
    Out.say(f"\nDone. Account '{cfg['account']}' is set up. {note}\nNext:\n"
            f"  keysync add-server <name> user@host[:port] [--password]   add a server\n"
            f"  keysync schedule                                          sync daily at 09:00\n"
            f"(Until the `keysync` command works, use:  {py_cmd()} {shown(STATE / 'keysync.py')} …)")


def cmd_unlock(args):
    cfg = load_config()
    bw = BW(cfg, None)
    os.environ.pop("BW_SESSION", None)
    open_vault(cfg, interactive=True)


def cmd_lock(args):
    cfg = load_config()
    clear_session()
    BW(cfg).run(["lock"], check=False)
    print("Vault locked and the stored session removed. Scheduled syncs will pause until `keysync unlock`.")


def cmd_sync(args):
    cfg = load_config()
    bw = open_vault(cfg, interactive=not args.unattended)
    results = do_sync(cfg, bw, only=args.only, deploy=not args.no_deploy)
    bad = [r for r in results if r.status in ("no-access", "unreachable", "host-key-changed", "error")]
    return 1 if bad and args.strict else 0


def cmd_check(args):
    cfg = load_config()
    bw = open_vault(cfg, interactive=True)
    Out.say(f"Can account '{cfg['account']}' log in with its own key?")
    do_sync(cfg, bw, only=args.only, check_only=True)


def parse_target(t):
    m = re.fullmatch(r"(?:([^@\s]+)@)?([^:\s@]+)(?::(\d+))?", t)
    if not m:
        die(f"expected user@host[:port], got {t!r}")
    return m.group(1) or getpass.getuser(), m.group(2), int(m.group(3) or 22)


def cmd_add_server(args):
    cfg = load_config()
    bw = open_vault(cfg, interactive=True)
    if not re.fullmatch(r"[A-Za-z0-9._-]+", args.alias):
        die("server name may contain letters, digits, dot, dash and underscore only")
    user, host, port = parse_target(args.target)
    password = ""
    if args.password:
        password = getpass.getpass(f"Password for {user}@{host} (stored in Bitwarden, used only when no key works): ")
    existing = next((i for i in bw.items() if i.get("name") == SERVER_PREFIX + args.alias), None)
    if existing:
        s = Server(existing)
        new = server_item(args.alias, user, host, port, password or s.password, args.proxy_jump or s.jump,
                          not args.no_manage, s.host_keys if (host, port) == (s.host, s.port) else [])
        existing.update({k: new[k] for k in ("login", "fields")})
        bw.edit(existing)
        Out.say(f"Updated server '{args.alias}' in Bitwarden.")
    else:
        bw.create(server_item(args.alias, user, host, port, password, args.proxy_jump or "", not args.no_manage))
        Out.say(f"Added server '{args.alias}' ({user}@{host}:{port}) to Bitwarden.")
    if not args.no_deploy:
        do_sync(cfg, bw, only=[args.alias])


def cmd_remove_server(args):
    cfg = load_config()
    bw = open_vault(cfg, interactive=True)
    it = next((i for i in bw.items() if i.get("name") == SERVER_PREFIX + args.alias), None)
    if not it:
        die(f"no server named {args.alias!r}")
    if not args.yes and input(f"Remove '{args.alias}' from Bitwarden? Keys already on the server stay. [y/N] ").lower() != "y":
        return
    bw.delete(it["id"])
    write_local_files(split_items(bw.items())[1], cfg)
    Out.say(f"Removed '{args.alias}'.")


def ssh_g(alias):
    r = subprocess.run(["ssh", "-F", str(SSH_CONFIG), "-G", alias], capture_output=True, text=True)
    out = {}
    for line in r.stdout.splitlines():
        k, _, v = line.partition(" ")
        out.setdefault(k.lower(), v)
    return out


def config_host_aliases():
    aliases, seen_files = [], set()

    def read(path):
        path = Path(os.path.expanduser(str(path)))
        if path in seen_files or not path.exists() or path == KS_CONFIG:
            return
        seen_files.add(path)
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                parts = shlex.split(raw.replace("\\", "/"), comments=True)
            except ValueError:
                parts = raw.strip().split()
            if len(parts) < 2 or parts[0].startswith("#"):
                continue
            key = parts[0].lower()
            if key == "include":
                for pat in parts[1:]:
                    p = Path(os.path.expanduser(pat))
                    p = p if p.is_absolute() else SSH_DIR / p
                    for f in sorted(p.parent.glob(p.name)):
                        read(f)
            elif key == "host":
                for a in parts[1:]:
                    if not any(c in a for c in "*?!") and a not in aliases:
                        aliases.append(a)
    read(SSH_CONFIG)
    return aliases


def known_lines_for(host, port):
    name = host if port == 22 else f"[{host}]:{port}"
    r = subprocess.run(["ssh-keygen", "-F", name, "-f", str(SSH_DIR / "known_hosts")], capture_output=True, text=True)
    return [l for l in r.stdout.splitlines() if l and not l.startswith("#")]


def import_config(cfg, bw, assume_yes=False):
    existing = {Server(i).alias for i in bw.items() if i.get("name", "").startswith(SERVER_PREFIX)}
    found = []
    for a in config_host_aliases():
        if a in existing:
            continue
        g = ssh_g(a)
        host, user, port = g.get("hostname", a), g.get("user", getpass.getuser()), int(g.get("port", "22") or 22)
        jump = g.get("proxyjump", "")
        jump = "" if jump in ("none", "") else jump
        found.append((a, user, host, port, jump))
    if not found:
        Out.say("No new hosts in ~/.ssh/config to import.")
        return
    Out.say("Hosts in ~/.ssh/config that aren't in Bitwarden yet:")
    for a, user, host, port, jump in found:
        Out.say(f"  {a:<20} {user}@{host}:{port}" + (f" via {jump}" if jump else ""))
    if not assume_yes and (not interactive_tty() or input("Import all of these? [y/N] ").lower() != "y"):
        Out.say("Skipped import.")
        return
    for a, user, host, port, jump in found:
        bw.create(server_item(a, user, host, port, "", jump, True, known_lines_for(host, port)))
    Out.say(f"Imported {len(found)} servers (no passwords; add them in Bitwarden if needed).")


def cmd_import_config(args):
    cfg = load_config()
    bw = open_vault(cfg, interactive=True)
    import_config(cfg, bw, assume_yes=args.yes)


def cmd_servers(args):
    cfg = load_config()
    bw = open_vault(cfg, interactive=True)
    _, servers = split_items(bw.items())
    if not servers:
        print("No servers yet. Add one:  keysync add-server <name> user@host[:port]")
    for s in servers:
        flags = [x for x, on in (("password", s.password), ("host key known", s.host_keys),
                                 ("keys NOT managed", not s.manage)) if on]
        print(f"  {s.alias:<20} {s.target}" + (f" via {s.jump}" if s.jump else "") + (f"   [{', '.join(flags)}]" if flags else ""))


def cmd_keys(args):
    cfg = load_config()
    bw = open_vault(cfg, interactive=True)
    keys, _ = split_items(bw.items())
    for k in sorted(keys, key=lambda k: (k.status != "active", k.name)):
        me = "  <- this account" if k.name == cfg["account"] else ""
        print(f"  {k.name:<36} {k.status:<8} {k.fp}  created {k.created[:10]}{me}")


def find_key(keys, needle):
    hits = [k for k in keys if needle in (k.name, k.fp) or k.name.startswith(needle + "@")]
    if len(hits) != 1:
        die(f"{'no' if not hits else 'more than one'} key matches {needle!r}; see `keysync keys`")
    return hits[0]


def set_key_status(args, status):
    cfg = load_config()
    bw = open_vault(cfg, interactive=True)
    keys, _ = split_items(bw.items())
    k = find_key(keys, args.key)
    if k.status == status:
        print(f"'{k.name}' is already {status}.")
    else:
        fset(k.item, "status", status)
        fset(k.item, f"{'revoked' if status == 'revoked' else 'reactivated'}_at", now())
        fset(k.item, f"{'revoked' if status == 'revoked' else 'reactivated'}_by", cfg["account"])
        bw.edit(k.item)
        Out.say(f"Marked '{k.name}' as {status} in Bitwarden.")
    if args.no_deploy:
        return
    if k.name == cfg["account"] and status == "revoked":
        Out.warn("you revoked THIS account's key, so this account can't push the change. "
                 "Run `keysync sync` from another account to remove it from servers.")
        return
    Out.say("Pushing the change to every server…")
    do_sync(cfg, bw)


def cmd_whois(args):
    cfg = load_config()
    text = " ".join(args.text)
    m = FP_RE.search(text)
    if not m:
        die("paste a fingerprint like SHA256:abc… or the sshd log line that contains one")
    bw = open_vault(cfg, interactive=True)
    keys, _ = split_items(bw.items())
    for k in keys:
        if k.fp == m.group(0):
            it = k.item
            print(f"{m.group(0)} = account '{k.name}' (OS user {fval(it, 'os_user')} on machine {fval(it, 'machine')}), "
                  f"status {k.status}, created {k.created}")
            return
    print(f"{m.group(0)} is not a keysync key. It belongs to a key outside keysync's managed block.")


LAUNCHD_LABEL = "com.keysync.sync"


def cmd_schedule(args):
    load_config()
    script = STATE / "keysync.py"
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", args.daily)
    if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
        die("--daily expects HH:MM (24-hour)")
    hh, mm = int(m.group(1)), int(m.group(2))
    cmd = [sys.executable, str(script), "sync", "--unattended", "--quiet"]
    tools = [shutil.which(x) for x in ("bw", "ssh", "node")]
    path = os.pathsep.join(dict.fromkeys([os.path.dirname(t) for t in tools if t] +
                                         ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"]))
    if IS_WINDOWS:
        if args.remove:
            subprocess.run(["schtasks", "/Delete", "/TN", "keysync", "/F"], capture_output=True)
            print("Removed the daily keysync task.")
            return
        pyw = Path(sys.executable).with_name("pythonw.exe")       # no console window flashing up
        task_cmd = subprocess.list2cmdline([str(pyw if pyw.exists() else sys.executable)] + cmd[1:])
        full = ["schtasks", "/Create", "/TN", "keysync", "/TR", task_cmd, "/SC", "DAILY",
                "/ST", f"{hh:02d}:{mm:02d}", "/F"]
        if args.print:
            print(subprocess.list2cmdline(full))
            return
        if len(task_cmd) > 261:
            die("the task command is longer than Task Scheduler allows (261 characters); "
                "move Python or your user folder to a shorter path, or create the task by hand.")
        r = subprocess.run(full, capture_output=True, text=True)
        if r.returncode:
            die(f"schtasks failed: {(r.stderr or r.stdout).strip()}")
        print(f"keysync will sync daily at {hh:02d}:{mm:02d} while you're signed in (Task Scheduler task 'keysync').")
        return
    if IS_MAC:
        import plistlib
        plist_path = HOME / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
        uid = str(os.getuid())
        plist = plistlib.dumps({"Label": LAUNCHD_LABEL, "ProgramArguments": cmd,
                                "StartCalendarInterval": {"Hour": hh, "Minute": mm},
                                "EnvironmentVariables": {"PATH": path, "HOME": str(HOME)},
                                "StandardOutPath": str(LOG_PATH), "StandardErrorPath": str(LOG_PATH)}).decode()
        if args.print:                       # show only: leave the installed job alone
            print(plist)
            return
        subprocess.run(["launchctl", "bootout", f"gui/{uid}", str(plist_path)], capture_output=True)
        if args.remove:
            plist_path.unlink(missing_ok=True)
            print("Removed the daily keysync job.")
            return
        plist_path.parent.mkdir(parents=True, exist_ok=True)
        plist_path.write_text(plist)
        r = subprocess.run(["launchctl", "bootstrap", f"gui/{uid}", str(plist_path)], capture_output=True, text=True)
        if r.returncode:
            die(f"launchctl failed: {r.stderr.strip()}")
        print(f"keysync will sync daily at {hh:02d}:{mm:02d} (a run missed during sleep happens on wake).")
        return
    line = f'{mm} {hh} * * * PATH="{path}" ' + " ".join(shlex.quote(c) for c in cmd) + f' >> {shlex.quote(str(LOG_PATH))} 2>&1 # keysync'
    if args.print:
        print(line)
        return
    if not shutil.which("crontab"):
        die("cron isn't installed. Install it (e.g. sudo apt install cron), or add this line to your scheduler:\n  "
            + line)
    cur = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    lines = [l for l in (cur.stdout.splitlines() if cur.returncode == 0 else []) if "# keysync" not in l]
    if not args.remove:
        lines.append(line)
    subprocess.run(["crontab", "-"], input="\n".join(lines) + "\n", text=True, check=True)
    print("Removed the keysync cron job." if args.remove else f"cron job installed: daily at {hh:02d}:{mm:02d}")


# ─────────────────────────────── settings page ───────────────────────────────
# `keysync ui` serves one page on 127.0.0.1 with a random token in its link. Other OS accounts
# on the same computer can reach localhost too, so every request must carry the token.
# The page never asks for the Bitwarden master password: unlocking stays in the terminal.

UI_NAME_RE = re.compile(r"^[A-Za-z0-9._@-]{1,120}$")
UI_TARGET_RE = re.compile(r"^(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9.:\[\]-]+?(?::\d{1,5})?$")


def ui_schedule():
    try:
        if IS_WINDOWS:
            r = subprocess.run(["schtasks", "/Query", "/TN", "keysync"], capture_output=True, text=True)
            return {"on": r.returncode == 0, "how": "Task Scheduler", "time": None}
        if IS_MAC:
            import plistlib
            plist_path = HOME / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
            if not plist_path.exists():
                return {"on": False, "how": "launchd", "time": None}
            sci = plistlib.loads(plist_path.read_bytes()).get("StartCalendarInterval") or {}
            return {"on": True, "how": "launchd",
                    "time": f"{sci['Hour']:02d}:{sci['Minute']:02d}" if "Hour" in sci else None}
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True) if shutil.which("crontab") else None
        for line in (r.stdout.splitlines() if r and r.returncode == 0 else []):
            if "# keysync" in line:
                m = re.match(r"^(\d+) (\d+) \* \* \*", line)
                return {"on": True, "how": "cron", "time": f"{int(m.group(2)):02d}:{int(m.group(1)):02d}" if m else None}
        return {"on": False, "how": "cron", "time": None}
    except Exception:
        return {"on": False, "how": "", "time": None}


def ui_state():
    cfg = load_config()
    kp = key_path(cfg)
    out = {"version": VERSION, "account": cfg["account"], "folder": cfg["folder"], "key_path": shown(kp),
           "have_key": kp.exists(), "schedule": ui_schedule(), "platform": PLATFORM}
    try:
        bw = BW(cfg, load_session())
    except Fail as e:
        out["error"] = str(e).replace("keysync: ", "")
        return out
    out["vault"] = bw.status().get("status") or "unknown"
    if out["vault"] != "unlocked":
        return out
    keys, servers = split_items(bw.items())
    out["keys"] = [{"name": k.name, "fp": k.fp, "status": k.status, "created": k.created[:10],
                    "machine": fval(k.item, "machine"), "os_user": fval(k.item, "os_user"),
                    "me": k.name == cfg["account"], "problem": k.problem}
                   for k in sorted(keys, key=lambda k: (k.status != "active", k.name))]
    out["servers"] = [{"alias": s.alias, "target": s.target, "jump": s.jump, "password": bool(s.password),
                       "host_key": bool(s.host_keys), "manage": s.manage} for s in servers]
    return out


def _ui_arg(value, rx, what):
    if not isinstance(value, str) or not rx.fullmatch(value) or value.startswith("-"):
        raise ValueError(f"check the {what}")
    return value


def ui_job_argv(action, body):
    """Map a button to a command line of this script. Nothing from the page reaches a shell."""
    if action in ("check", "sync"):
        return [action]
    if action in ("revoke", "reactivate"):
        return [action, _ui_arg(body.get("key"), UI_NAME_RE, "account name")]
    if action == "add-server":
        argv = ["add-server", _ui_arg(body.get("alias"), re.compile(r"^[A-Za-z0-9._-]{1,64}$"), "server name"),
                _ui_arg(body.get("target"), UI_TARGET_RE, "login (user@host or user@host:port)")]
        if body.get("jump"):
            argv += ["--proxy-jump", _ui_arg(body["jump"], UI_TARGET_RE, "jump host")]
        if body.get("manage") is False:
            argv.append("--no-manage")
        return argv
    if action == "remove-server":
        return ["remove-server", _ui_arg(body.get("alias"), re.compile(r"^[A-Za-z0-9._-]{1,64}$"), "server name"), "--yes"]
    if action == "whois":
        text = body.get("text")
        if not isinstance(text, str) or not FP_RE.search(text):
            raise ValueError("paste a line that contains a fingerprint like SHA256:…")
        return ["whois", FP_RE.search(text).group(0)]
    if action == "schedule":
        if body.get("off"):
            return ["schedule", "--remove"]
        t = body.get("time") or ""
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", t):
            raise ValueError("enter a time like 09:00")
        return ["schedule", "--daily", t]
    if action == "lock":
        return ["lock"]
    raise ValueError("unknown action")


KEYSYNC_UI = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>keysync settings</title>
<link rel="icon" type="image/png" href="data:image/png;base64,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">
<style>
:root{
  --bg:#EDF0F3; --surface:#FFFFFF; --sunk:#E3E8ED; --ink:#17212B; --muted:#5C6876; --rule:#D2D9E0;
  --ok:#0B7A64; --ok-soft:#D7EEE8; --drift:#B86E00; --drift-soft:#F7E9D2; --danger:#B42318; --danger-soft:#F8DEDA;
  --focus:#0B7A64; --btn:#17212B; --btn-ink:#FFFFFF;
  --sans: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI Variable Text", "Segoe UI", Inter, Roboto, "Helvetica Neue", Arial, sans-serif;
  --mono: ui-monospace, "SF Mono", SFMono-Regular, "Cascadia Mono", "Segoe UI Mono", Menlo, Consolas, "Liberation Mono", monospace;
  color-scheme: light;
}
@media (prefers-color-scheme: dark){
  :root{ --bg:#0F1419; --surface:#161D24; --sunk:#1D262F; --ink:#E4E9EE; --muted:#97A3B0; --rule:#2A3541;
    --ok:#3CC2A2; --ok-soft:#173A33; --drift:#E8A33D; --drift-soft:#3A2C14; --danger:#F2786D; --danger-soft:#3D1D1A;
    --focus:#3CC2A2; --btn:#E4E9EE; --btn-ink:#0F1419; color-scheme: dark; }
}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--bg); color:var(--ink); font:15px/1.5 var(--sans); -webkit-font-smoothing:antialiased}
a{color:inherit; text-underline-offset:3px}
button,input,select,textarea{font:inherit; color:inherit}
:focus-visible{outline:2px solid var(--focus); outline-offset:2px}
code,.mono{font-family:var(--mono); font-size:.9em}

.top{display:flex; align-items:center; gap:16px; flex-wrap:wrap; padding:18px 28px; border-bottom:1px solid var(--rule); background:var(--surface)}
.brand{display:flex; align-items:center; gap:10px; font-weight:650; font-size:17px}
.brand svg{flex:none}
.where{color:var(--muted); font-size:14px}
.actions{margin-left:auto; display:flex; gap:8px}
.btn{border:1px solid var(--rule); background:var(--surface); border-radius:7px; padding:8px 14px; cursor:pointer; font-weight:550; white-space:nowrap}
.btn:hover{background:var(--sunk)}
.btn.primary{background:var(--btn); color:var(--btn-ink); border-color:var(--btn)}
.btn.primary:hover{opacity:.9}
.btn.danger{color:var(--danger); border-color:color-mix(in srgb, var(--danger) 45%, var(--rule))}
.btn.small{padding:4px 10px; font-size:13px}
.btn:disabled{opacity:.5; cursor:default}

.shell{display:grid; grid-template-columns:240px minmax(0,1fr); max-width:1280px; margin:0 auto}
nav.tabs{padding:24px 12px 24px 28px; position:sticky; top:0; align-self:start}
nav.tabs a{display:flex; justify-content:space-between; align-items:center; gap:8px; white-space:nowrap; padding:8px 12px; border-radius:7px; text-decoration:none; color:var(--muted); font-weight:550}
nav.tabs a:hover{color:var(--ink); background:var(--sunk)}
nav.tabs a[aria-current="page"]{color:var(--ink); background:var(--surface); box-shadow:inset 3px 0 0 var(--ok)}
.count{font-variant-numeric:tabular-nums; font-size:12px; min-width:22px; text-align:center; padding:1px 7px; border-radius:20px; background:var(--drift-soft); color:var(--drift); font-weight:650}
main{padding:28px 28px 120px; min-width:0}
section[hidden]{display:none}
h1{font-size:26px; line-height:1.25; font-weight:650; margin:0 0 6px; max-width:30em; letter-spacing:-.01em}
h2{font-size:19px; margin:0 0 6px; font-weight:650}
h3{font-size:15px; margin:28px 0 8px; font-weight:650}
.lede{color:var(--muted); margin:0 0 22px; max-width:46em}
.muted{color:var(--muted)}

/* the pegboard */
.legend{display:flex; flex-wrap:wrap; gap:18px; font-size:13px; color:var(--muted); margin:0 0 12px}
.legend span{display:inline-flex; align-items:center; gap:7px}
.board{overflow-x:auto; background:var(--surface); border:1px solid var(--rule); border-radius:10px}
table.peg{border-collapse:collapse; width:100%; min-width:520px}
table.peg th, table.peg td{padding:7px 14px; text-align:left}
table.peg thead th{position:sticky; top:0; background:var(--surface); border-bottom:1px solid var(--rule); font-weight:600; vertical-align:bottom; z-index:1}
table.peg thead th small{display:block; font-weight:400; color:var(--muted); font-size:12px; font-family:var(--mono)}
table.peg thead th.acct, table.peg td{text-align:center; width:1%; white-space:nowrap}
table.peg thead th.hubcol, table.peg td.hubcol{border-left:1px dashed var(--rule)}
table.peg tr.group th{padding-top:18px; font-size:13px; color:var(--muted); font-weight:600; background:var(--surface)}
table.peg tbody tr.item:hover{background:var(--sunk)}
table.peg tbody tr.item th{font-family:var(--mono); font-weight:400; font-size:13.5px; overflow-wrap:anywhere; min-width:150px}
table.peg thead th:first-child, table.peg tbody tr.item th{position:sticky; left:0; background:var(--surface); z-index:2}
table.peg tbody tr.item:hover th{background:var(--sunk)}
.badge{display:inline-block; font-size:11.5px; padding:1px 7px; border-radius:20px; background:var(--sunk); color:var(--muted); margin-left:6px; font-family:var(--sans); font-weight:550}
.peg-dot{display:inline-block; width:14px; height:14px; border-radius:50%; vertical-align:middle}
.peg-dot.current{background:var(--ok)}
.peg-dot.older{border:2px solid var(--ok); background:linear-gradient(90deg, var(--ok) 50%, transparent 50%)}
.peg-dot.missing{border:2px solid var(--drift)}
.peg-dot.manual{border:2px dotted var(--drift)}
.peg-dot.unknown,.peg-dot.none{width:10px; height:2px; border-radius:1px; background:var(--rule)}

/* lists and tables elsewhere */
.panel{background:var(--surface); border:1px solid var(--rule); border-radius:10px}
table.list{border-collapse:collapse; width:100%}
table.list th, table.list td{padding:10px 14px; text-align:left; vertical-align:top; border-bottom:1px solid var(--rule)}
table.list tr:last-child td, table.list tr:last-child th{border-bottom:0}
table.list thead th{font-size:13px; color:var(--muted); font-weight:600}
.state{display:inline-flex; align-items:center; gap:6px; font-size:13px; font-weight:550}
.state::before{content:""; width:8px; height:8px; border-radius:50%; background:currentColor}
.state.ok{color:var(--ok)} .state.warn{color:var(--drift)} .state.bad{color:var(--danger)} .state.off{color:var(--muted)}
.conflict{padding:16px 18px; border-bottom:1px solid var(--rule)}
.conflict:last-child{border-bottom:0}
.conflict .key{font-family:var(--mono); font-size:14px; font-weight:600}
.choice{display:grid; grid-template-columns:minmax(90px,160px) minmax(0,1fr) auto; gap:4px 14px; align-items:center; margin-top:10px}
.choice .val{font-family:var(--mono); font-size:13px; background:var(--sunk); border-radius:5px; padding:4px 8px; overflow-wrap:anywhere}
.wins{font-size:12px; color:var(--ok); font-weight:600}
.empty{padding:28px 18px; color:var(--muted)}

.form-row{display:flex; gap:10px; flex-wrap:wrap; align-items:center}
input[type=text],input[type=password],input[type=time],select{border:1px solid var(--rule); background:var(--surface); border-radius:7px; padding:7px 10px; min-width:0}
input[type=text]{width:240px}
.checks{display:grid; grid-template-columns:repeat(auto-fill,minmax(190px,1fr)); gap:6px 18px; padding:14px 18px}
.checks label{display:flex; gap:8px; align-items:center; font-family:var(--mono); font-size:13.5px}
.chips{display:flex; flex-wrap:wrap; gap:6px; padding:12px 18px}
.chip{display:inline-flex; align-items:center; gap:6px; font-family:var(--mono); font-size:13px; background:var(--sunk); border-radius:6px; padding:3px 4px 3px 9px}
.chip button{border:0; background:none; cursor:pointer; color:var(--muted); padding:0 5px; font-size:15px; line-height:1}
.chip button:hover{color:var(--danger)}
.addrow{padding:0 18px 14px}
.savebar{display:flex; gap:12px; align-items:center; margin-top:18px}
.note{font-size:13px; color:var(--muted)}
.note.ok{color:var(--ok)} .note.bad{color:var(--danger)}
.setting{display:grid; grid-template-columns:minmax(0,1fr) auto; gap:14px; align-items:center; padding:16px 18px; border-bottom:1px solid var(--rule)}
.setting:last-child{border-bottom:0}
.setting p{margin:2px 0 0; color:var(--muted); font-size:14px}

/* output drawer */
.drawer{position:fixed; left:0; right:0; bottom:0; background:var(--surface); border-top:1px solid var(--rule); box-shadow:0 -8px 24px rgba(15,20,25,.12); max-height:55vh; display:flex; flex-direction:column; z-index:20}
.drawer[hidden]{display:none}
.drawer header{display:flex; align-items:center; gap:12px; padding:12px 28px; border-bottom:1px solid var(--rule)}
.drawer header strong{font-size:15px}
.drawer pre{margin:0; padding:14px 28px 22px; overflow:auto; font:12.5px/1.55 var(--mono); white-space:pre-wrap; overflow-wrap:anywhere}
.spin{width:12px; height:12px; border-radius:50%; border:2px solid var(--rule); border-top-color:var(--ok); animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

dialog{border:1px solid var(--rule); border-radius:12px; background:var(--surface); color:var(--ink); padding:22px 24px; max-width:440px; width:calc(100% - 32px)}
dialog::backdrop{background:rgba(15,20,25,.45)}
dialog p{color:var(--muted); margin:6px 0 18px}
dialog .row{display:flex; justify-content:flex-end; gap:8px}

footer{max-width:1280px; margin:0 auto; padding:0 28px 32px 268px; display:flex; flex-wrap:wrap; gap:6px 20px; font-size:13px; color:var(--muted)}
footer .grow{flex:1}
footer button{border:0; background:none; padding:0; cursor:pointer; color:var(--muted); text-decoration:underline; text-underline-offset:3px}
.notice{background:var(--drift-soft); border-radius:10px; padding:14px 18px; margin:0 0 22px}

@media (max-width: 860px){
  .top{padding:14px 16px}
  .actions{margin-left:0; width:100%}
  .actions .btn{flex:1}
  .shell{grid-template-columns:1fr}
  nav.tabs{position:static; display:flex; overflow-x:auto; padding:10px 16px 0; gap:4px}
  nav.tabs a{white-space:nowrap}
  nav.tabs a[aria-current="page"]{box-shadow:inset 0 -3px 0 var(--ok)}
  main{padding:18px 16px 120px}
  h1{font-size:22px}
  footer{padding:0 16px 28px}
  .choice{grid-template-columns:1fr auto}
  .choice .acct{grid-column:1 / -1; margin-top:6px}
  .drawer header,.drawer pre{padding-left:16px; padding-right:16px}
  input[type=text]{width:100%}
}
@media (prefers-reduced-motion: reduce){ .spin{animation:none} }
@media (max-width: 860px){
  table.list.stack thead{display:none}
  table.list.stack tr{display:block; padding:12px 16px; border-bottom:1px solid var(--rule)}
  table.list.stack tr:last-child{border-bottom:0}
  table.list.stack td{display:block; border:0; padding:3px 0; text-align:left !important}
  table.list.stack td .btn{margin-top:6px}
}
.fp{overflow-wrap:anywhere}
.fp{font-family:var(--mono); font-size:12.5px; color:var(--muted)}
.pill{display:inline-block; font-size:12px; padding:1px 8px; border-radius:20px; background:var(--sunk); color:var(--muted); margin:0 4px 4px 0; white-space:nowrap}
.status-revoked{color:var(--danger)}
textarea{width:100%; min-height:84px; border:1px solid var(--rule); border-radius:7px; padding:10px; background:var(--surface); font:13px/1.5 var(--mono); resize:vertical}
.result{margin-top:14px; padding:14px 18px; border-radius:10px; background:var(--surface); border:1px solid var(--rule); white-space:pre-wrap; font:13px/1.55 var(--mono)}
.result.hit{border-color:var(--ok); box-shadow:inset 3px 0 0 var(--ok)}
.addform{display:grid; grid-template-columns:repeat(3, minmax(0,1fr)); gap:12px 14px; padding:16px 18px}
.addform label{display:flex; flex-direction:column; gap:4px; font-size:13px; font-weight:600}
.addform input[type=text]{width:100%}
.addform .span{grid-column:1 / -1; display:flex; gap:14px; align-items:center; flex-wrap:wrap}
.addform .span label{flex-direction:row; align-items:center; gap:8px; font-weight:400; font-size:14px}
@media (max-width: 860px){ .addform{grid-template-columns:1fr} }
</style>
</head>
<body>
<div class="top">
  <div class="brand">
    <svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true"><circle cx="10" cy="16" r="6.5" fill="none" stroke="var(--ok)" stroke-width="3.5"/><path d="M16.5 16H29M24 16v5M28 16v4" stroke="var(--ok)" stroke-width="3.5" stroke-linecap="round"/></svg>
    keysync
  </div>
  <div class="where" id="where"></div>
  <div class="actions">
    <button class="btn" id="checkBtn" type="button">Check access</button>
    <button class="btn primary" id="syncBtn" type="button">Sync now</button>
  </div>
</div>

<div class="shell">
  <nav class="tabs" aria-label="Sections">
    <a href="#servers">Servers</a>
    <a href="#keys">Keys <span class="count" id="c-rev" hidden></span></a>
    <a href="#whois">Who logged in?</a>
    <a href="#automation">Automation</a>
  </nav>
  <main id="main"><p class="muted">Opening your Bitwarden vault…</p></main>
</div>

<footer>
  <span class="grow" id="ver"></span>
  <span>Made by <a href="https://shorconsulting.com" target="_blank" rel="noopener noreferrer">David Shor</a></span>
  <a href="https://github.com/shorconsulting/keysync#readme" target="_blank" rel="noopener noreferrer">Help</a>
  <a href="https://github.com/shorconsulting/keysync/issues" target="_blank" rel="noopener noreferrer">Report a problem</a>
  <button type="button" id="quitBtn">Stop the settings page</button>
</footer>

<div class="drawer" id="drawer" hidden role="region" aria-label="Output">
  <header><span class="spin" id="spin"></span><strong id="drawerTitle"></strong><span class="note" id="drawerNote"></span>
    <span style="flex:1"></span><button class="btn small" type="button" id="drawerClose">Close</button></header>
  <pre id="drawerOut"></pre>
</div>

<dialog id="confirm"><h2 id="cTitle"></h2><p id="cBody"></p>
  <div class="row"><button class="btn" type="button" id="cNo">Cancel</button><button class="btn primary" type="button" id="cYes"></button></div></dialog>

<script>
"use strict";
const TOKEN = new URLSearchParams(location.search).get("t") || "";
const $ = (s, r = document) => r.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const plural = (n, one, many) => n + " " + (n === 1 ? one : (many || one + "s"));
let S = null, whoisResult = null;

async function api(path, body) {
  const opt = {headers: {"X-Page-Token": TOKEN}};
  if (body !== undefined) { opt.method = "POST"; opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  let data = {};
  try { data = await r.json(); } catch (e) {}
  if (!r.ok) throw new Error(data.error || ("The page couldn't reach keysync (" + r.status + "). Is the terminal window still open?"));
  return data;
}
function ask(title, body, yes, danger) {
  return new Promise(res => {
    const d = $("#confirm");
    $("#cTitle").textContent = title; $("#cBody").textContent = body; $("#cYes").textContent = yes;
    $("#cYes").className = "btn " + (danger ? "danger" : "primary");
    const done = v => { d.close(); res(v); };
    $("#cYes").onclick = () => done(true); $("#cNo").onclick = () => done(false); d.oncancel = () => done(false);
    d.showModal();
  });
}

const unlocked = () => S && S.vault === "unlocked";

function lockedView() {
  if (S.error) return `<h1>keysync can't reach Bitwarden.</h1><div class="notice">${esc(S.error)}</div>`;
  return `<h1>Your Bitwarden vault is locked.</h1>
    <p class="lede">keysync keeps your servers and keys in Bitwarden. For your security this page never asks for your master password. Unlock in a terminal, then check again.</p>
    <div class="panel"><div class="setting"><div><strong>Run this in a terminal</strong><p class="mono">keysync unlock</p></div>
      <button class="btn primary" type="button" id="recheck">Check again</button></div></div>`;
}

function servers() {
  const sv = S.servers, active = S.keys.filter(k => k.status === "active").length;
  const managed = sv.filter(s => s.manage).length;
  const rows = sv.map(s => `<tr><td><strong class="mono">${esc(s.alias)}</strong></td><td class="mono">${esc(s.target)}${s.jump ? `<div class="muted">via ${esc(s.jump)}</div>` : ""}</td>
      <td>${s.host_key ? '<span class="pill">Host key pinned</span>' : '<span class="pill">Host key learned on first sync</span>'}${s.password ? '<span class="pill">Password in Bitwarden</span>' : ""}${s.manage ? "" : '<span class="pill">Keys not managed</span>'}</td>
      <td style="text-align:right"><button class="btn small" type="button" data-remove="${esc(s.alias)}">Remove</button></td></tr>`).join("");
  return `<h1>${sv.length ? `${plural(managed, "server trusts", "servers trust")} ${plural(active, "active key")}.` : "No servers yet."}</h1>
    <p class="lede">This account is <span class="mono">${esc(S.account)}</span>. Each sync writes every server below into your SSH config, so <span class="mono">ssh &lt;name&gt;</span> works in every account, then puts every active key on every managed server.</p>
    ${sv.length ? `<div class="panel" style="overflow-x:auto"><table class="list stack"><thead><tr><th>Name</th><th>Login</th><th>Notes</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>` : ""}
    <h3>Add a server</h3>
    <div class="panel"><div class="addform">
      <label>Name<input type="text" id="aAlias" placeholder="web-prod" autocomplete="off"></label>
      <label>Login<input type="text" id="aTarget" placeholder="deploy@203.0.113.10:22" autocomplete="off"></label>
      <label>Jump host (optional)<input type="text" id="aJump" placeholder="bastion" autocomplete="off"></label>
      <div class="span"><label><input type="checkbox" id="aManage" checked> Let keysync manage this server's keys</label>
        <span style="flex:1"></span><button class="btn primary" type="button" id="addBtn">Add server</button></div>
    </div></div>
    <p class="note">Adding a server logs into it once to put every active key there. To store a login password for a server, add it to the server's entry in Bitwarden, or run <span class="mono">keysync add-server &lt;name&gt; &lt;login&gt; --password</span> in a terminal.</p>`;
}

function keys() {
  const ks = S.keys, revoked = ks.filter(k => k.status !== "active").length;
  const rows = ks.map(k => `<tr><td><strong class="mono">${esc(k.name)}</strong>${k.me ? ' <span class="badge">this account</span>' : ""}</td>
      <td class="fp" title="${esc(k.fp)}">${esc(k.fp)}</td><td>${esc(k.created)}</td>
      <td>${k.problem ? `<span class="state warn" title="${esc(k.problem)}">Not deployed: ${esc(k.problem)}</span>` : (k.status === "active" ? '<span class="state ok">Active</span>' : '<span class="state bad">Revoked</span>')}</td>
      <td style="text-align:right">${k.status === "active" ? `<button class="btn small danger" type="button" data-revoke="${esc(k.name)}">Revoke</button>` : `<button class="btn small" type="button" data-reactivate="${esc(k.name)}">Reactivate</button>`}</td></tr>`).join("");
  return `<h1>${plural(ks.length - revoked, "account has", "accounts have")} access${revoked ? `, ${revoked} revoked` : ""}.</h1>
    <p class="lede">Every computer account gets its own key, named after the account and computer. A server's login log shows the fingerprint, and Who logged in? turns it back into a name. Revoke a key when a computer is lost or might be compromised; the next sync removes it from every server.</p>
    <div class="panel" style="overflow-x:auto"><table class="list stack"><thead><tr><th>Account</th><th>Fingerprint</th><th>Created</th><th>Status</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function whois() {
  return `<h1>Who logged in?</h1>
    <p class="lede">Paste a line from a server's login log, such as <span class="mono">/var/log/auth.log</span> or the output of <span class="mono">journalctl -u ssh</span>, or just the fingerprint.</p>
    <textarea id="whoisText" aria-label="Log line or fingerprint" placeholder="Accepted publickey for deploy from 203.0.113.7 port 52144 ssh2: ED25519 SHA256:…"></textarea>
    <div class="savebar"><button class="btn primary" type="button" id="whoisBtn">Look up</button><span class="note" id="whoisNote"></span></div>
    ${whoisResult ? whoisView(whoisResult) : ""}`;
}

function whoisView(r) {
  const m = r.text.match(/^(SHA256:\S+) = account '([^']+)' \(OS user (.*) on machine (.*)\), status (\S+), created (\S+)/);
  if (!m) return `<div class="result">${esc(r.text)}</div>`;
  const [, fp, acct, user, machine, status, created] = m;
  return `<div class="result hit" style="font-family:var(--sans); white-space:normal">
    <strong style="font-size:17px">That login was <span class="mono">${esc(acct)}</span>.</strong>
    <div class="muted" style="margin-top:4px">Computer account ${esc(user)} on ${esc(machine)}. Key created ${esc(created.slice(0, 10))}, ${status === "active" ? "still active" : "now revoked"}.</div>
    <div class="fp" style="margin-top:6px">${esc(fp)}</div></div>`;
}

function automation() {
  const sc = S.schedule;
  return `<h1>Automation</h1>
    <p class="lede">A daily sync picks up new servers and new accounts and puts every active key in place, without you opening this page.</p>
    <div class="panel">
      <div class="setting"><div><strong>Daily sync</strong> ${sc.on ? `<span class="state ok">On${sc.time ? ", daily at " + esc(sc.time) : ""}</span>` : '<span class="state off">Off</span>'}
        <p>Runs through ${esc(sc.how || "your computer's scheduler")} while the vault stays unlocked on this account.</p></div>
        <div class="form-row"><input type="time" id="dailyTime" value="${esc(sc.time || "09:00")}" aria-label="Daily sync time">
          <button class="btn small" type="button" id="schedOn">${sc.on ? "Change time" : "Turn on"}</button>
          ${sc.on ? '<button class="btn small" type="button" id="schedOff">Turn off</button>' : ""}</div></div>
      <div class="setting"><div><strong>Bitwarden vault</strong> ${unlocked() ? '<span class="state ok">Unlocked</span>' : '<span class="state off">Locked</span>'}
        <p>Locking pauses the daily sync until you run <span class="mono">keysync unlock</span> again.</p></div>
        ${unlocked() ? '<button class="btn small" type="button" id="lockBtn">Lock the vault</button>' : ""}</div>
    </div>`;
}

const SECTIONS = {servers, keys, whois, automation};
function render() {
  const id = (location.hash.slice(1) in SECTIONS) ? location.hash.slice(1) : "servers";
  document.querySelectorAll("nav.tabs a").forEach(a => { if (a.hash === "#" + id) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current"); });
  if (!S) return;
  $("#main").innerHTML = (unlocked() || id === "automation") ? SECTIONS[id]() : lockedView();
  $("#checkBtn").disabled = $("#syncBtn").disabled = !unlocked();
  wire(id);
}

async function load() {
  try { S = await api("/api/state"); }
  catch (e) { $("#main").innerHTML = `<div class="notice">${esc(e.message)}</div>`; return; }
  if (S.setup_needed) { $("#main").innerHTML = `<h1>keysync isn't set up on this account yet.</h1><p class="lede">Run the installer in a terminal (it asks for your Bitwarden password), then reload this page.</p>`; return; }
  $("#where").textContent = S.account;
  $("#ver").textContent = `keysync ${S.version}`;
  const rev = unlocked() ? S.keys.filter(k => k.status !== "active").length : 0;
  const c = $("#c-rev"); c.hidden = !rev; c.textContent = rev || "";
  render();
}

function wire(id) {
  if ($("#recheck")) $("#recheck").onclick = load;
  if (id === "servers" && unlocked()) {
    $("#addBtn").onclick = () => {
      const alias = $("#aAlias").value.trim(), target = $("#aTarget").value.trim();
      if (!alias || !target) { $("#aAlias").focus(); return; }
      run("add-server", `Adding ${alias}`, {alias, target, jump: $("#aJump").value.trim(), manage: $("#aManage").checked});
    };
    document.querySelectorAll("[data-remove]").forEach(b => b.onclick = async () => {
      if (await ask(`Remove ${b.dataset.remove}?`, "It's removed from Bitwarden and from every account's SSH config at their next sync. Keys already on the server stay there.", "Remove server", true))
        run("remove-server", `Removing ${b.dataset.remove}`, {alias: b.dataset.remove});
    });
  }
  if (id === "keys" && unlocked()) {
    document.querySelectorAll("[data-revoke]").forEach(b => b.onclick = async () => {
      const k = b.dataset.revoke, mine = S.keys.find(x => x.name === k)?.me;
      const body = mine ? "This is the account you're using. Once revoked, it can't push the change itself, so run Sync now from another account. You can reactivate it later."
                        : `${k}'s key is removed from every server now. Use this when that computer is lost or might be compromised. You can reactivate it later.`;
      if (await ask(`Revoke ${k}?`, body, "Revoke key", true)) run("revoke", `Revoking ${k}`, {key: k});
    });
    document.querySelectorAll("[data-reactivate]").forEach(b => b.onclick = async () => {
      if (await ask(`Reactivate ${b.dataset.reactivate}?`, "Its key goes back onto every server now.", "Reactivate")) run("reactivate", `Reactivating ${b.dataset.reactivate}`, {key: b.dataset.reactivate});
    });
  }
  if (id === "whois" && unlocked()) {
    $("#whoisBtn").onclick = async () => {
      const text = $("#whoisText").value;
      try { await api("/api/run/whois", {text}); } catch (e) { $("#whoisNote").className = "note bad"; $("#whoisNote").textContent = e.message; return; }
      $("#whoisNote").className = "note"; $("#whoisNote").textContent = "Looking it up…";
      const j = await waitJob();
      whoisResult = {text: (j.output || "").trim(), hit: /= account/.test(j.output || "")};
      render(); $("#whoisText").value = text;
    };
  }
  if (id === "automation") {
    $("#schedOn").onclick = () => run("schedule", "Daily sync", {time: $("#dailyTime").value});
    if ($("#schedOff")) $("#schedOff").onclick = () => run("schedule", "Daily sync", {off: true});
    if ($("#lockBtn")) $("#lockBtn").onclick = async () => { if (await ask("Lock the vault?", "Daily syncs pause until you run keysync unlock in a terminal.", "Lock")) run("lock", "Locking the vault"); };
  }
}

async function waitJob() {
  for (;;) {
    await new Promise(r => setTimeout(r, 600));
    let j; try { j = await api("/api/job"); } catch (e) { continue; }
    if (!j.running) return j;
  }
}
async function run(action, title, body = {}) {
  $("#drawer").hidden = false; $("#drawerTitle").textContent = title; $("#drawerOut").textContent = ""; $("#spin").hidden = false;
  $("#drawerNote").className = "note"; $("#drawerNote").textContent = "Running…";
  try { await api("/api/run/" + action, body); }
  catch (e) { $("#drawerOut").textContent = e.message; done(1); return; }
  const tick = setInterval(async () => { try { const j = await api("/api/job"); $("#drawerOut").textContent = j.output || ""; } catch (e) {} }, 700);
  const j = await waitJob(); clearInterval(tick);
  $("#drawerOut").textContent = j.output || ""; done(j.code); load();
}
function done(code) {
  $("#spin").hidden = true;
  $("#drawerNote").className = "note " + (code === 0 ? "ok" : "bad");
  $("#drawerNote").textContent = code === 0 ? "Finished" : "Finished with problems; see the lines starting with !";
}

$("#checkBtn").onclick = () => run("check", "Check access: which servers this account can log into");
$("#syncBtn").onclick = async () => {
  if (await ask("Sync every server now?", "keysync logs into each managed server and updates the keysync block in its authorized_keys. Keys outside that block aren't touched, and each server keeps a backup.", "Sync now"))
    run("sync", "Sync");
};
$("#drawerClose").onclick = () => $("#drawer").hidden = true;
$("#quitBtn").onclick = async () => {
  try { await api("/api/quit", {}); } catch (e) { await ask("Not yet", e.message, "OK"); return; }
  document.body.innerHTML = '<main style="padding:40px"><h1>The settings page has stopped.</h1><p class="lede">You can close this tab. Run <code>keysync ui</code> to open it again.</p></main>';
};
window.addEventListener("hashchange", render);
setInterval(() => { if (!document.hidden) api("/api/ping").catch(() => {}); }, 60000);
load();
</script>
</body>
</html>
"""


class LocalPage:
    """A token-locked page + JSON API on 127.0.0.1. Shared shape with the other tool's settings page."""

    def __init__(self, title, html, get_state, posts, job_argv, script, port=0):
        import secrets as _s
        import threading
        self.title, self.get_state, self.posts, self.job_argv = title, get_state, posts, job_argv
        self.script = script
        self.token = _s.token_urlsafe(24)
        self.nonce = _s.token_urlsafe(16)
        self.html = html.replace("<script>", f'<script nonce="{self.nonce}">')
        self.job = None
        self.job_lock = threading.Lock()
        self.last_seen = time.time()
        self.port = port

    def run_job(self, argv):
        import threading
        with self.job_lock:
            if self.job and self.job["running"]:
                raise ValueError("another action is still running")
            job = {"id": int(time.time() * 1000), "argv": argv, "running": True, "output": "", "code": None}
            self.job = job
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0", PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
        env.setdefault("GIT_SSH_COMMAND", "ssh -o BatchMode=yes")
        # own process group: Ctrl+C or closing the page never interrupts a sync halfway,
        # and with no terminal attached nothing can sit waiting for a password prompt
        detach = {"creationflags": 0x00000200} if IS_WINDOWS else {"start_new_session": True}

        def work():
            try:
                p = subprocess.Popen([sys.executable, str(self.script)] + argv, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                     encoding="utf-8", errors="replace", env=env, **detach)
                for line in p.stdout:
                    job["output"] += line
                job["code"] = p.wait()
            except Exception as e:                       # report, never crash the page
                job["output"] += f"\n{e}\n"
                job["code"] = 1
            job["running"] = False
        threading.Thread(target=work, daemon=True).start()
        return job

    def busy(self):
        return bool(self.job and self.job["running"])

    def _open_browser(self, url):
        """Open the page without putting the token on a command line other users can read."""
        import webbrowser
        if IS_MAC or IS_WINDOWS:                 # handed over via Apple Events / ShellExecute, not argv
            webbrowser.open(url)
            return
        import tempfile
        import threading
        # in the home folder: browsers installed as snaps can't read /tmp
        fd, path = tempfile.mkstemp(prefix="settings-page-", suffix=".html", dir=str(HOME))
        with os.fdopen(fd, "w", encoding="utf-8") as f:   # mkstemp: readable by this user only
            f.write(f'<!doctype html><meta http-equiv="refresh" content="0;url={url}"><a href="{url}">Open</a>')
        webbrowser.open("file://" + path)
        t = threading.Timer(60, lambda: os.path.exists(path) and os.unlink(path))
        t.daemon = True
        t.start()

    def serve(self, open_browser=True):
        import hmac
        import http.server
        import threading
        import urllib.parse
        page = self

        def same(a, b):
            return hmac.compare_digest(a.encode("utf-8", "replace"), b.encode("utf-8", "replace"))

        class Handler(http.server.BaseHTTPRequestHandler):
            server_version = "local"
            sys_version = ""
            timeout = 30                                  # idle connections don't pin threads

            def log_message(self, *a):
                pass

            def _host_ok(self):
                return self.headers.get("Host", "") in (f"127.0.0.1:{page.port}", f"localhost:{page.port}")

            def _send(self, code, body, ctype="application/json"):
                data = body if isinstance(body, bytes) else (
                    json.dumps(body).encode() if ctype == "application/json" else body.encode())
                self.send_response(code)
                self.send_header("Content-Type", ctype + "; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy",
                                 f"default-src 'none'; script-src 'nonce-{page.nonce}'; style-src 'unsafe-inline'; "
                                 "connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; "
                                 "frame-ancestors 'none'")
                self.end_headers()
                self.wfile.write(data)

            def _authed(self):
                ok = self._host_ok() and same(self.headers.get("X-Page-Token", ""), page.token)
                if ok:
                    page.last_seen = time.time()
                return ok

            def do_GET(self):
                u = urllib.parse.urlparse(self.path)
                if u.path == "/":
                    q = urllib.parse.parse_qs(u.query).get("t", [""])[0]
                    if not (self._host_ok() and same(q, page.token)):
                        return self._send(403, "<p>Open the link printed in your terminal. It changes every time "
                                               "the settings page starts.</p>", "text/html")
                    page.last_seen = time.time()
                    return self._send(200, page.html, "text/html")
                if not self._authed():
                    return self._send(403, {"error": "not allowed"})
                try:
                    if u.path == "/api/state":
                        return self._send(200, page.get_state())
                    if u.path == "/api/job":
                        return self._send(200, page.job or {})
                    if u.path == "/api/ping":
                        return self._send(200, {"ok": True})
                except SystemExit as e:
                    return self._send(200, {"setup_needed": str(e)})
                except Exception as e:
                    return self._send(500, {"error": str(e)})
                return self._send(404, {"error": "not found"})

            def do_POST(self):
                if not self._authed() or not self.headers.get("Content-Type", "").startswith("application/json"):
                    return self._send(403, {"error": "not allowed"})
                try:
                    n = int(self.headers.get("Content-Length") or 0)
                    if n > 1_000_000:
                        raise ValueError("request too large")
                    body = json.loads(self.rfile.read(n) or b"{}")
                    if not isinstance(body, dict):
                        raise ValueError("bad request")
                    path = urllib.parse.urlparse(self.path).path
                    if path == "/api/quit":
                        if page.busy():
                            raise ValueError("wait for the running action to finish, then stop the page")
                        self._send(200, {"ok": True})
                        threading.Thread(target=self.server.shutdown, daemon=True).start()
                        return
                    if path.startswith("/api/run/"):
                        job = page.run_job(page.job_argv(path[len("/api/run/"):], body))
                        return self._send(200, job)
                    fn = page.posts.get(path)
                    if not fn:
                        return self._send(404, {"error": "not found"})
                    return self._send(200, fn(body) or {"ok": True})
                except (ValueError, KeyError, TypeError) as e:
                    return self._send(400, {"error": str(e)})
                except SystemExit as e:
                    return self._send(400, {"error": str(e)})
                except Exception as e:
                    return self._send(500, {"error": str(e)})

        class Server(http.server.ThreadingHTTPServer):
            allow_reuse_address = not IS_WINDOWS          # on Windows it would let another user share the port
            daemon_threads = True

        srv = Server(("127.0.0.1", self.port), Handler)
        self.port = srv.server_address[1]
        url = f"http://127.0.0.1:{self.port}/?t={self.token}"

        def idle_watch():                          # stop on its own once the tab has been closed a while
            while True:
                time.sleep(30)
                if not self.busy() and time.time() - self.last_seen > 1800:
                    srv.shutdown()
                    return
        threading.Thread(target=idle_watch, daemon=True).start()
        print(f"{self.title} is open at:\n  {url}\n"
              f"Only this link works; it changes every time. Leave this window open while you use the page,\n"
              f"press Ctrl+C to stop (it also stops by itself 30 minutes after you close the tab).", flush=True)
        if open_browser:
            try:
                self._open_browser(url)
            except Exception:
                pass
        try:
            srv.serve_forever(poll_interval=0.5)
        except KeyboardInterrupt:
            pass
        finally:
            srv.server_close()
        if self.busy():        # the action runs in its own process group, so Ctrl+C didn't reach it
            print("Letting the running action finish first, so nothing is left half done...", flush=True)
            try:
                while self.busy():
                    time.sleep(0.3)
                print((self.job or {}).get("output", "")[-2000:])
            except KeyboardInterrupt:
                print("Stopped waiting. The action may be left half done; run it again to finish.")
        print("Settings page stopped.")


def cmd_ui(args):
    load_config()
    LocalPage("The keysync settings page", KEYSYNC_UI, ui_state, {}, ui_job_argv,
              Path(__file__).resolve(), port=args.port).serve(open_browser=not args.no_browser)


def safe_console():
    """Windows sends piped or redirected output through an old code page (e.g. cp1252) that can't
    encode characters like "…" or "─". Show a "?" instead of crashing halfway through a run."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv=None):
    safe_console()
    p = argparse.ArgumentParser(prog="keysync", description="One SSH key per account, shared through Bitwarden.")
    p.add_argument("--version", action="version", version=VERSION)
    p.add_argument("--quiet", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("setup", help="set up this OS account (sign in to Bitwarden, create + publish its key, sync)")
    sp.add_argument("--import-config", action="store_true", help="also import the hosts in ~/.ssh/config into Bitwarden")
    sp.add_argument("--passphrase", action="store_true", help="protect the new key with a passphrase (kept in the macOS Keychain)")
    sp.add_argument("--folder", help="Bitwarden folder to use (default: keysync)")
    sp.add_argument("--no-deploy", action="store_true", help="don't log into servers yet; only set up this account")
    sp.add_argument("--yes", action="store_true")
    sp.set_defaults(fn=cmd_setup)

    sp = sub.add_parser("sync", help="pull servers + keys from Bitwarden and push every active key to every server")
    sp.add_argument("--only", nargs="+", metavar="SERVER")
    sp.add_argument("--no-deploy", action="store_true", help="only update local ~/.ssh files")
    sp.add_argument("--unattended", action="store_true", help="never prompt (used by the daily job)")
    sp.add_argument("--strict", action="store_true", help="exit 1 if any server failed")
    sp.set_defaults(fn=cmd_sync)

    sp = sub.add_parser("check", help="test which servers this account can log into with its own key")
    sp.add_argument("--only", nargs="+", metavar="SERVER")
    sp.set_defaults(fn=cmd_check)

    sp = sub.add_parser("add-server", help="add or update a server in Bitwarden, then push keys to it")
    sp.add_argument("alias")
    sp.add_argument("target", help="user@host[:port]")
    sp.add_argument("--password", action="store_true", help="prompt for a login password to store in Bitwarden")
    sp.add_argument("--proxy-jump", metavar="HOST", help="reach it through this jump host")
    sp.add_argument("--no-manage", action="store_true", help="keep it in ~/.ssh/config but never change its keys")
    sp.add_argument("--no-deploy", action="store_true")
    sp.set_defaults(fn=cmd_add_server)

    sp = sub.add_parser("remove-server", help="remove a server from Bitwarden")
    sp.add_argument("alias")
    sp.add_argument("--yes", action="store_true")
    sp.set_defaults(fn=cmd_remove_server)

    sp = sub.add_parser("import-config", help="import the hosts in ~/.ssh/config into Bitwarden")
    sp.add_argument("--yes", action="store_true")
    sp.set_defaults(fn=cmd_import_config)

    sp = sub.add_parser("servers", help="list servers")
    sp.set_defaults(fn=cmd_servers)
    sp = sub.add_parser("keys", help="list every account's key")
    sp.set_defaults(fn=cmd_keys)

    sp = sub.add_parser("revoke", help="revoke an account's key and remove it from every server")
    sp.add_argument("key", help="account name (user@machine), user, or fingerprint")
    sp.add_argument("--no-deploy", action="store_true")
    sp.set_defaults(fn=lambda a: set_key_status(a, "revoked"))

    sp = sub.add_parser("reactivate", help="undo a revoke")
    sp.add_argument("key")
    sp.add_argument("--no-deploy", action="store_true")
    sp.set_defaults(fn=lambda a: set_key_status(a, "active"))

    sp = sub.add_parser("whois", help="which account owns a key? paste a fingerprint or an sshd log line")
    sp.add_argument("text", nargs="+")
    sp.set_defaults(fn=cmd_whois)

    sp = sub.add_parser("unlock", help="unlock Bitwarden and store the session for unattended syncs")
    sp.set_defaults(fn=cmd_unlock)
    sp = sub.add_parser("lock", help="lock Bitwarden and forget the stored session")
    sp.set_defaults(fn=cmd_lock)

    sp = sub.add_parser("schedule", help="run `sync` daily (launchd on macOS, cron elsewhere)")
    sp.add_argument("--daily", default="09:00", metavar="HH:MM")
    sp.add_argument("--print", action="store_true")
    sp.add_argument("--remove", action="store_true")
    sp.set_defaults(fn=cmd_schedule)

    sp = sub.add_parser("ui", help="open the settings page in your browser")
    sp.add_argument("--port", type=int, default=0, help="port on 127.0.0.1 (default: any free port)")
    sp.add_argument("--no-browser", action="store_true", help="print the link instead of opening a browser")
    sp.set_defaults(fn=cmd_ui)

    args = p.parse_args(argv)
    Out.quiet = args.quiet
    try:
        rc = args.fn(args) or 0
    except BWError as e:
        Out.warn(f"Bitwarden: {e}")
        rc = 1
    except Fail as e:
        Out.warn(str(e).replace("keysync: ", ""))
        rc = 1
    except KeyboardInterrupt:
        rc = 130
    if args.cmd in ("sync", "setup", "revoke", "reactivate", "add-server"):
        log_run()
    sys.exit(rc)


if __name__ == "__main__":
    main()
