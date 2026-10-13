---
name: ssh-keys
description: Manage SSH access to the user's servers with keysync, which gives each computer account its own SSH key and shares the server list and public keys through Bitwarden. Use when the user wants to add a server, give an account or computer access to their servers, check which servers an account can reach, find out which account made a login, revoke a lost or compromised machine, or set up keysync.
---

# keysync

keysync gives every OS account on every computer its own SSH key, which makes logins traceable. It keeps the list of servers and every account's public key in a "keysync" folder in Bitwarden. Its sync rewrites a marked block in each server's `~/.ssh/authorized_keys` so that every active key is trusted. Private keys never leave the account they were created on.

## How to run it

- After setup, use the `keysync` command. If that command isn't found, run `python3 ~/.keysync/keysync.py` instead, or on Windows `py -3 "%USERPROFILE%\.keysync\keysync.py"`.
- The tool ships at `${CLAUDE_PLUGIN_ROOT}/keysync.py`.

## Setup belongs to the user

Setup needs the user's Bitwarden master password, and you must never type a password. If `~/.keysync/config.json` doesn't exist, ask the user to run the installer in their own terminal:

- macOS / Linux: `bash "${CLAUDE_PLUGIN_ROOT}/install.sh"`
- Windows (PowerShell): `powershell -ExecutionPolicy Bypass -File "${CLAUDE_PLUGIN_ROOT}\install.ps1"`

If a command reports that the vault is locked, ask the user to run `keysync unlock` themselves.

## What you can run

- **Read-only, safe any time:**
  - `keysync servers`: list servers.
  - `keysync keys`: list every account's key and its status.
  - `keysync check`: which servers this account reaches with its own key.
  - `keysync whois "<sshd log line or SHA256 fingerprint>"`: which account made a login.
- **Changes servers, so ask first:** `keysync sync` logs into every server and updates the keysync block in its `authorized_keys`. Keys outside that block are never touched, and each server keeps `authorized_keys.keysync-bak`.
- **Adding a server:** `keysync add-server <name> user@host[:port]`, optionally with `--proxy-jump <host>` or `--no-manage`. Don't pass `--password`, because it prompts for input. If the user wants a stored password, ask them to run that command themselves.
- **Revoking, always confirm:** `keysync revoke <user@machine>` removes that account's key from every server. Explain that this is the response to a lost or compromised machine, and that `keysync reactivate` undoes it.

## Settings page

If the user would rather click than type, suggest they run `keysync ui` in their own terminal. It opens a page in their browser for servers, keys, revoking and "who logged in", and keeps running in that window, so don't start it yourself. It never asks for the master password; a locked vault still needs `keysync unlock` in their terminal.

## Reading the results

- **NO ACCESS:** this account's key isn't on that server yet. A sync from any account that can already log in fixes it, as does storing the server's password in Bitwarden.
- **unreachable, "closed the connection before login":** newer OpenSSH servers briefly block an address after several failed logins (often right after a new account was set up). Suggest waiting a few minutes, then syncing again.
- **HOST KEY CHANGED:** stop and tell the user. Either the server was rebuilt or the connection is being intercepted. Only after a rebuild should they clear the `host_keys` field of that server in Bitwarden.
