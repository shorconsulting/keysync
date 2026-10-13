# Security

## Reporting a vulnerability

Please report security problems privately through GitHub: **Security → Report a vulnerability** on this repository. For anything else, open an issue.

## What keysync does with credentials

keysync manages SSH access from your own accounts to your own servers, so it has to use credentials that already exist on your computer. It reads only these, and passes each only to the program shown:

| Credential | Passed to |
|---|---|
| The Bitwarden session token made by `keysync unlock` (never your master password), from `BW_SESSION`, the macOS Keychain, a DPAPI-encrypted file on Windows, or a mode-600 file on Linux | your own `bw` CLI |
| This account's keysync SSH key, `~/.ssh/keysync_ed25519` | your own `ssh` |
| Your existing SSH keys or SSH agent, only to reach a server the first time | your own `ssh` |
| A server's optional bootstrap password from your Bitwarden folder | your own `ssh`, through a private helper, never written to disk |

No credential is sent to any other host. Data leaves your computer only to your own Bitwarden vault and the SSH servers you list. See [PRIVACY.md](PRIVACY.md) and the README's "Credentials it reads from your computer, and why".

## Automated scanner findings, explained

Automated plugin scanners pair any URL in a file with any credential the plugin reads, and flag shell pipes. These findings are false positives:

| Where | What is flagged | What it actually is |
|---|---|---|
| `keysync.py` | `shorconsulting.com`, `github.com` | The publisher and source links in the settings page footer. Nothing is sent there. |
| `keysync.py` | `127.0.0.1` | The settings page, which listens only on this computer, behind a random per-run token. |
| `keysync.py` | a script piped to a remote shell over `ssh` | keysync sends its own `authorized_keys` script, written inside `keysync.py`, to your server over `ssh`. Nothing is downloaded. |
| skill and README | reads `~/.ssh/authorized_keys`, uses `ssh` | Updating the keysync block in your servers' `authorized_keys` over `ssh` is what keysync is for. |
| `tests/windows_check.py` | `127` | The test logs in to a closed port on this computer, so nothing is contacted. |
| `tests/*` | HTTP requests and command output handed to a local checker | Requests to the local settings page at 127.0.0.1 and local command output, checked locally. Tests run only when a developer starts them by hand. |

The plugin fetches and runs nothing from the network at install or run time. The installers (`install.sh`, `install.ps1`) offer to install Python and the Bitwarden CLI from your system's package manager (`brew`, `npm` or `winget`) and ask before each step.
