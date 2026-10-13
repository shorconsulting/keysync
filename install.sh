#!/bin/bash
# keysync installer for macOS and Linux. Run once in each user account:
#     bash "/path/to/keysync/install.sh"
# (Windows: use install.ps1 instead.)
# It asks before importing servers, before changing anything on a server,
# and before scheduling the daily sync.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
KS="python3 $HOME/.keysync/keysync.py"
say() { printf "\n\033[1m%s\033[0m\n" "$*"; }
ask() { local a; read -r -p "$1 [y/N] " a; [[ "$a" =~ ^[Yy] ]]; }
OS="$(uname -s)"

if ! command -v python3 >/dev/null; then
  if [ "$OS" = Darwin ]; then echo "Python 3 is missing. Run:  xcode-select --install   then run this again."
  else echo "Python 3 is missing. Install it (e.g. sudo apt install python3), then run this again."; fi
  exit 1
fi
if ! command -v ssh-keygen >/dev/null; then
  echo "OpenSSH is missing. Install it (e.g. sudo apt install openssh-client), then run this again."; exit 1
fi
if ! command -v bw >/dev/null; then
  say "The Bitwarden CLI isn't installed for this account."
  if [ "$OS" = Darwin ] && command -v brew >/dev/null && ask "Install it now (brew install bitwarden-cli)?"; then
    brew install bitwarden-cli; hash -r
  elif command -v npm >/dev/null && ask "Install it now (npm install -g @bitwarden/cli)?"; then
    npm install -g @bitwarden/cli; hash -r
  elif [ "$OS" = Linux ] && command -v snap >/dev/null && ask "Install it now (sudo snap install bw)?"; then
    sudo snap install bw; hash -r
  else
    echo "Install it with  npm install -g @bitwarden/cli  (macOS: brew install bitwarden-cli), then run this again."; exit 1
  fi
fi

say "Step 1 of 4 — Set up this account"
echo "Signs in to Bitwarden (first time only), creates this account's own SSH key and publishes its public key."
python3 "$HERE/keysync.py" setup --no-deploy

say "Step 2 of 4 — Servers"
echo "Hosts in this account's ~/.ssh/config that aren't in Bitwarden yet (you'll be asked before anything is imported):"
$KS import-config
echo; echo "Servers in Bitwarden:"; $KS servers

say "Step 3 of 4 — Put keys on the servers"
echo "This logs into each server above and updates the keysync block in its ~/.ssh/authorized_keys."
echo "Keys outside that block are left alone, and each server keeps a backup (authorized_keys.keysync-bak)."
if ask "Do it now?"; then $KS sync; else echo "Skipped. Run  keysync sync  when you're ready."; fi

say "Step 4 of 4 — Daily sync"
if ask "Sync automatically every day at 09:00?"; then $KS schedule; else echo "Skipped. Run  keysync schedule  any time."; fi

say "Done. Open a new terminal window to use the 'keysync' command."
