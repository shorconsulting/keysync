# keysync installer for Windows. Run once in each Windows user account, from PowerShell:
#     powershell -ExecutionPolicy Bypass -File "C:\path\to\keysync\install.ps1"
# It asks before importing servers, before changing anything on a server,
# and before scheduling the daily sync.
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
function Say($t) { Write-Host ""; Write-Host $t -ForegroundColor Cyan }
function Ask($q) { (Read-Host "$q [y/N]") -match '^[Yy]' }
function Refresh-Path {
  $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
}

# Python (the "python" in WindowsApps is only a Microsoft Store shortcut, not a real install)
$PyExe = $null; $PyArgs = @()
if (Get-Command py -ErrorAction SilentlyContinue) { $PyExe = 'py'; $PyArgs = @('-3') }
else {
  $c = Get-Command python -ErrorAction SilentlyContinue
  if ($c -and $c.Source -notmatch 'WindowsApps') { $PyExe = 'python' }
}
if (-not $PyExe) {
  Say "Python 3 isn't installed."
  if ((Get-Command winget -ErrorAction SilentlyContinue) -and (Ask "Install it now (winget install Python.Python.3.13)?")) {
    winget install --id Python.Python.3.13 -e --accept-source-agreements --accept-package-agreements
    Refresh-Path; $PyExe = 'py'; $PyArgs = @('-3')
  } else { Write-Host "Install Python 3 from python.org (or: winget install Python.Python.3.13), then run this again."; exit 1 }
}
function KS { & $PyExe @PyArgs "$HOME\.keysync\keysync.py" @args }

# OpenSSH client (built into Windows 10/11, but can be turned off)
if (-not (Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
  Write-Host "The OpenSSH Client isn't installed. Add it in Settings > System > Optional features > Add a feature > OpenSSH Client, then run this again."
  exit 1
}

# Bitwarden CLI
if (-not (Get-Command bw -ErrorAction SilentlyContinue)) {
  Say "The Bitwarden CLI isn't installed for this account."
  if ((Get-Command winget -ErrorAction SilentlyContinue) -and (Ask "Install it now (winget install Bitwarden.CLI)?")) {
    winget install --id Bitwarden.CLI -e --accept-source-agreements --accept-package-agreements; Refresh-Path
  } elseif ((Get-Command npm -ErrorAction SilentlyContinue) -and (Ask "Install it now (npm install -g @bitwarden/cli)?")) {
    npm install -g @bitwarden/cli; Refresh-Path
  } else { Write-Host "Install it with  winget install --id Bitwarden.CLI -e  (or npm install -g @bitwarden/cli), then run this again."; exit 1 }
}

Say "Step 1 of 4 - Set up this account"
Write-Host "Signs in to Bitwarden (first time only), creates this account's own SSH key and publishes its public key."
& $PyExe @PyArgs "$Here\keysync.py" setup --no-deploy
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Say "Step 2 of 4 - Servers"
Write-Host "Hosts in this account's .ssh\config that aren't in Bitwarden yet (you'll be asked before anything is imported):"
KS import-config
Write-Host ""; Write-Host "Servers in Bitwarden:"; KS servers

Say "Step 3 of 4 - Put keys on the servers"
Write-Host "This logs into each server above and updates the keysync block in its ~/.ssh/authorized_keys."
Write-Host "Keys outside that block are left alone, and each server keeps a backup (authorized_keys.keysync-bak)."
if (Ask "Do it now?") { KS sync } else { Write-Host "Skipped. Run  keysync sync  when you're ready." }

Say "Step 4 of 4 - Daily sync"
if (Ask "Sync automatically every day at 09:00?") { KS schedule } else { Write-Host "Skipped. Run  keysync schedule  any time." }

Say "Done. Open a new terminal window to use the 'keysync' command."
