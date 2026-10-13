# keysync privacy policy

Effective 2026-10-13. Publisher: David Shor (Shor Consulting).

keysync is a tool that runs entirely on your own computers. The publisher runs no server for it and receives no data from it: no telemetry, no analytics, no crash reports, no accounts.

## What keysync handles

- **Your computer login name and computer name** (for example `david@macbook-air`). keysync uses them to label this account's SSH key so that every login can be traced to an account. The label is stored in your own Bitwarden vault and in the `authorized_keys` file on the servers you list.
- **SSH public keys, server details and optional server passwords** that you or other accounts in your organization add. They are stored in one folder of your own Bitwarden vault.
- **Credentials on your computer**: the Bitwarden session token made by `keysync unlock`, this account's keysync SSH key, and any existing SSH keys. They are passed only to your own `bw` CLI and `ssh` programs. The README's "Credentials it reads from your computer, and why" table lists each one.

## Where data goes

Only to services you choose and control:

- **Your Bitwarden vault**, through the official Bitwarden CLI signed in as you. Bitwarden's own privacy policy applies to your vault.
- **The SSH servers you list**, where keysync updates its marked block in `authorized_keys`.

Nothing is sent to the publisher, to Anthropic, or to anyone else. When you use keysync through Claude Code, the commands' output is shown to Claude in your session as with any other command. keysync never gives Claude your Bitwarden master password, which you type only in your own terminal.

## Retention and deletion

keysync keeps nothing outside your own computers, vault and servers. To remove its data:

- run `keysync revoke <account>` to remove a key from every server;
- run `keysync lock` on each computer to delete the stored Bitwarden session;
- delete the `keysync` folder in your Bitwarden vault;
- on each computer, delete `~/.keysync/`, the `keysync_*` files in `~/.ssh/`, and the `Include` line keysync added to `~/.ssh/config`.

## Children

keysync is a tool for developers and system administrators and is not intended for anyone under 18.

## Changes and contact

Changes to this policy are published in this file, with its history in the repository. Questions: open an issue at https://github.com/shorconsulting/keysync/issues.
