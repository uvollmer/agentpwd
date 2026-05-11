# AgentPwd

**Credential management for AI agents. Agents fill the form. They never see the password.**

```
agent.call("ap_fill_login", { credential_id: "..." })
   ↓
AgentPwd decrypts in memory → injects into the browser via CDP / AppleScript
   ↓
agent.receives({ status: "success" })   ← the agent never sees the plaintext
```

That's the whole pitch. Same idea as 1Password's `op run`, except the *fill* itself stays out of the LLM's context — not just an env var.

---

## Why this exists

A normal password manager hands the secret to whoever asked. That works fine for humans typing into a browser. If you give an LLM access to "give me the GitHub password", that secret is now in the LLM's context window — logged, cached, potentially leaked into telemetry, and one prompt-injection away from being exfiltrated.

AgentPwd's MCP tools are shaped *do something with the credential* (fill a form, inject as an env var, generate a TOTP), and they always return `{status, ...}` metadata. Plaintext flows from the encrypted vault to the browser through the AgentPwd process, never out through the MCP response.

---

## Status

Early. Roadmap below. The threat model is documented honestly — see [`docs/threat-model.md`](docs/threat-model.md) for what v1 defends against, what it doesn't (an agent with shell access can extract the master key from the OS keychain; defended in v2), and the planned improvements.

## Quick start

```bash
git clone https://github.com/uvollmer/agentpwd && cd agentpwd
npm install
npm run build

# Initialize a default vault (master key → OS keychain)
node dist/cli/index.js init

# Add a credential interactively
node dist/cli/index.js add --site github.com --username me@example.com
# Enter password: ••••••••••

# Or auto-generate a strong password
node dist/cli/index.js add --site aws.amazon.com --username admin --generate

# List (metadata only, no passwords)
node dist/cli/index.js list
```

Wire the MCP server into your agent. For Claude Code, add to `.mcp.json`:

```json
{
  "mcpServers": {
    "agentpwd": {
      "command": "node",
      "args": ["/path/to/agentpwd/dist/mcp/server.js"]
    }
  }
}
```

## CLI

| Command | What it does |
|---|---|
| `ap init [name]` | Create a vault, store master key in OS keychain |
| `ap add --site --username [--generate]` | Add a credential (hidden password input, or auto-generated) |
| `ap list` | List credentials in a vault (metadata only) |
| `ap delete --id` | Delete a credential |
| `ap vaults` | List all vaults |

**No `ap show`** in v1. A TTY-gated reveal would be fake security (trivially bypassed by `script -q`, `pty.spawn`, etc.). Real human-only reveal needs hardware-attested user presence (Touch ID / Windows Hello) — deferred to v2.

## MCP tools

| Tool | Returns plaintext? |
|---|---|
| `ap_create_vault` | No |
| `ap_list_vaults` | No |
| `ap_create_credential` | No (auto-generates password if omitted; returns ID, never the value) |
| `ap_list_credentials` | No (IDs, sites, usernames) |
| `ap_delete_credential` | No |
| `ap_fill_login` | No — injects directly into the browser |
| `ap_fill_field` | No |
| `ap_set_totp` | No |
| `ap_fill_totp` | No — TOTP code injected, never returned |
| `ap_run` | No — output is scrubbed for the password + common encodings |

Every fill tool accepts an optional `cdp_url` so agents driving remote browsers (Browserbase, Anchor, OpenClaw, Browserless) pass their endpoint directly. Without `cdp_url`, the tools auto-detect `http://localhost:9222` (Chrome with `--remote-debugging-port`) and fall back to AppleScript on macOS.

## Browser injection paths

| Target | Mechanism |
|---|---|
| Local Chrome (mac, already open) | AppleScript — needs Chrome → View → Developer → *Allow JavaScript from Apple Events* |
| Local Chrome with `--remote-debugging-port=9222` (any OS) | CDP, auto-detected |
| Browserbase / Anchor / Browserless / OpenClaw managed | CDP, pass their endpoint as `cdp_url` |
| Browser Use / Playwright / Puppeteer | CDP under the hood |

All paths go through the same `Injector` abstraction. Same property-descriptor-setter + `input`/`change` event dispatch logic — frameworks (React/Vue/Angular) see the value update like real user input.

## Anti-phishing: domain validation

Before every fill, AgentPwd reads the page's URL via the injector and compares its hostname against the credential's stored site. If they don't match, the fill is refused with an explicit error.

| Active tab URL | Credential site | Result |
|---|---|---|
| `https://github.com/login` | `github.com` | ✅ filled |
| `https://login.github.com` | `github.com` | ✅ filled (subdomain) |
| `https://fake-github.com` | `github.com` | ❌ refused |
| `https://github.com.evil.com` | `github.com` | ❌ refused |

## Security

- **Encryption**: AES-256-GCM with per-entry random nonces ([`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers))
- **Key derivation**: Argon2id, 64 MiB / 3 iterations ([`@noble/hashes`](https://github.com/paulmillr/noble-hashes))
- **Master key**: random 256-bit, stored in OS keychain (macOS Keychain / Linux Secret Service / Windows Credential Manager) via `keytar`
- **Storage**: SQLite (WAL mode), encrypted at the application layer
- **Domain validation**: every fill is gated on hostname match (anti-phishing)
- **Output scrubbing**: `ap_run` redacts the password and common encodings (base64, hex, URL-encoded, reversed) from stdout/stderr. Best-effort, **not a boundary** — see threat model.
- **Audit log**: every credential access logged (who, when, which credential — never the value)

The threat model is the load-bearing doc — please read [`docs/threat-model.md`](docs/threat-model.md) before relying on this for anything sensitive. v1 is honest about its limits: an agent with shell access can extract credentials by reading the OS keychain directly. v2 (hosted vault + remote browser) closes that gap.

## Architecture

```
agentpwd/
├── src/
│   ├── vault/
│   │   ├── crypto.ts          # AES-256-GCM + Argon2id
│   │   ├── keychain.ts        # OS keychain (master key)
│   │   ├── store.ts           # SQLite encrypted CRUD + audit log
│   │   ├── password-gen.ts    # Secure password generator
│   │   └── totp.ts            # RFC 4226 HMAC-SHA1 TOTP
│   ├── browser/
│   │   ├── injector.ts        # Abstract Injector base + types + domainMatches
│   │   ├── applescript.ts     # macOS AppleScript backend
│   │   ├── cdp.ts             # CDP backend via chrome-remote-interface
│   │   └── index.ts           # getInjector() factory
│   ├── mcp/
│   │   ├── server.ts          # MCP server (stdio)
│   │   ├── tools.ts           # 10 MCP tool definitions
│   │   └── scrub.ts           # ap_run output scrubbing
│   ├── cli/
│   │   └── index.ts           # CLI (ap command)
│   └── types.ts
├── tests/                     # vitest — vault + scrub + injector + CDP integration
└── docs/
    └── threat-model.md
```

## Platform support

- **macOS**: full support (CDP + AppleScript)
- **Linux**: CDP-only (launch Chrome with `--remote-debugging-port` or use a remote browser)
- **Windows**: CDP-only (same)

## Roadmap

What's deliberately not in v1 (in rough order):

- **Share flow** (`ap_request_credential`) — generate a one-time link for a human to type a password they only know. Zero-knowledge via cloudflared tunnel + client-side Web Crypto with a per-request key.
- **`ap setup` wizard** — first-run UX: initialize vault, write MCP config, print platform guidance.
- **Wait-for-navigation in `ap_fill_login`** — shrink the post-fill DOM-exposure window to near-zero by blocking on `Page.frameNavigated` before returning. Documented in the threat model.
- **Agent integration recipes** under `docs/agents/` — one-pager per target: Claude Code, Claude for Chrome, OpenClaw, Hermes, Browserbase, Anchor.
- **`ap audit` CLI** — surface the existing audit log from a terminal.
- **Claude Code hook examples** under `hooks/` — `PreToolUse` block patterns that elevate `ap_run` and keychain-extraction attempts.

Larger work for v2 (gated on traction signal from this v1 OSS launch):

- **Hosted vault + remote browser** — credentials never reach the user's machine; the hosted service decrypts in its own memory and pushes via CDP to the remote browser (Browserbase, Anchor, etc.). A locally-compromised agent finds nothing to decrypt. Details in the threat model.
- **Chrome extension** — bridge for local Chrome under the hosted-vault model. Meaningfully better than a standalone local daemon for that case.

## Contributing

Early days. Feedback and small focused PRs welcome — for non-trivial changes, file an issue first. For security reports, please email instead of opening a public issue.

## License

MIT — see [LICENSE](LICENSE).
