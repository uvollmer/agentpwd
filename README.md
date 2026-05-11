<h1 align="center">AgentPwd</h1>

<h3 align="center">Credential management for AI agents</h3>

<p align="center"><strong>Agents fill the form. They never see the password.</strong></p>

<p align="center">
  <a href="docs/threat-model.md">Threat model</a> ·
  <a href="#roadmap">Roadmap</a> ·
  <a href="https://github.com/uvollmer/agentpwd/issues">Issues</a> ·
  <a href="#license">License</a>
</p>

<br />

```
agent.call("ap_fill_login", { credential_id: "..." })
   ↓
AgentPwd decrypts in memory → injects into the browser via CDP / AppleScript
   ↓
agent.receives({ status: "success" })   ← the agent never sees the plaintext
```

<br />

# Why AgentPwd

You give your AI agent browser access. Sooner or later it needs to log into something.

A normal password manager hands the secret over — and now it's in the LLM's context window. Logged, cached, potentially leaked into telemetry. One prompt injection away from being exfiltrated.

AgentPwd is built differently. Every credential operation is shaped *do something with the credential* — fill a form, inject as an env var, generate a TOTP. The agent gets back `{status: "success"}`. Plaintext flows from the encrypted vault to the browser through the AgentPwd process, never through the LLM.

Think of it as `1Password's op run`, except the *fill itself* stays out of the context — not just the env var.

<br />

# Getting started

```bash
git clone https://github.com/uvollmer/agentpwd && cd agentpwd
npm install && npm run build

# Create your default vault — master key goes into the OS keychain
node dist/cli/index.js init

# Add a credential interactively (hidden password input)
node dist/cli/index.js add --site github.com --username me@example.com

# Or auto-generate a strong one
node dist/cli/index.js add --site aws.amazon.com --username admin --generate

# Inspect (metadata only)
node dist/cli/index.js list
```

Wire the MCP server into your agent. For [Claude Code](https://claude.com/claude-code), drop this into `.mcp.json`:

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

Then ask your agent to log in somewhere. It'll call `ap_fill_login(credential_id="...")` and the form fills — without the LLM ever seeing what got typed.

A hosted version where credentials never reach the agent's machine at all is on the [roadmap](#roadmap).

<br />

# Tools

The MCP surface. Ten tools. The "No" column is the whole point.

| Tool | Returns plaintext to the LLM? |
|---|---|
| `ap_create_vault` | No |
| `ap_list_vaults` | No |
| `ap_create_credential` | No |
| `ap_list_credentials` | No — IDs, sites, usernames |
| `ap_delete_credential` | No |
| `ap_fill_login` | No — injected straight into the browser |
| `ap_fill_field` | No |
| `ap_set_totp` | No |
| `ap_fill_totp` | No — code injected, not returned |
| `ap_run` | No — output is scrubbed for the password and common encodings |

Every fill tool accepts an optional `cdp_url` so agents driving remote browsers pass their endpoint directly.

<br />

# Browsers

Two injection paths, one abstraction.

| Target | What to do |
|---|---|
| Local Chrome on macOS (already open) | Enable *View → Developer → Allow JavaScript from Apple Events*. AgentPwd uses AppleScript out of the box. |
| Local Chrome anywhere | Launch with `--remote-debugging-port=9222`. AgentPwd auto-detects. |
| Browserbase, Anchor, Browserless | Pass their `connectUrl` / `cdp_url` as the `cdp_url` parameter. |
| OpenClaw managed sessions | Same — pass the CDP endpoint. |
| Browser Use, Playwright, Puppeteer | CDP under the hood; same. |

The property-descriptor + `input`/`change` event dispatch logic is identical across paths — frameworks (React, Vue, Angular) see the value update like real user input.

<br />

# Anti-phishing

Before every fill, AgentPwd reads the page URL and matches its hostname against the credential's stored site. Mismatches are refused with an explicit error.

| Active tab | Credential | Result |
|---|---|---|
| `https://github.com/login` | `github.com` | ✅ filled |
| `https://login.github.com` | `github.com` | ✅ filled (subdomain) |
| `https://fake-github.com` | `github.com` | ❌ refused |
| `https://github.com.evil.com` | `github.com` | ❌ refused |

<br />

# Security

Read the **[threat model](docs/threat-model.md)** before relying on this for anything sensitive — it's the load-bearing doc.

Short version: AgentPwd defends well against the *intended* path leaking plaintext into the LLM. It does not, in v1, defend against a malicious agent with shell access. Such an agent can read the master key from the OS keychain directly and decrypt the vault. v2 (hosted vault + remote browser, see roadmap) closes that gap by removing the credentials from the agent's machine entirely.

Crypto: [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers) (AES-256-GCM) + [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) (Argon2id) + [`keytar`](https://github.com/atom/node-keytar) (OS keychain).

<br />

# Roadmap

Landing in v1:

- **Share flow** — a one-time link for a human to type a password they only know. Zero-knowledge: client-side Web Crypto with a per-request key, served over a cloudflared tunnel.
- **`ap setup` wizard** — first-run UX: vault init, MCP config, platform guidance.
- **Wait-for-navigation in `ap_fill_login`** — shrink the post-fill DOM exposure window to near-zero by blocking on `Page.frameNavigated` before returning.
- **Agent recipes** — one-page guide per target: Claude Code, Claude for Chrome, OpenClaw, Hermes, Browserbase, Anchor.

Bigger work for v2, gated on traction from the v1 OSS launch:

- **Hosted vault + remote browser** — credentials never reach the agent's machine. The hosted service decrypts in its own memory and pushes via CDP to the remote browser (Browserbase, Anchor, etc.). A locally-compromised agent finds nothing to extract.
- **Chrome extension** — bridge for local Chrome under the hosted-vault model. Meaningfully better than a standalone daemon for that case.

<br />

# Stack

TypeScript + Node 20+. [MCP](https://modelcontextprotocol.io) SDK. SQLite via [`better-sqlite3`](https://github.com/WiseLibs/better-sqlite3). [`chrome-remote-interface`](https://github.com/cyrus-and/chrome-remote-interface) for CDP. Vitest for tests.

<br />

# Contributing

Early days. Feedback and small focused PRs welcome — for non-trivial changes, file an issue first. For security reports, email instead of opening a public issue.

<br />

# License

MIT — see [LICENSE](LICENSE).
