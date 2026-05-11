# Claude Code

[Claude Code](https://claude.com/claude-code) speaks MCP natively. Wire AgentPwd in via the standard `.mcp.json` mechanism and the 10 tools become available to the agent.

## Setup

After `npm install` + `npm run build`, drop this into your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "agentpwd": {
      "command": "node",
      "args": ["/absolute/path/to/agentpwd/dist/mcp/server.js"]
    }
  }
}
```

For user-level config (available across projects), use `claude mcp add` instead.

Initialize a vault before the first tool call:

```bash
node /path/to/agentpwd/dist/cli/index.js init
node /path/to/agentpwd/dist/cli/index.js add --site github.com --username me
```

## Browser path

What AgentPwd will do depends on your OS and Chrome state:

| OS | Chrome state | Path used |
|---|---|---|
| macOS | Already open (default) | AppleScript — enable Chrome → View → Developer → *Allow JavaScript from Apple Events* |
| macOS | Launched with `--remote-debugging-port=9222` | CDP, auto-detected (preferred when available) |
| Linux / Windows | Launched with `--remote-debugging-port=9222` | CDP, auto-detected |
| Linux / Windows | Already open without debug port | Not supported — use a remote browser via `cdp_url` |

For the CDP path, launch Chrome like this and leave it running:

```bash
# macOS
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --remote-debugging-port=9222

# Linux
google-chrome --remote-debugging-port=9222

# Windows
"C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222
```

## Sample interaction

```
You: log me into github.com using my agentpwd credential
Claude: [calls ap_list_credentials → finds id]
        [calls ap_fill_login(credential_id="<id>")]
        → {status: "success", navigated: true}
        Logged in.
```

## Optional hardening

Add a `PreToolUse` hook on `mcp__agentpwd__ap_run` if you want a confirmation prompt or a deny-list for shell commands the agent might try to run with credential injection. Example hooks ship in `hooks/` (TODO).

See the [threat model](../threat-model.md) for what AgentPwd defends against and what it doesn't.
