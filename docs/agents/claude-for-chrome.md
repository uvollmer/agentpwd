# Claude for Chrome

[Claude for Chrome](https://www.anthropic.com/news/claude-for-chrome) is Anthropic's research-preview Chrome extension that lets Claude operate the user's browser. AgentPwd plugs in by running locally and using the same browser Claude is operating on.

## Setup

1. Install AgentPwd locally and initialize a vault (see [Claude Code recipe](claude-code.md#setup) — same steps).
2. Launch Chrome **with the debug port** *before* opening Claude for Chrome — the flag is read at startup, can't be toggled on a running Chrome.
   ```bash
   /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --remote-debugging-port=9222
   ```
3. Wire the AgentPwd MCP server into whatever runs Claude for Chrome's tool calls (typically your local Claude Code config). Same `.mcp.json` snippet as the Claude Code recipe.

## Flow

```
Claude for Chrome (extension in your Chrome tab)
        │
        │ MCP tool call: ap_fill_login(credential_id="...")
        ▼
AgentPwd MCP server (local Node process)
        │
        │ decrypts credential in memory
        │ opens CDP to http://localhost:9222 (auto-detected)
        │ Runtime.evaluate injects username + password into the active tab
        │ clicks submit, blocks until Page.frameNavigated
        ▼
Form fills + page navigates + Claude sees {status: "success", navigated: true}
```

The tab Claude for Chrome is operating on is the same tab AgentPwd fills. No coordination needed beyond ensuring the right tab is focused.

## Why launch with the debug port

If you skip step 2 on macOS, AgentPwd falls back to AppleScript, which still works against the focused Chrome tab — but you lose the wait-for-navigation guarantee and a few error-handling improvements that CDP enables. On Linux/Windows, AppleScript isn't an option, so the debug port is required.

## Caveats

- **Tab focus matters.** Both AppleScript and CDP-auto-detect operate on the active page. If Claude for Chrome navigates to one tab and you have a different tab focused, the fill may go to the wrong place. Domain validation will catch the mismatch with an explicit error.
- **Future improvement.** A dedicated AgentPwd Chrome extension would let two extensions cohabit cleanly without the debug-port dance. Tracked on the [v2 roadmap](../threat-model.md#roadmap--closing-the-gap).
