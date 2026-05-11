# Anchor Browser

[Anchor Browser](https://anchorbrowser.io) returns a `cdp_url` per session. AgentPwd connects to it directly — same shape as Browserbase / OpenClaw / Browserless.

## Getting the CDP URL

Anchor's `Start Browser Session` API (and the async `Session Status` endpoint) returns a session object containing `cdp_url`, `live_view_url`, and `session_id`. The `cdp_url` is what AgentPwd needs.

## Sample tool call

```json
{
  "name": "ap_fill_login",
  "arguments": {
    "credential_id": "<credential id>",
    "cdp_url": "<anchor cdp_url>"
  }
}
```

The same `cdp_url` works for `ap_fill_field` and `ap_fill_totp`.

## Flow

```
Agent
   │ 1. starts an Anchor session → gets cdp_url
   │ 2. navigates the session to the login page (Playwright, Puppeteer, raw CDP — whatever)
   │ 3. calls ap_fill_login(credential_id, cdp_url=<cdp_url>)
   ▼
AgentPwd MCP server
   │ decrypts credential
   │ opens a CDP WebSocket to cdp_url
   │ attaches to the page target if the URL is browser-level (auto)
   │ injects, clicks submit, blocks until Page.frameNavigated
   │ closes the connection
   ▼
Form filled in the Anchor browser; agent receives {status: "success", navigated: true}
```

## Notes

- **Browser-level vs page-level URL.** Anchor's `cdp_url` may be either. AgentPwd handles both — for browser-level, it auto-attaches to the first page target with flatten mode.
- **Domain validation runs.** AgentPwd reads `window.location.href` from the Anchor session and refuses fills on hostname mismatch with an explicit error.
- **Per-call cleanup.** AgentPwd closes its CDP WebSocket after each fill. Anchor's session lifecycle is managed independently by your agent.
