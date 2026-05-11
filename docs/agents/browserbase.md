# Browserbase

[Browserbase](https://browserbase.com) returns a CDP-compatible WebSocket per session. AgentPwd connects to it directly.

## Getting the CDP URL

Browserbase's session API returns a `connectUrl` (`wss://...`):

```bash
curl -X POST https://api.browserbase.com/v1/sessions \
  -H "X-BB-API-Key: $BROWSERBASE_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"projectId\":\"$BROWSERBASE_PROJECT_ID\"}"
```

Response (abridged):

```json
{
  "id": "abc...",
  "connectUrl": "wss://connect.browserbase.com?apiKey=...&sessionId=abc...",
  "signingKey": "..."
}
```

The `connectUrl` is a **browser-level** WebSocket. AgentPwd handles this transparently by attaching to the first page target via `Target.attachToTarget` (flatten mode) — you don't need to do anything special.

## Flow

```
Agent
   │ 1. creates Browserbase session → gets connectUrl
   │ 2. navigates the session to the login page (Playwright, Puppeteer, or raw CDP — your choice)
   │ 3. calls ap_fill_login(credential_id="abc", cdp_url="<connectUrl>")
   ▼
AgentPwd MCP server
   │ decrypts credential in memory
   │ opens its own short-lived CDP connection to connectUrl
   │ attaches to the page target, injects, clicks submit, blocks until navigation
   ▼
Form filled in the Browserbase Chrome
   │
   ▼
Agent receives {status: "success", navigated: true} — never sees the password
```

## Sample tool call

```json
{
  "name": "ap_fill_login",
  "arguments": {
    "credential_id": "<credential id>",
    "cdp_url": "wss://connect.browserbase.com?apiKey=...&sessionId=..."
  }
}
```

## Trust model

- The password flows: AgentPwd memory → TLS to Browserbase → Browserbase Chrome → form. Browserbase sees the value as part of the form submission (same as any password manager filling into their browser).
- The LLM still gets only `{status, navigated}` back.
- Anti-phishing domain validation runs server-side: AgentPwd reads the page's URL via CDP and refuses to fill if the hostname doesn't match the credential's site. If your agent navigated to the wrong page, the fill is rejected — not silently mis-filled.

## Caveats

- **Session expiry.** Browserbase sessions time out. If the session expires before AgentPwd connects, you'll get a connection error from the CDP WebSocket — not a credential leak.
- **Browser-level CDP.** AgentPwd auto-handles the attachment to a page target. If the session has no pages yet (race), the fill returns a clear error.
