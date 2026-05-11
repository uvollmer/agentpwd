# OpenClaw

[OpenClaw](https://openclaw.ai) drives Chromium via raw CDP — local managed, headless, and remote configurations all expose a CDP endpoint. AgentPwd integrates by reusing that endpoint as its `cdp_url`.

## Setup

AgentPwd setup is the same as for any other client (see [Claude Code recipe](claude-code.md#setup)). The only OpenClaw-specific bit is that you pass the per-session CDP endpoint into the MCP fill calls.

## Flow

```
Agent
   │ 1. starts OpenClaw browser session, receives CDP endpoint
   │
   │ 2. calls ap_fill_login(credential_id="abc", cdp_url="<openclaw cdp endpoint>")
   ▼
AgentPwd MCP server
   │ decrypts credential
   │ opens CDP WebSocket to the OpenClaw session
   │ Runtime.evaluate injects, clicks submit, blocks until navigation
   ▼
Form filled in the OpenClaw-driven browser
```

## Sample tool call

```json
{
  "name": "ap_fill_login",
  "arguments": {
    "credential_id": "<your stored credential id>",
    "cdp_url": "<openclaw cdp endpoint, e.g. ws://...>"
  }
}
```

`ap_fill_field` and `ap_fill_totp` take the same `cdp_url` parameter.

## Notes

- **Snapshot/ref vs raw CDP.** OpenClaw recommends its snapshot/ref API for the agent's own actions. AgentPwd's CDP injection is independent of that — both can run against the same browser session without conflict.
- **Domain validation runs.** Before each fill, AgentPwd reads `window.location.href` from the OpenClaw session and matches against the credential's stored site. Mismatches are refused with an explicit error.
- **Per-call connection.** AgentPwd opens and closes a CDP WebSocket per fill — no persistent state in the AgentPwd process. OpenClaw's session lifecycle is unaffected.
