# Hermes (Nous Research)

> **Status: stub.** [Hermes' public docs](https://hermes-agent.nousresearch.com/docs) describe "full web control — search, extract, browse, vision" but don't disclose whether it exposes a CDP endpoint that external tools can connect to. Help wanted.

## If Hermes exposes CDP per session

The integration is identical to [OpenClaw](openclaw.md), [Browserbase](browserbase.md), or [Anchor](anchor-browser.md): pass the endpoint as `cdp_url` to AgentPwd's MCP fill tools.

```json
{
  "name": "ap_fill_login",
  "arguments": {
    "credential_id": "<credential id>",
    "cdp_url": "<hermes cdp endpoint>"
  }
}
```

## If Hermes drives an internal browser without external CDP access

Integration would require one of:

- A **user-controlled local browser** — Hermes operates the user's Chrome (the user runs Chrome with `--remote-debugging-port=9222`, AgentPwd auto-detects, Hermes drives via whatever mechanism it normally uses)
- A future Hermes API that accepts text-injection commands from external tools
- An AgentPwd Chrome extension as the cross-tool bridge (planned for v2)

## Want to help

If you use Hermes and have insight into the browser tool internals, please open an issue or PR against this file with:

1. Whether the session creation API returns a CDP-compatible WebSocket URL
2. The field name and any auth model
3. If not, whether there's a documented way to inject text into the active page from an external process
