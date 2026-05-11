import CDP from "chrome-remote-interface";
import { Injector } from "./injector.js";

/**
 * CDP-based injector. Speaks Chrome DevTools Protocol over WebSocket.
 *
 * Used for:
 *   - Local Chrome launched with --remote-debugging-port=9222 (HTTP discovery URL)
 *   - Remote browser providers (Browserbase connectUrl, Anchor cdp_url, Browserless)
 *   - OpenClaw managed sessions
 *   - Browser Use / Playwright-driven Chromium (CDP under the hood)
 *
 * Accepts either:
 *   - HTTP(S) discovery URL (http://localhost:9222) — picks an active page
 *   - Direct WebSocket URL (ws(s)://...) — connects, auto-attaches to a page
 *     target if the connection is browser-level
 */
export class CdpInjector extends Injector {
  private constructor(
    private client: CDP.Client,
    private sessionId?: string,
  ) {
    super();
  }

  static async connect(url: string): Promise<CdpInjector> {
    const opts = parseConnectionUrl(url);

    if (opts.kind === "http") {
      // HTTP discovery: enumerate page targets, pick the first non-DevTools page.
      // chrome-remote-interface's default target picker does this, but we do it
      // explicitly so we can throw a clearer error if no page exists.
      const targets = await CDP.List({ host: opts.host, port: opts.port });
      const pages = targets.filter(
        (t) => t.type === "page" && !t.url.startsWith("devtools://"),
      );
      if (pages.length === 0) {
        throw new Error(
          `No page targets at ${url}. Is Chrome launched with --remote-debugging-port?`,
        );
      }
      const client = await CDP({
        host: opts.host,
        port: opts.port,
        target: pages[0],
      });
      return new CdpInjector(client);
    }

    // WebSocket URL — connect directly. The connection may be browser-level
    // (Browserbase, Anchor) in which case Runtime.evaluate isn't valid; we
    // need to attach to a page target with flatten=true and route via sessionId.
    const client = await CDP({ target: opts.url });

    try {
      const { targetInfos } = await client.send("Target.getTargets");
      const pages = (targetInfos as Array<{
        type: string;
        url: string;
        targetId: string;
      }>).filter((t) => t.type === "page" && !t.url.startsWith("devtools://"));

      if (pages.length > 0) {
        const { sessionId } = await client.send("Target.attachToTarget", {
          targetId: pages[0].targetId,
          flatten: true,
        });
        return new CdpInjector(client, sessionId);
      }
    } catch {
      // Either the Target domain isn't available (already a page-level
      // connection), or the connection doesn't support attachToTarget — in
      // either case fall through and treat as an already-page-level client.
    }

    return new CdpInjector(client);
  }

  async evaluate(jsCode: string): Promise<string> {
    const params = {
      expression: jsCode,
      returnByValue: true,
      awaitPromise: true,
    };

    const response = this.sessionId
      ? await this.client.send("Runtime.evaluate", params, this.sessionId)
      : await this.client.Runtime.evaluate(params);

    if (response.exceptionDetails) {
      const detail =
        response.exceptionDetails.exception?.description ||
        response.exceptionDetails.text ||
        "Runtime.evaluate exception";
      throw new Error(detail);
    }

    const value = response.result?.value;
    if (value === undefined || value === null) return "";
    return typeof value === "string" ? value : JSON.stringify(value);
  }

  async close(): Promise<void> {
    try {
      await this.client.close();
    } catch {
      // Connection may already be closed; nothing to do.
    }
  }
}

type ConnectionOpts =
  | { kind: "http"; host: string; port: number }
  | { kind: "ws"; url: string };

function parseConnectionUrl(url: string): ConnectionOpts {
  if (url.startsWith("http://") || url.startsWith("https://")) {
    const u = new URL(url);
    const port = u.port
      ? parseInt(u.port, 10)
      : u.protocol === "https:"
        ? 443
        : 80;
    return { kind: "http", host: u.hostname, port };
  }
  if (url.startsWith("ws://") || url.startsWith("wss://")) {
    return { kind: "ws", url };
  }
  throw new Error(
    `Unsupported CDP URL scheme: ${url}. Use http(s):// for discovery or ws(s):// for direct connection.`,
  );
}
