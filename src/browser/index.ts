import { request } from "node:http";
import { Injector } from "./injector.js";
import { AppleScriptInjector } from "./applescript.js";
import { CdpInjector } from "./cdp.js";

export { Injector, domainMatches } from "./injector.js";
export type { FillResult, DetectedFields } from "./injector.js";
export { AppleScriptInjector } from "./applescript.js";
export { CdpInjector } from "./cdp.js";

export interface InjectorOptions {
  /** Optional CDP endpoint (http://host:port for discovery, or ws(s)://... direct). */
  cdpUrl?: string;
  /** Override the auto-probed default port (defaults to 9222). */
  localCdpPort?: number;
}

/**
 * Resolve an injector backend in this order:
 *   1. If `cdpUrl` was passed → CDP backend
 *   2. If `http://localhost:9222` (or `localCdpPort`) is reachable → CDP backend
 *   3. If running on macOS → AppleScript backend
 *   4. Otherwise → throw with explicit guidance
 *
 * Callers MUST call `injector.close()` when done (CDP holds a WebSocket).
 */
export async function getInjector(
  opts: InjectorOptions = {},
): Promise<Injector> {
  if (opts.cdpUrl) {
    return CdpInjector.connect(opts.cdpUrl);
  }

  const port = opts.localCdpPort ?? 9222;
  if (await isCdpReachable("127.0.0.1", port)) {
    return CdpInjector.connect(`http://127.0.0.1:${port}`);
  }

  if (process.platform === "darwin") {
    return new AppleScriptInjector();
  }

  throw new Error(
    "No injection backend available. " +
      "On macOS, AppleScript is used by default (requires Chrome with " +
      "'View → Developer → Allow JavaScript from Apple Events' enabled). " +
      "Otherwise, pass cdp_url to use a remote/managed browser, or launch " +
      "Chrome with --remote-debugging-port=9222.",
  );
}

function isCdpReachable(host: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const req = request(
      {
        host,
        port,
        path: "/json/version",
        method: "GET",
        timeout: 250,
      },
      (res) => {
        resolve(res.statusCode === 200);
        res.resume();
      },
    );
    req.on("error", () => resolve(false));
    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });
    req.end();
  });
}
