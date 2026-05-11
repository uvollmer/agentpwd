import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, existsSync, rmSync } from "node:fs";
import { tmpdir, platform } from "node:os";
import { join } from "node:path";
import { request } from "node:http";
import { CdpInjector } from "../src/browser/cdp.js";

/**
 * Locate a Chromium-family browser on this machine. Returns null if none found,
 * which causes the test to skip gracefully (CI without Chrome installed).
 */
function findChrome(): string | null {
  const fromEnv = process.env.CHROME_PATH;
  if (fromEnv && existsSync(fromEnv)) return fromEnv;

  if (platform() === "darwin") {
    const candidates = [
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
      "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
      "/Applications/Chromium.app/Contents/MacOS/Chromium",
    ];
    return candidates.find((p) => existsSync(p)) ?? null;
  }

  // Linux: try PATH lookups
  if (platform() === "linux") {
    const candidates = [
      "/usr/bin/google-chrome",
      "/usr/bin/google-chrome-stable",
      "/usr/bin/chromium",
      "/usr/bin/chromium-browser",
    ];
    return candidates.find((p) => existsSync(p)) ?? null;
  }

  return null;
}

async function waitForPort(port: number, timeoutMs = 10000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const ok = await new Promise<boolean>((resolve) => {
      const req = request(
        { host: "127.0.0.1", port, path: "/json/version", timeout: 250 },
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
    if (ok) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`Chrome debug port :${port} did not open within ${timeoutMs}ms`);
}

const chromePath = findChrome();
const PORT = 9333; // use a non-default port to avoid colliding with a user's running Chrome

const fixtureHtml = `
<!doctype html>
<html><body>
<input id="email" type="email" />
<input id="pw" type="password" />
<button type="submit">Sign in</button>

<script>
  // Simulate framework state tracking: state is only updated when input/change
  // events fire (like React/Vue/Angular). A naive \`el.value = 'x'\` would NOT
  // trigger these events on its own — agentpwd's injector must dispatch them
  // explicitly after the prototype-setter write, otherwise frameworks miss it.
  window._state = { email: '', pw: '' };
  window._events = [];

  function track(el, key) {
    el.addEventListener('input', () => {
      window._state[key] = el.value;
      window._events.push(key + ':input');
    });
    el.addEventListener('change', () => {
      window._state[key] = el.value;
      window._events.push(key + ':change');
    });
  }
  track(document.getElementById('email'), 'email');
  track(document.getElementById('pw'), 'pw');
</script>
</body></html>
`;

describe.skipIf(!chromePath)("CdpInjector integration", () => {
  let chrome: ChildProcess | null = null;
  let userDataDir = "";
  let injector: CdpInjector | null = null;

  beforeAll(async () => {
    if (!chromePath) return;
    userDataDir = mkdtempSync(join(tmpdir(), "ap-cdp-test-"));

    chrome = spawn(
      chromePath,
      [
        "--headless=new",
        `--remote-debugging-port=${PORT}`,
        "--remote-debugging-address=127.0.0.1",
        `--user-data-dir=${userDataDir}`,
        "--disable-gpu",
        "--no-first-run",
        "--no-default-browser-check",
        "--hide-scrollbars",
        `data:text/html;charset=utf-8,${encodeURIComponent(fixtureHtml)}`,
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );

    await waitForPort(PORT);
    injector = await CdpInjector.connect(`http://127.0.0.1:${PORT}`);
    // Give the page a moment to evaluate the inline script
    await new Promise((r) => setTimeout(r, 200));
  }, 30000);

  afterAll(async () => {
    if (injector) await injector.close();
    if (chrome) {
      chrome.kill("SIGKILL");
      await new Promise((r) => setTimeout(r, 100));
    }
    if (userDataDir) {
      try {
        rmSync(userDataDir, { recursive: true, force: true });
      } catch {}
    }
  });

  it("reads the current URL", async () => {
    if (!injector) return;
    const url = await injector.getCurrentUrl();
    expect(url).toMatch(/^data:text\/html/);
  });

  it("fills a controlled input via property-descriptor setter", async () => {
    if (!injector) return;
    const result = await injector.fillField("#email", "alice@example.com");
    expect(result.status).toBe("success");

    const stateJson = await injector.evaluate("JSON.stringify(window._state)");
    const state = JSON.parse(stateJson);
    expect(state.email).toBe("alice@example.com");
  });

  it("dispatches input and change events on filled fields", async () => {
    if (!injector) return;
    // Reset events
    await injector.evaluate("window._events = []; void 0");
    await injector.fillField("#pw", "hunter2");

    const eventsJson = await injector.evaluate(
      "JSON.stringify(window._events)",
    );
    const events = JSON.parse(eventsJson);
    expect(events).toContain("pw:input");
    expect(events).toContain("pw:change");
  });

  it("returns an error on missing selector", async () => {
    if (!injector) return;
    const result = await injector.fillField("#does-not-exist", "x");
    expect(result.status).toBe("error");
    expect(result.reason).toMatch(/not found/i);
  });

  it("detectLoginFields finds email + password + submit", async () => {
    if (!injector) return;
    const fields = await injector.detectLoginFields();
    expect(fields.passwordSelector).toBeTruthy();
    expect(fields.usernameSelector).toBeTruthy();
    expect(fields.submitSelector).toBeTruthy();
  });

  it("waitForNavigation times out when nothing navigates", async () => {
    if (!injector) return;
    const start = Date.now();
    const navigated = await injector.waitForNavigation({ timeoutMs: 500 });
    const elapsed = Date.now() - start;
    expect(navigated).toBe(false);
    // Should NOT take much longer than the requested timeout
    expect(elapsed).toBeLessThan(2000);
  });

  it("waitForNavigation resolves true when the top frame navigates", async () => {
    if (!injector) return;
    // Kick off the wait and the navigation concurrently. We navigate to
    // about:blank (not another data: URL) because Chromium headless does NOT
    // emit Page.frameNavigated for cross-data-URL navigations — empirically
    // verified. about:blank is a reliable trigger.
    const waitPromise = injector.waitForNavigation({ timeoutMs: 5000 });
    setTimeout(() => {
      injector!
        .evaluate("window.location.assign('about:blank')")
        .catch(() => {});
    }, 100);

    const navigated = await waitPromise;
    expect(navigated).toBe(true);

    // Give Chromium a moment to settle after the navigation
    await new Promise((r) => setTimeout(r, 200));
  }, 10000);
});
