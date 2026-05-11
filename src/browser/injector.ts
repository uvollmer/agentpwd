export interface FillResult {
  status: "success" | "error";
  reason?: string;
}

export interface DetectedFields {
  usernameSelector: string | null;
  passwordSelector: string | null;
  submitSelector: string | null;
}

/**
 * Abstract base class for browser injection backends.
 * Subclasses (AppleScriptInjector, CdpInjector) only need to implement
 * `evaluate()` and `close()`. The high-level methods (fillField, fillLogin,
 * detectLoginFields, getCurrentUrl) are transport-agnostic and live here.
 */
export abstract class Injector {
  abstract evaluate(jsCode: string): Promise<string>;
  abstract close(): Promise<void>;

  async getCurrentUrl(): Promise<string> {
    const raw = await this.evaluate("window.location.href");
    return stripQuotes(raw).trim();
  }

  async fillField(cssSelector: string, value: string): Promise<FillResult> {
    const b64 = Buffer.from(value, "utf-8").toString("base64");
    const jsCode = `(function() {
  var el = document.querySelector(${JSON.stringify(cssSelector)});
  if (!el) return 'ERROR:Element not found';
  var v = atob('${b64}');
  var setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  setter.call(el, v);
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
  return 'ok';
})()`;

    try {
      const result = await this.evaluate(jsCode);
      const v = stripQuotes(result);
      if (v.startsWith("ERROR:")) {
        return { status: "error", reason: v.slice(6) };
      }
      return { status: "success" };
    } catch (err) {
      return {
        status: "error",
        reason: err instanceof Error ? err.message : String(err),
      };
    }
  }

  async clickElement(cssSelector: string): Promise<FillResult> {
    const jsCode = `(function() {
  var el = document.querySelector(${JSON.stringify(cssSelector)});
  if (!el) return 'ERROR:Element not found';
  el.click();
  return 'ok';
})()`;

    try {
      const result = await this.evaluate(jsCode);
      const v = stripQuotes(result);
      if (v.startsWith("ERROR:")) {
        return { status: "error", reason: v.slice(6) };
      }
      return { status: "success" };
    } catch (err) {
      return {
        status: "error",
        reason: err instanceof Error ? err.message : String(err),
      };
    }
  }

  async detectLoginFields(): Promise<DetectedFields> {
    const jsCode = `(function() {
  function findVisible(selectors) {
    for (var i = 0; i < selectors.length; i++) {
      var els = document.querySelectorAll(selectors[i]);
      for (var j = 0; j < els.length; j++) {
        var el = els[j];
        var style = window.getComputedStyle(el);
        if (style.display !== 'none' && style.visibility !== 'hidden' &&
            style.opacity !== '0' && el.offsetWidth > 0 && el.offsetHeight > 0) {
          return selectors[i];
        }
      }
    }
    return null;
  }

  var userSels = [
    'input[type="email"]',
    'input[autocomplete="username"]',
    'input[autocomplete="email"]',
    'input[name="email"]',
    'input[name="username"]',
    'input[name="login"]',
    'input[name="user"]',
    'input[name="login_field"]',
    'input[id*="email"]',
    'input[id*="user"]',
    'input[id*="login"]',
    'input[type="text"]'
  ];

  var passSels = [
    'input[type="password"]',
    'input[autocomplete="current-password"]',
    'input[autocomplete="new-password"]',
    'input[name="password"]',
    'input[name="passwd"]'
  ];

  var submitSels = [
    'button[type="submit"]',
    'input[type="submit"]',
    'button[name="commit"]',
    'form button'
  ];

  return JSON.stringify({
    usernameSelector: findVisible(userSels),
    passwordSelector: findVisible(passSels),
    submitSelector: findVisible(submitSels)
  });
})()`;

    try {
      const result = await this.evaluate(jsCode);
      return JSON.parse(stripQuotes(result));
    } catch {
      return {
        usernameSelector: null,
        passwordSelector: null,
        submitSelector: null,
      };
    }
  }

  async fillLogin(username: string, password: string): Promise<FillResult> {
    const fields = await this.detectLoginFields();

    if (!fields.usernameSelector && !fields.passwordSelector) {
      return {
        status: "error",
        reason: "No login form fields detected on the page",
      };
    }

    if (fields.usernameSelector && !fields.passwordSelector) {
      const res = await this.fillField(fields.usernameSelector, username);
      if (res.status === "error") return res;

      if (fields.submitSelector) {
        await this.clickElement(fields.submitSelector);
        await new Promise((r) => setTimeout(r, 2000));
        const newFields = await this.detectLoginFields();
        if (newFields.passwordSelector) {
          const passRes = await this.fillField(
            newFields.passwordSelector,
            password,
          );
          if (passRes.status === "error") return passRes;
          if (newFields.submitSelector) {
            await this.clickElement(newFields.submitSelector);
          }
          return { status: "success" };
        }
        return {
          status: "error",
          reason: "Password field not found after username submission",
        };
      }
      return {
        status: "error",
        reason: "Submit button not found for username-first flow",
      };
    }

    if (fields.usernameSelector) {
      const res = await this.fillField(fields.usernameSelector, username);
      if (res.status === "error") return res;
    }

    if (fields.passwordSelector) {
      const res = await this.fillField(fields.passwordSelector, password);
      if (res.status === "error") return res;
    }

    if (fields.submitSelector) {
      await this.clickElement(fields.submitSelector);
    }

    return { status: "success" };
  }
}

/**
 * Strip surrounding quotes from a value returned by Chrome's JS evaluation.
 * AppleScript wraps strings in quotes; CDP returns raw values, but we
 * normalize to a plain string either way.
 */
function stripQuotes(s: string): string {
  if (s.length >= 2) {
    const first = s[0];
    const last = s[s.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      return s.slice(1, -1);
    }
  }
  return s;
}

/**
 * Compares the current page URL's hostname against a credential's stored site.
 * Returns true if the hostname equals the site OR is a subdomain of the site.
 *
 * Examples (assuming credential.site = "github.com"):
 *   https://github.com/login         → true
 *   https://login.github.com         → true
 *   https://fake-github.com          → false
 *   https://github.com.evil.com      → false
 */
export function domainMatches(
  currentUrl: string,
  credentialSite: string,
): boolean {
  let site = credentialSite.trim().toLowerCase();
  // Strip protocol
  site = site.replace(/^https?:\/\//, "");
  // Strip path/query/hash
  site = site.split(/[/?#]/)[0];
  // Strip port
  site = site.split(":")[0];

  if (!site) return false;

  let host: string;
  try {
    host = new URL(currentUrl).hostname.toLowerCase();
  } catch {
    return false;
  }

  if (host === site) return true;
  if (host.endsWith("." + site)) return true;
  return false;
}
