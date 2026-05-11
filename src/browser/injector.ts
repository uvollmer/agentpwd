export interface FillResult {
  status: "success" | "error";
  reason?: string;
  /**
   * For login flows: did the page navigate after submit?
   * - `true` — the form submitted, navigation observed; the filled DOM
   *   is gone. This is the safe outcome.
   * - `false` — submit was clicked but no navigation observed within the
   *   timeout (login failed, SPA without URL change, slow server). The
   *   caller should treat this as "submission may not have succeeded" and
   *   the password field may have been best-effort cleared post-hoc.
   * - `undefined` — this fill didn't involve a submit (e.g. fillField).
   */
  navigated?: boolean;
}

export interface DetectedFields {
  usernameSelector: string | null;
  passwordSelector: string | null;
  submitSelector: string | null;
}

/** Card-form autocomplete tokens we know how to fill. */
export const CARD_TOKENS = [
  "cc-number",
  "cc-exp",
  "cc-exp-month",
  "cc-exp-year",
  "cc-csc",
  "cc-name",
] as const;
export type CardToken = (typeof CARD_TOKENS)[number];

/** Identity-form autocomplete tokens we know how to fill. */
export const IDENTITY_TOKENS = [
  "given-name",
  "family-name",
  "name",
  "email",
  "tel",
  "street-address",
  "address-line1",
  "address-line2",
  "address-level1",
  "address-level2",
  "postal-code",
  "country",
  "country-name",
  "bday",
] as const;
export type IdentityToken = (typeof IDENTITY_TOKENS)[number];

export type DetectedTokenMap = Partial<Record<string, string>>;

/** A normalized payload the injector consumes — `{ token: value }`. */
export interface CardFillPayload {
  number: string;
  expMonth: string;
  expYear: string;
  cvc: string;
  holderName: string;
}

/** Iframe selectors that indicate a hosted payment widget we don't support yet. */
const IFRAME_PAYMENT_WIDGET_SELECTORS = [
  'iframe[name^="__privateStripeFrame"]',
  'iframe[src*="js.stripe.com"]',
  'iframe[name*="adyen"]',
  'iframe[src*="adyen.com"]',
  'iframe[src*="braintreegateway.com"]',
];

/**
 * Abstract base class for browser injection backends.
 * Subclasses (AppleScriptInjector, CdpInjector) only need to implement
 * `evaluate()` and `close()`. The high-level methods (fillField, fillLogin,
 * detectLoginFields, getCurrentUrl) are transport-agnostic and live here.
 */
export interface WaitForNavigationOptions {
  /** Max time to wait, in ms. Defaults to 5000. */
  timeoutMs?: number;
}

export abstract class Injector {
  abstract evaluate(jsCode: string): Promise<string>;
  abstract close(): Promise<void>;

  /**
   * Block until the page navigates (top-level URL changes) or the timeout
   * elapses. Default implementation polls window.location.href every 250ms.
   * CDP overrides this with a Page.frameNavigated subscription for tighter
   * timing. Returns true if navigation observed within timeout, false if
   * the timeout elapsed first.
   *
   * Used by fillLogin() after clicking submit so the MCP tool doesn't
   * return until the filled DOM is gone — closes the post-fill exposure
   * window for an agent that might read input.value before navigation
   * completes.
   */
  async waitForNavigation(opts: WaitForNavigationOptions = {}): Promise<boolean> {
    const timeoutMs = opts.timeoutMs ?? 5000;
    const start = Date.now();
    let initialUrl: string;
    try {
      initialUrl = await this.getCurrentUrl();
    } catch {
      // If we can't read the URL, the page may already be transitioning;
      // treat that as a navigation signal.
      return true;
    }
    while (Date.now() - start < timeoutMs) {
      await new Promise((r) => setTimeout(r, 250));
      try {
        const url = await this.getCurrentUrl();
        if (url !== initialUrl) return true;
      } catch {
        // Connection in transition — likely a navigation tearing the
        // previous page down. Treat as success.
        return true;
      }
    }
    return false;
  }

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
          return this.submitAndWait(newFields.submitSelector, newFields.passwordSelector);
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

    return this.submitAndWait(fields.submitSelector, fields.passwordSelector);
  }

  // ----- Card / Identity (PII) helpers -----

  /**
   * Detect a visible iframe payment widget (Stripe Elements, Adyen, Braintree).
   * Returns the selector that matched, or null.
   */
  async detectIframePaymentWidget(): Promise<string | null> {
    const sels = JSON.stringify(IFRAME_PAYMENT_WIDGET_SELECTORS);
    const jsCode = `(function() {
  var sels = ${sels};
  for (var i = 0; i < sels.length; i++) {
    var el = document.querySelector(sels[i]);
    if (el) {
      var s = window.getComputedStyle(el);
      if (s.display !== 'none' && s.visibility !== 'hidden') return sels[i];
    }
  }
  return null;
})()`;
    try {
      const raw = await this.evaluate(jsCode);
      const v = stripQuotes(raw);
      return v === "null" || v === "" ? null : v;
    } catch {
      return null;
    }
  }

  /**
   * Generic page-protocol check: returns "https" for https://, "localhost-http" for
   * http://localhost or http://127.0.0.1, or "other" otherwise.
   */
  async getPageProtocol(): Promise<"https" | "localhost-http" | "other"> {
    const jsCode = `(function() {
  var p = window.location.protocol;
  var h = window.location.hostname;
  if (p === 'https:') return 'https';
  if (p === 'http:' && (h === 'localhost' || h === '127.0.0.1' || h === '::1')) return 'localhost-http';
  return 'other';
})()`;
    try {
      const raw = await this.evaluate(jsCode);
      const v = stripQuotes(raw);
      if (v === "https" || v === "localhost-http") return v;
      return "other";
    } catch {
      return "other";
    }
  }

  /** Find a visible input with autocomplete=<token>, returning its CSS selector or null. */
  protected async detectByAutocomplete(
    tokens: readonly string[],
  ): Promise<DetectedTokenMap> {
    const list = JSON.stringify(tokens);
    const jsCode = `(function() {
  var tokens = ${list};
  function isVisible(el) {
    var s = window.getComputedStyle(el);
    return s.display !== 'none' && s.visibility !== 'hidden' &&
           s.opacity !== '0' && el.offsetWidth > 0 && el.offsetHeight > 0;
  }
  function selectorFor(el) {
    if (el.id) return '#' + CSS.escape(el.id);
    var ac = el.getAttribute('autocomplete');
    if (ac) return 'input[autocomplete="' + ac + '"]';
    if (el.name) return 'input[name="' + el.name + '"]';
    return null;
  }
  var out = {};
  tokens.forEach(function(tok) {
    var nodes = document.querySelectorAll(
      'input[autocomplete~="' + tok + '"], input[autocomplete*="' + tok + '"], select[autocomplete~="' + tok + '"]'
    );
    for (var i = 0; i < nodes.length; i++) {
      if (isVisible(nodes[i])) {
        var sel = selectorFor(nodes[i]);
        if (sel) { out[tok] = sel; break; }
      }
    }
  });
  return JSON.stringify(out);
})()`;
    try {
      const raw = await this.evaluate(jsCode);
      return JSON.parse(stripQuotes(raw)) as DetectedTokenMap;
    } catch {
      return {};
    }
  }

  async detectCardFields(): Promise<DetectedTokenMap> {
    return this.detectByAutocomplete(CARD_TOKENS);
  }

  async detectIdentityFields(): Promise<DetectedTokenMap> {
    return this.detectByAutocomplete(IDENTITY_TOKENS);
  }

  /**
   * Apply viewport-only masking on `cc-number` and `cc-csc` inputs:
   *   - style.webkitTextSecurity = "disc"   (rendered as dots; input.value unchanged)
   *   - element.blur()                       (kill autocomplete dropdown, lose focus salience)
   *
   * Vision-only mitigation. Does NOT defend against DOM reads (`input.value`
   * still returns the PAN). See docs/threat-model.md.
   */
  protected async maskCardFields(
    selectors: { ccNumber?: string; ccCsc?: string },
  ): Promise<void> {
    const targets = [selectors.ccNumber, selectors.ccCsc].filter(
      (s): s is string => Boolean(s),
    );
    if (targets.length === 0) return;
    const sels = JSON.stringify(targets);
    const jsCode = `(function() {
  var sels = ${sels};
  sels.forEach(function(s) {
    var el = document.querySelector(s);
    if (!el) return;
    try { el.style.webkitTextSecurity = 'disc'; } catch (e) {}
    try { el.style.textSecurity = 'disc'; } catch (e) {}
    try { el.blur(); } catch (e) {}
  });
  try { if (document.activeElement && document.activeElement.blur) document.activeElement.blur(); } catch (e) {}
  return 'ok';
})()`;
    try {
      await this.evaluate(jsCode);
    } catch {
      // Best-effort. A failed mask doesn't break the fill.
    }
  }

  /**
   * Fill a card payment form. Detects fields by autocomplete token, fills what's
   * present. Does NOT submit — checkout flows are multi-step. Returns the list
   * of autocomplete tokens that were filled.
   */
  async fillCard(
    data: CardFillPayload,
  ): Promise<FillResult & { fieldsFilled?: string[] }> {
    const detected = await this.detectCardFields();
    const filled: string[] = [];

    if (detected["cc-number"]) {
      const r = await this.fillField(detected["cc-number"], data.number);
      if (r.status === "error") return r;
      filled.push("cc-number");
    }
    if (detected["cc-name"]) {
      const r = await this.fillField(detected["cc-name"], data.holderName);
      if (r.status === "error") return r;
      filled.push("cc-name");
    }
    // Expiry: prefer combined cc-exp; fall back to split month/year.
    if (detected["cc-exp"]) {
      // Default to MM/YY; if the input's maxlength suggests MM/YYYY, send that.
      const value = `${data.expMonth}/${data.expYear.slice(-2)}`;
      const r = await this.fillField(detected["cc-exp"], value);
      if (r.status === "error") return r;
      filled.push("cc-exp");
    } else {
      if (detected["cc-exp-month"]) {
        const r = await this.fillField(detected["cc-exp-month"], data.expMonth);
        if (r.status === "error") return r;
        filled.push("cc-exp-month");
      }
      if (detected["cc-exp-year"]) {
        const r = await this.fillField(detected["cc-exp-year"], data.expYear);
        if (r.status === "error") return r;
        filled.push("cc-exp-year");
      }
    }
    if (detected["cc-csc"]) {
      const r = await this.fillField(detected["cc-csc"], data.cvc);
      if (r.status === "error") return r;
      filled.push("cc-csc");
    }

    if (filled.length === 0) {
      return {
        status: "error",
        reason: "No card fields detected on the page (autocomplete cc-* tokens)",
      };
    }

    await this.maskCardFields({
      ccNumber: detected["cc-number"],
      ccCsc: detected["cc-csc"],
    });

    return { status: "success", fieldsFilled: filled };
  }

  /**
   * Fill an identity (name/email/phone/address) form. Detects fields by
   * autocomplete token, fills what's present AND for which we have a value.
   * Does NOT submit.
   */
  async fillIdentity(
    data: Partial<Record<IdentityToken, string>>,
  ): Promise<FillResult & { fieldsFilled?: string[] }> {
    const detected = await this.detectIdentityFields();
    const filled: string[] = [];

    for (const token of IDENTITY_TOKENS) {
      const selector = detected[token];
      const value = data[token];
      if (!selector || !value) continue;
      const r = await this.fillField(selector, value);
      if (r.status === "error") return r;
      filled.push(token);
    }

    if (filled.length === 0) {
      return {
        status: "error",
        reason: "No identity fields detected on the page (autocomplete tokens)",
      };
    }
    return { status: "success", fieldsFilled: filled };
  }

  /**
   * Click the submit button (if found) and block until the page navigates,
   * to close the post-fill DOM exposure window. If no navigation happens
   * within the timeout (login failed, SPA without URL change, slow server),
   * best-effort clear the password field so the cleartext isn't sitting in
   * input.value waiting for an agent to read it.
   */
  private async submitAndWait(
    submitSelector: string | null,
    passwordSelector: string | null,
  ): Promise<FillResult> {
    if (!submitSelector) {
      // No submit button found — caller will need to submit elsewhere. We
      // can't wait for a navigation we didn't trigger.
      return { status: "success", navigated: false };
    }
    await this.clickElement(submitSelector);
    const navigated = await this.waitForNavigation();
    if (!navigated && passwordSelector) {
      // Best-effort cleanup: form submission already either fired or didn't.
      // Clear the password field so its value isn't lingering for an agent
      // that reads the DOM. Failure to clear isn't fatal.
      try {
        await this.fillField(passwordSelector, "");
      } catch {
        // ignore
      }
    }
    return { status: "success", navigated };
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
