import { describe, it, expect } from "vitest";
import { Injector } from "../src/browser/injector.js";

/**
 * In-memory Injector for unit tests. Captures every `evaluate` call and
 * returns the next canned response from the queue. If the queue is empty,
 * returns `"ok"`.
 */
class MockInjector extends Injector {
  calls: string[] = [];
  responses: string[];

  constructor(responses: string[] = []) {
    super();
    this.responses = responses;
  }

  async evaluate(jsCode: string): Promise<string> {
    this.calls.push(jsCode);
    const next = this.responses.shift();
    return next ?? '"ok"';
  }

  async close(): Promise<void> {}
}

function jsonResp(obj: unknown): string {
  return JSON.stringify(obj);
}

describe("Injector — card field detection", () => {
  it("returns the autocomplete token map produced by the page script", async () => {
    const inj = new MockInjector([
      jsonResp({
        "cc-number": '#card-number',
        "cc-exp": '#card-exp',
        "cc-csc": '#card-csc',
        "cc-name": '#card-name',
      }),
    ]);
    const fields = await inj.detectCardFields();
    expect(fields["cc-number"]).toBe("#card-number");
    expect(fields["cc-exp"]).toBe("#card-exp");
    expect(fields["cc-csc"]).toBe("#card-csc");
    expect(fields["cc-name"]).toBe("#card-name");
  });

  it("returns empty map when no fields detected", async () => {
    const inj = new MockInjector([jsonResp({})]);
    const fields = await inj.detectCardFields();
    expect(Object.keys(fields).length).toBe(0);
  });
});

describe("Injector — identity field detection", () => {
  it("returns the autocomplete tokens for shipping identity", async () => {
    const inj = new MockInjector([
      jsonResp({
        "given-name": '#first',
        "family-name": '#last',
        email: '#email',
        tel: '#phone',
        "street-address": '#addr',
        "postal-code": '#zip',
        country: '#country',
      }),
    ]);
    const fields = await inj.detectIdentityFields();
    expect(fields.email).toBe("#email");
    expect(fields["given-name"]).toBe("#first");
    expect(fields["postal-code"]).toBe("#zip");
  });
});

describe("Injector — fillCard", () => {
  it("fills detected cc-* fields and applies viewport masking", async () => {
    const inj = new MockInjector([
      // detect call
      jsonResp({
        "cc-number": '#n',
        "cc-name": '#h',
        "cc-exp": '#e',
        "cc-csc": '#c',
      }),
      // fill cc-number
      '"ok"',
      // fill cc-name
      '"ok"',
      // fill cc-exp
      '"ok"',
      // fill cc-csc
      '"ok"',
      // mask call
      '"ok"',
    ]);

    const result = await inj.fillCard({
      number: "4111111111111111",
      expMonth: "12",
      expYear: "2030",
      cvc: "123",
      holderName: "Test User",
    });

    expect(result.status).toBe("success");
    expect(result.fieldsFilled).toEqual([
      "cc-number",
      "cc-name",
      "cc-exp",
      "cc-csc",
    ]);
    // The last evaluate call should be the masking call — applies webkitTextSecurity.
    const lastCall = inj.calls[inj.calls.length - 1];
    expect(lastCall).toMatch(/webkitTextSecurity/);
    expect(lastCall).toMatch(/disc/);
  });

  it("returns error when no card fields are detected", async () => {
    const inj = new MockInjector([jsonResp({})]);
    const result = await inj.fillCard({
      number: "4111111111111111",
      expMonth: "12",
      expYear: "2030",
      cvc: "123",
      holderName: "Test",
    });
    expect(result.status).toBe("error");
    expect(result.reason).toMatch(/No card fields detected/);
  });

  it("uses split month/year when cc-exp is absent", async () => {
    const inj = new MockInjector([
      jsonResp({
        "cc-number": '#n',
        "cc-exp-month": '#m',
        "cc-exp-year": '#y',
      }),
      '"ok"', // fill cc-number
      '"ok"', // fill cc-exp-month
      '"ok"', // fill cc-exp-year
      '"ok"', // mask
    ]);
    const result = await inj.fillCard({
      number: "4111111111111111",
      expMonth: "07",
      expYear: "2030",
      cvc: "123",
      holderName: "T",
    });
    expect(result.status).toBe("success");
    expect(result.fieldsFilled).toEqual([
      "cc-number",
      "cc-exp-month",
      "cc-exp-year",
    ]);
  });
});

describe("Injector — fillIdentity", () => {
  it("only fills tokens for which we have a value", async () => {
    const inj = new MockInjector([
      jsonResp({
        email: '#email',
        tel: '#phone',
        "given-name": '#first',
      }),
      '"ok"', // fill given-name
      '"ok"', // fill email
      // No tel value in payload — should be skipped
    ]);
    const result = await inj.fillIdentity({
      email: "a@b.com",
      "given-name": "Ada",
      // tel intentionally omitted
    });
    expect(result.status).toBe("success");
    expect(result.fieldsFilled).toEqual(["given-name", "email"]);
  });

  it("returns error when no fields detected", async () => {
    const inj = new MockInjector([jsonResp({})]);
    const result = await inj.fillIdentity({ email: "a@b.com" });
    expect(result.status).toBe("error");
    expect(result.reason).toMatch(/No identity fields detected/);
  });
});

describe("Injector — iframe widget detection", () => {
  it("returns the matched selector when widget present", async () => {
    const inj = new MockInjector([
      '"iframe[name^=\\"__privateStripeFrame\\"]"',
    ]);
    const result = await inj.detectIframePaymentWidget();
    expect(result).toMatch(/privateStripeFrame/);
  });

  it("returns null when no widget present", async () => {
    const inj = new MockInjector(['"null"']);
    const result = await inj.detectIframePaymentWidget();
    expect(result).toBeNull();
  });
});

describe("Injector — page protocol", () => {
  it("returns https for https pages", async () => {
    const inj = new MockInjector(['"https"']);
    expect(await inj.getPageProtocol()).toBe("https");
  });
  it("returns localhost-http for local dev", async () => {
    const inj = new MockInjector(['"localhost-http"']);
    expect(await inj.getPageProtocol()).toBe("localhost-http");
  });
  it("returns other for plain http", async () => {
    const inj = new MockInjector(['"other"']);
    expect(await inj.getPageProtocol()).toBe("other");
  });
});
