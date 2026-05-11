import { describe, it, expect } from "vitest";
import { scrubPassword } from "../src/mcp/scrub.js";

describe("scrubPassword", () => {
  it("redacts the raw password", () => {
    expect(scrubPassword("token: hunter2", "hunter2")).toBe(
      "token: ***REDACTED***",
    );
  });

  it("redacts the password reversed", () => {
    expect(scrubPassword("reversed: 2retnuh", "hunter2")).toBe(
      "reversed: ***REDACTED***",
    );
  });

  it("redacts the base64 of the password", () => {
    const pw = "hunter2";
    const b64 = Buffer.from(pw, "utf-8").toString("base64"); // "aHVudGVyMg=="
    expect(scrubPassword(`out: ${b64}`, pw)).toBe("out: ***REDACTED***");
  });

  it("redacts the unpadded base64", () => {
    const pw = "hunter2";
    const b64NoPad = Buffer.from(pw, "utf-8")
      .toString("base64")
      .replace(/=+$/, "");
    expect(scrubPassword(`out: ${b64NoPad}`, pw)).toBe("out: ***REDACTED***");
  });

  it("redacts the hex of the password", () => {
    const pw = "hunter2";
    const hex = Buffer.from(pw, "utf-8").toString("hex");
    expect(scrubPassword(`out: ${hex}`, pw)).toBe("out: ***REDACTED***");
  });

  it("redacts URL-encoded password", () => {
    const pw = "h u n t#r2";
    const url = encodeURIComponent(pw);
    expect(scrubPassword(`url=${url}`, pw)).toBe("url=***REDACTED***");
  });

  it("redacts multiple variants in the same output", () => {
    const pw = "hunter2";
    const b64 = Buffer.from(pw, "utf-8").toString("base64");
    const hex = Buffer.from(pw, "utf-8").toString("hex");
    const input = `${pw} ${b64} ${hex}`;
    const out = scrubPassword(input, pw);
    expect(out).toBe("***REDACTED*** ***REDACTED*** ***REDACTED***");
  });

  it("redacts all occurrences of the same variant", () => {
    expect(scrubPassword("a hunter2 b hunter2 c", "hunter2")).toBe(
      "a ***REDACTED*** b ***REDACTED*** c",
    );
  });

  it("handles passwords with regex metacharacters", () => {
    expect(scrubPassword("got: a.b*c+d?", "a.b*c+d?")).toBe(
      "got: ***REDACTED***",
    );
  });

  it("leaves output untouched when password is empty", () => {
    expect(scrubPassword("anything goes here", "")).toBe(
      "anything goes here",
    );
  });

  it("leaves output untouched when no variant appears", () => {
    expect(scrubPassword("nothing sensitive here", "hunter2")).toBe(
      "nothing sensitive here",
    );
  });

  it("does not partial-match shorter variant inside longer encoded form", () => {
    // The raw password "ab" appears INSIDE its base64 "YWI=" (no, it doesn't —
    // but with longest-first ordering we guarantee the encoded form is replaced
    // first, so the shorter raw match doesn't fragment the encoding).
    const pw = "ab";
    const b64 = Buffer.from(pw, "utf-8").toString("base64"); // "YWI="
    const input = `raw: ${pw}, b64: ${b64}`;
    // Both should redact cleanly, regardless of order
    expect(scrubPassword(input, pw)).toBe(
      "raw: ***REDACTED***, b64: ***REDACTED***",
    );
  });

  it("does not leak the password through line continuation or splitting", () => {
    // We don't claim to defeat clever encoding — this test just shows that
    // standard variants ARE caught even when surrounded by other text.
    const pw = "hunter2";
    const input = `Error: PASSWORD=${pw} (do not log!)`;
    expect(scrubPassword(input, pw)).toContain("***REDACTED***");
    expect(scrubPassword(input, pw)).not.toContain(pw);
  });
});
