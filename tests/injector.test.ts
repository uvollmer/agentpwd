import { describe, it, expect } from "vitest";
import { domainMatches } from "../src/browser/injector.js";

describe("domainMatches", () => {
  it("matches exact hostname", () => {
    expect(domainMatches("https://github.com/login", "github.com")).toBe(true);
  });

  it("matches subdomain", () => {
    expect(domainMatches("https://login.github.com/", "github.com")).toBe(true);
    expect(
      domainMatches("https://api.deep.sub.example.com/", "example.com"),
    ).toBe(true);
  });

  it("rejects look-alike hostnames", () => {
    expect(domainMatches("https://fake-github.com", "github.com")).toBe(false);
    expect(domainMatches("https://github.com.evil.com", "github.com")).toBe(
      false,
    );
    expect(domainMatches("https://notgithub.com", "github.com")).toBe(false);
  });

  it("normalizes the credential site (strip protocol/path/port)", () => {
    expect(
      domainMatches("https://github.com/login", "https://github.com/foo"),
    ).toBe(true);
    expect(domainMatches("https://github.com/login", "github.com:443")).toBe(
      true,
    );
    expect(domainMatches("https://github.com", "GitHub.COM")).toBe(true);
  });

  it("returns false for unparseable URLs", () => {
    expect(domainMatches("not a url", "github.com")).toBe(false);
  });

  it("returns false when the site is empty after normalization", () => {
    expect(domainMatches("https://github.com", "https://")).toBe(false);
    expect(domainMatches("https://github.com", "")).toBe(false);
  });
});
