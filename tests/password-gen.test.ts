import { describe, it, expect } from "vitest";
import { generatePassword } from "../src/vault/password-gen.js";

describe("password generator", () => {
  it("generates passwords of requested length", () => {
    expect(generatePassword({ length: 16 }).length).toBe(16);
    expect(generatePassword({ length: 32 }).length).toBe(32);
    expect(generatePassword({ length: 64 }).length).toBe(64);
  });

  it("defaults to 24 characters", () => {
    expect(generatePassword().length).toBe(24);
  });

  it("includes uppercase when enabled", () => {
    const pwd = generatePassword({ length: 100, lowercase: false, digits: false, symbols: false });
    expect(pwd).toMatch(/^[A-Z]+$/);
  });

  it("includes lowercase when enabled", () => {
    const pwd = generatePassword({ length: 100, uppercase: false, digits: false, symbols: false });
    expect(pwd).toMatch(/^[a-z]+$/);
  });

  it("includes digits when enabled", () => {
    const pwd = generatePassword({ length: 100, uppercase: false, lowercase: false, symbols: false });
    expect(pwd).toMatch(/^[0-9]+$/);
  });

  it("includes symbols when enabled", () => {
    const pwd = generatePassword({ length: 100, uppercase: false, lowercase: false, digits: false });
    expect(pwd).toMatch(/^[^a-zA-Z0-9]+$/);
  });

  it("contains at least one of each enabled set", () => {
    for (let i = 0; i < 20; i++) {
      const pwd = generatePassword({ length: 8 });
      expect(pwd).toMatch(/[A-Z]/);
      expect(pwd).toMatch(/[a-z]/);
      expect(pwd).toMatch(/[0-9]/);
      expect(pwd).toMatch(/[^a-zA-Z0-9]/);
    }
  });

  it("generates unique passwords", () => {
    const set = new Set<string>();
    for (let i = 0; i < 100; i++) {
      set.add(generatePassword());
    }
    expect(set.size).toBe(100);
  });

  it("throws on empty charset", () => {
    expect(() =>
      generatePassword({ uppercase: false, lowercase: false, digits: false, symbols: false }),
    ).toThrow("At least one character set must be enabled");
  });

  it("throws when length is too short for required sets", () => {
    expect(() => generatePassword({ length: 2 })).toThrow();
  });

  it("excludes ambiguous characters when requested", () => {
    for (let i = 0; i < 10; i++) {
      const pwd = generatePassword({ length: 100, excludeAmbiguous: true });
      expect(pwd).not.toMatch(/[Il1O0]/);
    }
  });
});
