import { describe, it, expect } from "vitest";
import {
  normalizePan,
  detectBrand,
  validateLuhn,
  lastFour,
  normalizeExpMonth,
  normalizeExpYear,
} from "../src/vault/card.js";

describe("card utilities", () => {
  describe("normalizePan", () => {
    it("strips spaces and dashes", () => {
      expect(normalizePan("4111 1111 1111 1111")).toBe("4111111111111111");
      expect(normalizePan("4111-1111-1111-1111")).toBe("4111111111111111");
      expect(normalizePan("  4111\n1111  ")).toBe("41111111");
    });
    it("returns empty string for non-digit input", () => {
      expect(normalizePan("abc")).toBe("");
      expect(normalizePan("")).toBe("");
    });
  });

  describe("detectBrand", () => {
    it("detects Visa (starts with 4)", () => {
      expect(detectBrand("4111111111111111")).toBe("visa");
      expect(detectBrand("4012888888881881")).toBe("visa");
    });
    it("detects Mastercard 51-55", () => {
      expect(detectBrand("5500000000000004")).toBe("mastercard");
      expect(detectBrand("5105105105105100")).toBe("mastercard");
    });
    it("detects Mastercard 2221-2720 range", () => {
      expect(detectBrand("2221000000000000")).toBe("mastercard");
      expect(detectBrand("2720990000000000")).toBe("mastercard");
    });
    it("detects American Express (34, 37)", () => {
      expect(detectBrand("340000000000009")).toBe("amex");
      expect(detectBrand("371449635398431")).toBe("amex");
    });
    it("detects Discover (6011, 65)", () => {
      expect(detectBrand("6011111111111117")).toBe("discover");
      expect(detectBrand("6500000000000000")).toBe("discover");
    });
    it("detects JCB (3528-3589)", () => {
      expect(detectBrand("3530111333300000")).toBe("jcb");
    });
    it("detects UnionPay (62)", () => {
      expect(detectBrand("6200000000000005")).toBe("unionpay");
    });
    it("returns unknown for unrecognized prefix", () => {
      expect(detectBrand("1234567890123456")).toBe("unknown");
      expect(detectBrand("")).toBe("unknown");
    });
    it("works on formatted input (with spaces)", () => {
      expect(detectBrand("4111 1111 1111 1111")).toBe("visa");
    });
  });

  describe("validateLuhn", () => {
    it("accepts valid Visa test card", () => {
      expect(validateLuhn("4111111111111111")).toBe(true);
    });
    it("accepts valid Amex test card", () => {
      expect(validateLuhn("378282246310005")).toBe(true);
    });
    it("rejects too-short numbers", () => {
      expect(validateLuhn("41111")).toBe(false);
    });
    it("rejects checksum failures", () => {
      expect(validateLuhn("4111111111111112")).toBe(false);
    });
    it("rejects non-digit input", () => {
      expect(validateLuhn("hello world")).toBe(false);
    });
    it("accepts formatted input", () => {
      expect(validateLuhn("4111 1111 1111 1111")).toBe(true);
    });
  });

  describe("lastFour", () => {
    it("returns the last 4 digits", () => {
      expect(lastFour("4111111111111111")).toBe("1111");
      expect(lastFour("4111 1111 1111 9999")).toBe("9999");
    });
  });

  describe("normalizeExpMonth", () => {
    it("pads single digit to 2", () => {
      expect(normalizeExpMonth("1")).toBe("01");
      expect(normalizeExpMonth(7)).toBe("07");
    });
    it("keeps 2-digit values", () => {
      expect(normalizeExpMonth("12")).toBe("12");
    });
  });

  describe("normalizeExpYear", () => {
    it("expands 2-digit year to 20YY", () => {
      expect(normalizeExpYear("30")).toBe("2030");
      expect(normalizeExpYear(25)).toBe("2025");
    });
    it("keeps 4-digit year", () => {
      expect(normalizeExpYear("2030")).toBe("2030");
    });
  });
});
