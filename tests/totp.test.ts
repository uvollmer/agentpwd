import { describe, it, expect } from "vitest";
import { decodeBase32, generateTOTP } from "../src/vault/totp.js";

describe("decodeBase32", () => {
  it("decodes a valid base32 string", () => {
    // "JBSWY3DPEE" is base32 for "Hello!"
    const result = decodeBase32("JBSWY3DPEE");
    expect(Buffer.from(result).toString("ascii")).toBe("Hello!");
  });

  it("handles lowercase input", () => {
    const result = decodeBase32("jbswy3dpee");
    expect(Buffer.from(result).toString("ascii")).toBe("Hello!");
  });

  it("handles padding", () => {
    const result = decodeBase32("JBSWY3DPEE======");
    expect(Buffer.from(result).toString("ascii")).toBe("Hello!");
  });

  it("handles whitespace", () => {
    const result = decodeBase32("JBSW Y3DP EE");
    expect(Buffer.from(result).toString("ascii")).toBe("Hello!");
  });

  it("throws on invalid characters", () => {
    expect(() => decodeBase32("JBSWY3DP!")).toThrow("Invalid base32 character");
  });

  it("decodes the RFC 4648 test vectors", () => {
    // "" -> ""
    expect(decodeBase32("")).toEqual(new Uint8Array([]));
    // "f" -> "MY"
    expect(Buffer.from(decodeBase32("MY")).toString("ascii")).toBe("f");
    // "fo" -> "MZXQ"
    expect(Buffer.from(decodeBase32("MZXQ")).toString("ascii")).toBe("fo");
    // "foo" -> "MZXW6"
    expect(Buffer.from(decodeBase32("MZXW6")).toString("ascii")).toBe("foo");
    // "foob" -> "MZXW6YQ"
    expect(Buffer.from(decodeBase32("MZXW6YQ")).toString("ascii")).toBe("foob");
    // "fooba" -> "MZXW6YTB"
    expect(Buffer.from(decodeBase32("MZXW6YTB")).toString("ascii")).toBe("fooba");
    // "foobar" -> "MZXW6YTBOI"
    expect(Buffer.from(decodeBase32("MZXW6YTBOI")).toString("ascii")).toBe("foobar");
  });
});

describe("generateTOTP", () => {
  // RFC 6238 test vectors use the ASCII string "12345678901234567890" as the seed.
  // Base32 of "12345678901234567890" is "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
  const seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

  it("generates correct code for RFC 6238 test vector at t=59", () => {
    const code = generateTOTP(seed, { timestamp: 59 });
    expect(code).toBe("287082");
  });

  it("generates correct code for RFC 6238 test vector at t=1111111109", () => {
    const code = generateTOTP(seed, { timestamp: 1111111109 });
    expect(code).toBe("081804");
  });

  it("generates correct code for RFC 6238 test vector at t=1111111111", () => {
    const code = generateTOTP(seed, { timestamp: 1111111111 });
    expect(code).toBe("050471");
  });

  it("generates correct code for RFC 6238 test vector at t=1234567890", () => {
    const code = generateTOTP(seed, { timestamp: 1234567890 });
    expect(code).toBe("005924");
  });

  it("generates correct code for RFC 6238 test vector at t=2000000000", () => {
    const code = generateTOTP(seed, { timestamp: 2000000000 });
    expect(code).toBe("279037");
  });

  it("returns a 6-digit zero-padded string", () => {
    const code = generateTOTP(seed, { timestamp: 59 });
    expect(code).toHaveLength(6);
    expect(code).toMatch(/^\d{6}$/);
  });

  it("codes within the same 30s window are identical", () => {
    const code1 = generateTOTP(seed, { timestamp: 60 });
    const code2 = generateTOTP(seed, { timestamp: 89 });
    expect(code1).toBe(code2);
  });

  it("codes in different 30s windows differ", () => {
    const code1 = generateTOTP(seed, { timestamp: 0 });
    const code2 = generateTOTP(seed, { timestamp: 30 });
    expect(code1).not.toBe(code2);
  });

  it("throws on invalid seed", () => {
    expect(() => generateTOTP("!!!INVALID!!!", { timestamp: 0 })).toThrow();
  });
});
