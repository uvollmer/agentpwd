import { describe, it, expect } from "vitest";
import {
  encrypt,
  decrypt,
  encryptString,
  decryptString,
  deriveKey,
  generateMasterKey,
  generateSalt,
} from "../src/vault/crypto.js";

describe("crypto", () => {
  it("encrypts and decrypts bytes", () => {
    const key = generateMasterKey();
    const data = new TextEncoder().encode("hello world");
    const { ciphertext, nonce } = encrypt(data, key);

    expect(ciphertext).not.toEqual(data);
    expect(ciphertext.length).toBeGreaterThan(data.length); // GCM tag adds 16 bytes

    const decrypted = decrypt(ciphertext, nonce, key);
    expect(decrypted).toEqual(data);
  });

  it("encrypts and decrypts strings", () => {
    const key = generateMasterKey();
    const { ciphertext, nonce } = encryptString("s3cret!", key);
    const result = decryptString(ciphertext, nonce, key);
    expect(result).toBe("s3cret!");
  });

  it("uses unique nonces per encryption", () => {
    const key = generateMasterKey();
    const { nonce: n1 } = encryptString("same", key);
    const { nonce: n2 } = encryptString("same", key);
    expect(n1).not.toEqual(n2);
  });

  it("fails to decrypt with wrong key", () => {
    const key1 = generateMasterKey();
    const key2 = generateMasterKey();
    const { ciphertext, nonce } = encryptString("secret", key1);
    expect(() => decryptString(ciphertext, nonce, key2)).toThrow();
  });

  it("fails to decrypt with tampered ciphertext", () => {
    const key = generateMasterKey();
    const { ciphertext, nonce } = encryptString("secret", key);
    ciphertext[0] ^= 0xff;
    expect(() => decryptString(ciphertext, nonce, key)).toThrow();
  });

  it("derives consistent keys from same password+salt", () => {
    const salt = generateSalt();
    const k1 = deriveKey("password123", salt);
    const k2 = deriveKey("password123", salt);
    expect(k1).toEqual(k2);
    expect(k1.length).toBe(32);
  });

  it("derives different keys from different passwords", () => {
    const salt = generateSalt();
    const k1 = deriveKey("password1", salt);
    const k2 = deriveKey("password2", salt);
    expect(k1).not.toEqual(k2);
  });

  it("derives different keys from different salts", () => {
    const s1 = generateSalt();
    const s2 = generateSalt();
    const k1 = deriveKey("password", s1);
    const k2 = deriveKey("password", s2);
    expect(k1).not.toEqual(k2);
  });

  it("generates 32-byte master keys", () => {
    const key = generateMasterKey();
    expect(key.length).toBe(32);
    expect(key).toBeInstanceOf(Uint8Array);
  });

  it("generates unique master keys", () => {
    const k1 = generateMasterKey();
    const k2 = generateMasterKey();
    expect(k1).not.toEqual(k2);
  });
});
