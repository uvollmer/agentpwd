import { hmac } from "@noble/hashes/hmac";
import { sha1 } from "@noble/hashes/sha1";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function decodeBase32(input: string): Uint8Array {
  const cleaned = input.toUpperCase().replace(/=+$/, "").replace(/\s+/g, "");
  for (const ch of cleaned) {
    if (!BASE32_ALPHABET.includes(ch)) {
      throw new Error(`Invalid base32 character: ${ch}`);
    }
  }

  const bits: number[] = [];
  for (const ch of cleaned) {
    const val = BASE32_ALPHABET.indexOf(ch);
    bits.push((val >> 4) & 1, (val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1);
  }

  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    const offset = i * 8;
    bytes[i] =
      (bits[offset] << 7) |
      (bits[offset + 1] << 6) |
      (bits[offset + 2] << 5) |
      (bits[offset + 3] << 4) |
      (bits[offset + 4] << 3) |
      (bits[offset + 5] << 2) |
      (bits[offset + 6] << 1) |
      bits[offset + 7];
  }
  return bytes;
}

export interface TOTPOptions {
  period?: number;  // default 30
  digits?: number;  // default 6
  timestamp?: number; // override current time (for testing)
}

export function generateTOTP(seed: string, options?: TOTPOptions): string {
  const period = options?.period ?? 30;
  const digits = options?.digits ?? 6;
  const now = options?.timestamp ?? Math.floor(Date.now() / 1000);

  const counter = Math.floor(now / period);
  const key = decodeBase32(seed);

  // Encode counter as 8-byte big-endian
  const counterBytes = new Uint8Array(8);
  let tmp = counter;
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = tmp & 0xff;
    tmp = Math.floor(tmp / 256);
  }

  const mac = hmac(sha1, key, counterBytes);

  // Dynamic truncation (RFC 4226)
  const offset = mac[mac.length - 1] & 0x0f;
  const code =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);

  const otp = code % 10 ** digits;
  return otp.toString().padStart(digits, "0");
}
