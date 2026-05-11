import { randomBytes } from "@noble/ciphers/webcrypto";
import type { PasswordOptions } from "../types.js";

const UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
const DIGITS = "0123456789";
const SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?";
const AMBIGUOUS = "Il1O0";

export function generatePassword(options: PasswordOptions = {}): string {
  const {
    length = 24,
    uppercase = true,
    lowercase = true,
    digits = true,
    symbols = true,
    excludeAmbiguous = false,
  } = options;

  let charset = "";
  const required: string[] = [];

  if (uppercase) {
    let chars = UPPERCASE;
    if (excludeAmbiguous) chars = chars.replace(/[IO]/g, "");
    charset += chars;
    required.push(chars);
  }
  if (lowercase) {
    let chars = LOWERCASE;
    if (excludeAmbiguous) chars = chars.replace(/[l]/g, "");
    charset += chars;
    required.push(chars);
  }
  if (digits) {
    let chars = DIGITS;
    if (excludeAmbiguous) chars = chars.replace(/[01]/g, "");
    charset += chars;
    required.push(chars);
  }
  if (symbols) {
    charset += SYMBOLS;
    required.push(SYMBOLS);
  }

  if (charset.length === 0) {
    throw new Error("At least one character set must be enabled");
  }

  if (length < required.length) {
    throw new Error(
      `Password length (${length}) must be at least ${required.length} to include all required character sets`,
    );
  }

  // Generate password ensuring at least one char from each required set
  const password = new Array<string>(length);

  // Fill required positions first (shuffled into random positions later)
  for (let i = 0; i < required.length; i++) {
    password[i] = secureRandomChar(required[i]);
  }

  // Fill remaining positions from full charset
  for (let i = required.length; i < length; i++) {
    password[i] = secureRandomChar(charset);
  }

  // Fisher-Yates shuffle
  for (let i = password.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    [password[i], password[j]] = [password[j], password[i]];
  }

  return password.join("");
}

function secureRandomChar(charset: string): string {
  return charset[secureRandomInt(charset.length)];
}

function secureRandomInt(max: number): number {
  // Rejection sampling to avoid modulo bias
  const bytes = randomBytes(4);
  const value =
    ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
  const limit = Math.floor(0x100000000 / max) * max;
  if (value >= limit) return secureRandomInt(max); // reject and retry
  return value % max;
}
