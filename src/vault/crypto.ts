import { gcm } from "@noble/ciphers/aes";
import { randomBytes } from "@noble/ciphers/webcrypto";
import { argon2id } from "@noble/hashes/argon2";

const NONCE_LENGTH = 12; // 96 bits for AES-GCM
const KEY_LENGTH = 32; // 256 bits

/** Encrypt plaintext with AES-256-GCM. Returns { ciphertext, nonce }. */
export function encrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
): { ciphertext: Uint8Array; nonce: Uint8Array } {
  const nonce = randomBytes(NONCE_LENGTH);
  const aes = gcm(key, nonce);
  const ciphertext = aes.encrypt(plaintext);
  return { ciphertext, nonce };
}

/** Decrypt ciphertext with AES-256-GCM. */
export function decrypt(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
): Uint8Array {
  const aes = gcm(key, nonce);
  return aes.decrypt(ciphertext);
}

/** Encrypt a UTF-8 string. */
export function encryptString(
  plaintext: string,
  key: Uint8Array,
): { ciphertext: Uint8Array; nonce: Uint8Array } {
  return encrypt(new TextEncoder().encode(plaintext), key);
}

/** Decrypt to a UTF-8 string. */
export function decryptString(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
): string {
  return new TextDecoder().decode(decrypt(ciphertext, nonce, key));
}

/** Derive a 256-bit key from a password using Argon2id. */
export function deriveKey(
  password: string,
  salt: Uint8Array,
): Uint8Array {
  return argon2id(new TextEncoder().encode(password), salt, {
    t: 3, // iterations
    m: 65536, // 64 MiB memory
    p: 1, // parallelism
    dkLen: KEY_LENGTH,
  });
}

/** Generate a random 256-bit master key. */
export function generateMasterKey(): Uint8Array {
  return randomBytes(KEY_LENGTH);
}

/** Generate a random salt for Argon2id. */
export function generateSalt(): Uint8Array {
  return randomBytes(16);
}
