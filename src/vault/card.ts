import type { CardBrand } from "../types.js";

/** Strip spaces, dashes, anything non-digit. */
export function normalizePan(pan: string): string {
  return pan.replace(/\D+/g, "");
}

/** Detect card brand from PAN prefix. PAN expected to be digits only. */
export function detectBrand(pan: string): CardBrand {
  const n = normalizePan(pan);
  if (!n) return "unknown";

  // Visa: starts with 4
  if (/^4/.test(n)) return "visa";

  // Amex: 34 or 37
  if (/^3[47]/.test(n)) return "amex";

  // Mastercard: 51-55 or 2221-2720
  if (/^5[1-5]/.test(n)) return "mastercard";
  if (/^2(2[2-9][1-9]|[3-6]\d{2}|7([01]\d|20))/.test(n)) return "mastercard";

  // Discover: 6011, 644-649, 65
  if (/^(6011|65|64[4-9])/.test(n)) return "discover";

  // JCB: 3528-3589 (must come before Diners because 35* overlaps)
  if (/^35(2[89]|[3-8]\d)/.test(n)) return "jcb";

  // Diners: 300-305, 36, 38
  if (/^(30[0-5]|36|38)/.test(n)) return "diners";

  // UnionPay: 62
  if (/^62/.test(n)) return "unionpay";

  return "unknown";
}

/** Luhn checksum. */
export function validateLuhn(pan: string): boolean {
  const n = normalizePan(pan);
  if (n.length < 12) return false;

  let sum = 0;
  let alt = false;
  for (let i = n.length - 1; i >= 0; i--) {
    let d = n.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

/** Extract last four digits. */
export function lastFour(pan: string): string {
  const n = normalizePan(pan);
  return n.slice(-4);
}

/** Pad expiry month to 2 digits. */
export function normalizeExpMonth(month: string | number): string {
  const m = String(month).replace(/\D+/g, "");
  return m.length === 1 ? "0" + m : m.slice(-2);
}

/** Normalize expiry year to 4 digits. Accepts "YY" or "YYYY". */
export function normalizeExpYear(year: string | number): string {
  const y = String(year).replace(/\D+/g, "");
  if (y.length === 2) return "20" + y;
  return y.slice(-4);
}
