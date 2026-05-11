export interface Vault {
  id: string;
  name: string;
  createdAt: string;
}

export interface Credential {
  id: string;
  vaultId: string;
  site: string;
  username: string;
  createdAt: string;
  updatedAt: string;
}

/** Internal representation with encrypted data — never exposed via MCP. */
export interface EncryptedCredential extends Credential {
  encryptedPassword: Uint8Array;
  nonce: Uint8Array;
  /** Optional encrypted TOTP seed. */
  encryptedTotp?: Uint8Array;
  totpNonce?: Uint8Array;
}

export interface DecryptedCredential extends Credential {
  password: string;
  totp?: string;
}

export type EntityType = "credential" | "card" | "identity";

export interface AuditEntry {
  id: string;
  /** The id of the credential, card, or identity. SQL column is still named credential_id for back-compat. */
  entityId: string;
  entityType: EntityType;
  action:
    | "create"
    | "read"
    | "fill"
    | "fill_card"
    | "fill_identity"
    | "run"
    | "delete";
  timestamp: string;
  /** Contextual info — never the credential value. */
  detail?: string;
}

export type CardBrand =
  | "visa"
  | "mastercard"
  | "amex"
  | "discover"
  | "diners"
  | "jcb"
  | "unionpay"
  | "unknown";

export interface Card {
  id: string;
  vaultId: string;
  nickname: string;
  brand: CardBrand;
  last4: string;
  createdAt: string;
  updatedAt: string;
}

/** Plaintext card payload — only exists transiently in memory during a fill. */
export interface CardPayload {
  number: string;
  expMonth: string; // "01".."12"
  expYear: string; // "YYYY"
  cvc: string;
  holderName: string;
}

export interface EncryptedCard extends Card {
  encryptedData: Uint8Array;
  nonce: Uint8Array;
}

export interface DecryptedCard extends Card {
  data: CardPayload;
}

export interface IdentityFields {
  givenName?: string;
  familyName?: string;
  email?: string;
  phone?: string;
  streetAddress?: string;
  addressLine2?: string;
  city?: string;
  region?: string;
  postalCode?: string;
  country?: string;
  dateOfBirth?: string;
}

export interface Identity {
  id: string;
  vaultId: string;
  nickname: string;
  createdAt: string;
  updatedAt: string;
}

export interface EncryptedIdentity extends Identity {
  encryptedData: Uint8Array;
  nonce: Uint8Array;
}

export interface DecryptedIdentity extends Identity {
  data: IdentityFields;
}

export interface PasswordOptions {
  length?: number;
  uppercase?: boolean;
  lowercase?: boolean;
  digits?: boolean;
  symbols?: boolean;
  excludeAmbiguous?: boolean;
}
