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

export interface AuditEntry {
  id: string;
  credentialId: string;
  action: "create" | "read" | "fill" | "run" | "delete";
  timestamp: string;
  /** Contextual info — never the credential value. */
  detail?: string;
}

export interface PasswordOptions {
  length?: number;
  uppercase?: boolean;
  lowercase?: boolean;
  digits?: boolean;
  symbols?: boolean;
  excludeAmbiguous?: boolean;
}
