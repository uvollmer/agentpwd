import Database from "better-sqlite3";
import { randomBytes } from "@noble/ciphers/webcrypto";
import { encryptString, decryptString } from "./crypto.js";
import { generatePassword } from "./password-gen.js";
import { detectBrand, lastFour, normalizePan } from "./card.js";
import type {
  Vault,
  Credential,
  EncryptedCredential,
  DecryptedCredential,
  AuditEntry,
  EntityType,
  PasswordOptions,
  Card,
  CardPayload,
  EncryptedCard,
  DecryptedCard,
  Identity,
  IdentityFields,
  EncryptedIdentity,
  DecryptedIdentity,
} from "../types.js";

function generateId(): string {
  return Buffer.from(randomBytes(12)).toString("base64url");
}

export class VaultStore {
  private db: Database.Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
    this.migrate();
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS vaults (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS credentials (
        id TEXT PRIMARY KEY,
        vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
        site TEXT NOT NULL,
        username TEXT NOT NULL,
        encrypted_password BLOB NOT NULL,
        nonce BLOB NOT NULL,
        encrypted_totp BLOB,
        totp_nonce BLOB,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS cards (
        id TEXT PRIMARY KEY,
        vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
        nickname TEXT NOT NULL,
        brand TEXT NOT NULL,
        last4 TEXT NOT NULL,
        encrypted_data BLOB NOT NULL,
        nonce BLOB NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS identities (
        id TEXT PRIMARY KEY,
        vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
        nickname TEXT NOT NULL,
        encrypted_data BLOB NOT NULL,
        nonce BLOB NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS audit_log (
        id TEXT PRIMARY KEY,
        credential_id TEXT NOT NULL,
        action TEXT NOT NULL,
        timestamp TEXT NOT NULL DEFAULT (datetime('now')),
        detail TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_credentials_vault ON credentials(vault_id);
      CREATE INDEX IF NOT EXISTS idx_credentials_site ON credentials(site);
      CREATE INDEX IF NOT EXISTS idx_cards_vault ON cards(vault_id);
      CREATE INDEX IF NOT EXISTS idx_identities_vault ON identities(vault_id);
      CREATE INDEX IF NOT EXISTS idx_audit_credential ON audit_log(credential_id);
    `);

    // Add entity_type column to existing audit_log if absent (legacy DBs).
    const cols = this.db
      .prepare("PRAGMA table_info(audit_log)")
      .all() as Array<{ name: string }>;
    if (!cols.some((c) => c.name === "entity_type")) {
      this.db.exec(
        "ALTER TABLE audit_log ADD COLUMN entity_type TEXT NOT NULL DEFAULT 'credential'",
      );
    }
  }

  // --- Vault operations ---

  createVault(name: string): Vault {
    const id = generateId();
    this.db
      .prepare("INSERT INTO vaults (id, name) VALUES (?, ?)")
      .run(id, name);
    return this.getVault(id)!;
  }

  getVault(id: string): Vault | null {
    const row = this.db
      .prepare("SELECT id, name, created_at as createdAt FROM vaults WHERE id = ?")
      .get(id) as Vault | undefined;
    return row ?? null;
  }

  getVaultByName(name: string): Vault | null {
    const row = this.db
      .prepare("SELECT id, name, created_at as createdAt FROM vaults WHERE name = ?")
      .get(name) as Vault | undefined;
    return row ?? null;
  }

  listVaults(): Vault[] {
    return this.db
      .prepare("SELECT id, name, created_at as createdAt FROM vaults ORDER BY created_at")
      .all() as Vault[];
  }

  deleteVault(id: string): boolean {
    const result = this.db.prepare("DELETE FROM vaults WHERE id = ?").run(id);
    return result.changes > 0;
  }

  // --- Credential operations ---

  createCredential(
    vaultId: string,
    site: string,
    username: string,
    key: Uint8Array,
    password?: string,
    passwordOptions?: PasswordOptions,
  ): Credential {
    const id = generateId();
    const pwd = password ?? generatePassword(passwordOptions);
    const { ciphertext, nonce } = encryptString(pwd, key);

    this.db
      .prepare(
        `INSERT INTO credentials (id, vault_id, site, username, encrypted_password, nonce)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(id, vaultId, site, username, ciphertext, nonce);

    this.logAudit(id, "credential", "create", `Created credential for ${site}`);

    return this.credentialMeta(id, vaultId, site, username);
  }

  /** Store a credential with already-encrypted password bytes (from client-side encryption). */
  createCredentialEncrypted(
    vaultId: string,
    site: string,
    username: string,
    encryptedPassword: Uint8Array,
    nonce: Uint8Array,
  ): string {
    const id = generateId();

    this.db
      .prepare(
        `INSERT INTO credentials (id, vault_id, site, username, encrypted_password, nonce)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(id, vaultId, site, username, encryptedPassword, nonce);

    this.logAudit(id, "credential", "create", `Created credential for ${site} (remote input)`);

    return id;
  }

  private credentialMeta(
    id: string,
    vaultId: string,
    site: string,
    username: string,
  ): Credential {
    return {
      id,
      vaultId,
      site,
      username,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
  }

  getCredential(id: string): EncryptedCredential | null {
    const row = this.db
      .prepare(
        `SELECT id, vault_id as vaultId, site, username,
                encrypted_password as encryptedPassword, nonce,
                encrypted_totp as encryptedTotp, totp_nonce as totpNonce,
                created_at as createdAt, updated_at as updatedAt
         FROM credentials WHERE id = ?`,
      )
      .get(id) as any;
    if (!row) return null;

    return {
      ...row,
      encryptedPassword: new Uint8Array(row.encryptedPassword),
      nonce: new Uint8Array(row.nonce),
      encryptedTotp: row.encryptedTotp
        ? new Uint8Array(row.encryptedTotp)
        : undefined,
      totpNonce: row.totpNonce ? new Uint8Array(row.totpNonce) : undefined,
    };
  }

  decryptCredential(
    id: string,
    key: Uint8Array,
  ): DecryptedCredential | null {
    const enc = this.getCredential(id);
    if (!enc) return null;

    this.logAudit(id, "credential", "read", "Decrypted credential");

    const password = decryptString(enc.encryptedPassword, enc.nonce, key);
    const totp =
      enc.encryptedTotp && enc.totpNonce
        ? decryptString(enc.encryptedTotp, enc.totpNonce, key)
        : undefined;

    return {
      id: enc.id,
      vaultId: enc.vaultId,
      site: enc.site,
      username: enc.username,
      createdAt: enc.createdAt,
      updatedAt: enc.updatedAt,
      password,
      totp,
    };
  }

  listCredentials(vaultId: string): Credential[] {
    return this.db
      .prepare(
        `SELECT id, vault_id as vaultId, site, username,
                created_at as createdAt, updated_at as updatedAt
         FROM credentials WHERE vault_id = ? ORDER BY site, username`,
      )
      .all(vaultId) as Credential[];
  }

  deleteCredential(id: string): boolean {
    this.logAudit(id, "credential", "delete", "Deleted credential");
    const result = this.db
      .prepare("DELETE FROM credentials WHERE id = ?")
      .run(id);
    return result.changes > 0;
  }

  updateCredentialPassword(
    id: string,
    key: Uint8Array,
    newPassword: string,
  ): boolean {
    const { ciphertext, nonce } = encryptString(newPassword, key);
    const result = this.db
      .prepare(
        `UPDATE credentials
         SET encrypted_password = ?, nonce = ?, updated_at = datetime('now')
         WHERE id = ?`,
      )
      .run(ciphertext, nonce, id);
    return result.changes > 0;
  }

  setTotp(id: string, key: Uint8Array, totpSeed: string): boolean {
    const { ciphertext, nonce } = encryptString(totpSeed, key);
    const result = this.db
      .prepare(
        `UPDATE credentials
         SET encrypted_totp = ?, totp_nonce = ?, updated_at = datetime('now')
         WHERE id = ?`,
      )
      .run(ciphertext, nonce, id);
    return result.changes > 0;
  }

  // --- Card operations ---

  createCard(
    vaultId: string,
    nickname: string,
    payload: CardPayload,
    key: Uint8Array,
  ): Card {
    const id = generateId();
    const number = normalizePan(payload.number);
    const normalized: CardPayload = { ...payload, number };
    const brand = detectBrand(number);
    const l4 = lastFour(number);
    const { ciphertext, nonce } = encryptString(JSON.stringify(normalized), key);

    this.db
      .prepare(
        `INSERT INTO cards (id, vault_id, nickname, brand, last4, encrypted_data, nonce)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(id, vaultId, nickname, brand, l4, ciphertext, nonce);

    this.logAudit(id, "card", "create", `Stored card ${brand} •••• ${l4}`);

    const now = new Date().toISOString();
    return {
      id,
      vaultId,
      nickname,
      brand,
      last4: l4,
      createdAt: now,
      updatedAt: now,
    };
  }

  getCard(id: string): EncryptedCard | null {
    const row = this.db
      .prepare(
        `SELECT id, vault_id as vaultId, nickname, brand, last4,
                encrypted_data as encryptedData, nonce,
                created_at as createdAt, updated_at as updatedAt
         FROM cards WHERE id = ?`,
      )
      .get(id) as any;
    if (!row) return null;
    return {
      ...row,
      encryptedData: new Uint8Array(row.encryptedData),
      nonce: new Uint8Array(row.nonce),
    };
  }

  decryptCard(id: string, key: Uint8Array): DecryptedCard | null {
    const enc = this.getCard(id);
    if (!enc) return null;
    this.logAudit(id, "card", "read", "Decrypted card");
    const json = decryptString(enc.encryptedData, enc.nonce, key);
    const data = JSON.parse(json) as CardPayload;
    return {
      id: enc.id,
      vaultId: enc.vaultId,
      nickname: enc.nickname,
      brand: enc.brand,
      last4: enc.last4,
      createdAt: enc.createdAt,
      updatedAt: enc.updatedAt,
      data,
    };
  }

  listCards(vaultId: string): Card[] {
    return this.db
      .prepare(
        `SELECT id, vault_id as vaultId, nickname, brand, last4,
                created_at as createdAt, updated_at as updatedAt
         FROM cards WHERE vault_id = ? ORDER BY nickname`,
      )
      .all(vaultId) as Card[];
  }

  deleteCard(id: string): boolean {
    this.logAudit(id, "card", "delete", "Deleted card");
    const result = this.db.prepare("DELETE FROM cards WHERE id = ?").run(id);
    return result.changes > 0;
  }

  // --- Identity operations ---

  createIdentity(
    vaultId: string,
    nickname: string,
    fields: IdentityFields,
    key: Uint8Array,
  ): Identity {
    const id = generateId();
    const { ciphertext, nonce } = encryptString(JSON.stringify(fields), key);

    this.db
      .prepare(
        `INSERT INTO identities (id, vault_id, nickname, encrypted_data, nonce)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(id, vaultId, nickname, ciphertext, nonce);

    this.logAudit(id, "identity", "create", `Stored identity ${nickname}`);

    const now = new Date().toISOString();
    return {
      id,
      vaultId,
      nickname,
      createdAt: now,
      updatedAt: now,
    };
  }

  getIdentity(id: string): EncryptedIdentity | null {
    const row = this.db
      .prepare(
        `SELECT id, vault_id as vaultId, nickname,
                encrypted_data as encryptedData, nonce,
                created_at as createdAt, updated_at as updatedAt
         FROM identities WHERE id = ?`,
      )
      .get(id) as any;
    if (!row) return null;
    return {
      ...row,
      encryptedData: new Uint8Array(row.encryptedData),
      nonce: new Uint8Array(row.nonce),
    };
  }

  decryptIdentity(id: string, key: Uint8Array): DecryptedIdentity | null {
    const enc = this.getIdentity(id);
    if (!enc) return null;
    this.logAudit(id, "identity", "read", "Decrypted identity");
    const json = decryptString(enc.encryptedData, enc.nonce, key);
    const data = JSON.parse(json) as IdentityFields;
    return {
      id: enc.id,
      vaultId: enc.vaultId,
      nickname: enc.nickname,
      createdAt: enc.createdAt,
      updatedAt: enc.updatedAt,
      data,
    };
  }

  listIdentities(vaultId: string): Identity[] {
    return this.db
      .prepare(
        `SELECT id, vault_id as vaultId, nickname,
                created_at as createdAt, updated_at as updatedAt
         FROM identities WHERE vault_id = ? ORDER BY nickname`,
      )
      .all(vaultId) as Identity[];
  }

  deleteIdentity(id: string): boolean {
    this.logAudit(id, "identity", "delete", "Deleted identity");
    const result = this.db
      .prepare("DELETE FROM identities WHERE id = ?")
      .run(id);
    return result.changes > 0;
  }

  // --- Audit log ---

  private logAudit(
    entityId: string,
    entityType: EntityType,
    action: AuditEntry["action"],
    detail?: string,
  ): void {
    const id = generateId();
    this.db
      .prepare(
        "INSERT INTO audit_log (id, credential_id, entity_type, action, detail) VALUES (?, ?, ?, ?, ?)",
      )
      .run(id, entityId, entityType, action, detail ?? null);
  }

  getAuditLog(entityId?: string): AuditEntry[] {
    if (entityId) {
      return this.db
        .prepare(
          `SELECT id, credential_id as entityId, entity_type as entityType, action, timestamp, detail
           FROM audit_log WHERE credential_id = ? ORDER BY rowid DESC`,
        )
        .all(entityId) as AuditEntry[];
    }
    return this.db
      .prepare(
        `SELECT id, credential_id as entityId, entity_type as entityType, action, timestamp, detail
         FROM audit_log ORDER BY rowid DESC LIMIT 100`,
      )
      .all() as AuditEntry[];
  }

  close(): void {
    this.db.close();
  }
}
