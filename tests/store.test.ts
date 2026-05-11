import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { unlinkSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { VaultStore } from "../src/vault/store.js";
import { generateMasterKey } from "../src/vault/crypto.js";

const TEST_DB = join(tmpdir(), `agentpwd-test-${Date.now()}.db`);

describe("VaultStore", () => {
  let store: VaultStore;
  let key: Uint8Array;

  beforeEach(() => {
    store = new VaultStore(TEST_DB);
    key = generateMasterKey();
  });

  afterEach(() => {
    store.close();
    if (existsSync(TEST_DB)) unlinkSync(TEST_DB);
    const walPath = TEST_DB + "-wal";
    const shmPath = TEST_DB + "-shm";
    if (existsSync(walPath)) unlinkSync(walPath);
    if (existsSync(shmPath)) unlinkSync(shmPath);
  });

  describe("vaults", () => {
    it("creates a vault", () => {
      const vault = store.createVault("test-vault");
      expect(vault.id).toBeTruthy();
      expect(vault.name).toBe("test-vault");
      expect(vault.createdAt).toBeTruthy();
    });

    it("gets a vault by id", () => {
      const created = store.createVault("v1");
      const fetched = store.getVault(created.id);
      expect(fetched).not.toBeNull();
      expect(fetched!.name).toBe("v1");
    });

    it("gets a vault by name", () => {
      store.createVault("my-vault");
      const fetched = store.getVaultByName("my-vault");
      expect(fetched).not.toBeNull();
      expect(fetched!.name).toBe("my-vault");
    });

    it("lists vaults", () => {
      store.createVault("a");
      store.createVault("b");
      const vaults = store.listVaults();
      expect(vaults.length).toBe(2);
    });

    it("rejects duplicate vault names", () => {
      store.createVault("dup");
      expect(() => store.createVault("dup")).toThrow();
    });

    it("deletes a vault and cascades credentials", () => {
      const vault = store.createVault("to-delete");
      store.createCredential(vault.id, "example.com", "user", key, "pass");
      store.deleteVault(vault.id);
      expect(store.getVault(vault.id)).toBeNull();
      expect(store.listCredentials(vault.id).length).toBe(0);
    });
  });

  describe("credentials", () => {
    it("creates a credential with provided password", () => {
      const vault = store.createVault("v");
      const cred = store.createCredential(
        vault.id,
        "github.com",
        "agent@test.com",
        key,
        "mypassword",
      );
      expect(cred.id).toBeTruthy();
      expect(cred.site).toBe("github.com");
      expect(cred.username).toBe("agent@test.com");
      // Password is NOT in the returned Credential
      expect((cred as any).password).toBeUndefined();
    });

    it("creates a credential with auto-generated password", () => {
      const vault = store.createVault("v");
      const cred = store.createCredential(
        vault.id,
        "aws.amazon.com",
        "admin",
        key,
      );
      // Decrypt and verify a password was generated
      const dec = store.decryptCredential(cred.id, key);
      expect(dec!.password.length).toBe(24); // default length
    });

    it("decrypts a credential correctly", () => {
      const vault = store.createVault("v");
      const cred = store.createCredential(
        vault.id,
        "example.com",
        "user",
        key,
        "super-secret",
      );
      const dec = store.decryptCredential(cred.id, key);
      expect(dec).not.toBeNull();
      expect(dec!.password).toBe("super-secret");
      expect(dec!.site).toBe("example.com");
      expect(dec!.username).toBe("user");
    });

    it("fails to decrypt with wrong key", () => {
      const vault = store.createVault("v");
      const cred = store.createCredential(
        vault.id,
        "site.com",
        "user",
        key,
        "secret",
      );
      const wrongKey = generateMasterKey();
      expect(() => store.decryptCredential(cred.id, wrongKey)).toThrow();
    });

    it("lists credentials without passwords", () => {
      const vault = store.createVault("v");
      store.createCredential(vault.id, "a.com", "u1", key, "p1");
      store.createCredential(vault.id, "b.com", "u2", key, "p2");
      const list = store.listCredentials(vault.id);
      expect(list.length).toBe(2);
      for (const c of list) {
        expect((c as any).password).toBeUndefined();
        expect((c as any).encryptedPassword).toBeUndefined();
      }
    });

    it("updates a credential password", () => {
      const vault = store.createVault("v");
      const cred = store.createCredential(
        vault.id,
        "site.com",
        "user",
        key,
        "old-pass",
      );
      store.updateCredentialPassword(cred.id, key, "new-pass");
      const dec = store.decryptCredential(cred.id, key);
      expect(dec!.password).toBe("new-pass");
    });

    it("sets and retrieves TOTP", () => {
      const vault = store.createVault("v");
      const cred = store.createCredential(
        vault.id,
        "site.com",
        "user",
        key,
        "pass",
      );
      store.setTotp(cred.id, key, "JBSWY3DPEHPK3PXP");
      const dec = store.decryptCredential(cred.id, key);
      expect(dec!.totp).toBe("JBSWY3DPEHPK3PXP");
    });

    it("deletes a credential", () => {
      const vault = store.createVault("v");
      const cred = store.createCredential(
        vault.id,
        "site.com",
        "user",
        key,
        "pass",
      );
      expect(store.deleteCredential(cred.id)).toBe(true);
      expect(store.getCredential(cred.id)).toBeNull();
    });
  });

  describe("audit log", () => {
    it("logs credential creation", () => {
      const vault = store.createVault("v");
      const cred = store.createCredential(
        vault.id,
        "site.com",
        "user",
        key,
        "pass",
      );
      const log = store.getAuditLog(cred.id);
      expect(log.length).toBe(1);
      expect(log[0].action).toBe("create");
    });

    it("logs credential reads", () => {
      const vault = store.createVault("v");
      const cred = store.createCredential(
        vault.id,
        "site.com",
        "user",
        key,
        "pass",
      );
      store.decryptCredential(cred.id, key);
      const log = store.getAuditLog(cred.id);
      expect(log.length).toBe(2);
      expect(log[0].action).toBe("read"); // most recent first
    });

    it("logs credential deletion", () => {
      const vault = store.createVault("v");
      const cred = store.createCredential(
        vault.id,
        "site.com",
        "user",
        key,
        "pass",
      );
      store.deleteCredential(cred.id);
      // Audit entries survive credential deletion (no FK cascade on audit_log)
      const log = store.getAuditLog(cred.id);
      expect(log.some((e) => e.action === "delete")).toBe(true);
    });
  });
});
