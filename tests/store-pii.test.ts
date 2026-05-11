import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { unlinkSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { VaultStore } from "../src/vault/store.js";
import { generateMasterKey } from "../src/vault/crypto.js";
import type { CardPayload, IdentityFields } from "../src/types.js";

const TEST_DB = join(tmpdir(), `agentpwd-pii-test-${Date.now()}.db`);

describe("VaultStore PII (cards + identities)", () => {
  let store: VaultStore;
  let key: Uint8Array;
  let vaultId: string;

  beforeEach(() => {
    store = new VaultStore(TEST_DB);
    key = generateMasterKey();
    vaultId = store.createVault("v").id;
  });

  afterEach(() => {
    store.close();
    if (existsSync(TEST_DB)) unlinkSync(TEST_DB);
    const walPath = TEST_DB + "-wal";
    const shmPath = TEST_DB + "-shm";
    if (existsSync(walPath)) unlinkSync(walPath);
    if (existsSync(shmPath)) unlinkSync(shmPath);
  });

  describe("cards", () => {
    const payload: CardPayload = {
      number: "4111111111111111",
      expMonth: "12",
      expYear: "2030",
      cvc: "123",
      holderName: "Test User",
    };

    it("creates and encrypts a card", () => {
      const card = store.createCard(vaultId, "Personal", payload, key);
      expect(card.id).toBeTruthy();
      expect(card.nickname).toBe("Personal");
      expect(card.brand).toBe("visa");
      expect(card.last4).toBe("1111");
      // No card data leaks into the metadata object
      expect((card as any).number).toBeUndefined();
      expect((card as any).cvc).toBeUndefined();
    });

    it("decrypts a card round-trip with the correct key", () => {
      const card = store.createCard(vaultId, "Personal", payload, key);
      const dec = store.decryptCard(card.id, key);
      expect(dec).not.toBeNull();
      expect(dec!.data.number).toBe("4111111111111111");
      expect(dec!.data.expMonth).toBe("12");
      expect(dec!.data.expYear).toBe("2030");
      expect(dec!.data.cvc).toBe("123");
      expect(dec!.data.holderName).toBe("Test User");
    });

    it("decryption with the wrong key fails", () => {
      const card = store.createCard(vaultId, "Personal", payload, key);
      const wrongKey = generateMasterKey();
      expect(() => store.decryptCard(card.id, wrongKey)).toThrow();
    });

    it("strips formatting from the PAN before storing", () => {
      const card = store.createCard(
        vaultId,
        "Spaced",
        { ...payload, number: "4111 1111 1111 1111" },
        key,
      );
      const dec = store.decryptCard(card.id, key)!;
      expect(dec.data.number).toBe("4111111111111111");
      expect(card.last4).toBe("1111");
    });

    it("listCards returns metadata only", () => {
      store.createCard(vaultId, "A", payload, key);
      store.createCard(
        vaultId,
        "B",
        { ...payload, number: "5500000000000004", holderName: "Other" },
        key,
      );
      const cards = store.listCards(vaultId);
      expect(cards.length).toBe(2);
      const nicknames = cards.map((c) => c.nickname).sort();
      expect(nicknames).toEqual(["A", "B"]);
      // No payload fields on metadata rows
      for (const c of cards) {
        expect((c as any).number).toBeUndefined();
        expect((c as any).cvc).toBeUndefined();
      }
    });

    it("deletes a card", () => {
      const card = store.createCard(vaultId, "del", payload, key);
      expect(store.deleteCard(card.id)).toBe(true);
      expect(store.getCard(card.id)).toBeNull();
    });

    it("cascades when vault is deleted", () => {
      store.createCard(vaultId, "x", payload, key);
      store.deleteVault(vaultId);
      expect(store.listCards(vaultId).length).toBe(0);
    });
  });

  describe("identities", () => {
    const fields: IdentityFields = {
      givenName: "Ada",
      familyName: "Lovelace",
      email: "ada@example.com",
      phone: "+441234567890",
      streetAddress: "10 Downing St",
      city: "London",
      postalCode: "SW1A 2AA",
      country: "GB",
    };

    it("creates and encrypts an identity", () => {
      const idn = store.createIdentity(vaultId, "home", fields, key);
      expect(idn.id).toBeTruthy();
      expect(idn.nickname).toBe("home");
      // No payload leaks into metadata
      expect((idn as any).email).toBeUndefined();
    });

    it("decrypts an identity round-trip with the correct key", () => {
      const idn = store.createIdentity(vaultId, "home", fields, key);
      const dec = store.decryptIdentity(idn.id, key);
      expect(dec).not.toBeNull();
      expect(dec!.data.email).toBe("ada@example.com");
      expect(dec!.data.city).toBe("London");
      expect(dec!.data.country).toBe("GB");
    });

    it("decryption with the wrong key fails", () => {
      const idn = store.createIdentity(vaultId, "home", fields, key);
      const wrongKey = generateMasterKey();
      expect(() => store.decryptIdentity(idn.id, wrongKey)).toThrow();
    });

    it("supports partial identities (only some fields set)", () => {
      const idn = store.createIdentity(
        vaultId,
        "minimal",
        { email: "x@y.com" },
        key,
      );
      const dec = store.decryptIdentity(idn.id, key)!;
      expect(dec.data.email).toBe("x@y.com");
      expect(dec.data.phone).toBeUndefined();
    });

    it("listIdentities returns metadata only", () => {
      store.createIdentity(vaultId, "a", fields, key);
      store.createIdentity(vaultId, "b", { email: "b@b.com" }, key);
      const ids = store.listIdentities(vaultId);
      expect(ids.length).toBe(2);
      for (const i of ids) {
        expect((i as any).email).toBeUndefined();
      }
    });

    it("deletes an identity", () => {
      const idn = store.createIdentity(vaultId, "del", fields, key);
      expect(store.deleteIdentity(idn.id)).toBe(true);
      expect(store.getIdentity(idn.id)).toBeNull();
    });
  });

  describe("audit log generalization", () => {
    it("records entity_type for cards", () => {
      const card = store.createCard(
        vaultId,
        "audit-test",
        {
          number: "4111111111111111",
          expMonth: "12",
          expYear: "2030",
          cvc: "123",
          holderName: "T",
        },
        key,
      );
      const log = store.getAuditLog(card.id);
      expect(log.length).toBeGreaterThan(0);
      expect(log[0].entityType).toBe("card");
    });

    it("records entity_type for identities", () => {
      const idn = store.createIdentity(vaultId, "audit", { email: "a@b" }, key);
      const log = store.getAuditLog(idn.id);
      expect(log.length).toBeGreaterThan(0);
      expect(log[0].entityType).toBe("identity");
    });

    it("records entity_type for credentials (back-compat default)", () => {
      const cred = store.createCredential(vaultId, "g.com", "u", key, "p");
      const log = store.getAuditLog(cred.id);
      expect(log.length).toBeGreaterThan(0);
      expect(log[0].entityType).toBe("credential");
    });
  });
});
