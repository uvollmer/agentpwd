import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { homedir } from "node:os";
import { join } from "node:path";
import { mkdirSync, existsSync, chmodSync } from "node:fs";
import { VaultStore } from "../vault/store.js";
import { getOrCreateMasterKey, getMasterKey } from "../vault/keychain.js";

const AP_DIR = join(homedir(), ".agentpwd");
const DB_PATH = join(AP_DIR, "vault.db");

function ensureDir(): void {
  if (!existsSync(AP_DIR)) {
    mkdirSync(AP_DIR, { recursive: true, mode: 0o700 });
  }
  try {
    chmodSync(AP_DIR, 0o700);
  } catch {
    // Best-effort tightening — not all filesystems honor chmod
  }
}

function getStore(): VaultStore {
  ensureDir();
  return new VaultStore(DB_PATH);
}

function textResult(data: object) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data) }] };
}

function errorResult(message: string) {
  return {
    content: [
      { type: "text" as const, text: JSON.stringify({ error: message }) },
    ],
    isError: true,
  };
}

/**
 * Register the metadata-only tool surface. None of these tools return a
 * plaintext credential value to the caller (the LLM). Plaintext-touching
 * tools (`ap_fill_login`, `ap_run`, etc.) land in subsequent PRs alongside
 * the injection backend they delegate to.
 */
export function registerTools(server: McpServer): void {
  // --- ap_create_vault ---
  server.registerTool(
    "ap_create_vault",
    {
      description:
        "Create a new encrypted vault for storing credentials. " +
        "Generates a 256-bit master key and stores it in the OS keychain. " +
        "Returns the new vault's ID and metadata.",
      inputSchema: {
        name: z.string().describe("Name for the vault"),
      },
    },
    async ({ name }) => {
      const store = getStore();
      try {
        const existing = store.getVaultByName(name);
        if (existing) return errorResult(`Vault "${name}" already exists`);
        const vault = store.createVault(name);
        await getOrCreateMasterKey(vault.id);
        return textResult({
          vault_id: vault.id,
          name: vault.name,
          created_at: vault.createdAt,
        });
      } finally {
        store.close();
      }
    },
  );

  // --- ap_list_vaults ---
  server.registerTool(
    "ap_list_vaults",
    {
      description: "List all vaults.",
    },
    async () => {
      const store = getStore();
      try {
        const vaults = store.listVaults();
        return textResult({
          vaults: vaults.map((v) => ({
            vault_id: v.id,
            name: v.name,
            created_at: v.createdAt,
          })),
        });
      } finally {
        store.close();
      }
    },
  );

  // --- ap_create_credential ---
  server.registerTool(
    "ap_create_credential",
    {
      description:
        "Store a credential in a vault. The password is auto-generated if not " +
        "provided. The password is NEVER returned — only the credential ID and " +
        "metadata. To use a credential, call ap_fill_login (lands in a later PR).",
      inputSchema: {
        vault_id: z
          .string()
          .describe("ID of the vault to store the credential in"),
        site: z.string().describe("Website or service (e.g. github.com)"),
        username: z.string().describe("Username or email"),
        password: z
          .string()
          .optional()
          .describe("Password (auto-generated if omitted)"),
      },
    },
    async ({ vault_id, site, username, password }) => {
      const store = getStore();
      try {
        const vault = store.getVault(vault_id);
        if (!vault) return errorResult(`Vault "${vault_id}" not found`);

        const key = await getMasterKey(vault_id);
        if (!key) {
          return errorResult(
            `Master key for vault "${vault_id}" not found in OS keychain`,
          );
        }

        const cred = store.createCredential(
          vault_id,
          site,
          username,
          key,
          password || undefined,
        );

        return textResult({
          credential_id: cred.id,
          site: cred.site,
          username: cred.username,
          password_generated: !password,
          created_at: cred.createdAt,
        });
      } finally {
        store.close();
      }
    },
  );

  // --- ap_list_credentials ---
  server.registerTool(
    "ap_list_credentials",
    {
      description:
        "List credentials in a vault. Returns IDs, sites, and usernames only — " +
        "never passwords.",
      inputSchema: {
        vault_id: z.string().describe("ID of the vault"),
      },
    },
    async ({ vault_id }) => {
      const store = getStore();
      try {
        const creds = store.listCredentials(vault_id);
        return textResult({
          credentials: creds.map((c) => ({
            credential_id: c.id,
            site: c.site,
            username: c.username,
            created_at: c.createdAt,
          })),
        });
      } finally {
        store.close();
      }
    },
  );

  // --- ap_delete_credential ---
  server.registerTool(
    "ap_delete_credential",
    {
      description: "Delete a stored credential.",
      inputSchema: {
        credential_id: z.string().describe("ID of the credential to delete"),
      },
    },
    async ({ credential_id }) => {
      const store = getStore();
      try {
        const deleted = store.deleteCredential(credential_id);
        if (!deleted) {
          return errorResult(`Credential "${credential_id}" not found`);
        }
        return textResult({ status: "deleted", credential_id });
      } finally {
        store.close();
      }
    },
  );
}
