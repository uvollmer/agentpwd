#!/usr/bin/env node
import { Command } from "commander";
import * as readline from "node:readline/promises";
import { stdin, stderr } from "node:process";
import { homedir } from "node:os";
import { join } from "node:path";
import { mkdirSync, existsSync, chmodSync } from "node:fs";
import { VaultStore } from "../vault/store.js";
import { getOrCreateMasterKey, getMasterKey } from "../vault/keychain.js";
import { generatePassword } from "../vault/password-gen.js";
import {
  normalizePan,
  validateLuhn,
  detectBrand,
  normalizeExpMonth,
  normalizeExpYear,
} from "../vault/card.js";
import type { CardPayload, IdentityFields } from "../types.js";

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

function openStore(): VaultStore {
  ensureDir();
  return new VaultStore(DB_PATH);
}

/**
 * Read input without echoing characters (raw mode). Used for password entry
 * in interactive sessions. Falls back to readline if stdin isn't a TTY,
 * which is only reached via subcommands that wouldn't accept piped input
 * anyway — sensitive commands explicitly refuse non-TTY contexts.
 */
async function readHiddenInput(prompt: string): Promise<string> {
  if (stdin.isTTY) {
    stderr.write(prompt);
    return new Promise((resolve) => {
      let input = "";
      stdin.setRawMode(true);
      stdin.resume();
      stdin.setEncoding("utf8");
      const onData = (char: string) => {
        if (char === "\n" || char === "\r" || char === "\u0004") {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.removeListener("data", onData);
          stderr.write("\n");
          resolve(input);
        } else if (char === "\u0003") {
          stdin.setRawMode(false);
          process.exit(1);
        } else if (char === "\u007F" || char === "\b") {
          if (input.length > 0) input = input.slice(0, -1);
        } else {
          input += char;
        }
      };
      stdin.on("data", onData);
    });
  }
  const rl = readline.createInterface({ input: stdin, output: stderr });
  const answer = await rl.question(prompt);
  rl.close();
  return answer;
}

async function readInput(prompt: string): Promise<string> {
  const rl = readline.createInterface({ input: stdin, output: stderr });
  const answer = await rl.question(prompt);
  rl.close();
  return answer.trim();
}

const program = new Command();

program
  .name("ap")
  .description("AgentPwd — credential management for AI agents")
  .version("0.0.1");

// --- init ---
program
  .command("init")
  .description("Create a new vault")
  .argument("[name]", "Vault name", "default")
  .action(async (name: string) => {
    const store = openStore();
    try {
      const existing = store.getVaultByName(name);
      if (existing) {
        console.error(`Vault "${name}" already exists (${existing.id})`);
        process.exit(1);
      }
      const vault = store.createVault(name);
      await getOrCreateMasterKey(vault.id);
      console.log(`Vault created: ${vault.name} (${vault.id})`);
      console.log("Master key stored in OS keychain.");
    } finally {
      store.close();
    }
  });

// --- add ---
program
  .command("add")
  .description("Add a credential to the vault")
  .requiredOption("--site <site>", "Website or service name")
  .requiredOption("--username <username>", "Username or email")
  .option("--vault <name>", "Vault name", "default")
  .option("--generate", "Auto-generate password")
  .option("--length <n>", "Generated password length", "24")
  .action(async (opts) => {
    const store = openStore();
    try {
      const vault = store.getVaultByName(opts.vault);
      if (!vault) {
        console.error(
          `Vault "${opts.vault}" not found. Run "ap init" first.`,
        );
        process.exit(1);
      }

      const key = await getMasterKey(vault.id);
      if (!key) {
        console.error("Master key not found in OS keychain.");
        process.exit(1);
      }

      let password: string;
      if (opts.generate) {
        password = generatePassword({ length: parseInt(opts.length, 10) });
      } else {
        password = await readHiddenInput("Enter password: ");
        if (!password) {
          console.error("Password cannot be empty.");
          process.exit(1);
        }
      }

      const cred = store.createCredential(
        vault.id,
        opts.site,
        opts.username,
        key,
        password,
      );

      console.log("Credential stored.");
      console.log(`  ID:       ${cred.id}`);
      console.log(`  Site:     ${cred.site}`);
      console.log(`  Username: ${cred.username}`);
      if (opts.generate) {
        console.log("  Password: (auto-generated, use \"ap show\" to reveal)");
      }
    } finally {
      store.close();
    }
  });

// --- list ---
program
  .command("list")
  .description("List credentials in a vault")
  .option("--vault <name>", "Vault name", "default")
  .action(async (opts) => {
    const store = openStore();
    try {
      const vault = store.getVaultByName(opts.vault);
      if (!vault) {
        console.error(`Vault "${opts.vault}" not found.`);
        process.exit(1);
      }

      const creds = store.listCredentials(vault.id);
      if (creds.length === 0) {
        console.log("No credentials stored.");
        return;
      }

      console.log(`Credentials in vault "${vault.name}":\n`);
      for (const c of creds) {
        console.log(`  ${c.id}  ${c.site.padEnd(30)} ${c.username}`);
      }
      console.log(`\n${creds.length} credential(s)`);
    } finally {
      store.close();
    }
  });

// `ap show` is deliberately NOT included in v1. A TTY check is fake security
// (trivially bypassable via `script -q`, pty.spawn, etc.) and a real
// human-only reveal path requires hardware-attested user presence — deferred
// to v2 (Touch ID / Windows Hello). For now there is no CLI command that
// returns plaintext. See docs/threat-model.md.

// --- delete ---
program
  .command("delete")
  .description("Delete a credential")
  .requiredOption("--id <id>", "Credential ID")
  .action(async (opts) => {
    const store = openStore();
    try {
      const deleted = store.deleteCredential(opts.id);
      if (deleted) {
        console.log("Credential deleted.");
      } else {
        console.error("Credential not found.");
        process.exit(1);
      }
    } finally {
      store.close();
    }
  });

// --- vaults ---
program
  .command("vaults")
  .description("List all vaults")
  .action(async () => {
    const store = openStore();
    try {
      const vaults = store.listVaults();
      if (vaults.length === 0) {
        console.log("No vaults. Run \"ap init\" to create one.");
        return;
      }
      for (const v of vaults) {
        const creds = store.listCredentials(v.id);
        console.log(
          `  ${v.id}  ${v.name.padEnd(20)} ${creds.length} credential(s)`,
        );
      }
    } finally {
      store.close();
    }
  });

// --- add-card ---
program
  .command("add-card")
  .description(
    "Store a credit/debit card in the vault (interactive). " +
      "Card creation is CLI-only on purpose: passing a PAN through agent chat " +
      "would leak it to the LLM. There is no ap_create_card MCP tool.",
  )
  .option("--vault <name>", "Vault name", "default")
  .action(async (opts) => {
    const store = openStore();
    try {
      const vault = store.getVaultByName(opts.vault);
      if (!vault) {
        console.error(
          `Vault "${opts.vault}" not found. Run "ap init" first.`,
        );
        process.exit(1);
      }

      const key = await getMasterKey(vault.id);
      if (!key) {
        console.error("Master key not found in OS keychain.");
        process.exit(1);
      }

      const nickname = await readInput("Nickname (e.g. Personal Visa): ");
      if (!nickname) {
        console.error("Nickname cannot be empty.");
        process.exit(1);
      }

      const rawPan = await readHiddenInput("Card number: ");
      const pan = normalizePan(rawPan);
      if (!validateLuhn(pan)) {
        console.error(
          "Invalid card number (Luhn check failed). Aborting; nothing stored.",
        );
        process.exit(1);
      }

      const expMonthRaw = await readInput("Expiry month (MM): ");
      const expYearRaw = await readInput("Expiry year (YY or YYYY): ");
      const expMonth = normalizeExpMonth(expMonthRaw);
      const expYear = normalizeExpYear(expYearRaw);
      if (!/^(0[1-9]|1[0-2])$/.test(expMonth) || !/^\d{4}$/.test(expYear)) {
        console.error("Invalid expiry. Aborting; nothing stored.");
        process.exit(1);
      }

      const cvc = await readHiddenInput("CVC: ");
      if (!/^\d{3,4}$/.test(cvc)) {
        console.error("Invalid CVC. Aborting; nothing stored.");
        process.exit(1);
      }

      const holderName = await readInput("Cardholder name: ");
      if (!holderName) {
        console.error("Cardholder name cannot be empty.");
        process.exit(1);
      }

      const payload: CardPayload = {
        number: pan,
        expMonth,
        expYear,
        cvc,
        holderName,
      };
      const card = store.createCard(vault.id, nickname, payload, key);

      console.log("Card stored.");
      console.log(`  ID:       ${card.id}`);
      console.log(`  Nickname: ${card.nickname}`);
      console.log(`  Brand:    ${card.brand} (detected: ${detectBrand(pan)})`);
      console.log(`  Last4:    •••• ${card.last4}`);
    } finally {
      store.close();
    }
  });

// --- list-cards ---
program
  .command("list-cards")
  .description("List cards in a vault (no number, no CVC).")
  .option("--vault <name>", "Vault name", "default")
  .action(async (opts) => {
    const store = openStore();
    try {
      const vault = store.getVaultByName(opts.vault);
      if (!vault) {
        console.error(`Vault "${opts.vault}" not found.`);
        process.exit(1);
      }
      const cards = store.listCards(vault.id);
      if (cards.length === 0) {
        console.log("No cards stored.");
        return;
      }
      console.log(`Cards in vault "${vault.name}":\n`);
      for (const c of cards) {
        console.log(
          `  ${c.id}  ${c.nickname.padEnd(24)} ${c.brand.padEnd(12)} •••• ${c.last4}`,
        );
      }
      console.log(`\n${cards.length} card(s)`);
    } finally {
      store.close();
    }
  });

// --- delete-card ---
program
  .command("delete-card")
  .description("Delete a stored card")
  .requiredOption("--id <id>", "Card ID")
  .action(async (opts) => {
    const store = openStore();
    try {
      const ok = store.deleteCard(opts.id);
      if (ok) {
        console.log("Card deleted.");
      } else {
        console.error("Card not found.");
        process.exit(1);
      }
    } finally {
      store.close();
    }
  });

// --- add-identity ---
program
  .command("add-identity")
  .description(
    "Store an identity (name, email, phone, address) in the vault. " +
      "Each prompt is optional — press Enter to skip. At least one field must be filled.",
  )
  .option("--vault <name>", "Vault name", "default")
  .requiredOption("--nickname <nick>", "Short label, e.g. Home or Work")
  .action(async (opts) => {
    const store = openStore();
    try {
      const vault = store.getVaultByName(opts.vault);
      if (!vault) {
        console.error(
          `Vault "${opts.vault}" not found. Run "ap init" first.`,
        );
        process.exit(1);
      }
      const key = await getMasterKey(vault.id);
      if (!key) {
        console.error("Master key not found in OS keychain.");
        process.exit(1);
      }

      const fields: IdentityFields = {
        givenName: (await readInput("Given name (or empty): ")) || undefined,
        familyName: (await readInput("Family name (or empty): ")) || undefined,
        email: (await readInput("Email (or empty): ")) || undefined,
        phone: (await readInput("Phone E.164 (or empty): ")) || undefined,
        streetAddress:
          (await readInput("Street address (or empty): ")) || undefined,
        addressLine2:
          (await readInput("Address line 2 (or empty): ")) || undefined,
        city: (await readInput("City (or empty): ")) || undefined,
        region: (await readInput("Region/state (or empty): ")) || undefined,
        postalCode: (await readInput("Postal code (or empty): ")) || undefined,
        country: (await readInput("Country ISO code (or empty): ")) || undefined,
        dateOfBirth:
          (await readInput("DOB YYYY-MM-DD (or empty): ")) || undefined,
      };

      const hasAny = Object.values(fields).some((v) => v && v.length > 0);
      if (!hasAny) {
        console.error("At least one field is required.");
        process.exit(1);
      }

      const idn = store.createIdentity(vault.id, opts.nickname, fields, key);
      console.log("Identity stored.");
      console.log(`  ID:       ${idn.id}`);
      console.log(`  Nickname: ${idn.nickname}`);
    } finally {
      store.close();
    }
  });

// --- list-identities ---
program
  .command("list-identities")
  .description("List identities in a vault (no values).")
  .option("--vault <name>", "Vault name", "default")
  .action(async (opts) => {
    const store = openStore();
    try {
      const vault = store.getVaultByName(opts.vault);
      if (!vault) {
        console.error(`Vault "${opts.vault}" not found.`);
        process.exit(1);
      }
      const identities = store.listIdentities(vault.id);
      if (identities.length === 0) {
        console.log("No identities stored.");
        return;
      }
      console.log(`Identities in vault "${vault.name}":\n`);
      for (const i of identities) {
        console.log(`  ${i.id}  ${i.nickname}`);
      }
      console.log(`\n${identities.length} identity(ies)`);
    } finally {
      store.close();
    }
  });

// --- delete-identity ---
program
  .command("delete-identity")
  .description("Delete a stored identity")
  .requiredOption("--id <id>", "Identity ID")
  .action(async (opts) => {
    const store = openStore();
    try {
      const ok = store.deleteIdentity(opts.id);
      if (ok) {
        console.log("Identity deleted.");
      } else {
        console.error("Identity not found.");
        process.exit(1);
      }
    } finally {
      store.close();
    }
  });

program.parse();
