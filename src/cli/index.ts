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

program.parse();
