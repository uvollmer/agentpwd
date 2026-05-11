import keytar from "keytar";
import { generateMasterKey } from "./crypto.js";

const SERVICE_NAME = "agentpwd";

/** Get or create the master key for a vault from the OS keychain. */
export async function getOrCreateMasterKey(
  vaultId: string,
): Promise<Uint8Array> {
  const existing = await getMasterKey(vaultId);
  if (existing) return existing;

  const key = generateMasterKey();
  await storeMasterKey(vaultId, key);
  return key;
}

/** Retrieve the master key for a vault from the OS keychain. */
export async function getMasterKey(
  vaultId: string,
): Promise<Uint8Array | null> {
  const stored = await keytar.getPassword(SERVICE_NAME, vaultId);
  if (!stored) return null;
  return Buffer.from(stored, "base64");
}

/** Store a master key in the OS keychain. */
export async function storeMasterKey(
  vaultId: string,
  key: Uint8Array,
): Promise<void> {
  await keytar.setPassword(
    SERVICE_NAME,
    vaultId,
    Buffer.from(key).toString("base64"),
  );
}

/** Delete a master key from the OS keychain. */
export async function deleteMasterKey(vaultId: string): Promise<boolean> {
  return keytar.deletePassword(SERVICE_NAME, vaultId);
}

/** List all vault IDs that have keys stored. */
export async function listStoredVaults(): Promise<string[]> {
  const credentials = await keytar.findCredentials(SERVICE_NAME);
  return credentials.map((c) => c.account);
}
