import { execFile } from "node:child_process";
import { mkdtempSync, writeFileSync, unlinkSync, rmdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Injector } from "./injector.js";

/**
 * AppleScript-based injector for macOS Chrome.
 * Requires Chrome with View → Developer → "Allow JavaScript from Apple Events" enabled.
 *
 * The JS code is written to a temp file under a 0700 dir to avoid shell-escaping
 * pitfalls and prevent other users on the box from reading the in-flight payload.
 */
export class AppleScriptInjector extends Injector {
  async evaluate(jsCode: string): Promise<string> {
    // Create a per-call dir with 0700 so other users cannot read the JS payload
    const dir = mkdtempSync(join(tmpdir(), "ap-"), { encoding: "utf-8" });
    const jsPath = join(dir, "fill.js");
    const asPath = join(dir, "fill.scpt");

    const appleScript = `set jsFile to POSIX file "${jsPath}"
set jsCode to read jsFile as «class utf8»
tell application "Google Chrome"
  execute active tab of front window javascript jsCode
end tell`;

    try {
      writeFileSync(jsPath, jsCode, { encoding: "utf-8", mode: 0o600 });
      writeFileSync(asPath, appleScript, { encoding: "utf-8", mode: 0o600 });

      return await new Promise<string>((resolve, reject) => {
        execFile("osascript", [asPath], (error, stdout, stderr) => {
          if (error) {
            reject(
              new Error(
                `AppleScript execution failed: ${stderr || error.message}`,
              ),
            );
            return;
          }
          resolve(stdout.trim());
        });
      });
    } finally {
      try {
        unlinkSync(jsPath);
      } catch {}
      try {
        unlinkSync(asPath);
      } catch {}
      try {
        rmdirSync(dir);
      } catch {}
    }
  }

  async close(): Promise<void> {
    // Nothing to release for AppleScript — every call spawns its own osascript.
  }
}
