import { exec } from "node:child_process";
import { promisify } from "node:util";

const execAsync = promisify(exec);

export async function collectProcessMetadata() {
  try {
    const command = process.platform === "win32" ? "wmic process get Name,ProcessId,CommandLine /format:csv" : "ps -eo pid,comm,args --no-headers";
    const { stdout } = await execAsync(command);

    return stdout
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .slice(0, 25)
      .map((line) => {
        const parts = line.split(/\s+/);
        return {
          pid: Number(parts[0]) || 0,
          name: parts[1] || "unknown",
          command: parts.slice(1).join(" ") || "",
        };
      });
  } catch {
    return [];
  }
}
