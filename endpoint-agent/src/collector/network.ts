import { exec } from "node:child_process";
import { promisify } from "node:util";

const execAsync = promisify(exec);

export async function collectNetworkMetadata() {
  try {
    const command = process.platform === "win32" ? "netstat -ano" : "ss -tunap";
    const { stdout } = await execAsync(command);

    return stdout
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .slice(2)
      .map((line) => {
        const parts = line.split(/\s+/);
        const protocol = parts[0]?.toUpperCase() || "TCP";
        const local = parts[1] || "";
        const remote = parts[2] || "";
        const state = parts[3] || "UNKNOWN";
        const pid = parts[parts.length - 1] || "";

        return {
          protocol,
          local,
          remote,
          state,
          pid,
          timestamp: new Date().toISOString(),
        };
      })
      .slice(0, 25);
  } catch {
    return [];
  }
}
