import os from "node:os";

export async function collectSystemMetadata() {
  return {
    hostname: os.hostname(),
    os: `${process.platform} ${os.release()}`,
    uptimeSeconds: Math.round(os.uptime()),
    totalMemory: os.totalmem(),
    freeMemory: os.freemem(),
  };
}
