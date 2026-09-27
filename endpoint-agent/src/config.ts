export const config = {
  serverUrl: process.env.CYBERGUARD_SERVER_URL || "https://your-server",
  endpointId: process.env.CYBERGUARD_ENDPOINT_ID || "",
  endpointSecret: process.env.CYBERGUARD_ENDPOINT_SECRET || "",
  pollIntervalMs: Number(process.env.CYBERGUARD_POLL_INTERVAL_MS || 15000),
  hostname: process.env.COMPUTERNAME || process.env.HOSTNAME || "unknown-host",
};
