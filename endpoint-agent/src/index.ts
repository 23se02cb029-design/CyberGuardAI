import { config } from "./config.js";
import { collectNetworkMetadata } from "./collector/network.js";
import { collectProcessMetadata } from "./collector/processes.js";
import { collectSystemMetadata } from "./collector/system.js";
import { sendHeartbeat, sendTelemetry } from "./transport/api.js";
import { evaluateLocalSignals } from "./security/localRules.js";

async function tick() {
  if (!config.endpointId || !config.endpointSecret) {
    console.warn("[Endpoint Agent] Missing CYBERGUARD_ENDPOINT_ID or CYBERGUARD_ENDPOINT_SECRET.");
    return;
  }

  const system = await collectSystemMetadata();
  const processes = await collectProcessMetadata();
  const network = await collectNetworkMetadata();
  const signals = evaluateLocalSignals(network, processes);

  await sendHeartbeat({
    endpointId: config.endpointId,
    hostname: system.hostname,
    os: system.os,
    agentVersion: "1.0.0",
    status: signals.length ? "warning" : "online",
  });

  for (const event of signals) {
    await sendTelemetry({
      endpointId: config.endpointId,
      timestamp: new Date().toISOString(),
      eventType: event.eventType,
      source: { ip: event.sourceIp },
      destination: { ip: event.destinationIp, port: event.port },
      protocol: event.protocol,
      process: event.process,
      hostname: system.hostname,
      bytesSent: event.bytesSent,
      bytesReceived: event.bytesReceived,
      status: event.status,
      confidence: event.confidence,
      flags: event.flags,
    });
  }
}

console.log("[Endpoint Agent] Starting CyberGuard Endpoint Agent");

setInterval(() => {
  tick().catch((error) => console.error("[Endpoint Agent] Error:", error));
}, config.pollIntervalMs);

tick().catch((error) => console.error("[Endpoint Agent] Error:", error));
