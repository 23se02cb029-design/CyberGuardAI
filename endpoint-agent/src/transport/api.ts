import axios from "axios";
import { config } from "../config.js";

const api = axios.create({
  baseURL: config.serverUrl,
  timeout: 12000,
});

export async function sendHeartbeat(payload: Record<string, unknown>) {
  return api.post("/api/endpoints/heartbeat", payload, {
    headers: {
      Authorization: `Bearer ${config.endpointSecret}`,
      "x-endpoint-id": config.endpointId,
    },
  });
}

export async function sendTelemetry(payload: Record<string, unknown>) {
  return api.post("/api/endpoints/telemetry", payload, {
    headers: {
      Authorization: `Bearer ${config.endpointSecret}`,
      "x-endpoint-id": config.endpointId,
    },
  });
}
