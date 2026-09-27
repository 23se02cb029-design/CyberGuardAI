# CyberGuard Endpoint Agent

This lightweight agent is designed to run on an authorized workstation and securely send metadata-only security telemetry to the CyberGuard server.

## Consent and scope

The agent collects only metadata needed for network and endpoint monitoring. It does not capture packet payloads, passwords, browser history, or decrypted traffic.

## Installation

1. Create an endpoint in the CyberGuard dashboard.
2. Copy the generated enrollment token.
3. Configure environment variables:

```bash
export CYBERGUARD_SERVER_URL="https://your-server"
export CYBERGUARD_ENDPOINT_ID="123"
export CYBERGUARD_ENDPOINT_SECRET="ep_..."
```

4. Run the agent:

```bash
npm install
npm start
```

## Behavior

- Sends periodic heartbeat requests
- Collects process and connection metadata
- Filters for suspicious ports or process names
- Uploads only structured metadata to the CyberGuard API
- Stops telemetry when paused or revoked
