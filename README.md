# CyberGuard AI: Intelligent SOC Copilot

An automated Security Operations Center (SOC) copilot designed to ingest system security logs, isolate anomalous system behaviors, and provide structured threat intelligence alerts.

## CyberGuard Endpoint Agent

CyberGuard now includes a consent-based endpoint monitoring flow for authorized workstations. The design keeps the existing SOC workflow intact while adding endpoint registration, short-lived enrollment tokens, authenticated telemetry ingestion, risk scoring, and endpoint inventory management.

### Architecture

```text
Authorized PC
     ↓
CyberGuard Agent
     ↓ HTTPS
CyberGuard API
     ↓
Security Engine
     ↓
Database
     ↓
SOC Dashboard
```

### Installation

1. Install the app dependencies:

```bash
pnpm install
```

2. Start the platform:

```bash
pnpm run dev
```

3. Create an endpoint from the Dashboard → Endpoints page.

4. Generate the enrollment token and run the agent on an approved workstation.

### Authorization requirements

- Endpoint registration requires an authenticated admin user.
- Enrollment tokens are short-lived and single-use.
- Agents authenticate with a generated secret bound to the endpoint.
- Revoked endpoints are immediately marked inactive.
- Organization isolation prevents cross-tenant access.

### Collected telemetry

The agent should only send metadata necessary for defensive monitoring, including:

- timestamp
- local IP
- remote IP
- destination port
- protocol
- connection state
- process name when available
- hostname
- agent version
- bytes sent/received where available
- DNS metadata when legally allowed

The system does not collect packet payloads, passwords, browser history, secrets, TLS plaintext, or remote command execution payloads.

### Privacy and retention

The endpoint configuration supports:

- telemetry collection toggle
- retention window
- metadata collection toggles
- consent notice display
- endpoint revocation

### API endpoints

The project exposes the following endpoint-focused APIs through the existing tRPC server and Express-compatible architecture:

- `endpoints.create`
- `endpoints.list`
- `endpoints.status`
- `endpoints.enroll`
- `endpoints.heartbeat`
- `endpoints.telemetry`
- `endpoints.revoke`

### Security model

The endpoint flow uses:

- HTTPS/TLS for the agent-server channel
- short-lived enrollment tokens
- hashed secrets and tokens
- organization isolation
- request validation and schema checks
- rate limiting strategy via server-side controls and validation
- audit-friendly telemetry persistence

### Threat detection

The existing security engine is used for endpoint telemetry scoring. Events are assessed using a transparent, evidence-based risk model that considers:

- destination port
- process behavior
- repetition and frequency
- suspicious destinations
- confidence level
- correlation across event patterns

### Troubleshooting

- If enrollment fails, confirm the token is valid and not expired.
- If an endpoint does not appear online, verify the agent is connected and sending heartbeat traffic.
- If telemetry is not scored, confirm the event payload contains a valid timestamp and event type.
- If a workstation has been revoked, re-enroll it with a new token and secret.

## 🏗️ System Architecture
- **Ingestion Layer:** Efficient log ingestion engineered with TypeScript.
- **Analysis Engine:** Processes structural parameters using deterministic heuristic rules and predictive threat modules.
- **Alert Generation:** Outputs high-fidelity mitigation playbooks for systems administrators.

  <img width="430" height="455" alt="1" src="https://github.com/user-attachments/assets/e50978fa-13af-4030-a478-2a17c74cf53b" />
  <img width="960" height="540" alt="2" src="https://github.com/user-attachments/assets/4e3fbcc0-54f8-48b2-bc4d-fce761475be6" />
  <img width="948" height="474" alt="3" src="https://github.com/user-attachments/assets/39dc075f-e6ab-4f3c-8105-2fa05af1144e" />
  <img width="960" height="474" alt="5" src="https://github.com/user-attachments/assets/287d0b02-1bb2-457a-b92a-b2d51293de42" />
<img width="960" height="469" alt="4" src="https://github.com/user-attachments/assets/f83ab5f3-93f4-404d-b0e7-f590b1246ec6" />

## 🚀 Local Installation & Setup

1. Clone the environment:
```bash
git clone https://github.com/23se02cb029-design/CyberGuardAI.git
cd CyberGuardAI
```

2. Install system-level node dependencies:
```bash
pnpm install
```

3. Boot the development lifecycle:
```bash
pnpm run dev
```
4. Production Build:
```bash
pnpm build
```
---

# 📜 License

This project is licensed under the MIT License.

Feel free to use, modify, and distribute it for educational and personal purposes.

---

# 👨‍💻 Author

**Vasur Vora**

- GitHub: https://github.com/23se02cb029-design

If you found this project helpful, consider giving it a ⭐ on GitHub.

