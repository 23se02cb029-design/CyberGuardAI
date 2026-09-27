# CyberGuard AI Backend

This project already contains the Express + tRPC backend and the React frontend is wired to `/api/trpc`.

## Architecture

- `server/_core/index.ts` — Express server and API entry point
- `server/routers.ts` — authentication, logs, threats, dashboard, reports and SOC Copilot procedures
- `server/services/securityEngine.ts` — local security heuristics and Gemini failover
- `server/agents.ts` — log normalization and SOC Copilot agent
- `server/db.ts` — PostgreSQL/Drizzle persistence
- `drizzle/schema.ts` — users, organizations, logs, threats, recommendations, reports and chat history
- `client/src/lib/trpc.ts` + `client/src/main.tsx` — frontend API client

## Required environment

Copy `.env.example` to `.env` and set:

```env
DATABASE_URL=postgresql://USER:PASSWORD@HOST:5432/DATABASE
JWT_SECRET=replace-with-a-long-random-secret
OWNER_OPEN_ID=admin@example.com
GEMINI_API_KEY=your-gemini-key
```

`GEMINI_API_KEY` is optional because the security engine and SOC Copilot have local heuristic/fallback behavior.

## Run

```bash
pnpm install
pnpm run db:push
pnpm run dev
```

The Express server starts on port `3000` by default and mounts the React/Vite development server through the same process. The frontend calls `/api/trpc`, while the demo analyzer remains available at `/api/analyze`.

## Main flow

1. Sign up / sign in.
2. The backend provisions an organization for a new account.
3. Upload a CSV/JSON/syslog/plain-text security log.
4. Backend normalizes and stores log lines.
5. Threat analysis runs against unprocessed logs.
6. Detections, risk scores, indicators, MITRE mappings and recommendations are stored.
7. Dashboard metrics are read from PostgreSQL.
8. SOC Copilot uses Gemini when configured and falls back to local heuristics when it is unavailable.
9. Threat status and incident reports are persisted.
