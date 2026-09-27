# syntax=docker/dockerfile:1
# Production Dockerfile for CyberGuard AI

FROM node:22-alpine AS builder

WORKDIR /app

# Enable Corepack for pnpm
RUN corepack enable && corepack prepare pnpm@latest --activate

# Copy package manifests and lockfile
COPY package.json pnpm-lock.yaml ./

# Install dependencies with frozen lockfile
RUN pnpm install --frozen-lockfile

# Copy application source
COPY . .

# Run type check and production build
RUN pnpm run check && pnpm run build

# Prune devDependencies for runtime
RUN pnpm prune --prod

# --- Production Runner Stage ---
FROM node:22-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000

# Install netstat / procps for local network telemetry inspection if desired
RUN apk add --no-cache net-tools procps

# Create non-root user for security
RUN addgroup --system --gid 1001 cyberguard && \
    adduser --system --uid 1001 cyberguard

# Copy production build artifacts and dependencies from builder
COPY --from=builder --chown=cyberguard:cyberguard /app/dist ./dist
COPY --from=builder --chown=cyberguard:cyberguard /app/node_modules ./node_modules
COPY --from=builder --chown=cyberguard:cyberguard /app/package.json ./package.json

USER cyberguard

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/api/health || exit 1

CMD ["node", "dist/index.js"]
