# syntax=docker/dockerfile:1.7
#
# Multi-stage Linux build for the Group Self Service portal. Uses a minimal
# Alpine-based Node runtime, a non-root user, and a writable volume mount
# for the portal's on-disk state (encrypted settings, daily audit NDJSON
# files, file-backed sessions, login history, single-instance PID lockfile).
# The portal is intentionally single-instance per data directory; do not
# scale this service past one replica (see README "Deployment topology").
#
# Build:   docker build -t groupselfservice:latest .
# Run:     docker run --rm -p 3000:3000 \
#            -e SESSION_SECRET=... -e CREDENTIAL_ENCRYPTION_KEY=... \
#            -v gss-data:/app/data groupselfservice:latest

############################
# 1. install all deps      #
############################
FROM node:24-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci

############################
# 2. build TypeScript      #
############################
FROM node:24-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

############################
# 3. production deps only  #
############################
FROM node:24-alpine AS prod-deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

############################
# 4. runtime image         #
############################
FROM node:24-alpine AS runtime
WORKDIR /app

ENV NODE_ENV=production \
    PORT=3000 \
    SETTINGS_FILE_PATH=/app/data/portal-settings.json

# Drop privileges to the built-in `node` user and ensure the data volume is
# writable by it.
RUN mkdir -p /app/data /app/logs \
 && chown -R node:node /app

COPY --chown=node:node --from=prod-deps /app/node_modules ./node_modules
COPY --chown=node:node --from=build /app/dist ./dist
COPY --chown=node:node views ./views
COPY --chown=node:node public ./public
COPY --chown=node:node package.json ./

USER node

EXPOSE 3000
VOLUME ["/app/data"]

# Public unauthenticated liveness probe. Returns {"ok":true} with HTTP 200.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/healthz',{signal:AbortSignal.timeout(4000)}).then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

CMD ["node", "dist/server.js"]
