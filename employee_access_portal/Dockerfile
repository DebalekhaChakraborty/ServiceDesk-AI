# Employee Access Portal - Cloud Run container.
#
# No credential is ever baked into this image. Tenant/client identifiers arrive
# as Cloud Run environment variables and the two secrets arrive from Google
# Secret Manager at runtime.

# --- dependencies ------------------------------------------------------------
FROM node:22-alpine AS deps

WORKDIR /app
COPY package.json package-lock.json ./
# Production dependencies only: the test tooling never ships.
RUN npm ci --omit=dev && npm cache clean --force

# --- runtime -----------------------------------------------------------------
FROM node:22-alpine AS runtime

ENV NODE_ENV=production \
    PORT=8080

WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY public ./public

# Drop privileges: the `node` user ships with the base image.
USER node

EXPOSE 8080

# Local convenience only - Cloud Run performs its own probing.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

CMD ["node", "src/server.js"]
