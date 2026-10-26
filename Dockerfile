# ============================================================================
# Stage 1: Build TypeScript & native dependencies
# ============================================================================
FROM node:22-alpine AS builder

RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY package.json ./
RUN npm install

COPY tsconfig.json tsconfig.build.json ./
COPY src ./src

RUN npm run build && npm prune --omit=dev

# ============================================================================
# Stage 2: Production runtime (non-root user)
# ============================================================================
FROM node:22-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production

# Create non-root user and persistent data directory
RUN addgroup -S kashcash && adduser -S kashcash -G kashcash \
    && mkdir -p /app/data && chown -R kashcash:kashcash /app

COPY --from=builder --chown=kashcash:kashcash /app/package.json ./package.json
COPY --from=builder --chown=kashcash:kashcash /app/node_modules ./node_modules
COPY --from=builder --chown=kashcash:kashcash /app/dist ./dist

USER kashcash

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/healthz || exit 1

CMD ["node", "dist/index.js"]
