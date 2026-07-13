# Build stage
FROM node:24-alpine AS builder

RUN corepack enable

WORKDIR /app

COPY package.json pnpm-lock.yaml ./

RUN corepack install && pnpm install --frozen-lockfile

COPY . .

RUN pnpm build

# Production stage
FROM node:24-alpine AS production

RUN corepack enable

RUN addgroup --system --gid 1001 verifier && \
    adduser --system --uid 1001 verifier

WORKDIR /app

COPY --chown=verifier:verifier package.json pnpm-lock.yaml ./

RUN corepack install && pnpm install --frozen-lockfile --prod --ignore-scripts

COPY --from=builder --chown=verifier:verifier /app/dist ./dist

USER verifier

EXPOSE 3500

CMD ["node", "dist/main"]
