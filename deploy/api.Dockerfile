# Superseded for single-VM deployments by deploy/oci/Dockerfile (x86 and ARM). Kept for hosts that run only the API.
# Build from the repo root:  docker build --platform linux/amd64 -f deploy/api.Dockerfile -t nexora-cspm-api .
FROM node:22-alpine AS build
WORKDIR /app
RUN npm i -g pnpm@10
COPY . .
RUN pnpm install --frozen-lockfile && pnpm --filter @workspace/api-server build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production PORT=8080
COPY --from=build /app/artifacts/api-server/dist ./dist
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/api/healthz || exit 1
CMD ["node", "--enable-source-maps", "dist/index.mjs"]
