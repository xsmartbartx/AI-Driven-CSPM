# One Dockerfile, three images, for a single VM (x86 or ARM, e.g. OCI Ampere):
#   docker build --target api -t nexora-cspm-api .          (the API; Node, no native deps)
#   docker build --target web -t nexora-cspm-web .          (Caddy serving both static sites + proxying the API)
# Build from the repository root. The build stage uses Debian (glibc) because the workspace excludes musl binaries.
FROM node:22-bookworm-slim AS build
WORKDIR /app
RUN npm i -g pnpm@10
COPY . .
RUN pnpm install --frozen-lockfile
# Front-end URLs are baked in at build time; the build fails if they are missing (see the vite configs).
ARG VITE_API_URL
ARG VITE_APP_URL
ENV VITE_API_URL=$VITE_API_URL VITE_APP_URL=$VITE_APP_URL
RUN pnpm --filter @workspace/api-server build \
 && pnpm --filter @workspace/cspm-site build \
 && pnpm --filter @workspace/cspm-app build

FROM node:22-alpine AS api
WORKDIR /app
ENV NODE_ENV=production PORT=8080
COPY --from=build /app/artifacts/api-server/dist ./dist
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s CMD wget -qO- http://127.0.0.1:8080/api/healthz || exit 1
CMD ["node", "--enable-source-maps", "dist/index.mjs"]

FROM caddy:2-alpine AS web
COPY --from=build /app/artifacts/cspm-site/dist /srv/site
COPY --from=build /app/artifacts/cspm-app/dist /srv/app
COPY deploy/oci/Caddyfile /etc/caddy/Caddyfile
