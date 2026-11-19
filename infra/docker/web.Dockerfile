# UI image: React build served by unprivileged nginx (which also proxies /api).
#
# Offline build: npm installs strictly from vendor/npm-cache (populated by
# scripts/vendor.* inside a Linux container) with --offline; install scripts are
# disabled (.npmrc ignore-scripts=true).

ARG NODE_IMAGE=node:22.23.3-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392
ARG NGINX_IMAGE=nginx:1.30.7-alpine-slim@sha256:8c950211a641ec5b23f265450517001f6bcca533666120ebe36cb4cff3d00a55

FROM ${NODE_IMAGE} AS deps
ENV NPM_CONFIG_UPDATE_NOTIFIER=false NPM_CONFIG_FUND=false NPM_CONFIG_AUDIT=false
WORKDIR /src
COPY vendor/npm-cache /npm-cache
COPY frontend/package.json frontend/package-lock.json frontend/.npmrc ./
RUN npm ci --offline --cache /npm-cache --no-audit --no-fund

# ---- test / CI: lint + strict typecheck + unit tests ----
FROM deps AS test
COPY frontend/ ./
CMD ["sh", "-c", "npm run lint && npm run typecheck && npm test"]

FROM deps AS build
COPY frontend/ ./
RUN npm run build

# Official nginx image (1.30.7: CVE-2026-121810, -123007, -123633/4, musl, zlib fixes; the
# nginx-unprivileged variant had no 1.30.7 build yet). It starts as root by default: run it
# as its built-in nginx user (uid 101, as the unprivileged variant did) — the compose
# hardening drops every capability, and the config keeps pid / temp files in /tmp.
FROM ${NGINX_IMAGE} AS runtime
COPY infra/nginx/nginx.conf /etc/nginx/nginx.conf
COPY --from=build /src/dist /usr/share/nginx/html
USER 101
EXPOSE 8443
