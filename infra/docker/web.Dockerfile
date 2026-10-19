# UI image: React build served by unprivileged nginx (which also proxies /api).
#
# Offline build: npm installs strictly from vendor/npm-cache (populated by
# scripts/vendor.* inside a Linux container) with --offline; install scripts are
# disabled (.npmrc ignore-scripts=true).

ARG NODE_IMAGE=node:22.23.3-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392
ARG NGINX_IMAGE=nginxinc/nginx-unprivileged:1.28.2-alpine@sha256:7377697a821c131a924a7105fafbe7414db4e9fcc77a6f08f776f33f141ec3f8

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

FROM ${NGINX_IMAGE} AS runtime
COPY infra/nginx/nginx.conf /etc/nginx/nginx.conf
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 8443
