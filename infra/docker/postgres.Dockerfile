# PostgreSQL 16 for Doctor Firewall.
#
# The upstream image starts as root and drops to "postgres" with gosu. We start as
# "postgres" directly (no root step, no added capabilities), so gosu is unnecessary —
# and it is removed because it is a static Go binary that carries an outdated Go
# standard library (fixable HIGH/CRITICAL findings in the offline image scan).
ARG POSTGRES_IMAGE=postgres:16.15-bookworm@sha256:0ea6700a3b4f0ae6ce746519073558aed4d88a79d8d07622a9a644946c7319c4

FROM ${POSTGRES_IMAGE}
RUN rm -f /usr/local/bin/gosu
COPY infra/postgres/init/ /docker-entrypoint-initdb.d/
USER postgres
