# PostgreSQL 16 for Doctor Firewall.
#
# The upstream image starts as root and drops to "postgres" with gosu. We start as
# "postgres" directly (no root step, no added capabilities), so gosu is unnecessary —
# and it is removed because it is a static Go binary that carries an outdated Go
# standard library (fixable HIGH/CRITICAL findings in the offline image scan).
ARG POSTGRES_IMAGE=postgres:16.15-bookworm@sha256:e8a07d2c7579b038938cdba6c539e580e5001caf9ea203d397b5cc83e76bd938

FROM ${POSTGRES_IMAGE}
RUN rm -f /usr/local/bin/gosu
COPY infra/postgres/init/ /docker-entrypoint-initdb.d/
USER postgres
