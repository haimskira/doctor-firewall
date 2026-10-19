#!/usr/bin/env bash
# Generate TLS material with the project's own tool (runs inside the api image).
#
#   scripts/gen-certs.sh --dev            dev CA + UI cert + FMC-mock cert; the dev CA becomes
#                                         the FMC trust store (infra/certs/dev-ca.pem)
#   scripts/gen-certs.sh --ui <hostname>  production: self-signed UI cert (CA in infra/certs/ui/)
#                                         until the organisation's PKI issues a real one —
#                                         then just replace infra/certs/ui/ui.pem + ui.key.
#
# Existing certificates are never overwritten. The CA private key is deleted after use.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

MODE="${1:-}"
IMAGE="doctor-firewall/api:${DF_VERSION:-dev}"
CERTS="$INFRA/certs"
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "image $IMAGE not found — build or load it first"

issue() {  # issue <out-dir> <ca-name> <leaf spec>...
    local out="$1" ca="$2"; shift 2
    local args=()
    for leaf in "$@"; do args+=(--leaf "$leaf"); done
    mkdir -p "$out"
    # shellcheck disable=SC2046
    docker run --rm $(docker_user_args) -v "$(host_path "$out"):/out" "$IMAGE" \
        python -m app.tools.certs --out /out --key-mode 0644 --ca-name "$ca" "${args[@]}" >/dev/null
    rm -f "$out/ca.key"
}

case "$MODE" in
    --dev)
        if [[ -s "$CERTS/ui/ui.pem" ]]; then ok "dev certificates already exist"; exit 0; fi
        tmp="$CERTS/.tmp"; rm -rf "$tmp"
        issue "$tmp" "Doctor Firewall DEV CA (not for production)" \
            "ui:localhost,127.0.0.1" "fmc-mock:fmc-mock"
        mkdir -p "$CERTS/ui" "$CERTS/fmc-mock"
        mv "$tmp/ui.pem" "$tmp/ui.key" "$CERTS/ui/"
        mv "$tmp/fmc-mock.pem" "$tmp/fmc-mock.key" "$CERTS/fmc-mock/"
        mv "$tmp/ca.pem" "$CERTS/dev-ca.pem"
        rm -rf "$tmp"
        ok "dev certs in infra/certs (import infra/certs/dev-ca.pem into your browser to trust the UI)"
        ;;
    --ui)
        host="${2:?usage: gen-certs.sh --ui <hostname>[,<more-sans>]}"
        if [[ -s "$CERTS/ui/ui.pem" ]]; then ok "UI certificate already exists"; exit 0; fi
        issue "$CERTS/ui" "Doctor Firewall local UI CA" "ui:$host"
        chmod 0700 "$CERTS/ui"
        ok "self-signed UI cert for $host in infra/certs/ui (distribute ca.pem to admin browsers)"
        ;;
    *) die "usage: gen-certs.sh --dev | --ui <hostname>" ;;
esac
