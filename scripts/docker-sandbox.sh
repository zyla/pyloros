#!/usr/bin/env bash
#
# docker-sandbox.sh — Run a Docker container with all network access
# routed exclusively through the redlimitador proxy.
#
# Usage: scripts/docker-sandbox.sh [OPTIONS] IMAGE [COMMAND...]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Defaults
CONFIG=""
BINARY=""
PROXY_IMAGE=""
CA_DIR=""
KEEP=false
PREFIX="rl-sandbox-$$"
PROXY_PORT=8080
READINESS_TIMEOUT=30

usage() {
    cat <<'EOF'
Usage: docker-sandbox.sh [OPTIONS] IMAGE [COMMAND...]

Run a Docker container with all network access routed through the
redlimitador proxy. The sandbox container has no direct internet access;
all traffic must go through the proxy's allowlist rules.

Options:
  --config FILE    Proxy config file with rules (required)
  --image IMAGE    Docker image to use for the proxy
                   (default: ghcr.io/zyla/redlimitador:latest)
  --binary PATH    Path to redlimitador binary (builds a local Docker
                   image from the binary using the project Dockerfile)
  --ca-dir DIR     Use existing CA certs from this directory (default: auto-generate)
  --keep           Don't clean up containers/networks on exit (for debugging)
  -h, --help       Show this help message

Architecture:
  external network (bridge) ─── Proxy ─── Internet
                                  │
  internal network (--internal) ── Sandbox

The sandbox is on the internal network only (no direct internet).
The proxy bridges both networks, forwarding allowed requests.

Examples:
  # Interactive shell with proxy-only access (uses published image)
  scripts/docker-sandbox.sh --config config.toml alpine:latest sh

  # Use a local binary (builds a temporary Docker image)
  scripts/docker-sandbox.sh --config config.toml --binary target/release/redlimitador alpine:latest sh

  # Use a specific image
  scripts/docker-sandbox.sh --config config.toml --image my-proxy:dev alpine:latest sh
EOF
    exit 0
}

log() { echo "$*" >&2; }

die() {
    echo "Error: $*" >&2
    exit 1
}

# Parse arguments
POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)
            CONFIG="$2"
            shift 2
            ;;
        --binary)
            BINARY="$2"
            shift 2
            ;;
        --image)
            PROXY_IMAGE="$2"
            shift 2
            ;;
        --ca-dir)
            CA_DIR="$2"
            shift 2
            ;;
        --keep)
            KEEP=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        --)
            shift
            POSITIONAL+=("$@")
            break
            ;;
        -*)
            die "Unknown option: $1 (use -- to separate script options from container command)"
            ;;
        *)
            # First positional is IMAGE; everything after is COMMAND
            POSITIONAL+=("$@")
            break
            ;;
    esac
done

# Validate arguments
[[ -n "$CONFIG" ]] || die "--config is required"
[[ -f "$CONFIG" ]] || die "Config file not found: $CONFIG"
CONFIG="$(cd "$(dirname "$CONFIG")" && pwd)/$(basename "$CONFIG")"

[[ ${#POSITIONAL[@]} -ge 1 ]] || die "IMAGE argument is required"
IMAGE="${POSITIONAL[0]}"
COMMAND=("${POSITIONAL[@]:1}")

# --binary and --image are mutually exclusive
if [[ -n "$BINARY" ]] && [[ -n "$PROXY_IMAGE" ]]; then
    die "--binary and --image are mutually exclusive"
fi

# Check Docker is available
docker info >/dev/null 2>&1 || die "Docker is not running or not accessible"

# Determine proxy image
BUILT_LOCAL_IMAGE=false
if [[ -n "$BINARY" ]]; then
    # Build a local Docker image from the binary
    [[ -x "$BINARY" ]] || die "Binary is not executable: $BINARY"
    BINARY="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"
    PROXY_IMAGE="rl-sandbox-proxy-$$"
    log "Building local proxy image from $BINARY..."
    cp "$BINARY" "$PROJECT_DIR/redlimitador"
    docker build -t "$PROXY_IMAGE" -f "$PROJECT_DIR/Dockerfile" "$PROJECT_DIR" >/dev/null
    rm -f "$PROJECT_DIR/redlimitador"
    BUILT_LOCAL_IMAGE=true
elif [[ -z "$PROXY_IMAGE" ]]; then
    # Default to published image
    PROXY_IMAGE="ghcr.io/zyla/redlimitador:latest"
fi

# CA cert handling — when using --binary, the binary can generate certs directly
OWN_CA_DIR=false
if [[ -z "$CA_DIR" ]]; then
    CA_DIR="$(mktemp -d)"
    OWN_CA_DIR=true
    log "Generating CA certificate..."
    if [[ -n "$BINARY" ]]; then
        "$BINARY" generate-ca --out "$CA_DIR" >/dev/null
    else
        # Run generate-ca from the proxy image
        docker run --rm -v "$CA_DIR:/out" "$PROXY_IMAGE" generate-ca --out /out >/dev/null
    fi
fi
[[ -f "$CA_DIR/ca.crt" ]] || die "CA certificate not found: $CA_DIR/ca.crt"
[[ -f "$CA_DIR/ca.key" ]] || die "CA private key not found: $CA_DIR/ca.key"

# Resource names
NET_EXTERNAL="${PREFIX}-external"
NET_INTERNAL="${PREFIX}-internal"
CTR_PROXY="${PREFIX}-proxy"
CTR_SANDBOX="${PREFIX}-sandbox"

# Cleanup function
cleanup() {
    local exit_code=$?
    if [[ "$KEEP" == true ]]; then
        log "Keeping resources (--keep). Clean up manually:"
        log "  docker rm -f $CTR_SANDBOX $CTR_PROXY 2>/dev/null"
        log "  docker network rm $NET_INTERNAL $NET_EXTERNAL 2>/dev/null"
        return
    fi
    log "Cleaning up..."
    docker rm -f "$CTR_SANDBOX" >/dev/null 2>&1 || true
    docker rm -f "$CTR_PROXY" >/dev/null 2>&1 || true
    docker network rm "$NET_INTERNAL" >/dev/null 2>&1 || true
    docker network rm "$NET_EXTERNAL" >/dev/null 2>&1 || true
    if [[ "$OWN_CA_DIR" == true ]]; then
        rm -rf "$CA_DIR"
    fi
    if [[ "$BUILT_LOCAL_IMAGE" == true ]]; then
        docker rmi "$PROXY_IMAGE" >/dev/null 2>&1 || true
    fi
    exit "$exit_code"
}
trap cleanup EXIT

# Create networks
log "Creating Docker networks..."
docker network create "$NET_EXTERNAL" >/dev/null
docker network create --internal "$NET_INTERNAL" >/dev/null

# Start proxy container
log "Starting proxy container..."
docker run -d \
    --name "$CTR_PROXY" \
    --network "$NET_EXTERNAL" \
    -v "$CONFIG:/etc/redlimitador/config.toml:ro" \
    -v "$CA_DIR/ca.crt:/etc/redlimitador/ca.crt:ro" \
    -v "$CA_DIR/ca.key:/etc/redlimitador/ca.key:ro" \
    "$PROXY_IMAGE" \
    run \
        --config /etc/redlimitador/config.toml \
        --ca-cert /etc/redlimitador/ca.crt \
        --ca-key /etc/redlimitador/ca.key \
        --bind "0.0.0.0:${PROXY_PORT}" \
    >/dev/null

# Connect proxy to internal network (it's already on external)
docker network connect "$NET_INTERNAL" "$CTR_PROXY"

# Wait for proxy readiness
log "Waiting for proxy to be ready..."
SECONDS_WAITED=0
while [[ $SECONDS_WAITED -lt $READINESS_TIMEOUT ]]; do
    if docker logs "$CTR_PROXY" 2>&1 | grep -q "Proxy server listening"; then
        break
    fi
    # Check if container is still running
    if [[ "$(docker inspect -f '{{.State.Running}}' "$CTR_PROXY" 2>/dev/null)" != "true" ]]; then
        echo "Proxy container exited unexpectedly. Logs:" >&2
        docker logs "$CTR_PROXY" 2>&1 >&2
        exit 1
    fi
    sleep 1
    SECONDS_WAITED=$((SECONDS_WAITED + 1))
done

if [[ $SECONDS_WAITED -ge $READINESS_TIMEOUT ]]; then
    echo "Proxy failed to become ready within ${READINESS_TIMEOUT}s. Logs:" >&2
    docker logs "$CTR_PROXY" 2>&1 >&2
    exit 1
fi
log "Proxy is ready."

# Run sandbox container
log "Starting sandbox container..."
SANDBOX_ARGS=(
    --name "$CTR_SANDBOX"
    --network "$NET_INTERNAL"
    -e "HTTP_PROXY=http://${CTR_PROXY}:${PROXY_PORT}"
    -e "HTTPS_PROXY=http://${CTR_PROXY}:${PROXY_PORT}"
    -e "http_proxy=http://${CTR_PROXY}:${PROXY_PORT}"
    -e "https_proxy=http://${CTR_PROXY}:${PROXY_PORT}"
    -e "no_proxy="
    -e "SSL_CERT_FILE=/etc/redlimitador/ca.crt"
    -e "CURL_CA_BUNDLE=/etc/redlimitador/ca.crt"
    -e "NODE_EXTRA_CA_CERTS=/etc/redlimitador/ca.crt"
    -e "GIT_SSL_CAINFO=/etc/redlimitador/ca.crt"
    -e "REQUESTS_CA_BUNDLE=/etc/redlimitador/ca.crt"
    -v "$CA_DIR/ca.crt:/etc/redlimitador/ca.crt:ro"
)

# Add interactive flags if no command specified and stdin is a terminal
if [[ ${#COMMAND[@]} -eq 0 ]] && [[ -t 0 ]]; then
    SANDBOX_ARGS+=(-it)
fi

SANDBOX_EXIT=0
docker run "${SANDBOX_ARGS[@]}" "$IMAGE" "${COMMAND[@]+"${COMMAND[@]}"}" \
    || SANDBOX_EXIT=$?

exit "$SANDBOX_EXIT"
