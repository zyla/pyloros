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
  --binary PATH    Path to redlimitador binary (auto-detected from target/)
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
  # Interactive shell with proxy-only access
  scripts/docker-sandbox.sh --config config.toml alpine:latest sh

  # Run a specific command
  scripts/docker-sandbox.sh --config config.toml python:3.12 pip install requests
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

# Check Docker is available
docker info >/dev/null 2>&1 || die "Docker is not running or not accessible"

# Auto-detect binary
if [[ -z "$BINARY" ]]; then
    if [[ -x "$PROJECT_DIR/target/x86_64-unknown-linux-musl/release/redlimitador" ]]; then
        BINARY="$PROJECT_DIR/target/x86_64-unknown-linux-musl/release/redlimitador"
    elif [[ -x "$PROJECT_DIR/target/release/redlimitador" ]]; then
        BINARY="$PROJECT_DIR/target/release/redlimitador"
        echo "Warning: Using glibc binary ($BINARY)." >&2
        echo "  This may not work in all containers. For best compatibility," >&2
        echo "  build with: cargo build --release --target x86_64-unknown-linux-musl" >&2
    else
        die "Cannot find redlimitador binary. Build with 'cargo build --release' or specify --binary"
    fi
fi
[[ -x "$BINARY" ]] || die "Binary is not executable: $BINARY"
BINARY="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"

# CA cert handling
OWN_CA_DIR=false
if [[ -z "$CA_DIR" ]]; then
    CA_DIR="$(mktemp -d)"
    OWN_CA_DIR=true
    log "Generating CA certificate..."
    "$BINARY" generate-ca --out "$CA_DIR" >/dev/null
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
    -v "$BINARY:/usr/local/bin/redlimitador:ro" \
    -v "$CONFIG:/etc/redlimitador/config.toml:ro" \
    -v "$CA_DIR/ca.crt:/etc/redlimitador/ca.crt:ro" \
    -v "$CA_DIR/ca.key:/etc/redlimitador/ca.key:ro" \
    ubuntu:24.04 \
    /usr/local/bin/redlimitador run \
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
