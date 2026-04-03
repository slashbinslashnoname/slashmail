#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# E2E smoke test for slashmail
#
# Starts two daemon processes on localhost, sends a tagged message from A→B,
# then verifies that `list --tag` and `search` on B return expected results.
# Exits non-zero on any failure.
#
# Requirements:
#   - cargo (builds the binary)
#   - python3 with the `cryptography` package (generates Ed25519 keypairs)
#   - jq (optional, falls back to python3 for JSON parsing)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Colours (disabled when not a TTY) ───────────────────────────────────────
if [ -t 1 ]; then
    GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; NC='\033[0m'
else
    GREEN=''; RED=''; YELLOW=''; NC=''
fi

pass() { printf "${GREEN}PASS${NC} %s\n" "$1"; }
fail() { printf "${RED}FAIL${NC} %s\n" "$1"; exit 1; }
info() { printf "${YELLOW}==>>${NC} %s\n" "$1"; }

# ── Preflight checks ───────────────────────────────────────────────────────
check_python_crypto() {
    python3 -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey" 2>/dev/null \
        || { echo "ERROR: python3 'cryptography' package required. Install with: pip3 install cryptography"; exit 1; }
}

check_python_crypto

# ── JSON field extractor (prefers jq, falls back to python3) ───────────────
json_get() {
    local json="$1" path="$2"
    if command -v jq &>/dev/null; then
        echo "$json" | jq -r "$path"
    else
        # Python fallback: evaluate the path as Python subscript syntax.
        echo "$json" | python3 -c "
import sys, json, re
data = json.load(sys.stdin)
# Convert jq-like path to python: .data.foo[0].bar -> ['data']['foo'][0]['bar']
path = sys.argv[1]
keys = re.findall(r'\[(\d+)\]|\.([^.\[]+)', path)
result = data
for idx, key in keys:
    result = result[int(idx)] if idx else result[key]
print(result if not isinstance(result, list) else json.dumps(result))
" "$path"
    fi
}

# ── Build ──────────────────────────────────────────────────────────────────
info "Building slashmail..."
cargo build --manifest-path "$PROJECT_DIR/Cargo.toml" 2>&1 | tail -1
BIN="$PROJECT_DIR/target/debug/slashmail"
[ -x "$BIN" ] || fail "binary not found at $BIN"

# ── Temp directories for two isolated daemon homes ─────────────────────────
TMPA=$(mktemp -d "${TMPDIR:-/tmp}/slashmail_e2e_A.XXXXXX")
TMPB=$(mktemp -d "${TMPDIR:-/tmp}/slashmail_e2e_B.XXXXXX")
DAEMON_A_PID=""
DAEMON_B_PID=""

cleanup() {
    local exit_code=$?
    # Dump daemon logs on failure for debugging.
    if [ "$exit_code" -ne 0 ]; then
        echo "--- Daemon A log ---"
        cat "$TMPA/daemon.log" 2>/dev/null | tail -30 || true
        echo "--- Daemon B log ---"
        cat "$TMPB/daemon.log" 2>/dev/null | tail -30 || true
        echo "--------------------"
    fi
    [ -n "$DAEMON_A_PID" ] && kill "$DAEMON_A_PID" 2>/dev/null && wait "$DAEMON_A_PID" 2>/dev/null || true
    [ -n "$DAEMON_B_PID" ] && kill "$DAEMON_B_PID" 2>/dev/null && wait "$DAEMON_B_PID" 2>/dev/null || true
    rm -rf "$TMPA" "$TMPB"
}
trap cleanup EXIT

# ── Generate Ed25519 keypair (returns: secret_b64 pubkey_b64) ──────────────
generate_keypair() {
    python3 -c "
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
key = Ed25519PrivateKey.generate()
seed = key.private_bytes_raw()
pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
print(base64.b64encode(seed).decode(), base64.b64encode(pub).decode())
"
}

# ── Setup an identity directory ────────────────────────────────────────────
# Writes config.toml directly and uses SLASHMAIL_KEY env var (avoids keyring).
setup_identity() {
    local home_dir="$1"
    local pair secret_b64 pubkey_b64
    pair=$(generate_keypair)
    secret_b64="${pair%% *}"
    pubkey_b64="${pair##* }"

    mkdir -p "$home_dir/.slashmail"
    cat > "$home_dir/.slashmail/config.toml" <<EOF
public_key = "$pubkey_b64"
listen_addr = "/ip4/0.0.0.0/tcp/0"
mdns_enabled = false
EOF
    echo "$secret_b64 $pubkey_b64"
}

# ── Run slashmail with a specific identity ─────────────────────────────────
slashmail_a() { HOME="$TMPA" SLASHMAIL_KEY="$KEY_A" RUST_LOG=error "$BIN" "$@" 2>/dev/null; }
slashmail_b() { HOME="$TMPB" SLASHMAIL_KEY="$KEY_B" RUST_LOG=error "$BIN" "$@" 2>/dev/null; }

# ── Setup identities ──────────────────────────────────────────────────────
info "Generating identities..."
KEYS_A=$(setup_identity "$TMPA")
KEY_A="${KEYS_A%% *}"
PUB_A="${KEYS_A##* }"

KEYS_B=$(setup_identity "$TMPB")
KEY_B="${KEYS_B%% *}"
PUB_B="${KEYS_B##* }"

info "Peer A pubkey: ${PUB_A:0:16}..."
info "Peer B pubkey: ${PUB_B:0:16}..."

# ── Start daemons ─────────────────────────────────────────────────────────
LOG_A="$TMPA/daemon.log"
LOG_B="$TMPB/daemon.log"

# Start daemons directly (not via slashmail_a/b which suppress stderr).
info "Starting daemon A..."
HOME="$TMPA" SLASHMAIL_KEY="$KEY_A" "$BIN" daemon start --listen /ip4/127.0.0.1/tcp/0 >"$LOG_A" 2>&1 &
DAEMON_A_PID=$!

info "Starting daemon B..."
HOME="$TMPB" SLASHMAIL_KEY="$KEY_B" "$BIN" daemon start --listen /ip4/127.0.0.1/tcp/0 >"$LOG_B" 2>&1 &
DAEMON_B_PID=$!

# ── Wait for daemons to be ready ──────────────────────────────────────────
wait_for_daemon() {
    local label="$1"
    shift
    for _ in $(seq 1 30); do
        if output=$("$@" --json status 2>/dev/null); then
            running=$(json_get "$output" ".data.daemon.running" 2>/dev/null || echo "false")
            if [ "$running" = "true" ]; then
                info "$label is ready."
                return 0
            fi
        fi
        sleep 0.5
    done
    fail "$label did not start within 15 seconds"
}

wait_for_daemon "Daemon A" slashmail_a
wait_for_daemon "Daemon B" slashmail_b

# ── Get daemon A's listen address and peer ID ─────────────────────────────
STATUS_A=$(slashmail_a --json status)
PEER_ID_A=$(json_get "$STATUS_A" ".data.peer_id")
# Extract the 127.0.0.1 TCP listen address from the array.
LISTEN_ADDR_A=$(echo "$STATUS_A" | python3 -c "
import sys, json
addrs = json.load(sys.stdin)['data']['daemon']['listen_addrs']
for a in addrs:
    if '127.0.0.1' in a and '/tcp/' in a:
        print(a)
        break
else:
    print('NONE')
")
[ "$LISTEN_ADDR_A" != "NONE" ] || fail "daemon A has no 127.0.0.1 TCP listen address"

info "Daemon A: peer=$PEER_ID_A addr=$LISTEN_ADDR_A"

# ── Connect B → A ─────────────────────────────────────────────────────────
DIAL_ADDR="${LISTEN_ADDR_A}/p2p/${PEER_ID_A}"
info "Connecting B → A at $DIAL_ADDR"
slashmail_b add-peer "$DIAL_ADDR" >/dev/null

# Wait for the connection to establish and request-response protocol to negotiate.
sleep 3

# ── Send a tagged message from A → B ─────────────────────────────────────
TAG="smoke-e2e-$$"
BODY="Hello from the E2E smoke test tag=${TAG}"

info "Sending message from A → B  tag=$TAG"
SEND_OUTPUT=$(slashmail_a --json send --to "$PUB_B" --body "$BODY" --tags "$TAG")
SEND_OK=$(json_get "$SEND_OUTPUT" ".ok")
[ "$SEND_OK" = "true" ] || fail "send command failed: $SEND_OUTPUT"
MSG_ID=$(json_get "$SEND_OUTPUT" ".data.message_id")
info "Message sent: id=$MSG_ID"

# Wait for message delivery via request-response.
sleep 2

# ── Verify: list --tag on B ──────────────────────────────────────────────
info "Verifying list --tag $TAG on B..."
LIST_OUTPUT=$(slashmail_b --json list --tag "$TAG")
LIST_OK=$(json_get "$LIST_OUTPUT" ".ok")
LIST_COUNT=$(json_get "$LIST_OUTPUT" ".data.count")

[ "$LIST_OK" = "true" ] || fail "list --tag failed: $LIST_OUTPUT"
[ "$LIST_COUNT" -ge 1 ] 2>/dev/null || fail "list --tag returned count=$LIST_COUNT, expected >= 1. Output: $LIST_OUTPUT"

# Verify the message body contains our unique tag marker.
LIST_BODY=$(json_get "$LIST_OUTPUT" ".data.messages[0].body")
echo "$LIST_BODY" | grep -q "$TAG" || fail "list --tag message body does not contain tag marker. body=$LIST_BODY"

pass "list --tag  (count=$LIST_COUNT)"

# ── Verify: search on B ──────────────────────────────────────────────────
info "Verifying search 'smoke' on B..."
SEARCH_OUTPUT=$(slashmail_b --json search "smoke")
SEARCH_OK=$(json_get "$SEARCH_OUTPUT" ".ok")
SEARCH_COUNT=$(json_get "$SEARCH_OUTPUT" ".data.count")

[ "$SEARCH_OK" = "true" ] || fail "search failed: $SEARCH_OUTPUT"
[ "$SEARCH_COUNT" -ge 1 ] 2>/dev/null || fail "search returned count=$SEARCH_COUNT, expected >= 1. Output: $SEARCH_OUTPUT"

pass "search     (count=$SEARCH_COUNT)"

# ── Verify: message tags are correctly decrypted on B ─────────────────────
info "Verifying decrypted tags on B..."
FIRST_MSG_TAGS=$(json_get "$LIST_OUTPUT" ".data.messages[0].tags")
echo "$FIRST_MSG_TAGS" | grep -q "$TAG" || fail "tags on B do not contain '$TAG'. tags=$FIRST_MSG_TAGS"

pass "tag decrypt"

# ── Verify: sender's Sent folder ─────────────────────────────────────────
info "Verifying sender's list --tag on A..."
SENT_OUTPUT=$(slashmail_a --json list --tag "$TAG")
SENT_COUNT=$(json_get "$SENT_OUTPUT" ".data.count")
[ "$SENT_COUNT" -ge 1 ] 2>/dev/null || fail "sender list --tag returned count=$SENT_COUNT, expected >= 1 (Sent folder)"

pass "sent folder (count=$SENT_COUNT)"

# ── Summary ───────────────────────────────────────────────────────────────
echo ""
printf "${GREEN}All E2E smoke tests passed!${NC}\n"
