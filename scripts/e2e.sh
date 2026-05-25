#!/usr/bin/env bash
#
# scripts/e2e.sh — end-to-end smoke test for drift.
#
# Scope:
#   - drift init against MinIO
#   - drift vol create / list
#   - drift status
#   - drift doctor
#   - drift grant + drift token revoke
#   - drift recovery test (no state change)
#   - teardown
#
# What this script does NOT cover (covered by other tests):
#   - drift link / peer pairing — uses R2-local-sign JWTs that MinIO
#     doesn't validate. Tested by in-memory unit tests + manual R2.
#   - drift mount FUSE — environment-dependent (macFUSE / fuse3 +
#     kernel access). Tested manually.
#   - drift open bearer redeem — same local-sign-JWT issue as link.
#
# This script doubles as live documentation: the exact sequence below
# is what an operator runs to verify drift builds + boots + writes its
# control plane correctly.
#
# Requirements:
#   - bash, docker (for MinIO via test/docker-compose.yaml), curl
#
# Usage:
#   make e2e              # preferred — wraps with start/stop MinIO
#   bash scripts/e2e.sh   # direct invocation (MinIO must already be up)

set -euo pipefail

# ───────── config ─────────

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/drift"
CFG="/tmp/drift-e2e"

MINIO_ENDPOINT="http://127.0.0.1:9000"
MINIO_BUCKET="drift-e2e"
MINIO_AK="drift-test"
MINIO_SK="drift-test-secret"

PASSPHRASE="e2e-test-passphrase-not-secret-do-not-use-in-prod"

# ───────── helpers ─────────

log() { printf '\033[1;34m[e2e]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[e2e FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }

cleanup() {
    log "cleanup"
    "$BIN" --config "$CFG" close >/dev/null 2>&1 || true
    rm -rf "$CFG"
    # MinIO lifecycle is the caller's responsibility (see Makefile).
}
trap cleanup EXIT

require_tools() {
    need bash; need docker; need curl
}

wait_for_minio() {
    log "waiting for MinIO at $MINIO_ENDPOINT"
    for _ in $(seq 1 30); do
        if curl -fsS "$MINIO_ENDPOINT/minio/health/live" >/dev/null 2>&1; then
            log "MinIO is up"
            return 0
        fi
        sleep 1
    done
    die "MinIO did not become ready in 30s — run 'make docker-up' first"
}

ensure_bucket() {
    # Bucket creation via mc, fetched once to /tmp so the script
    # doesn't pollute the host PATH.
    local mc=/tmp/drift-e2e-mc
    if [[ ! -x $mc ]]; then
        log "fetching mc"
        local arch
        arch=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
        case "$(uname)" in
            Darwin) curl -fsSL -o "$mc" "https://dl.min.io/client/mc/release/darwin-$arch/mc" ;;
            Linux)  curl -fsSL -o "$mc" "https://dl.min.io/client/mc/release/linux-$arch/mc" ;;
            *) die "unsupported OS for mc download" ;;
        esac
        chmod +x "$mc"
    fi
    "$mc" alias set local "$MINIO_ENDPOINT" "$MINIO_AK" "$MINIO_SK" >/dev/null
    "$mc" mb "local/$MINIO_BUCKET" 2>/dev/null || true
    # Wipe previous-run state so init can claim a fresh manifest.
    # The bucket itself is preserved; only the objects go.
    "$mc" rm --recursive --force "local/$MINIO_BUCKET" >/dev/null 2>&1 || true
    log "bucket $MINIO_BUCKET ready (cleaned)"
}

build_drift() {
    log "building drift"
    (cd "$ROOT" && go build -o drift ./cmd/drift/) || die "build failed"
    log "drift: $("$BIN" --version)"
}

# ───────── steps ─────────

step_init() {
    log "step 1/7: init workspace against MinIO"
    rm -rf "$CFG"
    DRIFT_ACCESS_KEY_ID="$MINIO_AK" \
    DRIFT_SECRET_ACCESS_KEY="$MINIO_SK" \
    "$BIN" --config "$CFG" init \
        --bucket "$MINIO_BUCKET" \
        --endpoint "$MINIO_ENDPOINT" \
        --provider minio \
        --device-name "e2e-device" \
        --recovery-passphrase "$PASSPHRASE" \
        --allow-weak-passphrase \
        --quiet \
        > /tmp/drift-e2e-init.log 2>&1 \
        || die "init failed; see /tmp/drift-e2e-init.log"
}

step_vol_create() {
    log "step 2/7: create vol 'demo' in sync mode + verify list"
    "$BIN" --config "$CFG" vol create demo --mode sync \
        > /tmp/drift-e2e-vol-create.log 2>&1 \
        || die "vol create failed; see /tmp/drift-e2e-vol-create.log"
    local out
    out=$("$BIN" --config "$CFG" vol list 2>&1)
    grep -q '^demo' <<<"$out" || die "vol list didn't show 'demo'; got:\n$out"
}

step_status() {
    log "step 3/7: status reflects the workspace state"
    local out
    out=$("$BIN" --config "$CFG" status 2>&1)
    grep -q "Workspace " <<<"$out"        || die "status missing Workspace header"
    grep -q "demo " <<<"$out"             || die "status missing the 'demo' vol"
    # Fix #1 from this pre-tag cycle: empty session row mentions both
    # mount and open. Assert that string is present.
    grep -q "drift mount --background" <<<"$out" \
        || die "status's empty-session row should mention drift mount --background (pre-tag fix #1 regression?)"
}

step_doctor() {
    log "step 4/7: doctor probes environment + workspace"
    local out
    # doctor exits non-zero if any check fails; some checks (macFUSE)
    # legitimately fail on Linux. Capture output and accept any exit.
    out=$("$BIN" --config "$CFG" doctor 2>&1 || true)
    grep -q "rclone" <<<"$out"   || die "doctor didn't run the rclone probe"
    # Fix #3 from this pre-tag cycle: rclone mount support row is
    # produced when rclone is on PATH. Assert it appears.
    if command -v rclone >/dev/null 2>&1; then
        grep -q "rclone mount support" <<<"$out" \
            || die "doctor missing 'rclone mount support' row (pre-tag fix #3 regression?)"
    fi
}

step_grant_revoke() {
    log "step 5/7: mint a bearer token + revoke it"
    local tok_out
    tok_out=$("$BIN" --config "$CFG" grant --scope demo --mode rw --expires 1h --token-only 2>&1) \
        || die "grant failed: $tok_out"
    # The token line starts with "drifttoken1.". Parse the tid for
    # revocation (we don't actually use the token here — bearer
    # redeem against MinIO has the same R2-JWT problem as pairing).
    local list
    list=$("$BIN" --config "$CFG" tokens --all 2>&1)
    local tid
    tid=$(grep -oE 'tok_[a-f0-9]+' <<<"$list" | head -1)
    [[ -z $tid ]] && die "tokens --all returned no tid"
    "$BIN" --config "$CFG" revoke "$tid" > /tmp/drift-e2e-revoke.log 2>&1 \
        || die "revoke failed; see /tmp/drift-e2e-revoke.log"
    # Confirm revoked in subsequent listing.
    local after
    after=$("$BIN" --config "$CFG" tokens --all 2>&1)
    grep -q "revoked" <<<"$after" \
        || die "tokens --all should show 'revoked' after drift revoke"
}

step_recovery_test() {
    log "step 6/7: recovery test (verifies passphrase, no state change)"
    "$BIN" --config "$CFG" recovery test --passphrase "$PASSPHRASE" \
        > /tmp/drift-e2e-recovery.log 2>&1 \
        || die "recovery test failed; see /tmp/drift-e2e-recovery.log"
}

step_inspect_audit() {
    log "step 7/7: audit log has the init + vol create entries"
    local out
    out=$("$BIN" --config "$CFG" audit list 2>&1) || die "audit list failed:\n$out"
    grep -q "workspace.init" <<<"$out" \
        || die "audit log missing workspace.init entry"
    grep -q "compartment.create" <<<"$out" \
        || die "audit log missing compartment.create entry"
}

# ───────── main ─────────

require_tools
wait_for_minio
ensure_bucket
build_drift

step_init
step_vol_create
step_status
step_doctor
step_grant_revoke
step_recovery_test
step_inspect_audit

log "all e2e steps passed"
