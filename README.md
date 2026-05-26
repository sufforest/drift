# drift

End-to-end encrypted workspaces backed by an S3-compatible bucket.
A Go CLI that handles key management, multi-device pairing, scoped
capability tokens, and key rotation; rclone's encrypted remote does
the data-plane crypto underneath.

## Status

v1 alpha. Tested against Cloudflare R2. Code paths exist for AWS S3,
Backblaze B2, MinIO; the bearer-token flow is R2-specific until
provider-native minters land (see Provider compatibility below).

What's exercised end-to-end on R2:
- `init` → `mount` round-trip through encrypted storage
- Multi-device pairing with transcript-bound SAS verification
- Two peer modes: full (raw parent cred) and bearer (24h revocable
  split-cred, R2-enforced RO on the control plane)
- Per-device per-vol compartment scope
- Master and CPRK rotation
- Recovery from passphrase

## Provider compatibility

| Provider | Storage layer | Bearer-token flow |
|---|---|---|
| Cloudflare R2 | tested | tested |
| Backblaze B2 | code path only | needs B2Minter (unbuilt) |
| AWS S3 | code path only | needs STSMinter (unbuilt) |
| MinIO | code path only | partial via R2 JWT minter |
| Wasabi / DO Spaces / generic | code path only | no scoped-cred mechanism |

On non-R2 backends `drift mount` from a device that holds the parent
cred works; bearer-token flows do not.

## Install

drift requires `rclone` and (for mount-mode vols) macFUSE on macOS or
fuse3 on Linux.

Prebuilt binaries are attached to each release on the [releases
page](https://github.com/sufforest/drift/releases). For the current
alpha (`v0.1.0-alpha.1`):

```sh
# macOS arm64 (Apple Silicon)
curl -sSL https://github.com/sufforest/drift/releases/download/v0.1.0-alpha.1/drift_0.1.0-alpha.1_macos_arm64.tar.gz \
  | tar -xz -C /tmp drift && sudo mv /tmp/drift /usr/local/bin/

# Linux x86_64
curl -sSL https://github.com/sufforest/drift/releases/download/v0.1.0-alpha.1/drift_0.1.0-alpha.1_linux_x86_64.tar.gz \
  | tar -xz -C /tmp drift && sudo mv /tmp/drift /usr/local/bin/
```

`linux_arm64` and `macos_x86_64` archives are also published. Verify
the download against `checksums.txt` on the same release page if you
care about supply-chain integrity.

Or build from source:

```sh
git clone https://github.com/sufforest/drift
cd drift
make build              # produces ./drift
sudo mv drift /usr/local/bin/
```

System dependencies:

```sh
# rclone — use the upstream installer on macOS; Homebrew's rclone is
# built without FUSE mount support, which breaks drift mount.
curl https://rclone.org/install.sh | sudo bash       # macOS or Linux
sudo apt install fuse3                               # Linux, only for mount-mode vols
brew install --cask macfuse                          # macOS, only for mount-mode vols
```

Optional shell tab-completion:

```sh
drift completion install
```

## R2 setup

1. Create the bucket in the Cloudflare R2 dashboard. Note the bucket
   name and Cloudflare account ID.
2. Create an R2 API token scoped to the bucket. Permissions: **Object
   Read & Write**. Scope: the single bucket. Copy the Access Key ID
   and Secret Access Key.

Initialize:

```sh
export DRIFT_ACCESS_KEY_ID="<R2 access key>"
export DRIFT_SECRET_ACCESS_KEY="<R2 secret>"
export DRIFT_KEYCHAIN=1               # store keys in the OS keychain

drift init
```

`drift init` prompts for provider, bucket, device name, recovery
passphrase, and offers to create an initial vol. The parent
credential goes to the OS keychain when `DRIFT_KEYCHAIN=1`, otherwise
to `~/.config/drift/parent.json` at chmod 0600.

## Mount

```sh
drift mount main --background --sync-interval 15s
ls ~/workspace/main/
echo "hello" > ~/workspace/main/test.txt
drift close                 # stop the session; files at the mountpoint persist
```

## Bearer tokens

Single-use scoped credentials for hosts that should not hold the
parent cred.

```sh
# Primary mints + delivers via SSH (token never lands in shell history)
drift grant --scope main --mode rw --expires 12h --ssh user@host

# Or via file
drift grant --scope main --mode rw --expires 12h --out ~/.tok
scp ~/.tok host:~/incoming
ssh host 'drift open --token-file ~/incoming --background && shred -u ~/incoming'

drift revoke <tid>           # invalidate at the workspace level
```

## Multi-device pairing

`drift link` runs a bucket-mediated handshake with transcript-bound
SAS verification. Three target modes:

**Identity-only.** Secondary holds an Ed25519 device identity in the
manifest. No R2 cred. Workspace access requires a bearer token from
the primary via `drift grant`.

**Full peer (`--peer`).** Secondary holds a copy of the parent R2
credential. Can run `drift mount`, `drift grant`, and other data-plane
operations independently. Not revocable workspace-side: if the device
is compromised, the parent R2 token must also be rotated in the
Cloudflare dashboard.

**Bearer peer (`--peer-bearer`).** Secondary holds a 24h-TTL bearer
credential signed by the workspace master. Can `drift mount`; cannot
`drift grant`. The cred has two parts: RW on `compartments/<vol>/*`
and RO on workspace control-plane paths (manifest, revocations,
refresh blob). R2 enforces the read-only boundary. Revocable
workspace-side via `drift peer revoke <peer-id>`. Requires
`--peer-compartments`.

### Pairing flow

```sh
# On primary
drift link --new-device "<label>" --peer
# emits driftpair1.<base58> — copy to the new device

# On secondary
drift link "driftpair1.…"
# verifies the master signature, posts a response, displays an
# 8-hex-char SAS (e.g. AB12-CD34), blocks waiting for confirm

# On primary
drift link --confirm <pid>
# displays the same SAS, prompts y/N; visual comparison defeats
# side-channel MITM of the pairing token
```

The SAS is `H(masterPub ‖ pid ‖ secondary.signPub ‖ secondary.boxPub ‖
challenge)` truncated to 32 bits. Substituting any field changes the
SAS. For non-interactive automation: `--accept-sas AB12-CD34`.

### Capability matrix

| Operation | Primary | `--peer` | `--peer-bearer` | Identity-only |
|---|---|---|---|---|
| Mount vols | ✓ | ✓ (scope) | ✓ (scope) | via `drift open` |
| `drift grant` | ✓ | ✓ (scope) | ✗ | ✗ |
| Redeem bearer | ✓ | ✓ | ✓ | ✓ |
| Vol create/delete | ✓ | ✗ | ✗ | ✗ |
| `drift link --new-device` | ✓ | ✗ | ✗ | ✗ |
| Rotate CPRK / master | ✓ | ✗ | ✗ | ✗ |
| Recovery | ✓ | ✗ | ✗ | ✗ |
| Workspace-side revoke | n/a | + CF dashboard | `drift peer revoke` | `drift token revoke` |

### Compartment scope

Restrict a peer to a subset of vols at pairing time:

```sh
drift link --new-device "<label>" --peer-bearer --peer-compartments code
drift vol grant <peer-id> docs     # extend post-pairing
drift vol ungrant <peer-id> docs   # narrow + rotate the vol's CK
```

### Bearer peer day-to-day

```sh
drift --config <state-dir> peer status
drift --config <state-dir> mount code --background
# Near expiry:
#   on primary: drift peer refresh <peer-id>
#   on peer:    drift peer refresh
```

## Recovery

`drift init` writes a passphrase-wrapped copy of the master key to the
bucket. Restoring on a fresh machine:

```sh
drift recover \
    --bucket <name> \
    --endpoint https://<account-id>.r2.cloudflarestorage.com \
    --provider r2
```

Verify the passphrase periodically without state changes:

```sh
drift recovery test
```

Rotate the passphrase:

```sh
drift recovery rekey
```

## Incident response

The procedure depends on what kind of cred was on the compromised
device.

**Bearer peer (`--peer-bearer`).** Workspace-side only:

```sh
drift peer revoke <peer-id>
```

Next mount on the peer is refused via the manifest gate; running
mounts notice within ~15s via the revocations poller. The R2-side
JWT expires within 24h. For absolute cutoff against R2 before
expiry, optionally rotate the R2 token (`drift parent set` after a
dashboard rotation).

Vol-specific narrowing if only some compartments leaked:

```sh
drift vol ungrant <peer-id> <vol>
```

**Full peer (`--peer`).** The device holds the parent R2 cred, so
workspace-side revoke alone leaves the attacker with usable R2
access until the parent token is also rotated:

```sh
# 1. CF dashboard: revoke + re-mint the R2 token (same Object R/W scope)
# 2. Update drift to the new cred
export DRIFT_ACCESS_KEY_ID=<new-ak>
export DRIFT_SECRET_ACCESS_KEY=<new-sk>
drift parent set
# 3. Workspace-side
drift device revoke <peer-id>
drift rotate cprk
```

drift does not manage the account-level R2 token; step 1 is operator-
driven.

## Commands

```
init             Create a workspace on an S3-compatible bucket
mount            Mount/sync vols directly (primary, full peer, bearer peer)
open             Redeem a capability token and mount
close            Stop a background session
status           Workspace state: device, vols, tokens, session, audit
doctor           Diagnose environment + workspace state
grant            Issue a scoped bearer token (with optional --ssh delivery)
revoke           Revoke a bearer token
inspect          Decode + verify a capability or pairing token
verify           Manifest signature + provider capability check
audit            Show signed control-plane events
vol              create / list / delete / grant / ungrant vols
device           list / rename / revoke enrolled devices
tokens           List tokens by state
link             Pair another device (--peer, --peer-bearer,
                 --peer-compartments)
peer             revoke / refresh / list / status for bearer-mode peers
rotate           compartment / cprk / master key rotation
parent           set / show the stored parent S3 credential
recover          Restore from passphrase on a fresh machine
recovery         rekey / disable / status / test
gc               Sweep orphaned chunks and audit entries
workspace        Multi-workspace management
autostart        Install login-time auto-mount service
completion       Install / generate shell tab-completion
restore-master   Restore a rotated-out master.json backup
keychain         Show OS keychain status
```

Each command has `--help` with flags and behavior.

## Security model

| Layer | Mechanism |
|---|---|
| Data at rest | rclone crypt (XChaCha20-Poly1305) per vol |
| In flight | Scoped S3 credentials over TLS; bearer tokens verified offline before any network call |
| Trust root | Master fingerprint pinned on every device at pairing time; manifest enrollments chain to it |
| Pairing handshake | Transcript-bound SAS, master-signed pairing token, sealed-box handoff |
| Master rotation | Doubly-signed (old + new) announcement chain; pinned devices walk forward |
| Path scoping (token) | JWT `prefixPaths` / `objectPaths` claims enforced by R2 |
| Per-device scoping | `Device.CompartmentScope` in manifest; vol CKs not sealed for out-of-scope devices |
| Bearer peer split cred | Two R2 creds per PeerCred: RW on data, RO on control plane. R2 enforces. |
| Bearer peer revocation | Manifest gate (`drift peer revoke`) + JWT auto-expiry within 24h |
| Bucket scoping | R2 token bound to one bucket |

Out of scope:
- Compromise of the primary's master signing key
- Adversary holding both bucket bytes and the recovery passphrase
- Forward secrecy against future master compromise (rotate to recover)
- Re-encryption of historical chunks after a vol-key rotation
  (pre-rotation reads remain possible with the old CK until
  `drift rotate compartment --reencrypt` lands)

## R2 implementation notes

Empirical contracts that took non-trivial debugging to discover.
Pinned by guardrail tests under `internal/credentials/`,
`internal/mount/`, `internal/token/`.

- The `actions` claim is rejected by R2's local-sign JWT validator,
  despite the documentation. drift's minter omits it; scope alone
  (`object-read-only` / `object-read-write`) plus `prefixPaths` /
  `objectPaths` controls access.
- Object Read & Write at the R2 API token level is sufficient.
  Admin scope (account-wide) is not required and is not recommended
  because it expands blast radius across buckets.
- `drift open` requires `no_check_bucket=true` on the rclone S3
  backend and a HEAD-able `compartments/<vol>` (without trailing
  slash) for rclone's init probe. drift sets both automatically.

## Development

```sh
make build              # build the drift binary
make test               # unit tests
make test-integration   # spin up MinIO + run integration tests
make lint               # golangci-lint
make man                # generate man pages
```

## License

Apache 2.0. See `LICENSE`.
