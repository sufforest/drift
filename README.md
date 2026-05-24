# drift

A Go CLI for end-to-end encrypted workspaces on your own S3-compatible
bucket. Keep code, configs, and data on object storage; mount or sync
them onto your devices with cryptographic identity + short-lived
capability tokens for untrusted hosts.

drift is a thin layer over rclone's encrypted remote. rclone does the
data-plane crypto; drift adds key management, capability tokens, key
rotation, recovery, and an audit log.

**Status:** v1 alpha. Verified end-to-end against Cloudflare R2 with a
solo-dev workflow (init → mount → file round-trip through encrypted
storage). Multi-device pairing, mount-mode FUSE vols, and AWS/B2
backends exist in code but are not yet exercised against real
infrastructure. Run from source.

## When drift is for you

- You own an R2 / S3 / B2 / MinIO bucket and don't want a SaaS in front
  of it.
- You sometimes hand workspace access to machines you don't fully trust:
  rented GPUs, CI runners, contractors' laptops. drift's main job is
  letting them work for a bounded time without ever holding your
  long-term parent credential.
- You want to revoke access without re-encrypting every byte you've
  written.
- You want a paper trail of who got access to what.

## When drift is NOT for you (yet)

- Solo dev, one trusted machine, never lending the bucket to anyone —
  raw rclone is simpler and gives you the same encryption. drift's
  capability-token + revocation machinery is overhead you don't need.
- You need Windows-first support.
- You need a managed service. drift is local tooling against your own
  bucket; you operate it.
- You're on a backend other than Cloudflare R2. Code paths exist for
  MinIO/AWS/B2 but they've only been smoke-tested; the bearer-token
  flow has provider-specific quirks (see Provider Status below).

## Provider status

| Provider | Storage layer | Bearer token flow (drift grant + drift open) |
|---|---|---|
| **Cloudflare R2** | ✓ end-to-end verified | ✓ verified |
| Backblaze B2 | ✓ on the wire | ✗ — needs B2Minter (not built) |
| AWS S3 | ✓ on the wire | ✗ — needs STSMinter (not built) |
| MinIO | ✓ on the wire | partial (R2 JWT path; not native STS) |
| Wasabi / DigitalOcean Spaces / generic | ✓ on the wire | ✗ — no native scoped-credential mechanism |

Until provider-native minters land, drift on non-R2 backends works for
**primary-device direct mount** (`drift mount`), but the bearer flow
(handing tokens to GPU pods) only works on R2 today.

## Install

drift depends on `rclone` and (for mount-mode vols) macFUSE on macOS or
fuse3 on Linux. No prebuilt binaries yet — build from source:

```sh
git clone https://github.com/sufforest/drift
cd drift
make build              # produces ./drift
sudo mv drift /usr/local/bin/
```

Then either:

```sh
brew install rclone                 # macOS
brew install --cask macfuse         # macOS, ONLY if you want mount-mode vols
sudo apt install rclone fuse3       # Linux
```

Then install shell tab-completion (one-time, optional but nice):

```sh
drift completion install
```

## Setting up R2

drift's bearer-token flow is verified against Cloudflare R2. To set up:

1. **Create the bucket** in the Cloudflare R2 dashboard. Note the bucket
   name and your Cloudflare account ID (visible in the R2 overview).
2. **Create an R2 API token** scoped to that bucket:
   - Manage R2 API tokens → Create API token
   - Permissions: **Object Read & Write**
   - Specify bucket: your bucket (scoped to one bucket bounds the
     blast radius if the token leaks)
   - TTL: Forever
   - Copy the **Access Key ID** and **Secret Access Key**

For setting up drift for the first time:

```sh
export DRIFT_ACCESS_KEY_ID="<R2 access key>"
export DRIFT_SECRET_ACCESS_KEY="<R2 secret>"
export DRIFT_KEYCHAIN=1               # store keys in the OS keychain (recommended)

drift init
# walks you through provider, bucket, device name, recovery passphrase,
# and offers to create a default vol.
```

drift writes the parent credential to the OS keychain (with
`DRIFT_KEYCHAIN=1`) or to `~/.config/drift/parent.json` at chmod 0600.

After init, you don't need the env vars again on this device.

## Daily use

Direct mount (no token, no ceremony):

```sh
drift mount main --background --sync-interval 15s
ls ~/workspace/main/
echo "hello" > ~/workspace/main/test.txt
# wait ~15s; check the R2 dashboard's compartments/main/ for an encrypted blob
```

When you're done:

```sh
drift close
```

Files at `~/workspace/main/` persist; the sync just stops.

## Sharing access (bearer-token flow)

For a GPU pod, second laptop, or a coworker:

```sh
# On primary:
drift grant --scope main --mode rw --expires 12h --ssh user@gpu-pod
# This mints a token, pipes it to user@gpu-pod via SSH, and runs
# `drift open --stdin --background` on the remote. The token never
# touches your clipboard, shell history, or argv on either side.

# Revoke anytime:
drift revoke <tid>
```

If you can't SSH to the target, fall back to copying the token via file:

```sh
drift grant --scope main --mode rw --expires 12h --out ~/.tok
scp ~/.tok target:~/incoming-token
ssh target 'drift open --token-file ~/incoming-token --background && shred -u ~/incoming-token'
```

## Recovery

drift's recovery passphrase wraps your master key into the bucket. If
you lose your only device, you can restore on a new one:

```sh
drift recover \
    --bucket <name> \
    --endpoint https://<account-id>.r2.cloudflarestorage.com \
    --provider r2
# prompts for passphrase + R2 credentials
```

Verify the passphrase periodically (no state changes):

```sh
drift recovery test
```

Rotate the passphrase:

```sh
drift recovery rekey
```

## Multi-device caveat

`drift link` exists and pairs a second device with master-signed
enrollment, but in v1 the secondary device has **identity only** — it
can:

- Verify its own enrollment in the manifest
- Decrypt vols sealed for it
- Receive bearer tokens from the primary via `drift open`

It cannot independently:

- Talk to S3 (no parent credential — would need its own R2 API token)
- Mint new tokens (`drift grant` requires parent cred)
- Rotate the master key (no master signing key)

So for now, "second device" means "long-term bearer of tokens issued by
primary." First-class peer secondaries (each with their own R2 token)
are on the v1.5 roadmap.

## Commands

```
init             Create a workspace on an S3-compatible bucket
mount            Mount/sync vols directly (primary device only)
open             Redeem a capability token and mount (bearer flow)
close            Stop a background session
status           Workspace state: device, vols, tokens, session, audit
doctor           Diagnose environment + workspace state
grant            Issue a scoped bearer token (with optional --ssh delivery)
revoke           Revoke a specific token
inspect          Decode + verify a capability or pairing token
verify           Manifest signature + provider capability check
audit            Show signed control-plane events
vol              create / list / delete vols
device           list / revoke / rename enrolled devices
tokens           List tokens by state (active / revoked / expired)
link             Pair another device (multi-device caveat above)
rotate           compartment / cprk / master key rotation
recover          Restore from passphrase on a fresh machine
recovery         rekey / disable / status / test
gc               Sweep orphaned chunks and audit entries
workspace        Multi-workspace UX
autostart        Install login-time auto-mount service
config           set-parent (rotate the stored S3 credential)
completion       install / generate shell tab-completion
restore-master   Restore a rotated-out master.json backup
keychain         Show OS keychain status
```

Every command has `--help` with detailed flags and behavior notes.

## Security model

| Layer | Defense |
|---|---|
| At rest | rclone crypt (XChaCha20-Poly1305) per vol — drift doesn't touch chunks |
| In flight | scoped S3 credentials + TLS; tokens are master-signed and verified offline before any network call |
| Trust root | TOFU on first contact; pinned master fingerprint thereafter |
| Master rotation | Doubly-signed announcement chain that pinned devices walk forward |
| Path scoping | Bearers limited to specific vols by JWT prefix/objectPath claims, enforced by R2 |
| Bucket scoping | R2 API token scoped to one bucket — leaking it doesn't expose other buckets |

What drift does NOT defend against:

- Compromise of the primary device's master key
- An attacker with bucket admin + your recovery passphrase
- Forward secrecy against future master compromise (rotate if you suspect)
- Re-encrypting historical chunks after a vol-key rotation. The old key
  still reads pre-rotation chunks until you `drift rotate compartment
  --reencrypt` (not yet implemented; on roadmap)

## R2-specific notes

These came out of end-to-end testing on R2. Useful to know:

- **The `actions` JWT claim doesn't work in local-sign temp credentials**
  despite the docs saying it does. drift's minter omits it; scope alone
  governs which operations a bearer can perform. The bearer's path
  scoping is enforced via R2's own `prefixPaths`/`objectPaths` claims,
  which DO work.
- **Object Read & Write tokens work** for local-sign temp credentials.
  You don't need Admin scope (which would be account-wide and thus
  expose other buckets).
- **`drift open` requires** that drift's S3 client config sets
  `no_check_bucket=true` and that the bearer cred grants HEAD on
  `compartments/<vol>` (without trailing slash, for rclone's init
  probe) — drift does both automatically.

The full investigation that produced these notes is at
`dist/R2-DEBUG-LOG.md`.

## Development

```sh
make build         # build the drift binary
make test          # unit tests
make test-integration   # spin up MinIO + run integration tests
make lint          # golangci-lint
make man           # generate man pages
```

## License

TBD.
