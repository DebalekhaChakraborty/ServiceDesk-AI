# dograh_voice

Dograh voice-channel integration with ServiceDesk AI.

This is the module's single reference document. It covers what exists, how to
operate it, and the decisions that are expensive to rediscover. Two sub-modules
keep their own READMEs because they document code you would be reading anyway:

| Document | Covers |
|---|---|
| [`voice_gateway/README.md`](voice_gateway/README.md) | The gateway itself: the three call journeys, the Duo + Graph identity boundary, accepted bootstraps. **Read this before changing anything about who a caller is.** |
| [`provisioning/README.md`](provisioning/README.md) | Dograh config-as-code and Vertex BYOC — endpoints, idempotency, live-deployment schema notes. |

## Status

The voice channel is built and integrated. An external caller reaches a real
Service Desk line, states any problem, proves who they are through Cisco Duo
with a read-only Microsoft Graph corroboration, and is handed to `sd_chat` with
a trusted identity. An authenticated portal user gets a shortcut path that skips
Duo entirely. The TURN edge is live and verified.

For the security model behind that sentence — what selects a candidate versus
what decides identity, and why the caller's spoken words never reach `sd_chat`
before authentication — see `voice_gateway/README.md`. It is the authority; this
file does not restate it.

`sd_chat/` remains the authoritative ServiceDesk runtime and owns host port
`8000`. Nothing in this folder modifies it.

## Runtime provenance

Pinned for reproducibility. Do not silently move to a later tag or `main`.

| Field | Value |
|---|---|
| Repository | `https://github.com/dograh-hq/dograh` (official, no forks) |
| Tag | `dograh-v1.45.0` |
| Commit SHA | `48aa0f600b21bbdaf89ac59c704dd77b0bb22202` |
| Tag published / fetched | 2026-08-11 / 2026-08-15 |
| Docker Compose | v2.25.0 CLI plugin at `/usr/local/lib/docker/cli-plugins/` |
| Docker Engine | `docker.io` 20.10.24+dfsg1 — unchanged, API 1.41 |
| coturn | 4.6.1-1 (bookworm main, systemd-managed) |

Files were fetched at that exact SHA via `raw.githubusercontent.com`; the
repository was never cloned and no upstream script was executed.
`docker-compose.yaml` is byte-for-byte upstream and every deviation lives in
`docker-compose.override.yaml`. `scripts/start_docker.sh` was inspected only,
with its `-x` bit removed.

Compose v2.25.0 is a deliberate floor, not an accident: the override file uses
the `!override` tag, which needs v2.24.4+. Nothing in the upstream files
requires `include:`, `develop:`, `extends:`, or any post-2.25 feature.

**Why `docker-compose-local.yaml` is not used:** at this tag it defines only
`postgres`, `redis`, and `minio` — no `api`, no `ui` — so it cannot serve a UI.
The full `docker-compose.yaml` with **no `--profile` flag** yields exactly the
five services wanted, because everything that must not run is profile-gated
upstream (`dograh-init`, `nginx`, `coturn`, `cloudflared`). Upstream's
`start_docker.sh` ends with `--profile tunnel`; we deliberately do not, so
cloudflared never starts.

Secrets (`OSS_JWT_SECRET`, `POSTGRES_PASSWORD`, `REDIS_PASSWORD`,
`MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD`) are generated locally with
`openssl rand -hex 32` into `runtime/.env`, mode `0600`, git-ignored, never
printed. `ENABLE_TELEMETRY=false` is set and verified to render into both the
`api` and `ui` containers.

## Contents

| Path | Purpose | Tracked? |
|---|---|---|
| `voice_gateway/` | The Dograh → `sd_chat` adapter | yes |
| `provisioning/` | Dograh config-as-code + Vertex BYOC | yes |
| `runtime/docker-compose.override.yaml` | Our loopback-only port bindings | yes |
| `runtime/docker-compose.yaml` | Upstream, byte-for-byte unmodified | ignored |
| `runtime/reference-docker-compose-local.yaml` | Upstream reference (infra-only, unused) | ignored |
| `runtime/upstream-start_docker.sh` | Inspected only, never executed | ignored |
| `runtime/.env` | Generated secrets and TURN config — never commit | ignored |
| `runtime/recovery_identity.db` | Recovery identity map — never commit | ignored |

## Effective host port bindings

```
127.0.0.1:8001 -> api container :8000     (8000 belongs to ServiceDesk)
127.0.0.1:3010 -> ui  container :3010     (3000 belongs to Next.js)
127.0.0.1:9000 -> minio :9000
127.0.0.1:9001 -> minio console :9001
postgres        NO host port published
redis           NO host port published
```

## Operating the stack

The invoking user is not in the `docker` group by design, so all commands use
`sudo`. Always pass both compose files:

```bash
R=/home/AI_POC/servicedesk-ai/dograh_voice/runtime
sudo docker compose --project-directory "$R" \
  -f "$R/docker-compose.yaml" -f "$R/docker-compose.override.yaml" ps
```

Never run `docker compose up` without the override — upstream publishes the API
on host `8000`, which collides with ServiceDesk, and Postgres/Redis on
`0.0.0.0`, which would expose them VPC-wide.

Never pass `--profile` — that starts nginx, coturn, or cloudflared.

## TURN edge

A dedicated TURN host, built and verified 2026-08-15. It is deliberately a
separate VM in its own VPC rather than coturn on the shared host.

**Why separate.** Four pre-existing `0.0.0.0/0` ingress rules
(`default-allow-ssh`, `default-allow-rdp`, `default-allow-http`,
`default-allow-https`) are either untagged or match tags the shared VM carries.
Attaching an external IP to `dev-linux-instance` would therefore publish SSH to
the entire internet on the host holding `sd_chat/credentials.json`,
`sd_chat/.env`, and Entra automation able to enable accounts and reset
passwords. ServiceDesk `:8000` itself would stay unreachable, but that is not
the point — 22/80/443/3389 is the disqualifier. Making it safe would have meant
changing project-wide firewall posture for a PoC.

| Resource | Value |
|---|---|
| VPC / subnet | `turn-poc-vpc` / `turn-poc-subnet` (`10.200.0.0/29`, us-central1) — **no peering to `default`** |
| Static IP | `dograh-turn-ip` = `34.44.75.208` |
| VM | `dograh-turn`, us-central1-c, `e2-micro`, Debian 12, 10 GB pd-balanced |
| Internal IP | `10.200.0.2` |
| Service account | none (`--no-service-account --no-scopes`) |
| Shielded VM | secure boot + vTPM + integrity monitoring |
| Firewall | `turn-allow-stun-turn` (udp/tcp 3478), `turn-allow-relay-range` (udp 49152-49200), `turn-allow-iap-ssh` (tcp 22 from 35.235.240.0/20) — all tag-scoped to `dograh-turn` |

Verified: config actually read (`Default realm: dograh.com`, single listener,
10 blacklist ranges); relay ports reserved via
`/proc/sys/net/ipv4/ip_local_reserved_ports`; unauthenticated `Allocate`
refused with 401; valid HMAC-SHA1 credential allocates on the public IP in the
correct range, proving the `external-ip` mapping; wrong shared secret refused.

Dograh side: `runtime/.env` carries `ENABLE_COTURN=true`,
`TURN_HOST=34.44.75.208`, `TURN_PORT=3478`, `TURN_CREDENTIAL_TTL=3600`,
`FORCE_TURN_RELAY=true`, and a git-ignored `TURN_SECRET`. Only the `api`
container is recreated when these change.

### Two operational rules that cost us an incident

On first `systemctl enable --now`, coturn started **without reading**
`/etc/turnserver.conf` — no realm, no explicit listener — and answered an
unauthenticated `Allocate` with success. It was briefly an open relay reachable
from `0.0.0.0/0`, for roughly two minutes on a brand-new IP with no inbound
traffic observed. It was caught by the negative authentication test, which is
exactly why that test exists.

1. **Always `systemctl restart coturn` after writing the config**, and confirm
   `Default realm: dograh.com` appears in the log **before** opening the
   firewall. `enable --now` activated the unit before it picked up the newly
   written file.
2. **`TURNSERVER_ENABLED` in `/etc/default/coturn` is not a safety interlock.**
   Debian's `coturn.service` has no `EnvironmentFile`, so it is vestigial under
   systemd.

### Public IP surface

| Instance | Public IP |
|---|---|
| `dev-windows-instance` | `35.206.99.182` (intentional) |
| `dograh-turn` | `34.44.75.208` (TURN edge; 3478 + relay range only) |
| everything else | none |

Public IPs were removed from `infra-demo-linux-vm-1/2` and
`infra-demo-windows-vm-1` (the last of which had 3389, 80, and 443
world-reachable). Safe because Cloud NAT on `default`/us-central1 is
`ALL_SUBNETWORKS_ALL_IP_RANGES`, preserving outbound for every zone, and IAP
SSH/RDP does not require an external IP.

**Auditing lesson:** a stopped instance reports an empty `natIP` even when it
still holds an access config, so it acquires a fresh public IP the moment
someone starts it. Audit
`networkInterfaces[0].accessConfigs[0].name`, never `natIP` — the name is always
populated when a config exists.

### Rollback

Revert the Dograh side first: in `runtime/.env` set `ENABLE_COTURN=false`,
remove `TURN_HOST` / `TURN_PORT` / `TURN_SECRET` / `FORCE_TURN_RELAY`, then
recreate only the `api` container. Tear down the TURN VM, its firewall rules,
the static IP, and the VPC afterwards.
