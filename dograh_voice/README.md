# dograh_voice

Dograh voice-channel integration with ServiceDesk AI.

## Status — Phase 1 complete (LOCAL deployment only)

As of **2026-08-15**, a **local-only** Dograh stack is running on this host.
It is **not** integrated with ServiceDesk and **not** reachable from the
internet.

| Item | State |
|---|---|
| Dograh version | `dograh-v1.45.0` (commit `48aa0f6`) — see [runtime/PROVENANCE.md](runtime/PROVENANCE.md) |
| Services running | `postgres`, `redis`, `minio`, `api`, `ui` — all healthy |
| Exposure | **loopback only** — every published port is `127.0.0.1` |
| nginx / coturn / cloudflared | **not started** (profile-gated upstream) |
| Public IP / firewall / DNS | **unchanged** — none created |
| Telemetry | **disabled** (`ENABLE_TELEMETRY=false`) |
| ServiceDesk | **untouched** — same PID, still `0.0.0.0:8000`, `/health`=200 |

## Contents

| Path | Purpose | Tracked? |
|---|---|---|
| `READINESS_REPORT.md` | Read-only host readiness assessment | yes |
| `runtime/PROVENANCE.md` | Pinned upstream tag/SHA + Compose provenance | yes |
| `runtime/docker-compose.override.yaml` | Our safe, loopback-only port bindings | yes |
| `runtime/docker-compose.yaml` | Upstream, byte-for-byte unmodified | ignored |
| `runtime/reference-docker-compose-local.yaml` | Upstream reference (infra-only, unused) | ignored |
| `runtime/upstream-start_docker.sh` | Inspected only, never executed | ignored |
| `runtime/.env` | **Generated secrets — never commit** | ignored |

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
on host `8000`, which would collide with ServiceDesk, and Postgres/Redis on
`0.0.0.0`, which would expose them VPC-wide.

Never pass `--profile` — that would start nginx, coturn or cloudflared.

## Not yet done

- No Voice Gateway (Phase 3)
- No ServiceDesk integration (Phase 4)
- No TURN / coturn, no Cloudflare Tunnel, no public ingress
- Browser Web Call / audio path **unverified** (Phase 2 gate)

## Relationship to `sd_chat/`

`sd_chat/` remains the authoritative ServiceDesk runtime and owns host port
`8000`. Nothing in this folder modifies it. The future Voice Gateway will be a
narrow adapter between Dograh and ServiceDesk — see the security section of
`READINESS_REPORT.md`.
