# Dograh runtime provenance — Phase 1 LOCAL PoC

Pinned for reproducibility. Do not silently move to a later tag or `main`
during this PoC.

## Upstream Dograh

| Field | Value |
|---|---|
| Repository | `https://github.com/dograh-hq/dograh` (official, no forks) |
| Tag | **`dograh-v1.45.0`** |
| Commit SHA | **`48aa0f600b21bbdaf89ac59c704dd77b0bb22202`** |
| Tag type | lightweight (ref points directly at the commit) |
| Tag published | 2026-08-11 |
| Fetched | 2026-08-15 |

Files retrieved at that exact SHA via `raw.githubusercontent.com`
(the repository was **not** cloned; no upstream script was executed):

| File | Local name | SHA256 as fetched |
|---|---|---|
| `docker-compose.yaml` | `docker-compose.yaml` | `2069a12027125dbc8e8d3bd0f544d7d2b7e8453b6b8b5a1d29c3cfe228557cbd` |
| `docker-compose-local.yaml` | `reference-docker-compose-local.yaml` | `811c136c80d263bf676fc4925ee2e1f5fa1bfd8494310e7a0c47aac688ccb1ad` |
| `scripts/start_docker.sh` | `upstream-start_docker.sh` | inspected only, `-x` bit removed, never executed |

`docker-compose.yaml` is byte-for-byte upstream. All deviations live in
`docker-compose.override.yaml`.

### Why `docker-compose-local.yaml` is NOT used

At this tag it defines **only** `postgres`, `redis`, `minio` — it has no `api`
and no `ui`, so it cannot serve a UI on 3010. It is kept purely for reference.

The full `docker-compose.yaml` with **no `--profile` flag** yields exactly the
five services we want, because every component we must not run is profile-gated
upstream:

| Service | Upstream profile | Starts by default? |
|---|---|---|
| postgres, redis, minio, api, ui | *(none)* | **yes** |
| `dograh-init` | `remote`, `local-turn` | no |
| `nginx` | `remote` | no |
| `coturn` | `remote`, `local-turn` | no |
| `cloudflared` | `tunnel` | no |

**Deliberate deviation from upstream:** `scripts/start_docker.sh` ends with
`docker compose --profile tunnel up --pull always`. We do **not** enable the
`tunnel` profile, so cloudflared never starts.

## Docker Compose

| Field | Value |
|---|---|
| Version | **v2.25.0** (deliberately not 5.4.0) |
| Source | `https://github.com/docker/compose/releases/download/v2.25.0/docker-compose-linux-x86_64` |
| SHA256 | `53641b8a28419f947bc58c085e0c39b97a209b6e875a25c585e7fab44ff48576` |
| Verified against | the release's `.sha256` asset **and** `checksums.txt` — both matched |
| Installed to | `/usr/local/lib/docker/cli-plugins/docker-compose` (root:root, 0755) |
| Method | CLI plugin only. No apt repo added, no engine or containerd change, no legacy standalone `docker-compose` |
| Engine | `docker.io` 20.10.24+dfsg1 — **unchanged**, API 1.41 negotiated OK |

### Compose feature audit (why v2.25.0 suffices)

Features actually used by this tag's compose files, and the version each needs:

| Feature | Needs | v2.25.0 |
|---|---|---|
| Versionless Compose Spec (no `version:` key) | v2.x | OK |
| `profiles:` | v1.28+ | OK |
| `depends_on:` + `condition: service_healthy` | v2.0+ | OK |
| `depends_on:` + `condition: service_completed_successfully` | v2.0+ | OK |
| `${VAR:-default}` interpolation | v2.x | OK |
| `${VAR:?error}` required-var form (`OSS_JWT_SECRET`) | v2.x | OK |
| `healthcheck.start_period` | v2.x | OK |
| `logging.options.max-size` / `max-file` | v2.x | OK |
| `!override` tag — **used by our override file** | **v2.24.4+** | OK |

Nothing in the upstream files requires `include:`, `develop:`, `extends:` or any
other post-2.25 feature. Confirmed by a clean `docker compose config` parse.

## Secrets

Generated locally with `openssl rand -hex 32` (the same generator upstream's
`start_docker.sh` uses) into `runtime/.env`, mode `0600`:

`OSS_JWT_SECRET`, `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `MINIO_ROOT_USER`,
`MINIO_ROOT_PASSWORD`.

Values were never printed and are git-ignored. `ENABLE_TELEMETRY=false` is set
and verified to render into both the `api` and `ui` containers.
