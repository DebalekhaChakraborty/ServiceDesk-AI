# Dograh Voice — Debian Host Readiness / Compatibility Assessment

# READY WITH CONDITIONS

**Scope of that verdict — read carefully:**

- **READY WITH CONDITIONS** for a *controlled, non-default, localhost-bound*
  Dograh install used for a local/tunnelled PoC.
- **NOT READY** for Dograh's *documented remote/public deployment path*
  (`setup_remote.sh` + sslip.io HTTPS + coturn). That path requires inbound
  Internet reachability which this VM does not currently have.

Assessment date: **2026-08-15**
Assessment type: **READ-ONLY**. No packages installed, no containers started, no
firewall changed, no service restarted, no GCP resource modified, no commit, no push.
Host: `dev-linux-instance` (Debian 12.15 bookworm, GCE `e2-highcpu-32`)
Repo: `ServiceDesk-AI` @ branch `agent/entra-access-portal-demo`

---

## BLOCKERS

Genuine blockers only. Each must be cleared before any Dograh install.

### B1 — Docker Compose v2 is not installed and is not available from configured apt repos

Dograh is deployed entirely through Docker Compose. This host cannot run it today.

```
$ docker compose version
docker: 'compose' is not a docker command.

$ command -v docker-compose
(not present)

$ ls /usr/libexec/docker/cli-plugins/ /usr/lib/docker/cli-plugins/ /usr/local/lib/docker/cli-plugins/
No such file or directory   (all three)

$ apt-cache policy docker-compose-plugin
(empty — package not present in any configured repository)

$ dpkg -l | grep -iE 'docker|containerd'
containerd  1.6.20~ds1-1+deb12u3
docker.io   20.10.24+dfsg1-1+deb12u1+b6
```

Docker itself is fine: `20.10.24` satisfies Dograh's documented "Docker 20.10 or
later". The gap is purely the **Compose v2 plugin**. Docker's official
repository (`download.docker.com`) is **not** configured — only Debian
`bookworm/main` — so `docker-compose-plugin` cannot be installed without first
adding a repo or manually placing the plugin binary.

**NOT EXECUTED — MUTATING CHECK.** Installing Compose v2 requires either adding
Docker's apt repo + `apt install docker-compose-plugin`, or dropping the
`docker-compose` binary into `/usr/local/lib/docker/cli-plugins/`. Both mutate
the host and need explicit approval. Which of the two is preferred is a decision
for the host owner — the manual plugin drop is the smaller, more reversible
change and does not alter apt sources on a shared lab machine.

### B2 — The VM has no external IP; inbound Internet reachability is zero

This is the structural blocker for Dograh's documented remote deployment.

```
$ curl -H "Metadata-Flavor: Google" .../network-interfaces/0/access-configs/
0/
$ curl ... /access-configs/0/type
ONE_TO_ONE_NAT
$ curl ... /access-configs/0/external-ip | od -c
0000000                              <-- ZERO BYTES: no IP assigned

$ ip -brief addr
ens4   UP   10.128.0.2/32            <-- private only

$ curl https://api.ipify.org
136.119.184.87                        <-- Cloud NAT gateway address, not the VM

$ gcloud compute addresses list
nat-auto-ip-...  136.119.184.87  us-central1  IN_USE  ['ai-and-automation-coe-router']
```

An access config exists but carries **no** external IP. Egress works via **Cloud
NAT** (router `ai-and-automation-coe-router`). Cloud NAT is **outbound-only** —
it provides no inbound path whatsoever.

Direct consequences:

1. **Let's Encrypt / sslip.io certificate issuance will fail.** Dograh's
   `setup_remote.sh` obtains a cert via sslip.io + HTTP-01, which requires
   inbound TCP/80 to the server's public IP. Upstream docs state private/reserved
   IPs "fall back to self-signed certificates" — a self-signed cert on a host the
   browser cannot reach anyway is not a usable PoC endpoint.
2. **The laptop browser cannot reach the Dograh UI** at all over the Internet.
3. **coturn cannot function as a TURN relay.** A TURN server behind a
   NAT it does not control, with no public address to advertise as its relay
   candidate, cannot relay media for a remote browser.

### B3 — Host port 8000 collision: ServiceDesk owns it, upstream Dograh publishes it

Verified on both sides.

ServiceDesk, live now:

```
$ ss -ltnp | grep :8000
LISTEN 0 2048  0.0.0.0:8000  users:(("python",pid=3396520,fd=13))

$ ps -o pid,user,etime,cmd -p 3396520
3396520  debalekha_chakraborty  05:54:02
  /home/AI_POC/venvs/debalekha/bin/python sd_chat/server_with_upload.py
   cwd = /home/AI_POC/servicedesk-ai
```

Upstream Dograh `docker-compose.yaml` (github.com/dograh-hq/dograh, `main`):

```yaml
api:
  image: ${REGISTRY:-dograhai}/dograh-api:latest
  ports:
    - "8000:8000"        # <-- collides
```

Running upstream compose unmodified would fail to bind (or, worse, race the
ServiceDesk listener). **Dograh must not be installed with default ports.**
Solvable — see §9 — but it is a blocker against using defaults.

### B4 — GCP firewall has no rules for the TURN/WebRTC ports

```
$ gcloud compute firewall-rules list
NAME                             DIRECTION  SRC              ALLOW           TAGS
default-allow-http               INGRESS    0.0.0.0/0        tcp:80          http-server
default-allow-https              INGRESS    0.0.0.0/0        tcp:443         https-server
default-allow-ssh                INGRESS    0.0.0.0/0        tcp:22
allow-ssh-iap-ingress            INGRESS    35.235.240.0/20  tcp:22,tcp:3389
allow-rdp-ingress-from-iap       INGRESS    35.235.240.0/20  tcp:3389
default-allow-rdp                INGRESS    0.0.0.0/0        tcp:3389
default-allow-icmp               INGRESS    0.0.0.0/0        icmp
default-allow-internal           INGRESS    10.128.0.0/9     tcp:0-65535,udp:0-65535,icmp
allow-backup-4505-backup-target  INGRESS    0.0.0.0/0        tcp:4505        backup-target
```

**No rule permits `tcp/udp 3478`, `tcp/udp 5349`, or `udp 49152-49200`.**
Dograh's docs require all of these "reachable from Internet".

Note the VM *does* carry the `http-server` and `https-server` tags, so 80/443
are already permitted by policy — they are simply unreachable for lack of an
external IP (B2). Firewall visibility itself is fine (read access confirmed).

**NOT EXECUTED — MUTATING CHECK.** Creating these rules requires approval.

---

## REQUIRED BEFORE INSTALL

Actions needed before Phase 1, in order.

1. **Approve and install Docker Compose v2** (clears B1). Choose repo-add vs.
   manual plugin drop.
2. **Decide the reachability strategy** (clears B2). Three options, cheapest first:
   - **SSH tunnel** from the laptop (`ssh -L 3010:127.0.0.1:3010 ...`). Serves the
     UI at `http://localhost:3010` on the laptop, which **satisfies the browser
     secure-context requirement** for microphone access — upstream docs:
     *"microphone access requires a secure-context feature, so the app must be
     served over HTTPS — or accessed at localhost/127.0.0.1 over HTTP."*
     No external IP, no firewall change, no nginx, no coturn. **Caveat: this is
     verified for signalling only. The WebRTC media path over an SSH tunnel is
     not proven and must be empirically tested in Phase 2** — if media fails,
     fall through to option b or c.
   - **Cloudflare Tunnel.** Upstream compose already ships a `cloudflared`
     service (`cloudflare/cloudflared:latest`, host port `2000`, currently free).
     Gives a public HTTPS hostname with **no external IP and no inbound firewall
     rule**. Strong candidate; requires a Cloudflare account decision.
   - **Assign an external IP + open 80/443/3478/5349/49152-49200.** The documented
     path. Also the highest blast radius — see §20; strongly prefer a dedicated
     VM if this is chosen.
3. **Produce a port-remapped, localhost-bound compose override** (clears B3 and
   the exposure issues in §20). Do not run upstream compose unmodified.
4. **Reclaim Docker disk before pulling images.** ~10.5 GB is currently dangling:
   ```
   $ docker system df
   Images        13  ACTIVE 0   8.757GB   RECLAIMABLE 8.757GB (100%)
   Build Cache   16              1.726GB   RECLAIMABLE 1.726GB
   ```
   All 13 images are inactive (0 containers exist). Reclaiming takes free space
   from 18 GB to roughly 28 GB. **NOT EXECUTED — MUTATING CHECK** (`docker image
   prune` / `builder prune` were explicitly not run).
5. **Decide docker group membership.** The invoking user is **not** in the
   `docker` group, so every Docker/Compose operation currently needs `sudo`:
   ```
   $ id
   uid=1000(debalekha_chakraborty) groups=...,1000(google-sudoers),1003(aiops)
   $ ls -l /var/run/docker.sock
   srw-rw---- 1 root docker 0 ...
   $ getent group docker
   docker:x:111:            <-- no members
   ```
   Passwordless sudo is available, so this is workable as-is. Adding the user to
   `docker` is a privilege decision (docker group ≈ root) — recommend **leaving
   it as-is** and using sudo explicitly.
6. **Set `ENABLE_TELEMETRY=false`** before first start (see §19).

---

## OPTIONAL HARDENING

Can wait until after first audio. **Not blockers.**

- **`sd_chat` binds `0.0.0.0:8000`, not localhost.** Combined with
  `default-allow-internal` (`10.128.0.0/9`, all TCP/UDP), **any VM in the VPC can
  currently reach ServiceDesk**, including `/docs`. Pre-existing condition,
  independent of Dograh. Recommend binding to `127.0.0.1` once the Voice Gateway
  design lands.
- **`default-allow-rdp` permits tcp:3389 from `0.0.0.0/0`.** Pre-existing,
  out of scope, flagged for the host owner.
- **Ephemeral port range overlaps the TURN relay range.**
  `/proc/sys/net/ipv4/ip_local_port_range` = `32768 60999`, which spans
  `49152-49200`. The kernel may transiently occupy a relay port. Mitigation is
  `net.ipv4.ip_local_reserved_ports` — a sysctl change, **NOT EXECUTED —
  MUTATING CHECK**. Only relevant if coturn is ever actually deployed.
- **`~/.docker/config.json` is unreadable** by the invoking user (permission
  denied — likely root-owned from an earlier `sudo docker` run). Harmless today;
  produces a warning on every docker invocation.
- **No swap** (`SwapTotal: 0`). Irrelevant at 24 GB available, noted for completeness.

---

## 3. Host identity

| Property | Value |
|---|---|
| Hostname | `dev-linux-instance` |
| OS | Debian GNU/Linux 12 (bookworm), `12.15` |
| Kernel | `6.1.0-52-cloud-amd64` (Debian 6.1.180-1, 2026-08-03) |
| Architecture | `x86_64` |
| Uptime | 4 days, 5:56 |
| Virtualization | `google` — Google Compute Engine |
| Machine type | `e2-highcpu-32` |
| GCP project / zone | `ai-and-automation-coe` / `us-central1-c` |

Dograh supports "Linux with kernel 3.10+". Kernel 6.1 — **compatible**.

## 4. CPU / memory capacity

```
$ nproc                → 32
   Intel Xeon @ 2.20GHz, 16 cores / 2 threads, 1 socket, 1 NUMA node
$ cat /proc/loadavg    → 0.12 0.18 0.13
$ free -h
        total   used   free   shared  buff/cache   available
Mem:     31Gi   6.9Gi   16Gi     66Mi       8.7Gi        24Gi
Swap:      0B      0B     0B
```

Observed resident workload (top consumers):

| Workload | Runtime | RSS | %CPU |
|---|---|---|---|
| VS Code Server extension host | node | 1.68 GB | 2.2 |
| Pylance language server | node | 1.51 GB | 0.6 |
| **ServiceDesk `sd_chat/server_with_upload.py`** | python (venv `debalekha`) | **452 MB** | **0.2** |
| `next-server (v14.2.5)` (chatbot-portal) | node | 383 MB | 0.0 |
| Roslyn / C# language server | dotnet | 335 MB | 0.5 |
| Claude Code CLI sessions (×2) | native | 330 + 302 MB | 3.7 / 1.0 |
| `dockerd` | go | 70 MB | 0.0 |

Most of the 6.9 GB in use is **IDE tooling**, not AI workload. The actual
ServiceDesk agent is a 452 MB Python process at 0.2% CPU. Load average of
**0.14 across 32 cores ≈ 0.5% utilisation**.

Dograh asks for 4 vCPU / 8 GB. Against 32 vCPU and 24 GB *available* — not
merely 31 GB total — the margin is large even with the full seven-container
stack (Postgres, Redis, MinIO, API, UI, nginx, coturn), which realistically
lands in the 2–4 GB range at idle.

```
CPU_CAPACITY:    PASS
MEMORY_CAPACITY: PASS
```

Rationale is deliberately not "total RAM ≥ 8 GB": it rests on 24 GB *currently
available*, a near-idle 32-core load average, and the observation that the
existing ADK workload's real footprint is under 1 GB.

## 5. Disk / storage capacity

```
$ df -h
/dev/sda1   99G   77G   18G   82%  /          (ext4)
/dev/sda15 124M   12M  112M   10%  /boot/efi

$ df -i
/dev/sda1  6545408 inodes, 1009429 used, 5535979 free (16%)   <-- ample

$ lsblk -f
sda ├─sda1 ext4 ... 17.3G 78% /     <-- single disk, NO separate data disk
```

Docker storage:

```
$ docker info | grep -E 'Storage Driver|Docker Root|Images'
 Images: 75
 Storage Driver: overlay2   (Backing Filesystem: extfs, Native Overlay Diff: true)
 Docker Root Dir: /var/lib/docker

$ docker system df
TYPE           TOTAL  ACTIVE  SIZE      RECLAIMABLE
Images         13     0       8.757GB   8.757GB (100%)
Containers     0      0       0B        0B
Local Volumes  2      0       1.321MB   1.321MB (100%)
Build Cache    16             1.726GB
```

`overlay2` on `extfs` is the correct, supported driver. No cleanup command was run.

Assessment: 18 GB free exceeds Dograh's documented 10 GB minimum, but this is a
**single 99 GB root disk at 82% on a shared lab machine**, and MinIO audio
recordings grow without bound. The saving grace is that **all 13 images are
inactive**, so ~10.5 GB is reclaimable on demand, which would restore free space
to ~28 GB. `minio/minio:latest` is already pulled locally.

```
STORAGE_CAPACITY: CONDITIONAL
```

Conditional on reclaiming dangling images/build cache before pulling Dograh
images, and on capping MinIO retention. No new disk created.

## 6. Docker readiness

| Item | Result |
|---|---|
| Docker installed | **YES** — `/usr/bin/docker`, `20.10.24+dfsg1` (`docker.io` from bookworm/main) |
| Daemon running | **YES** — `docker.service` active since 2026-08-11, 4 days, PID 808 |
| **Compose v2** | **NO** — not a docker subcommand, no plugin dir, `docker-compose` v1 absent |
| Compose v2 installable from configured repos | **NO** — `docker-compose-plugin` not in any configured repo |
| Storage driver | `overlay2` on `extfs` |
| Docker root dir | `/var/lib/docker` |
| Cgroup driver / version | `systemd` / **v2** |
| containerd / runc | `1.6.20` / `1.1.5` |
| Running containers | **0** |
| Stopped containers | **0** |
| Networks | `bridge`, `host`, `none` (defaults only — no custom networks) |
| Volumes | 2 anonymous local volumes, 1.3 MB total |
| Socket access as invoking user | **DENIED** — user not in `docker` group; sudo required |

`docker inspect` was **not** run against any container (none exist), and no
container environment was read.

```
DOCKER_READY: CONDITIONAL
```

Engine is healthy and correctly configured; **Compose v2 is the sole gap** (B1).

## 7. Existing port inventory

Full listener set (`ss -lntup`):

| Port | Proto | Bind | Owner (PID) | Application |
|---|---|---|---|---|
| **8000** | tcp | **0.0.0.0** | `python` (3396520) | **ServiceDesk `sd_chat/server_with_upload.py`** |
| **3000** | tcp | `*` (v4+v6) | `next-server` (3247388) | Next.js dev — `/home/AI_POC/chatbot-portal` |
| 22 | tcp | `0.0.0.0`, `[::]` | sshd | SSH |
| 25 | tcp | `127.0.0.1`, `[::1]` | — | local MTA |
| 53 | tcp/udp | `127.0.0.53`, `127.0.0.54` | systemd-resolved | DNS stub |
| 5355 | tcp/udp | `0.0.0.0`, `[::]` | systemd-resolved | LLMNR |
| 68 | udp | `10.128.0.2` | — | DHCP client |
| 34585, 42291, 43963 | tcp | `127.0.0.1` | `code-*` | VS Code server |
| 21960, 40937, 45591, 44035 | tcp | `127.0.0.1` | node / MainThread | VS Code ext hosts |

Targeted availability check for every Dograh-relevant port:

| Port/proto | Status | Note |
|---|---|---|
| 80/tcp | **FREE** | no web server installed |
| 443/tcp | **FREE** | no web server installed |
| 2000/tcp | **FREE** | upstream `cloudflared` |
| 3000/tcp | **OCCUPIED** | Next.js dev server — avoid |
| 3010/tcp | **FREE** | upstream Dograh UI |
| 5432/tcp | **FREE** | upstream Postgres |
| 6379/tcp | **FREE** | upstream Redis |
| **8000/tcp** | **OCCUPIED** | **ServiceDesk** |
| 8001/tcp | **FREE** | verified — candidate API remap |
| 8010/tcp | **FREE** | verified — alternate candidate |
| 9000/tcp | **FREE** | upstream MinIO |
| 9001/tcp | **FREE** | upstream MinIO console |
| 3478/tcp, 3478/udp | **FREE** | coturn |
| 5349/tcp, 5349/udp | **FREE** | coturn TLS |
| 49152–49200/udp | **ENTIRE RANGE FREE** | polled individually; coturn relay |

Nothing was killed, moved, or restarted.

## 8. ServiceDesk port 8000 verification

```
SERVICEDESK_PORT_8000:
    owner:            /home/AI_POC/venvs/debalekha/bin/python sd_chat/server_with_upload.py
    pid:              3396520  (user debalekha_chakraborty, cwd /home/AI_POC/servicedesk-ai)
    bind_address:     0.0.0.0:8000   (IPv4 only — no IPv6 listener)
    runtime_status:   RUNNING — uptime 05:54:02, 0.2% CPU, 452 MB RSS
    collision_with_default_dograh_api: YES
```

Harmless read-only HTTP probes against the already-running service (no ADK
conversation started, no tool invoked, no session created):

```
GET http://127.0.0.1:8000/        → 404   (4.9 ms)
GET http://127.0.0.1:8000/health  → 200
GET http://127.0.0.1:8000/docs    → 200   (FastAPI/OpenAPI UI present)
```

Command line contains no credentials; no process environment was read.

**It binds `0.0.0.0`, not `127.0.0.1`** — combined with `default-allow-internal`
this makes ServiceDesk reachable from anywhere in `10.128.0.0/9` today. Recorded
under Optional Hardening.

## 9. Recommended Dograh port strategy — NOT IMPLEMENTED

Guiding principle: **the smallest possible public attack surface.** nginx is the
only component that ever needs a host port; everything else should reach it over
the Compose network.

**Does the Dograh API need a host port at all?** — **No.** nginx and the UI reach
`api:8000` over the Compose bridge network by service name. Publishing the API
on the host is only useful for direct debugging and for the future Voice Gateway,
and even then `127.0.0.1` binding suffices.

Recommended future mapping (all verified free unless noted):

| Service | Upstream default | **Recommended** | Rationale |
|---|---|---|---|
| api | `8000:8000` | **`127.0.0.1:8001:8000`** | 8000 is ServiceDesk. 8001 verified free. Localhost-only. Omit entirely if the Voice Gateway is containerised. |
| ui | `3010:3010` | `127.0.0.1:3010:3010` | 3010 free. **Never use 3000** — Next.js owns it. |
| postgres | `5432:5432` | **remove**, or `127.0.0.1:5433:5432` | Upstream publishes on `0.0.0.0` — must not stay that way (§20). |
| redis | `6379:6379` | **remove**, or `127.0.0.1:6380:6379` | Same — upstream binds `0.0.0.0`. |
| minio | `127.0.0.1:9000/9001` | keep as-is | Already correctly localhost-bound upstream. |
| nginx | `80:80`, `443:443` | keep — **only if publicly reachable** | Both free; pointless without an external IP (B2). |
| coturn | 3478/5349 tcp+udp, 49152-49200/udp | **defer entirely** | All free on host, but blocked by B2 + B4. |
| cloudflared | `2000:2000` | `127.0.0.1:2000:2000` | 2000 free; relevant if the Cloudflare Tunnel route is chosen. |

Implementation should be a **`docker-compose.override.yaml`** so upstream files
stay pristine and upgradable. **Not written in this phase.**

## 10. Existing web server / reverse proxy

```
nginx / apache2 / caddy / traefik / httpd / haproxy  →  none installed
systemctl status nginx    → Unit nginx.service could not be found
systemctl status apache2  → Unit apache2.service could not be found
```

Nothing listens on 80 or 443, and no proxy is installed.

```
PUBLIC_HTTP_PORTS_AVAILABLE: YES  (host-side)
```

Caveat: available on the host and permitted by GCP firewall (VM carries
`http-server` + `https-server` tags), but **not reachable from the Internet**
due to B2.

## 11. GCP network readiness

```
$ ip -brief addr
lo        UNKNOWN  127.0.0.1/8 ::1/128
ens4      UP       10.128.0.2/32
docker0   DOWN     172.17.0.1/16          (linkdown — no containers)
sdvdi-h@if4 UP     10.99.99.1/30          (pre-existing veth, unrelated)

$ ip route
default via 10.128.0.1 dev ens4 proto dhcp src 10.128.0.2 metric 100

$ getent hosts github.com
140.82.114.3
```

- Private IP: `10.128.0.2` — network `default`, subnet `default` (us-central1)
- External IP: **NONE** (proven in B2)
- Egress path: **Cloud NAT** via `ai-and-automation-coe-router` → `136.119.184.87`
- DNS: systemd-resolved → `169.254.169.254`, working

```
EXTERNAL_IP:         NONE
EXTERNAL_IP_PRESENT: NO
OUTBOUND_INTERNET:   PASS
```

No service-account token was requested. The
`/instance/service-accounts/default/token` endpoint was **never** queried.

## 12. GCP firewall readiness

```
FIREWALL_STATUS: READABLE — read access confirmed as debalekha.chakraborty@tcs.com
```

Full rule list is quoted in **B4**. Applied to this VM (tags `http-server`,
`https-server`):

| Future need | Rule exists? | Status |
|---|---|---|
| TCP 80 | `default-allow-http` (0.0.0.0/0, tag `http-server`) | **ALLOWED** |
| TCP 443 | `default-allow-https` (0.0.0.0/0, tag `https-server`) | **ALLOWED** |
| TCP 3478 | — | **MISSING** |
| UDP 3478 | — | **MISSING** |
| TCP 5349 | — | **MISSING** |
| UDP 5349 | — | **MISSING** |
| UDP 49152–49200 | — | **MISSING** |

**MUST REMAIN NON-PUBLIC** — no public ingress rule should ever be created for:

```
5432 (Postgres)   6379 (Redis)   8000 (ServiceDesk)
8001 (future Dograh API)         9000 / 9001 (MinIO)
```

Note that `default-allow-internal` already exposes **all** TCP/UDP ports to
`10.128.0.0/9`. That rule is why these services must be bound to `127.0.0.1`
rather than merely left off the public firewall — see §20.

## 13. Public DNS / HTTPS readiness

Current state, not theoretical state:

- Public DNS hostname associated with the VM: **NONE** (no external IP to map).
- Domain configuration in the repository: none relevant. A filename-only scan
  found `sd_chat/.env`, `sd_chat/credentials.json`,
  `employee_access_portal/.env.example`, `.local/rdp_demo.env` — **contents
  deliberately not read**. Config-key grep surfaced only `BASE_URL` in
  `employee_access_portal/README.md` and `sd_chat/tools/aad_tool.py`, neither
  indicating a public hostname.
- 80/443: free on host, firewall-permitted, Internet-unreachable.

```
PUBLIC_ADDRESS_STRATEGY:
    existing_public_ip:   NO
    existing_domain:      NO
    new_domain_required:  NO  — sslip.io would remove the need, but requires a public IP
    tunnel_possible:      YES — two independent routes
    UNKNOWN:              —
```

**Simplest future PoC option — recommended:** **SSH local port-forward** from the
laptop. `ssh -L 3010:127.0.0.1:3010 dev-linux-instance`, then browse
`http://localhost:3010`. This satisfies the browser secure-context rule via
`localhost` with **no external IP, no DNS record, no certificate, no firewall
change, and no nginx or coturn**. It is by a wide margin the lowest-risk path to
first audio, and it keeps the shared lab VM entirely unexposed.

Its one open question is whether the **WebRTC media path** survives a TCP tunnel
— that is a Phase 2 empirical test, not an assumption. If it fails, the ranked
fallbacks are (1) Cloudflare Tunnel via the `cloudflared` service already in
upstream compose, then (2) a dedicated VM with a real external IP.

No DNS record created. No certificate requested.

## 14. TURN / WebRTC host suitability

| Factor | Finding |
|---|---|
| Conflicting listeners on 3478 / 5349 | **None** — all four tcp/udp combinations free |
| UDP 49152–49200 | **Entire range free** (polled per-port) |
| Ephemeral range overlap | **YES** — `32768 60999` spans the relay range (hardening item) |
| Host firewall | Permissive: `iptables -P INPUT ACCEPT`; no `ufw`, no `nftables` |
| Docker networking | Available — `bridge`/`host`/`overlay` drivers present |
| Public IP | **NONE** |
| Behind NAT | **YES** — Cloud NAT, outbound-only |
| GCP ingress rules for TURN | **NONE** |

```
TURN_READINESS: FAIL
```

**Blockers, stated plainly:** the host-side situation is actually ideal — every
TURN port is free and the host firewall is permissive. TURN fails purely on
**network position**: a TURN relay behind an outbound-only Cloud NAT with no
public address cannot advertise a reachable relay candidate to a remote browser,
and no ingress rule exists for its ports. Both B2 and B4 must clear before
coturn is worth deploying. For the recommended localhost/tunnel PoC, **coturn is
not needed at all** — the local compose file omits it entirely.

Host firewall detail:

```
$ sudo iptables -S
-P INPUT ACCEPT
-P FORWARD DROP
-P OUTPUT ACCEPT
... standard DOCKER / DOCKER-ISOLATION / DOCKER-USER chains, DOCKER-USER -j RETURN
$ nft   → command not found
$ ufw   → not installed
```

No firewall rule was added, removed, or modified.

## 15. Outbound provider connectivity

DNS + TLS reachability only. **No credentials sent, no API keys read, no
authenticated call made.** Non-2xx codes are expected unauthenticated responses
and still prove DNS + TLS + routing work.

| Endpoint | DNS | HTTPS |
|---|---|---|
| `github.com` | OK | 200 |
| `ghcr.io` | OK | 301 |
| `registry-1.docker.io` | OK | 404 |
| `www.googleapis.com` | OK | 404 |
| `generativelanguage.googleapis.com` | OK | 404 |
| `login.microsoftonline.com` | OK | 302 |
| `graph.microsoft.com` | OK | 301 |
| `api.openai.com` | OK | 421 |
| `api.deepgram.com` | OK | 404 |
| `api.elevenlabs.io` | OK | 404 |
| `api.cartesia.ai` | OK | 200 |

Container registries, Google APIs, Microsoft identity/Graph (already used by
ServiceDesk), and the common STT/TTS providers are all reachable.

```
OUTBOUND_PROVIDER_CONNECTIVITY: PASS
```

## 16. Current ADK / lab workload inventory

No message content, prompt, secret, or credential was inspected.

| Workload | Runtime | %CPU | RSS | Listener |
|---|---|---|---|---|
| **ServiceDesk agent** (`sd_chat/server_with_upload.py`) | python, venv `debalekha` | 0.2 | 452 MB | **`0.0.0.0:8000`** |
| chatbot-portal (`next dev`) | node 14.2.5 | 0.0 | 383 MB | **`*:3000`** |
| VS Code Server (ext host, Pylance, Roslyn, tsserver, Copilot, Codex) | node/dotnet | ~4 | ~4.5 GB | `127.0.0.1` high ports |
| Claude Code CLI (×2) | native | ~4.7 | 640 MB | none |
| `dockerd` + `containerd` | go | 0.0 | 111 MB | none |
| Google guest agents | native | ~4 | 30 MB | none |
| **Docker containers** | — | — | — | **none running** |

Contention assessment: the only genuine long-running AI service is the 452 MB
ServiceDesk process. **Zero containers run today**, so Dograh would not contend
with any existing container workload. The two host-port collisions to respect
are **8000 (ServiceDesk)** and **3000 (Next.js)**.

## 17. Repository safety check

**Baseline, before any change:**

```
$ git rev-parse --show-toplevel   → /home/AI_POC/servicedesk-ai
$ git branch --show-current       → agent/entra-access-portal-demo
$ git status --short              → (empty — clean tree)
```

**After creating only the two permitted files:**

```
$ git status --short
?? dograh_voice/
```

Exactly the acceptable delta. `sd_chat/` untouched; no existing repository file
modified; nothing committed, staged, or pushed. No `.env` file was read at any
point. No secret value appears in this report.

## 18. Dograh upstream compatibility review

Sources consulted **2026-08-15**, read-only. No upstream script was downloaded
or executed; the repository was **not** cloned.

- `https://docs.dograh.com/` (index, prerequisites, deployment, deployment/docker)
- `https://github.com/dograh-hq/dograh` (README, `main`)
- `https://raw.githubusercontent.com/dograh-hq/dograh/main/docker-compose.yaml`
- `https://raw.githubusercontent.com/dograh-hq/dograh/main/docker-compose-local.yaml`

**Documented requirements vs. this host — current upstream, not a prior assumption:**

| Upstream requirement | This host | Verdict |
|---|---|---|
| Linux kernel 3.10+ | 6.1.0-52 | **PASS** |
| Docker 20.10 or later | 20.10.24 | **PASS** (at the floor) |
| Docker Compose | **absent** | **FAIL — B1** |
| CPU: 2 cores min, 4 recommended | 32 vCPU | **PASS** |
| RAM: 8 GB min (4 GB for Docker), 8 GB recommended | 31 GB / 24 GB available | **PASS** |
| Disk: 10 GB free | 18 GB (+10.5 GB reclaimable) | **CONDITIONAL** |
| Remote: public IP for sslip.io + Let's Encrypt | none | **FAIL — B2** |
| Remote: TCP 80, 443, 3478, 5349 from Internet | 80/443 permitted but unreachable; 3478/5349 no rule | **FAIL — B2/B4** |
| Remote: UDP 3478, 5349, 49152–49200 from Internet | no rule | **FAIL — B4** |
| Browser: HTTPS **or** localhost/127.0.0.1 for mic | localhost reachable via SSH tunnel | **CONDITIONAL** |
| `curl` present | yes | **PASS** |

**Current upstream stack — `docker-compose.yaml` (remote/full):**

| Service | Image | Host ports (verbatim) |
|---|---|---|
| postgres | `pgvector/pgvector:pg17` | `"5432:5432"` |
| redis | `redis:7` | `"6379:6379"` |
| minio | `minio/minio` | `"127.0.0.1:9000:9000"`, `"127.0.0.1:9001:9001"` |
| dograh-init | `bash:5.2` | — |
| nginx | `nginx:alpine` | `"80:80"`, `"443:443"` |
| coturn | `coturn/coturn:4.8.0` | `"3478:3478/udp"`, `"3478:3478/tcp"`, `"5349:5349/udp"`, `"5349:5349/tcp"`, `"49152-49200:49152-49200/udp"` |
| **api** | `${REGISTRY:-dograhai}/dograh-api:latest` | **`"8000:8000"`** |
| ui | `${REGISTRY:-dograhai}/dograh-ui:latest` | `"3010:3010"` |
| cloudflared | `cloudflare/cloudflared:latest` | `"2000:2000"` |

Volumes: `postgres_data`, `redis_data`, `minio-data`, `nginx-generated`,
`coturn-generated`.

**`docker-compose-local.yaml`** is materially smaller — **postgres, redis and
minio only**; it contains **no nginx, no coturn, no cloudflared**. This matters:
the local variant sidesteps every TURN/TLS/public-IP blocker, which is precisely
why the tunnel-based PoC in §13 is viable now while the remote path is not.

**Setup scripts (documented; NOT downloaded, NOT run):**
`scripts/start_docker.sh` (local), `scripts/setup_remote.sh` (remote, run under
`sudo`). Auto-generated env: `OSS_JWT_SECRET`, `REDIS_PASSWORD`,
`POSTGRES_PASSWORD`, TURN credentials; optional `CERT_MODE`,
`ACME_DOMAIN_SUFFIX`, `LETSENCRYPT_EMAIL`.

Upstream images are `:latest` — pin digests before any demo-critical deployment.

## 19. Telemetry / data considerations

**Telemetry is ON by default.** Upstream: *"We collect anonymous usage data to
improve the product. You can opt out by setting `ENABLE_TELEMETRY=false`."*

**Recommendation for this enterprise PoC: `ENABLE_TELEMETRY=false`.** Not
changed now — the value must be set before first start, since telemetry emits
from the first run onward.

**Services that persist data** (all would need volumes; **none created**):

| Service | Volume | Persists |
|---|---|---|
| postgres (pgvector) | `postgres_data` | Workflows, runs, transcripts, user records, embeddings |
| redis | `redis_data` | Queues, session/worker state |
| minio | `minio-data` | **Call audio recordings and artifacts** — grows unbounded |
| nginx | `nginx-generated` | Generated config (incl. TLS material) |
| coturn | `coturn-generated` | Generated config (incl. TURN credentials) |
| all | Docker `json-file` log driver | Container logs — uncapped by default |

Two data-governance points for a ServiceDesk PoC: **call recordings and
transcripts constitute personal data** and will accumulate in MinIO and Postgres,
requiring a retention decision before real users are recorded; and the default
`json-file` log driver is **uncapped**, so `max-size`/`max-file` limits should be
set given the 82%-full root disk.

## 20. Security assessment

Colocating Dograh with ServiceDesk on this VM carries real, specific risks.

| Surface | Assessment |
|---|---|
| **Public nginx on a privileged host** | The VM runs ServiceDesk code with Entra/Graph automation reach (`sd_chat/tools/aad_tool.py`) plus `sd_chat/credentials.json` and `sd_chat/.env`. Putting an Internet-facing nginx on this host means an nginx/Dograh compromise lands in the same filesystem and network namespace as identity credentials capable of enabling accounts and resetting passwords. **This is the single strongest argument against public exposure here.** |
| **Dograh API host exposure** | Upstream `8000:8000` both collides with ServiceDesk and would bind `0.0.0.0`. Remap to `127.0.0.1:8001` or do not publish. |
| **PostgreSQL exposure** | Upstream publishes **`5432:5432` on `0.0.0.0`**. With `default-allow-internal` (`10.128.0.0/9`, all ports), **every VM in the VPC could reach the Dograh database** — which holds transcripts and user records. Must bind `127.0.0.1` or drop the mapping. |
| **Redis exposure** | Same defect: **`6379:6379` on `0.0.0.0`**, VPC-wide reachable. `REDIS_PASSWORD` is auto-generated, but an exposed Redis remains a poor default. Must bind `127.0.0.1`. |
| **MinIO exposure** | Already `127.0.0.1`-bound upstream — correct. Keep it that way; it stores call audio. |
| **TURN UDP exposure** | coturn is a relay by design and is routinely abused as an open relay if misconfigured. Deploy only with credentials enforced and relay scoped — and only once B2/B4 are consciously accepted. |
| **Container-to-host reachability** | ServiceDesk listens on `0.0.0.0:8000`, so it is reachable from `172.17.0.0/16` via the docker0 gateway. **Any Dograh container could call ServiceDesk directly**, bypassing the intended Voice Gateway. Binding ServiceDesk to `127.0.0.1` closes this. |
| **ServiceDesk localhost isolation** | **Not currently isolated** — `0.0.0.0:8000` + `default-allow-internal` = VPC-wide reachable today, `/docs` included. Pre-existing, worth fixing regardless of Dograh. |
| **Docker daemon privilege** | Daemon runs as root; `docker` group ≈ root. The `docker` group is currently **empty** — a good default. Keep sudo-mediated access rather than adding the user. |
| **Secrets boundary** | Dograh auto-generates its own secrets into its `.env`. Keep them strictly separate from `sd_chat/.env`; the Voice Gateway should hold no Entra credentials of its own. |
| **Network segmentation** | Currently none between workloads. Dograh should run on its **own Compose bridge network**, never `network_mode: host`. |

**Preferred future security model** (design only — not implemented):

```
Internet
    |
    v
Dograh nginx / TURN only          <-- the ONLY publicly exposed components
    |
    v
Dograh containers (own bridge network, no host ports except nginx)
    |
    | controlled local HTTP, 127.0.0.1 only
    v
Voice Gateway                     <-- narrow adapter, strict allow-list
    |
    | localhost only
    v
ServiceDesk :8000  (bound 127.0.0.1)
```

The Voice Gateway must stay a **narrow adapter**: one endpoint, a fixed
request/response shape, no passthrough of arbitrary paths, no credential
forwarding. **ServiceDesk must never sit behind Dograh's public ingress.**

## 21. Colocation vs. dedicated VM

Scored on evidence gathered above (1 = poor, 5 = excellent).

| Criterion | A: Colocate | B: Dedicated VM |
|---|---|---|
| Cost | **5** — zero marginal cost | 2 — new billable instance |
| Setup effort | **4** — Docker present; needs Compose v2 + port remap | 2 — full provisioning, then Compose v2 anyway |
| Available capacity | **5** — 32 vCPU, 24 GB free, load 0.14 | 3 — must size and pay for it |
| Port conflicts | 3 — 8000 and 3000 taken; everything else free | **5** — clean slate |
| Security blast radius | **1** — public ingress next to Entra-privileged ServiceDesk code and credentials | **5** — fully isolated |
| Operational isolation | 2 — shared lab VM explicitly flagged "MUST NOT be disrupted" | **5** — freely restartable |
| Maintenance | 3 — Compose v2 + repo changes on a shared box | **4** — independent lifecycle |
| Suitability for PoC | **5** — fastest route to first audio via SSH tunnel | 3 — slower to start |
| Suitability for longer-term demo | 2 — needs a public IP on the wrong host | **5** — correct long-term home |
| **Total** | **30** | **34** |

```
RECOMMENDED_OPTION: COLOCATE  — strictly scoped to Phases 1–2 (localhost/tunnel, no public exposure)
                    DEDICATED_VM — required before ANY Internet-facing deployment
```

**Evidence for the split recommendation.** Colocation wins decisively on
capacity and time-to-first-audio: 24 GB free RAM, 0.5% CPU utilisation, zero
running containers, Docker already installed, and every port Dograh needs free
except the two known collisions. For a localhost/SSH-tunnel PoC there is no
public ingress at all, so the security objection does not yet apply and the
`docker-compose-local.yaml` variant (no nginx, no coturn) sidesteps B2 and B4
entirely.

The moment public exposure enters the picture, the scoring inverts. Giving this
VM an external IP would place Internet-facing nginx and a TURN relay on the same
host as `sd_chat/credentials.json`, `sd_chat/.env`, and Entra automation that can
enable accounts and reset passwords — on a machine already carrying
`default-allow-rdp` from `0.0.0.0/0` and a ServiceDesk bound to `0.0.0.0:8000`.
The brief states this VM "MUST NOT be disrupted"; that constraint and public
exposure are not compatible. **Hence a hard gate at the Phase 2 → Phase 3
boundary.**

## 22. Critical GO / NO-GO matrix

| Check | Result | Evidence | Blocker? | Action Needed |
|------|------|------|------|------|
| Debian/Linux compatible | PASS | Debian 12.15, kernel 6.1.0-52, x86_64; upstream needs kernel 3.10+ | No | None |
| CPU capacity | PASS | 32 vCPU `e2-highcpu-32`; load 0.12/0.18/0.13; upstream wants 4 | No | None |
| RAM capacity | PASS | 31 GB total, **24 GB available**; upstream wants 8 | No | None |
| Disk capacity | CONDITIONAL | `/` 99 GB, 18 GB free (82% used); 10.5 GB reclaimable; upstream wants 10 GB | No | Prune dangling images/build cache; cap MinIO retention + Docker log size |
| Docker installed | PASS | `docker.io` 20.10.24 ≥ upstream floor 20.10 | No | None |
| Docker daemon usable | CONDITIONAL | Active 4 days, PID 808; user not in `docker` group, socket denied | No | Use `sudo`; do not add user to `docker` group |
| Docker Compose available | **FAIL** | Not a subcommand; no plugin dir; v1 absent; not in configured apt repos | **YES — B1** | Approve + install Compose v2 |
| ServiceDesk :8000 identified | PASS | PID 3396520, `sd_chat/server_with_upload.py`, `0.0.0.0:8000`, `/health`=200 | No | None |
| Dograh API port collision understood | PASS | Upstream `api: "8000:8000"` vs ServiceDesk on 8000 — confirmed both sides | No | Never run upstream compose unmodified |
| Alternative API host port available | PASS | 8001 and 8010 verified FREE | No | Map `127.0.0.1:8001:8000`, or omit host port |
| 80/443 availability | CONDITIONAL | Host-free, no proxy installed, firewall-permitted via VM tags — but Internet-unreachable | No | Depends on B2 decision |
| 3478/5349 availability | CONDITIONAL | All four tcp/udp free on host; **no GCP ingress rule** | **YES for TURN — B4** | Approve firewall rules, or skip coturn |
| TURN UDP range suitability | CONDITIONAL | 49152–49200/udp entirely free; **ephemeral range 32768–60999 overlaps**; no ingress rule | **YES for TURN — B4** | Reserve ports via sysctl + open firewall, or skip coturn |
| External IP / reachable endpoint | **FAIL** | Access config `ONE_TO_ONE_NAT` with **empty** external-ip; egress via Cloud NAT `136.119.184.87` | **YES — B2** | Choose SSH tunnel / Cloudflare Tunnel / external IP |
| GCP firewall visibility | PASS | 9 rules listed successfully as `debalekha.chakraborty@tcs.com` | No | None |
| Outbound Internet | PASS | 11/11 endpoints resolved + TLS-reachable via Cloud NAT | No | None |
| Existing workload headroom | PASS | Only real AI workload is 452 MB ServiceDesk process; **0 containers running** | No | Respect ports 8000 and 3000 |
| Security isolation feasible | CONDITIONAL | Upstream publishes Postgres/Redis on `0.0.0.0`; `default-allow-internal` opens all ports to 10.128.0.0/9 | No | Localhost-bind everything; Voice Gateway adapter; no public ingress on this host |
| Dograh persistent storage feasible | CONDITIONAL | 5 named volumes required; `overlay2`/extfs healthy; disk at 82% | No | Free space first; set retention + log caps |
| **Overall readiness** | **CONDITIONAL** | Capacity strongly PASS; blocked on Compose v2 (B1) and inbound reachability (B2) | — | Clear B1–B4, then controlled port-remapped install |

## 24. HUMAN_INPUTS_REQUIRED

Based only on actual missing prerequisites:

1. **Approval to install Docker Compose v2**, and which method — add Docker's
   official apt repo, or drop the plugin binary into
   `/usr/local/lib/docker/cli-plugins/` (smaller, more reversible). *Clears B1.*
2. **Reachability decision** — SSH tunnel (recommended for Phase 2), Cloudflare
   Tunnel, or assign an external IP. *Clears B2.*
3. **Approval to run Dograh with a modified port mapping** rather than upstream
   defaults, delivered as a `docker-compose.override.yaml`. *Clears B3.*
4. **Approval to reclaim ~10.5 GB of dangling Docker images and build cache**
   on this shared VM (all 13 images are currently inactive).
5. **GCP firewall approval — only if coturn/public deployment is chosen:**
   TCP+UDP 3478, TCP+UDP 5349, UDP 49152–49200. *Clears B4.* Not needed for the
   tunnel-based PoC.
6. **Colocate vs. dedicated VM decision for anything Internet-facing** (§21
   recommends a dedicated VM at that point).
7. **Inference / STT / TTS provider choice** — all candidate endpoints are
   reachable; the selection itself is a business decision.
8. **Provider API credentials** — *Secret must be supplied through an approved
   secret mechanism later.*
9. **Approval to create persistent Docker volumes** (`postgres_data`,
   `redis_data`, `minio-data`, `nginx-generated`, `coturn-generated`), plus a
   **retention decision for call recordings and transcripts**, which are personal
   data.
10. **Confirmation that telemetry must be disabled** (`ENABLE_TELEMETRY=false`)
    for this enterprise PoC.

No secret value is requested or recorded anywhere in this report.

## 25. Future phase plan — NOT EXECUTED

| Phase | Scope | Gate |
|---|---|---|
| **1** | Dograh host installation — Compose v2, `docker-compose-local.yaml` + override, localhost-bound, `ENABLE_TELEMETRY=false`, no nginx/coturn | B1 cleared; disk reclaimed |
| **2** | Browser Web Call / Test Audio from the physical laptop via SSH tunnel to `http://localhost:3010`. **Empirically verify the WebRTC media path**; fall back to Cloudflare Tunnel if it fails | B2 decision made |
| **3** | Minimal local Voice Gateway — narrow adapter, `127.0.0.1` only | **HARD GATE:** if public exposure is needed, move to a dedicated VM first |
| **4** | Dograh → Voice Gateway → ServiceDesk single text turn | Phase 3 complete |
| **5** | Account Access conversational flow | Phase 4 complete |
| **6** | Identity verification + governed enable / password reset | Security review of the governance path |
| **7** | Optional real telephony | Business decision |

**No phase beyond readiness has been executed.**

---

*Assessment complete. Nothing was installed, started, stopped, restarted, opened,
committed, or pushed. The only filesystem change is the creation of
`dograh_voice/` containing this report and `README.md`.*
