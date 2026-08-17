# Isolated Dograh TURN Edge — Readiness & Design Plan

**Status: BUILT AND VERIFIED — 2026-08-15.** (Sections below were the approved
plan; §12 records what was actually built.) Dograh pinned at `dograh-v1.45.0`
(`48aa0f6`).

---

## 12. BUILD RECORD — what exists now

| Resource | Value |
|---|---|
| VPC / subnet | `turn-poc-vpc` / `turn-poc-subnet` (`10.200.0.0/29`, us-central1) — **no peering to `default`** |
| Static IP | `dograh-turn-ip` = **`34.44.75.208`** (reserved, IN_USE) |
| VM | `dograh-turn`, **`us-central1-c`**, `e2-micro`, Debian 12 bookworm, 10 GB pd-balanced |
| Internal IP | `10.200.0.2` |
| Service account | **none** (`--no-service-account --no-scopes`) |
| Shielded VM | secure boot + vTPM + integrity monitoring |
| coturn | **4.6.1-1** from bookworm main, systemd-managed |
| Firewall | `turn-allow-stun-turn` (udp/tcp 3478), `turn-allow-relay-range` (udp 49152-49200), `turn-allow-iap-ssh` (tcp 22 from 35.235.240.0/20) — all tag-scoped to `dograh-turn` |

### INCIDENT — open relay on first start, caught and closed

On the first `systemctl enable --now`, coturn started **without reading
`/etc/turnserver.conf`**. The log showed `Default realm:` empty and
`NO EXPLICIT LISTENER ADDRESS(ES) ARE CONFIGURED`; it bound `127.0.0.1`,
`10.200.0.2` and `::1` (its auto-discovery defaults) and **answered an
unauthenticated `Allocate` with `0x0103` success** — i.e. it was briefly an
open relay reachable from `0.0.0.0/0`.

Detected by the negative test in §9 step 3, which is exactly why that test
exists. Response:

1. `systemctl stop coturn` immediately (0 listeners confirmed).
2. Deleted both `0.0.0.0/0` firewall rules so diagnosis happened with **no**
   public exposure.
3. Confirmed the config itself was valid — running `turnserver -c
   /etc/turnserver.conf` manually as the `turnserver` user read every directive
   (realm, blacklists, `external-ip` whitelisting, single listener).
4. `systemctl restart coturn` with the config already in place → read correctly.
5. Re-created the firewall rules only after auth enforcement was proven.

**Root cause:** the initial `enable --now` activated the unit before it picked up
the newly written config file. **Durable rule: always `systemctl restart coturn`
after writing the config, then confirm `Default realm: dograh.com` appears in
the log before opening the firewall.** Note Debian's `coturn.service` has **no**
`EnvironmentFile`, so `TURNSERVER_ENABLED` in `/etc/default/coturn` is vestigial
under systemd and must not be relied on as a safety interlock.

Exposure window was roughly two minutes on a brand-new IP, with no inbound
traffic observed. Treat the secret as sound, but rotating it is cheap if desired.

### Verification results (all passing)

| Test | Result |
|---|---|
| Config actually read | `Default realm: dograh.com`; single listener `10.200.0.2`; 10 blacklist ranges applied; `Whitelisting external-ip private part: 10.200.0.2` |
| Relay ports reserved | `/proc/sys/net/ipv4/ip_local_reserved_ports` = `49152-49200` (ephemeral range remains `32768 60999`) |
| STUN Binding from Dograh VM | reply OK — TURN sees `136.119.184.87` (Cloud NAT) |
| **Unauthenticated Allocate** | **`0x0113` error 401 — refused** |
| **Valid HMAC-SHA1 credential** | **ALLOCATE SUCCESS, relayed = `34.44.75.208:49183`** — public IP, correct range ⇒ `external-ip` mapping proven |
| **Wrong shared secret** | **401 — refused** |

### Dograh side (applied after verification, per §6)

`runtime/.env`: `ENABLE_COTURN=true`, `TURN_HOST=34.44.75.208`, `TURN_PORT=3478`,
`TURN_CREDENTIAL_TTL=3600`, `FORCE_TURN_RELAY=true`, `TURN_SECRET=<git-ignored>`.
Only the `api` container was recreated. Health now reports
`turn_enabled: true`, `force_turn_relay: true`; UI reports
`backend.status: reachable`.

### External IP cleanup (requested)

| VM | Before | After |
|---|---|---|
| `dev-windows-instance` | `35.206.99.182` | **kept** (as requested) |
| `dograh-turn` | — | `34.44.75.208` (required for TURN) |
| `infra-demo-linux-vm-1` | `34.72.86.48` | **removed** |
| `infra-demo-linux-vm-2` | `34.170.171.188` | **removed** |
| `infra-demo-windows-vm-1` | `35.209.229.32` | **removed** — had `3389`, `80`, `443` world-reachable |
| `infra-demo-windows-vm-2` | none | none (no access config) |
| `dev-linux-instance` | none | none |

Safe because Cloud NAT on `default`/us-central1 is
`ALL_SUBNETWORKS_ALL_IP_RANGES`, so outbound is preserved for every zone, and
IAP SSH/RDP (`35.235.240.0/20`) does not require an external IP. All three
released IPs confirmed unreachable afterwards.

**Auditing lesson:** a stopped instance reports an empty `natIP` even when it
still has an access config, so it will acquire a fresh public IP the moment
someone starts it. `infra-demo-windows-vm-1` was `TERMINATED` during the first
sweep and later started with `35.209.229.32`. **Audit
`networkInterfaces[0].accessConfigs[0].name`, not `natIP`** — the name is always
populated when a config exists. (An intermediate check of mine that concatenated
several possibly-empty `value()` fields produced false positives; the `name`
column is the reliable discriminator.)

### Final public-IP surface for the project

| Instance | Public IP |
|---|---|
| `dev-windows-instance` | `35.206.99.182` (intentional) |
| `dograh-turn` | `34.44.75.208` (TURN edge, 3478 + relay range only) |
| *everything else* | **none** |

---

---

## 0. Answer to the framing question

> *Can we safely expose coturn only on the existing VM while proving every other
> ServiceDesk/Dograh port stays unreachable externally?*

**No.** Not without altering shared project-wide firewall posture. This is not a
judgement call — four pre-existing `0.0.0.0/0` ingress rules would activate the
instant `dev-linux-instance` receives an external IP:

| Rule | Allows | Target tags | Applies to dev-linux-instance? |
|---|---|---|---|
| `default-allow-ssh` | `tcp:22` | **none → all instances** | **YES** |
| `default-allow-rdp` | `tcp:3389` | **none → all instances** | **YES** |
| `default-allow-http` | `tcp:80` | `http-server` | **YES** — VM carries this tag |
| `default-allow-https` | `tcp:443` | `https-server` | **YES** — VM carries this tag |

So attaching an external IP would immediately publish SSH to the entire internet
on the host that holds `sd_chat/credentials.json`, `sd_chat/.env`, and Entra
automation capable of enabling accounts and resetting passwords.

ServiceDesk `:8000` itself would stay unreachable (no allow rule), and Dograh is
loopback-bound — but that is not the point. The exposure of 22/80/443/3389 is
the disqualifier. Making it safe would require removing the VM's network tags
and adding higher-priority DENY rules for 22/3389 — i.e. changing a shared lab
VM *and* project-wide posture, for a PoC.

**A dedicated TURN host is the correct design, and it is what this plan covers.**

---

## 1. Root cause of `ICE IN_PROGRESS` — proven, and it changes the framing

I tested rather than assumed. Two findings, one of which overturns the obvious
hypothesis:

### 1a. Cloud NAT is *not* symmetric — so that is not the blocker

Same UDP source socket, two different STUN servers:

```
local source port      : 43154
via stun.l.google.com  : 136.119.184.87:1026
via stun1.l.google.com : 136.119.184.87:1026   <- SAME public port
=> ENDPOINT-INDEPENDENT MAPPING (cone-like)
```

UDP egress through Cloud NAT works, and the mapping is endpoint-independent. A
symmetric-NAT explanation would have been wrong.

### 1b. The real cause — the API has no reachable candidate to offer at all

```
api container IP : 172.18.0.5   (Docker bridge, gateway 172.18.0.1)
host external IP : NONE
ENABLE_COTURN    : false
STUN in constants.py : none configured anywhere
```

The Dograh API's ICE candidate set is therefore **`{172.18.0.5}`** — a
Docker-internal address, doubly unroutable from the laptop (Docker bridge, then
a VM with no public IP). With no STUN and no TURN configured, it can generate
neither a server-reflexive nor a relay candidate. The browser has nothing it can
ever pair with, so connectivity checks run forever and never converge.

**Consequence: TURN is mandatory here, not an optimisation.** No amount of
firewall or NAT tuning fixes a peer that has no publicly reachable candidate to
advertise. This is exactly what a TURN relay supplies.

---

## 1b. Evaluation of reusing an existing VM (`infra-demo-linux-vm-1/2`)

Checked 2026-08-15. **Correction to an earlier listing: both are `RUNNING`, not
`TERMINATED`, and both already hold public IPs.**

| Property | `infra-demo-linux-vm-1` | `infra-demo-linux-vm-2` |
|---|---|---|
| Status | RUNNING | RUNNING |
| Machine type | `e2-custom-medium-2048` | **`e2-small`** (matches plan) |
| External IP | `34.72.86.48` — **ephemeral** | `34.170.171.188` — **ephemeral** |
| **Service-account scopes** | **`cloud-platform` (full project API)** | 6 narrow scopes (logging/monitoring/trace/servicecontrol, `devstorage.read_only`) |
| Network tags | `backup-target`, `http-server`, `https-server` | `http-server`, `https-server` |
| OS | `ubuntu-minimal-2204-jammy-v20260114` | boot disk cloned from `infra-demo-linux-vm-1-boot-image` (same Ubuntu 22.04 lineage) |
| Disk | 10 GB `pd-balanced` | 10 GB `pd-balanced` |
| VPC / subnet | `default` / `default` | `default` / `default` |
| Actually serving | stock **"Welcome to nginx!"** (612 B, nginx/1.18.0 Ubuntu) | identical stock nginx page |
| Public ports open | `22`, `80` | `22`, `80` |

### `infra-demo-linux-vm-1` — DISQUALIFIED

Its service account carries **`https://www.googleapis.com/auth/cloud-platform`**
— full project API access. Placing an internet-facing relay on that host means a
coturn compromise yields a metadata token with project-wide GCP authority. That
is disqualifying on its own. The `backup-target` tag additionally opens
`tcp:4505` to `0.0.0.0/0` via `allow-backup-4505-backup-target`.

### `infra-demo-linux-vm-2` — the only usable candidate, with six conditions

1. **Default VPC is immutable.** A VM's NIC network/subnet cannot be changed
   after creation. Reusing this VM therefore **abandons the isolated-VPC design
   in §3**, and `denied-peer-ip` becomes the *sole* control preventing a relay
   into `10.128.0.0/9` → `dev-linux-instance:8000`. This is the material loss.
2. **Ephemeral IP must be promoted to static** — otherwise `TURN_HOST` and
   coturn's `external-ip` break on the next stop/start. Doable in place with no
   downtime and no IP change:
   `gcloud compute addresses create dograh-turn-ip --addresses=34.170.171.188 --region=us-central1`
3. **Remove `http-server` / `https-server` tags** to close 80/443, which are
   world-open right now.
4. **Narrow or remove the service account** — requires a STOP, so do step 2
   first or the IP changes. Ideally attach no service account at all.
5. **Unaudited disk provenance.** The boot disk is a clone of vm-1's image;
   prior content is unknown. Re-imaging it from clean Debian 12 is essentially
   equivalent to creating a new VM.
6. **Ubuntu 22.04, not Debian 12.** coturn comes from jammy `universe` (4.5.x)
   rather than bookworm, diverging from this plan and from upstream's
   `coturn/coturn:4.8.0`.

### Cost argument for reuse is weaker than it appears

Both VMs are **running and billing right now while serving nothing but a default
nginx page**. Two idle `e2-small`-class instances cost roughly $25/month
combined — more than the entire proposed TURN host (~$11–13/month including the
static IP). **Stopping or deleting the two idle demo VMs would more than fund a
purpose-built TURN host.**

### Recommendation

**Prefer the dedicated VM in §2/§3.** Use `infra-demo-linux-vm-2` only if
avoiding any new resource is a hard requirement — and accept that conditions 1
and 5 remove most of the isolation this phase exists to provide.

### Pre-existing exposure, worth raising separately

Both VMs currently accept **SSH from `0.0.0.0/0`** (`default-allow-ssh`, no
target tags) and serve an untouched January-vintage nginx on a public IP. That
is independent of this project and should be addressed on its own merits.

---

## 2. Recommended target

| Item | Recommendation | Rationale |
|---|---|---|
| Machine type | **`e2-micro`** (2 shared vCPU, 1 GB) | One relayed audio call ≈ 128 kbps total. Trivially light. `e2-small` is the upgrade if packet loss appears under burst throttling. |
| OS | **Debian 12 bookworm** — image family `debian-12` (`debian-12-bookworm-v20260811`) | Matches existing fleet; coturn packaged in `bookworm/main` |
| Disk | **10 GB `pd-balanced`** | Debian minimum is 10 GB; coturn stores nothing |
| Zone | `us-central1-c` | Same region as `dev-linux-instance` — lowest relay latency |
| coturn | **native `apt install coturn`**, systemd-managed | Smallest footprint on a 1 GB host; no Docker daemon needed. Parity alternative: `coturn/coturn:4.8.0`, the exact image upstream Dograh uses. |
| External IP | **static (reserved) regional IPv4** | `TURN_HOST` and coturn's `external-ip=` are literal IPs. An ephemeral IP changes on stop/start and would silently break TURN. Billing is identical for in-use static vs ephemeral. |
| Name / tag | `dograh-turn` / network tag `dograh-turn` | All firewall rules scope to this tag only |

**Contains nothing else:** no ServiceDesk data, no Dograh database, no
application workload, no Entra credentials, no copy of `dograh_voice/runtime/.env`.
Only `turnserver.conf` and the shared TURN secret.

---

## 3. Network topology — and why a separate VPC

```
   Physical laptop browser
            │  turn:<TURN_PUBLIC_IP>:3478  (udp/tcp) + relay 49152-49200/udp
            ▼
   ┌───────────────────────────────┐
   │  dograh-turn  (NEW VM)        │   VPC: turn-poc-vpc  ← NO peering to default
   │  coturn only, static ext. IP  │   tag: dograh-turn
   └───────────────────────────────┘
            ▲
            │  outbound-initiated allocation via Cloud NAT (UDP proven working)
            │
   ┌───────────────────────────────┐
   │  dev-linux-instance           │   VPC: default, 10.128.0.2, NO external IP
   │  ServiceDesk :8000            │   UNCHANGED — no firewall/IP/config change
   │  Dograh api/ui loopback-only  │
   └───────────────────────────────┘
```

### Put the TURN host in its own VPC — this is the important decision

A TURN server is, by definition, a **relay**: an authenticated client asks it to
forward packets to an arbitrary peer address. If it sits in the `default` VPC it
inherits `default-allow-internal` (`10.128.0.0/9`, **all TCP and UDP**), which
makes it a clean pivot into the internal network — including
`dev-linux-instance:8000`, where ServiceDesk binds `0.0.0.0`.

The `default` VPC also already contains **`dev-windows-instance`
(35.206.99.182)** — a running VM with a public IP, reachable on `tcp:3389` from
`0.0.0.0/0` via `default-allow-rdp`. That is a pre-existing condition outside
this task's scope, but it is precisely why the TURN host should not be dropped
into the same broadcast domain and trusted to `denied-peer-ip` alone.

**A dedicated `turn-poc-vpc` makes the pivot structurally impossible** rather
than merely configured-away. It costs nothing extra. `denied-peer-ip` is then
defence in depth, not the only control.

Dograh reaches TURN over its public IP via Cloud NAT — already proven to work
for UDP (§1a), so no VPC peering is needed and none should be created.

---

## 4. Exact firewall rules

All scoped to target tag `dograh-turn` in `turn-poc-vpc`. A new VPC has an
implied deny-all ingress, so these are the only openings.

| # | Name | Direction | Source | Protocol/Ports | Target tag |
|---|---|---|---|---|---|
| 1 | `turn-allow-stun-turn` | INGRESS | `0.0.0.0/0` | `udp:3478`, `tcp:3478` | `dograh-turn` |
| 2 | `turn-allow-relay-range` | INGRESS | `0.0.0.0/0` | `udp:49152-49200` | `dograh-turn` |
| 3 | `turn-allow-iap-ssh` | INGRESS | `35.235.240.0/20` | `tcp:22` | `dograh-turn` |

**Deliberately NOT opened:** `5349` (no TLS listener in this PoC — see §5),
`80`, `443`, `3389`, and **`tcp:22` from `0.0.0.0/0`**. Administration is IAP
SSH only (`35.235.240.0/20` is Google's IAP forwarding range).

**Zero firewall changes on `dev-linux-instance`.** Its outbound path to TURN uses
existing Cloud NAT and the default allow-all egress.

---

## 5. coturn configuration

Derived from upstream `deploy/templates/turnserver.remote.conf.template` at
`48aa0f6` (sha256 `255426123315fa8b…62e6b0f`), which confirms the authentication
mechanism. **Placeholders only — no real secret appears here or in the repo.**

### Confirmed: what Dograh's HMAC-SHA1 temporary credentials require

Upstream's own template settles it — exactly two directives:

```
use-auth-secret
static-auth-secret=<SHARED_SECRET>
```

That is coturn's **TURN REST API** mode (RFC 5389 long-term credential mechanism
with a time-limited username). The client username is
`<unix-expiry-timestamp>:<user>` and the password is
`base64(HMAC-SHA1(<SHARED_SECRET>, username))`. Dograh generates these; coturn
recomputes and verifies them. The secret must be **byte-identical** on both
sides. No static user accounts are created — `lt-cred-mech` with a `user=` line
must **not** be used.

Confirmed Dograh-side settings from `api/constants.py` at this tag:

```
ENABLE_COTURN         default false
TURN_SECRET           (no default)
TURN_HOST             default PUBLIC_HOST or "localhost"
TURN_PORT             default 3478
TURN_TLS_PORT         default 5349
TURN_CREDENTIAL_TTL   default 86400   (24h — recommend lowering to 3600)
FORCE_TURN_RELAY      default false
```

`constants.py` also notes `TURN_HOST` should "stay a raw IP (coturn's
`external-ip` needs one)" and that it is "set explicitly only when the TURN
server runs on a separate host from the app" — precisely our case.

### Config skeleton (`/etc/turnserver.conf`)

```ini
# ── Listeners ────────────────────────────────────────────────────────────
listening-port=3478
listening-ip=__PRIVATE_IP__          # bind the NIC address, not 0.0.0.0

# TLS listener intentionally DISABLED for this PoC: no certificate is
# provisioned and 5349 is not opened in the firewall.
no-tls
no-dtls

# ── Relay range (must match firewall rule #2 exactly) ────────────────────
min-port=49152
max-port=49200

# ── GCE 1:1 NAT — THE most common cause of a silently broken TURN ───────
# A GCE NIC only ever holds the PRIVATE address; the public IP is 1:1 NAT
# applied outside the guest. Without this mapping coturn advertises its
# private 10.x relay address and every ICE check fails exactly as it does
# today. Use the explicit PUBLIC/PRIVATE form.
external-ip=__PUBLIC_IP__/__PRIVATE_IP__

# ── Realm ────────────────────────────────────────────────────────────────
realm=dograh.com                     # kept identical to upstream template

# ── Authentication: TURN REST API, time-limited HMAC-SHA1 credentials ────
use-auth-secret
static-auth-secret=__TURN_SHARED_SECRET__

# ── Hardening — NOT in the upstream template; added deliberately ─────────
# Upstream ships no peer restrictions at all. Unrestricted, any authenticated
# client could relay into private ranges and the GCP metadata service.
denied-peer-ip=0.0.0.0-0.255.255.255
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=100.64.0.0-100.127.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
denied-peer-ip=169.254.0.0-169.254.255.255      # GCP metadata 169.254.169.254
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=::1
denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
denied-peer-ip=fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff

no-tcp-relay                          # media needs UDP allocations only
no-multicast-peers
fingerprint
stale-nonce=600
user-quota=12
total-quota=100

# ── Ops ──────────────────────────────────────────────────────────────────
no-cli
log-file=stdout
simple-log
```

### Kernel setting — required, easy to miss

The relay range `49152-49200` sits **inside** Linux's default ephemeral range
(`32768 60999`, confirmed on the existing VM). The kernel can transiently occupy
a relay port and coturn will fail to bind it, producing intermittent, hard-to-
diagnose allocation failures. Reserve the range:

```
# /etc/sysctl.d/60-coturn-relay.conf
net.ipv4.ip_local_reserved_ports = 49152-49200
```

---

## 6. How Dograh will later reference TURN

**No change until TURN is verified independently.** Then, in
`dograh_voice/runtime/.env` only (never in a tracked file):

```
ENABLE_COTURN=true
TURN_HOST=<TURN_PUBLIC_IP>        # raw IPv4, no DNS needed
TURN_PORT=3478
TURN_SECRET=<same shared secret as coturn static-auth-secret>
TURN_CREDENTIAL_TTL=3600          # tighten from the 86400 default
FORCE_TURN_RELAY=true             # for the test only; set false afterwards
```

Then recreate **only** the API container, exactly as in the previous phases:

```bash
R=/home/AI_POC/servicedesk-ai/dograh_voice/runtime
sudo docker compose --project-directory "$R" \
  -f "$R/docker-compose.yaml" -f "$R/docker-compose.override.yaml" \
  up -d --no-deps --force-recreate api
```

Expected afterwards: `/api/v1/health` reports `turn_enabled: true` and
`force_turn_relay: true`.

The `cloudflared:127.0.0.1` fail-fast entry in the override stays as-is — it is
unrelated to TURN.

---

## 7. Expected monthly cost components

Approximate, `us-central1`, on-demand. **Confirm against the GCP pricing
calculator before approving — these figures may be stale and are indicative
only.**

| Component | Basis | Approx. / month |
|---|---|---|
| `e2-micro` instance | 730 h on-demand | ~$6–7 |
| 10 GB `pd-balanced` | ~$0.10/GB-month | ~$1 |
| Static external IPv4 (in use) | ~$0.005/h | ~$3.50–4 |
| Internet egress (relayed media) | ~$0.12/GB; audio ≈ 128 kbps ⇒ ~1.4 GB per 24 h of continuous call | <$1 for PoC usage |
| New VPC / subnet / firewall rules | no charge | $0 |
| **Total** | | **~$11–13 / month** |

Notes: `e2-micro` in `us-central1` may be free-tier eligible (one per month), but
the free tier covers **neither** the external IPv4 **nor** egress, so budget the
IP regardless. Cost drops to ~$4/month if the VM is stopped between demos —
**but keep the IP reserved**, or `TURN_HOST` changes and TURN breaks silently.

---

## 8. Commands to run *after* approval

Nothing below has been executed.

```bash
PROJECT=ai-and-automation-coe
REGION=us-central1
ZONE=us-central1-c

# ── 8.1 Isolated VPC (no peering to default — this is the security boundary)
gcloud compute networks create turn-poc-vpc \
  --project=$PROJECT --subnet-mode=custom

gcloud compute networks subnets create turn-poc-subnet \
  --project=$PROJECT --network=turn-poc-vpc \
  --region=$REGION --range=10.200.0.0/29

# ── 8.2 Static external IP (reserve BEFORE the VM so it never changes)
gcloud compute addresses create dograh-turn-ip \
  --project=$PROJECT --region=$REGION

gcloud compute addresses describe dograh-turn-ip \
  --project=$PROJECT --region=$REGION --format='value(address)'   # -> TURN_PUBLIC_IP

# ── 8.3 Firewall — three rules, all tag-scoped
gcloud compute firewall-rules create turn-allow-stun-turn \
  --project=$PROJECT --network=turn-poc-vpc --direction=INGRESS \
  --action=ALLOW --rules=udp:3478,tcp:3478 \
  --source-ranges=0.0.0.0/0 --target-tags=dograh-turn

gcloud compute firewall-rules create turn-allow-relay-range \
  --project=$PROJECT --network=turn-poc-vpc --direction=INGRESS \
  --action=ALLOW --rules=udp:49152-49200 \
  --source-ranges=0.0.0.0/0 --target-tags=dograh-turn

gcloud compute firewall-rules create turn-allow-iap-ssh \
  --project=$PROJECT --network=turn-poc-vpc --direction=INGRESS \
  --action=ALLOW --rules=tcp:22 \
  --source-ranges=35.235.240.0/20 --target-tags=dograh-turn

# ── 8.4 The VM
gcloud compute instances create dograh-turn \
  --project=$PROJECT --zone=$ZONE \
  --machine-type=e2-micro \
  --image-family=debian-12 --image-project=debian-cloud \
  --boot-disk-size=10GB --boot-disk-type=pd-balanced \
  --subnet=turn-poc-subnet \
  --address=$(gcloud compute addresses describe dograh-turn-ip \
              --project=$PROJECT --region=$REGION --format='value(address)') \
  --tags=dograh-turn \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
  --scopes=logging-write,monitoring-write        # NO broad API scopes

# ── 8.5 Install coturn (via IAP SSH; no public SSH)
gcloud compute ssh dograh-turn --project=$PROJECT --zone=$ZONE --tunnel-through-iap
#   sudo apt-get update && sudo apt-get install -y coturn
#   coturn -V                                   # record the actual version
#   sudo tee /etc/sysctl.d/60-coturn-relay.conf   <<< 'net.ipv4.ip_local_reserved_ports = 49152-49200'
#   sudo sysctl --system
#   sudo sed -i 's/^#TURNSERVER_ENABLED=1/TURNSERVER_ENABLED=1/' /etc/default/coturn
#   sudo install -m 0640 -o root -g turnserver /dev/stdin /etc/turnserver.conf  <<< '<config from §5>'
#   sudo systemctl enable --now coturn && systemctl status coturn --no-pager
```

**Secret handling:** generate once with `openssl rand -hex 32`. It goes in
exactly two places — `/etc/turnserver.conf` (mode `0640`, root:turnserver) on the
TURN VM, and `dograh_voice/runtime/.env` (mode `0600`, git-ignored) on the Dograh
VM. It is never printed, never committed, never placed in a tracked file.

---

## 9. Test plan

Run in order. **Do not skip to step 4** — each step isolates one failure domain.

### Step 1 — Browser → TURN (from the physical laptop)

Generate a temporary credential, then use the WebRTC Trickle ICE page
(`https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/`) with
server `turn:<TURN_PUBLIC_IP>:3478`.

```bash
USER="$(( $(date +%s) + 3600 )):poctest"
PASS=$(printf '%s' "$USER" | openssl dgst -sha1 -hmac "$TURN_SHARED_SECRET" -binary | base64)
```

- **PASS:** a candidate of type **`relay`** appears.
- **FAIL:** only `host`/`srflx` ⇒ firewall or `external-ip` wrong.

### Step 2 — Dograh VM → TURN (from `dev-linux-instance`, outbound only)

```bash
nc -zvu <TURN_PUBLIC_IP> 3478          # UDP reachability
turnutils_uclient -v -u "$USER" -w "$PASS" <TURN_PUBLIC_IP>   # if coturn-utils present
```

UDP egress through Cloud NAT is already proven working (§1a), so a failure here
points at the TURN VM's firewall, not at Cloud NAT.

### Step 3 — Authenticated allocation (positive **and** negative)

- Valid HMAC credential ⇒ **Allocate succeeds**, relayed transport address returned.
- Deliberately wrong secret ⇒ **401 Unauthorized**.
- Expired timestamp ⇒ **401**.

The negative cases matter as much as the positive one: they prove the relay is
not open to the internet. Also confirm a relay attempt toward `10.128.0.2` or
`169.254.169.254` is **refused** by `denied-peer-ip`.

### Step 4 — Dograh Test Audio

Set `ENABLE_COTURN=true` + `FORCE_TURN_RELAY=true`, recreate the API container
only, then from the laptop (IAP forwards for **both** 3010 and 8001 live) run
Test Audio.

Expect ICE to leave `IN_PROGRESS` and reach `connected`/`completed`, with the
selected pair using **relay** candidates on both sides. Then set
`FORCE_TURN_RELAY=false` and re-test to confirm normal operation.

**Verify throughout:** ServiceDesk PID unchanged, `:8000` `/health`=200, Next.js
`:3000` unchanged, no new host listener on `dev-linux-instance`.

---

## 10. Rollback / delete plan

Full teardown, reverse order of creation. Leaves no trace and costs nothing.

```bash
# Dograh side first — revert to the current known-good state
#   in dograh_voice/runtime/.env: ENABLE_COTURN=false, remove TURN_HOST/TURN_PORT/
#   TURN_SECRET/FORCE_TURN_RELAY, then recreate ONLY the api container.

gcloud compute instances delete dograh-turn --project=$PROJECT --zone=$ZONE --quiet
gcloud compute firewall-rules delete turn-allow-stun-turn turn-allow-relay-range \
       turn-allow-iap-ssh --project=$PROJECT --quiet
gcloud compute addresses delete dograh-turn-ip --project=$PROJECT --region=$REGION --quiet
gcloud compute networks subnets delete turn-poc-subnet --project=$PROJECT --region=$REGION --quiet
gcloud compute networks delete turn-poc-vpc --project=$PROJECT --quiet
```

Rollback touches **nothing** on `dev-linux-instance` beyond the `.env` revert and
an API container recreate — no firewall, no IP, no ServiceDesk change, because
none were ever made.

**Partial rollback (keep the design, stop the spend):** stop the VM but keep the
reserved IP (~$4/month). Do **not** release the IP — `TURN_HOST` and coturn's
`external-ip` both hard-code it.

---

## 11. Open items for human decision

1. Approve creation of a **separate VPC** (recommended) vs. placing TURN in
   `default` with `denied-peer-ip` as the only control (**not recommended** —
   see §3).
2. Approve `e2-micro` vs `e2-small`.
3. Confirm cost figures in §7 against the pricing calculator.
4. Approve opening `udp/tcp 3478` and `udp 49152-49200` to `0.0.0.0/0` on the
   new tag only.
5. TURN shared secret — *to be supplied/generated through an approved secret
   mechanism; no value in this document.*
6. Out of scope but worth raising separately: `dev-windows-instance`
   (`35.206.99.182`) is reachable on `tcp:3389` from `0.0.0.0/0` via
   `default-allow-rdp`.
