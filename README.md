# ServiceDesk AI

## Runtime environment

This project uses the shared application interpreter:

```
/home/AI_POC/venvs/debalekha/bin/python
/home/AI_POC/venvs/debalekha/bin/python -m pip install -r requirements-gcp-vdi.txt
```

Installing into `debalekha` is fine — it is the application environment.

**Never install packages into `/home/AI_POC/venvs/tactics`.** That interpreter is
the frozen scientific environment; adding ServiceDesk dependencies would invalidate
its exact-runtime provenance.

## Account Access backend

Account Access defaults to the non-executing `AD_ACCOUNT_MODE=off` mode. Use the
repository's existing Microsoft Graph application credentials for real Microsoft
Entra user profile, `accountEnabled`, and enable-account operations:

```ini
AD_ACCOUNT_MODE=graph
```

Graph status reads relevant account metadata directly from `/users/{UPN}`. Microsoft
Graph does not expose a current AD DS lockout boolean on the user resource, so Graph
mode reports lock state as unknown rather than claiming the account is unlocked.
For authorized Account Access diagnosis, the backend also samples up to 20 sign-in
events from the previous 24 hours through `/auditLogs/signIns`. It returns sanitized
failure, application, and device evidence, including any error code `50053`, while
keeping the current lock state unknown and never selecting remediation from log
evidence alone.

Sign-in investigation requires the Microsoft Graph `AuditLog.Read.All` application
permission with administrator consent and an applicable Microsoft Entra ID P1/P2
license. If that permission or service is unavailable, account profile diagnosis
continues and reports the sign-in evidence limitation explicitly. A real AD DS
connector is still required for authoritative AD DS lock inspection and unlock.

The deterministic in-process backend is retained only as a unit-test seam. It has
no environment-driven per-user status lists and must not be used to represent live
directory state. Unlocking never enables an account, and enabling never clears
lockout.

### Account Access identity orchestration

Protected Account Access conversations use a deterministic controller rather than
letting the language model assemble privileged calls. Every diagnosis, recheck,
and action refreshes and binds:

- the session requester corroborated against the exact Microsoft Graph user;
- the exact target Graph user and the target's current Graph manager;
- registered-device inventories for both requester and target; and
- the canonical self-or-current-manager policy decision.

A successful empty registered-device list is valid. A failed device or manager
query stops the flow. Device registration is recorded as security context only;
it does not grant endpoint-remediation permission. Real Graph account tools and
password reset also require the controller's fresh verification ID, so a manually
sequenced policy call cannot bypass device evidence.

Diagnosis creates a short-lived target/action-bound offer. Confirmation accepts no
target, manager, device, or action arguments and must arrive in a later ADK user
invocation. After enablement, any follow-up unlock is a new offer requiring a new
confirmation.

The current portal supplies the requester through session persona state. Graph
corroboration verifies that the claimed UPN/object exists and matches, but it is not
a replacement for interactive user authentication. A production deployment must
populate that persona from validated Entra ID authentication claims at the backend
trust boundary.

## GCP Windows virtual desktop PoC

This proof of concept treats a Windows VM on Google Compute Engine as a single-user
virtual desktop. It is not Google Workspace and it does not reuse the AWS WorkSpaces
diagnostic model. The portal performs read-only login and performance diagnosis
against real Compute Engine, Cloud Monitoring, and Cloud Logging evidence.

### Authentication and assignment

Local real-mode validation uses Google Application Default Credentials. The VM uses
a keyless service account limited to writing Ops Agent logs and metrics. Chat input
cannot supply a project, zone, VM name, Windows username, or filesystem path. Those
values come from a private mapping outside Git:

```ini
GCP_VDI_MODE=gcp
GCP_VDI_MAPPING_PATH=/secure/local/path/gcp_vdi_user_map.json
```

The authenticated `identity_context.upn` must exactly match the requested user and
an entry in that mapping. Current scope is self-service only. `off` is the safe
default, `demo` uses fake test fixtures, and `gcp` uses real APIs. A real API failure
never falls back to demo success.

### Evidence and threshold

Host CPU, memory, disk, and network are observations from Cloud Monitoring. The
Compute Engine received/sent byte counters are DELTA metrics: the result labels
them `aggregation=latest_delta`, includes their observed 60-second period, and
does not call them bandwidth, throughput, or a lookback-window total. VM running
duration is calculated from Compute Engine's `last_start_timestamp`, not
misreported from a latest 60-second uptime-delta bucket.
Windows and RDP session events plus `servicedesk_rdp_telemetry` come from Cloud
Logging through Google Ops Agent. Missing evidence remains unavailable rather than
becoming zero.

The bootstrap validates one bounded 30-second collector window synchronously and
then registers a one-minute repeating task. `IgnoreNew` is intended to prevent
parallel collectors, and every collector child is capped at 45 seconds. The task's
first trigger is scheduled 30 seconds after registration and its repetition plus
the VM have a three-hour safety boundary.

**Recurring scheduled User Input Delay collection is not yet live-validated.**
Real validation has proved the synchronous startup sample and task registration,
but it has not yet proved a later scheduled execution. Registration and unit tests
are not evidence that recurring collection is working. Until a post-registration
task run, successful/understood `LastTaskResult`, corresponding audit cycle, fresh
Cloud Logging record, and active-session counter value are all observed, recurring
User Input Delay must be treated as unavailable.

With no active session, the collector publishes capability/session state without
querying the session counter. Each native session/counter read runs in its own
2.5-second bounded child and is terminated as a process tree if Windows session
query or PDH stalls. Wildcard counter-set discovery occurs only once during
bootstrap; the validated `User Input Delay per Session` path is persisted locally
and reused by the child probes. A probe identifies active `rdp-tcp` session IDs
from Windows session state and selects only matching numeric counter instances.
Those IDs are used only in process memory and are never written to telemetry or
audit output. The probe emits no user or session identity.
The collector records only timestamp, active-session count, counter availability, and
maximum **RDP User Input Delay**. It does not record usernames, keystrokes, clipboard
content, credentials, or user input. User Input Delay is queued Windows application
input responsiveness, not network RTT or AWS WorkSpaces `InSessionLatency`.
The collector's bounded execution audit records timestamps, phases, exit codes,
and sanitized ServiceDesk task metadata. Unexpected action/principal values are
redacted. It contains no user or session identity.

The only explicit PoC performance boundary is:

```text
RDP User Input Delay > 200 ms
```

This boundary follows Microsoft Remote Desktop guidance. Exactly 200 ms is not a
breach. The PoC does not invent CPU, memory, disk, or network severity thresholds.

### Shared lab-machine boundary

The reused Windows lab VM also supports SCCM/ConfigMgr and infra-domain testing.
The PoC bootstrap must not modify domain membership, SCCM services/configuration,
endpoint-management policy, DNS, Windows firewall, registered devices, or existing
test data. Its in-guest footprint is limited to Google Ops Agent configuration and
the separate `C:\ProgramData\ServiceDeskVDI` telemetry collector/scheduled task.
Before the bootstrap first changes Ops Agent user configuration, it makes a
rollback-safe backup. It updates the file only when it is empty, exactly matches
the legacy ServiceDesk configuration, or exactly matches the ServiceDesk-owned
snapshot. An unrelated or subsequently modified user configuration is preserved
and causes a safe stop requiring an explicit merge; it is never overwritten.

### Cost and lifecycle

The PoC uses one `e2-medium` Windows VM with a 50 GB balanced persistent disk, no
GPU, no static IP, and a three-hour maximum run duration whose action is `STOP`.
The VM is reached through IAP TCP forwarding; TCP 3389 must not be made public for
the PoC. No user-defined Monitoring metric is created.

Start and stop an approved mapped demo VM explicitly:

```bash
gcloud compute instances start INSTANCE --project=PROJECT --zone=ZONE
gcloud compute instances stop INSTANCE --project=PROJECT --zone=ZONE
```

Real validation requires ADC, a private mapping, a secure Windows credential created
outside chat, a genuine IAP/RDP session, and `GCP_VDI_MODE=gcp`. Known limitations are
that diagnosis is read-only, an inactive RDP session has no User Input Delay value,
and inconclusive evidence requires escalation rather than automatic password reset
or infrastructure remediation.
