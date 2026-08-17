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
default, `demo` uses dummy test fixtures, and `gcp` uses real APIs. A real API failure
never falls back to demo success.

The mapping may contain an optional safe `display_name`; otherwise the portal uses
`Shared Virtual Workstation`. Raw project, zone, instance name, numeric instance ID,
and private IP remain controller-only. A sample tracked contract is provided
at `examples/gcp_vdi_user_map.example.json`. It documents the schema only and is
never loaded at runtime. The real mapping is stored under `.local/`, which is
outside Git, and is resolved through `GCP_VDI_MAPPING_PATH`.

### Evidence and threshold

Host CPU, memory, disk, and network are observations from Cloud Monitoring. The
Compute Engine received/sent byte counters are DELTA metrics: the result labels
them `aggregation=latest_delta`, includes their observed 60-second period, and
does not call them bandwidth, throughput, or a lookback-window total. VM running
duration is calculated from Compute Engine's `last_start_timestamp`, not
misreported from a latest 60-second uptime-delta bucket.
Windows and RDP session events come from Cloud Logging through Google Ops Agent.
The collector publishes its identity-free JSON through the fixed `ServiceDeskVDI`
Windows Application event source (telemetry event `7101`, execution audit event
`7102`); bounded atomic files under `C:\ProgramData\ServiceDeskVDI` remain local
diagnostic evidence. Missing evidence remains unavailable rather than becoming zero.

The bootstrap validates one bounded 30-second collector window synchronously and
then registers a one-minute repeating task. `IgnoreNew` is intended to prevent
parallel collectors, and every collector child is capped at 45 seconds. The task's
first trigger is given a two-minute registration runway and must have a future
`NextRunTime`; its repetition plus the VM have a three-hour safety boundary.

One-time read-only live discovery validated the Windows `RemoteFX Network(*)\Current
TCP RTT` counter with an active RDP session. Recurring telemetry and production
diagnosis preserve unavailable values as null; portal conversational behavior still
requires manual validation after deployment.

With no active session, the collector publishes capability/session state without
querying the session counter. Each native session/counter read runs in its own
5-second bounded child and is terminated as a process tree if Windows session
query or PDH stalls. Wildcard counter-set discovery occurs only once during
bootstrap; the validated `User Input Delay per Session` and `RemoteFX Network(*)\Current
TCP RTT` paths are persisted locally and reused by child probes. A probe identifies
active `rdp-tcp` sessions and matches each counter's documented instance form.
Those IDs are used only in process memory and are never written to telemetry or
audit output. The probe emits no user or session identity.
The collector records only timestamp, active-session count, counter availability,
maximum **RDP TCP RTT**, and maximum **RDP User Input Delay**. It does not record usernames, keystrokes, clipboard
content, credentials, or user input. User Input Delay is queued Windows application
input responsiveness, not network RTT or AWS WorkSpaces `InSessionLatency`.
The collector's bounded execution audit records timestamps, phases, exit codes,
and sanitized ServiceDesk task metadata. Unexpected action/principal values are
redacted. It contains no user or session identity.

User Input Delay remains a supporting responsiveness observation and never
qualifies cleanup. The only explicit customer-aligned performance boundary is:

```text
RDP TCP RTT > 200 ms
```

Exactly 200 ms is not a breach. The PoC does not invent CPU, memory, disk, or
network severity thresholds.

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

### Governed System File Cleanup

When genuine RDP TCP RTT is strictly greater than 200 ms, the performance
controller creates a ten-minute, caller- and mapping-bound System File Cleanup
offer. A later confirmation invokes one
GCP-specific controller; it revalidates the mapping, retrieves its SOP, requires
the exact `gcp.virtual_desktop.system_file_cleanup` planner action, runs
`check_list` once, and collects fresh evidence. It never uses generic
`cleanup_temp_files`.

The fixed guest worker runs in the mapped user's verified interactive session and
accepts only its controller-owned invocation and result paths. Its customer-visible
scope is exactly `Downloaded Program Files` and `Temporary Internet Files`.
Temporary Internet Files cleanup enumerates WinINet content entries and deletes
only eligible `NORMAL_CACHE_ENTRY` URLs; cookie, history, sticky, and edited cache
entries are excluded. Downloaded Program Files inspection is non-recursive and
limited to legacy ActiveX/Java payloads in the dedicated Windows folder. No eligible
items is a successful category result. The worker does not invoke Disk Cleanup,
DISM, or the `IEmptyVolumeCache` COM interfaces. It never targets user folders,
browser profiles, Outlook data, SCCM content, networking, domain membership, or
Windows services. The controller resolves the mapped VM's Compute Engine private
IP and invokes the fixed controller through the existing ServiceDesk
`win_tool.execute_winrm_ps` transport and `WINRM_*` runtime identity. The model
supplies neither the host nor PowerShell. No second transport, public IP, public
RDP, or public WinRM is added.

For a rehearsal that needs an elevated branch, use `GCP_VDI_MODE=demo` and
`GCP_VDI_DEMO_SCENARIO=kb0019144_high_latency`. This produces a clearly labelled
demo-only 243-ms RDP TCP RTT. For a genuine lab measurement, an operator
may run `scripts/gcp_vdi_demo_fault.ps1` through their existing secure guest
session; it is bounded to 60–120 seconds and is never exposed to chat.

## Amazon WorkSpaces

AWS WorkSpaces is a named-system domain alongside the GCP virtual desktop PoC. It
owns its own login and performance diagnosis and never routes into the GCP
`shared_virtual_workstation` path or into generic Account Access.

### Modes and identity mapping

`AWS_WORKSPACES_MODE` selects the backend and defaults to `off`:

| Mode | Behavior |
| --- | --- |
| `off` | No AWS call is made. Safe default. |
| `demo` | Reads `AWS_WORKSPACES_DEMO_FIXTURE_PATH`. Read-only; never starts a WorkSpace. |
| `aws` | Real read-only AWS calls plus the single governed start remediation. |

The authenticated Entra UPN is resolved through an explicit private mapping at
`AWS_WORKSPACES_USER_MAP_PATH`:

```json
{ "user@example.com": { "region": "...", "directory_id": "d-...", "workspace_username": "..." } }
```

An Entra UPN is never assumed to equal the WorkSpaces `UserName`, and its domain
is never stripped to guess one. Without a mapping entry the diagnosis stops with
`AWS_WORKSPACES_USER_NOT_MAPPED`. The real mapping is ignored by git and is never
committed. Install the optional runtime dependency with
`pip install -r requirements-aws-workspaces.txt`; boto3 uses its standard
credential provider chain and no key material is read from the repository.

### Required IAM

Read-only diagnosis needs `workspaces:DescribeWorkspaces`,
`workspaces:DescribeWorkspacesConnectionStatus`,
`workspaces:DescribeWorkspaceDirectories`, `ds:DescribeDirectories`, and
`cloudwatch:GetMetricData`. The governed start adds exactly one write permission,
`workspaces:StartWorkspaces`. No stop, reboot, rebuild, restore, terminate, or
property-modification permission is required or used.

### Diagnostic behavior and limitations

Login diagnosis inspects assignment, WorkSpace state, connection status, optional
client registration, directory-level MFA metadata, and the existing protected
domain-account prerequisites. Registration is reported only as `pass`, `fail`, or
`not_verifiable`; the WorkSpaces registration code is never returned, logged, or
persisted. Directory-level RADIUS configuration never implies individual MFA
enrollment, and an `Authentication Failure` never implies a wrong password or
triggers an automatic password reset.

Performance diagnosis reports CloudWatch observations and applies exactly one
KB-derived rule: `InSessionLatency` strictly greater than 200 ms. Exactly 200 ms
is not a breach. `system_file_cleanup.status` stays `not_automatable`; generic
`cleanup_temp_files` is not the KB0019144 System File Cleanup.

### Governed WorkSpace start

Starting a stopped WorkSpace is the only AWS mutation in this phase. The
read-only login diagnosis creates a ten-minute, caller- and WorkSpace-bound
`aws.workspaces.start` offer only when live AWS evidence shows an assigned
WorkSpace that is genuinely `STOPPED` with an `AUTO_STOP` or `MANUAL` running
mode. An `ALWAYS_ON` WorkSpace is not eligible and its running mode is never
modified to make it eligible. The offer is never created from what the caller
asked for.

Confirmation must arrive in a later turn. `aws_confirm_workspace_start()` takes
no arguments at all, so the model can never supply a `WorkspaceId`, Region,
`DirectoryId`, or WorkSpaces username — every one of those is re-read from the
trusted offer and the private mapping. The controller re-verifies the caller, the
mapping, the same `WorkspaceId`, a still-`STOPPED` state, and the running mode,
runs `check_list` once in an isolated policy context, consumes the confirmation
exactly once, and calls `StartWorkspaces` exactly once.

Success is never claimed from an accepted request. The controller then polls
`DescribeWorkspaces` read-only, treating `STARTING` as an expected intermediate
state, and reports success only when AWS itself reports `AVAILABLE`. Connection
state may remain `DISCONNECTED` until the employee actually connects and is never
required for success. A rejected request, a failure state, or a timeout is
reported as an error with the existing ServiceNow path, never as success, and the
write is never retried.
