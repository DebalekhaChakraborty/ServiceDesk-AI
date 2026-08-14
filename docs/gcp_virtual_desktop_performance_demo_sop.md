# GCP Virtual Desktop PoC SOP — Performance Diagnosis

This is a sanitized **KB screenshot-visible GCP Virtual Desktop PoC** procedure
for a single-user Windows desktop on Google Compute Engine. It mirrors the
customer process at a high level; it is not the customer's production policy and
it is not AWS WorkSpaces.

1. Validate that the authenticated caller has an explicit private mapping to a
   running Compute Engine Windows virtual desktop.
2. Retrieve recent real CPU, memory, disk, network, and uptime observations.
3. Retrieve genuine active-session Windows **RemoteFX Network Current TCP RTT**
   telemetry and keep **User Input Delay per Session** as a separate supporting
   responsiveness observation.
4. Review recent Remote Desktop session and disconnect events.
5. Treat **RDP TCP RTT > 200 ms** as `HIGH_SESSION_RTT`, following the customer
   KB threshold. Exactly 200 ms is not above the threshold. Missing RTT is never
   zero and never qualifies cleanup.
6. Keep CPU, memory, disk, and network values as observations; do not invent
   unsupported severity thresholds.
7. Treat unavailable telemetry as unknown, never as zero.
8. If, and only if, genuine RTT is above 200 ms, offer the
   **KB screenshot-visible PoC cleanup profile**. Require a separate later user
   confirmation; diagnosis never cleans automatically.
9. The confirmed cleanup runs the fixed ServiceDesk-owned Windows cleanup worker
   in the mapped user's active Windows session. The customer-facing action stays
   **System File Cleanup** and the approved categories stay exactly `Downloaded
   Program Files` and `Temporary Internet Files`.
   * `Temporary Internet Files` uses deterministic WinINet enumeration and
     deletion, restricted to `NORMAL_CACHE_ENTRY` items and explicitly excluding
     sticky, edited, cookie, and URL-history entries.
   * `Downloaded Program Files` reports `COMPLETED_NO_ELIGIBLE_ITEMS` when the
     category is empty, rather than reporting a failure.
   * The worker does **not** use `cleanmgr.exe`, `StateFlags9144`,
     `/sagerun:9144`, DISM, DismHost, `IEmptyVolumeCache`, or
     `IEmptyVolumeCache2`. Native `cleanmgr` was live-proven to stall on this
     healthy Windows Server 2022 lab image, which is why the fixed worker
     replaced it.
   * The worker accepts no model-supplied command, path, or filter.
   It does not delete user documents, Downloads, Desktop, browser profiles,
   cookies, browsing history, Outlook data, SCCM content, or arbitrary app data.
10. After cleanup, collect fresh GCP/Windows performance evidence. If it remains
    above threshold, is unavailable, or is inconclusive, offer escalation rather
    than claiming resolution.

RDP User Input Delay measures queued Windows application input responsiveness.
It is supporting evidence only and is not RTT, network latency, AWS WorkSpaces
`InSessionLatency`, or WorkSpaces latency.

The real backend uses the mapped Compute Engine VM, Cloud Monitoring, Cloud
Logging, and identity-free Windows telemetry. The deterministic
`kb0019144_high_latency` fixture is explicitly `backend=demo`; its 243-ms RTT value
is only for rehearsal and is never represented as a Google Cloud observation.

The lab cleanup reuses the existing ServiceDesk private WinRM transport. The
controller resolves the mapped Compute Engine VM's private IP and passes that
controller-owned target plus fixed PowerShell to `win_tool.execute_winrm_ps`;
neither comes from the model. It adds no public IP, public RDP, public WinRM, IAP
tunnel, or second execution framework. If private WinRM or the fixed cleanup
worker is not available, cleanup stops safely. An operator may run
`scripts/gcp_vdi_demo_fault.ps1` on the PoC guest to create a bounded 60–120
second CPU-pressure demonstration; it is not an agent tool and does not invent
or alter telemetry.

## Operator demo utilities (not agent-callable)

These exist for demonstration preparation and visual confirmation only. None is
registered as an action, and the agent has no path to invoke them.

* `scripts/seed_gcp_vdi_demo_cache.ps1` — seeds exactly four harmless WinINet
  `NORMAL_CACHE_ENTRY` items in the mapped user's own session so the cleanup
  demonstration removes real, verifiable entries. No cookies, no history, no
  credentials, no arbitrary URL or path input.
* `scripts/show_rdp_latency_monitor.ps1` — read-only desktop display of the
  genuine RemoteFX `Current TCP RTT` counter. Deployed to
  `C:\ProgramData\ServiceDeskVDI\Show-RdpLatency.ps1`. It never changes latency,
  never writes ServiceDesk telemetry, never fabricates a value, and never
  changes the >200 ms threshold.

## PoC closed-loop network recovery — STATUS: BLOCKED, NOT INTEGRATED

A controlled lab impairment harness exists and is validated at the network
layer:

* `scripts/gcp_vdi_demo_netfault_daemon.py` — root-owned daemon. It applies a
  bounded `netem` delay inside a dedicated `sdvdi-demo` network namespace that
  carries nothing except the demo RDP path. Host traffic (ServiceDesk backend,
  frontend, Google APIs, WinRM, SSH/IAP) is physically unaffected: measured
  250.7 ms inside the namespace against 0.6 ms on the host, simultaneously.
* `scripts/gcp_vdi_demo_netfaultctl.py` — operator CLI.

Security boundary: creating the impairment requires a root peer, enforced by the
kernel through `SO_PEERCRED` on the control socket. The unprivileged ServiceDesk
backend can read status and remove the impairment, but can never create it. The
fault carries a hard expiry with a watchdog that removes it automatically, and
an abnormally terminated run cannot strand a degraded path.

### Negative result — a TCP-terminating proxy hides latency from RemoteFX RTT

The first forwarding design routed RDP through a userspace TCP proxy inside the
namespace. **It does not work, and the approach should not be retried.**

With the proxy carrying a genuine RDP session, `\RemoteFX Network(*)\Current TCP
RTT` reported a constant 5 ms in 41 consecutive samples across every condition
tested: impairment applied mid-session, impairment already active before the
session connected, and with continuous synthetic input traffic. Raising the
delay to 800 ms — four times the customer threshold — still produced 5 ms on
both `Current TCP RTT` and `Base TCP RTT`, while `Current TCP Bandwidth` and
`TCP Received Rate` moved normally, proving the counter set itself was live.

Cause: a userspace proxy terminates the TCP connection and re-originates it, so
the RDP server's peer is the proxy on the same VPC (sub-millisecond). The
impairment sits on a different connection than the one Windows measures. By
contrast a direct client connection over a genuinely high-latency path does
report real values (302–320 ms observed).

Consequence: the forwarding layer must preserve the client-to-Windows TCP
connection end to end — for example `iptables` DNAT plus routing — so the RDP
connection itself traverses the impairment. That redesign is pending approval
and is not implemented here.

**The `gcp.virtual_desktop.demo_session_network_recovery` agent action is not
implemented.** The acceptance plan requires the harness to first pass
independent healthy/faulted/recovered validation against the genuine Windows
RemoteFX counter. Healthy passed (5 ms through the lab path, versus 302 ms
direct); faulted failed for the reason above. Until that passes, the existing
post-cleanup escalation behavior is unchanged.

When implemented, the closed-loop extension will read:

CUSTOMER-ALIGNED FLOW
: RTT > 200 ms -> System File Cleanup -> fresh verification.

POC CLOSED-LOOP EXTENSION
: if cleanup succeeds but fresh RTT remains > 200 ms **and** the controlled lab
  fault is active -> offer Session Network Recovery -> later explicit
  confirmation -> remove only the controlled impairment -> collect a genuinely
  newer RTT sample -> verify below threshold.

The controlled network fault and its recovery are a **PoC demonstration
mechanism**. They are not, and must not be represented as, the customer's
production network control plane. In production this action would integrate
with the customer's authorized network automation platform.
