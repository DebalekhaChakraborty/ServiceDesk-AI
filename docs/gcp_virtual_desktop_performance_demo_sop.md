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
10. After a successful cleanup, still collect fresh GCP/Windows performance
    evidence and retain it as internal evidence. The customer-facing completion
    leads with "System File Cleanup completed successfully.", reports the bounded
    category evidence, and then asks the user to continue using the workstation
    and report back. A fresh RTT that is still above threshold, unavailable, or
    inconclusive does not by itself turn that completion into a failure message
    or an escalation offer. Nothing claims the RTT changed, that latency is
    fixed, or that the backend resolved anything.
11. Further investigation and escalation happen only once the user reports that
    the problem persists. A cleanup that did not run or did not complete is
    still reported as a failure, with escalation offered.

## Customer workflow

```text
genuine RDP TCP RTT > 200 ms
  -> offer System File Cleanup
  -> separate later user confirmation
  -> real approved cleanup (Downloaded Program Files, Temporary Internet Files)
  -> report success + bounded category evidence, ask the user to continue
     using the session and report back
  -> further investigation or escalation ONLY if the user reports the lag persists
```

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
* `scripts/RDPLatencyMonitor.ps1` — the single canonical read-only desktop
  monitor, superseding the former `show_rdp_latency_monitor.ps1`. Deployed to
  `C:\ProgramData\ServiceDeskVDI\RDPLatencyMonitor.ps1`. It never changes
  latency, never writes ServiceDesk telemetry, never fabricates a value, and
  never changes the >200 ms threshold.
  * Default: displays the genuine RemoteFX `Current TCP RTT` for active
    `rdp-tcp` sessions, with User Input Delay shown separately.
  * Opt-in `-PresentationMode`: for a recorded demonstration only. It reads the
    genuine RTT first, remembers the `cleanup_9144_*.json` files that exist at
    startup, and watches `C:\ProgramData\ServiceDeskVDI` for a **new** result
    reporting successful completion. Only then does it animate the **displayed**
    value from the genuine starting RTT toward 65 ms over ~16 s, after which the
    status flips to below threshold on its own. A failed cleanup, an unreadable
    result, or no new result leaves the genuine value on screen. It writes
    nothing: no counter, no `rdp_telemetry*.jsonl`, no `capabilities.json`, no
    Cloud Logging, no backend state. The mode is declared in the window title
    and in the shortcut arguments; the console pane stays clean for recording.
* `scripts/install_rdp_latency_monitor.ps1` — operator deployment helper. Copies
  the monitor to `C:\ProgramData\ServiceDeskVDI\RDPLatencyMonitor.ps1` and
  creates a desktop shortcut named `RDP Latency Monitor` targeting
  `powershell.exe` with `-NoLogo -NoProfile -ExecutionPolicy Bypass -File
  "C:\ProgramData\ServiceDeskVDI\RDPLatencyMonitor.ps1" -PresentationMode`
  (`-GenuineOnly` omits the switch). It builds no executable and embeds no
  credential, and it touches nothing else on the guest.

## Guest collector redeployment (telemetry schema skew)

### When this is needed

The guest telemetry contract is versioned by
`servicedesk_vdi_telemetry_schema_version` in
`C:\ProgramData\ServiceDeskVDI\capabilities.json`.

| Version | Capability contract |
| --- | --- |
| absent / 0 | User Input Delay only. Cannot sample RDP TCP RTT. |
| 2 | Adds `rdp_tcp_rtt_counter_set_available` / `_set` / `_paths`. |

A guest below version 2 never samples `RemoteFX Network(*)\Current TCP RTT`,
even when Windows exposes a perfectly valid value. It publishes
`rdp_tcp_rtt_counter_available=false` with a null RTT, so the controller reports
RTT as unavailable and — correctly — creates no cleanup offer.

The backend now separates the two cases. An outdated guest yields the bounded
reason `collector_capability_schema_outdated` and an explicit collection
limitation, instead of being silently reported as a missing counter. The backend
never repairs the guest, never infers a value, and never treats stale telemetry
as a measurement.

**Redeployment is an operator action. It is not automated, and the agent has no
path to trigger it.**

### Procedure (idempotent)

Deploy the reviewed repository assets together — they are one unit, and a
partial copy reintroduces skew:

```
scripts/configure_gcp_vdi_windows.ps1
scripts/run_cleanup_9144.ps1
scripts/ServiceDeskFixedCleanup.cs
```

From an elevated PowerShell session on the PoC guest, reached through the
operator's existing secure administrative access:

```powershell
# 1. Stage the three reviewed assets together.
$Root = "C:\ProgramData\ServiceDeskVDI"
New-Item -Path $Root -ItemType Directory -Force | Out-Null
Copy-Item .\run_cleanup_9144.ps1        -Destination $Root -Force
Copy-Item .\ServiceDeskFixedCleanup.cs  -Destination $Root -Force

# 2. Re-run the bootstrap. It is idempotent: it rediscovers counters, rewrites
#    capabilities.json with the current schema version, and re-registers the
#    recurring task in place.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\configure_gcp_vdi_windows.ps1
```

Do **not** hand-edit `capabilities.json`. It is generated from live counter
discovery; editing it by hand fabricates capability claims.

The bootstrap preserves the existing safety boundaries: no domain membership
change, no SCCM/ConfigMgr change, no firewall change, no endpoint-management
change, no public RDP, and no fabricated telemetry.

### Post-deployment verification

```powershell
Get-Content C:\ProgramData\ServiceDeskVDI\capabilities.json

Get-ScheduledTask -TaskName "ServiceDeskVDI-RdpTelemetry" |
    Get-ScheduledTaskInfo

Get-Content C:\ProgramData\ServiceDeskVDI\rdp_telemetry.jsonl -Tail 5
```

Expected, when an RDP session is active and Windows exposes the counter:

* `capabilities.json` contains `servicedesk_vdi_telemetry_schema_version: 2`,
  `rdp_tcp_rtt_counter_set_available: true`, `rdp_tcp_rtt_counter_set:
  "RemoteFX Network"`, and a non-empty `rdp_tcp_rtt_counter_paths`.
* The scheduled task shows a recent `LastRunTime` and `LastTaskResult` 0.
* Recent telemetry records carry
  `servicedesk_vdi_telemetry_schema_version: 2`,
  `rdp_tcp_rtt_counter_available: true`, and a numeric `rdp_tcp_rtt_ms`.

`rdp_tcp_rtt_counter_set_available: false` is a legitimate result when Windows
genuinely does not expose the counter — for example with no active RDP session.
Confirm independently before treating it as a fault:

```powershell
Get-Counter '\RemoteFX Network(*)\Current TCP RTT' -MaxSamples 3
```
