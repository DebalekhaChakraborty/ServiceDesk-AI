# GCP Virtual Desktop PoC SOP — Performance Diagnosis

This is a sanitized **KB0019144-Compatible GCP Virtual Desktop PoC** procedure
for a single-user Windows desktop on Google Compute Engine. It mirrors the
customer process at a high level; it is not the customer's production policy and
it is not AWS WorkSpaces.

1. Validate that the authenticated caller has an explicit private mapping to a
   running Compute Engine Windows virtual desktop.
2. Retrieve recent real CPU, memory, disk, network, and uptime observations.
3. Retrieve recent Windows **User Input Delay per Session** telemetry.
4. Review recent Remote Desktop session and disconnect events.
5. Treat **RDP User Input Delay > 200 ms** as an elevated remote-session
   responsiveness signal for this PoC, based on Microsoft Remote Desktop
   guidance. Exactly 200 ms is not above the threshold.
6. Keep CPU, memory, disk, and network values as observations; do not invent
   unsupported severity thresholds.
7. Treat unavailable telemetry as unknown, never as zero.
8. If, and only if, the delay is above 200 ms, offer the
   **KB0019144-Compatible LAB Cleanup Profile**. Require a separate later user
   confirmation; diagnosis never cleans automatically.
9. The confirmed cleanup uses native Windows Disk Cleanup only when the approved
   PoC-only categories are present. It does not delete user documents, Downloads,
   Desktop, browser profiles, Outlook data, SCCM content, or arbitrary app data.
10. After cleanup, collect fresh GCP/Windows performance evidence. If it remains
    above threshold, is unavailable, or is inconclusive, offer escalation rather
    than claiming resolution.

RDP User Input Delay measures queued Windows application input responsiveness.
It is not network RTT, AWS WorkSpaces `InSessionLatency`, or WorkSpaces latency.

The real backend uses the mapped Compute Engine VM, Cloud Monitoring, Cloud
Logging, and identity-free Windows telemetry. The deterministic
`kb0019144_high_latency` fixture is explicitly `backend=demo`; its 243-ms value
is only for rehearsal and is never represented as a Google Cloud observation.

The lab cleanup reuses the existing ServiceDesk private WinRM transport. The
controller resolves the mapped Compute Engine VM's private IP and passes that
controller-owned target plus fixed PowerShell to `win_tool.execute_winrm_ps`;
neither comes from the model. It adds no public IP, public RDP, public WinRM, IAP
tunnel, or second execution framework. If private WinRM or native Disk Cleanup
is not available, cleanup stops safely. An operator may run
`scripts/gcp_vdi_demo_fault.ps1` on the PoC guest to create a bounded 60–120
second CPU-pressure demonstration; it is not an agent tool and does not invent
or alter telemetry.
