# GCP Virtual Desktop PoC SOP — Performance Diagnosis

This is a sanitized proof-of-concept procedure for a single-user Windows desktop
on Google Compute Engine. It is not a customer knowledge article.

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
8. Escalate where telemetry is unavailable or inconclusive.

RDP User Input Delay measures queued Windows application input responsiveness.
It is not network RTT, AWS WorkSpaces `InSessionLatency`, or WorkSpaces latency.
