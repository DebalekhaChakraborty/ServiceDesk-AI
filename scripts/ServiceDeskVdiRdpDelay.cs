// ServiceDesk GCP virtual-desktop PoC — controlled RDP latency helper.
//
// PURPOSE
//   Introduce or remove a bounded, delay-only impairment on the approved RDP
//   demo transport so the customer PoC can show a genuine Windows-measured
//   latency change. It exists only to demonstrate closed-loop remediation on a
//   lab workstation. It is not, and must not be represented as, repair of ISP,
//   WAN, or cloud networking.
//
// SAFETY PROPERTIES
//   * Delay only. Never drops, resets, duplicates, corrupts or rewrites packets.
//     Packets are re-injected byte-for-byte in arrival order (FIFO), so the RDP
//     session stays usable, only slower.
//   * Fixed filter. The WinDivert filter is a compile-time constant scoped to
//     inbound TCP for the local RDP listener. Port, direction, delay and filter
//     are never accepted from a caller, so WinRM/model input cannot widen it.
//     WinRM (5986), Ops Agent, DNS and all other traffic are untouched.
//   * Operator/agent split. Only "enable-demo" creates the impairment. The
//     agent-facing verbs are "status" and "recover", and "recover" takes no
//     parameters at all.
//   * Bounded. The worker self-expires (default 15 min, hard cap 30 min) and
//     fails open: if it dies or is killed, the WinDivert handle closes and all
//     traffic immediately flows unimpaired.
//
// USAGE
//   ServiceDeskVdiRdpDelay.exe enable-demo [delayMs] [ttlSeconds]   (operator)
//   ServiceDeskVdiRdpDelay.exe status                               (agent)
//   ServiceDeskVdiRdpDelay.exe recover                              (agent)

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

internal static class WinDivert
{
    public const short LayerNetwork = 0;
    public const ulong FlagNone = 0;
    public const int AddressSize = 64;   // sizeof(WINDIVERT_ADDRESS) in WinDivert 2.x

    [DllImport("WinDivert.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr WinDivertOpen(
        string filter, short layer, short priority, ulong flags);

    [DllImport("WinDivert.dll", SetLastError = true)]
    public static extern bool WinDivertRecv(
        IntPtr handle, byte[] pPacket, uint packetLen, out uint recvLen, byte[] pAddr);

    [DllImport("WinDivert.dll", SetLastError = true)]
    public static extern bool WinDivertSend(
        IntPtr handle, byte[] pPacket, uint packetLen, out uint sendLen, byte[] pAddr);

    [DllImport("WinDivert.dll", SetLastError = true)]
    public static extern bool WinDivertShutdown(IntPtr handle, uint how);

    [DllImport("WinDivert.dll", SetLastError = true)]
    public static extern bool WinDivertClose(IntPtr handle);
}

public static class ServiceDeskVdiRdpDelay
{
    // Fixed configuration. Deliberately not reachable from any caller.
    private const string Filter = "inbound and tcp and tcp.DstPort == 3389";
    private const int DefaultDelayMs = 250;
    private const int MinDelayMs = 50;
    private const int MaxDelayMs = 600;
    private const int DefaultTtlSeconds = 15 * 60;
    private const int MaxTtlSeconds = 30 * 60;
    private const int MaxPacket = 65535;

    private static readonly string Root =
        @"C:\ProgramData\ServiceDeskVDI\NetworkDemo";
    private static string StatePath { get { return Path.Combine(Root, "state.json"); } }

    public static int Main(string[] args)
    {
        Directory.CreateDirectory(Root);
        string verb = args.Length > 0 ? args[0].Trim().ToLowerInvariant() : "status";

        switch (verb)
        {
            case "status":
                Console.WriteLine(ReadState());
                return 0;

            case "recover":
                // Agent-facing. Accepts no parameters by design.
                if (args.Length > 1)
                {
                    Console.WriteLine("{\"ok\":false,\"error\":\"recover_takes_no_parameters\"}");
                    return 2;
                }
                return Recover();

            case "enable-demo":
                return EnableDemo(args);

            case "run-worker":
                // Internal: spawned by enable-demo. Not an operator or agent verb.
                return RunWorker(args);

            default:
                Console.WriteLine("{\"ok\":false,\"error\":\"unknown_verb\"}");
                return 2;
        }
    }

    private static string ReadState()
    {
        try
        {
            if (!File.Exists(StatePath))
                return "{\"ok\":true,\"state\":\"HEALTHY\",\"fault_id\":null,\"delay_ms\":null}";
            string raw = File.ReadAllText(StatePath);
            // Fail closed to HEALTHY if the recorded worker is gone (fail-open impairment).
            int pid = ExtractInt(raw, "\"pid\":");
            string state = raw.Contains("\"FAULT_ACTIVE\"") ? "FAULT_ACTIVE" : "HEALTHY";
            if (state == "FAULT_ACTIVE" && !ProcessAlive(pid))
            {
                WriteHealthy();
                return "{\"ok\":true,\"state\":\"HEALTHY\",\"fault_id\":null,\"delay_ms\":null,"
                     + "\"note\":\"worker_absent_impairment_not_active\"}";
            }
            return raw;
        }
        catch (Exception ex)
        {
            return "{\"ok\":false,\"error\":\"state_unreadable\",\"detail\":\""
                 + ex.Message.Replace("\"", "'") + "\"}";
        }
    }

    private static bool ProcessAlive(int pid)
    {
        if (pid <= 0) return false;
        try { Process.GetProcessById(pid); return true; }
        catch { return false; }
    }

    private static int ExtractInt(string raw, string key)
    {
        int i = raw.IndexOf(key, StringComparison.Ordinal);
        if (i < 0) return -1;
        int j = i + key.Length;
        while (j < raw.Length && (raw[j] == ' ')) j++;
        int k = j;
        while (k < raw.Length && (char.IsDigit(raw[k]) || raw[k] == '-')) k++;
        int val;
        return int.TryParse(raw.Substring(j, k - j), out val) ? val : -1;
    }

    private static void WriteHealthy()
    {
        File.WriteAllText(StatePath,
            "{\"ok\":true,\"state\":\"HEALTHY\",\"fault_id\":null,\"delay_ms\":null,\"pid\":0}");
    }

    private static int Recover()
    {
        try
        {
            if (File.Exists(StatePath))
            {
                int pid = ExtractInt(File.ReadAllText(StatePath), "\"pid\":");
                if (ProcessAlive(pid))
                {
                    try { Process.GetProcessById(pid).Kill(); } catch { }
                    Thread.Sleep(700);
                }
            }
            WriteHealthy();
            Console.WriteLine("{\"ok\":true,\"command\":\"recover\",\"state\":\"HEALTHY\"}");
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine("{\"ok\":false,\"command\":\"recover\",\"error\":\""
                + ex.Message.Replace("\"", "'") + "\"}");
            return 1;
        }
    }

    private static int EnableDemo(string[] args)
    {
        int delay = DefaultDelayMs, ttl = DefaultTtlSeconds;
        if (args.Length > 1) int.TryParse(args[1], out delay);
        if (args.Length > 2) int.TryParse(args[2], out ttl);
        if (delay < MinDelayMs) delay = MinDelayMs;
        if (delay > MaxDelayMs) delay = MaxDelayMs;
        if (ttl < 60) ttl = 60;
        if (ttl > MaxTtlSeconds) ttl = MaxTtlSeconds;

        Recover();  // idempotent: clear any prior worker first

        string faultId = "wfault-" + Guid.NewGuid().ToString("N");
        var psi = new ProcessStartInfo
        {
            FileName = Process.GetCurrentProcess().MainModule.FileName,
            Arguments = "run-worker " + delay + " " + ttl + " " + faultId,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = false,
        };
        var proc = Process.Start(psi);
        Thread.Sleep(1500);   // let the worker open the handle or fail fast

        if (proc.HasExited)
        {
            Console.WriteLine("{\"ok\":false,\"command\":\"enable-demo\",\"error\":"
                + "\"worker_exited\",\"exit_code\":" + proc.ExitCode + "}");
            return 1;
        }
        long expires = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + ttl;
        string json = "{\"ok\":true,\"state\":\"FAULT_ACTIVE\",\"fault_id\":\"" + faultId
            + "\",\"delay_ms\":" + delay + ",\"pid\":" + proc.Id
            + ",\"expires_at\":" + expires
            + ",\"filter\":\"" + Filter + "\"}";
        File.WriteAllText(StatePath, json);
        Console.WriteLine(json);
        return 0;
    }

    private sealed class Held
    {
        public byte[] Packet;
        public uint Length;
        public byte[] Addr;
        public long ReleaseTicks;
    }

    private static int RunWorker(string[] args)
    {
        int delay = args.Length > 1 ? int.Parse(args[1], CultureInfo.InvariantCulture) : DefaultDelayMs;
        int ttl = args.Length > 2 ? int.Parse(args[2], CultureInfo.InvariantCulture) : DefaultTtlSeconds;

        IntPtr handle = WinDivert.WinDivertOpen(Filter, WinDivert.LayerNetwork, 0, WinDivert.FlagNone);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
        {
            Console.Error.WriteLine("WinDivertOpen failed, error=" + Marshal.GetLastWin32Error());
            return 3;
        }

        var queue = new Queue<Held>();
        var gate = new object();
        bool stopping = false;
        DateTime deadline = DateTime.UtcNow.AddSeconds(ttl);

        // Re-injector: releases packets in arrival order once their delay elapses.
        var sender = new Thread(() =>
        {
            while (true)
            {
                Held item = null;
                lock (gate)
                {
                    if (queue.Count > 0 && queue.Peek().ReleaseTicks <= DateTime.UtcNow.Ticks)
                        item = queue.Dequeue();
                    else if (stopping && queue.Count == 0)
                        break;
                }
                if (item == null) { Thread.Sleep(2); continue; }
                uint sent;
                WinDivert.WinDivertSend(handle, item.Packet, item.Length, out sent, item.Addr);
            }
        });
        sender.IsBackground = true;
        sender.Start();

        try
        {
            while (DateTime.UtcNow < deadline)
            {
                var buf = new byte[MaxPacket];
                var addr = new byte[WinDivert.AddressSize];
                uint recvLen;
                if (!WinDivert.WinDivertRecv(handle, buf, (uint)buf.Length, out recvLen, addr))
                    continue;
                var held = new Held
                {
                    Packet = buf,
                    Length = recvLen,
                    Addr = addr,
                    ReleaseTicks = DateTime.UtcNow.AddMilliseconds(delay).Ticks,
                };
                lock (gate) { queue.Enqueue(held); }
            }
        }
        finally
        {
            // Fail open: flush everything still queued, then drop the filter so
            // traffic is never left blocked or delayed by a dying worker.
            lock (gate) { stopping = true; }
            try { sender.Join(5000); } catch { }
            try
            {
                while (true)
                {
                    Held item;
                    lock (gate) { if (queue.Count == 0) break; item = queue.Dequeue(); }
                    uint sent;
                    WinDivert.WinDivertSend(handle, item.Packet, item.Length, out sent, item.Addr);
                }
            }
            catch { }
            WinDivert.WinDivertClose(handle);
            try { WriteHealthy(); } catch { }
        }
        return 0;
    }
}
