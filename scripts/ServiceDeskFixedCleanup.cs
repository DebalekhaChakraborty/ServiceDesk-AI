using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

internal sealed class CategoryResult
{
    internal string Status;
    internal int BeforeCount;
    internal ulong BeforeBytes;
    internal int DeletedCount;
    internal int FailedOrLockedCount;
    internal int RemainingTargetCount;
    internal int AfterCount;
    internal ulong AfterBytes;
    internal int RegisteredDistributionUnitCount;
}

internal sealed class CacheEntry
{
    internal string Url;
    internal ulong SizeBytes;
}

internal static class NativeMethods
{
    internal const uint NormalCacheEntry = 0x00000001;
    internal const uint StickyCacheEntry = 0x00000004;
    internal const uint EditedCacheEntry = 0x00000008;
    internal const uint CookieCacheEntry = 0x00100000;
    internal const uint UrlHistoryCacheEntry = 0x00200000;
    internal const int ErrorFileNotFound = 2;
    internal const int ErrorAccessDenied = 5;
    internal const int ErrorSharingViolation = 32;
    internal const int ErrorLockViolation = 33;
    internal const int ErrorInsufficientBuffer = 122;
    internal const int ErrorNoMoreItems = 259;

    [StructLayout(LayoutKind.Sequential)]
    internal struct FileTime
    {
        internal uint Low;
        internal uint High;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct InternetCacheEntryInfo
    {
        internal uint StructSize;
        internal IntPtr SourceUrlName;
        internal IntPtr LocalFileName;
        internal uint CacheEntryType;
        internal uint UseCount;
        internal uint HitRate;
        internal uint SizeLow;
        internal uint SizeHigh;
        internal FileTime LastModifiedTime;
        internal FileTime ExpireTime;
        internal FileTime LastAccessTime;
        internal FileTime LastSyncTime;
        internal IntPtr HeaderInfo;
        internal uint HeaderInfoSize;
        internal IntPtr FileExtension;
        internal uint Reserved;
    }

    [DllImport("wininet.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr FindFirstUrlCacheEntryW(
        string pattern, IntPtr entry, ref uint size);

    [DllImport("wininet.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool FindNextUrlCacheEntryW(
        IntPtr handle, IntPtr entry, ref uint size);

    [DllImport("wininet.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool FindCloseUrlCache(IntPtr handle);

    [DllImport("wininet.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool DeleteUrlCacheEntryW(string url);
}

internal static class Program
{
    private const string Root = @"C:\ProgramData\ServiceDeskVDI";
    private const string DownloadedProgramFilesCategory = "Downloaded Program Files";
    private const string TemporaryInternetFilesCategory = "Temporary Internet Files";
    private static readonly HashSet<string> DownloadedProgramExtensions =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            ".cab", ".class", ".jar", ".ocx", ".dll", ".inf"
        };

    private static int Main(string[] args)
    {
        string invocation = null;
        string resultPath = null;
        for (int index = 0; index + 1 < args.Length; index += 2)
        {
            if (args[index] == "--invocation") invocation = args[index + 1];
            else if (args[index] == "--result") resultPath = args[index + 1];
            else return 2;
        }
        Guid parsedInvocation;
        if (!Guid.TryParseExact(invocation, "D", out parsedInvocation)) return 2;
        string expectedPath = Path.Combine(Root, "cleanup_9144_" + invocation + ".json");
        if (!String.Equals(resultPath, expectedPath, StringComparison.OrdinalIgnoreCase)) return 2;
        if (Process.GetCurrentProcess().SessionId <= 0) return WriteFailure(
            expectedPath, invocation, "SYSTEM_FILE_CLEANUP_INTERACTIVE_SESSION_REQUIRED",
            "System File Cleanup requires the mapped interactive user session.", null);

        Stopwatch stopwatch = Stopwatch.StartNew();
        string startedAt = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
        long? freeBefore = FreeDiskBytes();
        try
        {
            CategoryResult downloaded = CleanDownloadedProgramFiles();
            CategoryResult internet = CleanTemporaryInternetFiles();
            bool completed = downloaded.Status != "FAILED" && internet.Status != "FAILED";
            long? freeAfter = FreeDiskBytes();
            stopwatch.Stop();
            string json = BuildResult(
                completed, invocation, startedAt, stopwatch.Elapsed.TotalSeconds,
                freeBefore, freeAfter, downloaded, internet, null, null);
            WriteAtomic(expectedPath, json);
            return completed ? 0 : 1;
        }
        catch (Exception error)
        {
            stopwatch.Stop();
            return WriteFailure(
                expectedPath, invocation, "SYSTEM_FILE_CLEANUP_FAILED",
                "System File Cleanup failed safely.", error.GetType().Name);
        }
    }

    private static CategoryResult CleanDownloadedProgramFiles()
    {
        string windows = Environment.GetEnvironmentVariable("WINDIR") ?? @"C:\Windows";
        string folder = Path.Combine(windows, DownloadedProgramFilesCategory);
        List<FileInfo> eligible = new List<FileInfo>();
        if (Directory.Exists(folder))
        {
            foreach (string path in Directory.GetFiles(folder, "*", SearchOption.TopDirectoryOnly))
            {
                FileInfo item = new FileInfo(path);
                if ((item.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                if (DownloadedProgramExtensions.Contains(item.Extension)) eligible.Add(item);
            }
        }
        ulong bytes = 0;
        foreach (FileInfo item in eligible) bytes += unchecked((ulong)item.Length);
        int deleted = 0;
        int failed = 0;
        foreach (FileInfo item in eligible)
        {
            try
            {
                item.Delete();
                deleted++;
            }
            catch
            {
                failed++;
            }
        }
        int remaining = 0;
        foreach (FileInfo item in eligible) if (item.Exists) remaining++;
        int registryCount = 0;
        using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Code Store Database\Distribution Units", false))
        {
            if (key != null) registryCount = key.GetSubKeyNames().Length;
        }
        return new CategoryResult {
            Status = eligible.Count == 0 ? "COMPLETED_NO_ELIGIBLE_ITEMS" :
                (failed == 0 && remaining == 0 ? "COMPLETED" : "FAILED"),
            BeforeCount = eligible.Count,
            BeforeBytes = bytes,
            DeletedCount = deleted,
            FailedOrLockedCount = failed,
            RemainingTargetCount = remaining,
            AfterCount = remaining,
            AfterBytes = 0,
            RegisteredDistributionUnitCount = registryCount
        };
    }

    private static bool Eligible(NativeMethods.InternetCacheEntryInfo entry, string url)
    {
        uint excluded = NativeMethods.StickyCacheEntry | NativeMethods.EditedCacheEntry |
            NativeMethods.CookieCacheEntry | NativeMethods.UrlHistoryCacheEntry;
        return !String.IsNullOrWhiteSpace(url) &&
            (entry.CacheEntryType & NativeMethods.NormalCacheEntry) != 0 &&
            (entry.CacheEntryType & excluded) == 0 &&
            !url.StartsWith("cookie:", StringComparison.OrdinalIgnoreCase) &&
            !url.StartsWith("visited:", StringComparison.OrdinalIgnoreCase);
    }

    private static void AddCacheEntry(List<CacheEntry> result, IntPtr buffer)
    {
        NativeMethods.InternetCacheEntryInfo entry =
            (NativeMethods.InternetCacheEntryInfo)Marshal.PtrToStructure(
                buffer, typeof(NativeMethods.InternetCacheEntryInfo));
        string url = entry.SourceUrlName == IntPtr.Zero
            ? null : Marshal.PtrToStringUni(entry.SourceUrlName);
        if (!Eligible(entry, url)) return;
        result.Add(new CacheEntry {
            Url = url,
            SizeBytes = ((ulong)entry.SizeHigh << 32) | entry.SizeLow
        });
    }

    private static List<CacheEntry> EnumerateNormalCache()
    {
        List<CacheEntry> result = new List<CacheEntry>();
        uint capacity = 0;
        IntPtr handle = NativeMethods.FindFirstUrlCacheEntryW(null, IntPtr.Zero, ref capacity);
        if (handle != IntPtr.Zero)
        {
            NativeMethods.FindCloseUrlCache(handle);
            throw new InvalidOperationException("Unexpected WinINet enumeration state.");
        }
        int initialError = Marshal.GetLastWin32Error();
        if (initialError == NativeMethods.ErrorNoMoreItems) return result;
        if (initialError != NativeMethods.ErrorInsufficientBuffer || capacity == 0)
            throw new Win32Exception(initialError);

        IntPtr buffer = Marshal.AllocHGlobal((int)capacity);
        try
        {
            uint firstSize = capacity;
            handle = NativeMethods.FindFirstUrlCacheEntryW(null, buffer, ref firstSize);
            if (handle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                AddCacheEntry(result, buffer);
                while (true)
                {
                    uint nextSize = capacity;
                    if (NativeMethods.FindNextUrlCacheEntryW(handle, buffer, ref nextSize))
                    {
                        AddCacheEntry(result, buffer);
                        continue;
                    }
                    int error = Marshal.GetLastWin32Error();
                    if (error == NativeMethods.ErrorNoMoreItems) break;
                    if (error != NativeMethods.ErrorInsufficientBuffer || nextSize == 0)
                        throw new Win32Exception(error);
                    Marshal.FreeHGlobal(buffer);
                    buffer = IntPtr.Zero;
                    capacity = nextSize;
                    buffer = Marshal.AllocHGlobal((int)capacity);
                    uint retrySize = capacity;
                    if (!NativeMethods.FindNextUrlCacheEntryW(handle, buffer, ref retrySize))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    AddCacheEntry(result, buffer);
                }
            }
            finally
            {
                NativeMethods.FindCloseUrlCache(handle);
            }
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
        }
        return result;
    }

    private static CategoryResult CleanTemporaryInternetFiles()
    {
        List<CacheEntry> before = EnumerateNormalCache();
        Dictionary<string, ulong> targets = new Dictionary<string, ulong>(StringComparer.Ordinal);
        foreach (CacheEntry entry in before) targets[entry.Url] = entry.SizeBytes;
        ulong beforeBytes = 0;
        foreach (ulong size in targets.Values) beforeBytes += size;
        int deleted = 0;
        int failedOrLocked = 0;
        foreach (string url in targets.Keys)
        {
            if (NativeMethods.DeleteUrlCacheEntryW(url))
            {
                deleted++;
                continue;
            }
            int error = Marshal.GetLastWin32Error();
            if (error != NativeMethods.ErrorFileNotFound) failedOrLocked++;
        }
        List<CacheEntry> after = EnumerateNormalCache();
        int remaining = 0;
        ulong afterBytes = 0;
        foreach (CacheEntry entry in after)
        {
            afterBytes += entry.SizeBytes;
            if (targets.ContainsKey(entry.Url)) remaining++;
        }
        return new CategoryResult {
            Status = targets.Count == 0 ? "COMPLETED_NO_ELIGIBLE_ITEMS" :
                (failedOrLocked == 0 && remaining == 0 ? "COMPLETED" : "FAILED"),
            BeforeCount = targets.Count,
            BeforeBytes = beforeBytes,
            DeletedCount = deleted,
            FailedOrLockedCount = failedOrLocked,
            RemainingTargetCount = remaining,
            AfterCount = after.Count,
            AfterBytes = afterBytes,
            RegisteredDistributionUnitCount = 0
        };
    }

    private static long? FreeDiskBytes()
    {
        try { return new DriveInfo(Path.GetPathRoot(Environment.SystemDirectory)).AvailableFreeSpace; }
        catch { return null; }
    }

    private static string Json(string value)
    {
        if (value == null) return "null";
        return "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"")
            .Replace("\r", "\\r").Replace("\n", "\\n") + "\"";
    }

    private static string Number(long? value)
    {
        return value.HasValue ? value.Value.ToString(CultureInfo.InvariantCulture) : "null";
    }

    private static string CategoryJson(CategoryResult value, bool includeRegistry)
    {
        StringBuilder json = new StringBuilder("{");
        json.Append("\"status\":").Append(Json(value.Status));
        json.Append(",\"before_count\":").Append(value.BeforeCount);
        json.Append(",\"before_bytes\":").Append(value.BeforeBytes);
        json.Append(",\"deleted_count\":").Append(value.DeletedCount);
        json.Append(",\"failed_or_locked_count\":").Append(value.FailedOrLockedCount);
        json.Append(",\"remaining_target_count\":").Append(value.RemainingTargetCount);
        json.Append(",\"after_count\":").Append(value.AfterCount);
        json.Append(",\"after_bytes\":").Append(value.AfterBytes);
        if (includeRegistry)
            json.Append(",\"registered_distribution_unit_count\":")
                .Append(value.RegisteredDistributionUnitCount)
                .Append(",\"inspected_non_recursively\":true");
        else
            json.Append(",\"cookies_deleted\":0,\"history_deleted\":0");
        return json.Append("}").ToString();
    }

    private static string BuildResult(bool completed, string invocation, string startedAt,
        double elapsedSeconds, long? freeBefore, long? freeAfter,
        CategoryResult downloaded, CategoryResult internet, string failureCode, string failureMessage)
    {
        string code = failureCode ?? (completed ? "SYSTEM_FILE_CLEANUP_COMPLETED" : "SYSTEM_FILE_CLEANUP_CATEGORY_FAILED");
        string message = failureMessage ?? (completed
            ? "System File Cleanup completed successfully for the approved cleanup categories."
            : "System File Cleanup could not complete every approved cleanup category.");
        long? reclaimed = freeBefore.HasValue && freeAfter.HasValue
            ? freeAfter.Value - freeBefore.Value : (long?)null;
        return "{" +
            "\"status\":" + Json(completed ? "ok" : "error") + "," +
            "\"phase\":" + Json(completed ? "completed" : "failed") + "," +
            "\"code\":" + Json(code) + "," +
            "\"message\":" + Json(message) + "," +
            "\"invocation_id\":" + Json(invocation) + "," +
            "\"task_name\":" + Json("SystemFileCleanup9144-" + invocation) + "," +
            "\"selected_categories\":[" + Json(DownloadedProgramFilesCategory) + "," + Json(TemporaryInternetFilesCategory) + "]," +
            "\"categories\":{" +
              Json(DownloadedProgramFilesCategory) + ":" + (downloaded == null ? "null" : CategoryJson(downloaded, true)) + "," +
              Json(TemporaryInternetFilesCategory) + ":" + (internet == null ? "null" : CategoryJson(internet, false)) + "}," +
            "\"command_exit_code\":" + (completed ? "0" : "1") + "," +
            "\"free_disk_bytes_before\":" + Number(freeBefore) + "," +
            "\"free_disk_bytes_after\":" + Number(freeAfter) + "," +
            "\"bytes_reclaimed\":" + Number(reclaimed) + "," +
            "\"started_at\":" + Json(startedAt) + "," +
            "\"completed_at\":" + Json(DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture)) + "," +
            "\"elapsed_seconds\":" + elapsedSeconds.ToString("0.000", CultureInfo.InvariantCulture) + "," +
            "\"interactive_session_id\":" + Process.GetCurrentProcess().SessionId + "," +
            "\"run_as\":" + Json(WindowsIdentity.GetCurrent().Name) + "," +
            "\"worker_pid\":" + Process.GetCurrentProcess().Id + "," +
            "\"verification\":" + Json(completed ? "deterministic_fixed_cleanup_completed" : "deterministic_fixed_cleanup_failed") + "}";
    }

    private static int WriteFailure(string path, string invocation, string code,
        string message, string errorType)
    {
        string json = BuildResult(false, invocation,
            DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture), 0,
            FreeDiskBytes(), FreeDiskBytes(), null, null, code, message);
        if (errorType != null)
            json = json.Substring(0, json.Length - 1) + ",\"error_type\":" + Json(errorType) + "}";
        WriteAtomic(path, json);
        return 1;
    }

    private static void WriteAtomic(string path, string json)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path));
        string temporary = path + ".tmp." + Process.GetCurrentProcess().Id;
        File.WriteAllText(temporary, json, new UTF8Encoding(false));
        if (File.Exists(path)) File.Delete(path);
        File.Move(temporary, path);
    }
}
