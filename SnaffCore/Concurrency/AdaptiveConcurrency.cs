using System;
using System.Collections.Generic;

namespace SnaffCore.Concurrency
{
    /// <summary>
    /// Chooses a conservative default for mixed local/SMB scans. An explicit -x
    /// remains authoritative; this is only used when the operator omits it.
    /// </summary>
    public static class AdaptiveConcurrency
    {
        public static int Calculate(IList<string> pathTargets, string[] computerTargets)
        {
            int cpu = Math.Max(1, Environment.ProcessorCount);
            long memory = 0;
            try { memory = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes; } catch { }

            bool network = computerTargets != null && computerTargets.Length > 0;
            if (!network && pathTargets != null)
                foreach (string path in pathTargets)
                    if (!string.IsNullOrEmpty(path) && path.StartsWith("\\\\", StringComparison.Ordinal)) { network = true; break; }

            // File parsing is memory-heavy; network scans also benefit from
            // fewer concurrent SMB handles and less server throttling.
            int byCpu = network ? cpu : cpu * 2;
            int byMemory = memory > 0 ? (int)Math.Max(4, memory / (256L * 1024 * 1024)) : byCpu;
            int result = Math.Min(byCpu, byMemory);
            result = Math.Min(result, network ? 32 : 64);
            return Math.Max(4, result);
        }
    }
}
