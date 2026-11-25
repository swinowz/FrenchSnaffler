using SnaffCore.Concurrency;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SnaffCore.Checkpoint
{
    /// <summary>
    /// Pause/resume for long scans (--checkpoint &lt;file&gt;). An append-only log
    /// records directories whose files have all been scanned (D|path), computers
    /// whose shares were enumerated (C|host) and the shares found (S|host|share).
    /// Re-running the same command skips that work. Directories that were only
    /// partly scanned when the run stopped are scanned again, so a few findings
    /// can appear in both reports. Based on SnaffCon/Snaffler#200.
    /// </summary>
    public class ScanCheckpoint
    {
        public static ScanCheckpoint Instance { get; private set; } = new ScanCheckpoint();

        private readonly object _writeLock = new object();
        private readonly ConcurrentDictionary<string, byte> _completedDirs = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, byte> _completedComputers = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, byte>> _computerShares =
            new ConcurrentDictionary<string, ConcurrentDictionary<string, byte>>(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, int> _pendingFiles = new ConcurrentDictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        private StreamWriter _writer;

        public bool Enabled { get; private set; }
        public bool Resumed { get; private set; }
        public int ResumedDirs => _completedDirs.Count;

        /// <summary>For tests: a fresh, disabled instance.</summary>
        public static void Reset() { Instance.Close(); Instance = new ScanCheckpoint(); }

        public void Load(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            Enabled = true;
            if (File.Exists(path))
            {
                Resumed = true;
                foreach (string line in File.ReadLines(path, Encoding.UTF8))
                {
                    string[] parts = line.Split(new[] { '|' }, 3);
                    if (parts.Length < 2 || parts[1].Length == 0) continue;
                    switch (parts[0])
                    {
                        case "D": _completedDirs.TryAdd(parts[1], 0); break;
                        case "C": _completedComputers.TryAdd(parts[1], 0); break;
                        case "S":
                            if (parts.Length == 3) SharesOf(parts[1]).TryAdd(parts[2], 0);
                            break;
                    }
                }
                BlockingMq.GetMq().Info($"Resuming from checkpoint {path}: {_completedDirs.Count} directories and {_completedComputers.Count} computers already done.");
            }
            else
            {
                BlockingMq.GetMq().Info($"Checkpoint {path} created: re-run the same command to resume if the scan stops.");
            }
            _writer = new StreamWriter(new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read), new UTF8Encoding(false)) { AutoFlush = true };
        }

        public void Close()
        {
            lock (_writeLock)
            {
                try { _writer?.Dispose(); } catch (Exception) { }
                _writer = null;
            }
        }

        public bool IsDirComplete(string dir) => Enabled && _completedDirs.ContainsKey(dir);

        /// <summary>Call before queuing a directory's files; each file task then calls FileDone.</summary>
        public void BeginDir(string dir, int fileCount)
        {
            if (!Enabled) return;
            if (fileCount <= 0) { MarkDir(dir); return; }
            _pendingFiles[dir] = fileCount;
        }

        public void FileDone(string dir)
        {
            if (!Enabled) return;
            int left = _pendingFiles.AddOrUpdate(dir, 0, (_, n) => n - 1);
            if (left <= 0 && _pendingFiles.TryRemove(dir, out _)) MarkDir(dir);
        }

        public bool IsComputerComplete(string computer) => Enabled && _completedComputers.ContainsKey(computer);

        public IEnumerable<string> SharesFor(string computer) =>
            _computerShares.TryGetValue(computer, out var shares) ? (IEnumerable<string>)shares.Keys : Array.Empty<string>();

        public void RecordShare(string computer, string share)
        {
            if (Enabled && SharesOf(computer).TryAdd(share, 0)) Write("S|" + computer + "|" + share);
        }

        public void MarkComputer(string computer)
        {
            if (Enabled && _completedComputers.TryAdd(computer, 0)) Write("C|" + computer);
        }

        private void MarkDir(string dir)
        {
            if (_completedDirs.TryAdd(dir, 0)) Write("D|" + dir);
        }

        private ConcurrentDictionary<string, byte> SharesOf(string computer) =>
            _computerShares.GetOrAdd(computer, _ => new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase));

        private void Write(string line)
        {
            lock (_writeLock)
            {
                try { _writer?.WriteLine(line); }
                catch (Exception e) { BlockingMq.GetMq().Degub("Checkpoint write failed: " + e.Message); }
            }
        }

        /// <summary>
        /// A resumed run must not overwrite the first run's report (the Excel and
        /// JSON outputs are rewritten from scratch): use report-resume-N.ext.
        /// </summary>
        public static string ResumeOutputPath(string outputPath)
        {
            if (string.IsNullOrWhiteSpace(outputPath) || !File.Exists(outputPath)) return outputPath;
            string dir = Path.GetDirectoryName(Path.GetFullPath(outputPath));
            string stem = Path.GetFileNameWithoutExtension(outputPath);
            string ext = Path.GetExtension(outputPath);
            for (int i = 1; ; i++)
            {
                string candidate = Path.Combine(dir, $"{stem}-resume-{i}{ext}");
                if (!File.Exists(candidate)) return candidate;
            }
        }
    }
}
