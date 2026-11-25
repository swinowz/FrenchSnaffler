#if ULTRASNAFFLER
using SharpCompress.Archives;

using SnaffCore.Concurrency;
using SnaffCore.FileScan;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using static SnaffCore.Config.Options;

namespace SnaffCore.Classifiers
{
    public class ArchiveClassifier
    {
        // Separator between an archive and the member path in reports,
        // e.g. \\srv\share\backup.zip!conf\web.config
        public const string MemberSeparator = "!";

        // Temp extraction path -> path shown in reports. Findings raised while a
        // member is scanned must point at the archive, not at a deleted temp file.
        private static readonly ConcurrentDictionary<string, string> DisplayPaths =
            new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // Scans are synchronous on the worker thread: nested archives re-enter
        // Scan() through FileScanner, so depth and byte budget are per thread.
        [ThreadStatic] private static int _depth;
        [ThreadStatic] private static long _budgetLeft;

        public static string GetDisplayPath(string path)
        {
            if (path == null) return null;
            return DisplayPaths.TryGetValue(path, out string display) ? display : null;
        }

        public static void Scan(FileInfo fileInfo, int depth = 0)
        {
            BlockingMq mq = BlockingMq.GetMq();
            if (_depth >= MyOptions.MaxArchiveDepth) { mq.Trace("Archive depth limit reached: " + fileInfo.FullName); return; }
            bool outermost = _depth == 0;
            if (outermost) _budgetLeft = MyOptions.MaxArchiveTotalBytes;
            string archiveDisplay = GetDisplayPath(fileInfo.FullName) ?? fileInfo.FullName;
            string workDir = Path.Combine(Path.GetTempPath(), "sa-" + Guid.NewGuid().ToString("N"));
            int entries = 0;
            _depth++;
            try
            {
                using (IArchive archive = ArchiveFactory.OpenArchive(fileInfo.FullName))
                {
                    foreach (IArchiveEntry entry in archive.Entries)
                    {
                        if (entry.IsDirectory) continue;
                        if (++entries > MyOptions.MaxArchiveEntries) { mq.Trace("Archive entry limit reached: " + archiveDisplay); break; }
                        long declaredSize = entry.Size;
                        long limit = Math.Min(MyOptions.MaxArchiveEntryBytes, _budgetLeft);
                        if (declaredSize > limit)
                        {
                            mq.Trace("Archive entry skipped by size limit: " + entry.Key);
                            continue;
                        }

                        string memberPath = MemberPath(entry.Key, fileInfo.Name);
                        string temp = Path.Combine(workDir, Guid.NewGuid().ToString("N").Substring(0, 8), memberPath);
                        try
                        {
                            Directory.CreateDirectory(Path.GetDirectoryName(temp));
                            long written;
                            using (Stream input = entry.OpenEntryStream())
                            using (FileStream output = File.Create(temp)) written = CopyBounded(input, output, limit);
                            // Declared sizes can lie: the copy itself enforces the limit.
                            if (written < 0) { mq.Trace("Archive entry exceeded size limit while extracting: " + entry.Key); continue; }
                            _budgetLeft -= written;
                            if (entry.LastModifiedTime.HasValue)
                            {
                                try { File.SetLastWriteTime(temp, entry.LastModifiedTime.Value); } catch { }
                            }
                            DisplayPaths[temp] = archiveDisplay + MemberSeparator + memberPath;
                            // FileScanner applies every rule, including EnterArchive for nested archives.
                            new FileScanner().ScanFile(temp);
                        }
                        catch (Exception ex) { mq.Trace("Archive entry failed " + entry.Key + ": " + ex.Message); }
                        finally
                        {
                            DisplayPaths.TryRemove(temp, out _);
                            try { File.Delete(temp); } catch { }
                        }
                    }
                }
            }
            catch (CryptographicException)
            {
                mq.FileResult(new FileResult(fileInfo)
                {
                    MatchedRule = new ClassifierRule() { Triage = Triage.Black, RuleName = "EncryptedArchive" }
                });
            }
            catch (Exception e)
            {
                mq.Trace(e.ToString());
            }
            finally
            {
                _depth--;
                try { if (Directory.Exists(workDir)) Directory.Delete(workDir, true); } catch { }
            }
        }

        // Returns the number of bytes copied, or -1 as soon as the limit is exceeded.
        public static long CopyBounded(Stream input, Stream output, long limit)
        {
            byte[] buffer = new byte[81920];
            long total = 0;
            int read;
            while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                total += read;
                if (total > limit) return -1;
                output.Write(buffer, 0, read);
            }
            return total;
        }

        // Keeps the member's real file name (name-based rules need it) and its last
        // folders (path-based rules such as \.ssh\ need them). Drops "..", rooted
        // and invalid parts so a member can never be written outside the work dir.
        public static string MemberPath(string key, string archiveName)
        {
            var parts = new List<string>();
            foreach (string raw in (key ?? "").Split('/', '\\'))
            {
                if (raw.Length == 0 || raw == "." || raw == "..") continue;
                char[] chars = raw.ToCharArray();
                for (int i = 0; i < chars.Length; i++)
                    if (Array.IndexOf(InvalidNameChars, chars[i]) >= 0) chars[i] = '_';
                string part = new string(chars).TrimEnd('.', ' ');
                if (part.Length > 100) part = part.Substring(0, 100);
                if (part.Length > 0) parts.Add(part);
            }
            if (parts.Count == 0)
            {
                // Single-stream formats (.gz, .bz2, .xz) often have no member name.
                string inner = Path.GetFileNameWithoutExtension(archiveName ?? "");
                parts.Add(inner.Length > 0 ? inner : "entry");
            }
            const int maxParts = 5;
            if (parts.Count > maxParts) parts.RemoveRange(0, parts.Count - maxParts);
            return Path.Combine(parts.ToArray());
        }

        // Windows rules apply even when the scanner runs elsewhere (tests on Linux).
        private static readonly char[] InvalidNameChars = BuildInvalidNameChars();

        private static char[] BuildInvalidNameChars()
        {
            var chars = new List<char>("<>:\"|?*");
            for (char c = (char)0; c < 32; c++) chars.Add(c);
            return chars.ToArray();
        }
    }
}
#endif
