#if ULTRASNAFFLER
using SharpCompress.Archives;

using SnaffCore.Concurrency;
using SnaffCore.FileScan;
using System;
using System.IO;
using System.Security.Cryptography;
using SnaffCore;
using static SnaffCore.Config.Options;

namespace SnaffCore.Classifiers
{
    public class ArchiveClassifier
    {
        public static void Scan(FileInfo fileInfo, int depth = 0)
        {
            BlockingMq mq = BlockingMq.GetMq();
            if (depth >= MyOptions.MaxArchiveDepth) { mq.Trace("Archive depth limit reached: " + fileInfo.FullName); return; }
            long totalBytes = 0;
            int entries = 0;
            try
            {
                using (IArchive archive = ArchiveFactory.OpenArchive(fileInfo.FullName))
                {
                    foreach (IArchiveEntry entry in archive.Entries)
                    {
                        if (entry.IsDirectory) continue;
                        if (++entries > MyOptions.MaxArchiveEntries) break;
                        long declaredSize = entry.Size;
                        if (declaredSize < 0 || declaredSize > MyOptions.MaxArchiveEntryBytes || totalBytes > MyOptions.MaxArchiveTotalBytes - declaredSize)
                        {
                            mq.Trace("Archive entry skipped by size limit: " + entry.Key);
                            continue;
                        }
                        string extension = Path.GetExtension(entry.Key);
                        string temp = Path.Combine(Path.GetTempPath(), "snaffle-" + Guid.NewGuid().ToString("N") + extension);
                        try
                        {
                            using (Stream input = entry.OpenEntryStream())
                            using (FileStream output = File.Create(temp)) input.CopyTo(output);
                            long actualSize = new FileInfo(temp).Length;
                            if (actualSize > MyOptions.MaxArchiveEntryBytes || totalBytes > MyOptions.MaxArchiveTotalBytes - actualSize) continue;
                            totalBytes += actualSize;
                            new FileScanner().ScanFile(temp);
                            if (IsArchive(extension)) Scan(new FileInfo(temp), depth + 1);
                        }
                        catch (Exception ex) { mq.Trace("Archive entry failed " + entry.Key + ": " + ex.Message); }
                        finally { try { File.Delete(temp); } catch { } }
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
        }

        private static bool IsArchive(string extension)
        {
            switch ((extension ?? "").ToLowerInvariant())
            {
                case ".zip": case ".7z": case ".rar": case ".tar": case ".gz": case ".tgz": case ".bz2": case ".xz": return true;
                default: return false;
            }
        }
    }
}
#endif
