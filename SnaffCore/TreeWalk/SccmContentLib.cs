using SnaffCore.Classifiers;
using SnaffCore.Concurrency;
using SnaffCore.FileScan;
using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace SnaffCore.TreeWalk
{
    /// <summary>
    /// SCCM content library (SCCMContentLib$). Files are stored once under their
    /// hash in FileLib\&lt;first 4 chars&gt;\&lt;hash&gt;; their real names only
    /// exist as DataLib\&lt;package&gt;\...\&lt;name&gt;.INI files holding "Hash=".
    /// Walking the share as-is scans hash-named files, so name rules
    /// (unattend.xml, *.ps1, web.config) never match. Instead each DataLib entry
    /// is resolved and its FileLib file is scanned and reported under the DataLib
    /// path. Layout as used by CMLoot; based on SnaffCon/Snaffler#187.
    /// </summary>
    public static class SccmContentLib
    {
        private static readonly Regex HashLine = new Regex(@"^\s*Hash\s*=\s*([0-9A-Fa-f]{32,128})\s*$",
            RegexOptions.Multiline | RegexOptions.CultureInvariant | RegexOptions.Compiled);
        private static readonly Regex FileSection = new Regex(@"^\s*\[File\]\s*$",
            RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
        private const long MaxIniBytes = 64 * 1024;

        /// <summary>True for a folder named SCCMContentLib or SCCMContentLib$ holding DataLib and FileLib.</summary>
        public static bool IsContentLibRoot(string dir)
        {
            if (string.IsNullOrEmpty(dir)) return false;
            string trimmed = dir.TrimEnd('\\', '/');
            string leaf = trimmed.Substring(trimmed.LastIndexOfAny(new[] { '\\', '/' }) + 1);
            if (!leaf.Equals("SCCMContentLib", StringComparison.OrdinalIgnoreCase) &&
                !leaf.Equals("SCCMContentLib$", StringComparison.OrdinalIgnoreCase)) return false;
            try
            {
                return Directory.Exists(Path.Combine(dir, "DataLib")) && Directory.Exists(Path.Combine(dir, "FileLib"));
            }
            catch (Exception) { return false; }
        }

        /// <summary>FileLib file referenced by a DataLib .INI, or null.</summary>
        public static string ResolveDataLibEntry(string iniPath, string libRoot)
        {
            if (!iniPath.EndsWith(".INI", StringComparison.OrdinalIgnoreCase)) return null;
            var info = new FileInfo(iniPath);
            if (!info.Exists || info.Length > MaxIniBytes) return null;
            string text = ReadIni(iniPath);
            if (!FileSection.IsMatch(text)) return null;
            Match hash = HashLine.Match(text);
            if (!hash.Success) return null;
            string value = hash.Groups[1].Value;
            string target = Path.Combine(libRoot, "FileLib", value.Substring(0, 4), value);
            return File.Exists(target) ? target : null;
        }

        public static void ScanDataLibEntry(string iniPath, string libRoot, FileScanner scanner)
        {
            BlockingMq mq = BlockingMq.GetMq();
            string target = ResolveDataLibEntry(iniPath, libRoot);
            if (target == null)
            {
                mq.Trace("SCCM DataLib entry without readable FileLib content: " + iniPath);
                return;
            }
            string logical = iniPath.Substring(0, iniPath.Length - 4);
            using (ScanAliases.Use(target, logical))
                scanner.ScanFile(target);
        }

        // INI files may be UTF-16 with a BOM or 8-bit text: let the reader detect it.
        private static string ReadIni(string path)
        {
            using (var reader = new StreamReader(path, Encoding.UTF8, detectEncodingFromByteOrderMarks: true))
                return reader.ReadToEnd();
        }
    }
}
