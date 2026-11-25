using System.IO.Compression;
using SnaffCore.Classifiers;
using SnaffCore.Concurrency;
using SnaffCore.Config;
using SnaffCore.FileScan;

// Archive members must be reported where they really are (inside the archive),
// keep their real names for name-based rules, honour the depth limit and never
// be written outside the extraction folder. Uses reflection for the report path
// so the same checks also run against older builds (before/after comparison).
static class ArchiveRegression
{
    public static int Run()
    {
        string dir = Path.Combine(Path.GetTempPath(), "shareauditor-archive-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        string marker = "ghp_" + new string('J', 24);
        int failed = 0, total = 0;
        try
        {
            Options.MyOptions.MaxArchiveDepth = 3;
            Options.MyOptions.MaxArchiveEntries = 10_000;
            Options.MyOptions.MaxArchiveEntryBytes = 50 * 1024 * 1024;
            Options.MyOptions.MaxArchiveTotalBytes = 500 * 1024 * 1024;

            string ssh = Zip(dir, "home-backup.zip", ("home/bob/.ssh/id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic\n"));
            Check("Name rule inside archive (id_rsa)", () => Scan(ssh).Any(f => f.Rule == "KeepSSHKeysByFileName"));
            Check("Report path points into the archive", () => Scan(ssh).Any(f =>
                f.Rule == "KeepSSHKeysByFileName" && f.Path.StartsWith(ssh + "!", StringComparison.Ordinal) &&
                f.Path.EndsWith(Path.Combine("home", "bob", ".ssh", "id_rsa"), StringComparison.Ordinal)));

            string unattend = Zip(dir, "deploy.zip", ("sources/unattend.xml",
                "<AdministratorPassword><Value>synthetic-not-a-password</Value></AdministratorPassword>"));
            Check("Relay-by-name inside archive (unattend.xml)", () => Scan(unattend).Any(f => f.Rule == "KeepUnattendXmlRegexRed"));

            string inner = Zip(dir, "inner.zip", ("config.txt", marker));
            string outer = Zip(dir, "outer.zip", ("nested/inner.zip", File.ReadAllBytes(inner)));
            Check("Nested archive reported once", () => Scan(outer).Count(f => f.Rule == "KeepGitHubToken") == 1);
            Check("Nested report path chains archives", () => Scan(outer).Any(f =>
                f.Path == outer + "!" + Path.Combine("nested", "inner.zip") + "!config.txt"));

            // marker four archives deep, limit is three levels
            string level = Zip(dir, "l4.zip", ("config.txt", marker));
            for (int i = 3; i >= 1; i--) level = Zip(dir, $"l{i}.zip", ($"l{i + 1}.zip", File.ReadAllBytes(level)));
            Check("Depth limit honoured", () => !Scan(level).Any(f => f.Rule == "KeepGitHubToken"));
            string shallow = Zip(dir, "s1.zip", ("s2.zip", File.ReadAllBytes(Zip(dir, "s2.zip", ("s3.zip", File.ReadAllBytes(Zip(dir, "s3.zip", ("config.txt", marker))))))));
            Check("Depth 3 still scanned", () => Scan(shallow).Count(f => f.Rule == "KeepGitHubToken") == 1);

            string escapeName = "sa-escape-" + Guid.NewGuid().ToString("N") + ".txt";
            string slip = Zip(dir, "slip.zip", ("../../" + escapeName, marker));
            Check("Zip-slip member scanned and contained", () =>
            {
                bool found = Scan(slip).Any(f => f.Rule == "KeepGitHubToken");
                string tmp = Path.GetTempPath();
                bool escaped = File.Exists(Path.Combine(tmp, escapeName)) ||
                    File.Exists(Path.Combine(Path.GetDirectoryName(tmp.TrimEnd(Path.DirectorySeparatorChar)) ?? tmp, escapeName));
                return found && !escaped;
            });

            Check("No extraction leftovers", () =>
                !Directory.GetDirectories(Path.GetTempPath(), "sa-*").Any(d => Directory.GetLastWriteTimeUtc(d) > DateTime.UtcNow.AddMinutes(-5)));

            var copy = typeof(ArchiveClassifier).GetMethod("CopyBounded");
            Check("Copy stops at the size limit", () =>
            {
                if (copy == null) return false;
                using var input = new MemoryStream(new byte[300_000]);
                using var output = new MemoryStream();
                long result = (long)copy.Invoke(null, new object[] { input, output, 100_000L })!;
                return result == -1 && output.Length <= 100_000;
            });

            void Check(string name, Func<bool> test)
            {
                total++;
                try
                {
                    if (test()) { Console.WriteLine("PASS " + name); return; }
                }
                catch (Exception ex) { Console.WriteLine("  " + ex.GetType().Name + ": " + ex.Message); }
                Console.WriteLine("FAIL " + name);
                failed++;
            }
        }
        finally { Directory.Delete(dir, true); }
        Console.WriteLine($"{total - failed}/{total} archive regressions passed");
        return failed;
    }

    private static string Zip(string dir, string name, params (string Entry, object Content)[] entries)
    {
        string path = Path.Combine(dir, name);
        if (File.Exists(path)) File.Delete(path);
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach (var (entry, content) in entries)
        {
            using var stream = zip.CreateEntry(entry).Open();
            byte[] bytes = content as byte[] ?? System.Text.Encoding.UTF8.GetBytes((string)content);
            stream.Write(bytes, 0, bytes.Length);
        }
        return path;
    }

    private static List<(string Rule, string Path)> Scan(string path)
    {
        BlockingMq.MakeMq();
        new FileScanner().ScanFile(path);
        var found = new List<(string, string)>();
        while (BlockingMq.GetMq().Q.TryTake(out var message))
        {
            var result = message.FileResult;
            if (result == null) continue;
            string shown = result.GetType().GetProperty("ReportPath")?.GetValue(result) as string ?? result.FileInfo.FullName;
            found.Add((result.MatchedRule.RuleName, shown));
        }
        return found;
    }
}
