using System.Security.Cryptography;
using System.Text;
using SnaffCore.Concurrency;
using SnaffCore.FileScan;
using SnaffCore.TreeWalk;

// SCCM content library: FileLib files are stored under their hash, names live in
// DataLib\<package>\...\<name>.INI. Findings must use the real names and paths.
static class SccmRegression
{
    public static int Run()
    {
        string dir = Path.Combine(Path.GetTempPath(), "shareauditor-sccm-tests-" + Guid.NewGuid().ToString("N"));
        string lib = Path.Combine(dir, "SCCMContentLib$");
        string marker = "ghp_" + new string('S', 24);
        int failed = 0, total = 0;
        try
        {
            string unattendHash = Store(lib, "<AdministratorPassword><Value>synthetic-not-a-password</Value></AdministratorPassword>");
            string scriptHash = Store(lib, "$token = '" + marker + "'\r\n");
            string keyHash = Store(lib, "-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic\n");
            string unattend = Entry(lib, @"PKG00001.1\Sources\unattend.xml", unattendHash);
            string script = Entry(lib, @"PKG00002.1\Scripts\deploy.ps1", scriptHash);
            string scriptCopy = Entry(lib, @"PKG00003.1\Copy\deploy-copy.ps1", scriptHash); // single-instance store
            string key = Entry(lib, @"PKG00004.1\home\.ssh\id_rsa", keyHash);
            string noSection = Write(Path.Combine(lib, "DataLib", "PKG00005.1", "folder.INI"), "Hash=" + scriptHash + "\r\n");
            string missing = Entry(lib, @"PKG00006.1\gone.ps1", new string('F', 64));

            Check("Content library root detected", () => SccmContentLib.IsContentLibRoot(lib) &&
                !SccmContentLib.IsContentLibRoot(Path.Combine(lib, "DataLib")) && !SccmContentLib.IsContentLibRoot(dir));
            Check("Hash-named file alone misses name rules (old behaviour)", () =>
                !ScanRaw(FileLib(lib, unattendHash)).Any(f => f.Rule == "KeepUnattendXmlRegexRed"));
            Check("unattend.xml found under its DataLib name", () =>
                Scan(unattend, lib).Any(f => f.Rule == "KeepUnattendXmlRegexRed" && f.Path == Logical(unattend)));
            Check("Script content rule through DataLib name", () => Scan(script, lib).Any(f => f.Rule == "KeepGitHubToken"));
            Check("Same FileLib file reported under each name", () =>
                Scan(scriptCopy, lib).Any(f => f.Rule == "KeepGitHubToken" && f.Path == Logical(scriptCopy)));
            Check("id_rsa found under its DataLib name", () => Scan(key, lib).Any(f => f.Rule == "KeepSSHKeysByFileName"));
            Check("INI without [File] section ignored", () => Scan(noSection, lib).Count == 0);
            Check("Missing FileLib content ignored", () => Scan(missing, lib).Count == 0);

            void Check(string name, Func<bool> test)
            {
                total++;
                try { if (test()) { Console.WriteLine("PASS " + name); return; } }
                catch (Exception ex) { Console.WriteLine("  " + ex.GetType().Name + ": " + ex.Message); }
                Console.WriteLine("FAIL " + name);
                failed++;
            }
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
        Console.WriteLine($"{total - failed}/{total} SCCM regressions passed");
        return failed;
    }

    private static string Store(string lib, string content)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(content);
        string hash = Convert.ToHexString(SHA256.HashData(bytes));
        string path = FileLib(lib, hash);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, bytes);
        return hash;
    }

    private static string FileLib(string lib, string hash) => Path.Combine(lib, "FileLib", hash.Substring(0, 4), hash);

    private static string Entry(string lib, string relative, string hash) =>
        Write(Path.Combine(new[] { lib, "DataLib" }.Concat(relative.Split('\\')).ToArray()) + ".INI",
            "[File]\r\nHash=" + hash + "\r\nSize=1\r\n");

    private static string Write(string path, string text)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, text, Encoding.Unicode);
        return path;
    }

    private static string Logical(string ini) => ini.Substring(0, ini.Length - 4);

    private static List<(string Rule, string Path)> Scan(string ini, string lib)
    {
        BlockingMq.MakeMq();
        SccmContentLib.ScanDataLibEntry(ini, lib, new FileScanner());
        return Drain();
    }

    private static List<(string Rule, string Path)> ScanRaw(string path)
    {
        BlockingMq.MakeMq();
        new FileScanner().ScanFile(path);
        return Drain();
    }

    private static List<(string Rule, string Path)> Drain()
    {
        var found = new List<(string, string)>();
        while (BlockingMq.GetMq().Q.TryTake(out var message))
            if (message.FileResult != null) found.Add((message.FileResult.MatchedRule.RuleName, message.FileResult.ReportPath));
        return found;
    }
}
