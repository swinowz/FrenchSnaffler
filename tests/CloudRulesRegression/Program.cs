using System.IO.Compression;
using System.Runtime.CompilerServices;
using Nett;
using SnaffCore.Classifiers;
using SnaffCore.Concurrency;
using SnaffCore.Config;
using SnaffCore.FileScan;

// These regressions catch unreachable content rules and JSON fields that do not
// match their signatures. Exercise the real rules, file scanner and result queue.
// Skip only the Windows identity initializer: local classification needs no AD.
BlockingMq.MakeMq();
var options = (Options)RuntimeHelpers.GetUninitializedObject(typeof(Options));
options.ClassifierRules = Directory.GetFiles(Path.Combine(AppContext.BaseDirectory, "Rules"), "*.toml", SearchOption.AllDirectories)
    .OrderBy(path => path, StringComparer.Ordinal)
    .SelectMany(path => Toml.ReadString<RuleSet>(File.ReadAllText(path)).ClassifierRules).ToList();
options.MaxSizeToGrep = 1_000_000;
options.MatchContextBytes = 200;
options.LogType = LogType.Plain;
Options.MyOptions = options;
options.PrepareClassifiers();
var rules = options.ClassifierRules.ToDictionary(rule => rule.RuleName);
foreach (var relay in rules.Values.Where(rule => rule.MatchAction == MatchAction.Relay))
    foreach (var target in relay.RelayTargets)
        if (!rules.ContainsKey(target)) throw new Exception($"Unknown relay target: {relay.RuleName} -> {target}");

// Deliberately fake values, assembled at runtime so no credential-like fixtures
// are stored in Git. None is usable against a service.
string github = "ghp_" + new string('A', 24);
string fineGrained = "github_pat_" + new string('B', 30);
string google = "AIza" + new string('C', 35);
string secret = new string('D', 24);
string jwt = "eyJ" + new string('E', 12) + "." + new string('F', 16) + "." + new string('G', 16);
string auth = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("synthetic-user:invalid-test-password"));
var cases = new (string Path, string Content, string Rule, bool Expected)[]
{
    ("github.json", github, "KeepGitHubToken", true),
    ("fine-grained.yaml", fineGrained, "KeepGitHubToken", true),
    ("google.ini", google, "KeepGoogleApiKey", true),
    ("azure.json", "{\"client_secret\":\"" + secret + "\"}", "KeepAzureClientSecret", true),
    ("azure.env", "CLIENT_SECRET=" + secret, "KeepAzureClientSecret", true),
    ("jwt.txt", jwt, "KeepJwtToken", true),
    ("kube.yaml", "client-key-data: " + secret, "KeepKubernetesConfig", true),
    ("kube/config", "token: " + secret, "KeepKubernetesConfig", true),
    (".docker/config.json", "{\"auths\":{\"registry.example.test\":{\"auth\":\"" + auth + "\"}}}", "KeepDockerRegistryCredential", true),
    (".dockercfg", "{\"registry.example.test\":{\"auth\":\"" + auth + "\"}}", "KeepDockerRegistryCredential", true),
    ("app.py", github, "KeepGitHubToken", true),
    ("app.js", google, "KeepGoogleApiKey", true),
    ("app.ps1", github, "KeepGitHubToken", true),
    ("deploy.sh", github, "KeepGitHubToken", true),
    ("infra.tf", "client_secret = \"" + secret + "\"", "KeepAzureClientSecret", true),
    ("env/.env", "CLIENT_SECRET=" + secret, "KeepAzureClientSecret", true),
    ("env/.env.local", github, "KeepGitHubToken", true),
    ("example.docx", github, "KeepGitHubToken", true),
    ("username-only/.docker/config.json", "{\"username\":\"a-long-public-username\"}", "KeepDockerRegistryCredential", false),
    ("normal/config.json", "{\"auth\":\"" + auth + "\"}", "KeepDockerRegistryCredential", false),
    ("short.json", "{\"client_secret\":\"short\"}", "KeepAzureClientSecret", false),
    ("short.txt", "ghp_short", "KeepGitHubToken", false),
    ("empty.yaml", "apiVersion: v1\nkind: Config", "KeepKubernetesConfig", false),
    ("image.png", github, "KeepGitHubToken", false),
};
string temp = Path.Combine(Path.GetTempPath(), "shareauditor-cloud-tests-" + Guid.NewGuid().ToString("N"));
int failed = 0;
try
{
    foreach (var test in cases)
    {
        string path = Path.Combine(temp, test.Path);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        if (path.EndsWith(".docx", StringComparison.Ordinal))
        {
            using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
            using var writer = new StreamWriter(zip.CreateEntry("word/document.xml").Open());
            writer.Write("<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>" + test.Content + "</w:t></w:r></w:p></w:body></w:document>");
        }
        else File.WriteAllText(path, test.Content);
        new FileScanner().ScanFile(path);
        var found = new HashSet<string>();
        var errors = new List<string>();
        while (BlockingMq.GetMq().Q.TryTake(out var message))
        {
            if (message.FileResult != null) found.Add(message.FileResult.MatchedRule.RuleName);
            if (message.Type == SnafflerMessageType.Error) errors.Add(message.Message);
        }
        bool pass = found.Contains(test.Rule) == test.Expected && errors.Count == 0;
        Console.WriteLine($"{(pass ? "PASS" : "FAIL")} {test.Path}: {test.Rule} {(test.Expected ? "detected" : "absent")}");
        if (!pass)
        {
            failed++;
            Console.WriteLine("  Findings: " + string.Join(", ", found));
            foreach (var error in errors) Console.WriteLine("  Error: " + error);
        }
    }
}
finally { if (Directory.Exists(temp)) Directory.Delete(temp, true); }
Console.WriteLine($"{cases.Length - failed}/{cases.Length} passed");
failed += ParserRegression.Run();
failed += ArchiveRegression.Run();
failed += FormatRegression.Run();
return failed == 0 ? 0 : 1;

public class RuleSet
{
    public List<ClassifierRule> ClassifierRules { get; set; } = new();
}
