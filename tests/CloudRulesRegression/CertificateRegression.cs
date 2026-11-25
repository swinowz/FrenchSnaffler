using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SnaffCore.Concurrency;
using SnaffCore.Config;
using SnaffCore.FileScan;

// Certificate files: private keys must be found (PEM and PKCS#12), weak
// passwords cracked, and public-only certificates must stay silent.
static class CertificateRegression
{
    public static int Run()
    {
        string dir = Path.Combine(Path.GetTempPath(), "shareauditor-cert-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        Options.MyOptions.CertPasswords ??= new List<string> { "", "password", "changeme" };
        int failed = 0, total = 0;
        try
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=synthetic-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

            string pemKey = Write("withkey.pem", cert.ExportCertificatePem() + "\n" + rsa.ExportRSAPrivateKeyPem());
            Check("PEM with RSA private key", () => Context(pemKey)?.Contains("HasPrivateKey") == true);
            string pemPkcs8 = Write("pkcs8.pem", cert.ExportCertificatePem() + "\n" + rsa.ExportPkcs8PrivateKeyPem());
            Check("PEM with PKCS#8 private key", () => Context(pemPkcs8)?.Contains("HasPrivateKey") == true);
            string pemBareKey = Write("server-key.pem", rsa.ExportPkcs8PrivateKeyPem());
            Check("PEM private key without certificate", () => Context(pemBareKey) is string c && c.Contains("PrivateKeyWithoutCertificate"));
            string pemPublic = Write("public.pem", cert.ExportCertificatePem());
            Check("PEM public certificate silent", () => Context(pemPublic) == null);
            string der = WriteBytes("public.der", cert.Export(X509ContentType.Cert));
            Check("DER public certificate silent", () => Context(der) == null);

            string pfxOpen = WriteBytes("open.pfx", cert.Export(X509ContentType.Pfx, ""));
            Check("PFX without password", () => Context(pfxOpen) is string c && c.Contains("HasPrivateKey") && c.Contains("NoPasswordRequired"));
            string pfxWeak = WriteBytes("weak.pfx", cert.Export(X509ContentType.Pfx, "changeme"));
            Check("PFX weak password cracked", () => Context(pfxWeak) is string c && c.Contains("PasswordCracked: changeme") && c.Contains("HasPrivateKey"));
            string pfxStrong = WriteBytes("strong.p12", cert.Export(X509ContentType.Pfx, "x9-" + Guid.NewGuid().ToString("N")));
            Check("PFX strong password flagged", () => Context(pfxStrong) is string c && c.Contains("HasPassword"));

            void Check(string name, Func<bool> test)
            {
                total++;
                try { if (test()) { Console.WriteLine("PASS " + name); return; } }
                catch (Exception ex) { Console.WriteLine("  " + ex.GetType().Name + ": " + ex.Message); }
                Console.WriteLine("FAIL " + name);
                failed++;
            }
        }
        finally { Directory.Delete(dir, true); }
        Console.WriteLine($"{total - failed}/{total} certificate regressions passed");
        return failed;

        string Write(string name, string text) { string p = Path.Combine(dir, name); File.WriteAllText(p, text); return p; }
        string WriteBytes(string name, byte[] bytes) { string p = Path.Combine(dir, name); File.WriteAllBytes(p, bytes); return p; }
    }

    // MatchContext of the certificate finding, or null if none was raised.
    private static string? Context(string path)
    {
        BlockingMq.MakeMq();
        new FileScanner().ScanFile(path);
        string? context = null;
        while (BlockingMq.GetMq().Q.TryTake(out var message))
        {
            if (message.FileResult?.MatchedRule?.RuleName == "RelayCertByExtension") context = message.FileResult.TextResult?.MatchContext ?? "";
            if (message.Type == SnafflerMessageType.Error) Console.WriteLine("  Error: " + message.Message.Split('\n')[0]);
        }
        return context;
    }
}
