using System.IO.Compression;
using SnaffCore.Concurrency;
using SnaffCore.FileScan;

// Formats added to content scanning: OpenDocument (LibreOffice) and the Word
// parts that the fast DOCX reader used to skip (footnotes, endnotes, comments).
static class FormatRegression
{
    public static int Run()
    {
        string dir = Path.Combine(Path.GetTempPath(), "shareauditor-format-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        string marker = "ghp_" + new string('K', 24);
        string marker2 = "ghp_" + new string('N', 24);
        int failed = 0, total = 0;
        const string odfNs = "xmlns:office=\"urn:oasis:names:tc:opendocument:xmlns:office:1.0\" xmlns:text=\"urn:oasis:names:tc:opendocument:xmlns:text:1.0\" xmlns:table=\"urn:oasis:names:tc:opendocument:xmlns:table:1.0\"";
        try
        {
            string odt = Package(dir, "notes.odt", "application/vnd.oasis.opendocument.text",
                ("content.xml", $"<office:document-content {odfNs}><office:body><office:text><text:p>token {marker}</text:p></office:text></office:body></office:document-content>"));
            Check("OpenDocument text (.odt)", () => Found(odt, "KeepGitHubToken"));

            string ods = Package(dir, "comptes.ods", "application/vnd.oasis.opendocument.spreadsheet",
                ("content.xml", $"<office:document-content {odfNs}><office:body><office:spreadsheet><table:table>" +
                 "<table:table-row><table:table-cell><text:p>service</text:p></table:table-cell><table:table-cell><text:p>key</text:p></table:table-cell></table:table-row>" +
                 $"<table:table-row><table:table-cell><text:p>ci</text:p></table:table-cell><table:table-cell><text:p>{marker}</text:p></table:table-cell></table:table-row>" +
                 "</table:table></office:spreadsheet></office:body></office:document-content>"));
            Check("OpenDocument spreadsheet (.ods)", () => Found(ods, "KeepGitHubToken"));

            string encrypted = Package(dir, "secret.ods", "application/vnd.oasis.opendocument.spreadsheet",
                ("content.xml", "binary-encrypted-garbage"),
                ("META-INF/manifest.xml", "<manifest:manifest><manifest:file-entry manifest:full-path=\"content.xml\"><manifest:encryption-data/></manifest:file-entry></manifest:manifest>"));
            Check("Encrypted OpenDocument reported", () => Found(encrypted, "PasswordProtectedFile"));

            string clean = Package(dir, "clean.odt", "application/vnd.oasis.opendocument.text",
                ("content.xml", $"<office:document-content {odfNs}><office:body><office:text><text:p>Compte rendu de reunion, rien a signaler.</text:p></office:text></office:body></office:document-content>"));
            Check("Clean OpenDocument has no finding", () => !Findings(clean).Any());

            foreach (var part in new[] { "footnotes", "endnotes", "comments" })
            {
                string docx = Path.Combine(dir, part + ".docx");
                using (var zip = ZipFile.Open(docx, ZipArchiveMode.Create))
                {
                    Write(zip, "word/document.xml", "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>Body text only</w:t></w:r></w:p></w:body></w:document>");
                    Write(zip, $"word/{part}.xml", $"<w:{part} xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:p><w:r><w:t>{marker}</w:t></w:r></w:p></w:{part}>");
                }
                Check($"Word {part} scanned", () => Found(docx, "KeepGitHubToken"));
            }

            // PowerPoint: token on a slide, and a second token only in the slide notes
            const string aNs = "xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\"";
            string pptx = Path.Combine(dir, "deck.pptx");
            using (var zip = ZipFile.Open(pptx, ZipArchiveMode.Create))
            {
                Write(zip, "ppt/slides/slide1.xml", $"<p:sld xmlns:p=\"x\"><p:cSld><p:spTree><a:p {aNs}><a:r><a:t>intro {marker}</a:t></a:r></a:p></p:spTree></p:cSld></p:sld>");
                Write(zip, "ppt/notesSlides/notesSlide1.xml", $"<p:notes><a:p {aNs}><a:r><a:t>note {marker2}</a:t></a:r></a:p></p:notes>");
            }
            Check("PowerPoint slide text (.pptx)", () => Found(pptx, "KeepGitHubToken"));
            string notesOnly = Path.Combine(dir, "notesonly.pptx");
            using (var zip = ZipFile.Open(notesOnly, ZipArchiveMode.Create))
            {
                Write(zip, "ppt/slides/slide1.xml", $"<p:sld xmlns:p=\"x\"><p:cSld><p:spTree><a:p {aNs}><a:r><a:t>nothing sensitive here</a:t></a:r></a:p></p:spTree></p:cSld></p:sld>");
                Write(zip, "ppt/notesSlides/notesSlide1.xml", $"<p:notes><a:p {aNs}><a:r><a:t>note {marker}</a:t></a:r></a:p></p:notes>");
            }
            Check("PowerPoint speaker notes (.pptx)", () => Found(notesOnly, "KeepGitHubToken"));

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
        Console.WriteLine($"{total - failed}/{total} format regressions passed");
        return failed;
    }

    private static string Package(string dir, string name, string mime, params (string Entry, string Content)[] parts)
    {
        string path = Path.Combine(dir, name);
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        Write(zip, "mimetype", mime);
        foreach (var (entry, content) in parts) Write(zip, entry, content);
        return path;
    }

    private static void Write(ZipArchive zip, string entry, string content)
    {
        using var writer = new StreamWriter(zip.CreateEntry(entry).Open());
        writer.Write(content);
    }

    private static bool Found(string path, string rule) => Findings(path).Contains(rule);

    private static List<string> Findings(string path)
    {
        BlockingMq.MakeMq();
        new FileScanner().ScanFile(path);
        var found = new List<string>();
        while (BlockingMq.GetMq().Q.TryTake(out var message))
            if (message.FileResult != null) found.Add(message.FileResult.MatchedRule.RuleName);
        return found;
    }
}
