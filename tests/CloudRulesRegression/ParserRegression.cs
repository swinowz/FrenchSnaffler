using System.IO.Compression;
using System.Text;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;
using NPOI.HSSF.UserModel;
using OfficeOpenXml;
using OpenMcdf;
using SnaffCore.Classifiers;
using SnaffCore.Concurrency;
using SnaffCore.Config;
using SnaffCore.FileScan;

// Package upgrades must preserve real parsing, not just compile successfully.
static class ParserRegression
{
    public static int Run()
    {
        string dir = Path.Combine(Path.GetTempPath(), "shareauditor-parser-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        string marker = "ghp_" + new string('H', 24);
        int failed = 0;
        try
        {
            Options.MyOptions.MaxArchiveDepth = 3;
            Options.MyOptions.MaxArchiveEntries = 10_000;
            Options.MyOptions.MaxArchiveEntryBytes = 50 * 1024 * 1024;
            Options.MyOptions.MaxArchiveTotalBytes = 500 * 1024 * 1024;
            ExcelPackage.LicenseContext = LicenseContext.NonCommercial;

            string xlsx = Path.Combine(dir, "synthetic.xlsx");
            using (var book = new ExcelPackage())
            {
                book.Workbook.Worksheets.Add("Data").Cells[1, 1].Value = marker;
                book.SaveAs(new FileInfo(xlsx));
            }
            Check("Excel XLSX streaming", () => Detected(xlsx));

            string xls = Path.Combine(dir, "synthetic.xls");
            using (var book = new HSSFWorkbook())
            {
                book.CreateSheet("Data").CreateRow(0).CreateCell(0).SetCellValue(marker);
                using var stream = File.Create(xls);
                book.Write(stream);
            }
            Check("Excel XLS streaming", () => Detected(xls));

            string docx = Path.Combine(dir, "synthetic.docx");
            using (var doc = WordprocessingDocument.Create(docx, WordprocessingDocumentType.Document))
            {
                doc.AddMainDocumentPart().Document = new Document(new Body(new Paragraph(new Run(new Text(marker)))));
            }
            Check("Toxy/OpenXML fallback", () => new ContentClassifier(new ClassifierRule())
                .ParseFileToString(new FileInfo(docx)).Contains(marker, StringComparison.Ordinal));

            string msg = Path.Combine(dir, "synthetic.msg");
            using (var root = RootStorage.Create(msg))
            {
                WriteStream("__properties_version1.0", new byte[32]);
                WriteStream("__substg1.0_001A001F", Encoding.Unicode.GetBytes("IPM.Note\0"));
                WriteStream("__substg1.0_0037001F", Encoding.Unicode.GetBytes("Synthetic test\0"));
                WriteStream("__substg1.0_1000001F", Encoding.Unicode.GetBytes(marker + "\0"));
                void WriteStream(string name, byte[] bytes)
                {
                    using var stream = root.CreateStream(name);
                    stream.Write(bytes, 0, bytes.Length);
                }
            }
            Check("Toxy/MsgReader/OpenMcdf fallback", () => new ContentClassifier(new ClassifierRule())
                .ParseFileToString(new FileInfo(msg)).Contains(marker, StringComparison.Ordinal));

            string zipPath = Path.Combine(dir, "synthetic.zip");
            using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
            using (var writer = new StreamWriter(zip.CreateEntry("config.txt").Open())) writer.Write(marker);
            Check("SharpCompress ZIP member scanning", () => Detected(zipPath));

            Check("Excel findings report", () =>
            {
                BlockingMq.MakeMq();
                var mq = BlockingMq.GetMq();
                Options.MyOptions.LogType = LogType.Auto;
                string report = Path.Combine(dir, "report.xlsx");
                try
                {
                    mq.InitCsvOutput(report);
                    new FileScanner().ScanFile(docx);
                    mq.FinalizeCsv();
                    using var book = new ExcelPackage(new FileInfo(report));
                    var sheet = book.Workbook.Worksheets["Findings"];
                    return sheet != null && sheet.Dimension.End.Row > 1 &&
                        sheet.Cells.Any(cell => cell.Text.Trim('"') == "KeepGitHubToken");
                }
                finally { mq.Dispose(); Options.MyOptions.LogType = LogType.Plain; }
            });

            void Check(string name, Func<bool> test)
            {
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
        Console.WriteLine($"{6 - failed}/6 parser regressions passed");
        return failed;
    }

    private static bool Detected(string path)
    {
        BlockingMq.MakeMq();
        new FileScanner().ScanFile(path);
        bool detected = false;
        while (BlockingMq.GetMq().Q.TryTake(out var message))
            detected |= message.FileResult?.MatchedRule?.RuleName == "KeepGitHubToken";
        return detected;
    }
}
