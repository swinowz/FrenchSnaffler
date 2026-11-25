using SnaffCore.Concurrency;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using static SnaffCore.Config.Options;

#if ULTRASNAFFLER
using Toxy;
using Toxy.Parsers;
using ClosedXML.Excel;
#endif

namespace SnaffCore.Classifiers
{
    /// <summary>
    /// Optimized batch content classifier that reads a file once and applies multiple rules.
    /// This eliminates redundant file I/O when multiple relay rules target the same file.
    /// </summary>
    public class ContentBatchClassifier
    {
        private BlockingMq Mq { get; set; } = BlockingMq.GetMq();

#if ULTRASNAFFLER
        // Statique (evite de reallouer une liste a CHAQUE fichier)
        private static readonly System.Collections.Generic.HashSet<string> ParsedExtensions =
            new System.Collections.Generic.HashSet<string>(System.StringComparer.OrdinalIgnoreCase)
            {
                ".doc",".docx",".xls",".xlsx",".eml",".msg",".pdf",".ppt",".pptx",
                ".rtf",".docm",".xlsm",".pptm",".dot",".dotx",".dotm",".xlt",".xltm",
                ".odt",".ods",".odp",".ott",".ots"
            };

        private static readonly System.Text.RegularExpressions.RegexOptions XmlRx =
            System.Text.RegularExpressions.RegexOptions.Compiled | System.Text.RegularExpressions.RegexOptions.CultureInvariant;
        private static readonly System.Text.RegularExpressions.Regex DocxSeparators =
            new System.Text.RegularExpressions.Regex("</w:tc>|</w:tr>|</w:p>", XmlRx);
        private static readonly System.Text.RegularExpressions.Regex OdfSeparators =
            new System.Text.RegularExpressions.Regex("</table:table-cell>|<table:covered-table-cell/>|</table:table-row>|</text:p>|</text:h>|<text:tab/>|<text:line-break/>|<text:s/>|<text:s [^>]*/>", XmlRx);
        private static readonly System.Text.RegularExpressions.Regex XmlTags =
            new System.Text.RegularExpressions.Regex("<[^>]+>", XmlRx);
        // Word parts that hold user text: body, headers/footers, notes and comments.
        private static readonly System.Text.RegularExpressions.Regex DocxTextParts =
            new System.Text.RegularExpressions.Regex(@"^word/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml$",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase | XmlRx);
        // PowerPoint parts that hold user text: slides, their notes, and comments.
        private static readonly System.Text.RegularExpressions.Regex PptxTextParts =
            new System.Text.RegularExpressions.Regex(@"^ppt/(slides/slide\d+|notesSlides/notesSlide\d+|comments/.*)\.xml$",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase | XmlRx);
        // A run of text in a slide ends a paragraph: </a:p> -> newline.
        private static readonly System.Text.RegularExpressions.Regex PptxSeparators =
            new System.Text.RegularExpressions.Regex("</a:p>", XmlRx);
#endif

        /// <summary>
        /// Reads file content once and applies all specified rules.
        /// Significantly faster than calling ContentClassifier multiple times.
        /// </summary>
        public void ClassifyContentBatch(FileInfo fileInfo, List<ClassifierRule> rules)
        {
            if (rules == null || !rules.Any())
                return;

            // Check file size limit
            if (fileInfo.Length > MyOptions.MaxSizeToGrep)
            {
                Mq.Trace($"File {fileInfo.FullName} exceeds MaxSizeToGrep ({MyOptions.MaxSizeToGrep} bytes), skipping content scan");
                return;
            }

            try
            {
                // Group rules by match location type
                var byteRules = rules.Where(r => r.MatchLocation == MatchLoc.FileContentAsBytes).ToList();
                var stringRules = rules.Where(r => r.MatchLocation == MatchLoc.FileContentAsString).ToList();
                var lengthRules = rules.Where(r => r.MatchLocation == MatchLoc.FileLength).ToList();

                // Process byte-based rules
                if (byteRules.Any())
                {
                    byte[] fileBytes = File.ReadAllBytes(fileInfo.FullName);
                    ProcessByteRules(fileInfo, fileBytes, byteRules);
                }

                // Process string-based rules (read file only once!)
                if (stringRules.Any())
                {
                    string fileString = ReadFileAsString(fileInfo);
                    if (fileString != null)
                    {
                        ProcessStringRules(fileInfo, fileString, stringRules);
                    }
                }

                // Process length-based rules (no I/O needed)
                if (lengthRules.Any())
                {
                    ProcessLengthRules(fileInfo, lengthRules);
                }
            }
            catch (UnauthorizedAccessException)
            {
                // Silent fail - access denied
            }
            catch (IOException e)
            {
                Mq.Trace($"IOException reading {fileInfo.FullName}: {e.Message}");
            }
            catch (Exception e)
            {
                Mq.Error($"Error in ContentBatchClassifier for {fileInfo.FullName}: {e.Message}");
                Mq.Trace(e.ToString());
            }
        }

        private static string LogicalExtension(FileInfo fileInfo) =>
            ScanAliases.LogicalExtension(ScanAliases.Get(fileInfo.FullName) ?? fileInfo.FullName);

        private string ReadFileAsString(FileInfo fileInfo)
        {
            try
            {
#if ULTRASNAFFLER
                // Parse office documents and PDFs to text
                if (ParsedExtensions.Contains(LogicalExtension(fileInfo)))
                {
                    return ParseFileToString(fileInfo);
                }
#endif
                return File.ReadAllText(fileInfo.FullName);
            }
            catch
            {
                return null;
            }
        }

        private void ProcessByteRules(FileInfo fileInfo, byte[] fileBytes, List<ClassifierRule> rules)
        {
            foreach (var rule in rules)
            {
                if (ByteMatch(fileBytes, rule))
                {
                    var fileResult = new FileResult(fileInfo)
                    {
                        MatchedRule = rule
                    };
                    
                    if (fileResult.RwStatus.CanRead || fileResult.RwStatus.CanModify || fileResult.RwStatus.CanWrite)
                    {
                        Mq.FileResult(fileResult);
                    }
                    // Continue checking other rules - don't return!
                }
            }
        }

        private void ProcessStringRules(FileInfo fileInfo, string fileString, List<ClassifierRule> rules)
        {
            foreach (var rule in rules)
            {
                TextClassifier textClassifier = new TextClassifier(rule);
                TextResult textResult = textClassifier.TextMatch(fileString);
                
                if (textResult != null)
                {
                    if (DetectionFilters.IsKnownPlaceholder(rule, textResult))
                    {
                        Mq.Trace($"Suppressed known public placeholder for rule {rule.RuleName}: {textResult.MatchedValue}");
                        continue;
                    }
                    // Cap full content at 512KB for Excel export
                    if (MyOptions.LogType == SnaffCore.Config.LogType.Auto)
                    {
                        textResult.FullContent = fileString.Length > 512 * 1024
                            ? fileString.Substring(0, 512 * 1024)
                            : fileString;
                    }
                    
                    var fileResult = new FileResult(fileInfo)
                    {
                        MatchedRule = rule,
                        TextResult = textResult
                    };
                    
                    if (fileResult.RwStatus.CanRead || fileResult.RwStatus.CanModify || fileResult.RwStatus.CanWrite)
                    {
                        Mq.FileResult(fileResult);
                    }
                    // Continue checking other rules - a file can match multiple credential patterns!
                }
            }
        }

        private void ProcessLengthRules(FileInfo fileInfo, List<ClassifierRule> rules)
        {
            foreach (var rule in rules)
            {
                if (SizeMatch(fileInfo, rule))
                {
                    var fileResult = new FileResult(fileInfo)
                    {
                        MatchedRule = rule
                    };
                    
                    if (fileResult.RwStatus.CanRead || fileResult.RwStatus.CanModify || fileResult.RwStatus.CanWrite)
                    {
                        Mq.FileResult(fileResult);
                    }
                    // Continue checking other rules - don't return!
                }
            }
        }

        private bool ByteMatch(byte[] fileBytes, ClassifierRule rule)
        {
            if (fileBytes == null || rule?.WordList == null) return false;
            foreach (string pattern in rule.WordList)
            {
                byte[] needle = System.Text.Encoding.UTF8.GetBytes(pattern ?? "");
                if (needle.Length == 0 || needle.Length > fileBytes.Length) continue;
                for (int i = 0; i <= fileBytes.Length - needle.Length; i++)
                {
                    bool equal = true;
                    for (int j = 0; j < needle.Length; j++)
                        if (fileBytes[i + j] != needle[j]) { equal = false; break; }
                    if (!equal) continue;
                    if (rule.WordListType == MatchListType.Exact && fileBytes.Length != needle.Length) continue;
                    if (rule.WordListType == MatchListType.StartsWith && i != 0) continue;
                    if (rule.WordListType == MatchListType.EndsWith && i != fileBytes.Length - needle.Length) continue;
                    return true;
                }
            }
            return false;
        }

        private bool SizeMatch(FileInfo fileInfo, ClassifierRule rule)
        {
            // Implementation from original ContentClassifier
            // Check if file size matches criteria
            return fileInfo.Length == rule.MatchLength;
        }

#if ULTRASNAFFLER
        private string ParseFileToString(FileInfo fileInfo)
        {
            try
            {
                string ext = LogicalExtension(fileInfo).ToLowerInvariant();
                
                // Excel (xlsx/xlsm/xls/xlt...) : lecture STREAMING via ExcelDataReader
                // (pas de DOM complet en memoire comme ClosedXML/Toxy -> gros gain RAM avec bcp de threads).
                if (ext == ".xlsx" || ext == ".xlsm" || ext == ".xls" || ext == ".xlt" || ext == ".xltx" || ext == ".xltm")
                {
                    try
                    {
                        string result = ParseExcelStreamingWithRetry(fileInfo.FullName);
                        if (!string.IsNullOrEmpty(result))
                            return result;
                    }
                    catch (Exception ex)
                    {
                        string msg = ex.Message?.ToLower() ?? "";
                        string exType = ex.GetType().Name.ToLower();
                        if (msg.Contains("password") || msg.Contains("encrypted") || msg.Contains("encryption") ||
                            exType.Contains("crypto"))
                        {
                            ReportPasswordProtectedFile(fileInfo);
                            return "";
                        }
                        Mq.Trace($"Excel stream parse failed for {fileInfo.Name}: {ex.Message}");
                    }
                    // Fallback to text parser
                    return ParseWithTextParser(fileInfo);
                }
                
                // .docx / .docm / .dotx : extraction RAPIDE via OpenXML (lecture zip directe)
                // au lieu de Toxy (DOM complet en memoire, lib non maintenue).
                if (ext == ".docx" || ext == ".docm" || ext == ".dotx" || ext == ".dotm")
                {
                    try
                    {
                        string dresult = ParseDocxFast(fileInfo.FullName);
                        if (!string.IsNullOrEmpty(dresult)) return dresult;
                    }
                    catch (Exception ex) { Mq.Trace($"DOCX fast parse failed for {fileInfo.Name}: {ex.Message}"); }
                    return ParseWithTextParser(fileInfo); // repli sur Toxy
                }

                // OpenDocument (LibreOffice): zip + content.xml, no parser library needed.
                if (ext == ".odt" || ext == ".ods" || ext == ".odp" || ext == ".ott" || ext == ".ots")
                {
                    try { return ParseOpenDocument(fileInfo); }
                    catch (Exception ex) { Mq.Trace($"OpenDocument parse failed for {fileInfo.Name}: {ex.Message}"); return ""; }
                }

                // .pptx / .pptm / .potx : fast OpenXML path (zip, slides + notes), like DOCX.
                if (ext == ".pptx" || ext == ".pptm" || ext == ".potx" || ext == ".potm" || ext == ".ppsx" || ext == ".ppsm")
                {
                    try
                    {
                        string presult = ParsePptxFast(fileInfo.FullName);
                        if (!string.IsNullOrEmpty(presult)) return presult;
                    }
                    catch (Exception ex) { Mq.Trace($"PPTX fast parse failed for {fileInfo.Name}: {ex.Message}"); }
                    return ParseWithTextParser(fileInfo); // repli sur Toxy
                }

                // PDF and legacy binary .ppt go through Toxy's own parsers.
                return ParseWithTextParser(fileInfo);
            }
            catch
            {
                return "";
            }
        }

        // Extraction texte docx sans DOM : ouvre le zip, lit word/document.xml (+ headers/footers),
        // preserve la structure des tableaux (cellule -> tab, ligne/paragraphe -> newline) puis retire les balises.
        private string ParseDocxFast(string filePath)
        {
            var sb = new System.Text.StringBuilder();
            using (var zip = System.IO.Compression.ZipFile.OpenRead(filePath))
            {
                foreach (var entry in zip.Entries)
                {
                    if (!DocxTextParts.IsMatch(entry.FullName)) continue;
                    using (var s = entry.Open())
                    using (var r = new System.IO.StreamReader(s))
                    {
                        string xml = r.ReadToEnd();
                        xml = DocxSeparators.Replace(xml, m => m.Value == "</w:tc>" ? "\t" : "\n");
                        xml = XmlTags.Replace(xml, "");
                        sb.Append(System.Net.WebUtility.HtmlDecode(xml));
                        sb.Append('\n');
                    }
                }
            }
            return sb.ToString();
        }

        // PowerPoint text without a DOM: read ppt/slides/slideN.xml (and notes/comments),
        // paragraph -> newline, then strip tags. Slides are read in numeric order.
        // Upper bound on extracted text, so one huge document cannot blow up memory.
        // Scales with MaxSizeToGrep (default 1 MB file -> 8M chars).
        private static long ParsedTextLimit => Math.Max(MyOptions.MaxSizeToGrep * 8, 1024 * 1024);

        // ReadToEnd with a ceiling, for XML parts inside Office/ODF zips.
        private static string ReadCapped(System.IO.StreamReader reader, long cap)
        {
            var sb = new System.Text.StringBuilder();
            char[] buffer = new char[81920];
            int read;
            while ((read = reader.Read(buffer, 0, buffer.Length)) > 0)
            {
                long room = cap - sb.Length;
                if (read >= room) { sb.Append(buffer, 0, (int)room); break; }
                sb.Append(buffer, 0, read);
            }
            return sb.ToString();
        }

        private string ParsePptxFast(string filePath)
        {
            var sb = new System.Text.StringBuilder();
            long cap = ParsedTextLimit;
            using (var zip = System.IO.Compression.ZipFile.OpenRead(filePath))
            {
                foreach (var entry in zip.Entries
                    .Where(e => PptxTextParts.IsMatch(e.FullName))
                    .OrderBy(e => e.FullName, System.StringComparer.OrdinalIgnoreCase))
                {
                    using (var st = entry.Open())
                    using (var r = new System.IO.StreamReader(st))
                    {
                        string xml = ReadCapped(r, cap * 2);
                        xml = PptxSeparators.Replace(xml, "\n");
                        xml = XmlTags.Replace(xml, "");
                        sb.Append(System.Net.WebUtility.HtmlDecode(xml));
                        sb.Append('\n');
                        if (sb.Length >= cap) break;
                    }
                }
            }
            return sb.ToString();
        }

        // OpenDocument text extraction: content.xml (+ styles.xml for headers/footers).
        // Cells -> tab, rows/paragraphs -> newline, matching the Office parsers so the
        // credential-table extraction works the same way. Encrypted documents are reported.
        private string ParseOpenDocument(FileInfo fileInfo)
        {
            var sb = new System.Text.StringBuilder();
            using (var zip = System.IO.Compression.ZipFile.OpenRead(fileInfo.FullName))
            {
                var manifest = zip.GetEntry("META-INF/manifest.xml");
                if (manifest != null)
                {
                    using (var r = new System.IO.StreamReader(manifest.Open()))
                    {
                        if (r.ReadToEnd().IndexOf("encryption-data", StringComparison.Ordinal) >= 0)
                        {
                            ReportPasswordProtectedFile(fileInfo);
                            return "";
                        }
                    }
                }
                foreach (string part in new[] { "content.xml", "styles.xml" })
                {
                    var entry = zip.GetEntry(part);
                    if (entry == null) continue;
                    using (var r = new System.IO.StreamReader(entry.Open()))
                    {
                        string xml = r.ReadToEnd();
                        xml = OdfSeparators.Replace(xml, m =>
                            m.Value == "</table:table-cell>" || m.Value == "<table:covered-table-cell/>" || m.Value == "<text:tab/>" ? "\t"
                            : m.Value.StartsWith("<text:s", StringComparison.Ordinal) ? " " : "\n");
                        xml = XmlTags.Replace(xml, "");
                        sb.Append(System.Net.WebUtility.HtmlDecode(xml));
                        sb.Append('\n');
                    }
                }
            }
            return sb.ToString();
        }

        /// <summary>
        /// Report a password-protected file for manual investigation
        /// </summary>
        private void ReportPasswordProtectedFile(FileInfo fileInfo)
        {
            // Skip empty files - they're not password-protected, just empty/corrupt
            if (fileInfo.Length == 0)
            {
                Mq.Trace($"Skipping empty file {fileInfo.Name} - not password-protected");
                return;
            }
            
            // Skip Office lock/owner files (start with ~$) - these are temp files, not real documents
            if (fileInfo.Name.StartsWith("~$"))
            {
                Mq.Trace($"Skipping Office lock file {fileInfo.Name} - not password-protected");
                return;
            }
            
            var rule = new ClassifierRule
            {
                RuleName = "PasswordProtectedFile",
                EnumerationScope = EnumerationScope.FileEnumeration,
                MatchAction = MatchAction.Snaffle,
                Triage = Triage.Yellow,
                Description = "Password-protected document - may contain sensitive data"
            };
            
            var textResult = new TextResult
            {
                MatchContext = "File is password-protected - requires manual investigation"
            };
            
            var fileResult = new FileResult(fileInfo)
            {
                MatchedRule = rule,
                TextResult = textResult
            };
            
            Mq.FileResult(fileResult);
        }
        
        // Small but highly compressed workbooks expand to many MB inside ExcelDataReader.
        // With several workers on a small host this can throw OutOfMemoryException; the
        // Toxy fallback then rejects the file as a zip bomb and its findings are lost
        // (seen as run-to-run variation on Windows). Retry once, alone, after a GC.
        private static readonly object ExcelRetryLock = new object();
        private string ParseExcelStreamingWithRetry(string filePath)
        {
            try
            {
                return ParseExcelStreaming(filePath);
            }
            catch (OutOfMemoryException)
            {
                lock (ExcelRetryLock)
                {
                    Mq.Trace($"Excel parse ran out of memory, retrying alone: {filePath}");
                    System.GC.Collect();
                    return ParseExcelStreaming(filePath);
                }
            }
        }

        // Lecture Excel en STREAMING (xlsx ET xls) via ExcelDataReader : ligne par ligne, sans DOM complet.
        // Sortie tab-delimited (identique a l'ancien parseur) pour l'extraction de creds.
        private static bool _codePagesRegistered = false;
        private string ParseExcelStreaming(string filePath)
        {
            if (!_codePagesRegistered)
            {
                System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
                _codePagesRegistered = true;
            }
            var sb = new System.Text.StringBuilder();
            using (var stream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (var reader = ExcelDataReader.ExcelReaderFactory.CreateReader(stream))
            {
                do
                {
                    while (reader.Read())
                    {
                        for (int i = 0; i < reader.FieldCount; i++)
                        {
                            if (i > 0) sb.Append('\t');
                            object v = reader.GetValue(i);
                            if (v != null) sb.Append(v.ToString());
                        }
                        sb.Append('\n');
                    }
                } while (reader.NextResult());
            }
            return sb.ToString();
        }

        /// <summary>
        /// Parse .xlsx file using ClosedXML - fast and reliable
        /// </summary>
        private string ParseXlsxWithClosedXML(string filePath)
        {
            var sb = new System.Text.StringBuilder();
            
            try
            {
                using (var workbook = new XLWorkbook(filePath))
                {
                    foreach (var worksheet in workbook.Worksheets)
                    {
                        var usedRange = worksheet.RangeUsed();
                        if (usedRange == null) continue;
                        
                        foreach (var row in usedRange.Rows())
                        {
                            var cells = row.Cells().Select(c => c.GetString() ?? "").ToArray();
                            sb.AppendLine(string.Join("\t", cells));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Only report as password-protected if error explicitly mentions encryption
                string msg = ex.Message?.ToLower() ?? "";
                string exType = ex.GetType().Name.ToLower();
                if (msg.Contains("password") || msg.Contains("encrypted") || msg.Contains("encryption") ||
                    msg.Contains("not a zip") || msg.Contains("invalid zip") ||
                    exType.Contains("zip") || exType.Contains("crypto"))
                {
                    return "[PASSWORD_PROTECTED]";
                }
                // Other errors (corrupt, invalid, etc.) - just skip silently
                Mq.Trace($"XLSX parse error for {filePath}: {ex.Message}");
                return "";
            }
            
            return sb.ToString();
        }
        
        /// <summary>
        /// Fallback text parser for non-Excel documents
        /// </summary>
        private string ParseWithTextParser(FileInfo fileInfo)
        {
            // REMOVED Task.Run to prevent thread pool starvation with large file queues
            // Run synchronously - text parsing is fast enough (typically <100ms)
            try
            {
                ParserContext context = new ParserContext(fileInfo.FullName);
                ITextParser parser = ParserFactory.CreateText(context);
                string result = parser.Parse() ?? "";
                return result;
            }
            catch (Exception ex)
            {
                // Check if this is a password-protected file
                string msg = ex.Message?.ToLower() ?? "";
                string exType = ex.GetType().Name.ToLower();
                if (msg.Contains("password") || msg.Contains("encrypted") || msg.Contains("encryption") ||
                    msg.Contains("not a zip") || msg.Contains("invalid zip") ||
                    exType.Contains("zip") || exType.Contains("crypto"))
                {
                    ReportPasswordProtectedFile(fileInfo);
                }
                Mq.Trace($"Text parse failed for {fileInfo.Name}: {ex.Message}");
                return "";
            }
        }
        
        /// <summary>
        /// Convert ToxySpreadsheet to tab-delimited string for credential extraction
        /// </summary>
        private string ConvertSpreadsheetToTabDelimited(ToxySpreadsheet spreadsheet)
        {
            if (spreadsheet == null || spreadsheet.Tables == null || spreadsheet.Tables.Count == 0)
                return "";
            
            var sb = new System.Text.StringBuilder();
            
            foreach (var table in spreadsheet.Tables)
            {
                // Add header rows
                if (table.HeaderRows != null)
                {
                    foreach (var headerRow in table.HeaderRows)
                    {
                        if (headerRow.Cells != null && headerRow.Cells.Count > 0)
                        {
                            var cellValues = new string[headerRow.LastCellIndex + 1];
                            for (int i = 0; i <= headerRow.LastCellIndex; i++)
                                cellValues[i] = "";
                            
                            foreach (var cell in headerRow.Cells)
                            {
                                if (cell.CellIndex >= 0 && cell.CellIndex < cellValues.Length)
                                    cellValues[cell.CellIndex] = cell.Value ?? "";
                            }
                            sb.AppendLine(string.Join("\t", cellValues));
                        }
                    }
                }
                
                // Add data rows
                if (table.Rows != null)
                {
                    foreach (var row in table.Rows)
                    {
                        if (row.Cells != null && row.Cells.Count > 0)
                        {
                            var cellValues = new string[row.LastCellIndex + 1];
                            for (int i = 0; i <= row.LastCellIndex; i++)
                                cellValues[i] = "";
                            
                            foreach (var cell in row.Cells)
                            {
                                if (cell.CellIndex >= 0 && cell.CellIndex < cellValues.Length)
                                    cellValues[cell.Value != null ? cell.CellIndex : cell.CellIndex] = cell.Value ?? "";
                            }
                            sb.AppendLine(string.Join("\t", cellValues));
                        }
                    }
                }
            }
            
            return sb.ToString();
        }
#endif
    }
}
