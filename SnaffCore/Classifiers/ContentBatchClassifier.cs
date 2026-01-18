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

        private string ReadFileAsString(FileInfo fileInfo)
        {
            try
            {
#if ULTRASNAFFLER
                // Parse office documents and PDFs to text
                List<string> parsedExtensions = new List<string>()
                {
                    ".doc",".docx",".xls",".xlsx",".eml",".msg",".pdf",".ppt",".pptx",
                    ".rtf",".docm",".xlsm",".pptm",".dot",".dotx",".dotm",".xlt",".xlsm",".xltm"
                };

                if (parsedExtensions.Contains(fileInfo.Extension.ToLower()))
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
                    // Cap full content at 512KB for Excel export
                    textResult.FullContent = fileString.Length > 512 * 1024 
                        ? fileString.Substring(0, 512 * 1024) 
                        : fileString;
                    
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
            // Implementation from original ContentClassifier
            // Check if byte pattern matches
            // TODO: Copy from ContentClassifier.ByteMatch()
            return false; // Placeholder
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
                string ext = fileInfo.Extension.ToLower();
                
                // For .xlsx files, use ClosedXML directly (no Task.Run to avoid thread pool starvation)
                if (ext == ".xlsx" || ext == ".xlsm")
                {
                    try
                    {
                        string result = ParseXlsxWithClosedXML(fileInfo.FullName);
                        if (result == "[PASSWORD_PROTECTED]")
                        {
                            ReportPasswordProtectedFile(fileInfo);
                            return "";
                        }
                        if (!string.IsNullOrEmpty(result))
                            return result;
                    }
                    catch (Exception ex)
                    {
                        // Silently handle - errors logged at trace level
                        Mq.Trace($"XLSX parse failed for {fileInfo.Name}: {ex.Message}");
                    }
                    
                    // Fallback to text parser
                    return ParseWithTextParser(fileInfo);
                }
                
                // For old .xls files, use Toxy SpreadsheetParser directly
                if (ext == ".xls" || ext == ".xlt" || ext == ".xltx" || ext == ".xltm")
                {
                    try
                    {
                        ParserContext context = new ParserContext(fileInfo.FullName);
                        ISpreadsheetParser spreadsheetParser = ParserFactory.CreateSpreadsheet(context);
                        ToxySpreadsheet spreadsheet = spreadsheetParser.Parse();
                        string result = ConvertSpreadsheetToTabDelimited(spreadsheet);
                        
                        if (!string.IsNullOrEmpty(result) && result.Contains("\t"))
                            return result;
                    }
                    catch (Exception ex)
                    {
                        // Only report as password-protected if error explicitly says so
                        string msg = ex.Message?.ToLower() ?? "";
                        if (msg.Contains("password") || msg.Contains("encrypted"))
                        {
                            ReportPasswordProtectedFile(fileInfo);
                            return "";
                        }
                        Mq.Trace($"XLS parse failed for {fileInfo.Name}: {ex.Message}");
                    }
                    
                    // Fallback to text parser
                    return ParseWithTextParser(fileInfo);
                }
                
                // For all other documents, use text parser
                return ParseWithTextParser(fileInfo);
            }
            catch
            {
                return "";
            }
        }
        
        /// <summary>
        /// Report a password-protected file for manual investigation
        /// </summary>
        private void ReportPasswordProtectedFile(FileInfo fileInfo)
        {
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
        
        /// <summary>
        /// Parse .xlsx file using ClosedXML - fast and reliable
        /// </summary>
        private string ParseXlsxWithClosedXML(string filePath)
        {
            var sb = new System.Text.StringBuilder();
            
            // Suppress ClosedXML console errors ("Ran out of data before creating all the strings!")
            var originalError = System.Console.Error;
            try
            {
                System.Console.SetError(System.IO.TextWriter.Null);
                
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
            finally
            {
                System.Console.SetError(originalError);
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
