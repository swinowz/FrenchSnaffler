using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using ClosedXML.Excel;
using SnaffCore.Classifiers;
using SnaffCore.Concurrency;

namespace SnaffCore.ExcelExport
{
    /// <summary>
    /// Generates structured Excel reports for automated processing
    /// Accumulates findings during scan and exports at completion
    /// </summary>
    public class ExcelReportGenerator
    {
        private readonly List<ExcelFinding> _findings = new List<ExcelFinding>();
        private readonly string _outputPath;
        private readonly int _maxFindings = 50000;
        private readonly DateTime _scanStartTime;
        private readonly BlockingMq _mq;
        private bool _limitReached = false;
        private int _totalFilesScanned = 0;
        private readonly HashSet<string> _scannedPaths = new HashSet<string>();
        private readonly HashSet<string> _filesWithExtractedCredentials = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public ExcelReportGenerator(string outputPath, BlockingMq mq)
        {
            _outputPath = outputPath;
            _mq = mq;
            _scanStartTime = DateTime.Now;
        }

        /// <summary>
        /// Add a file result to the Excel report
        /// </summary>
        public void AddFinding(FileResult result)
        {
            if (_limitReached) return;

            _totalFilesScanned++;
            Console.WriteLine($"[DEBUG-EXCEL] AddFinding called for: {result.FileInfo.FullName}");
            Console.WriteLine($"[DEBUG-EXCEL] Current findings count: {_findings.Count}");

            if (_findings.Count >= _maxFindings)
            {
                if (!_limitReached)
                {
                    _mq.Error($"Excel finding limit reached ({_maxFindings}). Additional findings will be logged only.");
                    _limitReached = true;
                }
                return;
            }

            // Extract directory path for summary
            try
            {
                string dirPath = System.IO.Path.GetDirectoryName(result.FileInfo.FullName);
                if (!string.IsNullOrEmpty(dirPath) && dirPath.StartsWith("\\\\"))
                {
                    // Extract share path: \\server\share
                    string[] parts = dirPath.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2)
                    {
                        _scannedPaths.Add($"\\\\{parts[0]}\\{parts[1]}");
                    }
                }
            }
            catch { /* Ignore path parsing errors */ }

            Console.WriteLine($"[DEBUG-EXCEL] Creating finding object for: {result.FileInfo.Name}");
            var finding = new ExcelFinding
            {
                Severity = result.MatchedRule.Triage.ToString(),
                Type = DetermineType(result),
                FilePath = result.FileInfo.FullName,
                RuleName = result.MatchedRule.RuleName,
                DateFound = DateTime.Now,
                FileSize = result.FileInfo.Length
            };

            // Extract credentials if TextResult is available
            if (result.TextResult != null && !string.IsNullOrEmpty(result.TextResult.MatchContext))
            {
                Console.WriteLine($"[DEBUG-EXCEL] TextResult available, extracting credentials...");
                // Use FullContent for tabular extraction if available, fallback to MatchContext
                string contentForExtraction = result.TextResult.FullContent ?? result.TextResult.MatchContext;
                Console.WriteLine($"[DEBUG-EXCEL] Content length: {contentForExtraction?.Length ?? 0}");
                var extractionResult = ExtractAllCredentials(contentForExtraction);
                Console.WriteLine($"[DEBUG-EXCEL] ExtractAllCredentials returned: {extractionResult.AllCredentials?.Count ?? 0} creds");
                
                if (extractionResult.AllCredentials != null && extractionResult.AllCredentials.Count > 0)
                {
                    // Mark this file as having extracted credentials
                    _filesWithExtractedCredentials.Add(result.FileInfo.FullName);
                    
                    Console.WriteLine($"[DEBUG-EXCEL] Adding {extractionResult.AllCredentials.Count} credential rows...");
                    // Create ONE ROW PER CREDENTIAL in Excel
                    for (int i = 0; i < extractionResult.AllCredentials.Count; i++)
                    {
                        var cred = extractionResult.AllCredentials[i];
                        var credFinding = new ExcelFinding
                        {
                            Severity = result.MatchedRule.Triage.ToString(),
                            Type = DetermineType(result),
                            FilePath = result.FileInfo.FullName,
                            RuleName = result.MatchedRule.RuleName,
                            DateFound = DateTime.Now,
                            FileSize = result.FileInfo.Length,
                            Username = cred.Username,
                            Password = cred.Password,
                            ContentPreview = !string.IsNullOrEmpty(cred.Service) 
                                ? $"{cred.Service}" + (!string.IsNullOrEmpty(cred.Url) ? $" ({cred.Url})" : "")
                                : (!string.IsNullOrEmpty(cred.Url) ? cred.Url : $"Row {i + 1}")
                        };
                        _findings.Add(credFinding);
                    }
                    Console.WriteLine($"[DEBUG-EXCEL] Done adding credentials for {result.FileInfo.Name}, returning...");
                    return; // Already added all findings, don't add the base finding
                }
                else
                {
                    Console.WriteLine($"[DEBUG] No tabular creds, trying fallback extraction...");
                    // Fallback to old extraction method
                    var credentials = ExtractCredentials(contentForExtraction);
                    finding.Username = credentials.Username;
                    finding.Password = credentials.Password;
                    finding.ContentPreview = GetPreview(result.TextResult.MatchContext, 150);
                }
            }
            else
            {
                Console.WriteLine($"[DEBUG] No TextResult, using filename as preview");
                // For file-based matches (e.g., keyfiles), use filename as preview
                finding.ContentPreview = System.IO.Path.GetFileName(result.FileInfo.FullName);
            }

            // Skip adding if this file already has extracted credentials (avoid duplicates from filename rules)
            if (_filesWithExtractedCredentials.Contains(result.FileInfo.FullName) && 
                string.IsNullOrEmpty(finding.Username) && string.IsNullOrEmpty(finding.Password))
            {
                return; // Skip this duplicate entry with no credentials
            }

            _findings.Add(finding);
        }

        /// <summary>
        /// Determine the credential type based on rule name
        /// </summary>
        private string DetermineType(FileResult result)
        {
            string ruleName = result.MatchedRule.RuleName.ToLower();

            if (ruleName.Contains("credential") || ruleName.Contains("password") || 
                ruleName.Contains("motdepasse") || ruleName.Contains("identifiant"))
                return "Credentials";
            
            if (ruleName.Contains("key") && (ruleName.Contains("private") || ruleName.Contains("ssh") || ruleName.Contains("pgp")))
                return "Private Key";
            
            if (ruleName.Contains("certificate") || ruleName.Contains("cert"))
                return "Certificate";
            
            if (ruleName.Contains("keepass") || ruleName.Contains("kdbx") || ruleName.Contains("kdb"))
                return "Password Manager";
            
            if (ruleName.Contains("config") || ruleName.Contains("conf"))
                return "Config File";
            
            if (ruleName.Contains("database") || ruleName.Contains("sql") || ruleName.Contains("db"))
                return "Database";
            
            return "Other";
        }

        /// <summary>
        /// Credential data class for multi-credential extraction
        /// </summary>
        private class CredentialEntry
        {
            public string Service { get; set; }
            public string Username { get; set; }
            public string Password { get; set; }
            public string Url { get; set; }
        }

        /// <summary>
        /// Extract ALL credentials from content (tabular format like Excel/CSV)
        /// Returns list of all found credentials for rich preview
        /// </summary>
        private (List<CredentialEntry> AllCredentials, bool IsTabular) ExtractAllCredentials(string content)
        {
            var credentials = new List<CredentialEntry>();
            
            try
            {
                // Check for tab-delimited format
                if (!content.Contains("\t") || !content.Contains("\n"))
                    return (null, false);

                string[] lines = content.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                if (lines.Length < 2) return (null, false);

                // Find header row (look for credential-related keywords)
                int headerIndex = -1;
                string[] headers = null;
                
                for (int i = 0; i < Math.Min(lines.Length, 10); i++) // Check first 10 lines for headers
                {
                    string[] potentialHeaders = lines[i].Split('\t');
                    if (potentialHeaders.Length >= 2)
                    {
                        // Check if this row contains credential header keywords
                        bool hasUserKeyword = potentialHeaders.Any(h => 
                            Regex.IsMatch(h ?? "", @"(?i)(identifiant|login|username|utilisateur|user|compte|email)", RegexOptions.IgnoreCase));
                        bool hasPassKeyword = potentialHeaders.Any(h => 
                            Regex.IsMatch(h ?? "", @"(?i)(mdp|password|pwd|mot.*passe|pass)", RegexOptions.IgnoreCase));
                        
                        if (hasUserKeyword && hasPassKeyword)
                        {
                            headerIndex = i;
                            headers = potentialHeaders;
                            break;
                        }
                    }
                }

                if (headerIndex == -1 || headers == null) return (null, false);

                // Find column indices
                int userColIndex = -1;
                int passColIndex = -1;
                int serviceColIndex = -1;
                int urlColIndex = -1;

                for (int i = 0; i < headers.Length; i++)
                {
                    string header = headers[i]?.Trim()?.ToLower() ?? "";
                    
                    if (userColIndex == -1 && Regex.IsMatch(header, @"(identifiant|login|username|utilisateur|user|compte|email)"))
                        userColIndex = i;
                    if (passColIndex == -1 && Regex.IsMatch(header, @"(mdp|password|pwd|mot.*passe|pass)"))
                        passColIndex = i;
                    if (serviceColIndex == -1 && Regex.IsMatch(header, @"(nom|name|service|site|fournisseur|client|provider)"))
                        serviceColIndex = i;
                    if (urlColIndex == -1 && Regex.IsMatch(header, @"(lien|url|link|adresse|website)"))
                        urlColIndex = i;
                }

                if (userColIndex == -1 || passColIndex == -1) return (null, false);

                int maxCol = Math.Max(userColIndex, passColIndex);
                if (serviceColIndex > maxCol) maxCol = serviceColIndex;
                if (urlColIndex > maxCol) maxCol = urlColIndex;

                // Extract ALL credential rows (up to 100)
                for (int i = headerIndex + 1; i < Math.Min(lines.Length, headerIndex + 101); i++)
                {
                    string[] cells = lines[i].Split('\t');
                    if (cells.Length > maxCol)
                    {
                        string user = cells[userColIndex]?.Trim() ?? "";
                        string pass = cells[passColIndex]?.Trim() ?? "";
                        string service = serviceColIndex >= 0 && cells.Length > serviceColIndex ? cells[serviceColIndex]?.Trim() ?? "" : "";
                        string url = urlColIndex >= 0 && cells.Length > urlColIndex ? cells[urlColIndex]?.Trim() ?? "" : "";

                        // Validate - must have at least username or password that's not a header
                        bool validUser = !string.IsNullOrWhiteSpace(user) && user.Length >= 2 && user.Length <= 150 &&
                            !Regex.IsMatch(user, @"(?i)^(identifiant|login|username|utilisateur|user|compte)$");
                        bool validPass = !string.IsNullOrWhiteSpace(pass) && pass.Length >= 2 && pass.Length <= 150 &&
                            !Regex.IsMatch(pass, @"(?i)^(mdp|password|pwd|mot.*passe|pass)$");

                        if (validUser || validPass)
                        {
                            credentials.Add(new CredentialEntry
                            {
                                Username = validUser ? user : "(empty)",
                                Password = validPass ? pass : "(empty)",
                                Service = string.IsNullOrWhiteSpace(service) ? null : service,
                                Url = string.IsNullOrWhiteSpace(url) ? null : url
                            });
                        }
                    }
                }

                return (credentials.Count > 0 ? credentials : null, true);
            }
            catch
            {
                return (null, false);
            }
        }

        /// <summary>
        /// Extract username and password from matched content
        /// </summary>
        private (string Username, string Password) ExtractCredentials(string content)
        {
            string username = null;
            string password = null;

            try
            {
                // NEW: Try tabular extraction first (for Excel/CSV credential tables)
                if (content.Contains("\t") && content.Contains("\n"))
                {
                    var (isTabular, firstPair) = ExtractFromTabularFormat(content);
                    if (isTabular && firstPair.Username != null)
                    {
                        return (firstPair.Username, firstPair.Password);
                    }
                }

                // EXISTING: Extract email addresses (common username format)
                var emailMatch = Regex.Match(content, @"[\w\.-]+@[\w\.-]+\.\w+", RegexOptions.IgnoreCase);
                if (emailMatch.Success)
                {
                    username = emailMatch.Value;
                }

                // Extract username after username keywords
                if (string.IsNullOrEmpty(username))
                {
                    var userMatch = Regex.Match(content, 
                        @"(?i)(user|username|login|identifiant|utilisateur|user\s*name)[\s:=\t]+([^\s\t\n\r]{3,50})",
                        RegexOptions.IgnoreCase);
                    if (userMatch.Success && userMatch.Groups.Count > 2)
                    {
                        username = userMatch.Groups[2].Value.Trim();
                    }
                }

                // Extract password after password keywords
                var pwdMatch = Regex.Match(content,
                    @"(?i)(password|pwd|mdp|mot.?de.?passe|pass\s*word|mot\s*de\s*passe)[\s:=\t""']+([^\s\t\n\r""']{4,50})",
                    RegexOptions.IgnoreCase);
                if (pwdMatch.Success && pwdMatch.Groups.Count > 2)
                {
                    password = pwdMatch.Groups[2].Value.Trim();
                    // Clean up common delimiters
                    password = password.TrimEnd(',', ';', ')', '}', ']', '"', '\'');
                }
            }
            catch
            {
                // If extraction fails, return nulls
            }

            return (username, password);
        }

        /// <summary>
        /// Extract credentials from tab-delimited tabular format (e.g., Excel parsed by Toxy)
        /// Common in French business docs with columns like: Identifiant | MDP | ...
        /// </summary>
        private (bool IsTabular, (string Username, string Password) FirstPair) ExtractFromTabularFormat(string content)
        {
            try
            {
                string[] lines = content.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                if (lines.Length < 2) return (false, (null, null));

                // Find header row (look for credential-related keywords)
                int headerIndex = -1;
                string[] headers = null;
                
                for (int i = 0; i < Math.Min(lines.Length, 5); i++) // Check first 5 lines for headers
                {
                    string[] potentialHeaders = lines[i].Split('\t');
                    if (potentialHeaders.Length >= 2)
                    {
                        // Check if this row contains credential header keywords
                        bool hasUserKeyword = potentialHeaders.Any(h => 
                            Regex.IsMatch(h ?? "", @"(?i)(identifiant|login|username|utilisateur|user|compte)", RegexOptions.IgnoreCase));
                        bool hasPassKeyword = potentialHeaders.Any(h => 
                            Regex.IsMatch(h ?? "", @"(?i)(mdp|password|pwd|mot.*passe|pass)", RegexOptions.IgnoreCase));
                        
                        if (hasUserKeyword && hasPassKeyword)
                        {
                            headerIndex = i;
                            headers = potentialHeaders;
                            break;
                        }
                    }
                }

                if (headerIndex == -1 || headers == null) return (false, (null, null));

                // Find column indices for username and password
                int userColIndex = -1;
                int passColIndex = -1;

                for (int i = 0; i < headers.Length; i++)
                {
                    string header = headers[i]?.Trim() ?? "";
                    if (Regex.IsMatch(header, @"(?i)^(identifiant|login|username|utilisateur|user|compte)$", RegexOptions.IgnoreCase))
                    {
                        userColIndex = i;
                    }
                    if (Regex.IsMatch(header, @"(?i)^(mdp|password|pwd|mot.*passe|pass)$", RegexOptions.IgnoreCase))
                    {
                        passColIndex = i;
                    }
                }

                if (userColIndex == -1 || passColIndex == -1) return (false, (null, null));

                // Extract first valid credential pair from data rows
                for (int i = headerIndex + 1; i < Math.Min(lines.Length, headerIndex + 11); i++) // Check up to 10 data rows
                {
                    string[] cells = lines[i].Split('\t');
                    if (cells.Length > Math.Max(userColIndex, passColIndex))
                    {
                        string user = cells[userColIndex]?.Trim() ?? "";
                        string pass = cells[passColIndex]?.Trim() ?? "";

                        // Validate extracted values (not empty, not header duplicates, reasonable length)
                        if (!string.IsNullOrWhiteSpace(user) && 
                            !string.IsNullOrWhiteSpace(pass) &&
                            user.Length >= 3 && user.Length <= 100 &&
                            pass.Length >= 3 && pass.Length <= 100 &&
                            !Regex.IsMatch(user, @"(?i)^(identifiant|login|username)$") &&
                            !Regex.IsMatch(pass, @"(?i)^(mdp|password|pwd)$"))
                        {
                            return (true, (user, pass));
                        }
                    }
                }

                // Found tabular structure but no valid credentials
                return (true, (null, null));
            }
            catch
            {
                return (false, (null, null));
            }
        }

        /// <summary>
        /// Get a preview of the content
        /// </summary>
        private string GetPreview(string content, int maxLength)
        {
            if (string.IsNullOrEmpty(content))
                return "";

            // Remove excessive whitespace and normalize
            content = Regex.Replace(content, @"\s+", " ").Trim();

            if (content.Length <= maxLength)
                return content;

            return content.Substring(0, maxLength) + "...";
        }

        /// <summary>
        /// Generate the Excel report
        /// </summary>
        public void Generate()
        {
            try
            {
                _mq.Info($"Generating Excel report with {_findings.Count} findings...");

                using var workbook = new XLWorkbook();

                // Create Summary sheet first
                BuildSummarySheet(workbook.Worksheets.Add("Summary"));

                // Create Findings sheet
                BuildFindingsSheet(workbook.Worksheets.Add("Findings"));

                // Save workbook
                workbook.SaveAs(_outputPath);

                TimeSpan duration = DateTime.Now - _scanStartTime;
                _mq.Info($"✓ Excel report saved to: {_outputPath}");
                _mq.Info($"  - Total findings: {_findings.Count}");
                _mq.Info($"  - Scan duration: {duration.Hours}h {duration.Minutes}m {duration.Seconds}s");
            }
            catch (Exception ex)
            {
                _mq.Error($"Failed to generate Excel report: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Build the summary sheet with scan statistics
        /// </summary>
        private void BuildSummarySheet(IXLWorksheet ws)
        {
            int row = 1;

            // Title
            ws.Cell(row, 1).Value = "Snaffler Scan Report";
            ws.Cell(row, 1).Style.Font.Bold = true;
            ws.Cell(row, 1).Style.Font.FontSize = 16;
            row += 2;

            // Scan Information
            ws.Cell(row, 1).Value = "Scan Date:";
            ws.Cell(row, 1).Style.Font.Bold = true;
            ws.Cell(row, 2).Value = _scanStartTime.ToString("yyyy-MM-dd HH:mm:ss");
            row++;

            ws.Cell(row, 1).Value = "Scan Duration:";
            ws.Cell(row, 1).Style.Font.Bold = true;
            TimeSpan duration = DateTime.Now - _scanStartTime;
            ws.Cell(row, 2).Value = $"{duration.Hours}h {duration.Minutes}m {duration.Seconds}s";
            row++;

            ws.Cell(row, 1).Value = "Scanned Paths:";
            ws.Cell(row, 1).Style.Font.Bold = true;
            ws.Cell(row, 2).Value = string.Join(", ", _scannedPaths.Take(10));
            if (_scannedPaths.Count > 10)
            {
                ws.Cell(row, 2).Value += $" (and {_scannedPaths.Count - 10} more)";
            }
            row += 2;

            // Statistics
            ws.Cell(row, 1).Value = "Total Findings:";
            ws.Cell(row, 1).Style.Font.Bold = true;
            ws.Cell(row, 2).Value = _findings.Count;
            ws.Cell(row, 2).Style.Font.FontSize = 14;
            ws.Cell(row, 2).Style.Font.Bold = true;
            row += 2;

            // Breakdown by Severity
            ws.Cell(row, 1).Value = "Breakdown by Severity";
            ws.Cell(row, 1).Style.Font.Bold = true;
            ws.Cell(row, 1).Style.Font.FontSize = 12;
            row++;

            var severityCounts = _findings.GroupBy(f => f.Severity)
                .OrderByDescending(g => g.Key == "Red" ? 3 : g.Key == "Yellow" ? 2 : 1)
                .Select(g => new { Severity = g.Key, Count = g.Count() });

            foreach (var group in severityCounts)
            {
                ws.Cell(row, 1).Value = $"  {group.Severity}:";
                ws.Cell(row, 2).Value = group.Count;
                
                // Color code
                var color = group.Severity switch
                {
                    "Red" => XLColor.Red,
                    "Yellow" => XLColor.Yellow,
                    "Green" => XLColor.LightGreen,
                    _ => XLColor.White
                };
                ws.Cell(row, 1).Style.Fill.BackgroundColor = color;
                ws.Cell(row, 2).Style.Fill.BackgroundColor = color;
                
                row++;
            }
            row++;

            // Breakdown by Type
            ws.Cell(row, 1).Value = "Breakdown by Type";
            ws.Cell(row, 1).Style.Font.Bold = true;
            ws.Cell(row, 1).Style.Font.FontSize = 12;
            row++;

            var typeCounts = _findings.GroupBy(f => f.Type)
                .OrderByDescending(g => g.Count())
                .Take(10);

            foreach (var group in typeCounts)
            {
                ws.Cell(row, 1).Value = $"  {group.Key}:";
                ws.Cell(row, 2).Value = group.Count();
                row++;
            }

            // Auto-fit columns
            ws.Columns().AdjustToContents();
        }

        /// <summary>
        /// Build the findings sheet with detailed results
        /// </summary>
        private void BuildFindingsSheet(IXLWorksheet ws)
        {
            // Headers
            ws.Cell(1, 1).Value = "Severity";
            ws.Cell(1, 2).Value = "Type";
            ws.Cell(1, 3).Value = "File Location";
            ws.Cell(1, 4).Value = "Username";
            ws.Cell(1, 5).Value = "Password";
            ws.Cell(1, 6).Value = "Rule Name";
            ws.Cell(1, 7).Value = "Date Found";
            ws.Cell(1, 8).Value = "Preview";

            // Format header row
            var headerRow = ws.Row(1);
            headerRow.Style.Font.Bold = true;
            headerRow.Style.Fill.BackgroundColor = XLColor.LightGray;
            headerRow.Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;

            // Data rows - sort by severity (Red first)
            int row = 2;
            var sortedFindings = _findings
                .OrderByDescending(f => f.Severity == "Red" ? 3 : f.Severity == "Yellow" ? 2 : 1)
                .ThenByDescending(f => f.DateFound);

            foreach (var finding in sortedFindings)
            {
                ws.Cell(row, 1).Value = finding.Severity;
                ws.Cell(row, 2).Value = finding.Type;
                ws.Cell(row, 3).Value = finding.FilePath;
                ws.Cell(row, 4).Value = finding.Username ?? "";
                ws.Cell(row, 5).Value = finding.Password ?? "";
                ws.Cell(row, 6).Value = finding.RuleName;
                ws.Cell(row, 7).Value = finding.DateFound.ToString("yyyy-MM-dd HH:mm:ss");
                ws.Cell(row, 8).Value = finding.ContentPreview ?? "";

                // Apply severity color coding
                ApplySeverityColor(ws.Row(row), finding.Severity);

                row++;
            }

            // Auto-fit columns with max width
            ws.Column(1).Width = 10;  // Severity
            ws.Column(2).Width = 20;  // Type
            ws.Column(3).Width = 60;  // File Location
            ws.Column(4).Width = 30;  // Username
            ws.Column(5).Width = 30;  // Password
            ws.Column(6).Width = 35;  // Rule Name
            ws.Column(7).Width = 18;  // Date Found
            ws.Column(8).Width = 50;  // Preview

            // Freeze header row
            ws.SheetView.FreezeRows(1);

            // Enable filters
            ws.RangeUsed().SetAutoFilter();
        }

        /// <summary>
        /// Apply color coding based on severity
        /// </summary>
        private void ApplySeverityColor(IXLRow row, string severity)
        {
            var color = severity switch
            {
                "Red" => XLColor.Red,
                "Yellow" => XLColor.Yellow,
                "Green" => XLColor.LightGreen,
                _ => XLColor.White
            };

            // Apply background color to entire row
            row.Style.Fill.BackgroundColor = color;

            // Adjust text color for readability
            if (severity == "Red")
            {
                row.Style.Font.FontColor = XLColor.White;
            }
        }
    }

    /// <summary>
    /// Represents a single finding in the Excel report
    /// </summary>
    public class ExcelFinding
    {
        public string Severity { get; set; }
        public string Type { get; set; }
        public string FilePath { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string RuleName { get; set; }
        public DateTime DateFound { get; set; }
        public string ContentPreview { get; set; }
        public long FileSize { get; set; }
    }
}
