using SnaffCore.Classifiers;
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using OfficeOpenXml;
using OfficeOpenXml.Style;

namespace SnaffCore.Concurrency
{
    public class BlockingMq : IDisposable
    {
        private static BlockingMq _instance;
        
        // Direct Excel output
        private ExcelPackage _excelPackage;
        private ExcelWorksheet _worksheet;
        private readonly object _excelLock = new object();
        private string _excelPath;
        private int _findingsCount = 0;
        private int _filesProcessed = 0;
        private int _currentRow = 2; // Start after header row
        
        // Track written credentials to avoid duplicates
        private System.Collections.Generic.HashSet<string> _writtenCredentials = new System.Collections.Generic.HashSet<string>();

        /// <summary>
        /// Public method for FileScanner to trigger GC every 100 files
        /// </summary>
        public void TriggerGarbageCollection(int totalFilesProcessed)
        {
            _filesProcessed = totalFilesProcessed;
            
            // Force Gen2 collection with compaction
            System.GC.Collect(2, System.GCCollectionMode.Forced, true, true);
            System.Runtime.GCSettings.LargeObjectHeapCompactionMode = System.Runtime.GCLargeObjectHeapCompactionMode.CompactOnce;
        }

        public static void MakeMq()
        {
            _instance = new BlockingMq();
        }

        public static BlockingMq GetMq()
        {
            return _instance;
        }
        
        /// <summary>
        /// Initialize direct Excel output (call before scanning starts)
        /// </summary>
        public void InitCsvOutput(string outputPath)
        {
            // Set EPPlus license context
            ExcelPackage.LicenseContext = LicenseContext.NonCommercial;
            
            _excelPath = Path.ChangeExtension(outputPath, ".xlsx");
            _excelPackage = new ExcelPackage(new FileInfo(_excelPath));
            _worksheet = _excelPackage.Workbook.Worksheets.Add("Findings");
            
            // Create header row with formatting
            _worksheet.Cells[1, 1].Value = "Severity";
            _worksheet.Cells[1, 2].Value = "Type";
            _worksheet.Cells[1, 3].Value = "Hostname";
            _worksheet.Cells[1, 4].Value = "FilePath";
            _worksheet.Cells[1, 5].Value = "RuleName";
            _worksheet.Cells[1, 6].Value = "Username";
            _worksheet.Cells[1, 7].Value = "Password";
            _worksheet.Cells[1, 8].Value = "DateFound";
            _worksheet.Cells[1, 9].Value = "Preview";
            
            // Format header
            using (var range = _worksheet.Cells[1, 1, 1, 9])
            {
                range.Style.Font.Bold = true;
                range.Style.Fill.PatternType = ExcelFillStyle.Solid;
                range.Style.Fill.BackgroundColor.SetColor(System.Drawing.Color.LightGray);
            }
        }

        // Message Queue - bounded to prevent memory explosion
        public BlockingCollection<SnafflerMessage> Q { get; private set; }

        private BlockingMq()
        {
            // Bounded queue - prevents unbounded memory growth from console logging backlog
            Q = new BlockingCollection<SnafflerMessage>(5000);
        }

        public void Terminate()
        {
            Q.Add(new SnafflerMessage
            {
                DateTime = DateTime.Now,
                Type = SnafflerMessageType.Fatal,
                Message = "Terminate was called"
            });
        }

        public void Trace(string message)
        {
            Q.TryAdd(new SnafflerMessage
            {
                DateTime = DateTime.Now,
                Type = SnafflerMessageType.Trace,
                Message = message
            });
        }

        public void Degub(string message)
        {
            Q.TryAdd(new SnafflerMessage
            {
                DateTime = DateTime.Now,
                Type = SnafflerMessageType.Degub,
                Message = message
            });
        }

        public void Info(string message)
        {
            // Use TryAdd to prevent deadlock when queue is full
            Q.TryAdd(new SnafflerMessage
            {
                DateTime = DateTime.Now,
                Type = SnafflerMessageType.Info,
                Message = message
            });
        }

        public void Error(string message)
        {
            Q.Add(new SnafflerMessage
            {
                DateTime = DateTime.Now,
                Type = SnafflerMessageType.Error,
                Message = message
            });
        }

        public void FileResult(FileResult fileResult)
        {
            // DIRECT EXCEL WRITE - no memory accumulation
            if (_excelPackage != null)
            {
                // EXTRACT CREDENTIALS OUTSIDE LOCK (parallel processing)
                string severity = fileResult.MatchedRule?.Triage.ToString() ?? "Unknown";
                string type = DetermineType(fileResult);
                string filePath = EscapeCsv(fileResult.FileInfo?.FullName ?? "");
                string hostname = ExtractHostname(fileResult.FileInfo?.FullName ?? "");
                string ruleName = EscapeCsv(fileResult.MatchedRule?.RuleName ?? "");
                string dateFound = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                
                System.Collections.Generic.List<CredentialEntry> allCreds = null;
                string preview = "";
                bool hasTextResult = false;
                
                if (fileResult.TextResult != null)
                {
                    hasTextResult = true;
                    string content = fileResult.TextResult.FullContent ?? fileResult.TextResult.MatchContext ?? "";
                    
                    // Extract credentials (slow - do outside lock)
                    allCreds = ExtractAllCredentialsFromTable(content);
                    
                    // If no table credentials, try XML tag extraction
                    if (allCreds == null || allCreds.Count == 0)
                    {
                        allCreds = ExtractCredentialsFromXmlTags(content);
                    }
                    
                    // If no XML credentials, try regex extraction (now also returns list)
                    if (allCreds == null || allCreds.Count == 0)
                    {
                        allCreds = ExtractCredentialsRegex(content);
                    }
                    
                    // If still no credentials, just show preview
                    if (allCreds == null || allCreds.Count == 0)
                    {
                        preview = EscapeCsv(GetPreview(content, 100));
                    }
                }
                else
                {
                    preview = EscapeCsv(Path.GetFileName(fileResult.FileInfo?.FullName ?? ""));
                }
                
                // LOCK ONLY FOR EXCEL WRITE (fast operation)
                lock (_excelLock)
                {
                    try
                    {
                        if (hasTextResult)
                        {
                            if (allCreds != null && allCreds.Count > 0)
                            {
                                // Change type to "Credentials" and severity to "Red" when we actually have extracted credentials
                                string credType = "Credentials";
                                string credSeverity = "Red";  // Always Red for extracted credentials
                                
                                foreach (var cred in allCreds)
                                {
                                    // Create unique key for deduplication: FilePath + Username + Password
                                    string credKey = $"{filePath}|{cred.Username}|{cred.Password}";
                                    
                                    // Skip if already written
                                    if (_writtenCredentials.Contains(credKey))
                                    {
                                        continue;
                                    }
                                    
                                    string credPreview = !string.IsNullOrEmpty(cred.Service) 
                                        ? cred.Service + (!string.IsNullOrEmpty(cred.Url) ? $" ({cred.Url})" : "")
                                        : (!string.IsNullOrEmpty(cred.Url) ? cred.Url : "");
                                    
                                    if (string.IsNullOrEmpty(credPreview))
                                    {
                                        credPreview = preview; // Use file preview if no credential context
                                    }
                                    
                                    // Write to Excel
                                    _worksheet.Cells[_currentRow, 1].Value = credSeverity;
                                    _worksheet.Cells[_currentRow, 2].Value = credType;
                                    _worksheet.Cells[_currentRow, 3].Value = hostname;
                                    _worksheet.Cells[_currentRow, 4].Value = filePath;
                                    _worksheet.Cells[_currentRow, 5].Value = ruleName;
                                    _worksheet.Cells[_currentRow, 6].Value = cred.Username;
                                    _worksheet.Cells[_currentRow, 7].Value = cred.Password;
                                    _worksheet.Cells[_currentRow, 8].Value = dateFound;
                                    _worksheet.Cells[_currentRow, 9].Value = credPreview;
                                    
                                    // Color code by severity
                                    _worksheet.Cells[_currentRow, 1].Style.Fill.PatternType = ExcelFillStyle.Solid;
                                    _worksheet.Cells[_currentRow, 1].Style.Fill.BackgroundColor.SetColor(System.Drawing.Color.Red);
                                    _worksheet.Cells[_currentRow, 1].Style.Font.Color.SetColor(System.Drawing.Color.White);
                                    
                                    _currentRow++;
                                    _writtenCredentials.Add(credKey);
                                    _findingsCount++;
                                }
                            }
                            else
                            {
                                // No credentials found - downgrade Red to Yellow for sensitive files without actual credentials
                                string adjustedSeverity = severity == "Red" ? "Yellow" : severity;
                                
                                _worksheet.Cells[_currentRow, 1].Value = adjustedSeverity;
                                _worksheet.Cells[_currentRow, 2].Value = type;
                                _worksheet.Cells[_currentRow, 3].Value = hostname;
                                _worksheet.Cells[_currentRow, 4].Value = filePath;
                                _worksheet.Cells[_currentRow, 5].Value = ruleName;
                                _worksheet.Cells[_currentRow, 6].Value = "";
                                _worksheet.Cells[_currentRow, 7].Value = "";
                                _worksheet.Cells[_currentRow, 8].Value = dateFound;
                                _worksheet.Cells[_currentRow, 9].Value = preview;
                                
                                // Color code by severity
                                _worksheet.Cells[_currentRow, 1].Style.Fill.PatternType = ExcelFillStyle.Solid;
                                if (adjustedSeverity == "Yellow")
                                {
                                    _worksheet.Cells[_currentRow, 1].Style.Fill.BackgroundColor.SetColor(System.Drawing.Color.Yellow);
                                }
                                
                                _currentRow++;
                                _findingsCount++;
                            }
                        }
                        else
                        {
                            // No text content - downgrade Red to Yellow
                            string adjustedSeverity = severity == "Red" ? "Yellow" : severity;
                            
                            _worksheet.Cells[_currentRow, 1].Value = adjustedSeverity;
                            _worksheet.Cells[_currentRow, 2].Value = type;
                            _worksheet.Cells[_currentRow, 3].Value = hostname;
                            _worksheet.Cells[_currentRow, 4].Value = filePath;
                            _worksheet.Cells[_currentRow, 5].Value = ruleName;
                            _worksheet.Cells[_currentRow, 6].Value = "";
                            _worksheet.Cells[_currentRow, 7].Value = "";
                            _worksheet.Cells[_currentRow, 8].Value = dateFound;
                            _worksheet.Cells[_currentRow, 9].Value = preview;
                            
                            // Color code by severity
                            _worksheet.Cells[_currentRow, 1].Style.Fill.PatternType = ExcelFillStyle.Solid;
                            if (adjustedSeverity == "Yellow")
                            {
                                _worksheet.Cells[_currentRow, 1].Style.Fill.BackgroundColor.SetColor(System.Drawing.Color.Yellow);
                            }
                            
                            _currentRow++;
                            _findingsCount++;
                        }
                        
                        // Save every 10 writes to balance visibility and performance
                        if (_findingsCount % 10 == 0)
                        {
                            _excelPackage.Save();
                        }
                    }
                    catch { }
                }
                
                // FREE MEMORY AFTER CSV WRITE
                if (fileResult.TextResult != null)
                {
                    fileResult.TextResult.FullContent = null;
                    fileResult.TextResult.MatchContext = null;
                    fileResult.TextResult.MatchedStrings = null;
                }
            }
            
            // Don't add to console queue - CSV has everything we need
            // This prevents memory buildup from FileResult objects in the message queue
        }
        
        private class CredentialEntry
        {
            public string Service { get; set; }
            public string Username { get; set; }
            public string Password { get; set; }
            public string Url { get; set; }
        }
        
        /// <summary>
        /// Extract hostname from UNC path or drive letter path
        /// </summary>
        private string ExtractHostname(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return "";
            
            // UNC path: \\server\share\file
            if (filePath.StartsWith(@"\\"))
            {
                int firstSlash = 2;
                int secondSlash = filePath.IndexOf('\\', firstSlash);
                if (secondSlash > firstSlash)
                {
                    return filePath.Substring(firstSlash, secondSlash - firstSlash);
                }
                // Just \\server with no trailing slash
                return filePath.Substring(firstSlash);
            }
            
            // Local path or mapped drive - return "localhost" or extract computer name
            return Environment.MachineName ?? "localhost";
        }
        
        /// <summary>
        /// Decode HTML entities in passwords (e.g., &quot; to ")
        /// </summary>
        private string DecodeHtmlEntities(string text)
        {
            if (string.IsNullOrEmpty(text)) return text;
            return text
                .Replace("&quot;", "\"")
                .Replace("&quot", "\"")  // Handle truncated entity
                .Replace("&amp;", "&")
                .Replace("&amp", "&")
                .Replace("&lt;", "<")
                .Replace("&gt;", ">")
                .Replace("&apos;", "'")
                .Replace("&#39;", "'")
                .Trim('"', '\'', ' ');  // Clean up quotes
        }
        
        /// <summary>
        /// Check if text looks like a variable reference or common French word (not a real password)
        /// </summary>
        private bool IsVariableReference(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return true;
            
            // Very short codes (less than 4 chars, likely not real passwords)
            if (text.Length < 4 && Regex.IsMatch(text, @"^[A-Z0-9]+$", RegexOptions.IgnoreCase)) return true;
            
            // HTML/PHP/XML tags
            if ((text.StartsWith("<") || text.StartsWith(">")) && (text.EndsWith(">") || text.Contains("script") || text.Contains("param"))) return true;
            
            // PowerShell/PHP variables
            if (text.StartsWith("$") || text.Contains("$_") || text.Contains("$.")) return true;
            
            // Function calls and common PHP functions
            if (text.Contains("(") && text.Contains(")")) return true;
            if (Regex.IsMatch(text, @"(?i)^(substr|strlen|trim|echo|print|array|count|explode|implode|str_replace)")) return true;
            
            // md5/hash references
            if (Regex.IsMatch(text, @"(?i)\b(md5|sha|hash|crypt|encrypt)\b")) return true;
            
            // Object property access or code references (variable names, not values)
            if (text.Contains("->") || text.Contains(".CommandText") || text.Contains(".Context.")) return true;
            
            // Code property names that end with Password (the property itself, not the value)
            if (Regex.IsMatch(text, @"(?i)^_?configplugin\.|^common\.|^reportgenerator\.|^deliveryslip\.|^billgms\.|^website\.|^options\.")) return true;
            
            // Generic placeholders
            if (Regex.IsMatch(text, @"(?i)^(password|pwd|pass|user|username|login)$")) return true;
            
            // C# string.Format placeholders {0}, {1}, {2}, etc.
            if (Regex.IsMatch(text, @"^\{[0-9]+\}")) return true;
            
            // XML documentation tags - more comprehensive
            if (Regex.IsMatch(text, @"^[<>].*param[>]?$", RegexOptions.IgnoreCase)) return true;
            
            // Common French/English words (not passwords)
            if (Regex.IsMatch(text, @"(?i)^(pour|messagerie|vérouillé|verrouillé|remarque|doit|définir|distinct|master|status|liaisons|transport|information|generator|with|salt|passed|nécessaire|correct|incorrect|registre)$")) return true;
            
            // Partial connection string fragments (not passwords) - starts with semicolon
            if (Regex.IsMatch(text, @"(?i)^;(jet|data|oledb|initial|source|catalog|integrated|security|trusted)")) return true;
            
            return false;
        }
        
        private System.Collections.Generic.List<CredentialEntry> ExtractAllCredentialsFromTable(string content)
        {
            var credentials = new System.Collections.Generic.List<CredentialEntry>();
            try
            {
                // Check for tab-delimited tables
                bool hasTabDelimiter = content.Contains("\t");
                bool hasNewline = content.Contains("\n");
                
                // If no newlines and no tabs, might be single-line simple table
                if (!hasNewline && !hasTabDelimiter)
                {
                    return ExtractFromSimpleTable(new[] { content });
                }
                
                if (!hasNewline) return null;
                
                string[] lines = content.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                
                // If no tabs, try simple space-delimited table (1-3 rows)
                if (!hasTabDelimiter && lines.Length >= 1 && lines.Length <= 3)
                {
                    return ExtractFromSimpleTable(lines);
                }
                
                if (lines.Length < 2) return null;
                if (!hasTabDelimiter) return null;

                int headerIndex = -1;
                string[] headers = null;
                
                for (int i = 0; i < Math.Min(lines.Length, 10); i++)
                {
                    string[] potentialHeaders = lines[i].Split('\t');
                    if (potentialHeaders.Length >= 2)
                    {
                        bool hasUserKeyword = potentialHeaders.Any(h => 
                            Regex.IsMatch(h ?? "", @"(?i)(identifiant|login|username|utilisateur|user|compte|email|admin)"));
                        bool hasPassKeyword = potentialHeaders.Any(h => 
                            Regex.IsMatch(h ?? "", @"(?i)(mdp|password|pwd|mot.*passe|pass)"));
                        
                        if (hasUserKeyword && hasPassKeyword) { headerIndex = i; headers = potentialHeaders; break; }
                    }
                }
                if (headerIndex == -1 || headers == null) return null;

                int userColIndex = -1, passColIndex = -1, serviceColIndex = -1, urlColIndex = -1;
                for (int i = 0; i < headers.Length; i++)
                {
                    string header = headers[i]?.Trim()?.ToLower() ?? "";
                    if (userColIndex == -1 && Regex.IsMatch(header, @"(identifiant|login|username|utilisateur|user|compte|email|admin)")) userColIndex = i;
                    if (passColIndex == -1 && Regex.IsMatch(header, @"(mdp|password|pwd|mot.*passe|pass)")) passColIndex = i;
                    if (serviceColIndex == -1 && Regex.IsMatch(header, @"(nom|name|service|site|fournisseur|type)")) serviceColIndex = i;
                    if (urlColIndex == -1 && Regex.IsMatch(header, @"(lien|url|link|adresse|website)")) urlColIndex = i;
                }
                if (userColIndex == -1 || passColIndex == -1) return null;

                int maxCol = Math.Max(userColIndex, passColIndex);
                if (serviceColIndex > maxCol) maxCol = serviceColIndex;
                if (urlColIndex > maxCol) maxCol = urlColIndex;

                for (int i = headerIndex + 1; i < Math.Min(lines.Length, headerIndex + 101); i++)
                {
                    string[] cells = lines[i].Split('\t');
                    if (cells.Length > maxCol)
                    {
                        string user = DecodeHtmlEntities(cells[userColIndex]?.Trim() ?? "");
                        string pass = DecodeHtmlEntities(cells[passColIndex]?.Trim() ?? "");
                        string service = serviceColIndex >= 0 && cells.Length > serviceColIndex ? cells[serviceColIndex]?.Trim() ?? "" : "";
                        string url = urlColIndex >= 0 && cells.Length > urlColIndex ? cells[urlColIndex]?.Trim() ?? "" : "";

                        // Filter out obvious non-credentials (procedural text, instructions, etc.)
                        // Use word boundaries to avoid false positives like "FtpPass2024"
                        bool isProcedural = Regex.IsMatch(user + " " + pass, @"(?i)\b(cliquer|click|ouvrir|open|aller\s+à|voir|see|faire|exporter|export|enregistrer|save|vérifier|verify|intégrer|integrate)\b");
                        bool isGeneric = Regex.IsMatch(user + " " + pass, @"(?i)\b(formulaire|form|numéro|number|fichier|file|données|data|valeur|value|ligne|line|cellule|cell)\b");
                        
                        bool validUser = !string.IsNullOrWhiteSpace(user) && user.Length >= 2 && user.Length <= 150 &&
                            !Regex.IsMatch(user, @"(?i)^(identifiant|login|username|utilisateur|user|compte)$") &&
                            !IsVariableReference(user) && !isProcedural && !isGeneric;
                        bool validPass = !string.IsNullOrWhiteSpace(pass) && pass.Length >= 2 && pass.Length <= 150 &&
                            !Regex.IsMatch(pass, @"(?i)^(mdp|password|pwd|mot.*passe|pass)$") &&
                            !IsVariableReference(pass) && !isProcedural && !isGeneric;

                        if (validUser || validPass)
                        {
                            credentials.Add(new CredentialEntry { Username = validUser ? user : "", Password = validPass ? pass : "", Service = service, Url = url });
                        }
                    }
                }
                return credentials.Count > 0 ? credentials : null;
            }
            catch { return null; }
        }

        private System.Collections.Generic.List<CredentialEntry> ExtractFromSimpleTable(string[] lines)
        {
            var credentials = new System.Collections.Generic.List<CredentialEntry>();
            try
            {
                // Handle simple tables - could be multi-line or single-line with header embedded
                if (lines.Length == 0 || lines.Length > 3) return null;
                
                // Try to find credential keywords in any line
                string contentLower = string.Join(" ", lines).ToLower();
                bool hasUserKeyword = Regex.IsMatch(contentLower, @"(identifiant|login|username|utilisateur|user|compte)");
                bool hasPassKeyword = Regex.IsMatch(contentLower, @"(mdp|password|pwd|mot.*passe|pass)");
                
                if (!hasUserKeyword || !hasPassKeyword) return null;
                
                // Case 1: Single line with header and data (e.g., "Service Username Password  FTP Server ftpadmin FtpPass2024!")
                if (lines.Length == 1)
                {
                    string content = lines[0];
                    // Pattern: find where "Password" keyword ends, then look for data after multiple spaces
                    // Match: "Service Username Password" followed by "  FTP Server ftpadmin FtpPass2024!"
                    var match = Regex.Match(content, @"(?:password|pwd|pass)\s+(.+)$", RegexOptions.IgnoreCase);
                    if (match.Success)
                    {
                        string dataSection = match.Groups[1].Value.Trim();
                        
                        // Try splitting by single space first to see if we have exactly 3 parts
                        var singleSpaceParts = dataSection.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (singleSpaceParts.Length >= 3)
                        {
                            // Take first as service, second as username, third as password
                            string service = singleSpaceParts[0];
                            string username = singleSpaceParts.Length > 1 ? singleSpaceParts[singleSpaceParts.Length - 2] : singleSpaceParts[1];
                            string password = singleSpaceParts[singleSpaceParts.Length - 1];
                            
                            // If service has multiple words, combine them
                            if (singleSpaceParts.Length > 3)
                            {
                                service = string.Join(" ", singleSpaceParts.Take(singleSpaceParts.Length - 2));
                            }
                            
                            if (!string.IsNullOrWhiteSpace(username) && username.Length >= 2 && username.Length <= 150 &&
                                !string.IsNullOrWhiteSpace(password) && password.Length >= 2 && password.Length <= 150)
                            {
                                credentials.Add(new CredentialEntry { 
                                    Service = service, 
                                    Username = username, 
                                    Password = password, 
                                    Url = "" 
                                });
                            }
                        }
                    }
                }
                else
                {
                    // Case 2: Multi-line table (header on first line, data on subsequent lines)
                    for (int i = 1; i < lines.Length; i++)
                    {
                        string line = lines[i].Trim();
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        
                        // Split by multiple spaces (2+) to separate columns
                        var parts = Regex.Split(line, @"\s{2,}").Select(p => p.Trim()).Where(p => !string.IsNullOrEmpty(p)).ToArray();
                        
                        if (parts.Length >= 3)
                        {
                            string service = parts[0];
                            string username = parts[1];
                            string password = parts[2];
                            
                            if (!string.IsNullOrWhiteSpace(username) && username.Length >= 2 && username.Length <= 150 &&
                                !string.IsNullOrWhiteSpace(password) && password.Length >= 2 && password.Length <= 150)
                            {
                                credentials.Add(new CredentialEntry { 
                                    Service = service, 
                                    Username = username, 
                                    Password = password, 
                                    Url = "" 
                                });
                            }
                        }
                    }
                }
                
                return credentials.Count > 0 ? credentials : null;
            }
            catch { return null; }
        }

        private System.Collections.Generic.List<CredentialEntry> ExtractCredentialsFromXmlTags(string content)
        {
            var credentials = new System.Collections.Generic.List<CredentialEntry>();
            try
            {
                // Pattern: <SomePrefix.FtpPassword>value</SomePrefix.FtpPassword>
                // Matches: FtpPassword, SmtpPassword, ExcelPassword, DbPassword, SqlPassword, LdapPassword, etc.
                var xmlPasswordPattern = new Regex(@"<([^>]*\.)?(?<tagname>(?:ftp|smtp|excel|mail|db|sql|ldap|ssh|sftp|navision|server|database|admin)[._-]?(?:password|pwd))[^>]*>\s*(?<password>[^<]{3,}?)\s*</", 
                    RegexOptions.IgnoreCase | RegexOptions.Multiline);
                
                var seenPasswords = new System.Collections.Generic.HashSet<string>();
                
                foreach (Match match in xmlPasswordPattern.Matches(content))
                {
                    string password = DecodeHtmlEntities(match.Groups["password"].Value.Trim());
                    string tagName = match.Groups["tagname"].Value;
                    
                    // Skip obvious placeholders, variables, and duplicates
                    if (string.IsNullOrWhiteSpace(password) || 
                        password.Length < 3 || 
                        password.Length > 200 ||
                        Regex.IsMatch(password, @"(?i)^(password|pwd|none|null|empty)$") ||
                        IsVariableReference(password) ||
                        seenPasswords.Contains(password))
                        continue;
                    
                    seenPasswords.Add(password);
                    
                    // Try to find username in nearby tags
                    string username = "";
                    int matchPos = match.Index;
                    
                    // Look for username/login/user tags within 500 chars before this password tag
                    int contextStart = Math.Max(0, matchPos - 500);
                    int contextLength = matchPos - contextStart;
                    string contextBefore = content.Substring(contextStart, contextLength);
                    var userPattern = new Regex(@"<([^>]*\.)?(?:username|login|user|userid|user[._-]?id)[^>]*>\s*([^<]{2,}?)\s*</", 
                        RegexOptions.IgnoreCase);
                    var userMatches = userPattern.Matches(contextBefore);
                    if (userMatches.Count > 0)
                    {
                        username = DecodeHtmlEntities(userMatches[userMatches.Count - 1].Groups[2].Value.Trim());
                    }
                    
                    credentials.Add(new CredentialEntry 
                    { 
                        Username = username,
                        Password = password,
                        Service = tagName,
                        Url = ""
                    });
                }
                
                return credentials.Count > 0 ? credentials : null;
            }
            catch { return null; }
        }
        
        private System.Collections.Generic.List<CredentialEntry> ExtractCredentialsRegex(string content)
        {
            var credentials = new System.Collections.Generic.List<CredentialEntry>();
            try
            {
                // Safety check - don't process very large content
                if (string.IsNullOrEmpty(content) || content.Length > 500000) 
                    return null;
                
                var seenPasswords = new System.Collections.Generic.HashSet<string>();
                
                // PATTERN 1: C# string literals - string password = "value" or string userId = "value"
                var csharpPattern = new Regex(@"(?i)string\s+(password|pwd|userId|username|user)\s*=\s*""([^""]{3,100})""", RegexOptions.None, TimeSpan.FromMilliseconds(1000));
                foreach (Match match in csharpPattern.Matches(content))
                {
                    string varName = match.Groups[1].Value.ToLower();
                    string value = DecodeHtmlEntities(match.Groups[2].Value.Trim());
                    
                    if (string.IsNullOrWhiteSpace(value) || value.Length < 3 || value.Length > 100 || 
                        IsVariableReference(value) || seenPasswords.Contains(value))
                        continue;
                    
                    seenPasswords.Add(value);
                    
                    // Try to find nearby username/password pair
                    int matchPos = match.Index;
                    int contextStart = Math.Max(0, matchPos - 200);
                    int contextEnd = Math.Min(content.Length, matchPos + 200);
                    string context = content.Substring(contextStart, contextEnd - contextStart);
                    
                    string username = "", password = "";
                    if (varName.Contains("pass") || varName.Contains("pwd"))
                    {
                        password = value;
                        var userMatch = Regex.Match(context, @"(?i)string\s+(userId|username|user)\s*=\s*""([^""]{2,100})""");
                        if (userMatch.Success)
                            username = DecodeHtmlEntities(userMatch.Groups[2].Value.Trim());
                    }
                    else
                    {
                        username = value;
                        var passMatch = Regex.Match(context, @"(?i)string\s+(password|pwd)\s*=\s*""([^""]{3,100})""");
                        if (passMatch.Success)
                            password = DecodeHtmlEntities(passMatch.Groups[2].Value.Trim());
                    }
                    
                    if (!string.IsNullOrEmpty(username) || !string.IsNullOrEmpty(password))
                    {
                        credentials.Add(new CredentialEntry { Username = username, Password = password, Service = "", Url = "" });
                    }
                }
                
                // PATTERN 2: General password patterns
                var pwdPattern = new Regex(@"(?i)(password|pwd|mdp|mot.?de.?passe)[\s:=\t""']+([^\s\t\n\r""']{4,50})", RegexOptions.None, TimeSpan.FromMilliseconds(1000));
                
                foreach (Match pwdMatch in pwdPattern.Matches(content))
                {
                    if (pwdMatch.Groups.Count > 2)
                    {
                        string password = DecodeHtmlEntities(pwdMatch.Groups[2].Value.Trim().TrimEnd(',', ';', ')', '}', ']', '"', '\''));
                        
                        // Skip placeholders, variables, and duplicates
                        if (string.IsNullOrWhiteSpace(password) || password.Length < 4 || password.Length > 100 ||
                            Regex.IsMatch(password, @"(?i)^(password|pwd|mdp|none|null|empty|\*+|x+)$") ||
                            IsVariableReference(password) ||
                            seenPasswords.Contains(password))
                            continue;
                        
                        seenPasswords.Add(password);
                        
                        // Try to find username near this password (within 200 chars before)
                        string username = "";
                        int matchPos = pwdMatch.Index;
                        int contextStart = Math.Max(0, matchPos - 200);
                        int contextLength = matchPos - contextStart;
                        string contextBefore = content.Substring(contextStart, contextLength);
                        
                        // Try email first
                        var emailMatch = Regex.Match(contextBefore, @"[\w\.-]+@[\w\.-]+\.\w+");
                        if (emailMatch.Success)
                        {
                            username = emailMatch.Value;
                        }
                        else
                        {
                            // Try username pattern
                            var userPattern = new Regex(@"(?i)(user|username|login|identifiant|utilisateur|user\s*id)[\s:=\t""]+([^\s\t\n\r""']{3,50})");
                            var userMatches = userPattern.Matches(contextBefore);
                            if (userMatches.Count > 0)
                            {
                                username = DecodeHtmlEntities(userMatches[userMatches.Count - 1].Groups[2].Value.Trim());
                                if (IsVariableReference(username))
                                    username = "";
                            }
                        }
                        
                        credentials.Add(new CredentialEntry
                        {
                            Username = username,
                            Password = password,
                            Service = "",
                            Url = ""
                        });
                    }
                }
                
                return credentials.Count > 0 ? credentials : null;
            }
            catch { return null; }
        }
        
        private string DetermineType(FileResult result)
        {
            string ruleName = result.MatchedRule?.RuleName?.ToLower() ?? "";
            
            // Check for password-protected file first
            if (ruleName.Contains("passwordprotected") || ruleName == "passwordprotectedfile")
                return "Password-Protected File";
            
            if (ruleName.Contains("credential") || ruleName.Contains("password")) return "Credentials";
            if (ruleName.Contains("key") && ruleName.Contains("private")) return "Private Key";
            if (ruleName.Contains("config")) return "Config File";
            return "Sensitive File";
        }
        
        private string GetPreview(string content, int maxLen)
        {
            if (string.IsNullOrEmpty(content)) return "";
            content = content.Replace("\r", " ").Replace("\n", " ").Replace("\t", " ");
            return content.Length > maxLen ? content.Substring(0, maxLen) + "..." : content;
        }
        
        private string EscapeCsv(string value)
        {
            if (string.IsNullOrEmpty(value)) return "\"\"";
            // Escape quotes by doubling them, replace pipe, clean newlines
            // Wrap in quotes to protect semicolons and other characters from Excel's regional settings
            value = value.Replace("\"", "\"\"").Replace("|", "¦").Replace("\r", " ").Replace("\n", " ").Replace("\t", " ");
            return "\"" + value + "\"";
        }
        
        public void FinalizeCsv()
        {
            if (_excelPackage != null)
            {
                lock (_excelLock)
                {
                    // Auto-fit columns for readability
                    _worksheet.Cells[_worksheet.Dimension.Address].AutoFitColumns();
                    
                    // Save final version
                    _excelPackage.Save();
                    _excelPackage.Dispose();
                    _excelPackage = null;
                    Info($"Excel file finalized: {_findingsCount} findings from {_filesProcessed} files processed");
                }
            }
        }
        
        public void Dispose() 
        { 
            if (_excelPackage != null)
            {
                _excelPackage.Save();
                _excelPackage.Dispose();
            }
        }
        public int GetFindingsCount() => _findingsCount;
        public void DirResult(DirResult dirResult)
        {
            // say we did a thing
            Q.Add(new SnafflerMessage
            {
                DateTime = DateTime.Now,
                DirResult = dirResult,
                Type = SnafflerMessageType.DirResult
            });
        }
        public void ShareResult(ShareResult shareResult)
        {
            // say we did a thing
            Q.Add(new SnafflerMessage
            {
                DateTime = DateTime.Now,
                ShareResult = shareResult,
                Type = SnafflerMessageType.ShareResult
            });
        }

        public void Finish()
        {
            Q.Add(new SnafflerMessage()
            {
                DateTime = DateTime.Now,
                Type = SnafflerMessageType.Finish
            });
        }
    }
}