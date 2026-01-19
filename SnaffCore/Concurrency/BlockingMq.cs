using SnaffCore.Classifiers;
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace SnaffCore.Concurrency
{
    public class BlockingMq : IDisposable
    {
        private static BlockingMq _instance;
        
        // Direct CSV output - bypasses all memory accumulation
        private StreamWriter _csvWriter;
        private readonly object _csvLock = new object();
        private string _csvPath;
        private int _findingsCount = 0;
        private int _filesProcessed = 0;

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
        /// Initialize direct CSV output (call before scanning starts)
        /// </summary>
        public void InitCsvOutput(string outputPath)
        {
            _csvPath = Path.ChangeExtension(outputPath, ".csv");
            _csvWriter = new StreamWriter(_csvPath, false, Encoding.UTF8, 65536);
            _csvWriter.WriteLine("Severity,Type,FilePath,RuleName,Username,Password,DateFound,Preview");
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
            // DIRECT CSV WRITE - no memory accumulation
            if (_csvWriter != null)
            {
                // EXTRACT CREDENTIALS OUTSIDE LOCK (parallel processing)
                string severity = fileResult.MatchedRule?.Triage.ToString() ?? "Unknown";
                string type = DetermineType(fileResult);
                string filePath = EscapeCsv(fileResult.FileInfo?.FullName ?? "");
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
                
                // LOCK ONLY FOR CSV WRITE (fast operation)
                lock (_csvLock)
                {
                    try
                    {
                        if (hasTextResult)
                        {
                            if (allCreds != null && allCreds.Count > 0)
                            {
                                foreach (var cred in allCreds)
                                {
                                    string credPreview = !string.IsNullOrEmpty(cred.Service) 
                                        ? cred.Service + (!string.IsNullOrEmpty(cred.Url) ? $" ({cred.Url})" : "")
                                        : (!string.IsNullOrEmpty(cred.Url) ? cred.Url : "");
                                    
                                    if (string.IsNullOrEmpty(credPreview))
                                    {
                                        credPreview = preview; // Use file preview if no credential context
                                    }
                                    
                                    _csvWriter.WriteLine($"{severity},{type},{filePath},{ruleName},{EscapeCsv(cred.Username)},{EscapeCsv(cred.Password)},{dateFound},{EscapeCsv(credPreview)}");
                                    _findingsCount++;
                                }
                            }
                            else
                            {
                                // No credentials found - just show the file with preview
                                _csvWriter.WriteLine($"{severity},{type},{filePath},{ruleName},,,{dateFound},{preview}");
                                _findingsCount++;
                            }
                        }
                        else
                        {
                            _csvWriter.WriteLine($"{severity},{type},{filePath},{ruleName},,,{dateFound},{preview}");
                            _findingsCount++;
                        }
                        
                        // Flush every 10 writes to balance visibility and performance
                        if (_findingsCount % 10 == 0) _csvWriter.Flush();
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
                        string user = cells[userColIndex]?.Trim() ?? "";
                        string pass = cells[passColIndex]?.Trim() ?? "";
                        string service = serviceColIndex >= 0 && cells.Length > serviceColIndex ? cells[serviceColIndex]?.Trim() ?? "" : "";
                        string url = urlColIndex >= 0 && cells.Length > urlColIndex ? cells[urlColIndex]?.Trim() ?? "" : "";

                        // Filter out obvious non-credentials (procedural text, instructions, etc.)
                        // Use word boundaries to avoid false positives like "FtpPass2024"
                        bool isProcedural = Regex.IsMatch(user + " " + pass, @"(?i)\b(cliquer|click|ouvrir|open|aller\s+à|voir|see|faire|exporter|export|enregistrer|save|vérifier|verify|intégrer|integrate)\b");
                        bool isGeneric = Regex.IsMatch(user + " " + pass, @"(?i)\b(formulaire|form|numéro|number|fichier|file|données|data|valeur|value|ligne|line|cellule|cell)\b");
                        
                        bool validUser = !string.IsNullOrWhiteSpace(user) && user.Length >= 2 && user.Length <= 150 &&
                            !Regex.IsMatch(user, @"(?i)^(identifiant|login|username|utilisateur|user|compte)$") &&
                            !isProcedural && !isGeneric;
                        bool validPass = !string.IsNullOrWhiteSpace(pass) && pass.Length >= 2 && pass.Length <= 150 &&
                            !Regex.IsMatch(pass, @"(?i)^(mdp|password|pwd|mot.*passe|pass)$") &&
                            !isProcedural && !isGeneric;

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
                    string password = match.Groups["password"].Value.Trim();
                    string tagName = match.Groups["tagname"].Value;
                    
                    // Skip obvious placeholders and duplicates
                    if (string.IsNullOrWhiteSpace(password) || 
                        password.Length < 3 || 
                        password.Length > 200 ||
                        Regex.IsMatch(password, @"(?i)^(password|pwd|none|null|empty)$") ||
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
                        username = userMatches[userMatches.Count - 1].Groups[2].Value.Trim();
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
                
                // Find all passwords first (can be multiple)
                var seenPasswords = new System.Collections.Generic.HashSet<string>();
                var pwdPattern = new Regex(@"(?i)(password|pwd|mdp|mot.?de.?passe)[\s:=\t""']+([^\s\t\n\r""']{4,50})", RegexOptions.None, TimeSpan.FromMilliseconds(1000));
                
                foreach (Match pwdMatch in pwdPattern.Matches(content))
                {
                    if (pwdMatch.Groups.Count > 2)
                    {
                        string password = pwdMatch.Groups[2].Value.Trim().TrimEnd(',', ';', ')', '}', ']', '"', '\'');
                        
                        // Skip placeholders and duplicates
                        if (string.IsNullOrWhiteSpace(password) || password.Length < 4 || password.Length > 100 ||
                            Regex.IsMatch(password, @"(?i)^(password|pwd|mdp|none|null|empty|\*+|x+)$") ||
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
                            var userPattern = new Regex(@"(?i)(user|username|login|identifiant|utilisateur|user\s*id)[\s:=\t]+([^\s\t\n\r""']{3,50})");
                            var userMatches = userPattern.Matches(contextBefore);
                            if (userMatches.Count > 0)
                            {
                                username = userMatches[userMatches.Count - 1].Groups[2].Value.Trim();
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
            if (string.IsNullOrEmpty(value)) return "";
            if (value.Contains(",") || value.Contains(";") || value.Contains("\"") || value.Contains("\n") || value.Contains("\r"))
                return $"\"{value.Replace("\"", "\"\"")}\"";
            return value;
        }
        
        public void FinalizeCsv()
        {
            if (_csvWriter != null)
            {
                lock (_csvLock)
                {
                    _csvWriter.Flush();
                    _csvWriter.Close();
                    _csvWriter = null;
                    Info($"CSV finalized: {_findingsCount} findings from {_filesProcessed} files processed");
                }
            }
        }
        
        public void Dispose() { _csvWriter?.Dispose(); }
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