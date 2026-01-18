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
                (string Username, string Password) singleCred = (null, null);
                string preview = "";
                bool hasTextResult = false;
                
                if (fileResult.TextResult != null)
                {
                    hasTextResult = true;
                    string content = fileResult.TextResult.FullContent ?? fileResult.TextResult.MatchContext ?? "";
                    
                    // Extract credentials (slow - do outside lock)
                    allCreds = ExtractAllCredentialsFromTable(content);
                    
                    if (allCreds == null || allCreds.Count == 0)
                    {
                        singleCred = ExtractCredentialsRegex(content);
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
                                        : (!string.IsNullOrEmpty(cred.Url) ? cred.Url : "Credential from table");
                                    
                                    _csvWriter.WriteLine($"{severity},{type},{filePath},{ruleName},{EscapeCsv(cred.Username)},{EscapeCsv(cred.Password)},{dateFound},{EscapeCsv(credPreview)}");
                                    _findingsCount++;
                                }
                            }
                            else
                            {
                                _csvWriter.WriteLine($"{severity},{type},{filePath},{ruleName},{EscapeCsv(singleCred.Username ?? "")},{EscapeCsv(singleCred.Password ?? "")},{dateFound},{preview}");
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
                if (!content.Contains("\t") || !content.Contains("\n")) return null;
                string[] lines = content.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                if (lines.Length < 2) return null;

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
                        bool isProcedural = Regex.IsMatch(user + " " + pass, @"(?i)(cliquer|click|ouvrir|open|aller|go|voir|see|faire|do|exporter|export|enregistrer|save|vérifier|verify|passer|pass|intégrer|integrate)");
                        bool isGeneric = Regex.IsMatch(user + " " + pass, @"(?i)(formulaire|form|numéro|number|fichier|file|données|data|valeur|value|ligne|line|cellule|cell)");
                        
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
        
        private (string Username, string Password) ExtractCredentialsRegex(string content)
        {
            string username = null, password = null;
            try
            {
                var emailMatch = Regex.Match(content, @"[\w\.-]+@[\w\.-]+\.\w+");
                if (emailMatch.Success) username = emailMatch.Value;

                if (string.IsNullOrEmpty(username))
                {
                    var userMatch = Regex.Match(content, @"(?i)(user|username|login|identifiant|utilisateur)[\s:=\t]+([^\s\t\n\r]{3,50})");
                    if (userMatch.Success && userMatch.Groups.Count > 2) username = userMatch.Groups[2].Value.Trim();
                }

                var pwdMatch = Regex.Match(content, @"(?i)(password|pwd|mdp|mot.?de.?passe)[\s:=\t""']+([^\s\t\n\r""']{4,50})");
                if (pwdMatch.Success && pwdMatch.Groups.Count > 2)
                {
                    password = pwdMatch.Groups[2].Value.Trim().TrimEnd(',', ';', ')', '}', ']', '"', '\'');
                }
            }
            catch { }
            return (username, password);
        }
        
        private string DetermineType(FileResult result)
        {
            string ruleName = result.MatchedRule?.RuleName?.ToLower() ?? "";
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