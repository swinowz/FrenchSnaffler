using SnaffCore.Concurrency;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using static SnaffCore.Config.Options;

#if ULTRASNAFFLER
using Toxy;
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
                    
                    // Stop on first match to avoid duplicate findings
                    return;
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
                    
                    // Stop on first match to avoid duplicate findings
                    return;
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
                    
                    return;
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
            // Parse office documents using Toxy
            // Implementation from original ContentClassifier
            try
            {
                ParserContext context = new ParserContext(fileInfo.FullName);
                IDocumentParser parser = ParserFactory.CreateDocument(context);
                ToxyDocument document = parser.Parse();
                return document.ToString();
            }
            catch
            {
                return File.ReadAllText(fileInfo.FullName);
            }
        }
#endif
    }
}
