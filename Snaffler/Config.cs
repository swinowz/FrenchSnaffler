using CommandLineParser.Arguments;
using Nett;
using NLog;
using SnaffCore.Concurrency;
using SnaffCore.Config;
using System;
using System.Resources;
using System.IO;
using System.Linq;
using System.Text;
using System.Reflection;
using System.Security;
using System.Collections.Generic;
using System.Net;

namespace ShareAuditor
{
    public static class Config
    {
        public static Options Parse(string[] args)
        {
            BlockingMq Mq = BlockingMq.GetMq();
            Options options;

            // parse the args
            try
            {
                options = ParseImpl(args);
                if (options == null)
                {
                    return null;
                }
            }
            catch
            {
                Mq.Error("Something went wrong parsing args.");
                throw;
            }

            Mq.Info("Parsed args successfully.");
            return options;
        }


        public static string ReadResource(string name)
        {
            // Determine path
            var assembly = Assembly.GetExecutingAssembly();
            string resourcePath = name;
            // Format: "{Namespace}.{Folder}.{filename}.{Extension}"

            using (Stream stream = assembly.GetManifestResourceStream(resourcePath))
            using (StreamReader reader = new StreamReader(stream))
            {
                return reader.ReadToEnd();
            }
        }

        public static bool isIP(string host)
        {
            IPAddress ip;
            return IPAddress.TryParse(host, out ip);
        }

        private static Options ParseImpl(string[] args)
        {
            BlockingMq Mq = BlockingMq.GetMq();
            Mq.Info("Parsing args...");
            Options parsedConfig = new Options();

            // define args
            ValueArgument<string> configFileArg = new ValueArgument<string>('z', "config", "Path to a .toml config file. Run with \'generate\' to puke a sample config file into the working directory.");
            ValueArgument<string> outFileArg = new ValueArgument<string>('o', "outfile",
                "Path for output file. You probably want this if you're not using -s.");
            ValueArgument<string> verboseArg = new ValueArgument<string>('v', "verbosity",
                "Controls verbosity level, options are Trace (most verbose), Debug (less verbose), Info (less verbose still, default), and Data (results only). e.g '-v debug' ");
            SwitchArgument helpArg = new SwitchArgument('h', "help", "Displays this help.", false);
            SwitchArgument stdOutArg = new SwitchArgument('s', "stdout",
                "Enables outputting results to stdout as soon as they're found. You probably want this if you're not using -o.",
                false);
            ValueArgument<int> interestLevel = new ValueArgument<int>('b', "interest", "Interest level to report (0-3)");
            ValueArgument<string> snaffleArg = new ValueArgument<string>('m', "collect",
                "Enables and assigns an output dir for ShareAuditor to automatically collect a copy of any found files.");
            ValueArgument<long> snaffleSizeArg = new ValueArgument<long>('l', "collectsize", "Maximum size of file to collect, in bytes. Defaults to 10MB.");
            //var fileHuntArg = new SwitchArgument('f', "filehuntoff",
            //    "Disables file discovery, will only perform computer and share discovery.", false);
            ValueArgument<string> dirTargetArg = new ValueArgument<string>('i', "dirtarget",
                "Disables computer and share discovery, requires a path to a directory in which to perform file discovery.");
            ValueArgument<string> domainArg = new ValueArgument<string>('d', "domain",
                "Domain to search for computers to search for shares on to search for files in. Easy.");
            ValueArgument<string> domainControllerArg = new ValueArgument<string>('c', "domaincontroller",
                "Domain controller to query for a list of domain computers.");
            ValueArgument<long> maxGrepSizeArg = new ValueArgument<long>('r', "maxgrepsize",
                "The maximum size file (in bytes) to search inside for interesting strings. Defaults to 500k.");
            ValueArgument<int> grepContextArg = new ValueArgument<int>('j', "grepcontext",
                "How many bytes of context either side of found strings in files to show, e.g. -j 200");
            SwitchArgument domainUserArg = new SwitchArgument('u', "domainusers", "Makes ShareAuditor grab a list of interesting-looking accounts from the domain and uses them in searches.", false);
            ValueArgument<int> maxThreadsArg = new ValueArgument<int>('x', "maxthreads", "How many threads to be scanning with. Any less than 4 and you're gonna have a bad time.");
            SwitchArgument tsvArg = new SwitchArgument('y', "tsv", "Makes ShareAuditor output as tsv.", false);
            SwitchArgument dfsArg = new SwitchArgument('f', "dfs", "Limits ShareAuditor to finding file shares via DFS, for \"OPSEC\" reasons.", false);
            SwitchArgument findSharesOnlyArg = new SwitchArgument('a', "sharesonly",
                "Stops after finding shares, doesn't walk their filesystems.", false);
            ValueArgument<string> compExclusionArg = new ValueArgument<string>('k', "exclusions", "Path to a file containing a list of computers to exclude from scanning.");
            ValueArgument<string> compTargetArg = new ValueArgument<string>('n', "comptarget", "List of computers in a file(e.g C:\targets.txt), a single Computer (or comma separated list) to target.");
            ValueArgument<string> ruleDirArg = new ValueArgument<string>('p', "rulespath", "Path to a directory full of toml-formatted rules. ShareAuditor will load all of these in place of the default ruleset.");
            ValueArgument<string> logType = new ValueArgument<string>('t', "logtype", "Type of log you would like to output. Currently supported options are plain and JSON. Defaults to plain.");
            ValueArgument<string> testFileArg = new ValueArgument<string>('w', "testfile", "Test credential extraction methods on a specific file. Outputs method results to console only.");
            ValueArgument<string> timeOutArg = new ValueArgument<string>('e', "timeout",
                "Interval between status updates (in minutes) also acts as a timeout for AD data to be gathered via LDAP. Turn this knob up if you aren't getting any computers from AD when you run ShareAuditor through a proxy or other slow link. Default = 5");
            // list of letters i haven't used yet: gnq

            CommandLineParser.CommandLineParser parser = new CommandLineParser.CommandLineParser();
            parser.Arguments.Add(timeOutArg);
            parser.Arguments.Add(testFileArg);
            parser.Arguments.Add(configFileArg);
            parser.Arguments.Add(outFileArg);
            parser.Arguments.Add(helpArg);
            parser.Arguments.Add(stdOutArg);
            parser.Arguments.Add(snaffleArg);
            parser.Arguments.Add(snaffleSizeArg);
            parser.Arguments.Add(dirTargetArg);
            parser.Arguments.Add(interestLevel);
            parser.Arguments.Add(domainArg);
            parser.Arguments.Add(verboseArg);
            parser.Arguments.Add(domainControllerArg);
            parser.Arguments.Add(maxGrepSizeArg);
            parser.Arguments.Add(grepContextArg);
            parser.Arguments.Add(domainUserArg);
            parser.Arguments.Add(tsvArg);
            parser.Arguments.Add(dfsArg);
            parser.Arguments.Add(findSharesOnlyArg);
            parser.Arguments.Add(maxThreadsArg);
            parser.Arguments.Add(compTargetArg);
            parser.Arguments.Add(ruleDirArg);
            parser.Arguments.Add(logType);
            parser.Arguments.Add(compExclusionArg);

            // extra check to handle builtin behaviour from cmd line arg parser
            if ((args.Contains("--help") || args.Contains("/?") || args.Contains("help") || args.Contains("-h") || args.Length == 0))
            {
                parser.ShowUsage();
                return null; 
            }

            TomlSettings settings = TomlSettings.Create(cfg => cfg
.ConfigureType<LogLevel>(tc =>
    tc.WithConversionFor<TomlString>(conv => conv
        .FromToml(s => (LogLevel)Enum.Parse(typeof(LogLevel), s.Value, ignoreCase: true))
        .ToToml(e => e.ToString()))));

            try
            {
                parser.ParseCommandLine(args);

                // Test mode - extract credentials from single file and show methods
                if (testFileArg.Parsed && !String.IsNullOrWhiteSpace(testFileArg.Value))
                {
                    TestCredentialExtraction(testFileArg.Value);
                    return null; // Exit after test
                }

                if (timeOutArg.Parsed && !String.IsNullOrWhiteSpace(timeOutArg.Value))
                {
                    int timeOutVal;
                    if (int.TryParse(timeOutArg.Value, out timeOutVal))
                    {
                        Mq.Info("Set timeout/update interval to " + timeOutVal.ToString() + " minutes.");
                        parsedConfig.TimeOut = timeOutVal;
                    }
                    else
                    {
                        Mq.Error("Invalid timeout value passed, defaulting to 5 mins.");
                    }
                }

                if (logType.Parsed && !String.IsNullOrWhiteSpace(logType.Value))
                {
                    //Set the default to plain
                    parsedConfig.LogType = LogType.Plain;
                    //if they set a different type then replace it with the new type.
                    if (logType.Value.ToLower() == "json")
                    {
                        parsedConfig.LogType = LogType.JSON;
                    }
                    else if (logType.Value.ToLower() == "auto")
                    {
                        parsedConfig.LogType = LogType.Auto;
                        Mq.Info("Excel report generation enabled with -t auto");
                    }
                    else
                    {
                        Mq.Info("Invalid type argument passed (" + logType.Value + ") defaulting to plaintext");
                    }
                }

                if (ruleDirArg.Parsed && !String.IsNullOrWhiteSpace(ruleDirArg.Value))
                {
                    parsedConfig.RuleDir = ruleDirArg.Value;
                }

                // get the args into our config

                // output args
                if (outFileArg.Parsed && (!String.IsNullOrEmpty(outFileArg.Value)))
                {
                    parsedConfig.LogToFile = true;
                    parsedConfig.LogFilePath = outFileArg.Value;
                    Mq.Degub("Logging to file at " + parsedConfig.LogFilePath);
                }

                if (dfsArg.Parsed)
                {
                    parsedConfig.DfsOnly = dfsArg.Value;
                }
                if (compExclusionArg.Parsed)
                {
                    List<string> compExclusions = new List<string>();
                    string[] fileLines = File.ReadAllLines(compExclusionArg.Value);
                    foreach (string line in fileLines)
                    {
                        if (isIP(line))
                        {
                            compExclusions.Add(line);
                        }
                        else
                        {
                            try
                            {
                                IPHostEntry result = Dns.GetHostEntry(line);
                                foreach (IPAddress ipAddress in result.AddressList)
                                {
                                    compExclusions.Add(ipAddress.ToString());
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine(ex.Message);
                                continue;
                            }
                        }
                    }
                    if (compExclusions.Count > 0)
                    {
                        parsedConfig.ComputerExclusions = compExclusions;
                        parsedConfig.ComputerExclusionFile = compExclusionArg.Value;
                    }
                    else
                    {
                        throw new Exception("Failed to get a valid list of excluded computers from the excluded computers list.");
                    }
                }
                
                if (compTargetArg.Parsed)
                {
                    List<string> compTargets = new List<string>();
                    if (compTargetArg.Value.Contains(Path.DirectorySeparatorChar))
                    {
                        compTargets.AddRange(File.ReadLines(compTargetArg.Value).Select(line => line.Trim()));
                    }
                    else if (compTargetArg.Value.Contains(","))
                    {
                        compTargets.AddRange(compTargetArg.Value.Split(',').Select(x => x.Trim()));
                    }
                    else
                    {
                        compTargets.Add(compTargetArg.Value.Trim());
                    }
                    parsedConfig.ComputerTargets = compTargets.ToArray();
                }

                if (findSharesOnlyArg.Parsed)
                {
                    parsedConfig.ScanFoundShares = false;
                }
                if (maxThreadsArg.Parsed)
                {
                    parsedConfig.MaxThreads = maxThreadsArg.Value;
                }
                
                // If no -x specified, default to 100 threads
                if (parsedConfig.MaxThreads <= 0)
                {
                    parsedConfig.MaxThreads = 100;
                }

                // Allocate more threads to FileScanner since that's the bottleneck
                // Share: 10%, Tree: 20%, File: 70%
                parsedConfig.ShareThreads = Math.Max(1, parsedConfig.MaxThreads / 10);
                parsedConfig.TreeThreads = Math.Max(1, parsedConfig.MaxThreads / 5);
                parsedConfig.FileThreads = parsedConfig.MaxThreads - parsedConfig.ShareThreads - parsedConfig.TreeThreads;
                
                // Increase .NET ThreadPool limits to handle high concurrency
                System.Threading.ThreadPool.SetMinThreads(parsedConfig.MaxThreads, parsedConfig.MaxThreads);
                System.Threading.ThreadPool.SetMaxThreads(parsedConfig.MaxThreads * 2, parsedConfig.MaxThreads * 2);

                if (tsvArg.Parsed)
                {
                    parsedConfig.LogTSV = true;
                    if (parsedConfig.Separator == ' ')
                    {
                        parsedConfig.Separator = '\t';
                    }
                }

                // Set loglevel.
                if (verboseArg.Parsed)
                {
                    parsedConfig.LogLevelString = verboseArg.Value;
                    Mq.Degub("Requested verbosity level: " + parsedConfig.LogLevelString);
                }

                // Explicit console output flag
                if (stdOutArg.Parsed)
                {
                    parsedConfig.LogToConsole = true;
                    Mq.Degub("Console output enabled via -s flag.");
                }

                // args that tell us about targeting
                if ((domainArg.Parsed) && (!String.IsNullOrEmpty(domainArg.Value)))
                {
                    parsedConfig.TargetDomain = domainArg.Value;
                    Mq.Degub("Target domain is " + domainArg.Value);
                }

                if ((domainControllerArg.Parsed) && (!String.IsNullOrEmpty(domainControllerArg.Value)))
                {
                    parsedConfig.TargetDc = domainControllerArg.Value;
                    Mq.Degub("Target DC is " + domainControllerArg.Value);
                }

                if (domainUserArg.Parsed)
                {
                    parsedConfig.DomainUserRules = true;
                    Mq.Degub("Enabled use of domain user accounts in rules.");
                }

                if (dirTargetArg.Parsed)
                {
                    parsedConfig.ShareFinderEnabled = false;
                    Mq.Degub("Disabled finding shares.");

                    if (dirTargetArg.Value.Contains(","))
                    {
                        string pathTargetsString = dirTargetArg.Value;
                        string[] pathTargets = pathTargetsString.Split(',');
                        foreach (string pathTarget in pathTargets)
                        {
                            if (pathTarget.Length > 4)
                            {
                                parsedConfig.PathTargets.Add(pathTarget.TrimEnd('\\'));
                            }
                            else
                            {
                                parsedConfig.PathTargets.Add(pathTarget);
                            }
                        }
                    }
                    else
                    {
                        string pathTarget = dirTargetArg.Value;
                        if (dirTargetArg.Value.Length > 4)
                        {
                            pathTarget = dirTargetArg.Value.TrimEnd('\\');
                        }
                        parsedConfig.PathTargets.Add(pathTarget);
                    }
                    
                    //Console.WriteLine(parsedConfig.PathTargets[0]);
                    foreach (string pathTarget in parsedConfig.PathTargets)
                    {
                        Mq.Degub("Targeting path:" + pathTarget);
                    }
                }

                if (maxGrepSizeArg.Parsed)
                {
                    parsedConfig.MaxSizeToGrep = maxGrepSizeArg.Value;
                    Mq.Degub("We won't bother looking inside files if they're bigger than " + parsedConfig.MaxSizeToGrep +
                             " bytes");
                }

                if (snaffleSizeArg.Parsed)
                {
                    parsedConfig.MaxSizeToSnaffle = snaffleSizeArg.Value;
                }

                if (interestLevel.Parsed)
                {
                    parsedConfig.InterestLevel = interestLevel.Value;
                    Mq.Degub("Requested interest level: " + parsedConfig.InterestLevel);
                }

                // how many bytes 
                if (grepContextArg.Parsed)
                {
                    parsedConfig.MatchContextBytes = grepContextArg.Value;
                    Mq.Degub(
                        "We'll show you " + grepContextArg.Value +
                        " bytes of context around matches inside files.");
                }

                // if enabled, grab a copy of files that we like.
                if (snaffleArg.Parsed)
                {
                    if (snaffleArg.Value.Length <= 0)
                    {
                        Mq.Error("-m or -mirror arg requires a path value.");
                        throw new ArgumentException("Invalid argument combination.");
                    }

                    parsedConfig.Snaffle = true;
                    parsedConfig.SnafflePath = snaffleArg.Value.TrimEnd('\\');
                    Mq.Degub("Mirroring matched files to path " + parsedConfig.SnafflePath);
                }

                if (configFileArg.Parsed)
                {
                    if (configFileArg.Value.Equals("generate"))
                    {
                        Toml.WriteFile(parsedConfig, ".\\default.toml", settings);
                        Console.WriteLine("Wrote config values to .\\default.toml");
                        parsedConfig.LogToConsole = true;
                        Mq.Degub("Enabled logging to stdout.");
                        return null;
                    }
                    else
                    {
                        string configFile = configFileArg.Value;
                        parsedConfig = Toml.ReadFile<Options>(configFile, settings);
                        Mq.Info("Read config file from " + configFile);
                    }
                }

                // Default: If verbose mode is enabled but no output destination specified, use console
                if (verboseArg.Parsed && !parsedConfig.LogToFile && !parsedConfig.LogToConsole)
                {
                    parsedConfig.LogToConsole = true;
                    Mq.Info("Verbose mode enabled without output destination - defaulting to console.");
                }

                // Validation: Must have at least one output destination
                if (!parsedConfig.LogToConsole && !parsedConfig.LogToFile)
                {
                    Mq.Error("\nNo output destination specified. Use -s for console output or -o <file> for file output.");
                    throw new ArgumentException("No output destination specified.");
                }

                if (parsedConfig.ClassifierRules.Count <= 0)
                {
                    // For single-file apps, try multiple locations to find SnaffRules:
                    // 1. Directory where exe actually resides (from Environment.ProcessPath - .NET 6+)
                    // 2. Directory where exe was launched from (GetCurrentDirectory)
                    // 3. AppContext.BaseDirectory (temp extraction folder)
                    
                    string rulesDir = null;
                    string exeDir = null;
                    string[] searchPaths = new string[4];
                    
                    // Try the actual exe location first (most reliable for single-file)
                    try
                    {
                        string exePath = Environment.ProcessPath;
                        if (!string.IsNullOrEmpty(exePath))
                        {
                            exeDir = Path.GetDirectoryName(exePath);
                            searchPaths[0] = exeDir;
                            rulesDir = Path.Combine(exeDir, "SnaffRules", "DefaultRules");
                        }
                    }
                    catch { }
                    
                    // If not found, try Process.MainModule.FileName
                    if (rulesDir == null || !Directory.Exists(rulesDir))
                    {
                        try
                        {
                            exeDir = Path.GetDirectoryName(System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName);
                            searchPaths[1] = exeDir;
                            rulesDir = Path.Combine(exeDir, "SnaffRules", "DefaultRules");
                        }
                        catch { }
                    }
                    
                    // If not found, try current working directory
                    if (rulesDir == null || !Directory.Exists(rulesDir))
                    {
                        exeDir = Directory.GetCurrentDirectory();
                        searchPaths[2] = exeDir;
                        rulesDir = Path.Combine(exeDir, "SnaffRules", "DefaultRules");
                    }
                    
                    // If still not found, try AppContext.BaseDirectory
                    if (!Directory.Exists(rulesDir))
                    {
                        exeDir = AppContext.BaseDirectory;
                        searchPaths[3] = exeDir;
                        rulesDir = Path.Combine(exeDir, "SnaffRules", "DefaultRules");
                    }
                    
                    if (Directory.Exists(rulesDir) && String.IsNullOrWhiteSpace(parsedConfig.RuleDir))
                    {
                        Console.WriteLine($"[Info] Loading rules from: {rulesDir}");
                        string[] tomlfiles = Directory.GetFiles(rulesDir, "*.toml", SearchOption.AllDirectories);
                        Console.WriteLine($"[Info] Found {tomlfiles.Length} .toml files in rules directory");
                        
                        if (tomlfiles.Length == 0)
                        {
                            Console.WriteLine("[WARNING] Rules directory exists but contains no .toml files!");
                        }
                        else
                        {
                            StringBuilder sb = new StringBuilder();
                            foreach (string tomlfile in tomlfiles)
                            {
                                string tomlstring = File.ReadAllText(tomlfile);
                                sb.AppendLine(tomlstring);
                            }
                            string bulktoml = sb.ToString();
                            // deserialise the toml to an actual ruleset
                            RuleSet ruleSet = Toml.ReadString<RuleSet>(bulktoml, settings);
                            parsedConfig.ClassifierRules = ruleSet.ClassifierRules;
                            Console.WriteLine($"[Info] Loaded {parsedConfig.ClassifierRules.Count} rules from external directory");
                        }
                    }
                    else if (!String.IsNullOrWhiteSpace(parsedConfig.RuleDir))
                    {
                        // User specified custom rules directory with -p flag
                        Console.WriteLine($"[Info] Loading rules from user-specified directory: {parsedConfig.RuleDir}");
                        string[] tomlfiles = Directory.GetFiles(parsedConfig.RuleDir, "*.toml", SearchOption.AllDirectories);
                        Console.WriteLine($"[Info] Found {tomlfiles.Length} .toml files");
                        
                        StringBuilder sb = new StringBuilder();
                        foreach (string tomlfile in tomlfiles)
                        {
                            string tomlstring = File.ReadAllText(tomlfile);
                            sb.AppendLine(tomlstring);
                        }
                        string bulktoml = sb.ToString();
                        // deserialise the toml to an actual ruleset
                        RuleSet ruleSet = Toml.ReadString<RuleSet>(bulktoml, settings);
                        parsedConfig.ClassifierRules = ruleSet.ClassifierRules;
                        Console.WriteLine($"[Info] Loaded {parsedConfig.ClassifierRules.Count} rules from custom directory");
                    }
                    else
                    {
                        // Fall back to embedded resources
                        Console.WriteLine("[Info] Loading embedded rules from assembly resources");
                        string[] resourceNames = Assembly.GetExecutingAssembly().GetManifestResourceNames();
                        Console.WriteLine($"[Info] Found {resourceNames.Length} embedded resources");
                        
                        StringBuilder sb = new StringBuilder();
                        int tomlCount = 0;

                        foreach (string resourceName in resourceNames)
                        {
                            if (!resourceName.EndsWith(".toml"))
                            {
                                // skip this one as it's just metadata
                                continue;
                            }
                            tomlCount++;
                            string ruleFile = ReadResource(resourceName);
                            sb.AppendLine(ruleFile);
                        }

                        Console.WriteLine($"[Info] Found {tomlCount} embedded .toml resources");
                        
                        if (tomlCount == 0)
                        {
                            Console.WriteLine("[ERROR] No embedded resources found and no external rules directory!");
                            Console.WriteLine($"[ERROR] Expected rules at: {rulesDir}");
                            Console.WriteLine("[ERROR] Either rebuild with embedded resources or place rules in SnaffRules/DefaultRules/");
                            throw new Exception("No classification rules could be loaded!");
                        }

                        string bulktoml = sb.ToString();

                        // deserialise the toml to an actual ruleset
                        RuleSet ruleSet = Toml.ReadString<RuleSet>(bulktoml, settings);

                        // stick the rules in our config!
                        parsedConfig.ClassifierRules = ruleSet.ClassifierRules;
                        Console.WriteLine($"[Info] Loaded {parsedConfig.ClassifierRules.Count} rules from embedded resources");
                    }
                }

                parsedConfig.PrepareClassifiers();
            }
            catch (Exception e)
            {
                Mq.Error(e.ToString());
                throw;
            }

            return parsedConfig;
        }

        private static void TestCredentialExtraction(string filePath)
        {
            Console.WriteLine("====================================");
            Console.WriteLine("CREDENTIAL EXTRACTION TEST MODE");
            Console.WriteLine("====================================");
            Console.WriteLine($"File: {filePath}\n");

            if (!File.Exists(filePath))
            {
                Console.WriteLine($"ERROR: File not found: {filePath}");
                return;
            }

            // Read file content using appropriate parser
            string content = "";
            try
            {
                if (filePath.EndsWith(".xls", StringComparison.OrdinalIgnoreCase))
                {
                    // Use Toxy for XLS files
                    var context = new Toxy.ParserContext(filePath);
                    var parser = Toxy.ParserFactory.CreateText(context);
                    content = parser.Parse() ?? "";
                    Console.WriteLine($"Content parsed via Toxy (XLS): {content.Length} chars\n");
                }
                else if (filePath.EndsWith(".xlsx", StringComparison.OrdinalIgnoreCase))
                {
                    // Use ClosedXML for XLSX files
                    try
                    {
                        using (var workbook = new ClosedXML.Excel.XLWorkbook(filePath))
                        {
                            var sb = new StringBuilder();
                            foreach (var worksheet in workbook.Worksheets)
                            {
                                foreach (var row in worksheet.RowsUsed())
                                {
                                    foreach (var cell in row.CellsUsed())
                                    {
                                        sb.Append(cell.Value.ToString());
                                        sb.Append("\t");
                                    }
                                    sb.AppendLine();
                                }
                            }
                            content = sb.ToString();
                        }
                        Console.WriteLine($"Content parsed via ClosedXML (XLSX): {content.Length} chars\n");
                    }
                    catch
                    {
                        Console.WriteLine("XLSX file may be encrypted/password-protected\n");
                        return;
                    }
                }
                else
                {
                    content = File.ReadAllText(filePath, Encoding.Default);
                    Console.WriteLine($"Content read as text: {content.Length} chars\n");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR reading file: {ex.Message}\n");
                return;
            }

            Console.WriteLine("Content preview (first 500 chars):");
            string preview = content.Length > 500 ? content.Substring(0, 500) : content;
            // Replace non-printable chars
            preview = System.Text.RegularExpressions.Regex.Replace(preview, @"[^\x20-\x7E\t\n\r]", ".");
            Console.WriteLine(preview);
            Console.WriteLine();

            // Test extraction methods
            Console.WriteLine("Testing extraction methods:\n");

            // Method 1: Table extraction (tab-delimited)
            Console.WriteLine("1. TABLE EXTRACTION (Tab-delimited):");
            TestTableExtraction(content, useSimpleTable: false);

            // Method 2: Simple table extraction
            Console.WriteLine("\n2. SIMPLE TABLE EXTRACTION:");
            TestTableExtraction(content, useSimpleTable: true);

            // Method 3: XML tag extraction
            Console.WriteLine("\n3. XML TAG EXTRACTION:");
            TestXmlExtraction(content);

            // Method 4: Regex extraction
            Console.WriteLine("\n4. REGEX EXTRACTION:");
            TestRegexExtraction(content);
            
            // Method 5: Direct test of single-line extraction
            Console.WriteLine("\n5. SINGLE-LINE EXTRACTION TEST:");
            TestSingleLineExtraction(content);

            Console.WriteLine("\n====================================");
            Console.WriteLine("TEST COMPLETE");
            Console.WriteLine("====================================");
        }

        private static void TestSingleLineExtraction(string content)
        {
            try
            {
                // Simulate what ExtractFromSimpleTable does for single-line content
                var match = System.Text.RegularExpressions.Regex.Match(content, @"(?:password|pwd|pass)\s+(.+)$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (match.Success)
                {
                    string dataSection = match.Groups[1].Value.Trim();
                    Console.WriteLine($"   Captured after 'password': {dataSection}");
                    
                    // Split by BOTH space and tab
                    var parts = dataSection.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    Console.WriteLine($"   Parts count: {parts.Length}");
                    Console.WriteLine($"   Parts: [{string.Join("], [", parts)}]");
                    
                    if (parts.Length >= 3)
                    {
                        string service = string.Join(" ", parts.Take(parts.Length - 2));
                        string username = parts[parts.Length - 2];
                        string password = parts[parts.Length - 1];
                        
                        Console.WriteLine($"   EXTRACTED:");
                        Console.WriteLine($"     Service:  {service}");
                        Console.WriteLine($"     Username: {username}");
                        Console.WriteLine($"     Password: {password}");
                        Console.WriteLine("   RESULT: ✓ Would extract credentials");
                    }
                    else
                    {
                        Console.WriteLine("   RESULT: ✗ Not enough parts after splitting");
                    }
                }
                else
                {
                    Console.WriteLine("   RESULT: ✗ No password keyword match");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   RESULT: ERROR - {ex.Message}");
            }
        }

        private static void TestTableExtraction(string content, bool useSimpleTable)
        {
            try
            {
                bool hasTab = content.Contains("\t");
                bool hasNewline = content.Contains("\n");
                Console.WriteLine($"   Has tabs: {hasTab}");
                Console.WriteLine($"   Has newlines: {hasNewline}");

                if (!hasNewline)
                {
                    Console.WriteLine("   RESULT: SKIPPED (no newlines)");
                    return;
                }

                string[] lines = content.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                Console.WriteLine($"   Lines: {lines.Length}");

                if (useSimpleTable)
                {
                    if (!hasTab && lines.Length >= 1 && lines.Length <= 3)
                    {
                        Console.WriteLine("   Attempting simple table extraction...");
                        Console.WriteLine($"   Line 1: {lines[0]}");
                        
                        // Simulate simple table extraction logic
                        bool hasUserKeyword = System.Text.RegularExpressions.Regex.IsMatch(string.Join(" ", lines).ToLower(), @"(username|user)");
                        bool hasPassKeyword = System.Text.RegularExpressions.Regex.IsMatch(string.Join(" ", lines).ToLower(), @"(password|pwd|pass)");
                        
                        Console.WriteLine($"   Has username keyword: {hasUserKeyword}");
                        Console.WriteLine($"   Has password keyword: {hasPassKeyword}");
                        
                        if (hasUserKeyword && hasPassKeyword)
                        {
                            Console.WriteLine("   RESULT: ✓ Keywords found - would attempt extraction");
                        }
                        else
                        {
                            Console.WriteLine("   RESULT: ✗ Missing keywords");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"   RESULT: SKIPPED (has tabs or wrong line count)");
                    }
                }
                else
                {
                    if (!hasTab)
                    {
                        Console.WriteLine("   RESULT: SKIPPED (no tabs)");
                    }
                    else
                    {
                        Console.WriteLine("   Attempting tab-delimited extraction...");
                        
                        // Find header row
                        int headerIndex = -1;
                        string[] headers = null;
                        for (int i = 0; i < Math.Min(lines.Length, 10); i++)
                        {
                            string[] potentialHeaders = lines[i].Split('\t');
                            Console.WriteLine($"   Line {i}: [{string.Join("], [", potentialHeaders)}]");
                            
                            bool hasUserKeyword = potentialHeaders.Any(h => 
                                System.Text.RegularExpressions.Regex.IsMatch(h ?? "", @"(?i)(identifiant|login|username|utilisateur|user|compte|email|admin)"));
                            bool hasPassKeyword = potentialHeaders.Any(h => 
                                System.Text.RegularExpressions.Regex.IsMatch(h ?? "", @"(?i)(mdp|password|pwd|mot.*passe|pass)"));
                            
                            if (hasUserKeyword && hasPassKeyword) 
                            { 
                                headerIndex = i; 
                                headers = potentialHeaders; 
                                Console.WriteLine($"   HEADER FOUND at line {i}");
                                break; 
                            }
                        }
                        
                        if (headerIndex == -1)
                        {
                            Console.WriteLine("   RESULT: ✗ No header row with both username and password keywords");
                            return;
                        }
                        
                        // Find column indices
                        int userColIndex = -1, passColIndex = -1, serviceColIndex = -1;
                        for (int i = 0; i < headers.Length; i++)
                        {
                            string header = headers[i]?.Trim()?.ToLower() ?? "";
                            if (userColIndex == -1 && System.Text.RegularExpressions.Regex.IsMatch(header, @"(identifiant|login|username|utilisateur|user|compte|email|admin)")) userColIndex = i;
                            if (passColIndex == -1 && System.Text.RegularExpressions.Regex.IsMatch(header, @"(mdp|password|pwd|mot.*passe|pass)")) passColIndex = i;
                            if (serviceColIndex == -1 && System.Text.RegularExpressions.Regex.IsMatch(header, @"(nom|name|service|site|fournisseur|type)")) serviceColIndex = i;
                        }
                        
                        Console.WriteLine($"   Column indices: service={serviceColIndex}, user={userColIndex}, pass={passColIndex}");
                        
                        if (userColIndex == -1 || passColIndex == -1)
                        {
                            Console.WriteLine("   RESULT: ✗ Could not find username or password column");
                            return;
                        }
                        
                        // Extract from data rows
                        int extracted = 0;
                        for (int i = headerIndex + 1; i < lines.Length; i++)
                        {
                            string[] cells = lines[i].Split('\t');
                            Console.WriteLine($"   Data row {i}: [{string.Join("], [", cells)}]");
                            
                            int maxCol = Math.Max(userColIndex, passColIndex);
                            if (cells.Length > maxCol)
                            {
                                string user = cells[userColIndex]?.Trim() ?? "";
                                string pass = cells[passColIndex]?.Trim() ?? "";
                                string service = serviceColIndex >= 0 && cells.Length > serviceColIndex ? cells[serviceColIndex]?.Trim() ?? "" : "";
                                
                                Console.WriteLine($"   EXTRACTED: Service=[{service}], User=[{user}], Pass=[{pass}]");
                                extracted++;
                            }
                        }
                        
                        Console.WriteLine($"   RESULT: ✓ Extracted {extracted} credential(s)");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   RESULT: ERROR - {ex.Message}");
            }
        }

        private static void TestXmlExtraction(string content)
        {
            try
            {
                var pattern = new System.Text.RegularExpressions.Regex(@"<([^>]*\.)?(?<tagname>(?:ftp|smtp|excel|mail|db|sql|ldap|ssh|sftp)[._-]?(?:password|pwd))[^>]*>\s*(?<password>[^<]{3,}?)\s*</", 
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                var matches = pattern.Matches(content);
                Console.WriteLine($"   XML password tags found: {matches.Count}");
                if (matches.Count > 0)
                {
                    Console.WriteLine("   RESULT: ✓ Would extract XML credentials");
                }
                else
                {
                    Console.WriteLine("   RESULT: ✗ No XML tags found");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   RESULT: ERROR - {ex.Message}");
            }
        }

        private static void TestRegexExtraction(string content)
        {
            try
            {
                var pwdPattern = new System.Text.RegularExpressions.Regex(@"(?i)(password|pwd|mdp|mot.?de.?passe)[\s:=\t""']+([^\s\t\n\r""']{4,50})");
                var matches = pwdPattern.Matches(content);
                Console.WriteLine($"   Password patterns found: {matches.Count}");
                if (matches.Count > 0)
                {
                    Console.WriteLine("   RESULT: ✓ Would extract via regex");
                }
                else
                {
                    Console.WriteLine("   RESULT: ✗ No regex matches");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   RESULT: ERROR - {ex.Message}");
            }
        }
    }
}
