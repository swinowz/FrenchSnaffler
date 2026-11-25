using SnaffCore.Concurrency;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static SnaffCore.Config.Options;
using SnaffCore.Classifiers.EffectiveAccess;

namespace SnaffCore.Classifiers
{
    public class FileClassifier
    {
        private ClassifierRule ClassifierRule { get; set; }

        public FileClassifier(ClassifierRule inRule)
        {
            this.ClassifierRule = inRule;
        }

        // Cache nom -> regle : evite un scan lineaire .First() sur TOUTES les regles,
        // pour chaque relais, pour chaque fichier (point chaud a l'echelle entreprise).
        private static System.Collections.Generic.Dictionary<string, ClassifierRule> _rulesByName;
        private static readonly object _rulesByNameLock = new object();
        private static ClassifierRule GetRuleByName(string name)
        {
            if (_rulesByName == null)
            {
                lock (_rulesByNameLock)
                {
                    if (_rulesByName == null)
                    {
                        var d = new System.Collections.Generic.Dictionary<string, ClassifierRule>();
                        foreach (var r in MyOptions.ClassifierRules) d[r.RuleName] = r;
                        _rulesByName = d;
                    }
                }
            }
            return _rulesByName.TryGetValue(name, out var rule)
                ? rule
                : MyOptions.ClassifierRules.First(thing => thing.RuleName == name);
        }

        public bool ClassifyFile(FileInfo fileInfo)
        {
            BlockingMq Mq = BlockingMq.GetMq();
            // figure out what part we gonna look at
            string stringToMatch = null;

            switch (ClassifierRule.MatchLocation)
            {
                case MatchLoc.FileExtension:
                    stringToMatch = fileInfo.Extension;
                    // special handling to treat files named like 'thing.kdbx.bak'
                    if (stringToMatch == ".bak")
                    {
                        // strip off .bak
                        string subName = fileInfo.Name.Replace(".bak", "");
                        stringToMatch = Path.GetExtension(subName);
                        // if this results in no file extension, put it back.
                        if (stringToMatch == "")
                        {
                            stringToMatch = ".bak";
                        }
                    }
                    // this is insane that i have to do this but apparently files with no extension return
                    // this bullshit
                    if (stringToMatch == "")
                    {
                        return false;
                    }
                    break;
                case MatchLoc.FileName:
                    stringToMatch = fileInfo.Name;
                    break;
                case MatchLoc.FilePath:
                    stringToMatch = fileInfo.FullName;
                    break;
                case MatchLoc.FileLength:
                    if (!SizeMatch(fileInfo))
                    {
                        return false;
                    }
                    else break;
                default:
                    Mq.Error("You've got a misconfigured file classifier rule named " + ClassifierRule.RuleName + ".");
                    return false;
            }

            TextResult textResult = null;

            if (!String.IsNullOrEmpty(stringToMatch))
            {
                TextClassifier textClassifier = new TextClassifier(ClassifierRule);
                // check if it matches
                textResult = textClassifier.TextMatch(stringToMatch);
                
                if (textResult == null)
                {
                    // if it doesn't we just bail now.
                    return false;
                }
            }

            FileResult fileResult;
            // if it matches, see what we're gonna do with it
            switch (ClassifierRule.MatchAction)
            {
                case MatchAction.Discard:
                    // chuck it.
                    return true;
                case MatchAction.Snaffle:

                    if (MyOptions.PostMatchClassifiers.Count >= 1)
                    {
                        foreach (ClassifierRule rule in MyOptions.PostMatchClassifiers)
                        {
                            PostMatchClassifier pmClassifier = new PostMatchClassifier(rule);
                            if (pmClassifier.ClassifyPostMatch(fileInfo))
                            {
                                // only support discard rules for PostMatch, so anything that returns true means we bail out.
                                return true;
                            }
                        }
                    }

                    // we've passed the final postmatch test, so let's snaffle that bad boy
                    fileResult = new FileResult(fileInfo)
                    {
                        MatchedRule = ClassifierRule,
                        TextResult = textResult
                    };
                    // if the file was list-only, don't bother sending a result back to the user.
                    if (!fileResult.RwStatus.CanRead && !fileResult.RwStatus.CanModify && !fileResult.RwStatus.CanWrite) { return false; };
                    Mq.FileResult(fileResult);
                    return false;
                case MatchAction.CheckForKeys:
                    // do a special x509 dance
                    List<string> x509MatchReason = x509Match(fileInfo);
                    if (x509MatchReason.Count > 0)
                    {
                        // if there were any matchreasons, cat them together...
                        string matchContext = String.Join(",", x509MatchReason);
                        // and sling the results on the queue
                        fileResult = new FileResult(fileInfo)
                        {
                            MatchedRule = ClassifierRule,
                            TextResult = new TextResult()
                            {
                                MatchContext = matchContext,
                                MatchedStrings = new List<string>() { "" }
                            }
                        };

                        if (!fileResult.RwStatus.CanRead && !fileResult.RwStatus.CanModify && !fileResult.RwStatus.CanWrite) { return false; };

                        Mq.FileResult(fileResult);
                    }
                    return false;
                case MatchAction.Relay:
                    // Optimized relay processing: batch content reads for all content-based relay targets
                    try
                    {
                        bool fLoggedContentSizeWarning = false;
                        
                        // Separate relay targets by enumeration scope
                        var contentTargets = new List<ClassifierRule>();
                        var fileTargets = new List<string>();
                        
                        foreach (string relayTarget in ClassifierRule.RelayTargets)
                        {
                            ClassifierRule nextRule = GetRuleByName(relayTarget);

                            if (nextRule.EnumerationScope == EnumerationScope.ContentsEnumeration)
                            {
                                if (fileInfo.Length > MyOptions.MaxSizeToGrep)
                                {
                                    if(!fLoggedContentSizeWarning)
                                    {
                                        Mq.Trace("The following file was bigger than the MaxSizeToGrep config parameter:" + fileInfo.FullName);
                                        fLoggedContentSizeWarning = true;
                                    }
                                    continue;
                                }
                                
                                contentTargets.Add(nextRule);
                            }
                            else if (nextRule.EnumerationScope == EnumerationScope.FileEnumeration)
                            {
                                fileTargets.Add(relayTarget);
                            }
                            else
                            {
                                Mq.Error("You've got a misconfigured file ClassifierRule named " + ClassifierRule.RuleName + ".");
                            }
                        }
                        
                        // Batch process all content targets with a single file read
                        if (contentTargets.Any())
                        {
                            ContentBatchClassifier batchClassifier = new ContentBatchClassifier();
                            batchClassifier.ClassifyContentBatch(fileInfo, contentTargets);
                        }
                        
                        // Process file-based targets normally
                        foreach (string fileTarget in fileTargets)
                        {
                            ClassifierRule nextRule = GetRuleByName(fileTarget);
                            FileClassifier nextFileClassifier = new FileClassifier(nextRule);
                            nextFileClassifier.ClassifyFile(fileInfo);
                        }
                        
                        return false;
                    }
                    catch (IOException e)
                    {
                        Mq.Trace(e.ToString());
                    }
                    catch (Exception e)
                    {
                        Mq.Error("You've got a misconfigured file ClassifierRule named " + ClassifierRule.RuleName + ".");
                        Mq.Trace(e.ToString());
                    }
                    return false;
                case MatchAction.EnterArchive:
                    // do a special looking inside archive files dance using
                    // https://github.com/adamhathcock/sharpcompress
                    ArchiveClassifier.Scan(fileInfo);
                    return false;
                default:
                    Mq.Error("You've got a misconfigured file ClassifierRule named " + ClassifierRule.RuleName + ".");
                    return false;
            }
        }
        public bool SizeMatch(FileInfo fileInfo)
        {
            if (this.ClassifierRule.MatchLength == fileInfo.Length)
            {
                return true;
            }
            return false;
        }

        // Returns null when the file holds no certificate. Throws CryptographicException
        // only when a password is needed (or the given one is wrong), which drives the
        // password guessing in x509Match. Keys are ephemeral: nothing is written to the
        // machine key store, so no temp copy or key container cleanup is needed.
        private const long MaxCertFileBytes = 10 * 1024 * 1024;

        public X509Certificate2 parseCert(string certPath, string password = null)
        {
            if (new FileInfo(certPath).Length > MaxCertFileBytes) return null;
            byte[] data = File.ReadAllBytes(certPath);

            if (LooksLikePem(data))
            {
                string pem = Encoding.UTF8.GetString(data);
                bool hasCert = pem.Contains("-----BEGIN CERTIFICATE-----");
                bool hasKey = pem.Contains("PRIVATE KEY-----");
                bool encryptedKey = pem.Contains("-----BEGIN ENCRYPTED PRIVATE KEY-----");
                if (!hasCert) return null;
                X509Certificate2 publicOnly = X509Certificate2.CreateFromPem(pem);
                if (!hasKey) return publicOnly;
                if (encryptedKey)
                {
                    if (password == null) throw new CryptographicException("Encrypted private key requires a password");
                    publicOnly.Dispose();
                    return X509Certificate2.CreateFromEncryptedPem(pem, pem, password);
                }
                try
                {
                    X509Certificate2 withKey = X509Certificate2.CreateFromPem(pem, pem);
                    publicOnly.Dispose();
                    return withKey;
                }
                catch (CryptographicException)
                {
                    // key present but unreadable or not matching the certificate
                    return publicOnly;
                }
            }

            switch (X509Certificate2.GetCertContentType(data))
            {
                case X509ContentType.Pfx:
                    return X509CertificateLoader.LoadPkcs12(data, password, X509KeyStorageFlags.EphemeralKeySet);
                case X509ContentType.Cert:
                    return X509CertificateLoader.LoadCertificate(data);
                default:
                    return null;
            }
        }

        // PEM private key without certificate (key.pem, server.pem): a secret on its own.
        private static bool IsBarePemPrivateKey(string certPath)
        {
            try
            {
                if (new FileInfo(certPath).Length > MaxCertFileBytes) return false;
                byte[] data = File.ReadAllBytes(certPath);
                if (!LooksLikePem(data)) return false;
                string pem = Encoding.UTF8.GetString(data);
                return pem.Contains("PRIVATE KEY-----") && !pem.Contains("-----BEGIN CERTIFICATE-----");
            }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
        }

        private static bool LooksLikePem(byte[] data)
        {
            int limit = Math.Min(data.Length, 4096);
            for (int i = 0; i + 10 < limit; i++)
                if (data[i] == '-' && data[i + 1] == '-' && data[i + 2] == '-' && data[i + 3] == '-' && data[i + 4] == '-' &&
                    data[i + 5] == 'B' && data[i + 6] == 'E' && data[i + 7] == 'G' && data[i + 8] == 'I' && data[i + 9] == 'N')
                    return true;
            return false;
        }

        public List<string> x509Match(FileInfo fileInfo)
        {
            BlockingMq Mq = BlockingMq.GetMq();
            string certPath = fileInfo.FullName;
            List<string> matchReasons = new List<string>();
            X509Certificate2 parsedCert = null;
            bool nopwrequired = false;

            // TODO - handle if there is no private key, strip out unnecessary stuff from Certificate.cs, make work with pfx style stuff below

            try
            {
                // try to parse it, it'll throw if it needs a password
                parsedCert = parseCert(certPath);

                // if it parses we know we didn't need a password
                nopwrequired = parsedCert != null;
                if (parsedCert == null && IsBarePemPrivateKey(certPath))
                {
                    matchReasons.Add("HasPrivateKey");
                    matchReasons.Add("PrivateKeyWithoutCertificate");
                }
            }
            catch (CryptographicException e)
            {
                // if it doesn't parse that almost certainly means we need a password
                Mq.Trace(e.ToString());

                // build the list of passwords to try including the filename
                // COPIE : ne pas aliaser/faire grossir la liste globale MyOptions.CertPasswords (fuite + O(n^2))
                List<string> passwords = new List<string>(MyOptions.CertPasswords);
                passwords.Add(Path.GetFileNameWithoutExtension(fileInfo.Name));

                // try each of our very obvious passwords
                foreach (string password in passwords)
                {
                    try
                    {
                        parsedCert = parseCert(certPath, password);
                        if (parsedCert == null) continue;
                        if (password == "")
                        {
                            matchReasons.Add("PasswordBlank");
                        }
                        else
                        {
                            matchReasons.Add("PasswordCracked: " + password);
                        }
                        break;
                    }
                    catch (CryptographicException ee)
                    {
                        Mq.Trace("Password " + password + " invalid for cert file " + fileInfo.FullName + " " + ee.ToString());
                    }
                }
                if (matchReasons.Count == 0) 
                {
                    matchReasons.Add("HasPassword");
                    matchReasons.Add("LookNearbyFor.txtFiles");
                }
            }
            catch (Exception e)
            {
                Mq.Error("Unhandled exception parsing cert: " + fileInfo.FullName + " " + e.ToString());
            }

            if (parsedCert != null)
            {
                // check if it includes a private key, if not, who cares?
                if (parsedCert.HasPrivateKey)
                {
                    matchReasons.Add("HasPrivateKey");

                    if (nopwrequired) { matchReasons.Add("NoPasswordRequired"); }

                    matchReasons.Add("Subject:" + parsedCert.Subject);

                    // take a look at the extensions
                    X509ExtensionCollection extensions = parsedCert.Extensions;

                    // this feels dumb but whatever
                    foreach (X509Extension extension in extensions)
                    {
                        AsnEncodedData asndata = new AsnEncodedData(extension.Oid, extension.RawData);
                        string asndataString = asndata.Format(false);
                        if (extension.Oid.FriendlyName == "Basic Constraints")
                        {
                            if (asndataString.Contains("Subject Type=CA"))
                            {
                                matchReasons.Add("IsCACert");
                            }
                        }
                        if (extension.GetType() == typeof(X509KeyUsageExtension))
                        {
                            matchReasons.Add((extension as X509KeyUsageExtension).KeyUsages.ToString());
                        }
                        if (extension.GetType() == typeof(X509EnhancedKeyUsageExtension))
                        {
                            List<string> ekus = new List<string>();

                            X509EnhancedKeyUsageExtension ekuExtension = (X509EnhancedKeyUsageExtension)extension;
                            foreach (Oid eku in ekuExtension.EnhancedKeyUsages)
                            {
                                ekus.Add(eku.FriendlyName);
                            }
                            // include the EKUs in the info we're passing to the user
                            string ekustring = String.Join("|", ekus);
                            matchReasons.Add(ekustring);
                        };
                        if (extension.Oid.FriendlyName == "Subject Alternative Name")
                        {
                            byte[] sanbytes = extension.RawData;
                            string san = Encoding.UTF8.GetString(sanbytes, 0, sanbytes.Length);
                            matchReasons.Add(asndataString);
                        }
                    }

                    matchReasons.Add("Expiry:" + parsedCert.GetExpirationDateString());
                    matchReasons.Add("Issuer:" + parsedCert.Issuer);
                }
            }
            return matchReasons;
        }
    }
}
