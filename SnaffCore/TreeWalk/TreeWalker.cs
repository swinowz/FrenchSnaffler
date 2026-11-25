using SnaffCore.Classifiers;
using SnaffCore.Concurrency;
using SnaffCore.FileScan;
using System;
using System.IO;
using static SnaffCore.Config.Options;

namespace SnaffCore.TreeWalk
{
    public class TreeWalker
    {
        private BlockingMq Mq { get; set; }
        private BlockingStaticTaskScheduler FileTaskScheduler { get; set; }
        private BlockingStaticTaskScheduler TreeTaskScheduler { get; set; }
        private FileScanner FileScanner { get; set; }

        public TreeWalker()
        {
            Mq = BlockingMq.GetMq();

            FileTaskScheduler = SnaffCon.GetFileTaskScheduler();
            TreeTaskScheduler = SnaffCon.GetTreeTaskScheduler();
            FileScanner = SnaffCon.GetFileScanner();
        }

        public void WalkTree(string currentDir)
        {
             // Walks a tree checking files and generating results as it goes.
             
             if (!Directory.Exists(currentDir))
             {
                 return;
             }

            // SCCM content library: scan DataLib entries under their real names
            // instead of the hash-named FileLib files.
            if (SccmContentLib.IsContentLibRoot(currentDir))
            {
                Mq.Info("SCCM content library found, resolving DataLib names: " + currentDir);
                WalkSccmDataLib(Path.Combine(currentDir, "DataLib"), currentDir);
                return;
            }

            // Direct directory enumeration - no timeout (let the OS handle it)
            string[] files = null;
            string[] subDirs = null;
            
            try
            {
                files = Directory.GetFiles(currentDir);
            }
            catch (UnauthorizedAccessException) { }
            catch (DirectoryNotFoundException) { }
            catch (IOException) { }
            catch (Exception e)
            {
                Mq.Trace(e.ToString());
            }

            // Queue files for scanning
            if (files != null)
            {
                foreach (string file in files)
                {
                    FileTaskScheduler.New(() =>
                    {
                        try
                        {
                            FileScanner.ScanFile(file);
                        }
                        catch (Exception e)
                        {
                            Mq.Error("Exception in FileScanner task for file " + file);
                            Mq.Trace(e.ToString());
                        }
                    });
                }
            }

            try
            {
                subDirs = Directory.GetDirectories(currentDir);
            }
            catch (UnauthorizedAccessException) { }
            catch (DirectoryNotFoundException) { }
            catch (IOException) { }
            catch (Exception e)
            {
                Mq.Trace(e.ToString());
            }

            // Queue subdirectories for walking
            if (subDirs != null && subDirs.Length >= 1)
            {
                foreach (string dirStr in subDirs)
                {
                    bool scanDir = ShouldScanDir(dirStr);
                    if (scanDir == true)
                    {
                        TreeTaskScheduler.New(() =>
                        {
                            try
                            {
                                WalkTree(dirStr);
                            }
                            catch (Exception e)
                            {
                                Mq.Error("Exception in TreeWalker task for dir " + dirStr);
                                Mq.Error(e.ToString());
                            }
                        });
                    }
                    else
                    {
                        Mq.Trace("Skipped scanning on " + dirStr + " due to Discard rule match.");
                    }
                }
            }
        }

        private bool ShouldScanDir(string dirStr)
        {
            foreach (ClassifierRule classifier in MyOptions.DirClassifiers)
            {
                try
                {
                    DirResult dirResult = new DirClassifier(classifier).ClassifyDir(dirStr);
                    if (dirResult.ScanDir == false) return false;
                }
                catch (Exception e)
                {
                    Mq.Trace(e.ToString());
                }
            }
            return true;
        }

        private void WalkSccmDataLib(string currentDir, string libRoot)
        {
            string[] files = null;
            string[] subDirs = null;
            try { files = Directory.GetFiles(currentDir, "*.INI"); }
            catch (Exception e) when (e is UnauthorizedAccessException || e is IOException) { }
            catch (Exception e) { Mq.Trace(e.ToString()); }

            if (files != null)
            {
                foreach (string ini in files)
                {
                    FileTaskScheduler.New(() =>
                    {
                        try { SccmContentLib.ScanDataLibEntry(ini, libRoot, FileScanner); }
                        catch (Exception e)
                        {
                            Mq.Error("Exception in SCCM DataLib task for " + ini);
                            Mq.Trace(e.ToString());
                        }
                    });
                }
            }

            try { subDirs = Directory.GetDirectories(currentDir); }
            catch (Exception e) when (e is UnauthorizedAccessException || e is IOException) { }
            catch (Exception e) { Mq.Trace(e.ToString()); }

            if (subDirs == null) return;
            foreach (string dirStr in subDirs)
            {
                if (!ShouldScanDir(dirStr))
                {
                    Mq.Trace("Skipped scanning on " + dirStr + " due to Discard rule match.");
                    continue;
                }
                TreeTaskScheduler.New(() =>
                {
                    try { WalkSccmDataLib(dirStr, libRoot); }
                    catch (Exception e)
                    {
                        Mq.Error("Exception in SCCM DataLib walker for dir " + dirStr);
                        Mq.Error(e.ToString());
                    }
                });
            }
        }
    }
}