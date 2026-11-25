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
                    bool scanDir = true;
                    foreach (ClassifierRule classifier in MyOptions.DirClassifiers)
                    {
                        try
                        {
                            DirClassifier dirClassifier = new DirClassifier(classifier);
                            DirResult dirResult = dirClassifier.ClassifyDir(dirStr);

                            if (dirResult.ScanDir == false)
                            {
                                scanDir = false;
                                break;
                            }
                        }
                        catch (Exception e)
                        {
                            Mq.Trace(e.ToString());
                            continue;
                        }
                    }
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
    }
}