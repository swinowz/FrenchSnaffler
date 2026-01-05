using System;
using System.IO;

namespace ShareAuditor
{
    public static class ShareAuditor
    {
        public static void Main(string[] args)
        {
            // Redirect console output to out.txt file
            var fileStream = new FileStream("out.txt", FileMode.Create, FileAccess.Write, FileShare.Read);
            var streamWriter = new StreamWriter(fileStream);
            streamWriter.AutoFlush = true;
            Console.SetOut(streamWriter);
            
            AuditorRunner runner = new AuditorRunner();
            runner.Run(args);
            Console.WriteLine("ShareAuditor scan complete.");
            
            streamWriter.Close();
            fileStream.Close();
        }
    }
}