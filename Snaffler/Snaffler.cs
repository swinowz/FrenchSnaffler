using System;
using System.IO;

namespace ShareAuditor
{
    public static class ShareAuditor
    {
        public static void Main(string[] args)
        {
            AuditorRunner runner = new AuditorRunner();
            runner.Run(args);
            Console.WriteLine("ShareAuditor scan complete.");
        }
    }
}