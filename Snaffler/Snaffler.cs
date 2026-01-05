using System;
using System.IO;

namespace Snaffler
{
    public static class Snaffler
    {
        public static void Main(string[] args)
        {
            // Redirect console output to out.txt file
            var fileStream = new FileStream("out.txt", FileMode.Create, FileAccess.Write, FileShare.Read);
            var streamWriter = new StreamWriter(fileStream);
            streamWriter.AutoFlush = true;
            Console.SetOut(streamWriter);
            
            SnaffleRunner runner = new SnaffleRunner();
            runner.Run(args);
            Console.WriteLine("I snaffled 'til the snafflin was done.");
            
            streamWriter.Close();
            fileStream.Close();
        }
    }
}