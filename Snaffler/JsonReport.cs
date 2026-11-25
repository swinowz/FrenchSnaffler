using System;
using System.IO;

namespace ShareAuditor
{
    internal static class JsonReport
    {
        internal static void Normalize(string path)
        {
            if (!File.Exists(path)) return;

            string temporaryPath = Path.GetFullPath(path) + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                var streamOptions = new FileStreamOptions
                {
                    Mode = FileMode.CreateNew,
                    Access = FileAccess.Write
                };
                if (!OperatingSystem.IsWindows())
                    streamOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

                using (var writer = new StreamWriter(temporaryPath, streamOptions))
                {
                    writer.Write("{\"entries\": [\n");
                    bool first = true;
                    foreach (string line in File.ReadLines(path))
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        if (!first) writer.WriteLine(",");
                        writer.Write(line);
                        first = false;
                    }
                    writer.Write("\n]\n}");
                }

                // Keep the source journal intact until its replacement has been written.
                File.Replace(temporaryPath, path, null);
            }
            finally
            {
                File.Delete(temporaryPath);
            }
        }
    }
}
