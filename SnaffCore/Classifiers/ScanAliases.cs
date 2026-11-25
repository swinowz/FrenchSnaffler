using System;
using System.Collections.Generic;

namespace SnaffCore.Classifiers
{
    /// <summary>
    /// Lets a file be classified and reported under another (logical) path:
    /// archive members extracted to a temp file, SCCM content library files
    /// stored under their hash. Name, extension and path rules match the logical
    /// path; reports show it. A scan is synchronous on its worker thread, so the
    /// aliases are per thread: the same physical file can be scanned under two
    /// names at once on two threads (SCCM single-instance store).
    /// </summary>
    public static class ScanAliases
    {
        [ThreadStatic] private static Dictionary<string, string> _aliases;

        public static string Get(string physicalPath)
        {
            if (physicalPath == null || _aliases == null) return null;
            return _aliases.TryGetValue(physicalPath, out string logical) ? logical : null;
        }

        public static IDisposable Use(string physicalPath, string logicalPath)
        {
            if (_aliases == null) _aliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            _aliases.TryGetValue(physicalPath, out string previous);
            _aliases[physicalPath] = logicalPath;
            return new Scope(physicalPath, previous);
        }

        /// <summary>Last path segment; '!' separates an archive from its members.</summary>
        public static string LogicalName(string path)
        {
            if (string.IsNullOrEmpty(path)) return path;
            int cut = path.LastIndexOfAny(new[] { '\\', '/', '!' });
            return cut >= 0 ? path.Substring(cut + 1) : path;
        }

        public static string LogicalExtension(string path)
        {
            // same result as Path.GetExtension on the last segment
            string name = LogicalName(path) ?? "";
            int dot = name.LastIndexOf('.');
            return dot < 0 || dot == name.Length - 1 ? "" : name.Substring(dot);
        }

        private sealed class Scope : IDisposable
        {
            private readonly string _path;
            private readonly string _previous;
            private bool _done;

            public Scope(string path, string previous) { _path = path; _previous = previous; }

            public void Dispose()
            {
                if (_done) return;
                _done = true;
                if (_previous != null) _aliases[_path] = _previous;
                else _aliases.Remove(_path);
            }
        }
    }
}
