using SnaffCore.Checkpoint;

// Pause/resume log: completed directories and computers survive a restart,
// partly scanned directories do not, and a resumed run never reuses the
// first report's file name.
static class CheckpointRegression
{
    public static int Run()
    {
        string dir = Path.Combine(Path.GetTempPath(), "shareauditor-checkpoint-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        string log = Path.Combine(dir, "scan.checkpoint");
        int failed = 0, total = 0;
        try
        {
            ScanCheckpoint.Reset();
            var first = ScanCheckpoint.Instance;
            first.Load(log);
            first.BeginDir(@"\\srv\share\done", 2); first.FileDone(@"\\srv\share\done"); first.FileDone(@"\\srv\share\done");
            first.BeginDir(@"\\srv\share\partial", 3); first.FileDone(@"\\srv\share\partial");
            first.BeginDir(@"\\srv\share\empty", 0);
            first.RecordShare("srv", @"\\srv\share"); first.MarkComputer("srv");
            Check("Fresh run is not a resume", () => !first.Resumed);
            ScanCheckpoint.Reset(); // simulate a stop

            var second = ScanCheckpoint.Instance;
            second.Load(log);
            Check("Resumed flag set", () => second.Resumed);
            Check("Finished directory skipped", () => second.IsDirComplete(@"\\srv\share\done"));
            Check("Empty directory skipped", () => second.IsDirComplete(@"\\srv\share\empty"));
            Check("Partly scanned directory rescanned", () => !second.IsDirComplete(@"\\srv\share\partial"));
            Check("Computer and its shares replayed", () => second.IsComputerComplete("srv") && second.SharesFor("srv").Contains(@"\\srv\share"));
            ScanCheckpoint.Reset();
            Check("Disabled without a file", () => !ScanCheckpoint.Instance.Enabled && !ScanCheckpoint.Instance.IsDirComplete(@"\\srv\share\done"));

            string report = Path.Combine(dir, "report.xlsx");
            Check("Report name kept when absent", () => ScanCheckpoint.ResumeOutputPath(report) == report);
            File.WriteAllText(report, "x");
            Check("Resume writes report-resume-1", () => ScanCheckpoint.ResumeOutputPath(report) == Path.Combine(dir, "report-resume-1.xlsx"));
            File.WriteAllText(Path.Combine(dir, "report-resume-1.xlsx"), "x");
            Check("Then report-resume-2", () => ScanCheckpoint.ResumeOutputPath(report) == Path.Combine(dir, "report-resume-2.xlsx"));

            void Check(string name, Func<bool> test)
            {
                total++;
                try { if (test()) { Console.WriteLine("PASS " + name); return; } }
                catch (Exception ex) { Console.WriteLine("  " + ex.GetType().Name + ": " + ex.Message); }
                Console.WriteLine("FAIL " + name);
                failed++;
            }
        }
        finally { ScanCheckpoint.Reset(); Directory.Delete(dir, true); }
        Console.WriteLine($"{total - failed}/{total} checkpoint regressions passed");
        return failed;
    }
}
