// Copyright (c) EurekaGao. All locations and contents below are generated fixtures.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using FolderSeal;

internal static class LibraryTests
{
    private const string Old = "Generated-Old-927!", Master = "Generated-Master-642!";
    private static int checks;
    private static string root;
    private static void Check(bool value, string message) { if (!value) throw new Exception(message); checks++; Console.WriteLine("PASS " + message); }
    private static void Fails(Action work, string message)
    {
        bool failed = false;
        try { work(); } catch (IOException) { failed = true; } catch (CryptographicException) { failed = true; } catch (UnauthorizedAccessException) { failed = true; }
        Check(failed, message);
    }
    private static VaultSession Session(string name) { return new VaultSession(Path.Combine(root, name), Path.Combine(root, "sessions"), false); }
    private static void Create(string name)
    {
        using (VaultSession s = Session(name))
        {
            s.Create(Old); File.WriteAllText(Path.Combine(s.Work, "sample.txt"), "version-one\n中文"); s.Lock();
            s.Unlock(Old); File.WriteAllText(Path.Combine(s.Work, "sample.txt"), "version-two\n中文"); s.Lock();
        }
    }
    private static void Content(string name, string password, string expected)
    {
        using (VaultSession s = Session(name))
        { s.Unlock(password); Check(File.ReadAllText(Path.Combine(s.Work, "sample.txt")) == expected, "content preserved: " + name); s.Lock(); }
    }
    private static void CopyVault(string source, string name)
    {
        Directory.CreateDirectory(Path.Combine(root, name));
        foreach (string file in Directory.GetFiles(source)) File.Copy(file, Path.Combine(root, name, Path.GetFileName(file)));
    }
    private static void Catalog()
    {
        VaultCatalog c = new VaultCatalog(Path.Combine(root, "settings", "catalog.egcatalog"), true);
        c.Add(Path.Combine(root, "Generated secret location"), false); c.Add(Path.Combine(root, "GENERATED SECRET LOCATION"), true);
        c.Scanned = true; c.Complete = false; c.Skipped = 2; c.Summary = "Generated cancelled scan"; c.Save(Master);
        byte[] good = File.ReadAllBytes(c.FilePath);
        Check(!Encoding.UTF8.GetString(good).Contains("Generated secret location"), "catalog paths encrypted on disk");
        Check(!Encoding.UTF8.GetString(good).Contains(Master), "master password absent from catalog");
        VaultCatalog loaded = new VaultCatalog(c.FilePath, true); loaded.Load(Master);
        Check(loaded.Locations.Count == 1 && loaded.Locations[0].Managed, "case insensitive merge preserves enrolled state");
        Check(loaded.Scanned && !loaded.Complete && loaded.Skipped == 2, "cancelled scan is remembered across restart");
        Fails(delegate { loaded.Load(Old); }, "wrong master cannot load catalog");
        Check(loaded.Locations.Count == 1, "failed load does not replace existing catalog");
        byte[] damaged = (byte[])good.Clone(); damaged[Header.Size + 1] ^= 1; File.WriteAllBytes(c.FilePath, damaged);
        Fails(delegate { new VaultCatalog(c.FilePath, true).Load(Master); }, "catalog tamper rejected");
        File.WriteAllBytes(c.FilePath, good); loaded.Add(Path.Combine(root, "missing"), false); loaded.Save(Master);
        VaultCatalog again = new VaultCatalog(c.FilePath, true); again.Load(Master);
        Check(again.Locations.Count == 2 && !Directory.Exists(again.Locations[1].Path), "unavailable locations retained without scanning");
        string blocked = Path.Combine(root, "blocked-settings"); File.WriteAllText(blocked, "fixture");
        VaultCatalog denied = new VaultCatalog(Path.Combine(blocked, "catalog.egcatalog"));
        Fails(delegate { denied.Save(Master); }, "catalog write failure surfaced");
        byte[] stable = File.ReadAllBytes(c.FilePath);
        using (FileStream held = new FileStream(c.FilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        { again.Summary = "replacement must fail"; Fails(delegate { again.Save(Master); }, "occupied catalog refuses atomic replacement"); }
        Check(Paths.Equal(stable, File.ReadAllBytes(c.FilePath)), "failed replacement preserves previous catalog bytes");
    }
    private sealed class Progress : IProgress<ScanProgress>
    {
        public readonly List<string> Found = new List<string>(); public CancellationTokenSource Stop;
        public void Report(ScanProgress s) { if (s.Found != null) { Found.Add(s.Found); if (Stop != null) Stop.Cancel(); } }
    }
    private static void Discovery()
    {
        string scanRoot = Path.Combine(root, "discovery"); Directory.CreateDirectory(scanRoot);
        CopyVault(Path.Combine(root, "original"), "discovery/one"); CopyVault(Path.Combine(root, "original"), "discovery/two");
        Directory.CreateDirectory(Path.Combine(scanRoot, "fake")); File.WriteAllText(Path.Combine(scanRoot, "fake", VaultSession.DataName), "fake header");
        Progress p = new Progress(); ScanProgress result = VaultDiscovery.Scan(new[] { scanRoot, scanRoot }, CancellationToken.None, p, true);
        Check(result.Count == 2 && p.Found.Count == 2 && result.Skipped == 1, "discovery checks headers, deduplicates and counts damaged files");
        using (CancellationTokenSource stop = new CancellationTokenSource())
        {
            Progress cancelling = new Progress { Stop = stop };
            ScanProgress partial = VaultDiscovery.Scan(new[] { scanRoot }, stop.Token, cancelling, true);
            Check(stop.IsCancellationRequested && partial.Count == 1 && partial.FoundPaths.Count == 1, "cancellation preserves discovered locations");
            stop.Cancel(); Check(VaultDiscovery.Scan(new[] { scanRoot }, stop.Token, null, true).Visited == 0, "pre-cancelled scan visits no directories");
        }
        Check(VaultDiscovery.Scan(new[] { Path.Combine(root, "absent") }, CancellationToken.None, null, true).Skipped == 1, "unavailable root does not abort scan");
        string link = Path.Combine(scanRoot, "junction");
        using (System.Diagnostics.Process command = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c mklink /J \"" + link + "\" \"" + Path.Combine(root, "original") + "\"") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true }))
        { command.WaitForExit(); Check(command.ExitCode == 0, "generated junction fixture created"); }
        try { Check(VaultDiscovery.Scan(new[] { link }, CancellationToken.None, null, true).Skipped == 1, "junction is not followed"); }
        finally { Directory.Delete(link); }
    }
    private static void Migration()
    {
        string original = Path.Combine(root, "original");
        foreach (string stage in new[] { "prepared", "current", "backup", "cleanup" })
        {
            string name = "interrupt-" + stage; CopyVault(original, name);
            using (VaultSession s = Session(name))
            {
                bool interrupted = false;
                try { s.ChangePassword(Old, Master, delegate(string point) { if (point == stage) throw new IOException("Generated interruption"); }); }
                catch (IOException) { interrupted = true; }
                Check(interrupted && s.HasPendingMigration, "journal survives interruption at " + stage);
                Fails(delegate { s.Unlock(Master); }, "editing blocked until transaction recovery: " + stage);
                Fails(delegate { s.ChangePassword(null, Old); }, "wrong master cannot recover: " + stage);
                s.ChangePassword(null, Master); Check(!s.HasPendingMigration, "recovery completes: " + stage);
                Check(s.AcceptsPassword(Master), "both snapshots use master: " + stage);
                Fails(delegate { s.Unlock(Old); }, "old password rejected: " + stage);
                string previous = Path.Combine(root, name, VaultSession.BackupName);
                string copy = Path.Combine(root, "previous-" + stage); Directory.CreateDirectory(copy); File.Copy(previous, Path.Combine(copy, VaultSession.DataName));
                Content("previous-" + stage, Master, "version-one\n中文");
            }
            Content(name, Master, "version-two\n中文");
            Check(!Directory.GetFiles(Path.Combine(root, name), ".pending-*").Any(), "migration staging and originals cleaned: " + stage);
        }
        using (VaultSession s = Session("original")) Check(s.AcceptsPassword(Old), "external original backup still uses old password");
        CopyVault(original, "wrong"); byte[] before = Paths.Hash(Path.Combine(root, "wrong", VaultSession.DataName));
        using (VaultSession s = Session("wrong")) Fails(delegate { s.ChangePassword("wrong-password", Master); }, "wrong original password prevents migration");
        Check(Paths.Equal(before, Paths.Hash(Path.Combine(root, "wrong", VaultSession.DataName))), "wrong password leaves original untouched");
        CopyVault(original, "occupied");
        using (VaultSession holder = Session("occupied"))
        using (VaultSession other = Session("occupied"))
        { holder.Unlock(Old); Fails(delegate { other.ChangePassword(Old, Master); }, "in-use vault cannot migrate"); holder.Lock(); }
        CopyVault(original, "corrupt-backup");
        string corrupt = Path.Combine(root, "corrupt-backup", VaultSession.BackupName); byte[] data = File.ReadAllBytes(corrupt); data[Header.Size + 1] ^= 1; File.WriteAllBytes(corrupt, data);
        byte[] prior = Paths.Hash(Path.Combine(root, "corrupt-backup", VaultSession.DataName));
        using (VaultSession s = Session("corrupt-backup")) Fails(delegate { s.ChangePassword(Old, Master); }, "corrupt previous snapshot prevents migration");
        Check(Paths.Equal(prior, Paths.Hash(Path.Combine(root, "corrupt-backup", VaultSession.DataName))), "backup failure leaves current snapshot untouched");
        CopyVault(original, "stage-blocked"); Directory.CreateDirectory(Path.Combine(root, "stage-blocked", ".pending-rekey-new-" + VaultSession.DataName));
        using (VaultSession s = Session("stage-blocked")) Fails(delegate { s.ChangePassword(Old, Master); }, "blocked staging cannot replace originals");
        CopyVault(original, "changed");
        using (VaultSession s = Session("changed"))
        {
            Fails(delegate { s.ChangePassword(Old, Master, delegate(string point) { if (point == "prepared") throw new IOException("interrupt"); }); }, "generated prepared transaction");
            string target = Path.Combine(root, "changed", VaultSession.DataName); byte[] bytes = File.ReadAllBytes(target); bytes[Header.Size + 1] ^= 1; File.WriteAllBytes(target, bytes);
            Fails(delegate { s.ChangePassword(null, Master); }, "external change halts migration recovery");
            Check(File.Exists(target) && s.HasPendingMigration, "externally changed transaction and originals retained");
        }
        CopyVault(original, "prepare-failure");
        byte[] originalCurrent = Paths.Hash(Path.Combine(root, "prepare-failure", VaultSession.DataName)), originalBackup = Paths.Hash(Path.Combine(root, "prepare-failure", VaultSession.BackupName));
        using (VaultSession s = Session("prepare-failure"))
        {
            Fails(delegate { s.ChangePassword(Old, Master, delegate(string point) { if (point == "staged") throw new IOException("Generated staging I/O failure (disk full)"); }); }, "injected preparation I/O failure stops migration");
            Check(Paths.Equal(originalCurrent, Paths.Hash(s.Data)) && Paths.Equal(originalBackup, Paths.Hash(Path.Combine(s.Root, VaultSession.BackupName))), "staging failure preserves both originals");
            Check(!s.HasPendingMigration, "failed preparation is not a committed transaction");
            s.ChangePassword(Old, Master); Check(s.AcceptsPassword(Master), "retry replaces incomplete encrypted staging safely");
        }
        CopyVault(original, "cleanup-failure");
        using (VaultSession s = Session("cleanup-failure"))
        {
            FileStream occupied = null;
            try
            {
                Fails(delegate { s.ChangePassword(Old, Master, delegate(string point)
                { if (point == "cleanup") occupied = new FileStream(Path.Combine(s.Root, ".pending-rekey-old-" + VaultSession.DataName), FileMode.Open, FileAccess.Read, FileShare.Read); }); }, "original cleanup failure retains journal");
                Check(s.HasPendingMigration, "cleanup failure remains recoverable");
            }
            finally { if (occupied != null) occupied.Dispose(); }
            s.ChangePassword(null, Master); Check(s.AcceptsPassword(Master) && !s.HasPendingMigration, "retry completes cleanup without re-encrypting");
        }
    }
    private static void OrphanProtection()
    {
        CopyVault(Path.Combine(root, "original"), "orphan-vault");
        using (VaultSession s = Session("orphan-vault"))
        {
            string workspace = Path.Combine(root, "sessions", "generated-orphan"); Directory.CreateDirectory(workspace);
            byte[] before = Paths.Hash(s.Data);
            foreach (string name in new[] { "工作区说明.txt", "清理状态.txt" })
            {
                string note = Path.Combine(workspace, name); File.WriteAllText(note, s.Root + "\r\nGenerated metadata");
                Check(s.HasUnfinishedWorkspace, "orphan detected using " + name);
                Fails(delegate { s.ChangePassword(Old, Master); }, "orphan blocks password migration: " + name);
                Check(Paths.Equal(before, Paths.Hash(s.Data)), "orphan rejection preserves current snapshot"); File.Delete(note);
            }
            Directory.Delete(workspace); Check(!s.HasUnfinishedWorkspace, "unrelated or cleaned sessions do not block migration");
        }
    }
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length != 1 || !Directory.Exists(args[0])) return 2;
        root = Path.Combine(Path.GetFullPath(args[0]), "generated-library-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        bool passed = false;
        try { Catalog(); Create("original"); Discovery(); Migration(); OrphanProtection(); passed = true; Console.WriteLine("SUCCESS " + checks + " library checks"); return 0; }
        catch (Exception error) { Console.Error.WriteLine(error); Console.Error.WriteLine("Generated fixtures retained: " + root); return 1; }
        finally
        {
            if (passed && Paths.Inside(root, args[0]) && Path.GetFileName(root).StartsWith("generated-library-", StringComparison.Ordinal)) Paths.DeleteTree(root);
        }
    }
}
