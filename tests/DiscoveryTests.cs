// Copyright (c) EurekaGao. Regression fixtures are generated under artifacts only.
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using FolderSeal;

internal static class DiscoveryTests
{
    private static int checks;
    private static void Check(bool value, string message) { if (!value) throw new Exception(message); checks++; Console.WriteLine("PASS " + message); }
    private static void Candidate(string seed, string path)
    { Directory.CreateDirectory(path); File.Copy(seed, Path.Combine(path, VaultSession.DataName)); }
    private static int Main(string[] args)
    {
        if (args.Length != 1 || !Directory.Exists(args[0])) return 2;
        string root = Path.Combine(Path.GetFullPath(args[0]), "generated-filter-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root); bool passed = false;
        try
        {
            string work = Path.Combine(root, "empty-work"); Directory.CreateDirectory(work);
            string seed = Path.Combine(root, "seed.egvault"); Header h = Header.New(); h.Iterations = 100000;
            using (KeySet k = new KeySet("Generated-Test-Only-927!", h.Salt, h.Iterations)) ArchiveCrypto.Encrypt(work, seed, h, k);
            string user = Path.Combine(root, "user"), sample = Path.Combine(root, "generated-library-" + new string('a', 32), "original"), recycle = Path.Combine(root, "$RECYCLE.BIN", "generated-account", "original");
            foreach (string name in new[] { "original", "changed", "示例资料", "generated-library-personal" }) Candidate(seed, Path.Combine(user, name));
            Candidate(seed, sample); Candidate(seed, recycle);
            foreach (string prefix in new[] { "entry-test-", "generated-test-", "generated-ui-", ".setup-test-" }) Candidate(seed, Path.Combine(root, prefix + new string('b', 32), "nested"));
            ScanProgress scan = VaultDiscovery.Scan(new[] { root }, CancellationToken.None, null);
            Check(scan.Count == 4, "scan excludes all recognized generated fixtures and recycle bin");
            Check(scan.FoundPaths.All(x => Paths.Inside(x, user)), "only original user locations returned");
            Check(scan.FoundPaths.Any(x => Path.GetFileName(x) == "original") && scan.FoundPaths.Any(x => Path.GetFileName(x) == "changed"), "ordinary folder names are not blacklisted");
            Check(scan.FoundPaths.Any(x => Path.GetFileName(x) == "generated-library-personal"), "similar personal names retained unless exact fixture pattern matches");
            Check(VaultDiscovery.Scan(new[] { sample, recycle }, CancellationToken.None, null).Count == 0, "explicitly selecting excluded subdirectories cannot reintroduce samples");
            Check(VaultDiscovery.IsExcluded(Path.Combine(root, "$recycle.bin", "nested")), "recycle exclusion is case insensitive");
            string actual = Path.Combine(user, "示例资料"), missing = Path.Combine(user, "offline-original"), cache = Path.Combine(root, "catalog.egcatalog");
            // Simulate a pre-fix encrypted cache, including managed test/recycle entries.
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter w = new BinaryWriter(m, Encoding.UTF8, true))
                {
                    w.Write(1); w.Write(true); w.Write(false); w.Write(0); w.Write("Old cached list with samples"); w.Write(4);
                    foreach (string p in new[] { actual, missing, sample, recycle }) { w.Write(p); w.Write(p != missing); }
                }
                SecretRecord.Write(cache, m.ToArray(), "Generated-Master-Only-642!");
            }
            VaultCatalog catalog = new VaultCatalog(cache); catalog.Load("Generated-Master-Only-642!");
            Check(catalog.Locations.Count == 2 && catalog.NeedsSave, "loading legacy cache removes test and recycle records even when managed");
            Check(catalog.Locations.Any(x => x.Path == actual && x.Managed), "real enrolled location preserved");
            Check(catalog.Locations.Any(x => x.Path == missing && !x.Managed), "unavailable original location remains recoverable");
            Check(catalog.Summary.Contains("2 个") && !catalog.Summary.Contains("Old cached"), "summary updates after cache cleanup");
            catalog.Add(sample, true); catalog.Add(recycle, true);
            Check(catalog.Locations.Count == 2, "excluded paths cannot be merged back into catalog");
            catalog.Save("Generated-Master-Only-642!");
            VaultCatalog reloaded = new VaultCatalog(cache); reloaded.Load("Generated-Master-Only-642!");
            Check(reloaded.Locations.Count == 2 && !reloaded.NeedsSave && reloaded.Scanned, "pruned cache persists without triggering automatic full rescan");
            Check(Paths.Equal(Paths.Hash(seed), Paths.Hash(Path.Combine(sample, VaultSession.DataName))) && File.Exists(Path.Combine(recycle, VaultSession.DataName)), "filtering never deletes or modifies excluded vault data");
            passed = true; Console.WriteLine("SUCCESS " + checks + " discovery-filter checks"); return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); Console.Error.WriteLine("Fixtures retained: " + root); return 1; }
        finally { if (passed && Paths.Inside(root, args[0])) Paths.DeleteTree(root); }
    }
}
