// Copyright (c) EurekaGao. Tests use generated fixtures, never personal files.
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace FolderSeal
{
    internal static class Tests
    {
        private static int checks;
        private static string container;
        private const string Password = "Test-Only-Password-927!";
        private static void Assert(bool condition, string message)
        {
            if (!condition) throw new Exception("FAIL: " + message);
            checks++;
        }
        private static void Fails(Action action, string message)
        {
            bool failed = false;
            try { action(); }
            catch (Exception e) { if (e is IOException || e is UnauthorizedAccessException || e is CryptographicException || e is ArgumentException) failed = true; else throw; }
            Assert(failed, message);
        }
        private static void Say(string message) { Console.WriteLine("PASS " + message); }
        private static string Child(string name) { return Path.Combine(container, name); }
        private static VaultSession Session(string name) { return new VaultSession(Child(name), Child("sessions"), false); }
        private static int Main(string[] args)
        {
            if (args.Length == 0) { Console.Error.WriteLine("Specify an existing writable test parent."); return 2; }
            string parent = Paths.Full(args[0]);
            if (!Directory.Exists(parent)) return 2;
            container = Path.Combine(parent, "generated-test-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(container);
            bool passed = false;
            string report = args.Length > 1 && args[1] == "--acl" ? Path.Combine(parent, "权限验证结果_V1_2026-10-31.txt") : null;
            try
            {
                if (args.Length > 1 && args[1] == "--acl") AclTest();
                else { PasswordBoundary(); RoundTrip(); Tamper(); PathValidation(); FailureSafety(); CleanupRecovery(); WorkspaceVersionRecovery(); Concurrency(); DeleteAuthentication(); HardLinkTest(); ImportSourceCleanupTest(); DirtyCheckFastLockTest(); SealedAclRulesTest(); }
                Console.WriteLine("SUCCESS " + checks + " checks");
                if (report != null) File.WriteAllText(report, "SUCCESS " + checks + " checks\r\n" + DateTime.Now.ToString("s"), Encoding.UTF8);
                passed = true; return 0;
            }
            catch (Exception error) { Console.Error.WriteLine(error); Console.Error.WriteLine("Generated fixtures retained: " + container); if (report != null) File.WriteAllText(report, "FAILED\r\n" + error + "\r\n" + container, Encoding.UTF8); return 1; }
            finally
            {
                if (passed && Paths.Inside(container, parent) && Path.GetFileName(container).StartsWith("generated-test-"))
                {
                    try { Paths.DeleteTree(container); }
                    catch (Exception error) { Console.Error.WriteLine("Fixture cleanup: " + error.Message); }
                }
            }
        }
        private static void PasswordBoundary()
        {
            using (VaultSession vault = Session("password-boundary"))
            {
                Fails(delegate { vault.Create(""); }, "empty password rejected");
                Fails(delegate { vault.Create("1234567"); }, "seven-character password rejected");
                Fails(delegate { vault.Create("        "); }, "whitespace-only eight-character password rejected");
                Assert(!Directory.Exists(vault.Root), "short or blank passwords create no vault directory");
                vault.Create("12345678");
                Assert(vault.Open, "exactly eight characters accepted");
                File.WriteAllText(Path.Combine(vault.Work, "fixture.txt"), "eight-character password fixture");
                vault.Lock();
                Fails(delegate { vault.Unlock("87654321"); }, "incorrect eight-character password rejected");
                vault.Unlock("12345678");
                Assert(File.ReadAllText(Path.Combine(vault.Work, "fixture.txt")) == "eight-character password fixture", "eight-character password roundtrip");
                vault.Lock();
                Fails(delegate { vault.ChangePassword("12345678", "1234567"); }, "change password rejects seven-character new password");
                vault.Delete("12345678");
                Assert(!Directory.Exists(vault.Root), "eight-character password authorizes deletion");
            }
            Assert(PasswordDialog.HintExposesPassword("p a s s w o r d 1", "password1"), "hint check blocks spaced password variant");
            Assert(PasswordDialog.HintExposesPassword("1drowssap", "password1"), "hint check blocks reversed password variant");
            Assert(!PasswordDialog.HintExposesPassword("老家楼栋号", "password1"), "hint check allows unrelated clue");
            Say("minimum eight meaningful characters, seven/whitespace rejected, hint variants blocked, correct unlock and authenticated deletion");
        }
        private static void RoundTrip()
        {
            byte[] binary = Header.Random(230000);
            using (VaultSession vault = Session("任意位置"))
            {
                vault.Create(Password);
                Directory.CreateDirectory(Path.Combine(vault.Work, "中文子目录", "空目录"));
                File.WriteAllText(Path.Combine(vault.Work, "中文子目录", "示例.md"), "# 测试\r\n这不是用户数据。", Encoding.UTF8);
                File.WriteAllBytes(Path.Combine(vault.Work, "binary.bin"), binary);
                File.WriteAllBytes(Path.Combine(vault.Work, "empty.txt"), new byte[0]);
                string work = vault.Work;
                vault.Lock();
                Assert(!Directory.Exists(work) && !vault.Open, "lock removes workspace and clears session");
                byte[] encrypted = File.ReadAllBytes(vault.Data);
                Assert(!Encoding.UTF8.GetString(encrypted).Contains("示例.md"), "file names are encrypted");
                int before = Directory.GetDirectories(Child("sessions")).Length;
                Fails(delegate { vault.Unlock("Incorrect-Password"); }, "wrong password rejected");
                Assert(Directory.GetDirectories(Child("sessions")).Length == before, "wrong password creates no plaintext workspace");
                vault.Unlock(Password);
                Assert(Paths.Equal(binary, File.ReadAllBytes(Path.Combine(vault.Work, "binary.bin"))), "binary roundtrip");
                Assert(File.ReadAllText(Path.Combine(vault.Work, "中文子目录", "示例.md")).Contains("这不是用户数据"), "Unicode roundtrip");
                Assert(Directory.Exists(Path.Combine(vault.Work, "中文子目录", "空目录")), "empty directory roundtrip");
                Assert(new FileInfo(Path.Combine(vault.Work, "empty.txt")).Length == 0, "zero-byte file roundtrip");
                File.AppendAllText(Path.Combine(vault.Work, "empty.txt"), "edited");
                vault.Lock();
                vault.Unlock(Password);
                Assert(File.ReadAllText(Path.Combine(vault.Work, "empty.txt")) == "edited", "edits persist");
                vault.Lock();
            }
            Say("Unicode, binary, empty files/directories, edits, password rejection and cleanup");
        }
        private static void Tamper()
        {
            string path = Path.Combine(Child("任意位置"), VaultSession.DataName);
            byte[] original = File.ReadAllBytes(path);
            Header header = Header.Read(path);
            using (KeySet keys = new KeySet(Password, header.Salt, header.Iterations))
            {
                foreach (int offset in new[] { 12, 44, 60, original.Length - 1 })
                {
                    byte[] changed = (byte[])original.Clone(); changed[offset] ^= 1;
                    string temp = Child("tampered.egvault"); File.WriteAllBytes(temp, changed);
                    string plain = Child("must-not-exist.zip");
                    Fails(delegate { ArchiveCrypto.DecryptZip(temp, plain, header, keys); }, "tampering rejected at " + offset);
                    Assert(!File.Exists(plain), "no plaintext before authentication");
                    File.Delete(temp);
                }
            }
            string truncated = Child("truncated.egvault"); File.WriteAllBytes(truncated, original.Take(70).ToArray());
            Fails(delegate { Header.Read(truncated); }, "truncation rejected");
            byte[] iterations = (byte[])original.Clone(); Array.Copy(BitConverter.GetBytes(Int32.MaxValue), 0, iterations, 8, 4);
            File.WriteAllBytes(truncated, iterations); Fails(delegate { Header.Read(truncated); }, "unbounded KDF work rejected");
            Say("salt/IV/ciphertext/MAC tampering, truncation and KDF parameter bounds");
        }
        private static void PathValidation()
        {
            foreach (string path in new[] { "../escape", "/absolute", "x/../../escape", "x:stream", "CON.txt", "a/../b", "a./b", @"..\escape" })
                Fails(delegate { Paths.Relative(path); }, "unsafe path rejected: " + path);
            string output = Child("extract"); Directory.CreateDirectory(output);
            string archive = Child("evil.zip");
            using (ZipArchive zip = ZipFile.Open(archive, ZipArchiveMode.Create))
            {
                zip.CreateEntry("safe.txt"); zip.CreateEntry("../outside.txt");
            }
            Fails(delegate { ArchiveCrypto.Extract(archive, output); }, "ZIP traversal rejected");
            Assert(Directory.GetFileSystemEntries(output).Length == 0, "all archive paths checked before extraction");
            File.Delete(archive);
            using (ZipArchive zip = ZipFile.Open(archive, ZipArchiveMode.Create)) { zip.CreateEntry("a.txt"); zip.CreateEntry("A.txt"); }
            Fails(delegate { ArchiveCrypto.Extract(archive, output); }, "case-insensitive duplicate rejected");
            Say("ZIP traversal, Windows reserved names, alternate streams and duplicate paths");
        }
        private static void FailureSafety()
        {
            using (VaultSession vault = Session("failure"))
            {
                vault.Create(Password);
                string file = Path.Combine(vault.Work, "editing.txt"); File.WriteAllText(file, "unsaved-important-test");
                byte[] original = Paths.Hash(vault.Data);
                using (FileStream writer = new FileStream(file, FileMode.Open, FileAccess.Write, FileShare.ReadWrite))
                    Fails(delegate { vault.Lock(); }, "open writer prevents lock");
                Assert(vault.Open && File.Exists(file), "failed lock retains unlocked workspace");
                Assert(Paths.Equal(original, Paths.Hash(vault.Data)), "failed lock retains previous encrypted snapshot");
                Assert(Directory.GetFiles(vault.Root, ".pending-*").Length == 0, "failed stage cleaned up");
                vault.Lock();
                vault.Unlock(Password);
                string backup = Path.Combine(vault.Root, VaultSession.BackupName);
                byte[] previous = Paths.Hash(backup);
                byte[] current = Paths.Hash(vault.Data);
                File.WriteAllText(Path.Combine(vault.Work, "editing.txt"), "new edit");
                using (FileStream reader = new FileStream(backup, FileMode.Open, FileAccess.Read, FileShare.Read))
                    Fails(delegate { vault.Lock(); }, "held previous snapshot prevents replacement without deleting backups");
                Assert(vault.Open && Paths.Equal(previous, Paths.Hash(backup)) && Paths.Equal(current, Paths.Hash(vault.Data)), "failed replacement keeps both encrypted versions");
                vault.Lock();
                Assert(Paths.Equal(current, Paths.Hash(backup)), "success rotates the former current snapshot into the backup");
            }
            Say("failed save retains source data and existing encrypted snapshot");
        }
        private static void Concurrency()
        {
            using (VaultSession first = Session("concurrent"))
            using (VaultSession second = Session("concurrent"))
            {
                first.Create(Password);
                Fails(delegate { second.Unlock(Password); }, "exclusive folder session");
                byte[] original = File.ReadAllBytes(first.Data);
                File.AppendAllText(first.Data, "external-change");
                Fails(delegate { first.Lock(); }, "external snapshot replacement detected");
                Assert(first.Open && Directory.Exists(first.Work), "conflict preserves workspace");
                File.WriteAllBytes(first.Data, original);
                first.Lock();
            }
            Say("parallel-session exclusion and external-change protection");
        }
        private static void CleanupRecovery()
        {
            string savedSession;
            using (VaultSession vault = Session("cleanup-recovery"))
            {
                vault.Create(Password);
                File.WriteAllText(Path.Combine(vault.Work, "a.txt"), "first fixture");
                File.WriteAllText(Path.Combine(vault.Work, "z.txt"), "second fixture");
                savedSession = vault.SessionRoot;
                using (FileStream reader = new FileStream(Path.Combine(vault.Work, "z.txt"), FileMode.Open, FileAccess.Read, FileShare.Read))
                    Fails(delegate { vault.Lock(); }, "read handle can prevent plaintext cleanup");
                Assert(vault.CleanupPending, "incomplete cleanup distinguished from incomplete save");
                Assert(vault.Open, "pending cleanup remains operable after releasing encryption keys");
                Assert(File.Exists(Path.Combine(savedSession, "清理状态.txt")), "cleanup recovery marker persisted");
                Assert(!File.Exists(Path.Combine(vault.Work, "a.txt")), "test exercised partial cleanup");
                bool importBlocked = false;
                try { vault.ImportFile(Child("evil.zip")); }
                catch (InvalidOperationException) { importBlocked = true; }
                Assert(importBlocked, "no import while cleanup pending");
            }
            using (VaultSession resumed = Session("cleanup-recovery"))
            {
                resumed.Resume(savedSession, Password);
                Assert(resumed.CleanupPending, "restart recognizes committed snapshot");
                resumed.Lock();
                Assert(!Directory.Exists(savedSession), "retry finishes cleanup");
                resumed.Unlock(Password);
                Assert(File.ReadAllText(Path.Combine(resumed.Work, "a.txt")) == "first fixture", "partial cleanup cannot overwrite full snapshot");
                Assert(File.ReadAllText(Path.Combine(resumed.Work, "z.txt")) == "second fixture", "remaining file preserved");
                resumed.Lock();
            }
            Say("partial-cleanup failure and crash recovery preserve the full encrypted snapshot");
        }
        private static void WorkspaceVersionRecovery()
        {
            string stale, legacy;
            using (VaultSession vault = Session("workspace-version"))
            {
                vault.Create(Password); vault.Lock();
                vault.Unlock(Password);
                File.WriteAllText(Path.Combine(vault.Work, "fixture.txt"), "recoverable edit");
                stale = vault.SessionRoot;
            }
            using (VaultSession vault = Session("workspace-version"))
            {
                Assert(vault.RecoveryWorkspaces().SequenceEqual(new[] { stale }), "only the matching workspace is listed");
                vault.Resume(stale, Password);
                Assert(File.ReadAllText(Path.Combine(vault.Work, "fixture.txt")) == "recoverable edit", "matching source version can be recovered");
                vault.Lock();
                vault.Unlock(Password);
                File.WriteAllText(Path.Combine(vault.Work, "fixture.txt"), "older unsaved edit");
                stale = vault.SessionRoot;
            }
            using (VaultSession vault = Session("workspace-version"))
            {
                vault.Unlock(Password);
                File.WriteAllText(Path.Combine(vault.Work, "fixture.txt"), "newer saved edit");
                vault.Lock();
                vault.Unlock(Password);
                legacy = vault.SessionRoot;
                string note = Path.Combine(legacy, "工作区说明.txt");
                File.WriteAllLines(note, File.ReadAllLines(note).Where(line => !line.StartsWith("来源版本：")));
            }
            using (VaultSession vault = Session("workspace-version"))
            {
                byte[] current = Paths.Hash(vault.Data), backup = Paths.Hash(Path.Combine(vault.Root, VaultSession.BackupName));
                Fails(delegate { vault.Resume(stale, Password); }, "older workspace cannot replace newer saved content");
                Fails(delegate { vault.Resume(legacy, Password); }, "legacy workspace without recorded origin cannot replace a snapshot");
                Assert(!vault.Open && Paths.Equal(Paths.Hash(vault.Data), current) && Paths.Equal(Paths.Hash(Path.Combine(vault.Root, VaultSession.BackupName)), backup), "rejected recovery leaves both encrypted versions unchanged");
                Assert(File.ReadAllText(Path.Combine(stale, "编辑区", "fixture.txt")) == "older unsaved edit" && Directory.Exists(legacy), "rejected recovery leaves both old workspaces available for manual copy");
                using (VaultSession other = Session("workspace-version-other"))
                {
                    other.Create(Password); other.Lock();
                    Assert(!other.RecoveryWorkspaces().Any(), "unrelated vault does not list those workspaces");
                    Fails(delegate { other.Resume(stale, Password); }, "workspace cannot be restored into another vault");
                }
                vault.Unlock(Password);
                Assert(File.ReadAllText(Path.Combine(vault.Work, "fixture.txt")) == "newer saved edit", "newer saved edit remains the current version");
                vault.Lock();
            }
            Say("matching recovery works; stale, legacy and unrelated workspaces are retained without overwriting");
        }
        private static void DeleteAuthentication()
        {
            using (VaultSession vault = Session("delete"))
            {
                vault.Create(Password); vault.Lock();
                Fails(delegate { vault.Delete("wrong-password"); }, "delete requires correct password");
                Assert(File.Exists(vault.Data), "wrong-password deletion preserves encrypted data");
                File.WriteAllText(Path.Combine(vault.Root, "unexpected.txt"), "preserve me");
                Fails(delegate { vault.Delete(Password); }, "unknown files prevent folder deletion");
                Assert(File.Exists(vault.Data), "unexpected-file failure preserves data");
                File.Delete(Path.Combine(vault.Root, "unexpected.txt"));
                vault.Delete(Password);
                Assert(!Directory.Exists(vault.Root), "password-authorized deletion succeeds");
            }
            Say("password-authorized deletion and unknown-file safeguards");
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateHardLink(string link, string existing, IntPtr reserved);
        private static void HardLinkTest()
        {
            string root = Child("links"); Directory.CreateDirectory(root);
            string original = Path.Combine(root, "original.txt"), link = Path.Combine(root, "link.txt");
            File.WriteAllText(original, "fixture");
            if (!CreateHardLink(link, original, IntPtr.Zero)) throw new IOException("Cannot create test hard link: " + Marshal.GetLastWin32Error());
            Fails(delegate { Paths.Files(root); }, "hard links rejected before recursive ACL changes/deletion");
            File.Delete(link);
            Assert(File.ReadAllText(original) == "fixture", "hard-link rejection preserves original");
            Say("hard-link safety");
        }
        private static void ImportSourceCleanupTest()
        {
            string sources = Child("import-sources");
            Directory.CreateDirectory(sources);
            string plainFile = Path.Combine(sources, "plain.txt");
            File.WriteAllText(plainFile, "plain-file-content", Encoding.UTF8);
            string plainDir = Path.Combine(sources, "plain-folder");
            Directory.CreateDirectory(Path.Combine(plainDir, "nested"));
            string nestedFile = Path.Combine(plainDir, "nested", "readonly.txt");
            File.WriteAllText(nestedFile, "nested-content", Encoding.UTF8);
            File.SetAttributes(nestedFile, FileAttributes.ReadOnly);
            string modifiedFile = Path.Combine(sources, "modified.txt");
            File.WriteAllText(modifiedFile, "before-change", Encoding.UTF8);
            string removedFromWork = Path.Combine(sources, "removed-from-work.txt");
            File.WriteAllText(removedFromWork, "keep-original-if-removed", Encoding.UTF8);

            using (VaultSession vault = Session("import-cleanup"))
            {
                vault.Create(Password);
                vault.ImportFile(plainFile, true);
                vault.ImportFolder(plainDir, true);
                vault.ImportFile(modifiedFile, true);
                vault.ImportFile(removedFromWork, true);
                Assert(vault.PendingSourceDeleteCount == 4, "imports track four pending original sources");
                Assert(File.Exists(plainFile) && Directory.Exists(plainDir), "original plaintext remains until save and lock");

                // Simulate external edit after import and user removing one file from workspace before locking.
                File.WriteAllText(modifiedFile, "changed-externally", Encoding.UTF8);
                File.Delete(Path.Combine(vault.Work, "removed-from-work.txt"));

                // Simulate a failed lock due to an open writer; original plaintext must stay intact.
                using (FileStream writer = new FileStream(Path.Combine(vault.Work, "plain.txt"), FileMode.Open, FileAccess.Write, FileShare.ReadWrite))
                    Fails(delegate { vault.Lock(); }, "failed lock retains pending original sources");
                Assert(File.Exists(plainFile) && Directory.Exists(plainDir), "failed lock never deletes original plaintext");

                vault.Lock();
                Assert(!File.Exists(plainFile), "imported file original plaintext permanently deleted on lock");
                Assert(!Directory.Exists(plainDir), "imported folder original plaintext permanently deleted on lock");
                Assert(File.Exists(modifiedFile), "externally modified original file is preserved");
                Assert(File.Exists(removedFromWork), "file removed from workspace before lock keeps its original");
                Assert(vault.LastSourceDeletedCount == 2, "lock reports two deleted original sources");
                Assert(vault.LastSourceCleanupWarnings.Count == 1, "lock warns about the externally modified source");

                vault.Unlock(Password);
                Assert(File.ReadAllText(Path.Combine(vault.Work, "plain.txt"), Encoding.UTF8) == "plain-file-content", "imported file persisted in vault");
                Assert(File.ReadAllText(Path.Combine(vault.Work, "plain-folder", "nested", "readonly.txt"), Encoding.UTF8) == "nested-content", "imported folder persisted in vault");
                Assert(File.ReadAllText(Path.Combine(vault.Work, "modified.txt"), Encoding.UTF8) == "before-change", "vault kept snapshot captured at import time");
                Assert(!File.Exists(Path.Combine(vault.Work, "removed-from-work.txt")), "removed file is absent from vault");
                vault.Lock();
            }

            // Regression for WS-2-01 (same-name replacement in workspace must never delete unarchived source A)
            string dirA = Path.Combine(sources, "same-name-a"), dirB = Path.Combine(sources, "same-name-b");
            Directory.CreateDirectory(dirA); Directory.CreateDirectory(dirB);
            string sameA = Path.Combine(dirA, "report.txt"), sameB = Path.Combine(dirB, "report.txt");
            File.WriteAllText(sameA, "content-A-never-saved", Encoding.UTF8);
            File.WriteAllText(sameB, "content-B-saved", Encoding.UTF8);
            using (VaultSession vault = Session("import-same-name-safety"))
            {
                vault.Create(Password);
                vault.ImportFile(sameA, true);
                File.Delete(Path.Combine(vault.Work, "report.txt"));
                vault.ImportFile(sameB, true);
                vault.Lock();
                Assert(File.Exists(sameA), "replaced same-name original A is preserved when not archived");
                Assert(!File.Exists(sameB), "archived same-name original B is deleted on lock");
            }

            // Regression for WS-2-03 (pending source deletions survive cleanup interruption and complete on Resume -> Lock)
            string resumeSrc = Path.Combine(sources, "resume-delete.txt");
            File.WriteAllText(resumeSrc, "delete-after-resume", Encoding.UTF8);
            string interruptedSession;
            using (VaultSession vault = Session("import-cleanup-resume"))
            {
                vault.Create(Password);
                vault.ImportFile(resumeSrc, true);
                File.WriteAllText(Path.Combine(vault.Work, "blocker.txt"), "lock-me", Encoding.UTF8);
                interruptedSession = vault.SessionRoot;
                using (FileStream hold = new FileStream(Path.Combine(vault.Work, "blocker.txt"), FileMode.Open, FileAccess.Read, FileShare.Read))
                    Fails(delegate { vault.Lock(); }, "blocked workspace cleanup stops before deleting original source");
                Assert(vault.CleanupPending && File.Exists(resumeSrc), "source remains intact while cleanup is pending");
            }
            using (VaultSession resumed = Session("import-cleanup-resume"))
            {
                resumed.Resume(interruptedSession, Password);
                resumed.Lock();
                Assert(!File.Exists(resumeSrc), "resumed cleanup finishes pending original source deletion");
                Assert(resumed.LastSourceDeletedCount == 1, "resumed cleanup reports deleted source count");
            }
            Say("imported files and folders delete unchanged original plaintext on lock and preserve modified or removed sources");
        }
        private static void DirtyCheckFastLockTest()
        {
            using (VaultSession vault = Session("dirty-check"))
            {
                // 1. Newly created empty vault with no edits skips snapshot on lock.
                vault.Create(Password);
                Assert(!vault.HasWorkspaceChanges(), "newly created empty workspace reports clean");
                byte[] emptyDataHash = Paths.Hash(vault.Data);
                vault.Lock();
                Assert(vault.LastLockSkippedSnapshot, "locking untouched newly created vault skips snapshot");
                Assert(Paths.Equal(emptyDataHash, Paths.Hash(vault.Data)), "untouched newly created vault ciphertext unchanged");

                // Populate initial content with a known past timestamp for deterministic same-size edit testing.
                vault.Unlock(Password);
                Directory.CreateDirectory(Path.Combine(vault.Work, "sub"));
                string note = Path.Combine(vault.Work, "sub", "note.txt");
                File.WriteAllText(note, "hello", Encoding.UTF8);
                File.SetLastWriteTimeUtc(note, DateTime.UtcNow.AddMinutes(-10));
                Assert(vault.HasWorkspaceChanges(), "adding files and directories marks workspace dirty");
                vault.Lock();
                Assert(!vault.LastLockSkippedSnapshot, "adding files forces full snapshot");

                // Second edit to ensure BackupName exists and differs from DataName.
                vault.Unlock(Password);
                File.WriteAllText(Path.Combine(vault.Work, "extra.txt"), "v2", Encoding.UTF8);
                vault.Lock();
                Assert(!vault.LastLockSkippedSnapshot, "second edit rotates backup");

                string backupPath = Path.Combine(vault.Root, VaultSession.BackupName);
                byte[] dataHash = Paths.Hash(vault.Data);
                byte[] backupHash = Paths.Hash(backupPath);
                DateTime dataMtime = File.GetLastWriteTimeUtc(vault.Data);

                // 2. Read-only view + temporary lock file created and deleted (like Office ~$ files) => fast lock.
                vault.Unlock(Password);
                Assert(!vault.HasWorkspaceChanges(), "freshly unlocked workspace reports clean");
                string tempLock = Path.Combine(vault.Work, "sub", "~$note.txt");
                File.WriteAllText(tempLock, "temp-office-lock", Encoding.UTF8);
                Assert(vault.HasWorkspaceChanges(), "temporary file marks workspace dirty while present");
                File.Delete(tempLock);
                Assert(!vault.HasWorkspaceChanges(), "removing temporary file restores clean state");
                string workDir = vault.Work;
                vault.Lock();
                Assert(vault.LastLockSkippedSnapshot, "unchanged workspace skips snapshot on lock");
                Assert(!Directory.Exists(workDir) && !vault.Open, "fast lock cleans plaintext workspace and closes session");
                Assert(Paths.Equal(dataHash, Paths.Hash(vault.Data)) && File.GetLastWriteTimeUtc(vault.Data) == dataMtime, "fast lock leaves current ciphertext untouched");
                Assert(Paths.Equal(backupHash, Paths.Hash(backupPath)), "fast lock preserves previous backup snapshot");

                // 3. Zero changes but open write handle still blocks lock and preserves workspace.
                vault.Unlock(Password);
                string unlockedNote = Path.Combine(vault.Work, "sub", "note.txt");
                using (FileStream writer = new FileStream(unlockedNote, FileMode.Open, FileAccess.Write, FileShare.ReadWrite))
                    Fails(delegate { vault.Lock(); }, "open write handle blocks fast lock");
                Assert(vault.Open && !vault.CleanupPending && File.Exists(unlockedNote), "blocked fast lock preserves unlocked workspace");
                vault.Lock();
                Assert(vault.LastLockSkippedSnapshot, "closing write handle allows fast lock");

                // 4. Zero changes but external ciphertext tampering is still caught.
                vault.Unlock(Password);
                byte[] savedCipher = File.ReadAllBytes(vault.Data);
                File.AppendAllText(vault.Data, "tampered");
                Fails(delegate { vault.Lock(); }, "external ciphertext modification blocks fast lock");
                Assert(vault.Open && Directory.Exists(vault.Work), "tampered ciphertext preserves workspace");
                File.WriteAllBytes(vault.Data, savedCipher);
                vault.Lock();
                Assert(vault.LastLockSkippedSnapshot, "restoring ciphertext allows fast lock");

                // 5. Zero changes with open read handle enters CleanupPending and resumes cleanly.
                vault.Unlock(Password);
                string cleanupSession = vault.SessionRoot;
                using (FileStream reader = new FileStream(Path.Combine(vault.Work, "extra.txt"), FileMode.Open, FileAccess.Read, FileShare.Read))
                    Fails(delegate { vault.Lock(); }, "open read handle prevents fast-lock plaintext deletion");
                Assert(vault.CleanupPending && vault.LastLockSkippedSnapshot && vault.Open, "fast lock enters pending cleanup on read handle");
                vault.Lock();
                Assert(!Directory.Exists(cleanupSession) && !vault.Open, "retrying cleanup completes fast lock");
                Assert(Paths.Equal(dataHash, Paths.Hash(vault.Data)), "cleanup retry leaves ciphertext untouched");

                // 6. Same-size content modification triggers full snapshot.
                vault.Unlock(Password);
                string sameSizeNote = Path.Combine(vault.Work, "sub", "note.txt");
                File.WriteAllText(sameSizeNote, "WORLD", Encoding.UTF8);
                Assert(vault.HasWorkspaceChanges(), "same-size edit with updated timestamp marks workspace dirty");
                vault.Lock();
                Assert(!vault.LastLockSkippedSnapshot, "same-size edit forces full snapshot");

                // 7. Case-only rename triggers full snapshot.
                vault.Unlock(Password);
                string renamedNote = Path.Combine(vault.Work, "sub", "Note.txt");
                File.Move(Path.Combine(vault.Work, "sub", "note.txt"), renamedNote);
                Assert(vault.HasWorkspaceChanges(), "case-only rename marks workspace dirty");
                vault.Lock();
                Assert(!vault.LastLockSkippedSnapshot, "case-only rename forces full snapshot");

                // 8. Empty directory addition and deletion trigger full snapshot.
                vault.Unlock(Password);
                Directory.CreateDirectory(Path.Combine(vault.Work, "empty-dir"));
                Assert(vault.HasWorkspaceChanges(), "adding empty directory marks workspace dirty");
                vault.Lock();
                Assert(!vault.LastLockSkippedSnapshot, "adding empty directory forces full snapshot");

                vault.Unlock(Password);
                Directory.Delete(Path.Combine(vault.Work, "empty-dir"));
                Assert(vault.HasWorkspaceChanges(), "deleting empty directory marks workspace dirty");
                vault.Lock();
                Assert(!vault.LastLockSkippedSnapshot, "deleting empty directory forces full snapshot");

                // 9. Resumed workspace conservatively forces full snapshot even without further edits.
                vault.Unlock(Password);
                string abandoned = vault.SessionRoot;
                vault.Dispose();
                vault.Resume(abandoned, Password);
                Assert(vault.HasWorkspaceChanges(), "resumed workspace conservatively reports dirty");
                vault.Lock();
                Assert(!vault.LastLockSkippedSnapshot, "resumed workspace forces full snapshot");

                // Final integrity verification.
                vault.Unlock(Password);
                Assert(File.ReadAllText(Path.Combine(vault.Work, "sub", "Note.txt"), Encoding.UTF8) == "WORLD", "all edits persisted after mixed fast and full locks");
                vault.Lock();
                Assert(vault.LastLockSkippedSnapshot, "final read-only verification fast-locks cleanly");
            }
            Say("dirty-check fast lock skips snapshot when unchanged and safely falls back on edits, handles, tampering and recovery");
        }
        [StructLayout(LayoutKind.Sequential)] private struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CreateRestrictedToken(IntPtr token, uint flags, uint disableCount, ref SidAndAttributes disable, uint deleteCount, IntPtr privileges, uint restrictCount, IntPtr restricted, out IntPtr result);
        [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
        private static bool HasRule(FileSystemSecurity acl, SecurityIdentifier sid, AccessControlType type, FileSystemRights requiredRights)
        {
            return acl.GetAccessRules(true, false, typeof(SecurityIdentifier))
                .OfType<FileSystemAccessRule>()
                .Any(r => r.IdentityReference.Equals(sid) && r.AccessControlType == type && (r.FileSystemRights & requiredRights) == requiredRights);
        }
        private static void SealedAclRulesTest()
        {
            SecurityIdentifier admin = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            SecurityIdentifier system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            SecurityIdentifier user = WindowsIdentity.GetCurrent().User;

            DirectorySecurity dirAcl = Permissions.BuildSealedDirectoryAcl();
            Assert(dirAcl.AreAccessRulesProtected, "sealed directory disables ACL inheritance");
            Assert(HasRule(dirAcl, user, AccessControlType.Deny, Permissions.SealedDirectoryDeny), "sealed directory denies write and delete for user");
            Assert(HasRule(dirAcl, admin, AccessControlType.Deny, Permissions.SealedDirectoryDeny), "sealed directory denies write and delete for administrators");
            Assert(HasRule(dirAcl, system, AccessControlType.Deny, Permissions.SealedDirectoryDeny), "sealed directory denies write and delete for SYSTEM");
            Assert(HasRule(dirAcl, admin, AccessControlType.Allow, FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership | FileSystemRights.ReadAndExecute), "sealed directory preserves admin permission-management and read rights");
            Assert(!HasRule(dirAcl, admin, AccessControlType.Allow, FileSystemRights.WriteData), "sealed directory does not grant write allow to administrators");
            Assert(HasRule(dirAcl, system, AccessControlType.Allow, FileSystemRights.ReadAndExecute) && !HasRule(dirAcl, system, AccessControlType.Allow, FileSystemRights.WriteData), "sealed directory grants SYSTEM read-only allow");
            Assert(!HasRule(dirAcl, user, AccessControlType.Allow, FileSystemRights.ReadAttributes), "sealed directory grants no allow rules to ordinary user");

            FileSecurity fileAcl = Permissions.BuildSealedFileAcl();
            Assert(fileAcl.AreAccessRulesProtected, "sealed ciphertext disables ACL inheritance");
            Assert(HasRule(fileAcl, user, AccessControlType.Deny, Permissions.SealedFileDeny), "sealed ciphertext denies write and delete for user");
            Assert(HasRule(fileAcl, admin, AccessControlType.Deny, Permissions.SealedFileDeny), "sealed ciphertext denies write and delete for administrators");
            Assert(HasRule(fileAcl, system, AccessControlType.Deny, Permissions.SealedFileDeny), "sealed ciphertext denies write and delete for SYSTEM");
            Assert(HasRule(fileAcl, admin, AccessControlType.Allow, FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership | FileSystemRights.ReadAndExecute), "sealed ciphertext preserves admin permission-management and read rights");
            Assert(!HasRule(fileAcl, admin, AccessControlType.Allow, FileSystemRights.WriteData), "sealed ciphertext does not grant write allow to administrators");
            Assert(HasRule(fileAcl, system, AccessControlType.Allow, FileSystemRights.ReadAndExecute) && !HasRule(fileAcl, system, AccessControlType.Allow, FileSystemRights.WriteData), "sealed ciphertext grants SYSTEM read-only allow");

            FileSecurity entryAcl = Permissions.BuildProtectedEntryAcl();
            Assert(entryAcl.AreAccessRulesProtected, "protected shortcut disables ACL inheritance");
            Assert(HasRule(entryAcl, user, AccessControlType.Allow, FileSystemRights.ReadAndExecute), "protected shortcut allows user read-and-execute");
            Assert(HasRule(entryAcl, user, AccessControlType.Deny, Permissions.SealedFileDeny), "protected shortcut denies write and delete for user");
            Assert(HasRule(entryAcl, admin, AccessControlType.Deny, Permissions.SealedFileDeny), "protected shortcut denies write and delete for administrators");
            Assert(HasRule(entryAcl, system, AccessControlType.Deny, Permissions.SealedFileDeny), "protected shortcut denies write and delete for SYSTEM");
            Say("sealed ACL rules explicitly deny write and delete for user, administrators and SYSTEM while preserving authorized recovery rights");
        }
        private static void AclTest()
        {
            if (!Native.IsAdmin()) throw new UnauthorizedAccessException("ACL integration tests require an elevated process.");
            Native.LocalNtfs(container);
            // Use known permissions on the generated directory regardless of the checkout's inherited ACL.
            Permissions.Set(container, false);
            string root = Child("protected-folder"); Directory.CreateDirectory(root);
            File.WriteAllText(Path.Combine(root, "ciphertext.fixture"), "dummy ciphertext");
            Permissions.Seal(root);
            Assert(Directory.GetAccessControl(root).GetAccessRules(true, false, typeof(SecurityIdentifier)).OfType<FileSystemAccessRule>().Any(x => x.AccessControlType == AccessControlType.Deny && (x.FileSystemRights & FileSystemRights.Delete) != 0), "sealed folder denies deletion explicitly");
            Fails(delegate { Directory.Delete(root, true); }, "elevated process cannot directly delete sealed folder");
            Fails(delegate { File.Delete(Path.Combine(root, "ciphertext.fixture")); }, "elevated process cannot directly delete sealed ciphertext");
            Fails(delegate { File.WriteAllText(Path.Combine(root, "ciphertext.fixture"), "elevated tamper"); }, "elevated process cannot directly overwrite sealed ciphertext");
            Fails(delegate { File.AppendAllText(Path.Combine(root, "ciphertext.fixture"), "append"); }, "elevated process cannot directly append sealed ciphertext");
            Fails(delegate { File.WriteAllText(Path.Combine(root, "rogue.txt"), "injected"); }, "elevated process cannot directly create file in sealed folder");
            Fails(delegate { File.Move(Path.Combine(root, "ciphertext.fixture"), Path.Combine(root, "elevated-moved.fixture")); }, "elevated process cannot directly rename sealed ciphertext");
            string emptyRoot = Child("protected-empty"); Directory.CreateDirectory(emptyRoot); Permissions.Seal(emptyRoot);
            Assert(!Native.ParentAllowsDeleteChild(container), "ordinary parent has no DELETE_CHILD override");
            SecurityIdentifier admin = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            Assert(Directory.GetAccessControl(root).GetOwner(typeof(SecurityIdentifier)).Equals(admin), "folder owned by Administrators");
            Assert(File.GetAccessControl(Path.Combine(root, "ciphertext.fixture")).GetOwner(typeof(SecurityIdentifier)).Equals(admin), "ciphertext owned by Administrators");
            // Give the ordinary user full rights on the parent to test DELETE_CHILD bypass attempts.
            DirectorySecurity parentAcl = Directory.GetAccessControl(container);
            parentAcl.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User, FileSystemRights.FullControl, AccessControlType.Allow));
            Directory.SetAccessControl(container, parentAcl);
            Assert(Native.ParentAllowsDeleteChild(container), "parent DELETE_CHILD override detected");
            Fails(delegate { Native.RequireProtectedParent(container); }, "unsafe parent rejected before creating a vault");
            string safeParent = Child("safe-parent"); Directory.CreateDirectory(safeParent); Permissions.Set(safeParent, true);
            string safeRoot = Path.Combine(safeParent, "protected"); Directory.CreateDirectory(safeRoot);
            File.WriteAllText(Path.Combine(safeRoot, "dummy.fixture"), "dummy"); Permissions.Seal(safeRoot);
            Native.RequireProtectedParent(safeParent);
            byte[] sidBytes = new byte[admin.BinaryLength]; admin.GetBinaryForm(sidBytes, 0);
            IntPtr sid = Marshal.AllocHGlobal(sidBytes.Length), token = IntPtr.Zero, restricted = IntPtr.Zero;
            Marshal.Copy(sidBytes, 0, sid, sidBytes.Length);
            try
            {
                if (!OpenProcessToken(GetCurrentProcess(), 0x0002 | 0x0008 | 0x0001, out token)) throw new IOException("OpenProcessToken failed");
                SidAndAttributes disabled = new SidAndAttributes { Sid = sid, Attributes = 0 };
                if (!CreateRestrictedToken(token, 1, 1, ref disabled, 0, IntPtr.Zero, 0, IntPtr.Zero, out restricted)) throw new IOException("CreateRestrictedToken failed: " + Marshal.GetLastWin32Error());
                using (WindowsImpersonationContext context = WindowsIdentity.Impersonate(restricted))
                {
                    Assert(!Native.IsAdmin(), "test token has no administrator membership");
                    Fails(delegate { Directory.GetFiles(root); }, "ordinary folder listing blocked");
                    Fails(delegate { File.ReadAllText(Path.Combine(root, "ciphertext.fixture")); }, "ordinary ciphertext read blocked even with the exact path");
                    Fails(delegate { File.Delete(Path.Combine(root, "ciphertext.fixture")); }, "ordinary file deletion blocked");
                    Fails(delegate { File.WriteAllText(Path.Combine(root, "ciphertext.fixture"), "corrupt"); }, "ordinary overwrite blocked");
                    Fails(delegate { Directory.Delete(root, true); }, "recursive folder deletion blocked despite parent full control");
                    Fails(delegate { Directory.Delete(emptyRoot, false); }, "empty protected folder cannot be removed even when the parent allows it");
                    Fails(delegate { Directory.Move(safeRoot, Child("recycle-simulation")); }, "moving protected directory away is blocked at supported locations");
                }
                Assert(File.ReadAllText(Path.Combine(root, "ciphertext.fixture")) == "dummy ciphertext", "elevated backup can read the unchanged ciphertext");
                parentAcl.RemoveAccessRuleSpecific(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User, FileSystemRights.FullControl, AccessControlType.Allow));
                Directory.SetAccessControl(container, parentAcl);
                Native.RequireProtectedParent(container);
                using (VaultSession vault = new VaultSession(Child("protected-session"), Child("private-sessions"), true))
                {
                    vault.Create(Password);
                    File.WriteAllText(Path.Combine(vault.Work, "fixture.txt"), "protected session roundtrip");
                    vault.Lock();
                    using (WindowsIdentity.Impersonate(restricted))
                    {
                        Fails(delegate { Directory.GetFiles(vault.Root); }, "new locked vault rejects ordinary listing");
                        Fails(delegate { File.ReadAllBytes(vault.Data); }, "new locked vault rejects ordinary process reads");
                        Fails(delegate { File.WriteAllText(vault.Data, "invalid editor update"); }, "new locked vault rejects ordinary writes");
                        Fails(delegate { File.Delete(vault.Data); }, "new locked vault rejects ordinary deletion");
                        Fails(delegate { Directory.Move(vault.Root, Child("locked-vault-moved")); }, "new locked vault rejects ordinary moves");
                    }
                    Permissions.Set(vault.Root, false);
                    Permissions.Set(vault.Data, false);
                    using (WindowsIdentity.Impersonate(restricted))
                        Assert(File.ReadAllBytes(vault.Data).Length > 0, "legacy read permission is present in the migration fixture");
                    Fails(delegate { vault.RepairEntry("incorrect-password"); }, "shortcut repair requires the current vault password");
                    using (WindowsIdentity.Impersonate(restricted))
                        Assert(File.ReadAllBytes(vault.Data).Length > 0, "rejected repair leaves the vault access rules unchanged");
                    string entry = vault.RepairEntry(Password);
                    Fails(delegate { File.WriteAllText(entry, "tampered shortcut"); }, "elevated process cannot directly overwrite protected shortcut");
                    Assert(HasRule(File.GetAccessControl(entry), admin, AccessControlType.Deny, Permissions.SealedFileDeny), "protected shortcut denies write and delete for administrators");
                    using (WindowsIdentity.Impersonate(restricted))
                    {
                        Assert(File.ReadAllBytes(entry).Length > 0, "ordinary Explorer can read the branded entry");
                        Fails(delegate { File.WriteAllText(entry, "ordinary tamper"); }, "ordinary process cannot overwrite protected shortcut");
                        Fails(delegate { File.Delete(entry); }, "ordinary process cannot delete protected shortcut");
                        Fails(delegate { File.Move(entry, Child("ordinary-moved-entry.lnk")); }, "ordinary process cannot move protected shortcut");
                        Fails(delegate { Directory.GetFiles(vault.Root); }, "repair blocks ordinary folder listing");
                        Fails(delegate { File.ReadAllBytes(vault.Data); }, "repair restores ciphertext protection without opening the vault");
                    }
                    vault.Unlock(Password);
                    string workFile = Path.Combine(vault.Work, "fixture.txt");
                    string sessionNote = Path.Combine(vault.SessionRoot, "工作区说明.txt");
                    using (WindowsIdentity.Impersonate(restricted))
                    {
                        Fails(delegate { File.ReadAllBytes(vault.Data); }, "successful unlock removes the legacy ciphertext read permission");
                        Fails(delegate { Directory.GetFiles(vault.SessionRoot); }, "ordinary editor cannot list the private session container");
                        Fails(delegate { File.ReadAllBytes(sessionNote); }, "ordinary editor cannot read private session metadata");
                        Assert(File.ReadAllText(workFile) == "protected session roundtrip", "ordinary editor can read the decrypted workspace");
                        File.WriteAllText(workFile, "ordinary editor update");
                    }
                    vault.Lock();
                    Assert(!File.Exists(workFile), "locking removes the decrypted workspace");
                    vault.ChangePassword(Password, "RotatedPassword8");
                    vault.ChangePassword("RotatedPassword8", Password);
                    Fails(delegate { Directory.Delete(vault.Root, true); }, "sealed vault still blocks direct elevated deletion after password change");
                    Fails(delegate { File.WriteAllText(vault.Data, "tamper after rekey"); }, "sealed vault still blocks direct elevated overwrite after password change");
                    vault.Unlock(Password);
                    Assert(File.ReadAllText(Path.Combine(vault.Work, "fixture.txt")) == "ordinary editor update", "ordinary editor changes survive locking");
                    vault.Lock();
                    vault.HideEntry(Password);
                    Assert(!File.Exists(entry), "password-authorized hide removes the protected shortcut");
                    entry = vault.RepairEntry(Password);
                    Fails(delegate { File.WriteAllText(entry, "tamper recreated shortcut"); }, "recreated shortcut restores elevated write protection");
                    using (WindowsIdentity.Impersonate(restricted))
                        Fails(delegate { File.Delete(entry); }, "recreated shortcut restores ordinary delete protection");
                    Fails(delegate { vault.Delete("incorrect-password"); }, "protected delete rejects incorrect password");
                    vault.Delete(Password);
                    FolderEntry.Remove(vault.Root);
                    Assert(!File.Exists(entry), "authorized vault removal allows its protected shortcut to be removed");
                    Assert(!Directory.Exists(vault.Root), "protected folder deleted only by password-authorized operation");
                }
            }
            finally
            {
                if (restricted != IntPtr.Zero) CloseHandle(restricted);
                if (token != IntPtr.Zero) CloseHandle(token);
                Marshal.FreeHGlobal(sid);
            }
            Permissions.AllowDelete(emptyRoot); Directory.Delete(emptyRoot, false);
            Permissions.AllowDelete(root);
            Permissions.AllowDelete(safeRoot);
            Say("persistent NTFS protection blocks ordinary listing, reading, deletion, overwrite and moving");
            Say("full administrator-protected create/save/unlock/delete lifecycle");
        }
    }
}
