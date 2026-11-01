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
                else { PasswordBoundary(); RoundTrip(); Tamper(); PathValidation(); FailureSafety(); CleanupRecovery(); Concurrency(); DeleteAuthentication(); HardLinkTest(); }
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
                Fails(delegate { vault.Create("12345"); }, "five-character password rejected");
                Assert(!Directory.Exists(vault.Root), "short passwords create no vault directory");
                vault.Create("123456");
                Assert(vault.Open, "exactly six characters accepted");
                File.WriteAllText(Path.Combine(vault.Work, "fixture.txt"), "six-character password fixture");
                vault.Lock();
                Fails(delegate { vault.Unlock("654321"); }, "incorrect six-character password rejected");
                vault.Unlock("123456");
                Assert(File.ReadAllText(Path.Combine(vault.Work, "fixture.txt")) == "six-character password fixture", "six-character password roundtrip");
                vault.Lock(); vault.Delete("123456");
                Assert(!Directory.Exists(vault.Root), "six-character password authorizes deletion");
            }
            Say("minimum six characters, five rejected, correct unlock and authenticated deletion");
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
        [StructLayout(LayoutKind.Sequential)] private struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CreateRestrictedToken(IntPtr token, uint flags, uint disableCount, ref SidAndAttributes disable, uint deleteCount, IntPtr privileges, uint restrictCount, IntPtr restricted, out IntPtr result);
        [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
        private static void AclTest()
        {
            if (!Native.IsAdmin()) throw new UnauthorizedAccessException("ACL integration tests require an elevated process.");
            Native.LocalNtfs(container);
            string root = Child("protected-folder"); Directory.CreateDirectory(root);
            File.WriteAllText(Path.Combine(root, "ciphertext.fixture"), "dummy ciphertext");
            Permissions.Seal(root);
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
                    Assert(File.ReadAllText(Path.Combine(root, "ciphertext.fixture")) == "dummy ciphertext", "ordinary user can back up ciphertext");
                    Fails(delegate { File.Delete(Path.Combine(root, "ciphertext.fixture")); }, "ordinary file deletion blocked");
                    Fails(delegate { File.WriteAllText(Path.Combine(root, "ciphertext.fixture"), "corrupt"); }, "ordinary overwrite blocked");
                    Fails(delegate { Directory.Delete(root, true); }, "recursive folder deletion blocked despite parent full control");
                    Fails(delegate { Directory.Move(safeRoot, Child("recycle-simulation")); }, "moving protected directory away is blocked at supported locations");
                }
                Assert(File.Exists(Path.Combine(root, "ciphertext.fixture")), "ciphertext survives attempted deletion");
            }
            finally
            {
                if (restricted != IntPtr.Zero) CloseHandle(restricted);
                if (token != IntPtr.Zero) CloseHandle(token);
                Marshal.FreeHGlobal(sid);
            }
            Say("persistent NTFS protection, ordinary deletion/overwrite and administrator boundary");
            parentAcl.RemoveAccessRuleSpecific(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User, FileSystemRights.FullControl, AccessControlType.Allow));
            Directory.SetAccessControl(container, parentAcl);
            Native.RequireProtectedParent(container);
            using (VaultSession vault = new VaultSession(Child("protected-session"), Child("private-sessions"), true))
            {
                vault.Create(Password);
                File.WriteAllText(Path.Combine(vault.Work, "fixture.txt"), "protected session roundtrip");
                vault.Lock(); vault.Unlock(Password);
                Assert(File.ReadAllText(Path.Combine(vault.Work, "fixture.txt")) == "protected session roundtrip", "protected encrypted lifecycle");
                vault.Lock();
                Fails(delegate { vault.Delete("incorrect-password"); }, "protected delete rejects incorrect password");
                vault.Delete(Password);
                Assert(!Directory.Exists(vault.Root), "protected folder deleted only by password-authorized operation");
            }
            Say("full administrator-protected create/save/unlock/delete lifecycle");
        }
    }
}
