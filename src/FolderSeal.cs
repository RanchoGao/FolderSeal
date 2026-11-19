// Copyright (c) EurekaGao. Local-only Windows folder encryption tool.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace FolderSeal
{
    internal static class Paths
    {
        public static string Full(string path) { return Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar); }
        public static bool Inside(string path, string root)
        {
            return Full(path).StartsWith(Full(root) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }
        public static void NoLinks(string path)
        {
            string full = Path.GetFullPath(path);
            if (full.StartsWith(@"\\", StringComparison.Ordinal)) throw new IOException("仅支持本机 NTFS 磁盘，不支持网络共享。");
            string current = full;
            while (!String.IsNullOrEmpty(current))
            {
                if ((File.Exists(current) || Directory.Exists(current)) &&
                    (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("为避免越界操作，不支持链接、联接点和占位文件：" + current);
                DirectoryInfo parent = Directory.GetParent(current);
                current = parent == null ? null : parent.FullName;
            }
        }
        public static string Relative(string value)
        {
            string s = value.Replace('\\', '/');
            if (String.IsNullOrEmpty(s) || s.StartsWith("/") || s.Length > 200) throw new IOException("文件路径无效或过长。");
            string[] parts = s.TrimEnd('/').Split('/');
            foreach (string part in parts)
            {
                if (String.IsNullOrEmpty(part) || part == "." || part == ".." ||
                    part.EndsWith(".") || part.EndsWith(" ") || part.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
                    throw new IOException("文件名不安全：" + value);
                string stem = part.Split('.')[0].ToUpperInvariant();
                if (stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" ||
                    (stem.Length == 4 && (stem.StartsWith("COM") || stem.StartsWith("LPT")) && stem[3] >= '0' && stem[3] <= '9'))
                    throw new IOException("不支持 Windows 保留文件名。");
            }
            return s.TrimEnd('/');
        }
        public static string Target(string root, string relative)
        {
            string result = Path.Combine(root, Relative(relative).Replace('/', Path.DirectorySeparatorChar));
            if (!Inside(result, root) || result.Length >= 245) throw new IOException("文件路径过长或超出工作区。");
            return result;
        }
        public static List<string> Files(string root)
        {
            List<string> result = new List<string>();
            Walk(root, result, null);
            return result;
        }
        public static List<string> Directories(string root)
        {
            List<string> result = new List<string>();
            Walk(root, null, result);
            return result;
        }
        private static void Walk(string root, List<string> files, List<string> directories)
        {
            NoLinks(root);
            foreach (string child in Directory.GetFileSystemEntries(root).OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            {
                NoLinks(child);
                if (Directory.Exists(child))
                {
                    if (directories != null) directories.Add(child);
                    Walk(child, files, directories);
                }
                else if (files != null)
                {
                    Native.RejectHardLink(child);
                    files.Add(child);
                }
            }
        }
        public static void DeleteTree(string root)
        {
            NoLinks(root);
            foreach (string file in Directory.GetFiles(root))
            {
                NoLinks(file);
                Native.RejectHardLink(file);
                File.SetAttributes(file, File.GetAttributes(file) & ~FileAttributes.ReadOnly);
                File.Delete(file);
            }
            foreach (string directory in Directory.GetDirectories(root)) DeleteTree(directory);
            Directory.Delete(root, false);
        }
        public static byte[] Hash(string file)
        {
            NoLinks(file);
            using (FileStream stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (SHA256 sha = SHA256.Create()) return sha.ComputeHash(stream);
        }
        public static bool Equal(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
        public static string NameUnder(string root, string file) { return Relative(file.Substring(Full(root).Length + 1)); }
    }

    internal static class Native
    {
        [StructLayout(LayoutKind.Sequential)] private struct GenericMapping
        { public uint Read, Write, Execute, All; }
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr process, uint rights, out IntPtr token);
        [StructLayout(LayoutKind.Sequential)] private struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CreateRestrictedToken(IntPtr token, uint flags, uint disableCount, ref SidAndAttributes disable,
            uint deleteCount, IntPtr privileges, uint restrictCount, IntPtr restricted, out IntPtr result);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DuplicateToken(IntPtr token, int level, out IntPtr duplicate);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AccessCheck(byte[] descriptor, IntPtr token, uint desired, ref GenericMapping mapping,
            IntPtr privileges, ref uint length, out uint granted, out bool allowed);
        [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
        public static bool ParentAllowsDeleteChild(string parent)
        {
            IntPtr token = IntPtr.Zero, linked = IntPtr.Zero, impersonation = IntPtr.Zero, privileges = IntPtr.Zero, adminSid = IntPtr.Zero;
            try
            {
                if (!OpenProcessToken(GetCurrentProcess(), 0x0008 | 0x0002, out token)) throw new IOException("无法检查普通权限。");
                SecurityIdentifier admin = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                byte[] sidBytes = new byte[admin.BinaryLength]; admin.GetBinaryForm(sidBytes, 0);
                adminSid = Marshal.AllocHGlobal(sidBytes.Length); Marshal.Copy(sidBytes, 0, adminSid, sidBytes.Length);
                SidAndAttributes disabled = new SidAndAttributes { Sid = adminSid, Attributes = 0 };
                if (!CreateRestrictedToken(token, 1, 1, ref disabled, 0, IntPtr.Zero, 0, IntPtr.Zero, out linked))
                    throw new IOException("无法模拟普通权限，已停止创建保护目录。");
                if (!DuplicateToken(linked, 2, out impersonation)) throw new IOException("无法检查上级目录的有效权限：" + Marshal.GetLastWin32Error());
                byte[] descriptor = Directory.GetAccessControl(parent).GetSecurityDescriptorBinaryForm();
                GenericMapping mapping = new GenericMapping { Read = 0x120089, Write = 0x120116, Execute = 0x1200A0, All = 0x1F01FF };
                uint length = 1024, granted;
                bool allowed;
                privileges = Marshal.AllocHGlobal((int)length);
                if (!AccessCheck(descriptor, impersonation, 0x40, ref mapping, privileges, ref length, out granted, out allowed))
                    throw new IOException("无法核验上级目录删除权限：" + Marshal.GetLastWin32Error());
                return allowed;
            }
            finally
            {
                if (privileges != IntPtr.Zero) Marshal.FreeHGlobal(privileges);
                if (adminSid != IntPtr.Zero) Marshal.FreeHGlobal(adminSid);
                if (impersonation != IntPtr.Zero) CloseHandle(impersonation);
                if (linked != IntPtr.Zero) CloseHandle(linked);
                if (token != IntPtr.Zero) CloseHandle(token);
            }
        }
        public static void RequireProtectedParent(string parent)
        {
            LocalNtfs(parent);
            if (ParentAllowsDeleteChild(parent))
                throw new IOException("此上级目录允许普通用户绕过子目录权限，将整个文件夹移走或放入回收站，不能保证防删除。\r\n请选择其他符合权限要求的本机 NTFS 目录。本程序不会擅自修改上级目录权限。");
        }
        [StructLayout(LayoutKind.Sequential)] private struct FileInfoNative
        {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle handle, out FileInfoNative info);
        public static void RejectHardLink(string path)
        {
            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                FileInfoNative info;
                if (!GetFileInformationByHandle(stream.SafeFileHandle, out info)) throw new IOException("无法检查文件链接。");
                if (info.Links != 1) throw new IOException("不支持硬链接文件：" + path);
            }
        }
        public static bool IsAdmin()
        {
            return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        }
        public static void LocalNtfs(string parent)
        {
            Paths.NoLinks(parent);
            DriveInfo drive = new DriveInfo(Path.GetPathRoot(Path.GetFullPath(parent)));
            if (!drive.IsReady || !String.Equals(drive.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
                throw new IOException("防删除保护需要本机 NTFS 磁盘。");
        }
    }

    internal static class Permissions
    {
        private static readonly SecurityIdentifier Admin = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        private static readonly SecurityIdentifier SystemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        private static readonly SecurityIdentifier User = WindowsIdentity.GetCurrent().User;
        public static void Set(string path, bool writableUser)
        {
            Paths.NoLinks(path);
            bool directory = Directory.Exists(path);
            InheritanceFlags inheritance = directory ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None;
            FileSystemSecurity acl = directory ? (FileSystemSecurity)new DirectorySecurity() : new FileSecurity();
            acl.SetAccessRuleProtection(true, false);
            acl.SetOwner(Native.IsAdmin() ? Admin : User);
            acl.AddAccessRule(new FileSystemAccessRule(Admin, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(SystemSid, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(User, writableUser ? FileSystemRights.Modify : FileSystemRights.ReadAndExecute,
                inheritance, PropagationFlags.None, AccessControlType.Allow));
            if (directory) Directory.SetAccessControl(path, (DirectorySecurity)acl);
            else File.SetAccessControl(path, (FileSecurity)acl);
        }
        public static void Workspace(string root, bool writableUser)
        {
            // Validate the entire tree before changing ACLs, then recheck each item.
            List<string> files = Paths.Files(root);
            List<string> directories = Paths.Directories(root);
            Set(root, writableUser);
            foreach (string directory in directories) Set(directory, writableUser);
            foreach (string file in files) Set(file, writableUser);
        }
        public static void Seal(string root)
        {
            if (!Native.IsAdmin()) throw new UnauthorizedAccessException("启用防删除保护需要管理员权限。");
            Set(root, false);
            foreach (string file in Directory.GetFiles(root)) Set(file, false);
        }
    }

    internal sealed class KeySet : IDisposable
    {
        public readonly byte[] Encryption, Authentication;
        public KeySet(string password, byte[] salt, int iterations)
        {
            byte[] material;
            using (Rfc2898DeriveBytes kdf = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
                material = kdf.GetBytes(64);
            Encryption = material.Take(32).ToArray();
            Authentication = material.Skip(32).Take(32).ToArray();
            Array.Clear(material, 0, material.Length);
        }
        public void Dispose()
        {
            Array.Clear(Encryption, 0, Encryption.Length);
            Array.Clear(Authentication, 0, Authentication.Length);
        }
    }

    internal sealed class Header
    {
        public const int Size = 60;
        public const int IterationsDefault = 600000;
        private static readonly byte[] Magic = Encoding.ASCII.GetBytes("EGFOLD01");
        public int Iterations;
        public byte[] Salt, IV;
        public static byte[] Random(int count)
        {
            byte[] value = new byte[count];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(value);
            return value;
        }
        public static Header New() { return new Header { Iterations = IterationsDefault, Salt = Random(32), IV = Random(16) }; }
        public void Write(Stream stream)
        {
            using (BinaryWriter writer = new BinaryWriter(stream, Encoding.UTF8, true))
            { writer.Write(Magic); writer.Write(Iterations); writer.Write(Salt); writer.Write(IV); }
        }
        public static Header Read(string path)
        {
            Paths.NoLinks(path);
            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (BinaryReader reader = new BinaryReader(stream))
            {
                if (stream.Length < Size + 48 || (stream.Length - Size - 32) % 16 != 0 || !Paths.Equal(reader.ReadBytes(8), Magic))
                    throw new IOException("不是有效的加密文件，或文件已损坏。");
                int iterations = reader.ReadInt32();
                if (iterations < 100000 || iterations > 2000000) throw new IOException("不支持的密钥参数。");
                return new Header { Iterations = iterations, Salt = reader.ReadBytes(32), IV = reader.ReadBytes(16) };
            }
        }
    }

    internal sealed class LimitedStream : Stream
    {
        private readonly Stream source;
        private long remaining;
        public LimitedStream(Stream source, long size) { this.source = source; remaining = size; }
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (remaining == 0) return 0;
            int read = source.Read(buffer, offset, (int)Math.Min(count, remaining));
            if (read == 0) throw new EndOfStreamException();
            remaining -= read;
            return read;
        }
        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }
        public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
    }

    // .NET Framework ZipArchive requires a readable Position even for forward-only output.
    internal sealed class CountedWriteStream : Stream
    {
        private readonly Stream output;
        private long position;
        public CountedWriteStream(Stream output) { this.output = output; }
        public override bool CanRead { get { return false; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return true; } }
        public override long Length { get { return position; } }
        public override long Position { get { return position; } set { throw new NotSupportedException(); } }
        public override void Write(byte[] buffer, int offset, int count) { output.Write(buffer, offset, count); position += count; }
        public override void Flush() { output.Flush(); }
        public override int Read(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }
    }

    internal sealed class EntryStamp
    {
        public string Name;
        public byte[] Hash;
        public long Size;
        public bool Directory;
    }

    internal static class ArchiveCrypto
    {
        public static void Authenticate(string path, KeySet keys)
        {
            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (HMACSHA256 hmac = new HMACSHA256(keys.Authentication))
            {
                long length = stream.Length - 32;
                if (length <= Header.Size) throw new IOException("加密文件已截断。");
                byte[] actual = hmac.ComputeHash(new LimitedStream(stream, length));
                byte[] expected = new byte[32];
                if (stream.Read(expected, 0, expected.Length) != expected.Length || !Paths.Equal(actual, expected))
                    throw new CryptographicException("密码不正确，或加密文件已被修改/损坏。未解密任何文件。");
            }
        }
        public static List<EntryStamp> Encrypt(string work, string output, Header header, KeySet keys)
        {
            Paths.NoLinks(work);
            List<string> directories = Paths.Directories(work), files = Paths.Files(work);
            List<EntryStamp> manifest = new List<EntryStamp>();
            header.IV = Header.Random(16);
            using (FileStream destination = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                header.Write(destination);
                using (Aes aes = Aes.Create())
                {
                    aes.Key = keys.Encryption; aes.IV = header.IV; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
                    using (CryptoStream encrypted = new CryptoStream(destination, aes.CreateEncryptor(), CryptoStreamMode.Write, true))
                    {
                        using (ZipArchive zip = new ZipArchive(new CountedWriteStream(encrypted), ZipArchiveMode.Create, true, Encoding.UTF8))
                        {
                            foreach (string directory in directories)
                            {
                                string relative = Paths.NameUnder(work, directory);
                                zip.CreateEntry(relative + "/");
                                manifest.Add(new EntryStamp { Name = relative, Directory = true });
                            }
                            foreach (string file in files)
                            {
                                string relative = Paths.NameUnder(work, file);
                                ZipArchiveEntry entry = zip.CreateEntry(relative, CompressionLevel.Optimal);
                                DateTime time = File.GetLastWriteTime(file);
                                if (time.Year >= 1980 && time.Year <= 2107) entry.LastWriteTime = new DateTimeOffset(time);
                                using (FileStream source = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
                                {
                                    using (Stream entryStream = entry.Open()) source.CopyTo(entryStream);
                                    source.Position = 0;
                                    using (SHA256 sha = SHA256.Create()) manifest.Add(new EntryStamp { Name = relative, Size = source.Length, Hash = sha.ComputeHash(source) });
                                }
                            }
                        }
                        encrypted.FlushFinalBlock();
                    }
                }
                destination.Flush(true);
            }
            byte[] tag;
            using (FileStream source = new FileStream(output, FileMode.Open, FileAccess.Read, FileShare.None))
            using (HMACSHA256 hmac = new HMACSHA256(keys.Authentication)) tag = hmac.ComputeHash(source);
            using (FileStream destination = new FileStream(output, FileMode.Append, FileAccess.Write, FileShare.None))
            { destination.Write(tag, 0, tag.Length); destination.Flush(true); }
            return manifest;
        }
        public static void DecryptZip(string path, string output, Header header, KeySet keys)
        {
            Authenticate(path, keys);
            using (FileStream source = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (Aes aes = Aes.Create())
            {
                aes.Key = keys.Encryption; aes.IV = header.IV; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
                source.Position = Header.Size;
                using (CryptoStream decrypted = new CryptoStream(new LimitedStream(source, source.Length - Header.Size - 32), aes.CreateDecryptor(), CryptoStreamMode.Read))
                using (FileStream destination = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                { decrypted.CopyTo(destination); destination.Flush(true); }
            }
        }
        private static List<ZipArchiveEntry> Entries(ZipArchive zip)
        {
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            List<ZipArchiveEntry> result = new List<ZipArchiveEntry>();
            foreach (ZipArchiveEntry entry in zip.Entries)
            {
                string relative = Paths.Relative(entry.FullName);
                if (!seen.Add(relative) || ((entry.ExternalAttributes >> 16) & 0xF000) == 0xA000)
                    throw new IOException("加密包包含重复文件名或符号链接。");
                result.Add(entry);
            }
            return result;
        }
        public static void Extract(string zipPath, string destination)
        {
            using (ZipArchive zip = ZipFile.OpenRead(zipPath))
            {
                List<ZipArchiveEntry> entries = Entries(zip);
                // Validate every target before extracting the first byte.
                foreach (ZipArchiveEntry entry in entries) Paths.Target(destination, entry.FullName);
                foreach (ZipArchiveEntry entry in entries)
                {
                    string target = Paths.Target(destination, entry.FullName);
                    if (entry.FullName.EndsWith("/")) Directory.CreateDirectory(target);
                    else
                    {
                        Directory.CreateDirectory(Path.GetDirectoryName(target));
                        using (Stream input = entry.Open())
                        using (FileStream output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None)) input.CopyTo(output);
                        File.SetLastWriteTime(target, entry.LastWriteTime.LocalDateTime);
                    }
                }
            }
        }
        public static void Verify(string zipPath, List<EntryStamp> expected)
        {
            using (ZipArchive zip = ZipFile.OpenRead(zipPath))
            {
                List<ZipArchiveEntry> entries = Entries(zip);
                if (entries.Count != expected.Count) throw new IOException("加密验证失败：文件数量不符。");
                Dictionary<string, EntryStamp> index = expected.ToDictionary(x => x.Name, StringComparer.OrdinalIgnoreCase);
                foreach (ZipArchiveEntry entry in entries)
                {
                    EntryStamp stamp;
                    if (!index.TryGetValue(Paths.Relative(entry.FullName), out stamp) || stamp.Directory != entry.FullName.EndsWith("/"))
                        throw new IOException("加密验证失败：文件列表不符。");
                    if (!stamp.Directory)
                    {
                        using (Stream input = entry.Open())
                        using (SHA256 sha = SHA256.Create())
                            if (entry.Length != stamp.Size || !Paths.Equal(sha.ComputeHash(input), stamp.Hash)) throw new IOException("加密验证失败：文件内容不符。");
                    }
                }
            }
        }
        public static void CheckWorkspace(string work, List<EntryStamp> expected)
        {
            List<string> files = Paths.Files(work), directories = Paths.Directories(work);
            if (files.Count + directories.Count != expected.Count) throw new IOException("工作区在保存过程中发生变化，请关闭编辑器后重试。");
            foreach (EntryStamp entry in expected)
            {
                string path = Paths.Target(work, entry.Name);
                if (entry.Directory ? !Directory.Exists(path) : !File.Exists(path) || !Paths.Equal(Paths.Hash(path), entry.Hash))
                    throw new IOException("工作区在保存过程中发生变化，请关闭编辑器后重试。");
            }
        }
    }

    internal sealed class VaultSession : IDisposable
    {
        public const string DataName = "内容.egvault", BackupName = "上一版本.egvault", GateName = ".access.lock";
        public string Root, SessionRoot, Work;
        public bool Open { get { return keys != null; } }
        public bool CleanupPending { get; private set; }
        private KeySet keys;
        private Header header;
        private FileStream gate;
        private byte[] baseline;
        private readonly string sessionsBase;
        private readonly bool protect;
        public VaultSession(string root, string sessionsBase, bool protect)
        {
            Root = Paths.Full(root); this.sessionsBase = sessionsBase; this.protect = protect;
        }
        public string Data { get { return Path.Combine(Root, DataName); } }
        private void CheckRoot()
        {
            Paths.NoLinks(Root);
            if (!Directory.Exists(Root)) throw new IOException("加密文件夹不存在。");
            if (Directory.GetDirectories(Root).Length != 0) throw new IOException("加密目录含有未知子文件夹，已停止操作。");
            foreach (string file in Directory.GetFiles(Root))
            {
                string name = Path.GetFileName(file);
                if (name != DataName && name != BackupName && name != GateName &&
                    !(name.StartsWith(".pending-", StringComparison.Ordinal) && name.EndsWith(".egvault", StringComparison.Ordinal)))
                    throw new IOException("加密目录含有未知文件，已停止操作：" + name);
                Paths.NoLinks(file);
                if (name != GateName || gate == null) Native.RejectHardLink(file);
            }
        }
        private void Acquire()
        {
            CheckRoot();
            string gatePath = Path.Combine(Root, GateName);
            if (!File.Exists(gatePath))
            {
                using (FileStream marker = new FileStream(gatePath, FileMode.CreateNew, FileAccess.Write, FileShare.None)) marker.WriteByte(1);
            }
            if (protect) Permissions.Set(gatePath, false);
            gate = new FileStream(gatePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        }
        private void NewWorkspace()
        {
            Paths.NoLinks(sessionsBase);
            Directory.CreateDirectory(sessionsBase);
            SessionRoot = Path.Combine(sessionsBase, Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(SessionRoot);
            if (protect) Permissions.Set(SessionRoot, true);
            Work = Path.Combine(SessionRoot, "编辑区");
            Directory.CreateDirectory(Work);
            File.WriteAllText(Path.Combine(SessionRoot, "工作区说明.txt"), "未锁定的明文工作区。对应加密目录：\r\n" + Root + "\r\n请回到程序中恢复并锁定，不要直接删除。", Encoding.UTF8);
        }
        public void Create(string password)
        {
            if (password.Length < 6) throw new ArgumentException("密码至少需要 6 个字符。");
            if (Directory.Exists(Root) || File.Exists(Root)) throw new IOException("请使用尚不存在的新文件夹名称。");
            Paths.NoLinks(Path.GetDirectoryName(Root));
            if (protect) Native.RequireProtectedParent(Path.GetDirectoryName(Root));
            Directory.CreateDirectory(Root);
            if (protect) Permissions.Seal(Root);
            try
            {
                Acquire();
                header = Header.New(); keys = new KeySet(password, header.Salt, header.Iterations);
                NewWorkspace();
                SaveSnapshot();
            }
            catch { Dispose(); throw; }
        }
        public void Unlock(string password)
        {
            if (Open) throw new InvalidOperationException("当前文件夹已经解锁。");
            if (protect) Native.RequireProtectedParent(Path.GetDirectoryName(Root));
            Acquire();
            try
            {
                header = Header.Read(Data);
                keys = new KeySet(password, header.Salt, header.Iterations);
                ArchiveCrypto.Authenticate(Data, keys);
                NewWorkspace();
                string zip = Path.Combine(SessionRoot, "解密临时.zip");
                try { ArchiveCrypto.DecryptZip(Data, zip, header, keys); ArchiveCrypto.Extract(zip, Work); }
                finally { if (File.Exists(zip)) File.Delete(zip); }
                if (protect) Permissions.Workspace(Work, true);
                baseline = Paths.Hash(Data);
                if (protect) Permissions.Seal(Root);
            }
            catch
            {
                try { if (SessionRoot != null && Directory.Exists(SessionRoot)) Paths.DeleteTree(SessionRoot); }
                finally { SessionRoot = null; Work = null; Dispose(); }
                throw;
            }
        }
        public void Resume(string existingSession, string password)
        {
            if (Open) throw new InvalidOperationException();
            if (protect) Native.RequireProtectedParent(Path.GetDirectoryName(Root));
            Paths.NoLinks(existingSession);
            if (!Paths.Inside(existingSession, sessionsBase)) throw new IOException("不是本程序的工作区。");
            Acquire();
            try
            {
                header = Header.Read(Data); keys = new KeySet(password, header.Salt, header.Iterations);
                ArchiveCrypto.Authenticate(Data, keys);
                SessionRoot = Paths.Full(existingSession); Work = Path.Combine(SessionRoot, "编辑区");
                baseline = Paths.Hash(Data);
                string marker = Path.Combine(SessionRoot, "清理状态.txt");
                if (File.Exists(marker))
                {
                    string expected = Root + "\r\n" + Convert.ToBase64String(baseline);
                    if (File.ReadAllText(marker) != expected) throw new IOException("待清理工作区与当前密文版本不一致，已停止恢复。");
                    CleanupPending = true;
                }
                else
                {
                    if (!Directory.Exists(Work)) throw new IOException("找不到可恢复的编辑区。");
                    Paths.Files(Work); if (protect) Permissions.Workspace(Work, true);
                }
            }
            catch { Dispose(); throw; }
        }
        private void SaveSnapshot()
        {
            if (keys == null) throw new InvalidOperationException("请先解锁。");
            CheckRoot();
            if (baseline != null && (!File.Exists(Data) || !Paths.Equal(Paths.Hash(Data), baseline)))
                throw new IOException("磁盘上的加密版本已改变，为避免覆盖，已停止保存。明文工作区保留。");
            string stage = Path.Combine(Root, ".pending-" + Guid.NewGuid().ToString("N") + ".egvault");
            string verify = Path.Combine(SessionRoot, "验证临时.zip");
            try
            {
                List<EntryStamp> stamps = ArchiveCrypto.Encrypt(Work, stage, header, keys);
                ArchiveCrypto.DecryptZip(stage, verify, Header.Read(stage), keys);
                ArchiveCrypto.Verify(verify, stamps);
                ArchiveCrypto.CheckWorkspace(Work, stamps);
                File.Delete(verify);
                if (File.Exists(Data))
                {
                    string backup = Path.Combine(Root, BackupName);
                    if (File.Exists(backup)) File.Delete(backup);
                    File.Replace(stage, Data, backup, false);
                }
                else File.Move(stage, Data);
                baseline = Paths.Hash(Data);
                if (protect) Permissions.Seal(Root);
            }
            finally
            {
                if (File.Exists(verify)) File.Delete(verify);
                if (File.Exists(stage)) File.Delete(stage);
            }
        }
        public void Lock()
        {
            if (!Open) throw new InvalidOperationException("当前文件夹未解锁。");
            if (!CleanupPending)
            {
                if (protect) Permissions.Workspace(Work, false);
                try
                {
                    SaveSnapshot();
                    string marker = Path.Combine(SessionRoot, "清理状态.txt");
                    byte[] content = Encoding.UTF8.GetBytes(Root + "\r\n" + Convert.ToBase64String(baseline));
                    using (FileStream output = new FileStream(marker, FileMode.Create, FileAccess.Write, FileShare.None))
                    { output.Write(content, 0, content.Length); output.Flush(true); }
                    if (protect) Permissions.Set(marker, false);
                    CleanupPending = true;
                }
                catch
                {
                    if (protect && Directory.Exists(Work)) Permissions.Workspace(Work, true);
                    throw;
                }
            }
            // Never re-encrypt a partially cleaned workspace. The committed snapshot is authoritative.
            if (Directory.Exists(Work)) Paths.DeleteTree(Work);
            foreach (string child in Directory.GetFileSystemEntries(SessionRoot))
            {
                string name = Path.GetFileName(child);
                if (name != "清理状态.txt" && name != "工作区说明.txt" && name != "验证临时.zip" && name != "解密临时.zip")
                    throw new IOException("工作区有未知项目，明文清理尚未完成：" + name);
                Paths.NoLinks(child); Native.RejectHardLink(child);
            }
            foreach (string name in new[] { "工作区说明.txt", "验证临时.zip", "解密临时.zip" })
            { string path = Path.Combine(SessionRoot, name); if (File.Exists(path)) File.Delete(path); }
            File.Delete(Path.Combine(SessionRoot, "清理状态.txt"));
            Directory.Delete(SessionRoot, false);
            SessionRoot = null; Work = null; CleanupPending = false;
            Dispose();
        }
        public void ImportFile(string source)
        {
            if (!Open || CleanupPending) throw new InvalidOperationException("请先解锁，或完成上次的明文清理。");
            Paths.NoLinks(source); Native.RejectHardLink(source);
            if (Paths.Inside(source, Root) || Paths.Inside(source, Work)) throw new IOException("不能导入当前加密目录或工作区中的文件。");
            string target = Paths.Target(Work, Path.GetFileName(source));
            if (File.Exists(target) || Directory.Exists(target)) throw new IOException("编辑区中已有同名文件：" + Path.GetFileName(source));
            File.Copy(source, target, false);
            File.SetAttributes(target, File.GetAttributes(target) & ~FileAttributes.ReadOnly);
            if (protect) Permissions.Set(target, true);
        }
        public void ImportFolder(string source)
        {
            if (!Open || CleanupPending) throw new InvalidOperationException("请先解锁，或完成上次的明文清理。");
            Paths.NoLinks(source);
            if (Paths.Inside(Root, source) || Paths.Inside(source, Root) || Paths.Inside(source, Work) || Paths.Full(source) == Root)
                throw new IOException("源文件夹与加密目录或编辑区不能相互包含。");
            List<string> files = Paths.Files(source), directories = Paths.Directories(source);
            string target = Paths.Target(Work, new DirectoryInfo(source).Name);
            if (Directory.Exists(target) || File.Exists(target)) throw new IOException("编辑区已有同名文件夹。");
            Directory.CreateDirectory(target);
            foreach (string directory in directories) Directory.CreateDirectory(Paths.Target(target, Paths.NameUnder(source, directory)));
            foreach (string file in files) File.Copy(file, Paths.Target(target, Paths.NameUnder(source, file)), false);
            if (protect) Permissions.Workspace(target, true);
        }
        public void Delete(string password)
        {
            if (Open) throw new InvalidOperationException("请先锁定再删除。");
            Acquire();
            try
            {
                Header current = Header.Read(Data);
                using (KeySet supplied = new KeySet(password, current.Salt, current.Iterations)) ArchiveCrypto.Authenticate(Data, supplied);
                // Only the known, authenticated folder layout is eligible for deletion.
                CheckRoot();
                foreach (string file in Directory.GetFiles(Root))
                    if (Path.GetFileName(file) != GateName) File.Delete(file);
                gate.Dispose(); gate = null;
                File.Delete(Path.Combine(Root, GateName));
                Directory.Delete(Root, false);
            }
            finally { if (gate != null) { gate.Dispose(); gate = null; } }
        }
        public void Dispose()
        {
            if (keys != null) { keys.Dispose(); keys = null; }
            if (gate != null) { gate.Dispose(); gate = null; }
        }
    }

    internal sealed class PasswordDialog : Form
    {
        private readonly TextBox first = new TextBox(), second = new TextBox();
        private readonly bool creating;
        public string Value { get; private set; }
        public PasswordDialog(bool creating, string title)
        {
            this.creating = creating; Text = title; Width = 490; Height = creating ? 285 : 225;
            Font = new Font("Microsoft YaHei UI", 10); StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false;
            TableLayoutPanel layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(22), ColumnCount = 1, RowCount = creating ? 6 : 4 };
            layout.Controls.Add(new Label { Text = creating ? "设置密码（至少 6 个字符，请自行妥善保存）" : "输入此加密文件夹的密码", AutoSize = true });
            first.UseSystemPasswordChar = true; first.Dock = DockStyle.Top; layout.Controls.Add(first);
            if (creating)
            {
                layout.Controls.Add(new Label { Text = "再次输入密码", AutoSize = true });
                second.UseSystemPasswordChar = true; second.Dock = DockStyle.Top; layout.Controls.Add(second);
            }
            layout.Controls.Add(new Label { Text = "密码只在本机处理；忘记密码无法恢复。", AutoSize = true, ForeColor = Color.DimGray });
            FlowLayoutPanel buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, Height = 42 };
            Button ok = new Button { Text = "确认", Width = 90, Height = 32 };
            Button cancel = new Button { Text = "取消", Width = 90, Height = 32, DialogResult = DialogResult.Cancel };
            ok.Click += delegate
            {
                if (creating && first.Text.Length < 6) { MessageBox.Show(this, "密码至少需要 6 个字符。"); return; }
                if (creating && first.Text != second.Text) { MessageBox.Show(this, "两次输入的密码不同。"); return; }
                if (first.Text.Length == 0) return;
                Value = first.Text; first.Clear(); second.Clear(); DialogResult = DialogResult.OK;
            };
            buttons.Controls.Add(ok); buttons.Controls.Add(cancel); layout.Controls.Add(buttons); Controls.Add(layout);
            AcceptButton = ok; CancelButton = cancel; Shown += delegate { first.Focus(); };
        }
        protected override void Dispose(bool disposing) { Value = null; if (disposing) { first.Clear(); second.Clear(); } base.Dispose(disposing); }
    }

    internal sealed class NameDialog : Form
    {
        private readonly TextBox input = new TextBox();
        public string FolderName { get { return input.Text.Trim(); } }
        public NameDialog()
        {
            Text = "加密文件夹名称"; Width = 500; Height = 180; StartPosition = FormStartPosition.CenterParent;
            Font = new Font("Microsoft YaHei UI", 10); FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false;
            input.Text = "私密资料_V1_" + DateTime.Now.ToString("yyyy-MM-dd"); input.SetBounds(20, 25, 440, 30);
            Button ok = new Button { Text = "下一步", Left = 350, Top = 75, Width = 110, Height = 34 };
            ok.Click += delegate
            {
                try { if (Paths.Relative(FolderName).IndexOf('/') >= 0) throw new IOException(); DialogResult = DialogResult.OK; }
                catch { MessageBox.Show(this, "请输入有效的单个文件夹名称。"); }
            };
            Controls.Add(input); Controls.Add(ok); AcceptButton = ok;
        }
    }


    internal static class FolderEntry
    {
        public static string Create(string root, bool protect)
        {
            root = Paths.Full(root); Paths.NoLinks(root);
            Header.Read(Path.Combine(root, VaultSession.DataName));
            string entry = root + ".lnk";
            if (File.Exists(entry) || Directory.Exists(entry)) throw new IOException("同名入口已存在，未覆盖：" + entry);
            object shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell"));
            object link = null;
            try
            {
                link = shell.GetType().InvokeMember("CreateShortcut", System.Reflection.BindingFlags.InvokeMethod, null, shell, new object[] { entry });
                Set(link, "TargetPath", Application.ExecutablePath);
                Set(link, "Arguments", "--open-vault \"" + root + "\"");
                Set(link, "WorkingDirectory", Path.GetDirectoryName(Application.ExecutablePath));
                Set(link, "IconLocation", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "shell32.dll") + ",3");
                Set(link, "Description", "输入密码打开加密文件夹；使用结束后请保存并锁定。");
                link.GetType().InvokeMember("Save", System.Reflection.BindingFlags.InvokeMethod, null, link, null);
                if (!File.Exists(entry)) throw new IOException("入口创建失败。");
                if (protect) Permissions.Set(entry, false);
                File.SetAttributes(root, File.GetAttributes(root) | FileAttributes.Hidden);
                return entry;
            }
            finally
            {
                if (link != null) Marshal.FinalReleaseComObject(link);
                Marshal.FinalReleaseComObject(shell);
            }
        }
        private static void Set(object target, string property, object value)
        {
            target.GetType().InvokeMember(property, System.Reflection.BindingFlags.SetProperty, null, target, new object[] { value });
        }
    }

    internal sealed class MainForm : Form
    {
        private static readonly Color Green = Color.FromArgb(36, 91, 70), Ink = Color.FromArgb(38, 60, 50), Muted = Color.FromArgb(82, 103, 87), Line = Color.FromArgb(218, 229, 213);
        private readonly TextBox selected = new TextBox { ReadOnly = true, Dock = DockStyle.Fill, BorderStyle = BorderStyle.None, BackColor = Color.FromArgb(244, 248, 238), ForeColor = Muted, TabStop = true };
        private readonly Label status = new Label { Dock = DockStyle.Fill, ForeColor = Muted, TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true };
        private readonly Label hint = new Label { Dock = DockStyle.Fill, ForeColor = Color.FromArgb(121, 80, 25), Padding = new Padding(0, 5, 0, 0) };
        private readonly ListView files = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = false, BorderStyle = BorderStyle.None, HideSelection = false, BackColor = Color.White };
        private readonly FlowLayoutPanel actions = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(0, 6, 0, 0) };
        private readonly Label vaultName = new Label { Dock = DockStyle.Fill, Font = new Font("Microsoft YaHei UI", 14, FontStyle.Bold), ForeColor = Ink, AutoEllipsis = true, TextAlign = ContentAlignment.MiddleLeft };
        private readonly Label badge = new Label { AutoSize = true, Padding = new Padding(9, 5, 9, 5), Margin = new Padding(0, 7, 0, 0), ForeColor = Green, BackColor = Color.FromArgb(230, 240, 222) };
        private readonly Label noticeTitle = new Label { Dock = DockStyle.Fill, Font = new Font("Microsoft YaHei UI", 10, FontStyle.Bold), TextAlign = ContentAlignment.MiddleLeft };
        private readonly Panel notice = new Panel { Dock = DockStyle.Fill, Padding = new Padding(15, 9, 15, 8), Margin = new Padding(0, 12, 0, 10) };
        private readonly Label empty = new Label { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter, ForeColor = Muted, Padding = new Padding(24), BackColor = Color.FromArgb(250, 252, 247) };
        private readonly Label count = new Label { AutoSize = true, ForeColor = Muted, Margin = new Padding(12, 15, 0, 0) };
        private readonly Label caption = new Label { Dock = DockStyle.Fill, ForeColor = Muted, TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true };
        private readonly Label availability = new Label { Dock = DockStyle.Fill, ForeColor = Muted, AutoEllipsis = true };
        private readonly Label switchReason = new Label { Dock = DockStyle.Fill, ForeColor = Muted };
        private readonly ProgressBar progress = new ProgressBar { Dock = DockStyle.Bottom, Height = 3, Style = ProgressBarStyle.Marquee, MarqueeAnimationSpeed = 35, Visible = false };
        private readonly ToolTip tips = new ToolTip { AutoPopDelay = 15000 };
        private readonly string sessionsBase = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "EurekaGao", "FolderSeal", "Sessions");
        private readonly string pendingSource;
        private VaultSession session;
        private bool busy, closing, operationFailed;
        private string lastFailure;
        private Button create, choose, unlock, show, importFiles, importFolder, lockButton, delete, recover, entryButton, primaryCreate;
        public MainForm(string source, string openRoot)
        {
            pendingSource = source;
            Text = "FolderSeal · 文件夹加密工具 · EurekaGao";
            Font = new Font("Microsoft YaHei UI", 10); AutoScaleMode = AutoScaleMode.Dpi; AutoScaleDimensions = new SizeF(96, 96);
            ClientSize = new Size(1160, 820); MinimumSize = new Size(1080, 800); StartPosition = FormStartPosition.CenterScreen;
            BackColor = Color.White; ForeColor = Ink; KeyPreview = true;
            TableLayoutPanel shell = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
            shell.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 212)); shell.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            shell.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            TableLayoutPanel sidebar = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = Color.FromArgb(247, 249, 244), Padding = new Padding(18, 27, 18, 18), ColumnCount = 1, RowCount = 8 };
            foreach (int h in new[] { 43, 49, 48, 58, 58, 96 }) sidebar.RowStyles.Add(new RowStyle(SizeType.Absolute, h));
            sidebar.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); sidebar.RowStyles.Add(new RowStyle(SizeType.Absolute, 74));
            sidebar.Controls.Add(new Label { Text = "FolderSeal", Dock = DockStyle.Fill, Font = new Font(Font.FontFamily, 20, FontStyle.Bold), ForeColor = Green }, 0, 0);
            sidebar.Controls.Add(new Label { Text = "你的文件，安心保管。", Dock = DockStyle.Fill, ForeColor = Muted }, 0, 1);
            sidebar.Controls.Add(new Label { Text = "▣  加密文件夹", Dock = DockStyle.Fill, BackColor = Color.FromArgb(229, 237, 223), ForeColor = Green, Padding = new Padding(10, 12, 0, 0) }, 0, 2);
            create = Add("＋ 创建加密文件夹", CreateVault); choose = Add("选择已有文件夹", ChooseVault);
            create.Dock = choose.Dock = DockStyle.Fill; create.Margin = choose.Margin = new Padding(0, 11, 0, 3);
            sidebar.Controls.Add(create, 0, 3); sidebar.Controls.Add(choose, 0, 4);
            switchReason.Padding = new Padding(2, 12, 0, 0); sidebar.Controls.Add(switchReason, 0, 5);
            sidebar.Controls.Add(new Label { Text = "● 仅在本机处理\r\n无需账号，不上传文件。\r\n每个文件夹独立设置密码。", Dock = DockStyle.Fill, ForeColor = Muted }, 0, 7);
            TableLayoutPanel body = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(27, 24, 27, 12), ColumnCount = 1, RowCount = 10 };
            body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            foreach (int h in new[] { 73, 108, 120, 55 }) body.RowStyles.Add(new RowStyle(SizeType.Absolute, h));
            body.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            foreach (int h in new[] { 36, 50, 39, 47, 31 }) body.RowStyles.Add(new RowStyle(SizeType.Absolute, h));
            TableLayoutPanel heading = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 2 };
            heading.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); heading.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 112));
            heading.RowStyles.Add(new RowStyle(SizeType.Absolute, 40)); heading.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            heading.Controls.Add(new Label { Text = "加密文件夹", Dock = DockStyle.Fill, Font = new Font(Font.FontFamily, 19, FontStyle.Bold) }, 0, 0);
            heading.Controls.Add(new Label { Text = "解锁后照常编辑，用完请保存并锁定。", Dock = DockStyle.Fill, ForeColor = Muted }, 0, 1);
            Button help = Add("使用帮助 ↗", ShowHelp); heading.Controls.Add(help, 1, 0);
            body.Controls.Add(heading, 0, 0);
            TableLayoutPanel card = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = Color.FromArgb(244, 248, 238), Padding = new Padding(17, 12, 16, 11), ColumnCount = 2, RowCount = 2 };
            card.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); card.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 205));
            card.RowStyles.Add(new RowStyle(SizeType.Absolute, 45)); card.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            TableLayoutPanel identity = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1 };
            identity.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); identity.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            identity.Controls.Add(vaultName, 0, 0); identity.Controls.Add(badge, 1, 0); card.Controls.Add(identity, 0, 0);
            selected.Font = new Font(Font.FontFamily, 9); selected.AccessibleName = "加密目录位置"; card.Controls.Add(selected, 0, 1);
            unlock = Add("输入密码解锁", UnlockVault); lockButton = Add("保存并锁定", LockVault); Primary(unlock); Primary(lockButton);
            Panel primaryArea = new Panel { Dock = DockStyle.Fill, Padding = new Padding(12, 8, 0, 8) };
            unlock.Dock = lockButton.Dock = DockStyle.Fill; primaryArea.Controls.Add(unlock); primaryArea.Controls.Add(lockButton);
            primaryCreate = Add("创建加密文件夹", CreateVault); Primary(primaryCreate); primaryCreate.Dock = DockStyle.Fill; primaryArea.Controls.Add(primaryCreate);
            card.Controls.Add(primaryArea, 1, 0); card.SetRowSpan(primaryArea, 2); body.Controls.Add(card, 0, 1);
            TableLayoutPanel noticeText = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
            noticeText.RowStyles.Add(new RowStyle(SizeType.Absolute, 26)); noticeText.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            noticeText.Controls.Add(noticeTitle, 0, 0); hint.Font = new Font(Font.FontFamily, 9); noticeText.Controls.Add(hint, 0, 1);
            notice.Controls.Add(noticeText); notice.Controls.Add(progress); body.Controls.Add(notice, 0, 2);
            TableLayoutPanel toolbar = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1 };
            toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 180)); toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            FlowLayoutPanel fileHeading = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false };
            fileHeading.Controls.Add(new Label { Text = "文件内容", AutoSize = true, Font = new Font(Font.FontFamily, 10, FontStyle.Bold), Margin = new Padding(0, 15, 0, 0) }); fileHeading.Controls.Add(count);
            toolbar.Controls.Add(fileHeading, 0, 0);
            show = Add("打开编辑区 ↗", ShowWorkspace); importFiles = Add("导入文件", ImportFiles); importFolder = Add("导入文件夹", ImportFolder);
            show.BackColor = Color.FromArgb(235, 244, 226); actions.Controls.Add(show); actions.Controls.Add(importFolder); actions.Controls.Add(importFiles);
            toolbar.Controls.Add(actions, 1, 0); body.Controls.Add(toolbar, 0, 3);
            Panel fileArea = new Panel { Dock = DockStyle.Fill, BorderStyle = BorderStyle.FixedSingle };
            files.Columns.Add("名称", 400); files.Columns.Add("大小", 100); files.Columns.Add("修改时间", 170);
            fileArea.Controls.Add(files); fileArea.Controls.Add(empty); body.Controls.Add(fileArea, 0, 4);
            files.Resize += delegate { if (files.ClientSize.Width > 320) files.Columns[0].Width = Math.Max(120, files.ClientSize.Width - files.Columns[1].Width - files.Columns[2].Width - 28); };
            caption.Font = new Font(Font.FontFamily, 9); body.Controls.Add(caption, 0, 5);
            FlowLayoutPanel management = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, Padding = new Padding(0, 5, 0, 0) };
            entryButton = Add("创建图标入口", CreateEntry); recover = Add("恢复未锁定工作区", Recover); delete = Add("删除…", DeleteVault); delete.ForeColor = Color.FromArgb(157, 56, 52);
            management.Controls.Add(entryButton); management.Controls.Add(recover); management.Controls.Add(delete); body.Controls.Add(management, 0, 6);
            availability.Font = new Font(Font.FontFamily, 9); body.Controls.Add(availability, 0, 7);
            Button helpStrip = Add("操作与恢复帮助：保存失败怎么办？  ↗", ShowHelp); helpStrip.Dock = DockStyle.Fill; helpStrip.TextAlign = ContentAlignment.MiddleLeft; helpStrip.BackColor = Color.FromArgb(248, 251, 244); body.Controls.Add(helpStrip, 0, 8);
            status.Font = new Font(Font.FontFamily, 9); status.AccessibleName = "操作结果"; body.Controls.Add(status, 0, 9);
            tips.SetToolTip(selected, "当前加密目录位置；备份时请备份整个目录。"); tips.SetToolTip(lockButton, "先在编辑器中保存并关闭文件。快捷键 Alt + L。");
            tips.SetToolTip(importFiles, "复制到编辑区，保留源文件；同名文件不自动覆盖。"); tips.SetToolTip(importFolder, "复制整个文件夹，保留原文件夹。");
            tips.SetToolTip(delete, "永久删除，不进入回收站；需再次验证密码。");
            shell.Controls.Add(sidebar, 0, 0); shell.Controls.Add(body, 1, 0); Controls.Add(shell);
            FormClosing += OnClosing;
            Shown += delegate
            {
                if (Directory.Exists(sessionsBase) && Directory.GetDirectories(sessionsBase).Length > 0)
                    MessageBox.Show(this, "检测到上次未清理的工作区，其中可能仍有明文。请选择对应加密文件夹，点击“恢复未锁定工作区”，检查后保存并锁定。", "需要恢复", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            };
            RefreshState("尚未选择加密文件夹");
            if (!String.IsNullOrEmpty(openRoot)) Shown += async delegate { await OpenFromEntry(openRoot); };
        }
        private static void Primary(Button button) { button.BackColor = Green; button.ForeColor = Color.White; button.FlatAppearance.BorderColor = Green; button.FlatAppearance.MouseOverBackColor = Color.FromArgb(28, 76, 56); button.Font = new Font("Microsoft YaHei UI", 10, FontStyle.Bold); }
        private void ShowHelp(object sender, EventArgs e)
        {
            using (Form help = new Form { Text = "操作与恢复帮助 · FolderSeal", Font = Font, ForeColor = Ink, BackColor = Color.White, ClientSize = new Size(690, 590), MinimumSize = new Size(570, 430), StartPosition = FormStartPosition.CenterParent, MinimizeBox = false, MaximizeBox = false })
            {
                TableLayoutPanel layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(22), RowCount = 2, ColumnCount = 1 };
                layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 49));
                TextBox text = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, BorderStyle = BorderStyle.None, BackColor = Color.White, ForeColor = Ink, Text =
                    "日常编辑\r\n输入密码解锁 → 打开编辑区 → 用原有软件编辑 → 保存并关闭文件 → 回到这里保存并锁定。仅关闭资源管理器不会锁定。\r\n\r\n保存失败\r\n先关闭可能占用文件的 Word、Excel 等程序，再重试。保存失败时保留当前编辑区，不要自行删除；具体原因以错误提示为准。\r\n\r\n密文已保存，清理未完成\r\n关闭占用文件的程序，点击“重试清理并锁定”。此时只继续清理，不重新生成密文；清理完成前不能继续导入或编辑。\r\n\r\n异常退出\r\n选择对应加密文件夹，点击“恢复未锁定工作区”，选择匹配工作区并验证密码。恢复后检查内容，再保存锁定。\r\n\r\n备份与密码\r\n锁定后备份整个密文目录，包括隐藏目录。快捷方式不是资料。普通导入保留源文件。忘记密码无法找回。\r\n\r\n快捷操作\r\nAlt + L：保存或重试锁定。文件夹管理操作需先锁定。处理中请等待结果，不要强制退出。\r\n\r\n保护范围\r\n管理员仍可强制删除。明文采用普通删除，不保证清除磁盘残留、编辑器缓存或历史副本；软件尚未经过独立安全审计。" };
                Button close = Add("返回", delegate { help.Close(); }); close.DialogResult = DialogResult.Cancel; close.Anchor = AnchorStyles.Right | AnchorStyles.Bottom;
                layout.Controls.Add(text, 0, 0); layout.Controls.Add(close, 0, 1); help.Controls.Add(layout); help.CancelButton = close; help.ShowDialog(this);
            }
        }
        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            if (keyData == (Keys.Alt | Keys.L) && !busy && session != null && session.Open) { LockVault(this, EventArgs.Empty); return true; }
            return base.ProcessCmdKey(ref msg, keyData);
        }
        protected override void Dispose(bool disposing) { if (disposing) tips.Dispose(); base.Dispose(disposing); }
        private async Task OpenFromEntry(string root)
        {
            try
            {
                Paths.NoLinks(root);
                Header.Read(Path.Combine(root, VaultSession.DataName));
                session = new VaultSession(root, sessionsBase, true);
                RefreshState("请输入密码打开：" + new DirectoryInfo(root).Name);
                string password = AskPassword(false, "打开 " + new DirectoryInfo(root).Name);
                if (password == null) { Close(); return; }
                bool opened = await Run(delegate { session.Unlock(password); return "已解锁 · 使用结束后请保存并锁定"; });
                password = null;
                if (opened) ShowWorkspace(this, EventArgs.Empty);
            }
            catch (Exception error) { MessageBox.Show(this, error.Message, "无法打开加密文件夹"); }
        }
        private void CreateEntry(object sender, EventArgs e)
        {
            try
            {
                string entry = FolderEntry.Create(session.Root, true);
                MessageBox.Show(this, "已在原位置创建文件夹图标入口：\r\n" + entry + "\r\n双击后输入密码即可打开。原密文目录已隐藏；隐藏不是加密保护。", "入口已创建");
            }
            catch (Exception error) { MessageBox.Show(this, error.Message, "入口未完成"); }
        }
        private Button Add(string text, EventHandler click)
        {
            Button button = new ActionButton { Text = text, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, MinimumSize = new Size(75, 38), Padding = new Padding(8, 4, 8, 4), Margin = new Padding(0, 0, 7, 0), FlatStyle = FlatStyle.Flat, BackColor = Color.White, ForeColor = Ink, Cursor = Cursors.Hand, AccessibleName = text };
            button.FlatAppearance.BorderColor = Line; button.Click += click; return button;
        }
        private sealed class ActionButton : Button
        {
            private bool hovered;
            public ActionButton() { DoubleBuffered = true; }
            protected override void OnMouseEnter(EventArgs e) { hovered = true; Invalidate(); base.OnMouseEnter(e); }
            protected override void OnMouseLeave(EventArgs e) { hovered = false; Invalidate(); base.OnMouseLeave(e); }
            protected override void OnPaint(PaintEventArgs e)
            {
                e.Graphics.Clear(Parent == null ? Color.White : Parent.BackColor);
                e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                Rectangle bounds = new Rectangle(1, 1, Math.Max(1, Width - 3), Math.Max(1, Height - 3));
                int arc = Math.Min(12, Math.Min(bounds.Width, bounds.Height));
                using (var shape = new System.Drawing.Drawing2D.GraphicsPath())
                {
                    shape.AddArc(bounds.Left, bounds.Top, arc, arc, 180, 90); shape.AddArc(bounds.Right - arc, bounds.Top, arc, arc, 270, 90);
                    shape.AddArc(bounds.Right - arc, bounds.Bottom - arc, arc, arc, 0, 90); shape.AddArc(bounds.Left, bounds.Bottom - arc, arc, arc, 90, 90); shape.CloseFigure();
                    Color fill = !Enabled ? Color.FromArgb(243, 246, 239) : hovered ? ControlPaint.Light(BackColor, .12f) : BackColor;
                    using (var brush = new SolidBrush(fill)) e.Graphics.FillPath(brush, shape);
                    using (var pen = new Pen(Enabled ? FlatAppearance.BorderColor : Line)) e.Graphics.DrawPath(pen, shape);
                }
                Rectangle text = Rectangle.Inflate(ClientRectangle, -8, -4);
                TextFormatFlags flags = TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis;
                flags |= TextAlign == ContentAlignment.MiddleLeft ? TextFormatFlags.Left : TextFormatFlags.HorizontalCenter;
                TextRenderer.DrawText(e.Graphics, Text, Font, text, Enabled ? ForeColor : Color.FromArgb(112, 124, 106), flags);
                if (Focused && ShowFocusCues) ControlPaint.DrawFocusRectangle(e.Graphics, Rectangle.Inflate(ClientRectangle, -5, -5));
            }
        }
        private void RefreshState(string message)
        {
            bool has = session != null, open = has && session.Open, cleanup = open && session.CleanupPending;
            bool editable = !busy && open && !cleanup;
            create.Enabled = choose.Enabled = !busy && !open;
            unlock.Enabled = !busy && has && !open; unlock.Visible = has && !open; primaryCreate.Visible = !has; primaryCreate.Enabled = !busy;
            lockButton.Enabled = !busy && open; lockButton.Visible = open;
            show.Enabled = importFiles.Enabled = importFolder.Enabled = editable; actions.Visible = editable;
            delete.Enabled = recover.Enabled = entryButton.Enabled = !busy && has && !open;
            lockButton.Text = busy ? "处理中，请稍候…" : cleanup ? "重试清理并锁定" : operationFailed ? "重试保存并锁定" : "保存并锁定";
            selected.Text = has ? session.Root : "支持 Windows 本机 NTFS 磁盘";
            vaultName.Text = has ? new DirectoryInfo(session.Root).Name : "尚未选择加密文件夹";
            string state = busy ? "处理中" : cleanup ? "清理未完成" : operationFailed ? "操作失败" : open ? "已解锁" : has ? "已锁定" : "未选择";
            badge.Text = state; badge.AccessibleName = "文件夹状态：" + state;
            Color amber = Color.FromArgb(121, 80, 25), red = Color.FromArgb(148, 55, 47);
            badge.BackColor = notice.BackColor = operationFailed && !cleanup ? Color.FromArgb(255, 244, 238) : open && !busy ? Color.FromArgb(255, 249, 234) : Color.FromArgb(240, 246, 233);
            notice.ForeColor = hint.ForeColor = operationFailed && !cleanup ? red : open && !busy ? amber : Green;
            badge.ForeColor = notice.ForeColor;
            progress.Visible = busy;
            if (busy) { noticeTitle.Text = "正在处理，请等待结果"; hint.Text = "正在执行加密、核验或清理操作。大文件夹可能耗时较长；请勿强制退出或重复点击，完成后将更新状态。"; }
            else if (cleanup) { noticeTitle.Text = "密文已保存，但明文尚未清理完"; hint.Text = "请先关闭占用文件的程序，再点击“重试清理并锁定”。本次只重试清理，不重新生成密文。"; }
            else if (operationFailed) { noticeTitle.Text = open ? "操作未完成，编辑内容仍保留在工作区" : "操作未完成，请查看原因后重试"; hint.Text = lastFailure + (open ? " 请保留编辑区；关闭可能占用文件的程序后再重试。" : " 原有资料请保留。"); }
            else if (open) { noticeTitle.Text = "文件可以编辑，但尚未锁定"; hint.Text = "编辑区中存在未加密的文件。请先在编辑器中保存并关闭文件，再回到这里保存并锁定。仅关闭资源管理器不会锁定。"; }
            else if (has) { noticeTitle.Text = "当前文件夹已锁定"; hint.Text = "输入密码后查看和编辑文件。创建图标入口可方便下次访问；备份时须包含整个密文目录。"; }
            else { noticeTitle.Text = "先创建，或选择已有的加密文件夹"; hint.Text = "新建时单独设置密码，创建后为锁定状态。已有资料请通过左侧“选择已有文件夹”打开。忘记密码无法找回。"; }
            if (!String.IsNullOrEmpty(pendingSource) && File.Exists(pendingSource) && !busy)
                hint.Text += " 待移入文件：" + Path.GetFileName(pendingSource) + "；加密核验完成且源文件未变化才删除源明文。";
            files.BeginUpdate();
            try
            {
                files.Items.Clear();
                if (editable && Directory.Exists(session.Work))
                    foreach (string file in Paths.Files(session.Work))
                    {
                        FileInfo info = new FileInfo(file);
                        files.Items.Add(new ListViewItem(new[] { Paths.NameUnder(session.Work, file), FormatSize(info.Length), info.LastWriteTime.ToString("yyyy-MM-dd HH:mm") }));
                    }
            }
            finally { files.EndUpdate(); }
            files.Visible = editable && files.Items.Count > 0; empty.Visible = !files.Visible;
            empty.Text = busy ? "正在处理，请稍候…\r\n全部步骤完成后才会显示“已锁定”。" : cleanup ? "等待完成明文清理\r\n请关闭占用文件的程序，再重试清理。" : open ? "编辑区还没有文件\r\n导入文件、文件夹，或打开编辑区放入资料。" : has ? "文件已锁定\r\n输入密码后查看和编辑文件。\r\n锁定时不展示文件名称与内容。" : "从一个加密文件夹开始\r\n点击左侧“创建加密文件夹”或“选择已有文件夹”。";
            count.Visible = editable; count.Text = files.Items.Count.ToString() + " 个文件";
            caption.Text = cleanup ? "明文可能仍有残留；清理完成前不标记为已锁定。" : editable ? "导入会保留源文件；编辑器内保存后，还需在这里保存并锁定。" : "备份整个密文目录；图标快捷方式不是资料本体。";
            switchReason.Text = open || busy ? "先完成保存与清理，才能创建或切换文件夹。" : "新建文件夹，或选择已有目录。每个文件夹独立密码。";
            availability.Text = !has ? "选择加密文件夹后，才能使用管理操作。" : open || busy ? "以上管理操作需先完成锁定。删除还需再次验证密码，且不进入回收站。" : "图标入口不是资料本体。删除将永久移除资料，并需再次验证密码。";
            status.Text = message; tips.SetToolTip(status, message); tips.SetToolTip(hint, hint.Text); tips.SetToolTip(selected, selected.Text);
        }
        private static string FormatSize(long size)
        {
            if (size >= 1024L * 1024 * 1024) return (size / (1024.0 * 1024 * 1024)).ToString("0.##") + " GB";
            if (size >= 1024L * 1024) return (size / (1024.0 * 1024)).ToString("0.##") + " MB";
            if (size >= 1024) return (size / 1024.0).ToString("0.##") + " KB";
            return size.ToString() + " B";
        }
        private async Task<bool> Run(Func<string> work)
        {
            if (busy) return false;
            operationFailed = false; lastFailure = null; busy = true; RefreshState("处理中，请稍候"); UseWaitCursor = true;
            string result = null; Exception failure = null;
            try { result = await Task.Run(work); }
            catch (Exception error) { failure = error; }
            busy = false; UseWaitCursor = false; operationFailed = failure != null; lastFailure = failure == null ? null : failure.Message;
            try { RefreshState(failure == null ? result : "操作未完成，原有数据请保留"); }
            catch (Exception error) { failure = failure ?? error; operationFailed = true; lastFailure = failure.Message; noticeTitle.Text = "操作未完成，请保留当前资料"; hint.Text = lastFailure; }
            if (failure != null)
            {
                string detail = failure.Message;
                if (session != null && session.Open) detail += "\r\n明文工作区仍保留：\r\n" + session.Work;
                MessageBox.Show(this, detail, "操作未完成", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            return failure == null;
        }
        private string AskPassword(bool creating, string title)
        {
            using (PasswordDialog dialog = new PasswordDialog(creating, title))
                return dialog.ShowDialog(this) == DialogResult.OK ? dialog.Value : null;
        }
        private async void CreateVault(object sender, EventArgs e)
        {
            string parent;
            using (FolderBrowserDialog dialog = new FolderBrowserDialog { Description = "选择加密文件夹的上级目录", SelectedPath = File.Exists(pendingSource) ? Path.GetDirectoryName(pendingSource) : Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) })
            { if (dialog.ShowDialog(this) != DialogResult.OK) return; parent = dialog.SelectedPath; }
            string name;
            using (NameDialog dialog = new NameDialog()) { if (dialog.ShowDialog(this) != DialogResult.OK) return; name = dialog.FolderName; }
            string password = AskPassword(true, "创建加密文件夹 · 设置密码"); if (password == null) return;
            string root = Path.Combine(parent, name);
            await Run(delegate
            {
                if (session != null) session.Dispose();
                session = new VaultSession(root, sessionsBase, true);
                session.Create(password); password = null;
                string source = File.Exists(pendingSource) ? pendingSource : null;
                byte[] sourceHash = source == null ? null : Paths.Hash(source);
                if (source != null)
                {
                    session.ImportFile(source);
                    if (!Paths.Equal(sourceHash, Paths.Hash(Path.Combine(session.Work, Path.GetFileName(source)))))
                        throw new IOException("导入时源文件发生变化。原文件保留，请重新导入。");
                }
                session.Lock();
                if (source != null)
                {
                    if (!Paths.Equal(sourceHash, Paths.Hash(source))) return "加密并锁定成功；源文件发生变化，原文件已保留";
                    try { File.Delete(source); }
                    catch { return "加密并锁定成功；原文件无法删除，请自行处理明文副本"; }
                }
                return source == null ? "创建成功 · 已锁定并启用防误删保护" : "创建成功 · 原文件已加密移入，明文工作区已清理";
            });
            password = null;
        }
        private void ChooseVault(object sender, EventArgs e)
        {
            using (FolderBrowserDialog dialog = new FolderBrowserDialog { Description = "选择包含 内容.egvault 的加密文件夹" })
            {
                if (dialog.ShowDialog(this) != DialogResult.OK) return;
                try
                {
                    Header.Read(Path.Combine(dialog.SelectedPath, VaultSession.DataName));
                    Native.RequireProtectedParent(Path.GetDirectoryName(Paths.Full(dialog.SelectedPath)));
                    if (session != null) session.Dispose();
                    session = new VaultSession(dialog.SelectedPath, sessionsBase, true); operationFailed = false; lastFailure = null; RefreshState("已锁定 · 输入密码后访问");
                }
                catch (Exception error) { MessageBox.Show(this, error.Message, "无法选择"); }
            }
        }
        private async void UnlockVault(object sender, EventArgs e)
        {
            string password = AskPassword(false, "解锁加密文件夹"); if (password == null) return;
            await Run(delegate { session.Unlock(password); password = null; return "已解锁 · 修改后请保存并锁定"; }); password = null;
        }
        private async void LockVault(object sender, EventArgs e)
        {
            if (busy || session == null || !session.Open) return;
            if (!session.CleanupPending && MessageBox.Show(this, "请先在编辑器中保存修改，并关闭正在编辑的文件。\r\n接下来将生成新密文、核验并清理编辑区。继续吗？", "保存并锁定", MessageBoxButtons.OKCancel, MessageBoxIcon.Information, MessageBoxDefaultButton.Button2) != DialogResult.OK) return;
            await Run(delegate { session.Lock(); return "已锁定 · 已验证加密内容，明文工作区已清理"; });
        }
        private void ShowWorkspace(object sender, EventArgs e)
        {
            if (!busy && session != null && session.Open && !session.CleanupPending)
                Process.Start(new ProcessStartInfo("explorer.exe", "\"" + session.Work + "\"") { UseShellExecute = true });
        }
        private async void ImportFiles(object sender, EventArgs e)
        {
            using (OpenFileDialog dialog = new OpenFileDialog { Multiselect = true, Title = "选择要复制到加密文件夹的文件" })
            {
                if (dialog.ShowDialog(this) != DialogResult.OK) return;
                string[] sources = dialog.FileNames;
                await Run(delegate { foreach (string source in sources) session.ImportFile(source); return "已复制到编辑区 · 请保存并锁定；导入的源文件保留"; });
            }
        }
        private async void ImportFolder(object sender, EventArgs e)
        {
            using (FolderBrowserDialog dialog = new FolderBrowserDialog { Description = "选择要复制进来的文件夹（原文件夹保留）" })
            {
                if (dialog.ShowDialog(this) != DialogResult.OK) return;
                string source = dialog.SelectedPath;
                await Run(delegate { session.ImportFolder(source); return "文件夹已复制到编辑区 · 请保存并锁定；源文件夹保留"; });
            }
        }
        private async void DeleteVault(object sender, EventArgs e)
        {
            if (MessageBox.Show(this, "将永久删除整个加密文件夹及其中所有文件。\r\n此操作不进入回收站。是否继续验证密码？", "删除加密文件夹", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            string password = AskPassword(false, "删除前再次验证密码"); if (password == null) return;
            await Run(delegate { session.Delete(password); password = null; session.Dispose(); session = null; return "加密文件夹已删除"; }); password = null;
        }
        private async void Recover(object sender, EventArgs e)
        {
            if (!Directory.Exists(sessionsBase)) { MessageBox.Show(this, "没有待恢复工作区。"); return; }
            string existing;
            using (FolderBrowserDialog dialog = new FolderBrowserDialog { Description = "选择需要恢复的工作区编号目录（其中包含“编辑区”）", SelectedPath = sessionsBase })
            { if (dialog.ShowDialog(this) != DialogResult.OK) return; existing = dialog.SelectedPath; }
            string note = Path.Combine(existing, "工作区说明.txt");
            string marker = Path.Combine(existing, "清理状态.txt");
            bool matches = File.Exists(note) && File.ReadAllText(note).Contains(session.Root);
            matches = matches || (File.Exists(marker) && File.ReadAllText(marker).StartsWith(session.Root + "\r\n", StringComparison.OrdinalIgnoreCase));
            if (!matches) { MessageBox.Show(this, "此工作区与当前选择的加密目录不匹配。"); return; }
            string password = AskPassword(false, "验证密码并恢复工作区"); if (password == null) return;
            await Run(delegate { session.Resume(existing, password); password = null; return "已恢复明文工作区 · 请检查内容后保存并锁定"; }); password = null;
        }
        private async void OnClosing(object sender, FormClosingEventArgs e)
        {
            if (closing) return;
            if (busy) { e.Cancel = true; return; }
            if (session == null || !session.Open) { if (session != null) session.Dispose(); return; }
            e.Cancel = true;
            if (MessageBox.Show(this, "退出前需要加密保存并清理明文工作区。\r\n请先关闭正在编辑的文件。现在保存并锁定吗？", "保存后退出", MessageBoxButtons.OKCancel, MessageBoxIcon.Information) != DialogResult.OK) return;
            if (await Run(delegate { session.Lock(); return "已安全锁定"; })) { closing = true; Close(); }
        }
    }

    internal static class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
            if (!Native.IsAdmin()) { MessageBox.Show("此程序需要管理员授权来启用和管理文件夹防删除保护。", "需要管理员权限"); return; }
            string source = args.Length == 2 && args[0] == "--move-source" ? args[1] : null;
            string openRoot = args.Length == 2 && args[0] == "--open-vault" ? args[1] : null;
            Application.Run(new MainForm(source, openRoot));
        }
    }
}
