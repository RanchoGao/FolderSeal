// Copyright (c) EurekaGao. Local-only Windows folder encryption tool.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.IO.Pipes;
using System.Linq;
using System.Net;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace FolderSeal
{
    internal sealed class UpdateInfo
    {
        public Version Version;
        public string DownloadUrl;
        public bool Prerelease;
    }

    internal static class UpdateChecker
    {
        private const int MaximumResponseBytes = 4 * 1024 * 1024;
        internal static Version CurrentVersion { get { return typeof(UpdateChecker).Assembly.GetName().Version; } }
        [DataContract]
        private sealed class Release
        {
            [DataMember(Name = "tag_name")] public string Tag { get; set; }
            [DataMember(Name = "draft")] public bool Draft { get; set; }
            [DataMember(Name = "prerelease")] public bool Prerelease { get; set; }
            [DataMember(Name = "assets")] public Asset[] Assets { get; set; }
        }
        [DataContract]
        private sealed class Asset
        {
            [DataMember(Name = "name")] public string Name { get; set; }
            [DataMember(Name = "browser_download_url")] public string Url { get; set; }
            [DataMember(Name = "size")] public long Size { get; set; }
            [DataMember(Name = "state")] public string State { get; set; }
        }
        internal static UpdateInfo Parse(Stream input, Version current)
        {
            Release[] releases = (Release[])new DataContractJsonSerializer(typeof(Release[])).ReadObject(input);
            if (releases == null) throw new InvalidDataException("版本信息为空。");
            UpdateInfo newest = null;
            foreach (Release release in releases)
            {
                if (release == null || release.Draft || release.Assets == null || String.IsNullOrEmpty(release.Tag)) continue;
                string number = release.Tag.StartsWith("v", StringComparison.OrdinalIgnoreCase) ? release.Tag.Substring(1) : release.Tag;
                Version version;
                if (!System.Text.RegularExpressions.Regex.IsMatch(number, @"^\d+\.\d+\.\d+$") || !Version.TryParse(number, out version)) continue;
                version = new Version(version.Major, version.Minor, version.Build, 0);
                if (version <= current || (newest != null && version <= newest.Version)) continue;
                string name = "FolderSeal-" + number + "-Setup.exe";
                string expected = "https://github.com/RanchoGao/FolderSeal/releases/download/" + Uri.EscapeDataString(release.Tag) + "/" + name;
                Asset installer = release.Assets.FirstOrDefault(x => x != null && x.Name == name && x.Size > 0 && x.State == "uploaded" && x.Url == expected);
                if (installer != null) newest = new UpdateInfo { Version = version, DownloadUrl = expected, Prerelease = release.Prerelease };
            }
            return newest;
        }
        internal static Task<UpdateInfo> CheckAsync()
        {
            return Task.Run(delegate
            {
                // Direct Framework builds can inherit legacy TLS defaults without an app.config.
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://api.github.com/repos/RanchoGao/FolderSeal/releases?per_page=100");
                request.UserAgent = "FolderSeal/" + CurrentVersion.ToString(3);
                request.Accept = "application/vnd.github+json";
                request.Headers["X-GitHub-Api-Version"] = "2022-11-28";
                request.Timeout = request.ReadWriteTimeout = 10000;
                request.AllowAutoRedirect = false;
                using (WebResponse response = request.GetResponse())
                using (Stream stream = response.GetResponseStream())
                using (MemoryStream buffer = new MemoryStream())
                {
                    byte[] block = new byte[8192]; int read;
                    while ((read = stream.Read(block, 0, block.Length)) > 0)
                    {
                        if (buffer.Length + read > MaximumResponseBytes) throw new InvalidDataException("版本信息过大，请稍后重试。");
                        buffer.Write(block, 0, read);
                    }
                    buffer.Position = 0;
                    return Parse(buffer, CurrentVersion);
                }
            });
        }
    }

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

    // Explorer context-menu verbs live in HKCU so a portable copy can install and remove them without elevation.
    internal static class ExplorerMenu
    {
        internal const string SealVerb = "FolderSeal.Seal", OpenVerb = "FolderSeal.Open";
        internal const string ClassesRoot = @"Software\Classes";
        internal static bool IsVault(string directory)
        {
            try { return Directory.Exists(directory) && File.Exists(Path.Combine(directory, VaultSession.DataName)); }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
        }
        internal static bool Installed(string baseKey)
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(baseKey + @"\Directory\shell\" + SealVerb))
                return key != null;
        }
        internal static void Write(string baseKey, string executable, string sealFolder, string sealFile, string openFolder)
        {
            string command = "\"" + executable + "\" --seal \"%1\"";
            string open = "\"" + executable + "\" --open-vault \"%1\"";
            WriteVerb(baseKey + @"\Directory\shell\" + SealVerb, sealFolder, executable, command);
            WriteVerb(baseKey + @"\*\shell\" + SealVerb, sealFile, executable, command);
            WriteVerb(baseKey + @"\Directory\shell\" + OpenVerb, openFolder, executable, open);
        }
        private static void WriteVerb(string subKey, string label, string executable, string command)
        {
            using (RegistryKey key = Registry.CurrentUser.CreateSubKey(subKey))
            {
                if (key == null) throw new IOException("无法写入资源管理器菜单注册表项。");
                key.SetValue(null, label);
                key.SetValue("Icon", "\"" + executable + "\",0");
                key.SetValue("MultiSelectModel", "Single");
                using (RegistryKey verb = key.CreateSubKey("command")) verb.SetValue(null, command);
            }
        }
        internal static void Erase(string baseKey)
        {
            foreach (string subKey in new[] {
                @"Directory\shell\" + SealVerb, @"*\shell\" + SealVerb, @"Directory\shell\" + OpenVerb })
                Registry.CurrentUser.DeleteSubKeyTree(baseKey + @"\" + subKey, false);
        }
    }

    internal static class Native
    {
        [DllImport("user32.dll")]
        private static extern bool ShowScrollBar(IntPtr window, int bar, bool show);
        internal static void HideHorizontalScrollBar(ListView list)
        {
            if (list.IsHandleCreated) ShowScrollBar(list.Handle, 0, false);
        }
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
        // Detection only: the UI asks the user before sealing into a parent that allows removal.
        public static bool ParentLacksProtection(string parent)
{
            try { return ParentAllowsDeleteChild(parent); }
            catch (IOException) { return false; }
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
        private const FileSystemRights WorkspaceTraverse = FileSystemRights.Traverse | FileSystemRights.ReadAttributes | FileSystemRights.Synchronize;
        public static void Set(string path, bool writableUser)
        {
            Apply(path, writableUser ? FileSystemRights.Modify : FileSystemRights.ReadAndExecute);
        }
        internal static void Restrict(string path)
        {
            if (!Native.IsAdmin()) throw new UnauthorizedAccessException("锁定目录的保护需要管理员权限。");
            Apply(path, null);
        }
        internal static void ProtectWorkspaceContainer(string path)
        {
            if (!Native.IsAdmin()) throw new UnauthorizedAccessException("工作区保护需要管理员权限。");
            Apply(path, WorkspaceTraverse, false);
        }
        internal static void CreateWorkspaceContainer(string path)
        {
            if (!Native.IsAdmin()) throw new UnauthorizedAccessException("工作区保护需要管理员权限。");
            Paths.NoLinks(Path.GetDirectoryName(path));
            Directory.CreateDirectory(path, (DirectorySecurity)BuildAccessControl(true, WorkspaceTraverse, false));
        }
        private static void Apply(string path, FileSystemRights? userRights, bool inheritUser = true)
        {
            Paths.NoLinks(path);
            bool directory = Directory.Exists(path);
            FileSystemSecurity acl = BuildAccessControl(directory, userRights, inheritUser);
            if (directory) Directory.SetAccessControl(path, (DirectorySecurity)acl);
            else File.SetAccessControl(path, (FileSecurity)acl);
        }
        private static FileSystemSecurity BuildAccessControl(bool directory, FileSystemRights? userRights, bool inheritUser)
        {
            InheritanceFlags inheritance = directory ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None;
            FileSystemSecurity acl = directory ? (FileSystemSecurity)new DirectorySecurity() : new FileSecurity();
            acl.SetAccessRuleProtection(true, false);
            acl.SetOwner(Native.IsAdmin() ? Admin : User);
            acl.AddAccessRule(new FileSystemAccessRule(Admin, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(SystemSid, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
            if (userRights.HasValue)
                acl.AddAccessRule(new FileSystemAccessRule(User, userRights.Value, inheritUser ? inheritance : InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
            return acl;
        }
        public static void Workspace(string root, bool writableUser)
        {
            // Validate the entire tree before changing ACLs, then recheck each item.
            List<string> files = Paths.Files(root);
            List<string> directories = Paths.Directories(root);
            foreach (string path in new[] { root }.Concat(directories).Concat(files))
            {
                if (writableUser) Set(path, true);
                else Restrict(path);
            }
        }
        public static void Seal(string root)
        {
            Restrict(root);
            foreach (string file in Directory.GetFiles(root)) Restrict(file);
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

    // Encrypt-then-MAC records for the local catalog and migration journal.
    internal static class SecretRecord
    {
        public static byte[] Encode(byte[] plain, string password)
        {
            Header h = Header.New();
            using (KeySet k = new KeySet(password, h.Salt, h.Iterations))
            using (MemoryStream m = new MemoryStream())
            using (Aes aes = Aes.Create())
            {
                h.Write(m); aes.Key = k.Encryption; aes.IV = h.IV;
                using (CryptoStream c = new CryptoStream(m, aes.CreateEncryptor(), CryptoStreamMode.Write, true))
                { c.Write(plain, 0, plain.Length); c.FlushFinalBlock(); }
                byte[] body = m.ToArray();
                using (HMACSHA256 mac = new HMACSHA256(k.Authentication))
                { byte[] tag = mac.ComputeHash(body); m.Write(tag, 0, tag.Length); }
                return m.ToArray();
            }
        }
        public static byte[] Decode(string path, string password)
        {
            Header h = Header.Read(path);
            using (KeySet k = new KeySet(password, h.Salt, h.Iterations))
            {
                ArchiveCrypto.Authenticate(path, k);
                using (FileStream f = File.OpenRead(path))
                using (Aes aes = Aes.Create())
                using (MemoryStream result = new MemoryStream())
                {
                    aes.Key = k.Encryption; aes.IV = h.IV; f.Position = Header.Size;
                    using (CryptoStream c = new CryptoStream(new LimitedStream(f, f.Length - Header.Size - 32), aes.CreateDecryptor(), CryptoStreamMode.Read)) c.CopyTo(result);
                    return result.ToArray();
                }
            }
        }
        public static void Write(string path, byte[] plain, string password)
        {
            Paths.NoLinks(path); string temp = Path.Combine(Path.GetDirectoryName(path), ".pending-record-" + Guid.NewGuid().ToString("N") + ".egvault"); Paths.NoLinks(temp);
            byte[] encrypted = Encode(plain, password);
            try
            {
                using (FileStream f = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
                { f.Write(encrypted, 0, encrypted.Length); f.Flush(true); }
                if (File.Exists(path)) File.Replace(temp, path, null); else File.Move(temp, path);
            }
            finally { if (File.Exists(temp)) File.Delete(temp); }
        }
    }

    internal sealed class VaultLocation
    {
        public string Path;
        public bool Managed;
    }
    internal sealed class VaultCatalog
    {
        public readonly List<VaultLocation> Locations = new List<VaultLocation>();
        public bool Scanned, Complete;
        public int Skipped;
        public string Summary = "尚未扫描";
        public readonly string FilePath;
        private readonly bool includeTestFixtures;
        public bool NeedsSave { get; private set; }
        public VaultCatalog(string path, bool includeTestFixtures = false) { FilePath = path; this.includeTestFixtures = includeTestFixtures; }
        public bool Excludes(string path) { return VaultDiscovery.IsExcluded(path, includeTestFixtures); }
        private void RemoveExcluded()
        {
            int removed = Locations.RemoveAll(x => Excludes(x.Path));
            if (removed == 0) return;
            NeedsSave = true;
            Summary = "已记住 " + Locations.Count + " 个加密文件夹 · 已从列表移除 " + removed + " 条测试/回收站记录；可重新扫描";
        }
        public void Add(string path, bool managed)
        {
            path = Paths.Full(path);
            if (Excludes(path)) return;
            VaultLocation entry = Locations.FirstOrDefault(x => String.Equals(x.Path, path, StringComparison.OrdinalIgnoreCase));
            if (entry == null) Locations.Add(new VaultLocation { Path = path, Managed = managed });
            else if (managed) entry.Managed = true;
        }
        public void Load(string password)
        {
            byte[] data = SecretRecord.Decode(FilePath, password);
            try
            {
                using (BinaryReader r = new BinaryReader(new MemoryStream(data), Encoding.UTF8))
                {
                    if (r.ReadInt32() != 1) throw new IOException("不支持的目录表版本。");
                    bool scanned = r.ReadBoolean(), complete = r.ReadBoolean(); int skipped = r.ReadInt32(); string summary = r.ReadString();
                    int count = r.ReadInt32(); if (count < 0 || count > 100000) throw new IOException("目录表无效。");
                    List<VaultLocation> loaded = new List<VaultLocation>();
                    for (int i = 0; i < count; i++) loaded.Add(new VaultLocation { Path = Paths.Full(r.ReadString()), Managed = r.ReadBoolean() });
                    if (r.BaseStream.Position != r.BaseStream.Length) throw new IOException("目录表有未知内容。");
                    Locations.Clear(); Locations.AddRange(loaded); Scanned = scanned; Complete = complete; Skipped = skipped; Summary = summary;
                    NeedsSave = false; RemoveExcluded();
                }
            }
            finally { Array.Clear(data, 0, data.Length); }
        }
        public void Save(string password)
        {
            RemoveExcluded();
            Paths.NoLinks(System.IO.Path.GetDirectoryName(FilePath));
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(FilePath));
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter w = new BinaryWriter(m, Encoding.UTF8, true))
                {
                    w.Write(1); w.Write(Scanned); w.Write(Complete); w.Write(Skipped); w.Write(Summary);
                    w.Write(Locations.Count); foreach (VaultLocation e in Locations) { w.Write(e.Path); w.Write(e.Managed); }
                }
                byte[] data = m.ToArray();
                try { SecretRecord.Write(FilePath, data, password); NeedsSave = false; } finally { Array.Clear(data, 0, data.Length); }
            }
        }
    }

    internal sealed class ScanProgress
    {
        public string Found, Current;
        public int Visited, Skipped, Count;
        public readonly List<string> FoundPaths = new List<string>();
    }
    internal static class VaultDiscovery
    {
        // Match complete generated-fixture directory names, never ordinary names such as "original".
        private static readonly System.Text.RegularExpressions.Regex FixtureDirectory = new System.Text.RegularExpressions.Regex(
            @"^(?:generated-(?:library|test|ui)|entry-test|\.?setup-test)-[a-f0-9]{32}$",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);
        public static bool IsExcluded(string path, bool includeTestFixtures = false)
        {
            foreach (string segment in Path.GetFullPath(path).Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (segment.Equals("$RECYCLE.BIN", StringComparison.OrdinalIgnoreCase) || segment.Equals("RECYCLER", StringComparison.OrdinalIgnoreCase)) return true;
                if (!includeTestFixtures && FixtureDirectory.IsMatch(segment)) return true;
            }
            return false;
        }
        public static string[] FixedRoots()
        {
            List<string> roots = new List<string>();
            foreach (DriveInfo d in DriveInfo.GetDrives())
                try { if (d.IsReady && d.DriveType == DriveType.Fixed && d.DriveFormat == "NTFS") roots.Add(d.RootDirectory.FullName); }
                catch (IOException) { } catch (UnauthorizedAccessException) { }
            return roots.ToArray();
        }
        public static ScanProgress Scan(IEnumerable<string> roots, CancellationToken cancel, IProgress<ScanProgress> progress, bool includeTestFixtures = false)
        {
            ScanProgress state = new ScanProgress(); Stack<string> pending = new Stack<string>(roots.Reverse());
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            while (pending.Count > 0 && !cancel.IsCancellationRequested)
            {
                string path = pending.Pop();
                try
                {
                    if (!seen.Add(Paths.Full(path))) continue;
                    if (IsExcluded(path, includeTestFixtures)) continue;
                    Paths.NoLinks(path); state.Current = path; state.Visited++;
                    string data = Path.Combine(path, VaultSession.DataName);
                    if (File.Exists(data))
                    {
                        try { Header.Read(data); Native.RejectHardLink(data); state.Count++; state.FoundPaths.Add(path); Report(progress, state, path); }
                        catch (IOException) { state.Skipped++; } catch (UnauthorizedAccessException) { state.Skipped++; }
                    }
                    foreach (string child in Directory.EnumerateDirectories(path)) pending.Push(child);
                }
                catch (IOException) { state.Skipped++; } catch (UnauthorizedAccessException) { state.Skipped++; }
                catch (System.Security.SecurityException) { state.Skipped++; }
                if (state.Visited % 100 == 0) Report(progress, state, null);
            }
            return state;
        }
        private static void Report(IProgress<ScanProgress> progress, ScanProgress s, string found)
        {
            if (progress != null) progress.Report(new ScanProgress { Found = found, Current = s.Current, Visited = s.Visited, Skipped = s.Skipped, Count = s.Count });
        }
    }

    internal sealed class VaultSession : IDisposable
    {
        public const string DataName = "内容.egvault", BackupName = "上一版本.egvault", GateName = ".access.lock";
        public string Root, SessionRoot, Work;
        public bool Open { get { return keys != null || (gate != null && CleanupPending); } }
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
        private void Acquire(bool migration = false)
        {
            try
            {
                CheckRoot();
                if (!migration && HasPendingMigration) throw new IOException("此目录改密尚未完成，请通过“我的加密文件夹”恢复后再打开。");
                string gatePath = Path.Combine(Root, GateName);
                if (!File.Exists(gatePath))
                {
                    using (FileStream marker = new FileStream(gatePath, FileMode.CreateNew, FileAccess.Write, FileShare.None)) marker.WriteByte(1);
                }
                if (protect) Permissions.Restrict(gatePath);
                gate = new FileStream(gatePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException error)
            {
                int code = error.HResult & 0xffff;
                if (code == 32 || code == 33)
                    throw new IOException("此加密文件夹正被其他窗口或进程使用。请先在原窗口保存并锁定，再重试；不要删除 .access.lock，也不要强制结束正在编辑的程序。", error);
                throw;
            }
        }
        private const string WorkspaceNote = "工作区说明.txt";
        private const string CleanupNote = "清理状态.txt";
        private const string WorkspaceBaseline = "来源版本：";

        private void WriteWorkspaceNote()
        {
            string origin = baseline == null ? "" : WorkspaceBaseline + Convert.ToBase64String(baseline) + "\r\n";
            File.WriteAllText(Path.Combine(SessionRoot, WorkspaceNote), "未锁定的明文工作区。对应加密目录：\r\n" + Root + "\r\n" + origin + "请回到程序中恢复并锁定，不要直接删除。", Encoding.UTF8);
        }
        private static string[] ReadWorkspaceNote(string directory, string name)
        {
            string path = Path.Combine(directory, name);
            if (!File.Exists(path)) return new string[0];
            Paths.NoLinks(path); Native.RejectHardLink(path);
            return File.ReadAllLines(path);
        }
        private bool MatchesWorkspace(string[] lines)
        {
            return lines.Any(line => String.Equals(line, Root, StringComparison.OrdinalIgnoreCase));
        }
        internal IEnumerable<string> RecoveryWorkspaces()
        {
            if (!Directory.Exists(sessionsBase)) yield break;
            Paths.NoLinks(sessionsBase);
            foreach (string directory in Directory.GetDirectories(sessionsBase))
            {
                Paths.NoLinks(directory);
                if (MatchesWorkspace(ReadWorkspaceNote(directory, CleanupNote)) ||
                    MatchesWorkspace(ReadWorkspaceNote(directory, WorkspaceNote))) yield return directory;
            }
        }
        private void NewWorkspace()
        {
            Paths.NoLinks(sessionsBase);
            Directory.CreateDirectory(sessionsBase);
            SessionRoot = Path.Combine(sessionsBase, Guid.NewGuid().ToString("N"));
            if (protect) Permissions.CreateWorkspaceContainer(SessionRoot);
            else Directory.CreateDirectory(SessionRoot);
            Work = Path.Combine(SessionRoot, "编辑区");
            Directory.CreateDirectory(Work);
            WriteWorkspaceNote();
        }
        public void Create(string password)
        {
            if (password.Length < 6) throw new ArgumentException("密码至少需要 6 个字符。");
            if (Directory.Exists(Root) || File.Exists(Root)) throw new IOException("请使用尚不存在的新文件夹名称。");
            Paths.NoLinks(Path.GetDirectoryName(Root));
            if (protect) Native.LocalNtfs(Path.GetDirectoryName(Root));
            Directory.CreateDirectory(Root);
            if (protect) Permissions.Seal(Root);
            try
            {
                Acquire();
                header = Header.New(); keys = new KeySet(password, header.Salt, header.Iterations);
                baseline = null;
                NewWorkspace();
                SaveSnapshot();
                WriteWorkspaceNote();
                if (protect) Permissions.Workspace(Work, true);
            }
            catch { Dispose(); throw; }
        }
        public void Unlock(string password)
        {
            if (Open) throw new InvalidOperationException("当前文件夹已经解锁。");
            if (protect) Native.LocalNtfs(Path.GetDirectoryName(Root));
            Acquire();
            try
            {
                header = Header.Read(Data);
                keys = new KeySet(password, header.Salt, header.Iterations);
                ArchiveCrypto.Authenticate(Data, keys);
                baseline = Paths.Hash(Data);
                NewWorkspace();
                string zip = Path.Combine(SessionRoot, "解密临时.zip");
                try { ArchiveCrypto.DecryptZip(Data, zip, header, keys); ArchiveCrypto.Extract(zip, Work); }
                finally { if (File.Exists(zip)) File.Delete(zip); }
                if (protect) Permissions.Workspace(Work, true);
                if (!Paths.Equal(Paths.Hash(Data), baseline))
                    throw new IOException("打开期间加密版本已改变，请重试。");
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
            if (protect) Native.LocalNtfs(Path.GetDirectoryName(Root));
            Paths.NoLinks(existingSession);
            if (!Paths.Inside(existingSession, sessionsBase)) throw new IOException("不是本程序的工作区。");
            existingSession = Paths.Full(existingSession);
            if (!String.Equals(Path.GetDirectoryName(existingSession), Paths.Full(sessionsBase), StringComparison.OrdinalIgnoreCase))
                throw new IOException("请选择直接位于工作区目录下的恢复记录。");
            Acquire();
            try
            {
                header = Header.Read(Data); keys = new KeySet(password, header.Salt, header.Iterations);
                ArchiveCrypto.Authenticate(Data, keys);
                byte[] current = Paths.Hash(Data);
                string version = Convert.ToBase64String(current);
                string work = Path.Combine(existingSession, "编辑区");
                string[] cleanup = ReadWorkspaceNote(existingSession, CleanupNote);
                bool pendingCleanup = File.Exists(Path.Combine(existingSession, CleanupNote));
                if (pendingCleanup)
                {
                    if (cleanup.Length != 2 || !String.Equals(cleanup[0], Root, StringComparison.OrdinalIgnoreCase) || cleanup[1] != version)
                        throw new IOException("待清理工作区与当前密文版本不一致，已停止恢复。请保留工作区和加密目录。");
                    if (protect && Directory.Exists(work)) Permissions.Workspace(work, false);
                }
                else
                {
                    string[] note = ReadWorkspaceNote(existingSession, WorkspaceNote);
                    if (!MatchesWorkspace(note)) throw new IOException("此工作区与当前加密文件夹不匹配。");
                    if (!Directory.Exists(work)) throw new IOException("找不到可恢复的编辑区。");
                    if (!note.Contains(WorkspaceBaseline + version))
                        throw new IOException("当前加密版本与工作区来源不同，或旧版工作区没有来源记录。两份内容均已保留。\r\n\r\n如需取回旧内容，请从下方编辑区复制需要的文件，导入另一个加密文件夹，核对后保存并锁定。请勿覆盖当前版本或直接删除工作区。\r\n\r\n编辑区：" + work);
                    Paths.Files(work); if (protect) Permissions.Workspace(work, true);
                }
                if (protect) Permissions.ProtectWorkspaceContainer(existingSession);
                baseline = current;
                SessionRoot = existingSession; Work = work; CleanupPending = pendingCleanup;
                if (CleanupPending) ReleaseKeys();
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
                try
                {
                    if (protect) Permissions.Workspace(Work, false);
                    SaveSnapshot();
                    string marker = Path.Combine(SessionRoot, "清理状态.txt");
                    byte[] content = Encoding.UTF8.GetBytes(Root + "\r\n" + Convert.ToBase64String(baseline));
                    using (FileStream output = new FileStream(marker, FileMode.Create, FileAccess.Write, FileShare.None))
                    { output.Write(content, 0, content.Length); output.Flush(true); }
                    if (protect) Permissions.Restrict(marker);
                    CleanupPending = true;
                    ReleaseKeys();
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
        private const string RekeyJournal = ".pending-rekey-journal.egvault";
        public bool HasPendingMigration { get { return File.Exists(Path.Combine(Root, RekeyJournal)); } }
        public bool HasUnfinishedWorkspace
        {
            get { return RecoveryWorkspaces().Any(); }
        }
        public bool AcceptsPassword(string password)
        {
            CheckRoot();
            foreach (string name in new[] { DataName, BackupName })
            {
                string file = Path.Combine(Root, name); if (name == BackupName && !File.Exists(file)) continue;
                Header h = Header.Read(file);
                using (KeySet k = new KeySet(password, h.Salt, h.Iterations)) ArchiveCrypto.Authenticate(file, k);
            }
            return true;
        }
        private sealed class RekeyEntry
        {
            public string Name; public byte[] Before, After;
            public string Stage(string root) { return Path.Combine(root, ".pending-rekey-new-" + Name); }
            public string Old(string root) { return Path.Combine(root, ".pending-rekey-old-" + Name); }
        }
        // Rewrap the authenticated ZIP stream directly; no plaintext files are created.
        private static void Rewrap(string input, string output, string oldPassword, string newPassword)
        {
            Header old = Header.Read(input), fresh = Header.New(); byte[] originalHash;
            using (KeySet oldKeys = new KeySet(oldPassword, old.Salt, old.Iterations))
            using (KeySet newKeys = new KeySet(newPassword, fresh.Salt, fresh.Iterations))
            {
                ArchiveCrypto.Authenticate(input, oldKeys);
                using (FileStream source = File.OpenRead(input))
                using (FileStream target = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (Aes decrypt = Aes.Create())
                using (Aes encrypt = Aes.Create())
                using (SHA256 hash = SHA256.Create())
                {
                    decrypt.Key = oldKeys.Encryption; decrypt.IV = old.IV;
                    encrypt.Key = newKeys.Encryption; encrypt.IV = fresh.IV;
                    fresh.Write(target); source.Position = Header.Size;
                    using (CryptoStream plain = new CryptoStream(new LimitedStream(source, source.Length - Header.Size - 32), decrypt.CreateDecryptor(), CryptoStreamMode.Read))
                    using (CryptoStream cipher = new CryptoStream(target, encrypt.CreateEncryptor(), CryptoStreamMode.Write, true))
                    {
                        byte[] buffer = new byte[81920]; int n;
                        try
                        {
                            while ((n = plain.Read(buffer, 0, buffer.Length)) != 0)
                            { hash.TransformBlock(buffer, 0, n, buffer, 0); cipher.Write(buffer, 0, n); }
                            hash.TransformFinalBlock(new byte[0], 0, 0); originalHash = hash.Hash;
                            cipher.FlushFinalBlock();
                        }
                        finally { Array.Clear(buffer, 0, buffer.Length); }
                    }
                    target.Flush(true);
                }
                byte[] tag;
                using (FileStream f = File.OpenRead(output))
                using (HMACSHA256 mac = new HMACSHA256(newKeys.Authentication)) tag = mac.ComputeHash(f);
                using (FileStream f = new FileStream(output, FileMode.Append, FileAccess.Write, FileShare.None))
                { f.Write(tag, 0, tag.Length); f.Flush(true); }
                ArchiveCrypto.Authenticate(output, newKeys);
                using (FileStream f = File.OpenRead(output))
                using (Aes aes = Aes.Create())
                using (SHA256 hash = SHA256.Create())
                {
                    aes.Key = newKeys.Encryption; aes.IV = fresh.IV; f.Position = Header.Size;
                    using (CryptoStream c = new CryptoStream(new LimitedStream(f, f.Length - Header.Size - 32), aes.CreateDecryptor(), CryptoStreamMode.Read))
                        if (!Paths.Equal(originalHash, hash.ComputeHash(c))) throw new IOException("改密验证失败，原快照保留。");
                }
            }
        }
        public void ChangePassword(string oldPassword, string newPassword, Action<string> checkpoint = null)
        {
            if (Open) throw new InvalidOperationException("请先保存并锁定。");
            if (newPassword == null || newPassword.Length < 6) throw new ArgumentException("密码至少需要 6 个字符。");
            if (!HasPendingMigration && HasUnfinishedWorkspace) throw new IOException("此目录还有未恢复的工作区，请先恢复、保存并锁定，再改密。");
            if (protect) Native.LocalNtfs(Path.GetDirectoryName(Root));
            Acquire(true);
            try
            {
                List<RekeyEntry> entries = new List<RekeyEntry>(); string journal = Path.Combine(Root, RekeyJournal);
                if (File.Exists(journal))
                {
                    byte[] record = SecretRecord.Decode(journal, newPassword);
                    try
                    {
                        using (BinaryReader r = new BinaryReader(new MemoryStream(record), Encoding.UTF8))
                        {
                            if (r.ReadInt32() != 1 || !String.Equals(r.ReadString(), Root, StringComparison.OrdinalIgnoreCase)) throw new IOException("改密事务与此目录不匹配。");
                            int n = r.ReadInt32(); if (n < 1 || n > 2) throw new IOException("改密事务无效。");
                            for (int i = 0; i < n; i++)
                            {
                                string name = r.ReadString();
                                if (name != (i == 0 ? DataName : BackupName)) throw new IOException("改密事务包含未知文件。");
                                byte[] before = r.ReadBytes(32), after = r.ReadBytes(32);
                                if (before.Length != 32 || after.Length != 32) throw new IOException("改密事务不完整。");
                                entries.Add(new RekeyEntry { Name = name, Before = before, After = after });
                            }
                            if (r.BaseStream.Position != r.BaseStream.Length) throw new IOException("改密事务有未知内容。");
                        }
                    }
                    finally { Array.Clear(record, 0, record.Length); }
                }
                else
                {
                    // Authenticate every original before removing any staging files from a failed preparation.
                    foreach (string name in new[] { DataName, BackupName })
                    {
                        string file = Path.Combine(Root, name); if (name == BackupName && !File.Exists(file)) continue;
                        Header h = Header.Read(file);
                        using (KeySet k = new KeySet(oldPassword, h.Salt, h.Iterations)) ArchiveCrypto.Authenticate(file, k);
                        entries.Add(new RekeyEntry { Name = name, Before = Paths.Hash(file) });
                    }
                    foreach (RekeyEntry e in entries)
                    {
                        if (File.Exists(e.Old(Root))) throw new IOException("发现无事务记录的原快照副本，请保留目录并检查，未覆盖数据。");
                        if (File.Exists(e.Stage(Root))) File.Delete(e.Stage(Root));
                        Rewrap(Path.Combine(Root, e.Name), e.Stage(Root), oldPassword, newPassword);
                        e.After = Paths.Hash(e.Stage(Root));
                        if (checkpoint != null) checkpoint("staged");
                    }
                    using (MemoryStream m = new MemoryStream())
                    {
                        using (BinaryWriter w = new BinaryWriter(m, Encoding.UTF8, true))
                        {
                            w.Write(1); w.Write(Root); w.Write(entries.Count);
                            foreach (RekeyEntry e in entries) { w.Write(e.Name); w.Write(e.Before); w.Write(e.After); }
                        }
                        SecretRecord.Write(journal, m.ToArray(), newPassword);
                    }
                    if (protect) Permissions.Seal(Root);
                    if (checkpoint != null) checkpoint("prepared");
                }
                // Hashes make roll-forward idempotent after a crash at any replacement boundary.
                foreach (RekeyEntry e in entries)
                {
                    string target = Path.Combine(Root, e.Name); byte[] actual = Paths.Hash(target);
                    if (!Paths.Equal(actual, e.After))
                    {
                        if (!Paths.Equal(actual, e.Before) || !File.Exists(e.Stage(Root)) || !Paths.Equal(Paths.Hash(e.Stage(Root)), e.After) || File.Exists(e.Old(Root)))
                            throw new IOException("改密事务文件被外部修改，已停止恢复并保留所有副本。");
                        File.Replace(e.Stage(Root), target, e.Old(Root), false);
                    }
                    Header h = Header.Read(target);
                    using (KeySet k = new KeySet(newPassword, h.Salt, h.Iterations)) ArchiveCrypto.Authenticate(target, k);
                    if (checkpoint != null) checkpoint(e.Name == DataName ? "current" : "backup");
                }
                if (protect) Permissions.Seal(Root);
                if (checkpoint != null) checkpoint("cleanup");
                foreach (RekeyEntry e in entries)
                {
                    string old = e.Old(Root);
                    if (File.Exists(old))
                    {
                        if (!Paths.Equal(Paths.Hash(old), e.Before)) throw new IOException("原快照副本被外部修改，未删除。");
                        File.Delete(old);
                    }
                }
                File.Delete(journal);
            }
            finally { Dispose(); }
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
        // Imports the direct children of a folder so the vault root mirrors the original folder.
        public void ImportContents(string source)
        {
            if (!Open || CleanupPending) throw new InvalidOperationException("请先解锁，或完成上次的明文清理。");
            Paths.NoLinks(source);
            if (Paths.Inside(Root, source) || Paths.Inside(source, Root) || Paths.Full(source) == Root)
                throw new IOException("源文件夹与加密目录不能相互包含。");
            foreach (string entry in Directory.GetFileSystemEntries(source).OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            {
                if (Directory.Exists(entry)) ImportFolder(entry);
                else ImportFile(entry);
            }
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
        private void ReleaseKeys()
        {
            if (keys != null) { keys.Dispose(); keys = null; }
        }
        public void Dispose()
        {
            ReleaseKeys();
            if (gate != null) { gate.Dispose(); gate = null; }
        }
    }

    internal sealed class PasswordDialog : Form
    {
        internal const int NewPasswordMinimum = 15;
        internal static bool HasMinimumLength(string password)
        {
            int length = 0;
            for (int i = 0; i < password.Length; i++)
            {
                if (Char.IsHighSurrogate(password[i]) && i + 1 < password.Length && Char.IsLowSurrogate(password[i + 1])) i++;
                if (++length >= NewPasswordMinimum) return true;
            }
            return false;
        }
        private readonly TextBox first = new TextBox(), second = new TextBox();
        private readonly bool creating;
        public string Value { get; private set; }
        public PasswordDialog(bool creating, string title, string targetPath = null)
        {
            this.creating = creating; Text = title; Width = 490; Height = creating ? 285 : 225;
            if (targetPath != null) Height += 36;
            Font = new Font("Microsoft YaHei UI", 10); StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false;
            TableLayoutPanel layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(22), ColumnCount = 1, RowCount = (creating ? 6 : 4) + (targetPath == null ? 0 : 1) };
            if (targetPath != null)
                layout.Controls.Add(new TextBox { Text = targetPath, ReadOnly = true, Dock = DockStyle.Top, AccessibleName = "将永久删除的加密文件夹路径" });
            layout.Controls.Add(new Label { Text = creating ? "设置密码（至少 " + NewPasswordMinimum + " 个字符）" : title.Contains("原密码") ? "输入此文件夹的原密码" : "输入密码", AutoSize = true });
            first.AccessibleName = "密码";
            first.UseSystemPasswordChar = true; first.Dock = DockStyle.Top; layout.Controls.Add(first);
            if (creating)
            {
                layout.Controls.Add(new Label { Text = "再次输入密码", AutoSize = true });
                second.AccessibleName = "再次输入密码";
                second.UseSystemPasswordChar = true; second.Dock = DockStyle.Top; layout.Controls.Add(second);
            }
            layout.Controls.Add(new Label { Text = "密码只在本机处理；忘记密码无法恢复。", AutoSize = true, ForeColor = Color.DimGray });
            FlowLayoutPanel buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, Height = 42 };
            Button ok = new Button { Text = "确认", Width = 90, Height = 32 };
            Button cancel = new Button { Text = "取消", Width = 90, Height = 32, DialogResult = DialogResult.Cancel };
            ok.Click += delegate
            {
                if (creating && !HasMinimumLength(first.Text)) { MessageBox.Show(this, "新密码至少需要 " + NewPasswordMinimum + " 个字符。建议使用密码管理器生成长密码。"); return; }
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
            input.AccessibleName = "加密文件夹名称";
            Button ok = new Button { Text = "创建", Left = 350, Top = 75, Width = 110, Height = 34 };
            Button cancel = new Button { Text = "取消", Left = 230, Top = 75, Width = 110, Height = 34, DialogResult = DialogResult.Cancel };
            ok.Click += delegate
            {
                try { if (Paths.Relative(FolderName).IndexOf('/') >= 0) throw new IOException(); DialogResult = DialogResult.OK; }
                catch { MessageBox.Show(this, "请输入有效的单个文件夹名称。"); }
            };
            Controls.Add(input); Controls.Add(ok); Controls.Add(cancel); AcceptButton = ok; CancelButton = cancel;
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

    internal sealed class VaultLibraryForm : Form
    {
        private readonly VaultCatalog catalog;
        private string password;
        private readonly ListView list = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, HideSelection = false, MultiSelect = false, ShowItemToolTips = true, AccessibleName = "加密文件夹列表" };
        private readonly TextBox search = new TextBox { Dock = DockStyle.Fill, AccessibleName = "搜索名称或路径" };
        private readonly Label info = new Label { Dock = DockStyle.Fill, AutoEllipsis = true, TextAlign = ContentAlignment.MiddleLeft };
        private readonly Button scan = new Button { Text = "重新扫描", AutoSize = true }, select = new Button { Text = "选择位置扫描", AutoSize = true }, cancel = new Button { Text = "取消扫描", AutoSize = true, Enabled = false }, open = new Button { Text = "打开所选文件夹", AutoSize = true, Enabled = false }, path = new Button { Text = "查看路径", AutoSize = true, Enabled = false };
        private CancellationTokenSource scanning;
        public string SelectedRoot;
        public VaultLibraryForm(VaultCatalog catalog, string password)
        {
            this.catalog = catalog; this.password = password;
            Text = "我的加密文件夹 · 密封夹"; Font = new Font("Microsoft YaHei UI", 10);
            BackColor = Color.White;
            using (Stream icon = typeof(VaultLibraryForm).Assembly.GetManifestResourceStream("FolderSeal.AppIcon"))
                if (icon != null) Icon = new Icon(icon);
            ClientSize = new Size(940, 570); MinimumSize = new Size(760, 430); StartPosition = FormStartPosition.CenterParent;
            TableLayoutPanel layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(18), ColumnCount = 1, RowCount = 5 };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            foreach (int height in new[] { 34, 44 }) layout.RowStyles.Add(new RowStyle(SizeType.Absolute, height));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 48)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
            layout.Controls.Add(new Label { Text = "搜索名称或路径", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft }, 0, 0);
            layout.Controls.Add(search, 0, 1);
            list.Columns.Add("名称", 180); list.Columns.Add("完整路径", 490); list.Columns.Add("状态", 180); layout.Controls.Add(list, 0, 2);
            list.Resize += delegate { FitColumns(); };
            FlowLayoutPanel buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(0, 8, 0, 0) };
            buttons.Controls.AddRange(new Control[] { scan, select, cancel, open, path }); layout.Controls.Add(buttons, 0, 3); layout.Controls.Add(info, 0, 4); Controls.Add(layout);
            info.Text = catalog.Summary;
            search.TextChanged += delegate { RefreshRows(); };
            scan.Click += async delegate { await Scan(VaultDiscovery.FixedRoots(), true); };
            select.Click += async delegate
            {
                using (FolderBrowserDialog d = new FolderBrowserDialog { Description = "选择本机 NTFS 磁盘或目录" })
                {
                    if (d.ShowDialog(this) != DialogResult.OK) return;
                    try
                    {
                        Paths.NoLinks(d.SelectedPath); DriveInfo drive = new DriveInfo(Path.GetPathRoot(d.SelectedPath));
                        if (!drive.IsReady || drive.DriveFormat != "NTFS" || drive.DriveType == DriveType.Network) throw new IOException("仅支持已就绪的本机 NTFS 磁盘。");
                        await Scan(new[] { d.SelectedPath }, false);
                    }
                    catch (Exception error) { MessageBox.Show(this, error.Message, "无法扫描"); }
                }
            };
            cancel.Click += delegate { if (scanning != null) scanning.Cancel(); };
            open.Click += delegate { SelectRoot(); }; list.DoubleClick += delegate { SelectRoot(); };
            list.SelectedIndexChanged += delegate { UpdateActions(); };
            list.KeyDown += delegate(object sender, KeyEventArgs e)
            {
                if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; SelectRoot(); }
            };
            path.Click += delegate
            {
                if (list.SelectedItems.Count == 1)
                    MessageBox.Show(this, (string)list.SelectedItems[0].Tag, "完整路径（Ctrl+C 可复制）");
            };
            FormClosing += delegate(object sender, FormClosingEventArgs e)
            {
                if (scanning != null) { scanning.Cancel(); e.Cancel = true; info.Text = "正在停止扫描并保存已发现的位置，请稍候…"; }
            };
            Shown += async delegate { RefreshRows(); if (!catalog.Scanned) await Scan(VaultDiscovery.FixedRoots(), true); };
        }
        private void FitColumns()
        {
            int width = list.ClientSize.Width - SystemInformation.VerticalScrollBarWidth - 4;
            if (width < 300) return;
            list.Columns[0].Width = width / 4;
            list.Columns[2].Width = width / 5;
            list.Columns[1].Width = width - list.Columns[0].Width - list.Columns[2].Width;
            Native.HideHorizontalScrollBar(list);
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing) password = null;
            base.Dispose(disposing);
        }
        private void UpdateActions()
        {
            path.Enabled = list.SelectedItems.Count == 1;
            open.Enabled = scanning == null && path.Enabled && File.Exists(Path.Combine((string)list.SelectedItems[0].Tag, VaultSession.DataName));
        }
        private void SelectRoot()
        {
            UpdateActions();
            if (!open.Enabled) return;
            SelectedRoot = (string)list.SelectedItems[0].Tag; DialogResult = DialogResult.OK; Close();
        }
        internal void RefreshRows()
        {
            list.BeginUpdate();
            try
            {
                list.Items.Clear();
                foreach (VaultLocation e in catalog.Locations.OrderBy(x => x.Path, StringComparer.OrdinalIgnoreCase))
                {
                    if (catalog.Excludes(e.Path)) continue;
                    if (e.Path.IndexOf(search.Text, StringComparison.OrdinalIgnoreCase) < 0) continue;
                    string state = !File.Exists(Path.Combine(e.Path, VaultSession.DataName)) ? "位置不可用" : File.Exists(Path.Combine(e.Path, ".pending-rekey-journal.egvault")) ? "改密待恢复" : e.Managed ? "已统一密码" : "待接入";
                    list.Items.Add(new ListViewItem(new[] { new DirectoryInfo(e.Path).Name, e.Path, state }) { Tag = e.Path, ToolTipText = e.Path });
                }
            }
            finally { list.EndUpdate(); }
            FitColumns();
            UpdateActions();
            if (scanning == null)
                info.Text = list.Items.Count > 0 ? catalog.Summary :
                    search.TextLength > 0 ? "未找到匹配项。请修改或清空搜索。" :
                    "暂无加密文件夹记录。可重新扫描或选择位置扫描。";
        }
        private async Task Scan(string[] roots, bool allFixed)
        {
            if (scanning != null) return;
            scanning = new CancellationTokenSource(); scan.Enabled = select.Enabled = open.Enabled = false; cancel.Enabled = true;
            try
            {
                bool accepting = true;
                Progress<ScanProgress> progress = new Progress<ScanProgress>(delegate(ScanProgress s)
                {
                    if (!accepting) return;
                    if (s.Found != null) { catalog.Add(s.Found, false); RefreshRows(); }
                    info.Text = "已发现 " + catalog.Locations.Count + " 个 · 已检查 " + s.Visited + " 个目录 · 跳过 " + s.Skipped;
                });
                ScanProgress result = await Task.Run(delegate { return VaultDiscovery.Scan(roots, scanning.Token, progress); });
                accepting = false;
                foreach (string path in result.FoundPaths) catalog.Add(path, false);
                catalog.Scanned = true; catalog.Complete = allFixed && roots.Length > 0 && !scanning.IsCancellationRequested && result.Skipped == 0;
                catalog.Skipped = result.Skipped;
                catalog.Summary = (allFixed ? "本机固定磁盘" : "指定位置") + "（" + String.Join("、", roots) + "）扫描" + (scanning.IsCancellationRequested ? "已取消，结果已保留" : catalog.Complete ? "已完成" : "未完整覆盖本机") + " · 共记录 " + catalog.Locations.Count + " 个 · 跳过 " + result.Skipped + "；下次直接显示列表";
                await Task.Run(delegate { catalog.Save(password); });
                info.Text = catalog.Summary; RefreshRows();
            }
            catch (Exception error) { MessageBox.Show(this, "扫描或保存位置失败，当前发现结果仍在本次列表中。\r\n" + error.Message, "操作未完成"); }
            finally
            {
                scanning.Dispose(); scanning = null; scan.Enabled = select.Enabled = true; cancel.Enabled = false;
                UpdateActions();
                if (list.Items.Count == 0)
                    info.Text = search.TextLength > 0 ? "未找到匹配项。请修改或清空搜索。" : catalog.Summary;
            }
        }
    }

    internal sealed class MainForm : Form
    {
        private static readonly Color Green = Color.FromArgb(36, 91, 70), Ink = Color.FromArgb(38, 60, 50), Muted = Color.FromArgb(82, 103, 87), Line = Color.FromArgb(218, 229, 213);
        private readonly Label status = new Label { Dock = DockStyle.Fill, ForeColor = Muted, TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true };
        private readonly TextBox hint = new TextBox { ReadOnly = true, Multiline = true, WordWrap = true, Dock = DockStyle.Fill, BorderStyle = BorderStyle.None, AccessibleName = "操作提示详情" };
        private readonly ListView files = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = false, BorderStyle = BorderStyle.None, HideSelection = false, BackColor = Color.White };
        private readonly ImageList fileImages = new ImageList { ImageSize = new Size(24, 32), ColorDepth = ColorDepth.Depth32Bit };
        private readonly FlowLayoutPanel actions = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(0, 6, 0, 0) };
        private readonly Label vaultName = new Label { Anchor = AnchorStyles.Left | AnchorStyles.Right, Height = 30, Font = new Font("Microsoft YaHei UI", 14, FontStyle.Bold), ForeColor = Ink, AutoEllipsis = true, UseMnemonic = false, TextAlign = ContentAlignment.MiddleLeft };
        private readonly Label badge = new Label { AutoSize = true, Padding = new Padding(9, 5, 9, 5), Margin = new Padding(10, 10, 14, 0), ForeColor = Green, BackColor = Color.FromArgb(230, 240, 222) };
        private readonly Label noticeTitle = new Label { Dock = DockStyle.Fill, Font = new Font("Microsoft YaHei UI", 10, FontStyle.Bold), TextAlign = ContentAlignment.MiddleLeft };
        private readonly Panel notice = new Panel { Dock = DockStyle.Fill, Padding = new Padding(12, 8, 12, 8), Margin = new Padding(0, 0, 0, 8) };
        private readonly Label empty = new Label { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter, ForeColor = Muted, Padding = new Padding(24), BackColor = Color.White };
        private readonly Label count = new Label { AutoSize = true, ForeColor = Muted, Margin = new Padding(12, 15, 0, 0) };
        private readonly Label switchReason = new Label { Dock = DockStyle.Fill, ForeColor = Muted };
        private readonly ProgressBar progress = new ProgressBar { Dock = DockStyle.Bottom, Height = 3, Style = ProgressBarStyle.Marquee, MarqueeAnimationSpeed = 35, Visible = false };
        private readonly ToolTip tips = new ToolTip { AutoPopDelay = 15000 };
        private readonly ContextMenuStrip moreMenu = new ContextMenuStrip { ShowImageMargin = false };
        private TableLayoutPanel body, sidebar, identityBar, noticeText;
        private ToolStripMenuItem delete, recover, explorerMenu;
        private readonly string sessionsBase = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "EurekaGao", "FolderSeal", "Sessions");
        private string pendingSource, pendingSeal;
        private VaultSession session;
        private bool busy, closing, operationFailed, handlingLaunch;
        private string lastFailure;
        private string masterPassword;
        private readonly VaultCatalog catalog = new VaultCatalog(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "EurekaGao", "FolderSeal", "catalog.egcatalog"));
        private Button library;
        private readonly LinkLabel updateLink = new LinkLabel { Text = "检测升级", AccessibleName = "检测升级", Dock = DockStyle.Fill, Margin = new Padding(5, 0, 0, 0), TextAlign = ContentAlignment.MiddleLeft, LinkBehavior = LinkBehavior.HoverUnderline };
        private bool checkingUpdate;
        private UpdateInfo availableUpdate;
        private Func<Task<UpdateInfo>> updateLookup = UpdateChecker.CheckAsync;
        private Button create, choose, unlock, show, importFiles, importFolder, lockButton, more;
        public MainForm(string source, string openRoot, string stateRoot = null, string sealPath = null)
        {
            if (stateRoot != null)
            {
                sessionsBase = Path.Combine(stateRoot, "Sessions");
                catalog = new VaultCatalog(Path.Combine(stateRoot, "catalog.egcatalog"));
            }
            pendingSource = source; pendingSeal = sealPath;
            handlingLaunch = !String.IsNullOrEmpty(openRoot) || !String.IsNullOrEmpty(sealPath);
            Text = "密封夹";
            using (Stream iconStream = typeof(MainForm).Assembly.GetManifestResourceStream("FolderSeal.AppIcon"))
                Icon = new Icon(iconStream);
            Font = new Font("Microsoft YaHei UI", 10); AutoScaleMode = AutoScaleMode.Dpi; AutoScaleDimensions = new SizeF(96, 96);
            ClientSize = new Size(1160, 760); MinimumSize = new Size(1080, 720); StartPosition = FormStartPosition.CenterScreen;
            BackColor = Color.White; ForeColor = Ink; KeyPreview = true;
            TableLayoutPanel shell = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
            shell.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 212)); shell.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            shell.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            sidebar = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = Color.FromArgb(247, 249, 244), Padding = new Padding(18, 27, 18, 18), ColumnCount = 1, RowCount = 9 };
            sidebar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            foreach (int h in new[] { 43, 44, 56, 56, 56, 64 }) sidebar.RowStyles.Add(new RowStyle(SizeType.Absolute, h));
            sidebar.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); sidebar.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            sidebar.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
            sidebar.Controls.Add(new Label { Text = "密封夹", Dock = DockStyle.Fill, Font = new Font(Font.FontFamily, 20, FontStyle.Bold), ForeColor = Green }, 0, 0);
            sidebar.Controls.Add(new Label { Text = "你的文件，\r\n只有你能打开。", Dock = DockStyle.Fill, ForeColor = Muted }, 0, 1);
            create = Add("＋ 创建加密文件夹", CreateVault); choose = Add("选择已有文件夹", ChooseVault);
            create.Dock = choose.Dock = DockStyle.Fill; create.Margin = choose.Margin = new Padding(0, 11, 0, 3);
            sidebar.Controls.Add(create, 0, 2); sidebar.Controls.Add(choose, 0, 3);
            library = Add("我的加密文件夹", async delegate { await ShowLibrary(); }); library.Dock = DockStyle.Fill; library.Margin = new Padding(0, 11, 0, 3); sidebar.Controls.Add(library, 0, 4);
            switchReason.Padding = new Padding(2, 12, 0, 0); sidebar.Controls.Add(switchReason, 0, 5);
            LinkLabel helpLink = new LinkLabel { Text = "使用帮助与异常恢复", AccessibleName = "使用帮助与异常恢复", Dock = DockStyle.Fill, Margin = new Padding(5, 0, 0, 0), LinkColor = Green, ActiveLinkColor = Green, LinkBehavior = LinkBehavior.HoverUnderline, TextAlign = ContentAlignment.MiddleLeft, Font = new Font(Font.FontFamily, 9) };
            helpLink.LinkClicked += delegate { ShowHelp(this, EventArgs.Empty); };
            sidebar.Controls.Add(helpLink, 0, 7);
            updateLink.Font = helpLink.Font; updateLink.LinkColor = updateLink.ActiveLinkColor = Green;
            updateLink.LinkClicked += async delegate { if (availableUpdate != null) OfferUpdate(availableUpdate); else await CheckForUpdates(true); };
            tips.SetToolTip(updateLink, "当前版本 " + UpdateChecker.CurrentVersion.ToString(3) + "；检查公开发布的安装包。");
            sidebar.Controls.Add(updateLink, 0, 8);
            body = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(27, 24, 27, 12), ColumnCount = 1, RowCount = 5 };
            body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            foreach (int h in new[] { 56, 0, 56 }) body.RowStyles.Add(new RowStyle(SizeType.Absolute, h));
            body.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            body.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
            identityBar = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, RowCount = 1, Margin = Padding.Empty };
            identityBar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); identityBar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            identityBar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 180)); identityBar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 84));
            identityBar.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            identityBar.Controls.Add(vaultName, 0, 0); identityBar.Controls.Add(badge, 1, 0);
            unlock = Add("解锁文件夹", UnlockVault); lockButton = Add("保存并锁定", LockVault); Primary(unlock); Primary(lockButton);
            Panel primaryArea = new Panel { Dock = DockStyle.Fill, Padding = new Padding(0, 5, 7, 9), Margin = Padding.Empty };
            unlock.Dock = lockButton.Dock = DockStyle.Fill; primaryArea.Controls.Add(unlock); primaryArea.Controls.Add(lockButton);
            identityBar.Controls.Add(primaryArea, 2, 0);
            more = Add("更多 ▾", delegate { moreMenu.Show(more, new Point(0, more.Height)); }); more.Dock = DockStyle.Fill; more.Margin = new Padding(4, 5, 0, 9);
            identityBar.Controls.Add(more, 3, 0); body.Controls.Add(identityBar, 0, 0);
            moreMenu.Font = Font;
            recover = new ToolStripMenuItem("恢复未锁定工作区", null, Recover);
            explorerMenu = new ToolStripMenuItem("添加到资源管理器右键菜单", null, ToggleExplorerMenu);
            delete = new ToolStripMenuItem("删除加密文件夹…", null, DeleteVault) { ForeColor = Color.FromArgb(157, 56, 52), ToolTipText = "永久删除，不进入回收站；需再次验证密码。" };
            moreMenu.Items.AddRange(new ToolStripItem[] { recover, explorerMenu, new ToolStripSeparator(), delete });
            noticeText = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = Padding.Empty };
            noticeText.RowStyles.Add(new RowStyle(SizeType.Absolute, 26)); noticeText.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            noticeText.Controls.Add(noticeTitle, 0, 0); hint.Font = new Font(Font.FontFamily, 9); hint.Margin = new Padding(0, 4, 0, 0); noticeText.Controls.Add(hint, 0, 1);
            notice.Controls.Add(noticeText); notice.Controls.Add(progress); body.Controls.Add(notice, 0, 1);
            TableLayoutPanel toolbar = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1 };
            toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 180)); toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            FlowLayoutPanel fileHeading = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false };
            fileHeading.Controls.Add(new Label { Text = "文件内容", AutoSize = true, Font = new Font(Font.FontFamily, 10, FontStyle.Bold), Margin = new Padding(0, 15, 0, 0) }); fileHeading.Controls.Add(count);
            toolbar.Controls.Add(fileHeading, 0, 0);
            show = Add("打开所在文件夹", ShowWorkspace); importFiles = Add("导入文件", ImportFiles); importFolder = Add("导入文件夹", ImportFolder);
            show.BackColor = Color.FromArgb(235, 244, 226); actions.Controls.Add(show); actions.Controls.Add(importFolder); actions.Controls.Add(importFiles);
            toolbar.Controls.Add(actions, 1, 0); body.Controls.Add(toolbar, 0, 2);
            Panel fileArea = new Panel { Dock = DockStyle.Fill, Padding = new Padding(1), BackColor = Line };
            files.Columns.Add("名称", 400); files.Columns.Add("大小", 100); files.Columns.Add("修改时间", 170);
            files.SmallImageList = fileImages; files.ShowItemToolTips = true;
            files.OwnerDraw = true;
            files.DrawColumnHeader += delegate(object sender, DrawListViewColumnHeaderEventArgs e) {
                using (Brush brush = new SolidBrush(Color.FromArgb(247, 249, 246))) e.Graphics.FillRectangle(brush, e.Bounds);
                TextRenderer.DrawText(e.Graphics, e.Header.Text, files.Font, Rectangle.Inflate(e.Bounds, -8, 0), Muted, TextFormatFlags.Left | TextFormatFlags.VerticalCenter);
            };
            files.DrawItem += delegate(object sender, DrawListViewItemEventArgs e) { e.DrawDefault = true; };
            files.DrawSubItem += delegate(object sender, DrawListViewSubItemEventArgs e) { e.DrawDefault = true; };
            files.ItemActivate += OpenSelectedFile;
            FormClosed += delegate { fileImages.Dispose(); tips.Dispose(); moreMenu.Dispose(); };
            fileArea.Controls.Add(files); fileArea.Controls.Add(empty); body.Controls.Add(fileArea, 0, 3);
            files.Resize += delegate { FitFileColumns(); };
            status.Font = new Font(Font.FontFamily, 9); status.AccessibleName = "操作结果"; body.Controls.Add(status, 0, 4);
            tips.SetToolTip(show, "打开解锁后的临时编辑目录，可在其中整理文件。");
            tips.SetToolTip(more, "查看恢复与删除操作；执行前需先保存并锁定。");
            tips.SetToolTip(lockButton, "先在编辑器中保存并关闭文件。快捷键 Alt + L。");
            tips.SetToolTip(importFiles, "复制到编辑区，保留源文件；同名文件不自动覆盖。"); tips.SetToolTip(importFolder, "复制整个文件夹，保留原文件夹。");
            shell.Controls.Add(sidebar, 0, 0); shell.Controls.Add(body, 1, 0); Controls.Add(shell);
            FormClosing += OnClosing;
            Shown += async delegate
            {
                if (!String.IsNullOrEmpty(pendingSeal))
                {
                    string sealTarget = pendingSeal; pendingSeal = null;
                    handlingLaunch = true;
                    try { await SealFromExplorer(sealTarget); }
                    finally { handlingLaunch = false; Close(); }
                    return;
                }
                if (stateRoot == null) StartStartupUpdateCheck();
                handlingLaunch = true;
                try
                {
                    if (Directory.Exists(sessionsBase) && Directory.GetDirectories(sessionsBase).Length > 0)
                        MessageBox.Show(this, "检测到上次未清理的工作区，其中可能仍有明文。请选择对应加密文件夹，在“更多”中选择“恢复未锁定工作区”，检查后保存并锁定。", "需要恢复", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    if (!String.IsNullOrEmpty(openRoot)) await OpenFromEntry(openRoot);
                }
                finally { handlingLaunch = false; }
            };
            UpdateExplorerMenu();
            RefreshState("尚未选择加密文件夹");
        }
        private async void StartStartupUpdateCheck() { await CheckForUpdates(false); }
        private async Task CheckForUpdates(bool interactive)
        {
            if (checkingUpdate || IsDisposed || Disposing) return;
            checkingUpdate = true; updateLink.Enabled = false; updateLink.Text = "正在检测升级…";
            try
            {
                UpdateInfo result = await updateLookup();
                if (IsDisposed || Disposing) return;
                availableUpdate = result;
                updateLink.Text = result == null ? "检测升级" : "发现新版 " + result.Version.ToString(3);
                if (interactive)
                {
                    if (result == null) MessageBox.Show(this, "当前版本：" + UpdateChecker.CurrentVersion.ToString(3) + "\r\n未发现更新的已发布安装包。", "检测升级", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    else OfferUpdate(result);
                }
            }
            catch (Exception)
            {
                if (!IsDisposed && !Disposing)
                {
                    updateLink.Text = "检测升级";
                    if (interactive) MessageBox.Show(this, "暂时无法检查更新。请检查网络，或稍后再试。\r\n文件加密和编辑功能可继续使用。", "检测升级未完成", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            finally { checkingUpdate = false; if (!IsDisposed && !Disposing) updateLink.Enabled = true; }
        }
        private void OfferUpdate(UpdateInfo update)
        {
            string message = "当前版本：" + UpdateChecker.CurrentVersion.ToString(3) + "\r\n新版本：" + update.Version.ToString(3) + (update.Prerelease ? "（预发布版，仍有验证工作未完成）" : "") + "\r\n\r\n是否打开浏览器下载安装包？\r\n安装前请保存并锁定资料，正常退出软件，再运行安装包。";
            if (MessageBox.Show(this, message, "发现新版本", MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes)
            {
                try { Process.Start(new ProcessStartInfo(update.DownloadUrl) { UseShellExecute = true }); }
                catch (Exception) { MessageBox.Show(this, "无法打开浏览器，请检查默认浏览器设置后重试。", "下载未开始"); }
            }
        }
        private async Task<bool> EnsureMaster(bool requirePassword = false)
        {
            if (!requirePassword && masterPassword != null) return true;
            bool creating = !File.Exists(catalog.FilePath);
            if (creating) MessageBox.Show(this, "请设置密码，用于打开所有加密文件夹。以后访问加密资料时输入。\r\n旧文件夹需先验证原密码，再统一使用此密码。\r\n忘记密码无法恢复，请单独妥善保管。", "设置密码");
            while (true)
            {
                string supplied = AskPassword(creating, creating ? "设置密码" : "输入密码");
                if (supplied == null) return false;
                Enabled = false;
                try
                {
                    await Task.Run(delegate
                    {
                        if (creating) catalog.Save(supplied);
                        else { catalog.Load(supplied); if (catalog.NeedsSave) catalog.Save(supplied); }
                    });
                    masterPassword = supplied; return true;
                }
                catch (Exception error) { MessageBox.Show(this, "密码错误，或目录表无法读取/保存。未重置目录表。\r\n" + error.Message, "验证未完成"); }
                finally { Enabled = true; supplied = null; }
            }
        }
        private void ReleaseAuthorization()
        {
            masterPassword = null;
            catalog.Locations.Clear();
            catalog.Scanned = catalog.Complete = false;
            catalog.Skipped = 0;
            catalog.Summary = "尚未扫描";
        }
        private async Task ShowLibrary()
        {
            if (busy) return;
            if (session != null && session.Open) { MessageBox.Show(this, "请先保存并锁定当前文件夹，再切换资料。", "请先锁定"); return; }
            try
            {
                if (!await EnsureMaster(true)) return;
                string root;
                using (VaultLibraryForm dialog = new VaultLibraryForm(catalog, masterPassword))
                { if (dialog.ShowDialog(this) != DialogResult.OK) return; root = dialog.SelectedRoot; }
                await OpenFromEntry(root, true);
            }
            finally { ReleaseAuthorization(); }
        }
        private static void Primary(Button button) { button.BackColor = Green; button.ForeColor = Color.White; button.FlatAppearance.BorderColor = Green; button.FlatAppearance.MouseOverBackColor = Color.FromArgb(28, 76, 56); button.Font = new Font("Microsoft YaHei UI", 10, FontStyle.Bold); }
        private void ToggleExplorerMenu(object sender, EventArgs e)
        {
            try
            {
                if (ExplorerMenu.Installed(ExplorerMenu.ClassesRoot)) ExplorerMenu.Erase(ExplorerMenu.ClassesRoot);
                else ExplorerMenu.Write(ExplorerMenu.ClassesRoot, Application.ExecutablePath,
                    "加密此文件夹（密封夹）", "加密此文件（密封夹）", "用密封夹打开");
                UpdateExplorerMenu();
                status.Text = ExplorerMenu.Installed(ExplorerMenu.ClassesRoot)
                    ? "已添加到资源管理器右键菜单；菜单指向当前程序位置。" : "已从资源管理器右键菜单移除。";
            }
            catch (Exception error)
            {
                MessageBox.Show(this, "无法修改资源管理器右键菜单。\r\n" + error.Message, "操作未完成", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
        private void UpdateExplorerMenu()
        {
            if (explorerMenu == null) return;
            bool installed = false;
            try { installed = ExplorerMenu.Installed(ExplorerMenu.ClassesRoot); } catch (Exception) { }
            explorerMenu.Text = installed ? "从资源管理器右键菜单移除" : "添加到资源管理器右键菜单";
        }
        private void ShowHelp(object sender, EventArgs e)
        {
            using (Form help = CreateHelpDialog()) help.ShowDialog(this);
        }
        internal Form CreateHelpDialog()
        {
            Form help = new Form { Text = "操作与恢复帮助 · 密封夹", Font = Font, ForeColor = Ink, BackColor = Color.White, ClientSize = new Size(690, 590), MinimumSize = new Size(570, 430), StartPosition = FormStartPosition.CenterParent, MinimizeBox = false, MaximizeBox = false };
            {
                TableLayoutPanel layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(22), RowCount = 2, ColumnCount = 1 };
                layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 49));
                RichTextBox text = new RichTextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, WordWrap = true, DetectUrls = false, ScrollBars = RichTextBoxScrollBars.Vertical, BorderStyle = BorderStyle.None, BackColor = Color.White, ForeColor = Ink, Text =
                    "日常编辑\r\n输入密码解锁 → 打开临时编辑区 → 用原有软件编辑 → 保存并关闭文件 → 回到这里保存并锁定。仅关闭资源管理器不会锁定。解锁时，同一 Windows 账户可访问明文。\r\n\r\n保存失败\r\n先关闭可能占用文件的 Word、Excel 等程序，再重试。保存失败时保留当前编辑区，不要自行删除；具体原因以错误提示为准。\r\n\r\n密文已保存，清理未完成\r\n关闭占用文件的程序，点击“重试清理并锁定”。此时只继续清理，不重新生成密文；清理完成前不能继续导入或编辑。\r\n\r\n异常退出\r\n选择对应加密文件夹，在“更多”中选择“恢复未锁定工作区”，按时间和状态选择记录并验证密码。来源版本不同或无法确认时，程序保留两份内容。按提示将所需文件复制到另一个加密文件夹，核对后保存并锁定。\r\n\r\n备份与密码\r\n锁定后备份整个密文目录，包括隐藏目录。快捷方式不是资料。普通导入保留源文件。忘记密码无法找回。\r\n\r\n快捷操作\r\nAlt + L：保存或重试锁定。文件夹管理操作需先锁定。处理中请等待结果，不要强制退出。\r\n\r\n保护范围\r\n管理员仍可强制删除。明文采用普通删除，不保证清除磁盘残留、编辑器缓存或历史副本；软件尚未经过独立安全审计。" };
                Button close = Add("返回", delegate { help.Close(); }); close.DialogResult = DialogResult.Cancel; close.Anchor = AnchorStyles.Right | AnchorStyles.Bottom;
                layout.Controls.Add(text, 0, 0); layout.Controls.Add(close, 0, 1); help.Controls.Add(layout); help.CancelButton = close; return help;
            }
        }
        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            if (keyData == (Keys.Alt | Keys.L) && !busy && session != null && session.Open) { LockVault(this, EventArgs.Empty); return true; }
            return base.ProcessCmdKey(ref msg, keyData);
        }
        protected override void Dispose(bool disposing) { if (disposing) { masterPassword = null; tips.Dispose(); moreMenu.Dispose(); } base.Dispose(disposing); }
        internal string LaunchAction(string[] args)
        {
            if (args.Length == 0) return "activate";
            if (busy || closing || handlingLaunch || !Enabled || OwnedForms.Any(x => x.Visible)) return "busy";
            if (session != null && session.Open)
                return args[0] == "--open-vault" && !session.CleanupPending &&
                    Paths.Full(args[1]).Equals(session.Root, StringComparison.OrdinalIgnoreCase) ? "existing" : "lock-first";
            return args[0] == "--open-vault" ? "open" : (args[0] == "--seal" ? "seal" : "source");
        }
        internal async Task HandleLaunch(string[] args)
        {
            if (IsDisposed || Disposing) return;
            if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
            Show(); Activate(); BringToFront();
            Form dialog = OwnedForms.LastOrDefault(x => x.Visible);
            if (dialog != null) { dialog.Activate(); dialog.BringToFront(); }
            string action = LaunchAction(args);
            if (action == "activate") return;
            if (action == "busy") { status.Text = "已有操作或对话框正在进行；请完成后重新打开资料入口。"; return; }
            if (action == "lock-first")
            {
                MessageBox.Show(this, "当前资料尚未完成保存与锁定。\r\n请先保存正在编辑的文件，再在这里保存并锁定，然后重新打开目标入口。\r\n当前编辑区已保留，未切换资料。", "请先保存并锁定", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            handlingLaunch = true;
            try
            {
                if (action == "existing")
                {
                    try
                    {
                        if (await EnsureMaster(true)) { ShowWorkspace(this, EventArgs.Empty); status.Text = "此资料已解锁，已打开原编辑区。"; }
                    }
                    finally { ReleaseAuthorization(); }
                }
                else if (action == "open") await OpenFromEntry(args[1]);
                else if (action == "seal") await SealFromExplorer(args[1]);
                else
                {
                    if (!File.Exists(args[1])) { MessageBox.Show(this, "待加密的源文件不存在。", "无法选择源文件"); return; }
                    pendingSource = args[1]; RefreshState("已接收待加密文件；请创建加密文件夹。");
                }
            }
            finally { handlingLaunch = false; }
        }
        private Task<bool> EnsureOpenPassword(bool fromLibrary)
        {
            return EnsureMaster(!fromLibrary);
        }
        private async Task OpenFromEntry(string root, bool fromLibrary = false)
        {
            try
            {
                if (!await EnsureOpenPassword(fromLibrary)) return;
                if (session != null && session.Open) { MessageBox.Show(this, "请先保存并锁定当前文件夹。", "无法切换"); return; }
                Paths.NoLinks(root);
                Header.Read(Path.Combine(root, VaultSession.DataName));
                if (session != null) session.Dispose();
                session = new VaultSession(root, sessionsBase, true);
                pendingSource = null;
                RefreshState("正在打开：" + new DirectoryInfo(root).Name);
                if (!await Run(delegate { catalog.Add(session.Root, false); catalog.Save(masterPassword); return "位置已记住"; })) return;
                if (session.HasUnfinishedWorkspace)
                {
                    RefreshState("发现遗留工作区，请在“更多”中恢复。");
                    MessageBox.Show(this, "此加密文件夹有遗留工作区，已停在锁定状态。请先在“更多”中选择“恢复未锁定工作区”。", "发现遗留工作区", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                if (!await PrepareManaged()) return;
                bool opened = await Run(delegate { session.Unlock(masterPassword); return "已解锁 · 使用结束后请保存并锁定"; });
                if (opened) ShowWorkspace(this, EventArgs.Empty);
            }
            catch (Exception error) { MessageBox.Show(this, error.Message, "无法打开加密文件夹"); }
            finally { ReleaseAuthorization(); }
        }
        private async Task<bool> PrepareManaged()
        {
            if (session.HasPendingMigration)
                if (!await Run(delegate { session.ChangePassword(null, masterPassword); return "改密恢复完成"; })) return false;
            VaultLocation known = catalog.Locations.FirstOrDefault(x => String.Equals(x.Path, session.Root, StringComparison.OrdinalIgnoreCase));
            if (known == null || !known.Managed)
            {
                bool matches = false;
                if (!await Run(delegate
                {
                    try { matches = session.AcceptsPassword(masterPassword); } catch (CryptographicException) { matches = false; }
                    return matches ? "已使用当前密码" : "此文件夹需要统一密码";
                })) return false;
                if (!matches)
                {
                    if (session.HasUnfinishedWorkspace)
                    { MessageBox.Show(this, "此目录还有未恢复的明文工作区。请先在“更多”中恢复工作区，保存并锁定后，再统一密码。", "先恢复工作区"); return false; }
                    if (MessageBox.Show(this, "接入后，当前快照和目录内的上一版本将改用当前密码，原密码失效。\r\n其他位置的副本和备份不会改密，仍需各自原密码。\r\n请确保没有其他版本的程序或未恢复的工作区正在使用此目录。继续吗？", "统一密码", MessageBoxButtons.OKCancel, MessageBoxIcon.Information, MessageBoxDefaultButton.Button2) != DialogResult.OK) return false;
                    string old = AskPassword(false, "输入此文件夹的原密码 · " + new DirectoryInfo(session.Root).Name);
                    if (old == null) return false;
                    try { if (!await Run(delegate { session.ChangePassword(old, masterPassword); return "已改用当前密码"; })) return false; }
                    finally { old = null; }
                }
            }
            return await Run(delegate { catalog.Add(session.Root, true); catalog.Save(masterPassword); return "位置已记住 · 已统一密码"; });
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
            library.Enabled = !busy && !open;
            unlock.Enabled = !busy && has && !open; unlock.Visible = has && !open;
            lockButton.Enabled = !busy && open; lockButton.Visible = open;
            show.Enabled = importFiles.Enabled = importFolder.Enabled = editable; actions.Visible = editable;
            delete.Enabled = recover.Enabled = !busy && has && !open;
            more.Enabled = has && !busy;
            recover.Text = open ? "恢复未锁定工作区（需先保存并锁定）" : "恢复未锁定工作区";
            delete.Text = open ? "删除加密文件夹…（需先保存并锁定）" : "删除加密文件夹…";
            identityBar.Visible = has; body.RowStyles[0].Height = has ? 56 : 0;
            lockButton.Text = busy ? "处理中，请稍候…" : cleanup ? "重试清理并锁定" : operationFailed ? "重试保存并锁定" : "保存并锁定";
            vaultName.Text = has ? new DirectoryInfo(session.Root).Name : "尚未选择加密文件夹";
            vaultName.AccessibleDescription = has ? session.Root : "";
            tips.SetToolTip(vaultName, has ? session.Root : "");
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
            else if (open) { noticeTitle.Text = ""; hint.Text = "临时明文编辑区，同一 Windows 账户可访问。双击打开文件，保存并关闭文件后再锁定。"; notice.BackColor = Color.White; hint.ForeColor = Muted; }
            else { noticeTitle.Text = ""; hint.Text = ""; }
            bool pending = !String.IsNullOrEmpty(pendingSource) && File.Exists(pendingSource) && !busy;
            if (pending)
            {
                if (hint.Text.Length > 0) hint.Text += "\r\n";
                else noticeTitle.Text = "待加密文件";
                hint.Text += "待移入：" + Path.GetFileName(pendingSource) + "。请从左侧创建文件夹；加密核验成功且源文件未变化后，才会移除源明文。";
            }
            LayoutNotice(busy || cleanup || operationFailed || open || pending, busy || cleanup || operationFailed || pending);
            files.BeginUpdate();
            try
            {
                files.Items.Clear();
                if (editable && Directory.Exists(session.Work))
                    foreach (string file in Paths.Files(session.Work))
                    {
                        FileInfo info = new FileInfo(file);
                        string relative = Paths.NameUnder(session.Work, file);
                        files.Items.Add(new ListViewItem(new[] { relative, FormatSize(info.Length), info.LastWriteTime.ToString("yyyy-MM-dd HH:mm") }, FileImage(file)) { ToolTipText = relative });
                    }
            }
            finally { files.EndUpdate(); }
            files.Visible = editable && files.Items.Count > 0; empty.Visible = !files.Visible;
            if (files.Visible) FitFileColumns();
            empty.Text = busy ? "正在处理，请稍候…\r\n全部步骤完成后才会显示“已锁定”。" : cleanup ? "等待完成明文清理\r\n请关闭占用文件的程序，再重试清理。" : open ? "编辑区还没有文件\r\n导入文件、文件夹，或打开编辑区放入资料。" : has ? "文件已锁定\r\n点击解锁后查看和编辑文件。\r\n锁定时不展示文件名称与内容。" : "从一个加密文件夹开始\r\n点击左侧“我的加密文件夹”查看记录，或创建、选择文件夹。";
            count.Visible = editable; count.Text = files.Items.Count.ToString() + " 个文件";
            switchReason.Visible = open || busy;
            sidebar.RowStyles[5].Height = open || busy ? 72 : 0;
            switchReason.Text = "锁定后可切换文件夹。";
            status.Text = busy || operationFailed || cleanup || (!has && !pending && message == "尚未选择加密文件夹") || (message != null && message.StartsWith("已解锁")) ? "" : message;
            tips.SetToolTip(status, status.Text); tips.SetToolTip(hint, hint.Text);
        }
        private void FitFileColumns()
        {
            int width = files.ClientSize.Width - SystemInformation.VerticalScrollBarWidth - 4;
            if (width < 300) return;
            files.Columns[1].Width = width / 7;
            files.Columns[2].Width = width / 5;
            files.Columns[0].Width = width - files.Columns[1].Width - files.Columns[2].Width;
            Native.HideHorizontalScrollBar(files);
        }
        private void LayoutNotice(bool visible, bool detailed)
        {
            notice.Visible = visible;
            body.RowStyles[1].Height = !visible ? 0 : detailed ? (operationFailed ? 120 : 92) : 52;
            noticeTitle.Visible = detailed;
            noticeText.RowStyles[0].Height = detailed ? 26 : 0;
            hint.BackColor = notice.BackColor;
            hint.ScrollBars = detailed && HintOverflows() ? ScrollBars.Vertical : ScrollBars.None;
            hint.TabStop = detailed;
        }
        private bool HintOverflows()
{
            if (String.IsNullOrEmpty(hint.Text)) return false;
            int width = notice.ClientSize.Width - notice.Padding.Horizontal - SystemInformation.VerticalScrollBarWidth;
            int height = (int)body.RowStyles[1].Height - notice.Padding.Vertical - progress.Height
                - (noticeTitle.Visible ? (int)noticeText.RowStyles[0].Height : 0) - hint.Margin.Vertical;
            if (width < 60 || height <= 0) return false;
            Size measured = TextRenderer.MeasureText(hint.Text, hint.Font, new Size(width, Int32.MaxValue),
                TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl | TextFormatFlags.NoPadding);
            return measured.Height > height;
        }
        private int FileImage(string path)
        {
            string extension = Path.GetExtension(path).ToUpperInvariant();
            string key = extension.Length == 0 ? "(none)" : extension;
            if (!fileImages.Images.ContainsKey(key))
            {
                using (Bitmap bitmap = new Bitmap(24, 32))
                using (Graphics graphics = Graphics.FromImage(bitmap))
                using (Brush paper = new SolidBrush(Color.FromArgb(235, 242, 237)))
                using (Font font = new Font("Segoe UI", 6, FontStyle.Bold))
                {
                    graphics.FillRectangle(paper, 2, 5, 20, 23);
                    graphics.DrawRectangle(Pens.Gray, 2, 5, 20, 23);
                    string label = extension.TrimStart('.');
                    if (label.Length == 0) label = "FILE";
                    if (label.Length > 4) label = label.Substring(0, 4);
                    TextRenderer.DrawText(graphics, label, font, new Rectangle(1, 7, 23, 20), Green, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
                    fileImages.Images.Add(key, bitmap);
                    // Materialize the native image list before disposing the source bitmap.
                    IntPtr imageHandle = fileImages.Handle;
                }
            }
            return fileImages.Images.IndexOfKey(key);
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
            catch (Exception error)
            {
                failure = failure ?? error; operationFailed = true; lastFailure = failure.Message;
                noticeTitle.Text = "操作未完成，请保留当前资料"; hint.Text = lastFailure;
                notice.BackColor = Color.FromArgb(255, 244, 238); hint.ForeColor = noticeTitle.ForeColor = Color.FromArgb(148, 55, 47);
                LayoutNotice(true, true);
            }
            if (failure != null)
            {
                string detail = failure.Message;
                if (session != null && session.Open) detail += "\r\n明文工作区仍保留：\r\n" + session.Work;
                MessageBox.Show(this, detail, "操作未完成", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            return failure == null;
        }
        private string AskPassword(bool creating, string title, string targetPath = null)
        {
            using (PasswordDialog dialog = new PasswordDialog(creating, title, targetPath))
                return dialog.ShowDialog(this) == DialogResult.OK ? dialog.Value : null;
        }
        private Func<string, bool> weakParentConfirm = null;
        private bool ConfirmWeakParent(string parent)
{
            return ConfirmWeakParent(parent, String.IsNullOrEmpty(parent) || Native.ParentLacksProtection(parent));
        }
        internal bool ConfirmWeakParent(string parent, bool weak)
{
            if (!weak) return true;
            Func<string, bool> confirm = weakParentConfirm;
            if (confirm != null) return confirm(parent);
            return MessageBox.Show(this,
                "这个位置无法防止整个加密文件夹被移走或删除：\r\n" + parent +
                "\r\n\r\n所在文件夹允许普通程序删除其中的子文件夹，因此加密文件夹可能被整体拖走或放进回收站。" +
                "\r\n\r\n加密内容仍受密码保护，被移走后也打不开；但资料会从原位置消失。" +
                "\r\n\r\n仍要在这里加密吗？",
                "此位置无法防删除", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2) == DialogResult.Yes;
        }
        private async Task SealFromExplorer(string path)
        {
            try
            {
                string full;
                try { full = Paths.Full(path); }
                catch (Exception error)
                { MessageBox.Show(this, "无法读取所选位置。\r\n" + error.Message, "无法加密", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
                if (Directory.Exists(full) && ExplorerMenu.IsVault(full)) { await OpenFromEntry(full); return; }
                if (!Directory.Exists(full) && !File.Exists(full))
                { MessageBox.Show(this, "所选文件或文件夹不存在，可能已被移动或删除。", "无法加密", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
                string inside = VaultAncestor(full);
                if (inside != null)
                { MessageBox.Show(this, "所选内容已经位于加密文件夹内：\r\n" + inside + "\r\n\r\n请直接打开该加密文件夹，不要再次加密。", "无法再次加密", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
                if (Directory.Exists(full) && HasDirectVaultChild(full))
                { MessageBox.Show(this, "此文件夹内已有加密文件夹。请分别处理，避免嵌套加密。", "无法加密", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
                if (!ConfirmWeakParent(Path.GetDirectoryName(full))) return;
                if (!await EnsureMaster(true)) return;
                string password = masterPassword, root = null, warning = null;
                RefreshState("正在加密：" + Path.GetFileName(full));
                bool ok = await Run(delegate
                {
                    SealOutcome outcome = SealPath(full, sessionsBase, password);
                    password = null; root = outcome.Root; warning = outcome.Warning;
                    catalog.Add(root, true); catalog.Save(masterPassword);
                    return "已加密并锁定 · " + root;
                });
                password = null;
                if (!ok) return;
                MessageBox.Show(this, "已加密为：\r\n" + root + "\r\n\r\n" +
                    (String.IsNullOrEmpty(warning) ? "原位置的明文已删除。" : warning), "加密完成", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            finally { ReleaseAuthorization(); }
        }
        private async void CreateVault(object sender, EventArgs e)
        {
            try { await CreateVaultCore(); }
            finally { ReleaseAuthorization(); }
        }
        private async Task CreateVaultCore()
        {
            if (!await EnsureMaster(true)) return;
            string parent;
            using (FolderBrowserDialog dialog = new FolderBrowserDialog { Description = "选择加密文件夹的上级目录", SelectedPath = File.Exists(pendingSource) ? Path.GetDirectoryName(pendingSource) : Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) })
            { if (dialog.ShowDialog(this) != DialogResult.OK) return; parent = dialog.SelectedPath; }
            if (!ConfirmWeakParent(parent)) return;
            string name;
            using (NameDialog dialog = new NameDialog()) { if (dialog.ShowDialog(this) != DialogResult.OK) return; name = dialog.FolderName; }
            string password = masterPassword;
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
                catalog.Add(root, true); catalog.Save(masterPassword);
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
        internal sealed class SealOutcome { internal string Root, Warning; }
        // Explorer entry: seal a file into a same-named vault, or seal a folder in place.
        internal static SealOutcome SealPath(string path, string sessionsBase, string password, bool protect = true)
        {
            string full = Paths.Full(path);
            if (Directory.Exists(full)) return SealDirectory(full, sessionsBase, password, protect);
            if (!File.Exists(full)) throw new IOException("路径不存在：" + full);
            return SealFile(full, sessionsBase, password, protect);
        }
        private static SealOutcome SealFile(string file, string sessionsBase, string password, bool protect)
        {
            Paths.NoLinks(file); Native.RejectHardLink(file);
            string parent = Path.GetDirectoryName(file);
            string name = Path.GetFileNameWithoutExtension(file);
            if (String.IsNullOrEmpty(name)) name = Path.GetFileName(file);
            string root = UniqueRoot(parent, name);
            byte[] before = Paths.Hash(file);
            VaultSession session = new VaultSession(root, sessionsBase, protect);
            try
            {
                session.Create(password);
                session.ImportFile(file);
                if (!Paths.Equal(before, Paths.Hash(Path.Combine(session.Work, Path.GetFileName(file)))))
                    throw new IOException("导入时源文件发生变化。原文件保留，请重试。");
                session.Lock();
            }
            catch
            {
                session.Dispose();
                try { if (Directory.Exists(root)) Paths.DeleteTree(root); } catch (Exception) { }
                throw;
            }
            session.Dispose();
            SealOutcome result = new SealOutcome { Root = root };
            if (!Paths.Equal(before, Paths.Hash(file)))
            { result.Warning = "源文件在加密期间发生变化，原文件已保留：" + file; return result; }
            try { File.Delete(file); }
            catch (Exception error) { result.Warning = "原文件无法删除，请手动删除：" + file + "\r\n" + error.Message; }
            return result;
        }
        private static SealOutcome SealDirectory(string directory, string sessionsBase, string password, bool protect)
        {
            Paths.NoLinks(directory);
            string parent = Path.GetDirectoryName(directory);
            if (String.IsNullOrEmpty(parent)) throw new IOException("不能加密磁盘根目录。");
            string name = Path.GetFileName(directory);
            string parked = Path.Combine(parent, "." + name + ".sealing-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.Move(directory, parked);
            VaultSession session = new VaultSession(directory, sessionsBase, protect);
            try
            {
                session.Create(password);
                session.ImportContents(parked);
                session.Lock();
                session.Dispose();
            }
            catch (Exception error)
            {
                session.Dispose();
                bool cleared = false;
                try { if (Directory.Exists(directory)) Paths.DeleteTree(directory); cleared = true; } catch (Exception) { }
                if (!cleared) throw new IOException("加密未完成，原文件夹已保留在：" + parked + "\r\n原位置存在未清理的加密目录：" + directory, error);
                try { Directory.Move(parked, directory); }
                catch (Exception restore) { throw new IOException("加密未完成，原文件夹在：" + parked + "\r\n恢复到原位置失败：" + restore.Message, error); }
                throw;
            }
            SealOutcome result = new SealOutcome { Root = directory };
            try { Paths.DeleteTree(parked); }
            catch (Exception error) { result.Warning = "已加密，但暂存的原文件夹未能完全删除，请手动删除：" + parked + "\r\n" + error.Message; }
            return result;
        }
        private static string UniqueRoot(string parent, string name)
        {
            string root = Path.Combine(parent, name);
            for (int index = 2; Directory.Exists(root) || File.Exists(root); index++)
                root = Path.Combine(parent, name + " (" + index + ")");
            return root;
        }
        internal static string VaultAncestor(string path)
        {
            string current = Path.GetDirectoryName(Paths.Full(path));
            while (!String.IsNullOrEmpty(current))
            {
                if (ExplorerMenu.IsVault(current)) return current;
                DirectoryInfo parent = Directory.GetParent(current);
                if (parent == null) break;
                current = parent.FullName;
            }
            return null;
        }
        private static bool HasDirectVaultChild(string directory)
        {
            try
            {
                foreach (string child in Directory.GetDirectories(directory))
                    if (ExplorerMenu.IsVault(child)) return true;
            }
            catch (Exception) { }
            return false;
        }
        private async void ChooseVault(object sender, EventArgs e)
        {
            using (FolderBrowserDialog dialog = new FolderBrowserDialog { Description = "选择包含 内容.egvault 的加密文件夹" })
            {
                if (dialog.ShowDialog(this) != DialogResult.OK) return;
                await OpenFromEntry(dialog.SelectedPath);
            }
        }
        private async void UnlockVault(object sender, EventArgs e)
        {
            try
            {
                if (!await EnsureMaster(true) || !await PrepareManaged()) return;
                await Run(delegate { session.Unlock(masterPassword); return "已解锁 · 修改后请保存并锁定"; });
            }
            finally { ReleaseAuthorization(); }
        }
        private async void LockVault(object sender, EventArgs e)
        {
            if (busy || session == null || !session.Open) return;
            if (!session.CleanupPending && MessageBox.Show(this, "请先在编辑器中保存修改，并关闭正在编辑的文件。\r\n接下来将生成新密文、核验并清理编辑区。继续吗？", "保存并锁定", MessageBoxButtons.OKCancel, MessageBoxIcon.Information, MessageBoxDefaultButton.Button2) != DialogResult.OK) return;
            await Run(delegate { session.Lock(); return "已锁定 · 已验证加密内容，明文工作区已清理"; });
        }
        internal string SelectedFileToOpen()
        {
            if (busy || session == null || !session.Open || session.CleanupPending || files.SelectedItems.Count != 1) return null;
            string path = Paths.Target(session.Work, files.SelectedItems[0].Text);
            Paths.NoLinks(path);
            if (!File.Exists(path)) throw new IOException("文件已移动或删除，请重新打开编辑区查看。");
            Native.RejectHardLink(path);
            return path;
        }
        private void OpenSelectedFile(object sender, EventArgs e)
        {
            try
            {
                string path = SelectedFileToOpen(); if (path == null) return;
                Process.Start(new ProcessStartInfo(path) { UseShellExecute = true, WorkingDirectory = Path.GetDirectoryName(path) });
                status.Text = "已打开：" + Path.GetFileName(path);
            }
            catch (Exception error) { MessageBox.Show(this, "无法打开文件，请检查文件是否存在或已安装对应程序。\r\n" + error.Message, "无法打开文件", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
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
            string root = session.Root;
            if (MessageBox.Show(this, "将永久删除以下加密文件夹及其中所有文件：\r\n\r\n" + root + "\r\n\r\n此操作不进入回收站。是否继续验证密码？", "删除加密文件夹", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            string password = AskPassword(false, "删除前再次验证密码", root); if (password == null) return;
            await Run(delegate
            {
                session.Delete(password); session.Dispose(); session = null;
                try
                {
                    if (File.Exists(catalog.FilePath))
                    {
                        catalog.Load(password);
                        if (catalog.Locations.RemoveAll(x => String.Equals(x.Path, root, StringComparison.OrdinalIgnoreCase)) > 0)
                            catalog.Save(password);
                    }
                }
                catch (Exception) { return "加密文件夹已删除。位置记录未更新，列表可能仍显示不可用条目。"; }
                finally { password = null; ReleaseAuthorization(); }
                return "加密文件夹已删除";
            }); password = null;
        }
        private string PickWorkspace(string[] workspaces)
        {
            using (Form dialog = new Form { Text = "恢复未锁定工作区", Font = Font, ClientSize = new Size(690, 365), MinimumSize = new Size(570, 350), StartPosition = FormStartPosition.CenterParent, MinimizeBox = false })
            {
                TableLayoutPanel layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(16), RowCount = 4, ColumnCount = 1 };
                layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));
                layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
                layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
                layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
                TextBox root = new TextBox { Text = session.Root, ReadOnly = true, Dock = DockStyle.Fill, AccessibleName = "当前加密文件夹路径" };
                ListView list = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, MultiSelect = false, HideSelection = false, AccessibleName = "此加密文件夹的遗留工作区" };
                list.Columns.Add("最近修改时间", 160); list.Columns.Add("状态", 117); list.Columns.Add("工作区编号", 266);
                TextBox path = new TextBox { ReadOnly = true, Dock = DockStyle.Fill, AccessibleName = "所选工作区目录" };
                Button recoverButton = Add("验证并恢复", delegate { dialog.DialogResult = DialogResult.OK; });
                Button cancelButton = Add("取消", delegate { dialog.DialogResult = DialogResult.Cancel; });
                recoverButton.Enabled = false;
                foreach (string workspace in workspaces)
                {
                    bool cleanup = File.Exists(Path.Combine(workspace, "清理状态.txt"));
                    string work = Path.Combine(workspace, "编辑区");
                    DateTime time = Directory.GetLastWriteTime(Directory.Exists(work) ? work : workspace);
                    list.Items.Add(new ListViewItem(new[] { time.ToString("yyyy-MM-dd HH:mm"), cleanup ? "待清理" : "待恢复编辑", Path.GetFileName(workspace) }) { Tag = workspace });
                }
                list.SelectedIndexChanged += delegate
                {
                    recoverButton.Enabled = list.SelectedItems.Count == 1;
                    path.Text = recoverButton.Enabled ? (string)list.SelectedItems[0].Tag : "";
                };
                list.DoubleClick += delegate { if (recoverButton.Enabled) dialog.DialogResult = DialogResult.OK; };
                FlowLayoutPanel buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft };
                buttons.Controls.AddRange(new Control[] { recoverButton, cancelButton });
                layout.Controls.Add(root, 0, 0); layout.Controls.Add(list, 0, 1);
                layout.Controls.Add(path, 0, 2); layout.Controls.Add(buttons, 0, 3);
                dialog.Controls.Add(layout); dialog.AcceptButton = recoverButton; dialog.CancelButton = cancelButton;
                return dialog.ShowDialog(this) == DialogResult.OK && list.SelectedItems.Count == 1 ? (string)list.SelectedItems[0].Tag : null;
            }
        }
        private async void Recover(object sender, EventArgs e)
        {
            try { await RecoverCore(); }
            finally { ReleaseAuthorization(); }
        }
        private async Task RecoverCore()
        {
            string[] workspaces;
            try { workspaces = session.RecoveryWorkspaces().OrderByDescending(Directory.GetLastWriteTime).ToArray(); }
            catch (Exception error) { MessageBox.Show(this, "无法读取工作区。请保留资料，检查目录后重试。\r\n" + error.Message, "无法列出工作区"); return; }
            if (workspaces.Length == 0) { MessageBox.Show(this, "当前加密文件夹没有待恢复工作区。", "恢复未锁定工作区"); return; }
            string existing = PickWorkspace(workspaces);
            if (existing == null) return;
            if (!await EnsureMaster()) return;
            VaultLocation known = catalog.Locations.FirstOrDefault(x => String.Equals(x.Path, session.Root, StringComparison.OrdinalIgnoreCase));
            string password = known != null && known.Managed ? masterPassword : AskPassword(false, "输入原密码并恢复工作区"); if (password == null) return;
            await Run(delegate { session.Resume(existing, password); password = null; return "已恢复明文工作区 · 请检查内容后保存并锁定"; }); password = null;
        }
        private async void OnClosing(object sender, FormClosingEventArgs e)
        {
            if (closing) return;
            if (busy) { e.Cancel = true; return; }
            if (session == null || !session.Open) { if (session != null) session.Dispose(); return; }
            e.Cancel = true;
            if (MessageBox.Show(this, "退出前需要加密保存并清理明文工作区。\r\n请先关闭正在编辑的文件。现在保存并锁定吗？", "保存后退出", MessageBoxButtons.OKCancel, MessageBoxIcon.Information, MessageBoxDefaultButton.Button2) != DialogResult.OK) return;
            if (await Run(delegate { session.Lock(); return "已安全锁定"; })) { closing = true; Close(); }
        }
    }

    // Stable identity across installed and portable copies; IPC never leaves this PC.
    internal sealed class InstanceGate : IDisposable
    {
        private readonly Mutex mutex;
        private readonly string pipeName;
        private readonly CancellationTokenSource stopping = new CancellationTokenSource();
        private readonly object sync = new object();
        private NamedPipeServerStream server;
        private Task listener;
        public bool IsPrimary { get; private set; }
        [DllImport("user32.dll")] private static extern bool AllowSetForegroundWindow(int processId);
        public InstanceGate(string testIdentity)
        {
            string identity = testIdentity ?? ("EurekaGao.FolderSeal." + WindowsIdentity.GetCurrent().User.Value + "." + Process.GetCurrentProcess().SessionId);
            pipeName = identity + ".Launch";
            mutex = new Mutex(false, @"Local\" + identity);
            try { IsPrimary = mutex.WaitOne(0); }
            catch (AbandonedMutexException) { IsPrimary = true; }
        }
        public static string[] Normalize(string[] args)
        {
            if (args.Length == 0) return new string[0];
            if (args.Length != 2 || (args[0] != "--open-vault" && args[0] != "--move-source" && args[0] != "--seal") ||
                String.IsNullOrWhiteSpace(args[1]) || args[1].IndexOf('\0') >= 0)
                throw new ArgumentException("启动参数无效；只支持打开资料、选择待加密文件或从资源管理器加密。");
            string[] result = { args[0], Path.GetFullPath(args[1]) };
            if (Encoding.UTF8.GetByteCount(String.Join("\0", result)) > 32768) throw new ArgumentException("启动参数过长。");
            return result;
        }
        private NamedPipeServerStream NewServer()
        {
            PipeSecurity security = new PipeSecurity();
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User, PipeAccessRights.FullControl, AccessControlType.Allow));
            return new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096, security);
        }
        private static async Task<byte[]> ReadBlock(Stream stream, int length, CancellationToken token)
        {
            byte[] bytes = new byte[length]; int read = 0;
            while (read < length)
            {
                int count = await stream.ReadAsync(bytes, read, length - read, token).ConfigureAwait(false);
                if (count == 0) throw new EndOfStreamException();
                read += count;
            }
            return bytes;
        }
        public void Listen(Action<string[]> receive)
        {
            if (!IsPrimary || listener != null) throw new InvalidOperationException();
            server = NewServer();
            listener = Task.Run(async delegate
            {
                while (!stopping.IsCancellationRequested)
                {
                    NamedPipeServerStream current;
                    lock (sync) { if (stopping.IsCancellationRequested) return; current = server ?? (server = NewServer()); }
                    try
                    {
                        await current.WaitForConnectionAsync(stopping.Token).ConfigureAwait(false);
                        using (CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(stopping.Token))
                        using (timeout.Token.Register(delegate { current.Dispose(); }))
                        {
                            timeout.CancelAfter(5000);
                            byte[] pid = BitConverter.GetBytes(Process.GetCurrentProcess().Id);
                            await current.WriteAsync(pid, 0, pid.Length, timeout.Token).ConfigureAwait(false);
                            int length = BitConverter.ToInt32(await ReadBlock(current, 4, timeout.Token).ConfigureAwait(false), 0);
                            if (length < 0 || length > 32768) throw new IOException("Invalid launch request length.");
                            byte[] payload = await ReadBlock(current, length, timeout.Token).ConfigureAwait(false);
                            string text = new UTF8Encoding(false, true).GetString(payload);
                            string[] args = Normalize(length == 0 ? new string[0] : text.Split('\0'));
                            receive(args);
                            await current.WriteAsync(new byte[] { 1 }, 0, 1, timeout.Token).ConfigureAwait(false);
                        }
                    }
                    catch (Exception error)
                    {
                        if (!(error is IOException || error is OperationCanceledException || error is ObjectDisposedException ||
                            error is ArgumentException || error is InvalidOperationException)) throw;
                    }
                    finally { lock (sync) { current.Dispose(); if (server == current) server = null; } }
                }
            });
        }
        public void Forward(string[] args)
        {
            ForwardAsync(Normalize(args)).GetAwaiter().GetResult();
        }
        private async Task ForwardAsync(string[] args)
        {
            using (NamedPipeClientStream client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
            using (CancellationTokenSource timeout = new CancellationTokenSource(7000))
            using (timeout.Token.Register(delegate { client.Dispose(); }))
            {
                await client.ConnectAsync(5000, timeout.Token).ConfigureAwait(false);
                int pid = BitConverter.ToInt32(await ReadBlock(client, 4, timeout.Token).ConfigureAwait(false), 0);
                AllowSetForegroundWindow(pid);
                byte[] payload = Encoding.UTF8.GetBytes(String.Join("\0", args));
                byte[] length = BitConverter.GetBytes(payload.Length);
                await client.WriteAsync(length, 0, length.Length, timeout.Token).ConfigureAwait(false);
                await client.WriteAsync(payload, 0, payload.Length, timeout.Token).ConfigureAwait(false);
                if ((await ReadBlock(client, 1, timeout.Token).ConfigureAwait(false))[0] != 1) throw new IOException("Launch request was not accepted.");
            }
        }
        public void Dispose()
        {
            stopping.Cancel();
            lock (sync) { if (server != null) server.Dispose(); }
            if (listener != null) { try { listener.Wait(1000); } catch (AggregateException) { } }
            if (IsPrimary) { mutex.ReleaseMutex(); IsPrimary = false; }
            mutex.Dispose(); stopping.Dispose();
        }
    }

    internal static class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
            if (!Native.IsAdmin()) { MessageBox.Show("此程序需要管理员授权来启用和管理文件夹防删除保护。", "需要管理员权限"); return; }
            try
            {
                args = InstanceGate.Normalize(args);
                using (InstanceGate instance = new InstanceGate(null))
                {
                    if (!instance.IsPrimary) { instance.Forward(args); return; }
                    string source = args.Length == 2 && args[0] == "--move-source" ? args[1] : null;
                    string openRoot = args.Length == 2 && args[0] == "--open-vault" ? args[1] : null;
                    string sealPath = args.Length == 2 && args[0] == "--seal" ? args[1] : null;
                    using (MainForm form = new MainForm(source, openRoot, null, sealPath))
                    {
                        IntPtr handle = form.Handle;
                        instance.Listen(delegate(string[] request)
                        {
                            form.BeginInvoke((Action)(async delegate { await form.HandleLaunch(request); }));
                        });
                        Application.Run(form);
                    }
                }
            }
            catch (Exception error)
            {
                MessageBox.Show("无法启动或转交打开请求。若已有窗口正在启动、退出或等待确认，请先完成该操作后重试。\r\n未强制关闭已有窗口，也未删除锁文件。\r\n\r\n" + error.Message, "密封夹", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
    }
}
