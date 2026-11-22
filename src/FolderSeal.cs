// Copyright (c) EurekaGao. Local-only Windows folder encryption tool.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
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
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, string lParam);
        internal static void SetPlaceholder(TextBox box, string text)
        {
            EventHandler apply = delegate { if (box.IsHandleCreated) SendMessage(box.Handle, 0x1501, IntPtr.Zero, text); };
            box.HandleCreated += apply;
            apply(box, EventArgs.Empty);
        }
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
            DenyDeletion(root);
            foreach (string file in Directory.GetFiles(root)) Restrict(file);
        }
        // An explicit deny on the folder itself stops delete, rename and move even when the parent allows removal.
        private static void DenyDeletion(string path)
{
            if (!Native.IsAdmin()) throw new UnauthorizedAccessException("锁定目录的保护需要管理员权限。");
            DirectorySecurity acl = (DirectorySecurity)BuildAccessControl(true, null, true);
            acl.AddAccessRule(new FileSystemAccessRule(User, FileSystemRights.Delete, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Deny));
            Directory.SetAccessControl(path, acl);
        }
        // Called only after the password check, so removal requires the program and the password.
        public static void AllowDelete(string path)
{
            if (!Native.IsAdmin()) throw new UnauthorizedAccessException("删除受保护目录需要管理员权限。");
            Apply(path, null);
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
        public long LastOpenedUtcTicks;
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
        public void Add(string path, bool managed, long lastOpenedUtcTicks = 0)
        {
            path = Paths.Full(path);
            if (Excludes(path)) return;
            VaultLocation entry = Locations.FirstOrDefault(x => String.Equals(x.Path, path, StringComparison.OrdinalIgnoreCase));
            if (entry == null) Locations.Add(new VaultLocation { Path = path, Managed = managed, LastOpenedUtcTicks = lastOpenedUtcTicks });
            else
            {
                if (managed) entry.Managed = true;
                if (lastOpenedUtcTicks != 0) entry.LastOpenedUtcTicks = lastOpenedUtcTicks;
            }
        }
        public void Load(string password)
        {
            byte[] data = SecretRecord.Decode(FilePath, password);
            try
            {
                using (BinaryReader r = new BinaryReader(new MemoryStream(data), Encoding.UTF8))
                {
                    int version = r.ReadInt32();
                    if (version != 1 && version != 2) throw new IOException("不支持的目录表版本。");
                    bool scanned = r.ReadBoolean(), complete = r.ReadBoolean(); int skipped = r.ReadInt32(); string summary = r.ReadString();
                    int count = r.ReadInt32(); if (count < 0 || count > 100000) throw new IOException("目录表无效。");
                    List<VaultLocation> loaded = new List<VaultLocation>();
                    for (int i = 0; i < count; i++)
                    {
                        VaultLocation entry = new VaultLocation { Path = Paths.Full(r.ReadString()), Managed = r.ReadBoolean() };
                        if (version == 2) entry.LastOpenedUtcTicks = r.ReadInt64();
                        if (entry.LastOpenedUtcTicks < 0 || entry.LastOpenedUtcTicks > DateTime.MaxValue.Ticks) throw new IOException("目录表的打开时间无效。");
                        loaded.Add(entry);
                    }
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
                    bool hasHistory = Locations.Any(e => e.LastOpenedUtcTicks != 0);
                    w.Write(hasHistory ? 2 : 1); w.Write(Scanned); w.Write(Complete); w.Write(Skipped); w.Write(Summary);
                    w.Write(Locations.Count);
                    foreach (VaultLocation e in Locations)
                    {
                        w.Write(e.Path); w.Write(e.Managed);
                        if (hasHistory) w.Write(e.LastOpenedUtcTicks);
                    }
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
        private void Acquire(bool migration = false, bool protectGate = true)
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
                if (protect && protectGate) Permissions.Restrict(gatePath);
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
        public string RepairEntry(string password)
        {
            if (Open) throw new InvalidOperationException("请先保存并锁定，再修复密封夹入口。");
            Acquire(protectGate: false);
            try
            {
                AcceptsPassword(password);
                if (protect) Permissions.Seal(Root);
                return FolderEntry.Create(Root, protect);
            }
            finally { Dispose(); }
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
                if (protect) Permissions.AllowDelete(Root);
                foreach (string file in Directory.GetFiles(Root))
                    if (Path.GetFileName(file) != GateName) File.Delete(file);
                gate.Dispose(); gate = null;
                File.Delete(Path.Combine(Root, GateName));
                Directory.Delete(Root, false);
            }
            finally
            {
                if (gate != null) { gate.Dispose(); gate = null; }
                if (protect && Directory.Exists(Root)) { try { Permissions.Seal(Root); } catch (Exception) { } }
            }
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

    internal enum ButtonTone { Secondary, Primary, Tint, Danger, Ghost }

    internal static class UiTheme
    {
        internal static readonly Color Primary = Color.FromArgb(31, 94, 69);
        internal static readonly Color PrimaryHover = Color.FromArgb(23, 75, 54);
        internal static readonly Color PrimaryTint = Color.FromArgb(234, 243, 238);
        internal static readonly Color PrimaryBorder = Color.FromArgb(198, 221, 208);
        internal static readonly Color Canvas = Color.White;
        internal static readonly Color Surface = Color.FromArgb(245, 247, 244);
        internal static readonly Color Surface2 = Color.FromArgb(239, 243, 236);
        internal static readonly Color Ink = Color.FromArgb(30, 46, 38);
        internal static readonly Color Muted = Color.FromArgb(94, 113, 102);
        internal static readonly Color Muted2 = Color.FromArgb(130, 148, 137);
        internal static readonly Color Line = Color.FromArgb(221, 229, 220);
        internal static readonly Color LineSoft = Color.FromArgb(234, 239, 234);
        internal static readonly Color Amber = Color.FromArgb(138, 86, 18);
        internal static readonly Color AmberBg = Color.FromArgb(255, 246, 229);
        internal static readonly Color AmberBorder = Color.FromArgb(242, 212, 155);
        internal static readonly Color AmberBar = Color.FromArgb(200, 131, 30);
        internal static readonly Color Red = Color.FromArgb(180, 46, 39);
        internal static readonly Color RedBg = Color.FromArgb(254, 242, 242);
        internal static readonly Color RedBorder = Color.FromArgb(245, 194, 191);

        internal static Icon LoadAppIcon()
        {
            using (Stream stream = typeof(UiTheme).Assembly.GetManifestResourceStream("FolderSeal.AppIcon"))
                return stream == null ? null : new Icon(stream);
        }

        internal static Bitmap LoadLogoBitmap(int size)
        {
            using (Stream stream = typeof(UiTheme).Assembly.GetManifestResourceStream("FolderSeal.AppIcon"))
            {
                if (stream == null) return null;
                using (Icon icon = new Icon(stream, size, size))
                    return icon.ToBitmap();
            }
        }

        internal static void StyleDialog(Form form, string title)
        {
            form.Text = title;
            form.Font = new Font("Microsoft YaHei UI", 10);
            form.BackColor = Canvas;
            form.ForeColor = Ink;
            form.AutoScaleMode = AutoScaleMode.Dpi;
            form.AutoScaleDimensions = new SizeF(96, 96);
            form.StartPosition = FormStartPosition.CenterParent;
            Icon icon = LoadAppIcon();
            if (icon != null)
            {
                form.Icon = icon;
                form.FormClosed += delegate { icon.Dispose(); };
            }
        }

        internal static GraphicsPath RoundedRect(Rectangle bounds, int radius)
        {
            int d = Math.Max(2, Math.Min(radius * 2, Math.Min(bounds.Width, bounds.Height)));
            GraphicsPath path = new GraphicsPath();
            path.AddArc(bounds.Left, bounds.Top, d, d, 180, 90);
            path.AddArc(bounds.Right - d, bounds.Top, d, d, 270, 90);
            path.AddArc(bounds.Right - d, bounds.Bottom - d, d, d, 0, 90);
            path.AddArc(bounds.Left, bounds.Bottom - d, d, d, 90, 90);
            path.CloseFigure();
            return path;
        }

        internal static ActionButton CreateButton(string text, EventHandler click, ButtonTone tone = ButtonTone.Secondary, int minWidth = 86, int height = 36)
        {
            ActionButton button = new ActionButton
            {
                Text = text,
                Tone = tone,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                MinimumSize = new Size(minWidth, height),
                Padding = new Padding(12, 2, 12, 2),
                Margin = new Padding(0, 0, 8, 0),
                Cursor = Cursors.Hand,
                AccessibleName = text
            };
            if (click != null) button.Click += click;
            return button;
        }

        internal static Bitmap CreateFileTypeGlyph(string extension)
        {
            string ext = (extension ?? "").TrimStart('.').ToUpperInvariant();
            Color bg = Color.FromArgb(240, 243, 240), border = Color.FromArgb(218, 226, 220), fg = Color.FromArgb(85, 102, 91);
            string label = ext.Length == 0 ? "FILE" : (ext.Length > 4 ? ext.Substring(0, 4) : ext);
            if (ext == "DOC" || ext == "DOCX" || ext == "RTF") { bg = Color.FromArgb(235, 243, 250); border = Color.FromArgb(203, 224, 242); fg = Color.FromArgb(39, 94, 142); label = "DOC"; }
            else if (ext == "XLS" || ext == "XLSX" || ext == "CSV") { bg = Color.FromArgb(234, 245, 236); border = Color.FromArgb(196, 228, 204); fg = Color.FromArgb(37, 106, 63); label = "XLS"; }
            else if (ext == "PPT" || ext == "PPTX") { bg = Color.FromArgb(253, 240, 234); border = Color.FromArgb(245, 211, 196); fg = Color.FromArgb(174, 72, 39); label = "PPT"; }
            else if (ext == "PDF") { bg = Color.FromArgb(252, 238, 235); border = Color.FromArgb(244, 204, 196); fg = Color.FromArgb(168, 56, 43); label = "PDF"; }
            else if (ext == "MD" || ext == "TXT" || ext == "JSON" || ext == "XML") { bg = Color.FromArgb(242, 238, 249); border = Color.FromArgb(221, 210, 240); fg = Color.FromArgb(91, 65, 143); }
            else if (ext == "PNG" || ext == "JPG" || ext == "JPEG" || ext == "GIF" || ext == "BMP" || ext == "WEBP") { bg = Color.FromArgb(232, 246, 246); border = Color.FromArgb(193, 228, 230); fg = Color.FromArgb(31, 108, 112); label = "IMG"; }
            else if (ext == "ZIP" || ext == "7Z" || ext == "RAR" || ext == "GZ") { bg = Color.FromArgb(253, 244, 227); border = Color.FromArgb(240, 216, 172); fg = Color.FromArgb(141, 91, 18); label = "ZIP"; }
            Bitmap bitmap = new Bitmap(30, 28);
            using (Graphics g = Graphics.FromImage(bitmap))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                g.Clear(Color.Transparent);
                Rectangle box = new Rectangle(1, 2, 27, 23);
                using (GraphicsPath path = RoundedRect(box, 5))
                using (SolidBrush fill = new SolidBrush(bg))
                using (Pen pen = new Pen(border, 1f))
                {
                    g.FillPath(fill, path);
                    g.DrawPath(pen, path);
                }
                using (Font font = new Font("Segoe UI", label.Length >= 4 ? 6.5f : 7f, FontStyle.Bold))
                    TextRenderer.DrawText(g, label, font, new Rectangle(1, 2, 28, 24), fg, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
            }
            return bitmap;
        }
    }

    internal sealed class ActionButton : Button
    {
        private bool hovered, pressed;
        private ButtonTone tone = ButtonTone.Secondary;
        public ButtonTone Tone
        {
            get { return tone; }
            set { tone = value; ApplyTone(); Invalidate(); }
        }
        public ActionButton()
        {
            DoubleBuffered = true;
            FlatStyle = FlatStyle.Flat;
            FlatAppearance.BorderSize = 1;
            ApplyTone();
        }
        private void ApplyTone()
        {
            if (tone == ButtonTone.Primary)
            {
                BackColor = UiTheme.Primary; ForeColor = Color.White; FlatAppearance.BorderColor = UiTheme.Primary;
                Font = new Font("Microsoft YaHei UI", 10, FontStyle.Bold);
            }
            else if (tone == ButtonTone.Tint)
            {
                BackColor = UiTheme.PrimaryTint; ForeColor = UiTheme.Primary; FlatAppearance.BorderColor = UiTheme.PrimaryBorder;
                Font = new Font("Microsoft YaHei UI", 9.5f, FontStyle.Bold);
            }
            else if (tone == ButtonTone.Danger)
            {
                BackColor = Color.White; ForeColor = UiTheme.Red; FlatAppearance.BorderColor = UiTheme.RedBorder;
                Font = new Font("Microsoft YaHei UI", 9.5f, FontStyle.Bold);
            }
            else if (tone == ButtonTone.Ghost)
            {
                BackColor = UiTheme.Surface; ForeColor = UiTheme.Muted; FlatAppearance.BorderColor = UiTheme.Surface;
                Font = new Font("Microsoft YaHei UI", 9.5f);
            }
            else
            {
                BackColor = Color.White; ForeColor = UiTheme.Ink; FlatAppearance.BorderColor = UiTheme.Line;
                Font = new Font("Microsoft YaHei UI", 9.5f);
            }
        }
        protected override void OnMouseEnter(EventArgs e) { hovered = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { hovered = false; pressed = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnMouseDown(MouseEventArgs e) { pressed = true; Invalidate(); base.OnMouseDown(e); }
        protected override void OnMouseUp(MouseEventArgs e) { pressed = false; Invalidate(); base.OnMouseUp(e); }
        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.Clear(Parent == null ? Color.White : Parent.BackColor);
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            Rectangle bounds = new Rectangle(1, 1, Math.Max(2, Width - 3), Math.Max(2, Height - 3));
            Color fill, border, textColor;
            if (!Enabled)
            {
                fill = tone == ButtonTone.Primary ? Color.FromArgb(145, 175, 162) : UiTheme.Surface;
                border = tone == ButtonTone.Primary ? fill : UiTheme.LineSoft;
                textColor = tone == ButtonTone.Primary ? Color.FromArgb(240, 245, 242) : UiTheme.Muted2;
            }
            else if (tone == ButtonTone.Primary)
            {
                fill = pressed ? Color.FromArgb(18, 62, 44) : hovered ? UiTheme.PrimaryHover : UiTheme.Primary;
                border = fill; textColor = Color.White;
            }
            else if (tone == ButtonTone.Tint)
            {
                fill = pressed ? Color.FromArgb(207, 228, 217) : hovered ? Color.FromArgb(220, 236, 227) : UiTheme.PrimaryTint;
                border = hovered ? Color.FromArgb(172, 203, 185) : UiTheme.PrimaryBorder;
                textColor = UiTheme.Primary;
            }
            else if (tone == ButtonTone.Danger)
            {
                fill = pressed ? Color.FromArgb(250, 226, 226) : hovered ? UiTheme.RedBg : Color.White;
                border = hovered ? Color.FromArgb(229, 154, 149) : UiTheme.RedBorder;
                textColor = UiTheme.Red;
            }
            else if (tone == ButtonTone.Ghost)
            {
                fill = pressed ? UiTheme.Surface2 : hovered ? UiTheme.Surface : (Parent == null ? Color.White : Parent.BackColor);
                border = fill; textColor = hovered ? UiTheme.Ink : UiTheme.Muted;
            }
            else
            {
                fill = pressed ? UiTheme.Surface2 : hovered ? UiTheme.Surface : BackColor;
                border = hovered ? Color.FromArgb(199, 213, 200) : FlatAppearance.BorderColor;
                textColor = ForeColor;
            }
            using (GraphicsPath shape = UiTheme.RoundedRect(bounds, 6))
            using (SolidBrush brush = new SolidBrush(fill))
            using (Pen pen = new Pen(border, 1f))
            {
                e.Graphics.FillPath(brush, shape);
                if (tone != ButtonTone.Ghost || hovered) e.Graphics.DrawPath(pen, shape);
            }
            Rectangle textRect = Rectangle.Inflate(ClientRectangle, -8, -3);
            TextFormatFlags flags = TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis;
            flags |= TextAlign == ContentAlignment.MiddleLeft ? TextFormatFlags.Left : TextFormatFlags.HorizontalCenter;
            TextRenderer.DrawText(e.Graphics, Text, Font, textRect, textColor, flags);
            if (Focused && ShowFocusCues) ControlPaint.DrawFocusRectangle(e.Graphics, Rectangle.Inflate(ClientRectangle, -4, -4));
        }
    }

    internal sealed class StatusPill : Label
    {
        public Color PillBorder { get; set; }
        public StatusPill()
        {
            AutoSize = false;
            DoubleBuffered = true;
            Height = 26;
            Font = new Font("Microsoft YaHei UI", 9, FontStyle.Bold);
            PillBorder = UiTheme.PrimaryBorder;
        }
        public void FitWidth()
        {
            Size measured = TextRenderer.MeasureText(Text ?? "", Font);
            Width = Math.Max(68, measured.Width + 28);
            Invalidate();
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.Clear(Parent == null ? Color.White : Parent.BackColor);
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            Rectangle rect = new Rectangle(1, 1, Math.Max(2, Width - 3), Math.Max(2, Height - 3));
            using (GraphicsPath path = UiTheme.RoundedRect(rect, Height / 2))
            using (SolidBrush fill = new SolidBrush(BackColor))
            using (Pen pen = new Pen(PillBorder, 1f))
            {
                e.Graphics.FillPath(fill, path);
                e.Graphics.DrawPath(pen, path);
            }
            using (SolidBrush dot = new SolidBrush(ForeColor))
                e.Graphics.FillEllipse(dot, 10, (Height - 6) / 2, 6, 6);
            Rectangle textRect = new Rectangle(20, 0, Math.Max(10, Width - 26), Height);
            TextRenderer.DrawText(e.Graphics, Text, Font, textRect, ForeColor, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
        }
    }

    internal sealed class NoticeCard : Panel
    {
        public Color CardBorder { get; set; }
        public Color AccentBar { get; set; }
        public NoticeCard()
        {
            DoubleBuffered = true;
            CardBorder = UiTheme.Line;
            AccentBar = UiTheme.Primary;
            Resize += delegate { Invalidate(); };
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.Clear(Parent == null ? Color.White : Parent.BackColor);
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            Rectangle rect = new Rectangle(0, 0, Math.Max(2, Width - 1), Math.Max(2, Height - 1));
            using (GraphicsPath path = UiTheme.RoundedRect(rect, 7))
            using (SolidBrush fill = new SolidBrush(BackColor))
            using (Pen pen = new Pen(CardBorder, 1f))
            {
                e.Graphics.FillPath(fill, path);
                e.Graphics.SetClip(path);
                using (SolidBrush accent = new SolidBrush(AccentBar))
                    e.Graphics.FillRectangle(accent, 0, 0, 4, Height);
                e.Graphics.ResetClip();
                e.Graphics.DrawPath(pen, path);
            }
        }
    }

    internal sealed class HomeActionCard : Panel
    {
        private bool hovered;
        private readonly string titleText, descText, ctaText;
        private readonly bool dashed;
        public event EventHandler Activated;
        public HomeActionCard(string title, string desc, string cta, bool dashed = false)
        {
            titleText = title; descText = desc; ctaText = cta; this.dashed = dashed;
            DoubleBuffered = true; Cursor = Cursors.Hand; BackColor = dashed ? UiTheme.Surface : Color.White;
            MouseEnter += delegate { hovered = true; Invalidate(); };
            MouseLeave += delegate { hovered = false; Invalidate(); };
            Click += delegate { if (Activated != null) Activated(this, EventArgs.Empty); };
            Resize += delegate { Invalidate(); };
        }
        public void SetDragHighlight(bool active)
        {
            hovered = active;
            Invalidate();
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.Clear(Parent == null ? Color.White : Parent.BackColor);
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            Rectangle rect = new Rectangle(1, 1, Math.Max(2, Width - 3), Math.Max(2, Height - 3));
            Color fill = hovered ? (dashed ? UiTheme.PrimaryTint : Color.FromArgb(250, 252, 250)) : (dashed ? UiTheme.Surface : Color.White);
            Color border = hovered ? UiTheme.Primary : (dashed ? Color.FromArgb(189, 208, 195) : UiTheme.Line);
            using (GraphicsPath path = UiTheme.RoundedRect(rect, 9))
            using (SolidBrush brush = new SolidBrush(fill))
            using (Pen pen = new Pen(border, dashed ? 1.5f : 1f))
            {
                if (dashed) pen.DashStyle = DashStyle.Dash;
                e.Graphics.FillPath(brush, path);
                e.Graphics.DrawPath(pen, path);
            }
            if (dashed)
            {
                using (Font tf = new Font("Microsoft YaHei UI", 10.5f, FontStyle.Bold))
                using (Font df = new Font("Microsoft YaHei UI", 9f))
                {
                    TextRenderer.DrawText(e.Graphics, titleText, tf, new Rectangle(18, 18, Width - 36, 28), UiTheme.Ink, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
                    TextRenderer.DrawText(e.Graphics, descText, df, new Rectangle(18, 48, Width - 36, Math.Max(24, Height - 60)), UiTheme.Muted, TextFormatFlags.HorizontalCenter | TextFormatFlags.Top | TextFormatFlags.WordBreak);
                }
            }
            else
            {
                Rectangle iconBox = new Rectangle(18, 16, 32, 32);
                using (GraphicsPath ip = UiTheme.RoundedRect(iconBox, 8))
                using (SolidBrush ib = new SolidBrush(UiTheme.PrimaryTint))
                    e.Graphics.FillPath(ib, ip);
                using (Font icf = new Font("Microsoft YaHei UI", 12f, FontStyle.Bold))
                    TextRenderer.DrawText(e.Graphics, ctaText.StartsWith("创建") ? "＋" : "≡", icf, iconBox, UiTheme.Primary, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
                using (Font tf = new Font("Microsoft YaHei UI", 11f, FontStyle.Bold))
                using (Font df = new Font("Microsoft YaHei UI", 9f))
                using (Font cf = new Font("Microsoft YaHei UI", 9f, FontStyle.Bold))
                {
                    TextRenderer.DrawText(e.Graphics, titleText, tf, new Rectangle(18, 56, Width - 36, 26), UiTheme.Ink, TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
                    TextRenderer.DrawText(e.Graphics, descText, df, new Rectangle(18, 86, Width - 36, 46), UiTheme.Muted, TextFormatFlags.Left | TextFormatFlags.Top | TextFormatFlags.WordBreak);
                    TextRenderer.DrawText(e.Graphics, ctaText + " →", cf, new Rectangle(18, Height - 32, Width - 36, 22), UiTheme.Primary, TextFormatFlags.Left | TextFormatFlags.VerticalCenter);
                }
            }
        }
    }

    internal sealed class PasswordDialog : Form
    {
        internal const int NewPasswordMinimum = 15;
        internal static int CharacterCount(string password)
        {
            if (String.IsNullOrEmpty(password)) return 0;
            int length = 0;
            for (int i = 0; i < password.Length; i++)
            {
                if (Char.IsHighSurrogate(password[i]) && i + 1 < password.Length && Char.IsLowSurrogate(password[i + 1])) i++;
                length++;
            }
            return length;
        }
        internal static bool HasMinimumLength(string password)
        {
            return CharacterCount(password) >= NewPasswordMinimum;
        }
        private readonly TextBox first = new TextBox(), second = new TextBox();
        private readonly Label lengthHint = new Label { AutoSize = true, ForeColor = UiTheme.Muted, Font = new Font("Microsoft YaHei UI", 8.5f) };
        private readonly Panel meterBack = new Panel { Dock = DockStyle.Top, Height = 5, BackColor = UiTheme.Surface2, Margin = new Padding(0, 6, 0, 4) };
        private readonly Panel meterFill = new Panel { Dock = DockStyle.Left, Width = 0, BackColor = UiTheme.AmberBar };
        private readonly Label capsHint = new Label { Text = "提示：大写锁定（Caps Lock）已开启", AutoSize = true, ForeColor = UiTheme.Amber, Visible = false, Font = new Font("Microsoft YaHei UI", 8.5f), Margin = new Padding(0, 4, 0, 0) };
        private readonly Label errorHint = new Label { AutoSize = false, Height = 36, Dock = DockStyle.Top, ForeColor = UiTheme.Red, Visible = false, Font = new Font("Microsoft YaHei UI", 9f), Margin = new Padding(0, 6, 0, 0) };
        private readonly bool creating;
        private readonly Func<string, string> validator;
        private bool validating;
        public string Value { get; private set; }
        public PasswordDialog(bool creating, string title, string targetPath = null, Func<string, string> validator = null)
        {
            this.creating = creating; this.validator = validator;
            UiTheme.StyleDialog(this, title);
            FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false;
            bool danger = title != null && title.Contains("删除");
            ClientSize = new Size(490, creating ? 378 : (targetPath != null ? 296 : 242));

            TableLayoutPanel root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = Padding.Empty };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 62));

            TableLayoutPanel body = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(22, 18, 22, 10), ColumnCount = 1, AutoSize = false };
            body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

            if (targetPath != null)
            {
                body.Controls.Add(new Label { Text = danger ? "将永久删除的目标加密文件夹（不进入回收站）" : "目标加密文件夹", AutoSize = true, ForeColor = danger ? UiTheme.Red : UiTheme.Muted, Font = new Font("Microsoft YaHei UI", 9f, FontStyle.Bold), Margin = new Padding(0, 0, 0, 4) });
                body.Controls.Add(new TextBox { Text = targetPath, ReadOnly = true, Dock = DockStyle.Top, BackColor = UiTheme.Surface, ForeColor = UiTheme.Ink, AccessibleName = "将永久删除的加密文件夹路径", Margin = new Padding(0, 0, 0, 10) });
            }

            body.Controls.Add(new Label { Text = creating ? "设置密码（至少 " + NewPasswordMinimum + " 个字符）" : title.Contains("原密码") ? "输入此文件夹的原密码" : "输入密码", AutoSize = true, Font = new Font("Microsoft YaHei UI", 9.5f, FontStyle.Bold), Margin = new Padding(0, 0, 0, 5) });
            first.AccessibleName = "密码"; first.UseSystemPasswordChar = true; first.Dock = DockStyle.Fill;
            body.Controls.Add(WrapPasswordBox(first, "显示密码"));

            if (creating)
            {
                meterBack.Controls.Add(meterFill);
                body.Controls.Add(meterBack);
                lengthHint.Text = "已输入 0 / " + NewPasswordMinimum + " 个字符（建议使用密码管理器生成独立长密码）";
                lengthHint.Margin = new Padding(0, 0, 0, 8);
                body.Controls.Add(lengthHint);
                body.Controls.Add(new Label { Text = "再次输入密码", AutoSize = true, Font = new Font("Microsoft YaHei UI", 9.5f, FontStyle.Bold), Margin = new Padding(0, 2, 0, 5) });
                second.AccessibleName = "再次输入密码"; second.UseSystemPasswordChar = true; second.Dock = DockStyle.Fill;
                body.Controls.Add(WrapPasswordBox(second, "显示确认密码"));
            }

            body.Controls.Add(capsHint);
            body.Controls.Add(errorHint);
            body.Controls.Add(new Label { Text = "密码只在本机处理，操作结束后释放；忘记密码无法恢复。", AutoSize = true, ForeColor = UiTheme.Muted, Font = new Font("Microsoft YaHei UI", 8.5f), Margin = new Padding(0, 8, 0, 0) });

            Panel footer = new Panel { Dock = DockStyle.Fill, BackColor = UiTheme.Surface, Padding = new Padding(22, 8, 22, 12) };
            footer.Paint += delegate(object s, PaintEventArgs e) { using (Pen pen = new Pen(UiTheme.LineSoft)) e.Graphics.DrawLine(pen, 0, 0, footer.Width, 0); };
            FlowLayoutPanel buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, WrapContents = false, Margin = Padding.Empty };
            ActionButton ok = UiTheme.CreateButton(danger ? "确认永久删除" : "确认", null, danger ? ButtonTone.Danger : ButtonTone.Primary, danger ? 120 : 94, 34);
            ActionButton cancel = UiTheme.CreateButton("取消", null, ButtonTone.Secondary, 84, 34);
            cancel.DialogResult = DialogResult.Cancel;
            buttons.Controls.Add(ok); buttons.Controls.Add(cancel); footer.Controls.Add(buttons);

            first.TextChanged += delegate { errorHint.Visible = false; UpdateMeter(); };
            second.TextChanged += delegate { errorHint.Visible = false; };
            KeyEventHandler capsCheck = delegate { capsHint.Visible = Control.IsKeyLocked(Keys.CapsLock); };
            first.KeyUp += capsCheck; second.KeyUp += capsCheck;

            ok.Click += async delegate
            {
                if (validating) return;
                if (creating && !HasMinimumLength(first.Text)) { ShowInlineError("新密码至少需要 " + NewPasswordMinimum + " 个字符。建议使用密码管理器生成长密码。"); first.Focus(); return; }
                if (creating && first.Text != second.Text) { ShowInlineError("两次输入的密码不一致，请核对。"); second.Focus(); second.SelectAll(); return; }
                if (first.Text.Length == 0) { ShowInlineError("请输入密码。"); first.Focus(); return; }
                string candidate = first.Text;
                if (this.validator != null)
                {
                    validating = true; ok.Enabled = cancel.Enabled = first.Enabled = second.Enabled = false;
                    string originalText = ok.Text; ok.Text = "验证中…";
                    string err = null;
                    try { err = await Task.Run(delegate { return this.validator(candidate); }); }
                    catch (Exception ex) { err = ex.Message; }
                    finally
                    {
                        validating = false;
                        if (!IsDisposed) { ok.Text = originalText; ok.Enabled = cancel.Enabled = first.Enabled = second.Enabled = true; }
                    }
                    if (IsDisposed) return;
                    if (!String.IsNullOrEmpty(err))
                    {
                        ShowInlineError(err);
                        first.SelectAll(); first.Focus();
                        return;
                    }
                }
                Value = candidate; first.Clear(); second.Clear(); DialogResult = DialogResult.OK;
            };

            root.Controls.Add(body, 0, 0); root.Controls.Add(footer, 0, 1); Controls.Add(root);
            AcceptButton = ok; CancelButton = cancel;
            Shown += delegate { capsHint.Visible = Control.IsKeyLocked(Keys.CapsLock); UpdateMeter(); first.Focus(); };
        }
        private Control WrapPasswordBox(TextBox box, string toggleName)
        {
            TableLayoutPanel row = new TableLayoutPanel { Dock = DockStyle.Top, Height = 32, ColumnCount = 2, RowCount = 1, Margin = new Padding(0, 0, 0, 2) };
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 58));
            box.Margin = new Padding(0, 2, 6, 0);
            ActionButton toggle = UiTheme.CreateButton("显示", null, ButtonTone.Secondary, 54, 28);
            toggle.Dock = DockStyle.Fill; toggle.Margin = Padding.Empty; toggle.Padding = new Padding(2);
            toggle.Font = new Font("Microsoft YaHei UI", 8.5f); toggle.AccessibleName = toggleName; toggle.TabStop = false;
            toggle.Click += delegate
            {
                box.UseSystemPasswordChar = !box.UseSystemPasswordChar;
                toggle.Text = box.UseSystemPasswordChar ? "显示" : "隐藏";
                box.Focus();
            };
            row.Controls.Add(box, 0, 0); row.Controls.Add(toggle, 1, 0);
            return row;
        }
        private void UpdateMeter()
        {
            if (!creating) return;
            int count = CharacterCount(first.Text);
            bool ok = count >= NewPasswordMinimum;
            int maxWidth = Math.Max(1, meterBack.Width);
            meterFill.Width = Math.Min(maxWidth, (int)Math.Round(maxWidth * Math.Min(1.0, count / (double)NewPasswordMinimum)));
            meterFill.BackColor = ok ? UiTheme.Primary : UiTheme.AmberBar;
            lengthHint.ForeColor = ok ? UiTheme.Primary : UiTheme.Muted;
            lengthHint.Text = ok
                ? "已输入 " + count + " 个字符 · 长度已符合安全要求"
                : "已输入 " + count + " / " + NewPasswordMinimum + " 个字符（建议使用密码管理器生成独立长密码）";
        }
        private void ShowInlineError(string message)
        {
            errorHint.Text = message;
            errorHint.Visible = true;
        }
        protected override void Dispose(bool disposing) { Value = null; if (disposing) { first.Clear(); second.Clear(); } base.Dispose(disposing); }
    }

    internal sealed class NameDialog : Form
    {
        private readonly TextBox input = new TextBox();
        public string FolderName { get { return input.Text.Trim(); } }
        public NameDialog()
        {
            UiTheme.StyleDialog(this, "加密文件夹名称");
            ClientSize = new Size(480, 172); FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false;
            TableLayoutPanel root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = Padding.Empty };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 56));
            TableLayoutPanel body = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(22, 18, 22, 10), ColumnCount = 1, RowCount = 2 };
            body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            body.Controls.Add(new Label { Text = "请输入新的加密文件夹名称", AutoSize = true, Font = new Font("Microsoft YaHei UI", 9.5f, FontStyle.Bold), Margin = new Padding(0, 0, 0, 8) }, 0, 0);
            input.Text = "新建加密文件夹"; input.Dock = DockStyle.Top; input.AccessibleName = "加密文件夹名称";
            body.Controls.Add(input, 0, 1);
            Panel footer = new Panel { Dock = DockStyle.Fill, BackColor = UiTheme.Surface, Padding = new Padding(22, 10, 22, 10) };
            FlowLayoutPanel buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, WrapContents = false };
            ActionButton ok = UiTheme.CreateButton("创建", null, ButtonTone.Primary, 92, 34);
            ActionButton cancel = UiTheme.CreateButton("取消", null, ButtonTone.Secondary, 84, 34); cancel.DialogResult = DialogResult.Cancel;
            ok.Click += delegate
            {
                try { if (Paths.Relative(FolderName).IndexOf('/') >= 0) throw new IOException(); DialogResult = DialogResult.OK; }
                catch { MessageBox.Show(this, "请输入有效的单个文件夹名称。", "名称无效"); }
            };
            buttons.Controls.Add(ok); buttons.Controls.Add(cancel); footer.Controls.Add(buttons);
            root.Controls.Add(body, 0, 0); root.Controls.Add(footer, 0, 1); Controls.Add(root);
            AcceptButton = ok; CancelButton = cancel;
            Shown += delegate { input.Focus(); input.SelectAll(); };
        }
    }

    internal sealed class CreateVaultDialog : Form
    {
        private readonly TextBox nameInput = new TextBox { AccessibleName = "加密文件夹名称" };
        private readonly TextBox parentInput = new TextBox { AccessibleName = "存放位置" };
        private readonly Label previewLabel = new Label { AutoSize = false, Dock = DockStyle.Fill, ForeColor = UiTheme.Ink, AutoEllipsis = true, TextAlign = ContentAlignment.MiddleLeft, Font = new Font("Microsoft YaHei UI", 9f) };
        private readonly Label feedback = new Label { AutoSize = false, Height = 24, Dock = DockStyle.Top, ForeColor = UiTheme.Red, Font = new Font("Microsoft YaHei UI", 9f), AutoEllipsis = true };
        private readonly CheckBox keepOpenBox = new CheckBox { Text = "创建后保持解锁，立即导入文件", Checked = true, AutoSize = true, Font = new Font("Microsoft YaHei UI", 9.5f, FontStyle.Bold), ForeColor = UiTheme.Ink };
        public string SelectedRoot { get; private set; }
        public bool KeepOpen { get { return keepOpenBox.Visible && keepOpenBox.Checked; } }

        public CreateVaultDialog(string defaultParent, string pendingSourceFile = null)
        {
            UiTheme.StyleDialog(this, "创建加密文件夹");
            FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false;
            bool hasPending = !String.IsNullOrEmpty(pendingSourceFile);
            ClientSize = new Size(560, hasPending ? 330 : 376);

            TableLayoutPanel root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = Padding.Empty };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 62));

            TableLayoutPanel body = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(22, 18, 22, 8), ColumnCount = 1 };
            body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

            body.Controls.Add(new Label { Text = "文件夹名称", AutoSize = true, Font = new Font("Microsoft YaHei UI", 9.5f, FontStyle.Bold), Margin = new Padding(0, 0, 0, 5) });
            nameInput.Dock = DockStyle.Top;
            nameInput.Text = hasPending ? Path.GetFileNameWithoutExtension(pendingSourceFile) : "新建加密文件夹";
            if (String.IsNullOrWhiteSpace(nameInput.Text)) nameInput.Text = "新建加密文件夹";
            nameInput.Margin = new Padding(0, 0, 0, 12);
            body.Controls.Add(nameInput);

            body.Controls.Add(new Label { Text = "存放位置（本机 NTFS 磁盘）", AutoSize = true, Font = new Font("Microsoft YaHei UI", 9.5f, FontStyle.Bold), Margin = new Padding(0, 0, 0, 5) });
            TableLayoutPanel pathRow = new TableLayoutPanel { Dock = DockStyle.Top, Height = 38, ColumnCount = 2, RowCount = 1, Margin = new Padding(0, 0, 0, 10) };
            pathRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            pathRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
            parentInput.Dock = DockStyle.Fill; parentInput.Margin = new Padding(0, 5, 8, 0);
            parentInput.Text = String.IsNullOrEmpty(defaultParent) ? Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) : defaultParent;
            ActionButton browse = UiTheme.CreateButton("浏览…", null, ButtonTone.Secondary, 84, 34);
            browse.Dock = DockStyle.Fill; browse.Margin = new Padding(0, 1, 0, 1);
            browse.Click += delegate
            {
                try
                {
                    string picked = VaultFolderPicker.Choose(Handle, "选择加密文件夹的存放位置", "选择此位置");
                    if (!String.IsNullOrEmpty(picked)) { parentInput.Text = picked; UpdatePreview(); }
                }
                catch (COMException)
                {
                    using (FolderBrowserDialog fallback = new FolderBrowserDialog { Description = "选择加密文件夹的上级目录", SelectedPath = parentInput.Text })
                        if (fallback.ShowDialog(this) == DialogResult.OK) { parentInput.Text = fallback.SelectedPath; UpdatePreview(); }
                }
            };
            pathRow.Controls.Add(parentInput, 0, 0); pathRow.Controls.Add(browse, 1, 0);
            body.Controls.Add(pathRow);

            NoticeCard previewBox = new NoticeCard { Dock = DockStyle.Top, Height = 40, BackColor = UiTheme.Surface, CardBorder = UiTheme.LineSoft, AccentBar = UiTheme.Primary, Padding = new Padding(12, 6, 10, 6), Margin = new Padding(0, 0, 0, 10) };
            previewBox.Controls.Add(previewLabel);
            body.Controls.Add(previewBox);

            if (!hasPending)
            {
                NoticeCard optionBox = new NoticeCard { Dock = DockStyle.Top, Height = 64, BackColor = UiTheme.PrimaryTint, CardBorder = UiTheme.PrimaryBorder, AccentBar = UiTheme.Primary, Padding = new Padding(14, 9, 12, 8), Margin = new Padding(0, 0, 0, 6) };
                TableLayoutPanel optLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
                optLayout.Controls.Add(keepOpenBox, 0, 0);
                optLayout.Controls.Add(new Label { Text = "省去建完后再次输入密码解锁的步骤；导入资料完成后再保存并锁定。", AutoSize = true, ForeColor = UiTheme.Muted, Font = new Font("Microsoft YaHei UI", 8.5f), Margin = new Padding(20, 2, 0, 0) }, 0, 1);
                optionBox.Controls.Add(optLayout);
                body.Controls.Add(optionBox);
            }
            else
            {
                keepOpenBox.Visible = false; keepOpenBox.Checked = false;
                body.Controls.Add(new Label { Text = "创建后将自动移入待加密文件并安全锁定。", AutoSize = true, ForeColor = UiTheme.Muted, Font = new Font("Microsoft YaHei UI", 9f), Margin = new Padding(0, 2, 0, 4) });
            }

            body.Controls.Add(feedback);

            Panel footer = new Panel { Dock = DockStyle.Fill, BackColor = UiTheme.Surface, Padding = new Padding(22, 8, 22, 12) };
            footer.Paint += delegate(object s, PaintEventArgs e) { using (Pen pen = new Pen(UiTheme.LineSoft)) e.Graphics.DrawLine(pen, 0, 0, footer.Width, 0); };
            FlowLayoutPanel buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, WrapContents = false };
            ActionButton ok = UiTheme.CreateButton("创建加密文件夹", null, ButtonTone.Primary, 134, 34);
            ActionButton cancel = UiTheme.CreateButton("取消", null, ButtonTone.Secondary, 84, 34); cancel.DialogResult = DialogResult.Cancel;
            buttons.Controls.Add(ok); buttons.Controls.Add(cancel); footer.Controls.Add(buttons);

            nameInput.TextChanged += delegate { UpdatePreview(); };
            parentInput.TextChanged += delegate { UpdatePreview(); };
            ok.Click += delegate
            {
                string name = nameInput.Text.Trim();
                string parent = parentInput.Text.Trim().Trim('"').Replace('/', '\\');
                try
                {
                    if (Paths.Relative(name).IndexOf('/') >= 0) throw new IOException("请输入有效的单个文件夹名称。");
                    if (parent.Length < 3 || parent[1] != ':' || parent[2] != '\\') throw new IOException("请输入本机文件夹的完整存放路径。");
                    parent = Path.GetFullPath(parent);
                    if (!Directory.Exists(parent)) throw new IOException("所选存放位置不存在，请重新选择。");
                    string combined = Path.Combine(parent, name);
                    if (Directory.Exists(combined) || File.Exists(combined)) throw new IOException("该位置已存在同名项目，请更换文件夹名称。");
                    SelectedRoot = combined;
                    DialogResult = DialogResult.OK;
                }
                catch (Exception error)
                {
                    feedback.Text = error.Message;
                    nameInput.Focus();
                }
            };

            root.Controls.Add(body, 0, 0); root.Controls.Add(footer, 0, 1); Controls.Add(root);
            AcceptButton = ok; CancelButton = cancel;
            UpdatePreview();
            Shown += delegate { UpdatePreview(); nameInput.Focus(); nameInput.SelectAll(); };
        }

        private void UpdatePreview()
        {
            feedback.Text = "";
            string name = nameInput.Text.Trim();
            string parent = parentInput.Text.Trim().Trim('"').TrimEnd('\\', '/');
            previewLabel.Text = "将创建于：" + (String.IsNullOrEmpty(parent) ? "（请选择位置）" : parent + "\\" + (String.IsNullOrEmpty(name) ? "…" : name));
        }
    }

    internal sealed class VaultPathDialog : Form
    {
        private readonly TextBox input = new TextBox { AccessibleName = "加密文件夹路径" };
        private readonly Label feedback = new Label { ForeColor = UiTheme.Red, AutoEllipsis = true, Dock = DockStyle.Top, Height = 24, Font = new Font("Microsoft YaHei UI", 9f), AccessibleName = "路径验证结果" };
        public string SelectedRoot { get; private set; }

        public VaultPathDialog()
        {
            UiTheme.StyleDialog(this, "按路径打开");
            ClientSize = new Size(570, 194); FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = ShowInTaskbar = false;

            TableLayoutPanel root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = Padding.Empty };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 62));

            TableLayoutPanel body = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(22, 18, 22, 8), ColumnCount = 1, RowCount = 3 };
            body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            body.Controls.Add(new Label { Text = "输入或粘贴加密文件夹的完整路径", AutoSize = true, Font = new Font("Microsoft YaHei UI", 9.5f, FontStyle.Bold), Margin = new Padding(0, 0, 0, 8) }, 0, 0);

            TableLayoutPanel row = new TableLayoutPanel { Dock = DockStyle.Top, Height = 38, ColumnCount = 2, RowCount = 1, Margin = new Padding(0, 0, 0, 6) };
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
            input.Dock = DockStyle.Fill; input.Margin = new Padding(0, 5, 8, 0);
            ActionButton browse = UiTheme.CreateButton("浏览…", null, ButtonTone.Secondary, 84, 34);
            browse.Dock = DockStyle.Fill; browse.Margin = new Padding(0, 1, 0, 1);
            row.Controls.Add(input, 0, 0); row.Controls.Add(browse, 1, 0);
            body.Controls.Add(row, 0, 1);
            body.Controls.Add(feedback, 0, 2);

            Panel footer = new Panel { Dock = DockStyle.Fill, BackColor = UiTheme.Surface, Padding = new Padding(22, 8, 22, 12) };
            footer.Paint += delegate(object s, PaintEventArgs e) { using (Pen pen = new Pen(UiTheme.LineSoft)) e.Graphics.DrawLine(pen, 0, 0, footer.Width, 0); };
            FlowLayoutPanel buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, WrapContents = false };
            ActionButton open = UiTheme.CreateButton("打开", null, ButtonTone.Primary, 94, 34);
            ActionButton cancel = UiTheme.CreateButton("取消", null, ButtonTone.Secondary, 84, 34); cancel.DialogResult = DialogResult.Cancel;
            buttons.Controls.Add(open); buttons.Controls.Add(cancel); footer.Controls.Add(buttons);

            input.TextChanged += delegate { feedback.Text = ""; };
            browse.Click += delegate
            {
                try
                {
                    string path = VaultFolderPicker.Choose(Handle);
                    if (path != null) { input.Text = path; input.Focus(); }
                }
                catch (COMException) { feedback.Text = "无法启动浏览窗口，请粘贴文件夹路径。"; }
            };
            open.Click += delegate
            {
                string path = input.Text.Trim();
                if (path.Length >= 2 && path[0] == '"' && path[path.Length - 1] == '"') path = path.Substring(1, path.Length - 2);
                path = path.Replace('/', '\\');
                try
                {
                    if (path.Length < 3 || path[1] != ':' || path[2] != '\\') throw new ArgumentException();
                    path = Path.GetFullPath(path);
                    Paths.NoLinks(path);
                    string data = Path.Combine(path, VaultSession.DataName);
                    if (!File.Exists(data)) { ShowError("请选择包含 内容.egvault 的加密文件夹。"); return; }
                    Header.Read(data);
                    SelectedRoot = path; DialogResult = DialogResult.OK;
                }
                catch (ArgumentException) { ShowError("请输入本机文件夹的完整路径，例如 D:\\资料\\密封夹。"); }
                catch (NotSupportedException) { ShowError("请输入本机文件夹的完整路径，例如 D:\\资料\\密封夹。"); }
                catch (IOException error) { ShowError(error.Message); }
                catch (UnauthorizedAccessException) { ShowError("无法访问此文件夹，请检查权限或选择其他位置。"); }
            };

            root.Controls.Add(body, 0, 0); root.Controls.Add(footer, 0, 1); Controls.Add(root);
            AcceptButton = open; CancelButton = cancel; ActiveControl = input;
        }

        private void ShowError(string message)
        {
            feedback.Text = message;
            input.Focus();
        }
    }

    internal sealed class LockConfirmDialog : Form
    {
        public LockConfirmDialog(string title, string heading, string detail, string confirmText)
        {
            UiTheme.StyleDialog(this, title);
            FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false;
            ClientSize = new Size(490, 242);

            TableLayoutPanel root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = Padding.Empty };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 62));

            TableLayoutPanel body = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(22, 18, 22, 10), ColumnCount = 1, RowCount = 2 };
            body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            NoticeCard card = new NoticeCard { Dock = DockStyle.Top, Height = 82, BackColor = UiTheme.AmberBg, CardBorder = UiTheme.AmberBorder, AccentBar = UiTheme.AmberBar, Padding = new Padding(14, 10, 12, 10), Margin = new Padding(0, 0, 0, 12) };
            TableLayoutPanel cardText = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
            cardText.Controls.Add(new Label { Text = heading, AutoSize = true, ForeColor = UiTheme.Amber, Font = new Font("Microsoft YaHei UI", 10f, FontStyle.Bold) }, 0, 0);
            cardText.Controls.Add(new Label { Text = "如果 Word、Excel 等外部软件仍占用编辑区内的文件，保存或清理将会受阻。", Dock = DockStyle.Fill, ForeColor = UiTheme.Amber, Font = new Font("Microsoft YaHei UI", 9f), Margin = new Padding(0, 4, 0, 0) }, 0, 1);
            card.Controls.Add(cardText);
            body.Controls.Add(card, 0, 0);
            body.Controls.Add(new Label { Text = detail, Dock = DockStyle.Fill, ForeColor = UiTheme.Muted, Font = new Font("Microsoft YaHei UI", 9f) }, 0, 1);

            Panel footer = new Panel { Dock = DockStyle.Fill, BackColor = UiTheme.Surface, Padding = new Padding(22, 8, 22, 12) };
            footer.Paint += delegate(object s, PaintEventArgs e) { using (Pen pen = new Pen(UiTheme.LineSoft)) e.Graphics.DrawLine(pen, 0, 0, footer.Width, 0); };
            FlowLayoutPanel buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, WrapContents = false };
            ActionButton ok = UiTheme.CreateButton(confirmText, delegate { DialogResult = DialogResult.OK; }, ButtonTone.Primary, 132, 34);
            ActionButton cancel = UiTheme.CreateButton("先去检查", null, ButtonTone.Secondary, 92, 34); cancel.DialogResult = DialogResult.Cancel;
            buttons.Controls.Add(ok); buttons.Controls.Add(cancel); footer.Controls.Add(buttons);

            root.Controls.Add(body, 0, 0); root.Controls.Add(footer, 0, 1); Controls.Add(root);
            AcceptButton = ok; CancelButton = cancel;
            Shown += delegate { cancel.Focus(); };
        }
    }

    internal sealed class SettingsDialog : Form
    {
        private readonly Label stateLabel = new Label { AutoSize = true, Font = new Font("Microsoft YaHei UI", 9.5f, FontStyle.Bold) };
        private readonly ActionButton toggleBtn;
        private readonly Action onToggle;
        private readonly Func<bool> checkInstalled;

        public SettingsDialog(Func<bool> checkInstalled, Action onToggle)
        {
            this.checkInstalled = checkInstalled; this.onToggle = onToggle;
            UiTheme.StyleDialog(this, "右键菜单与设置 · 密封夹");
            FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false;
            ClientSize = new Size(560, 290);

            TableLayoutPanel root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = Padding.Empty };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 62));

            TableLayoutPanel body = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(22, 18, 22, 10), ColumnCount = 1, RowCount = 2 };
            body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

            NoticeCard menuCard = new NoticeCard { Dock = DockStyle.Top, Height = 104, BackColor = Color.White, CardBorder = UiTheme.Line, AccentBar = UiTheme.Primary, Padding = new Padding(14, 12, 14, 10), Margin = new Padding(0, 0, 0, 12) };
            TableLayoutPanel cardLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 2 };
            cardLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            cardLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 134));
            cardLayout.Controls.Add(new Label { Text = "资源管理器右键快捷加密与打开", AutoSize = true, Font = new Font("Microsoft YaHei UI", 10f, FontStyle.Bold), ForeColor = UiTheme.Ink }, 0, 0);
            cardLayout.Controls.Add(new Label { Text = "右键任意文件或文件夹可直接原地加密或用密封夹打开。写入当前用户注册表，移动程序后需重新开启。", Dock = DockStyle.Fill, ForeColor = UiTheme.Muted, Font = new Font("Microsoft YaHei UI", 8.5f), Margin = new Padding(0, 4, 8, 0) }, 0, 1);
            toggleBtn = UiTheme.CreateButton("启用右键菜单", delegate { this.onToggle(); Sync(); }, ButtonTone.Tint, 124, 34);
            toggleBtn.Dock = DockStyle.Top; toggleBtn.Margin = new Padding(4, 2, 0, 0);
            cardLayout.Controls.Add(toggleBtn, 1, 0);
            stateLabel.Margin = new Padding(6, 8, 0, 0);
            cardLayout.Controls.Add(stateLabel, 1, 1);
            menuCard.Controls.Add(cardLayout);
            body.Controls.Add(menuCard, 0, 0);

            NoticeCard infoCard = new NoticeCard { Dock = DockStyle.Top, Height = 76, BackColor = UiTheme.Surface, CardBorder = UiTheme.LineSoft, AccentBar = UiTheme.Muted2, Padding = new Padding(14, 10, 14, 10) };
            TableLayoutPanel infoLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
            infoLayout.Controls.Add(new Label { Text = "当前程序版本与位置（v" + UpdateChecker.CurrentVersion.ToString(3) + "）", AutoSize = true, Font = new Font("Microsoft YaHei UI", 9.5f, FontStyle.Bold), ForeColor = UiTheme.Ink }, 0, 0);
            infoLayout.Controls.Add(new TextBox { Text = Application.ExecutablePath, ReadOnly = true, BorderStyle = BorderStyle.None, BackColor = UiTheme.Surface, ForeColor = UiTheme.Muted, Dock = DockStyle.Top, Font = new Font("Microsoft YaHei UI", 8.5f), Margin = new Padding(0, 4, 0, 0) }, 0, 1);
            infoCard.Controls.Add(infoLayout);
            body.Controls.Add(infoCard, 0, 1);

            Panel footer = new Panel { Dock = DockStyle.Fill, BackColor = UiTheme.Surface, Padding = new Padding(22, 8, 22, 12) };
            footer.Paint += delegate(object s, PaintEventArgs e) { using (Pen pen = new Pen(UiTheme.LineSoft)) e.Graphics.DrawLine(pen, 0, 0, footer.Width, 0); };
            FlowLayoutPanel buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, WrapContents = false };
            ActionButton close = UiTheme.CreateButton("完成", null, ButtonTone.Primary, 92, 34); close.DialogResult = DialogResult.Cancel;
            buttons.Controls.Add(close); footer.Controls.Add(buttons);

            root.Controls.Add(body, 0, 0); root.Controls.Add(footer, 0, 1); Controls.Add(root);
            CancelButton = close; AcceptButton = close;
            Sync();
        }

        private void Sync()
        {
            bool installed = checkInstalled();
            stateLabel.Text = installed ? "状态：已启用" : "状态：未启用";
            stateLabel.ForeColor = installed ? UiTheme.Primary : UiTheme.Muted;
            toggleBtn.Text = installed ? "移除右键菜单" : "添加右键菜单";
            toggleBtn.Tone = installed ? ButtonTone.Secondary : ButtonTone.Primary;
        }
    }

    internal static class VaultFolderPicker
    {
        private const uint PickFolders = 0x20, ForceFileSystem = 0x40, DontAddToRecent = 0x02000000;
        private const uint FileSystemPath = 0x80058000;
        private const int Cancelled = unchecked((int)0x800704C7);

        // COM methods are declared in their native vtable order through GetResult.
        [ComImport, Guid("42f85136-db7e-439c-85f1-e4075d135fc8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IFileDialog
        {
            [PreserveSig] int Show(IntPtr owner);
            void SetFileTypes(uint count, IntPtr specs);
            void SetFileTypeIndex(uint index);
            void GetFileTypeIndex(out uint index);
            void Advise(IntPtr events, out uint cookie);
            void Unadvise(uint cookie);
            void SetOptions(uint options);
            void GetOptions(out uint options);
            void SetDefaultFolder(IntPtr folder);
            void SetFolder(IntPtr folder);
            void GetFolder(out IntPtr folder);
            void GetCurrentSelection(out IntPtr item);
            void SetFileName([MarshalAs(UnmanagedType.LPWStr)] string value);
            void GetFileName(out IntPtr value);
            void SetTitle([MarshalAs(UnmanagedType.LPWStr)] string title);
            void SetOkButtonLabel([MarshalAs(UnmanagedType.LPWStr)] string label);
            void SetFileNameLabel([MarshalAs(UnmanagedType.LPWStr)] string label);
            void GetResult(out IShellItem item);
        }

        [ComImport, Guid("43826d1e-e718-42ee-bc55-a1e261c37bfe"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IShellItem
        {
            void BindToHandler(IntPtr context, ref Guid handler, ref Guid iid, out IntPtr result);
            void GetParent(out IShellItem parent);
            void GetDisplayName(uint kind, out IntPtr name);
        }

        public static string Choose(IntPtr owner, string title = "选择加密文件夹", string okLabel = "选择文件夹")
        {
            Type dialogType = Type.GetTypeFromCLSID(new Guid("dc1c5a9c-e88a-4dde-a5a1-60f82a20aef7"));
            IFileDialog dialog = (IFileDialog)Activator.CreateInstance(dialogType);
            IShellItem selected = null;
            IntPtr name = IntPtr.Zero;
            try
            {
                uint options;
                dialog.GetOptions(out options);
                dialog.SetOptions(options | PickFolders | ForceFileSystem | DontAddToRecent);
                dialog.SetTitle(title);
                dialog.SetOkButtonLabel(okLabel);
                int result = dialog.Show(owner);
                if (result == Cancelled) return null;
                Marshal.ThrowExceptionForHR(result);
                dialog.GetResult(out selected);
                selected.GetDisplayName(FileSystemPath, out name);
                return Marshal.PtrToStringUni(name);
            }
            finally
            {
                Marshal.FreeCoTaskMem(name);
                if (selected != null) Marshal.ReleaseComObject(selected);
                Marshal.ReleaseComObject(dialog);
            }
        }
    }

    internal static class FolderEntry
    {
        private const string Description = "输入密码打开加密文件夹；使用结束后请保存并锁定。";

        public static string Create(string root, bool protect)
        {
            root = Paths.Full(root); Paths.NoLinks(root);
            Header.Read(Path.Combine(root, VaultSession.DataName));
            string entry = root + ".lnk";
            Paths.NoLinks(entry);
            string arguments = Arguments(root);
            string stage = Path.Combine(Path.GetDirectoryName(entry), ".folderseal-" + Guid.NewGuid().ToString("N") + ".lnk");
            object shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell"));
            object link = null;
            try
            {
                bool replace = File.Exists(entry);
                if (Directory.Exists(entry) || (replace && !Matches(shell, entry, arguments)))
                    throw new IOException("存在其他同名项目，未覆盖：" + entry);
                link = ReadLink(shell, stage);
                Set(link, "TargetPath", Application.ExecutablePath);
                Set(link, "Arguments", arguments);
                Set(link, "WorkingDirectory", Path.GetDirectoryName(Application.ExecutablePath));
                Set(link, "IconLocation", Application.ExecutablePath + ",0");
                Set(link, "Description", Description);
                link.GetType().InvokeMember("Save", System.Reflection.BindingFlags.InvokeMethod, null, link, null);
                if (!Matches(shell, stage, arguments)) throw new IOException("入口创建失败。");
                Paths.NoLinks(stage);
                Native.RejectHardLink(stage);
                if (protect) Permissions.Set(stage, false);
                if (replace)
                {
                    Paths.NoLinks(entry);
                    if (!Matches(shell, entry, arguments)) throw new IOException("同名入口在创建期间发生变化，未覆盖。");
                    File.Replace(stage, entry, null, false);
                    if (protect) Permissions.Set(entry, false);
                }
                else File.Move(stage, entry);
                File.SetAttributes(root, File.GetAttributes(root) | FileAttributes.Hidden | FileAttributes.System);
                NotifyShell(0x00000800, root); // SHCNE_ATTRIBUTES
                NotifyShell(replace ? 0x00002000u : 0x00000002u, entry); // SHCNE_UPDATEITEM or SHCNE_CREATE
                return entry;
            }
            finally
            {
                if (link != null) Marshal.FinalReleaseComObject(link);
                Marshal.FinalReleaseComObject(shell);
                if (File.Exists(stage)) File.Delete(stage);
            }
        }
        public static void Remove(string root)
        {
            root = Paths.Full(root);
            string entry = root + ".lnk";
            Paths.NoLinks(entry);
            if (!File.Exists(entry)) return;
            object shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell"));
            try
            {
                if (!Matches(shell, entry, Arguments(root))) return;
                File.Delete(entry);
                NotifyShell(0x00000004, entry); // SHCNE_DELETE
            }
            finally { Marshal.FinalReleaseComObject(shell); }
        }
        private static string Arguments(string root) { return "--open-vault \"" + root + "\""; }
        private static object ReadLink(object shell, string path)
        {
            return shell.GetType().InvokeMember("CreateShortcut", System.Reflection.BindingFlags.InvokeMethod, null, shell, new object[] { path });
        }
        private static bool Matches(object shell, string path, string arguments)
        {
            if (!File.Exists(path)) return false;
            object link = ReadLink(shell, path);
            try
            {
                string target = Get(link, "TargetPath");
                return (String.Equals(target, Application.ExecutablePath, StringComparison.OrdinalIgnoreCase) ||
                    String.Equals(Path.GetFileName(target), "FolderSeal.exe", StringComparison.OrdinalIgnoreCase)) &&
                    Get(link, "Arguments") == arguments && Get(link, "Description") == Description;
            }
            finally { Marshal.FinalReleaseComObject(link); }
        }
        private static string Get(object target, string property)
        {
            return (string)target.GetType().InvokeMember(property, System.Reflection.BindingFlags.GetProperty, null, target, null);
        }
        [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern void SHChangeNotify(uint eventId, uint flags, string item1, IntPtr item2);
        private static void NotifyShell(uint eventId, string path) { SHChangeNotify(eventId, 0x0005, path, IntPtr.Zero); }
        private static void Set(object target, string property, object value)
        {
            target.GetType().InvokeMember(property, System.Reflection.BindingFlags.SetProperty, null, target, new object[] { value });
        }
    }

    internal sealed class VaultLibraryForm : Form
    {
        private readonly VaultCatalog catalog;
        private string password;
        private readonly ListView list = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, HideSelection = false, MultiSelect = false, ShowItemToolTips = true, BorderStyle = BorderStyle.None, BackColor = Color.White, OwnerDraw = true, AccessibleName = "加密文件夹列表" };
        private readonly TextBox search = new TextBox { Dock = DockStyle.Fill, AccessibleName = "搜索名称或路径" };
        private readonly ActionButton clearSearch;
        private readonly Label info = new Label { Dock = DockStyle.Fill, AutoEllipsis = true, TextAlign = ContentAlignment.MiddleLeft, ForeColor = UiTheme.Muted, Font = new Font("Microsoft YaHei UI", 9f) };
        private readonly ActionButton openByPath, scanToggle, open, path;
        private readonly ContextMenuStrip scanMenu = new ContextMenuStrip { ShowImageMargin = false };
        private readonly ProgressBar scanProgress = new ProgressBar { Dock = DockStyle.Top, Height = 3, Style = ProgressBarStyle.Marquee, MarqueeAnimationSpeed = 35, Visible = false };
        private CancellationTokenSource scanning;
        public string SelectedRoot;

        public VaultLibraryForm(VaultCatalog catalog, string password)
        {
            this.catalog = catalog; this.password = password;
            UiTheme.StyleDialog(this, "我的加密文件夹 · 密封夹");
            ClientSize = new Size(920, 560); MinimumSize = new Size(760, 440);

            TableLayoutPanel root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = Padding.Empty };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 60));

            TableLayoutPanel body = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(20, 16, 20, 12), ColumnCount = 1, RowCount = 3 };
            body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            body.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
            body.RowStyles.Add(new RowStyle(SizeType.Absolute, 46));
            body.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            body.Controls.Add(new Label { Text = "搜索名称或路径 · 最近成功解锁的排在前面", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, ForeColor = UiTheme.Muted, Font = new Font("Microsoft YaHei UI", 9f) }, 0, 0);

            TableLayoutPanel topBar = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, RowCount = 1, Padding = new Padding(0, 4, 0, 6), Margin = Padding.Empty };
            topBar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            topBar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 34));
            topBar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 118));
            topBar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 118));

            search.Margin = new Padding(0, 4, 4, 0);
            Native.SetPlaceholder(search, "搜索文件夹名称或路径…");
            clearSearch = UiTheme.CreateButton("×", delegate { search.Clear(); search.Focus(); }, ButtonTone.Ghost, 28, 30);
            clearSearch.Dock = DockStyle.Fill; clearSearch.Margin = new Padding(0, 1, 6, 1); clearSearch.Padding = Padding.Empty; clearSearch.Visible = false; clearSearch.AccessibleName = "清空搜索";
            openByPath = UiTheme.CreateButton("按路径打开", null, ButtonTone.Secondary, 108, 34);
            openByPath.Dock = DockStyle.Fill; openByPath.Margin = new Padding(0, 0, 8, 0);
            scanToggle = UiTheme.CreateButton("扫描 ▾", null, ButtonTone.Secondary, 108, 34);
            scanToggle.Dock = DockStyle.Fill; scanToggle.Margin = Padding.Empty;

            scanMenu.Font = Font;
            scanMenu.Items.Add(new ToolStripMenuItem("重新扫描全部本地磁盘", null, async delegate { await Scan(VaultDiscovery.FixedRoots(), true); }));
            scanMenu.Items.Add(new ToolStripMenuItem("选择指定目录扫描…", null, async delegate { await ScanSelectedFolder(); }));

            topBar.Controls.Add(search, 0, 0);
            topBar.Controls.Add(clearSearch, 1, 0);
            topBar.Controls.Add(openByPath, 2, 0);
            topBar.Controls.Add(scanToggle, 3, 0);
            body.Controls.Add(topBar, 0, 1);

            Panel tableFrame = new Panel { Dock = DockStyle.Fill, Padding = new Padding(1), BackColor = UiTheme.Line };
            Panel tableInner = new Panel { Dock = DockStyle.Fill, BackColor = Color.White };
            list.Columns.Add("名称", 200); list.Columns.Add("完整路径", 480); list.Columns.Add("状态", 140);
            list.Resize += delegate { FitColumns(); };
            list.DrawColumnHeader += delegate(object sender, DrawListViewColumnHeaderEventArgs e)
            {
                using (SolidBrush bg = new SolidBrush(UiTheme.Surface)) e.Graphics.FillRectangle(bg, e.Bounds);
                using (Pen line = new Pen(UiTheme.Line)) e.Graphics.DrawLine(line, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
                TextRenderer.DrawText(e.Graphics, e.Header.Text, new Font("Microsoft YaHei UI", 9f, FontStyle.Bold), Rectangle.Inflate(e.Bounds, -8, 0), UiTheme.Muted, TextFormatFlags.Left | TextFormatFlags.VerticalCenter);
            };
            list.DrawItem += delegate(object sender, DrawListViewItemEventArgs e) { e.DrawDefault = false; };
            list.DrawSubItem += delegate(object sender, DrawListViewSubItemEventArgs e)
            {
                Color bg = e.Item.Selected ? UiTheme.PrimaryTint : Color.White;
                using (SolidBrush brush = new SolidBrush(bg)) e.Graphics.FillRectangle(brush, e.Bounds);
                using (Pen sep = new Pen(UiTheme.LineSoft)) e.Graphics.DrawLine(sep, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
                Color fg = UiTheme.Ink;
                if (e.ColumnIndex == 1) fg = UiTheme.Muted;
                else if (e.ColumnIndex == 2)
                {
                    if (e.SubItem.Text == "已统一密码") fg = UiTheme.Primary;
                    else if (e.SubItem.Text == "位置不可用") fg = UiTheme.Muted2;
                    else fg = UiTheme.Amber;
                }
                TextRenderer.DrawText(e.Graphics, e.SubItem.Text, e.ColumnIndex == 0 ? new Font("Microsoft YaHei UI", 9.5f, FontStyle.Bold) : Font, Rectangle.Inflate(e.Bounds, -8, 0), fg, TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine);
            };
            tableInner.Controls.Add(list);
            tableInner.Controls.Add(scanProgress);
            tableFrame.Controls.Add(tableInner);
            body.Controls.Add(tableFrame, 0, 2);

            Panel footer = new Panel { Dock = DockStyle.Fill, BackColor = UiTheme.Surface, Padding = new Padding(20, 11, 20, 11) };
            footer.Paint += delegate(object s, PaintEventArgs e) { using (Pen pen = new Pen(UiTheme.LineSoft)) e.Graphics.DrawLine(pen, 0, 0, footer.Width, 0); };
            TableLayoutPanel footerLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
            footerLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            footerLayout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            FlowLayoutPanel actionRow = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.RightToLeft, WrapContents = false, Margin = Padding.Empty };
            open = UiTheme.CreateButton("打开所选文件夹", delegate { SelectRoot(); }, ButtonTone.Primary, 138, 36); open.Enabled = false; open.Margin = Padding.Empty;
            path = UiTheme.CreateButton("复制路径", null, ButtonTone.Secondary, 96, 36); path.Enabled = false; path.Margin = new Padding(0, 0, 8, 0);
            actionRow.Controls.Add(open); actionRow.Controls.Add(path);
            footerLayout.Controls.Add(info, 0, 0);
            footerLayout.Controls.Add(actionRow, 1, 0);
            footer.Controls.Add(footerLayout);

            root.Controls.Add(body, 0, 0); root.Controls.Add(footer, 0, 1); Controls.Add(root);
            info.Text = catalog.Summary;

            search.TextChanged += delegate { clearSearch.Visible = search.TextLength > 0; RefreshRows(); };
            scanToggle.Click += delegate
            {
                if (scanning != null) scanning.Cancel();
                else scanMenu.Show(scanToggle, new Point(0, scanToggle.Height));
            };
            list.DoubleClick += delegate { SelectRoot(); };
            openByPath.Click += delegate
            {
                using (VaultPathDialog dialog = new VaultPathDialog())
                    if (dialog.ShowDialog(this) == DialogResult.OK) ConfirmRoot(dialog.SelectedRoot);
            };
            list.SelectedIndexChanged += delegate { UpdateActions(); };
            list.KeyDown += delegate(object sender, KeyEventArgs e)
            {
                if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; SelectRoot(); }
            };
            path.Click += delegate
            {
                if (list.SelectedItems.Count == 1)
                {
                    string selectedPath = (string)list.SelectedItems[0].Tag;
                    try { Clipboard.SetText(selectedPath); info.Text = "已复制路径：" + selectedPath; }
                    catch (Exception) { MessageBox.Show(this, selectedPath, "完整路径（Ctrl+C 可复制）"); }
                }
            };
            FormClosing += delegate(object sender, FormClosingEventArgs e)
            {
                if (scanning != null) { scanning.Cancel(); e.Cancel = true; info.Text = "正在停止扫描并保存已发现的位置，请稍候…"; }
            };
            FormClosed += delegate { scanMenu.Dispose(); };
            Shown += async delegate { RefreshRows(); if (!catalog.Scanned) await Scan(VaultDiscovery.FixedRoots(), true); };
        }

        private async Task ScanSelectedFolder()
        {
            string picked = null;
            try { picked = VaultFolderPicker.Choose(Handle, "选择本机 NTFS 磁盘或目录", "扫描此位置"); }
            catch (COMException)
            {
                using (FolderBrowserDialog d = new FolderBrowserDialog { Description = "选择本机 NTFS 磁盘或目录" })
                    if (d.ShowDialog(this) == DialogResult.OK) picked = d.SelectedPath;
            }
            if (String.IsNullOrEmpty(picked)) return;
            try
            {
                Paths.NoLinks(picked); DriveInfo drive = new DriveInfo(Path.GetPathRoot(picked));
                if (!drive.IsReady || drive.DriveFormat != "NTFS" || drive.DriveType == DriveType.Network) throw new IOException("仅支持已就绪的本机 NTFS 磁盘。");
                await Scan(new[] { picked }, false);
            }
            catch (Exception error) { MessageBox.Show(this, error.Message, "无法扫描"); }
        }

        private void FitColumns()
        {
            int width = list.ClientSize.Width - SystemInformation.VerticalScrollBarWidth - 4;
            if (width < 300) return;
            list.Columns[0].Width = width / 4;
            list.Columns[2].Width = Math.Max(110, width / 6);
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
            ConfirmRoot((string)list.SelectedItems[0].Tag);
        }
        private void ConfirmRoot(string root)
        {
            SelectedRoot = root; DialogResult = DialogResult.OK; Close();
        }
        internal void RefreshRows()
        {
            list.BeginUpdate();
            try
            {
                list.Items.Clear();
                foreach (VaultLocation e in catalog.Locations.OrderByDescending(x => x.LastOpenedUtcTicks).ThenBy(x => x.Path, StringComparer.OrdinalIgnoreCase))
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
                    "暂无加密文件夹记录。可点击“扫描”或“按路径打开”。";
        }
        private async Task Scan(string[] roots, bool allFixed)
        {
            if (scanning != null) return;
            scanning = new CancellationTokenSource();
            open.Enabled = openByPath.Enabled = false;
            scanToggle.Text = "取消扫描"; scanToggle.Tone = ButtonTone.Danger;
            scanProgress.Visible = true;
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
                foreach (string found in result.FoundPaths) catalog.Add(found, false);
                catalog.Scanned = true; catalog.Complete = allFixed && roots.Length > 0 && !scanning.IsCancellationRequested && result.Skipped == 0;
                catalog.Skipped = result.Skipped;
                catalog.Summary = (allFixed ? "本机固定磁盘" : "指定位置") + "（" + String.Join("、", roots) + "）扫描" + (scanning.IsCancellationRequested ? "已取消，结果已保留" : catalog.Complete ? "已完成" : "未完整覆盖本机") + " · 共记录 " + catalog.Locations.Count + " 个 · 跳过 " + result.Skipped + "；下次直接显示列表";
                await Task.Run(delegate { catalog.Save(password); });
                info.Text = catalog.Summary; RefreshRows();
            }
            catch (Exception error) { MessageBox.Show(this, "扫描或保存位置失败，当前发现结果仍在本次列表中。\r\n" + error.Message, "操作未完成"); }
            finally
            {
                scanning.Dispose(); scanning = null; openByPath.Enabled = true;
                scanToggle.Text = "扫描 ▾"; scanToggle.Tone = ButtonTone.Secondary;
                scanProgress.Visible = false;
                UpdateActions();
                if (list.Items.Count == 0)
                    info.Text = search.TextLength > 0 ? "未找到匹配项。请修改或清空搜索。" : catalog.Summary;
            }
        }
    }

    internal sealed class MainForm : Form
    {
        private static readonly Color Green = UiTheme.Primary, Ink = UiTheme.Ink, Muted = UiTheme.Muted, Line = UiTheme.Line;
        private readonly Label status = new Label { Dock = DockStyle.Fill, ForeColor = Muted, TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true };
        private readonly TextBox hint = new TextBox { ReadOnly = true, Multiline = true, WordWrap = true, Dock = DockStyle.Fill, BorderStyle = BorderStyle.None, AccessibleName = "操作提示详情" };
        private readonly ListView files = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = false, BorderStyle = BorderStyle.None, HideSelection = false, BackColor = Color.White, AllowDrop = true };
        private readonly ImageList fileImages = new ImageList { ImageSize = new Size(30, 28), ColorDepth = ColorDepth.Depth32Bit };
        private readonly FlowLayoutPanel actions = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(0, 6, 0, 0) };
        private readonly Label vaultName = new Label { AutoSize = false, Dock = DockStyle.Fill, Font = new Font("Microsoft YaHei UI", 14.5f, FontStyle.Bold), ForeColor = Ink, AutoEllipsis = true, UseMnemonic = false, TextAlign = ContentAlignment.MiddleLeft };
        private readonly LinkLabel pathLink = new LinkLabel { AutoSize = false, Dock = DockStyle.Fill, AutoEllipsis = true, LinkColor = Muted, ActiveLinkColor = Green, VisitedLinkColor = Muted, LinkBehavior = LinkBehavior.HoverUnderline, TextAlign = ContentAlignment.TopLeft, Font = new Font("Microsoft YaHei UI", 8.5f), UseMnemonic = false, AccessibleName = "当前文件夹完整路径" };
        private readonly StatusPill badge = new StatusPill { Margin = new Padding(10, 8, 12, 0), ForeColor = Green, BackColor = UiTheme.PrimaryTint, PillBorder = UiTheme.PrimaryBorder };
        private readonly Label noticeTitle = new Label { Dock = DockStyle.Fill, Font = new Font("Microsoft YaHei UI", 9.5f, FontStyle.Bold), TextAlign = ContentAlignment.MiddleLeft };
        private readonly NoticeCard notice = new NoticeCard { Dock = DockStyle.Fill, Padding = new Padding(14, 8, 12, 8), Margin = new Padding(0, 0, 0, 8) };
        private readonly Panel emptyPanel = new Panel { Dock = DockStyle.Fill, BackColor = Color.White };
        private readonly Label empty = new Label { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter, ForeColor = Muted, Padding = new Padding(24), BackColor = Color.White };
        private readonly Label count = new Label { AutoSize = true, ForeColor = Muted, BackColor = UiTheme.Surface2, Padding = new Padding(7, 2, 7, 2), Margin = new Padding(8, 13, 0, 0), Font = new Font("Microsoft YaHei UI", 8.5f) };
        private readonly NoticeCard switchReasonCard = new NoticeCard { Dock = DockStyle.Fill, BackColor = UiTheme.AmberBg, CardBorder = UiTheme.AmberBorder, AccentBar = UiTheme.AmberBar, Padding = new Padding(10, 6, 8, 6), Margin = new Padding(0, 10, 0, 0), Visible = false };
        private readonly Label switchReason = new Label { Dock = DockStyle.Fill, ForeColor = UiTheme.Amber, Font = new Font("Microsoft YaHei UI", 8.5f), TextAlign = ContentAlignment.MiddleLeft };
        private readonly ProgressBar progress = new ProgressBar { Dock = DockStyle.Bottom, Height = 3, Style = ProgressBarStyle.Marquee, MarqueeAnimationSpeed = 35, Visible = false };
        private readonly ToolTip tips = new ToolTip { AutoPopDelay = 15000 };
        private readonly ContextMenuStrip moreMenu = new ContextMenuStrip { ShowImageMargin = false };
        private readonly ContextMenuStrip fileCtxMenu = new ContextMenuStrip { ShowImageMargin = false };
        private readonly TextBox fileFilter = new TextBox { Width = 156, Margin = new Padding(0, 5, 4, 0), Font = new Font("Microsoft YaHei UI", 9f), AccessibleName = "筛选编辑区文件名" };
        private readonly NoticeCard startupRecovery = new NoticeCard { Dock = DockStyle.Top, Height = 48, BackColor = UiTheme.AmberBg, CardBorder = UiTheme.AmberBorder, AccentBar = UiTheme.AmberBar, Padding = new Padding(14, 8, 12, 8), Visible = false };
        private readonly Label startupRecoveryText = new Label { Dock = DockStyle.Fill, ForeColor = UiTheme.Amber, Font = new Font("Microsoft YaHei UI", 9f, FontStyle.Bold), TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true };
        private TableLayoutPanel body, sidebar, identityBar, noticeText, toolbar;
        private Panel homePanel, fileArea, contentHost;
        private HomeActionCard homeDropZone;
        private ToolStripMenuItem delete, recover, explorerMenu, repairEntry;
        private readonly string sessionsBase = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "EurekaGao", "FolderSeal", "Sessions");
        private string pendingSource, pendingSeal;
        private VaultSession session;
        private bool busy, closing, operationFailed, handlingLaunch;
        private string lastFailure;
        private string masterPassword;
        private readonly VaultCatalog catalog = new VaultCatalog(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "EurekaGao", "FolderSeal", "catalog.egcatalog"));
        private Button library;
        private readonly LinkLabel settingsLink = new LinkLabel { Text = "右键菜单与设置", AccessibleName = "右键菜单与设置", Dock = DockStyle.Fill, Margin = new Padding(4, 0, 0, 0), TextAlign = ContentAlignment.MiddleLeft, LinkBehavior = LinkBehavior.HoverUnderline };
        private readonly LinkLabel updateLink = new LinkLabel { Text = "检测升级", AccessibleName = "检测升级", Dock = DockStyle.Fill, Margin = new Padding(4, 0, 0, 0), TextAlign = ContentAlignment.MiddleLeft, LinkBehavior = LinkBehavior.HoverUnderline };
        private bool checkingUpdate;
        private UpdateInfo availableUpdate;
        private Func<Task<UpdateInfo>> updateLookup = UpdateChecker.CheckAsync;
        private Button create, unlock, show, importFiles, importFolder, lockButton, more, refreshBtn, clearFilterBtn, emptyUnlockBtn;
        private Bitmap brandLogoBitmap;
        private FileSystemWatcher workWatcher;
        private readonly System.Windows.Forms.Timer watchDebounce = new System.Windows.Forms.Timer { Interval = 300 };
        private int sortColumn = 0;
        private bool sortAscending = true;
        private string watchedWorkDir;

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
            Icon appIcon = UiTheme.LoadAppIcon();
            if (appIcon != null) Icon = appIcon;
            brandLogoBitmap = UiTheme.LoadLogoBitmap(32);
            Font = new Font("Microsoft YaHei UI", 10); AutoScaleMode = AutoScaleMode.Dpi; AutoScaleDimensions = new SizeF(96, 96);
            ClientSize = new Size(1080, 700); MinimumSize = new Size(900, 600); StartPosition = FormStartPosition.CenterScreen;
            BackColor = UiTheme.Canvas; ForeColor = Ink; KeyPreview = true;

            TableLayoutPanel shell = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
            shell.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 224)); shell.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            shell.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            // 左侧导航栏（品牌封印图标 + 主次分明的入口 + 底部全局工具）
            sidebar = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = UiTheme.Surface, Padding = new Padding(18, 22, 18, 14), ColumnCount = 1, RowCount = 9, Margin = Padding.Empty };
            sidebar.Paint += delegate(object s, PaintEventArgs e) { using (Pen p = new Pen(UiTheme.Line)) e.Graphics.DrawLine(p, sidebar.Width - 1, 0, sidebar.Width - 1, sidebar.Height); };
            sidebar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            foreach (int h in new[] { 40, 34, 52, 52, 0 }) sidebar.RowStyles.Add(new RowStyle(SizeType.Absolute, h));
            sidebar.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            sidebar.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
            sidebar.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
            sidebar.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));

            FlowLayoutPanel brandRow = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, Margin = Padding.Empty, Padding = Padding.Empty };
            if (brandLogoBitmap != null)
                brandRow.Controls.Add(new PictureBox { Image = brandLogoBitmap, Size = new Size(30, 30), SizeMode = PictureBoxSizeMode.Zoom, Margin = new Padding(0, 3, 8, 0), BackColor = Color.Transparent });
            brandRow.Controls.Add(new Label { Text = "密封夹", AutoSize = true, Font = new Font(Font.FontFamily, 17.5f, FontStyle.Bold), ForeColor = Green, Margin = new Padding(0, 1, 0, 0) });
            sidebar.Controls.Add(brandRow, 0, 0);
            sidebar.Controls.Add(new Label { Text = "你的文件，只有你能打开。", Dock = DockStyle.Fill, ForeColor = Muted, Font = new Font(Font.FontFamily, 9f), Margin = new Padding(2, 2, 0, 0) }, 0, 1);

            create = Add("＋ 创建加密文件夹", CreateVault, ButtonTone.Primary);
            create.Dock = DockStyle.Fill; create.Margin = new Padding(0, 8, 0, 4); create.TextAlign = ContentAlignment.MiddleLeft;
            sidebar.Controls.Add(create, 0, 2);

            library = Add("我的加密文件夹", async delegate { await ShowLibrary(); }, ButtonTone.Secondary);
            library.Dock = DockStyle.Fill; library.Margin = new Padding(0, 6, 0, 4); library.TextAlign = ContentAlignment.MiddleLeft;
            sidebar.Controls.Add(library, 0, 3);

            switchReasonCard.Controls.Add(switchReason);
            sidebar.Controls.Add(switchReasonCard, 0, 4);

            Panel sideSep = new Panel { Dock = DockStyle.Bottom, Height = 1, BackColor = UiTheme.Line };
            Panel spacer = new Panel { Dock = DockStyle.Fill, BackColor = Color.Transparent, Padding = new Padding(0, 0, 0, 8) };
            spacer.Controls.Add(sideSep);
            sidebar.Controls.Add(spacer, 0, 5);

            Font sideLinkFont = new Font(Font.FontFamily, 9f);
            settingsLink.Font = sideLinkFont; settingsLink.LinkColor = settingsLink.ActiveLinkColor = settingsLink.VisitedLinkColor = Green;
            settingsLink.LinkClicked += delegate { OpenSettingsDialog(); };
            sidebar.Controls.Add(settingsLink, 0, 6);

            LinkLabel helpLink = new LinkLabel { Text = "使用帮助与异常恢复", AccessibleName = "使用帮助与异常恢复", Dock = DockStyle.Fill, Margin = new Padding(4, 0, 0, 0), LinkColor = Green, ActiveLinkColor = Green, VisitedLinkColor = Green, LinkBehavior = LinkBehavior.HoverUnderline, TextAlign = ContentAlignment.MiddleLeft, Font = sideLinkFont };
            helpLink.LinkClicked += delegate { ShowHelp(this, EventArgs.Empty); };
            sidebar.Controls.Add(helpLink, 0, 7);

            updateLink.Font = sideLinkFont; updateLink.LinkColor = updateLink.ActiveLinkColor = updateLink.VisitedLinkColor = Green;
            updateLink.LinkClicked += async delegate { if (availableUpdate != null) OfferUpdate(availableUpdate); else await CheckForUpdates(true); };
            tips.SetToolTip(updateLink, "当前版本 " + UpdateChecker.CurrentVersion.ToString(3) + "；检查公开发布的安装包。");
            sidebar.Controls.Add(updateLink, 0, 8);

            // 右侧主工作容器（顶部可按需挂载启动遗留工作区横幅，不影响 body 行索引）
            Panel rightHost = new Panel { Dock = DockStyle.Fill, BackColor = UiTheme.Canvas, Margin = Padding.Empty };
            TableLayoutPanel recLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
            recLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            recLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
            ActionButton quickRecover = UiTheme.CreateButton("查看并恢复", delegate { ShowAllPendingWorkspaces(); }, ButtonTone.Secondary, 102, 30);
            quickRecover.Dock = DockStyle.Fill; quickRecover.Margin = Padding.Empty; quickRecover.Font = new Font(Font.FontFamily, 8.5f, FontStyle.Bold);
            recLayout.Controls.Add(startupRecoveryText, 0, 0);
            recLayout.Controls.Add(quickRecover, 1, 0);
            startupRecovery.Controls.Add(recLayout);

            body = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(26, 20, 26, 10), ColumnCount = 1, RowCount = 5, Margin = Padding.Empty };
            body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            foreach (int h in new[] { 66, 0, 50 }) body.RowStyles.Add(new RowStyle(SizeType.Absolute, h));
            body.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            body.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));

            // Row 0: 头部身份卡（名称 + 胶囊状态 + 可点击复制路径 + 主按钮 + 更多）
            identityBar = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, RowCount = 1, Margin = Padding.Empty, Padding = new Padding(0, 0, 0, 8) };
            identityBar.Paint += delegate(object s, PaintEventArgs e) { using (Pen p = new Pen(UiTheme.LineSoft)) e.Graphics.DrawLine(p, 0, identityBar.Height - 1, identityBar.Width, identityBar.Height - 1); };
            identityBar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            identityBar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            identityBar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 168));
            identityBar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 84));
            identityBar.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            TableLayoutPanel titleBlock = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = Padding.Empty };
            titleBlock.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            titleBlock.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            titleBlock.Controls.Add(vaultName, 0, 0);
            pathLink.LinkClicked += delegate
            {
                if (session == null) return;
                try { Clipboard.SetText(session.Root); status.Text = "已复制路径：" + session.Root; }
                catch (Exception) { MessageBox.Show(this, session.Root, "完整路径（Ctrl+C 可复制）"); }
            };
            titleBlock.Controls.Add(pathLink, 0, 1);
            identityBar.Controls.Add(titleBlock, 0, 0);

            Panel badgeHost = new Panel { AutoSize = true, Dock = DockStyle.Fill, Padding = new Padding(6, 10, 8, 0), Margin = Padding.Empty };
            badge.Location = new Point(6, 12);
            badgeHost.Controls.Add(badge);
            identityBar.Controls.Add(badgeHost, 1, 0);

            unlock = Add("解锁文件夹", UnlockVault, ButtonTone.Primary);
            lockButton = Add("保存并锁定", LockVault, ButtonTone.Primary);
            Panel primaryArea = new Panel { Dock = DockStyle.Fill, Padding = new Padding(4, 7, 6, 9), Margin = Padding.Empty };
            unlock.Dock = lockButton.Dock = DockStyle.Fill;
            primaryArea.Controls.Add(unlock); primaryArea.Controls.Add(lockButton);
            identityBar.Controls.Add(primaryArea, 2, 0);

            more = Add("更多 ▾", delegate { moreMenu.Show(more, new Point(0, more.Height)); }, ButtonTone.Secondary);
            more.Dock = DockStyle.Fill; more.Margin = new Padding(2, 7, 0, 9);
            identityBar.Controls.Add(more, 3, 0);
            body.Controls.Add(identityBar, 0, 0);

            moreMenu.Font = Font;
            recover = new ToolStripMenuItem("恢复未锁定工作区", null, Recover);
            repairEntry = new ToolStripMenuItem("创建或修复密封夹入口…", null, RepairFolderEntry);
            explorerMenu = new ToolStripMenuItem("添加到资源管理器右键菜单", null, ToggleExplorerMenu);
            delete = new ToolStripMenuItem("删除加密文件夹…", null, DeleteVault) { ForeColor = UiTheme.Red, ToolTipText = "永久删除，不进入回收站；需再次验证密码。" };
            moreMenu.Items.AddRange(new ToolStripItem[] { recover, repairEntry, explorerMenu, new ToolStripSeparator(), delete });

            // Row 1: 语义提示横幅
            noticeText = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = Padding.Empty };
            noticeText.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
            noticeText.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            noticeText.Controls.Add(noticeTitle, 0, 0);
            hint.Font = new Font(Font.FontFamily, 9f); hint.Margin = new Padding(0, 2, 0, 0);
            noticeText.Controls.Add(hint, 0, 1);
            notice.Controls.Add(noticeText); notice.Controls.Add(progress);
            body.Controls.Add(notice, 0, 1);

            // Row 2: 文件工具栏（标题 + 数量 + 快速筛选 + 导入 + 刷新 + 在资源管理器中打开）
            toolbar = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
            toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            FlowLayoutPanel fileHeading = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = false, Margin = Padding.Empty };
            fileHeading.Controls.Add(new Label { Text = "文件内容", AutoSize = true, Font = new Font(Font.FontFamily, 10f, FontStyle.Bold), Margin = new Padding(0, 13, 0, 0) });
            fileHeading.Controls.Add(count);
            toolbar.Controls.Add(fileHeading, 0, 0);

            show = Add("在资源管理器打开", ShowWorkspace, ButtonTone.Tint);
            show.MinimumSize = new Size(122, 34); show.Padding = new Padding(8, 3, 8, 3); show.Margin = new Padding(0, 0, 0, 0);
            refreshBtn = Add("刷新", delegate { RefreshFileList(true); status.Text = "已刷新编辑区文件列表"; }, ButtonTone.Secondary);
            refreshBtn.MinimumSize = new Size(52, 34); refreshBtn.Padding = new Padding(6, 3, 6, 3); refreshBtn.Margin = new Padding(0, 0, 6, 0);
            importFolder = Add("导入文件夹", ImportFolder, ButtonTone.Secondary);
            importFolder.MinimumSize = new Size(84, 34); importFolder.Padding = new Padding(8, 3, 8, 3); importFolder.Margin = new Padding(0, 0, 6, 0);
            importFiles = Add("导入文件", ImportFiles, ButtonTone.Secondary);
            importFiles.MinimumSize = new Size(76, 34); importFiles.Padding = new Padding(8, 3, 8, 3); importFiles.Margin = new Padding(0, 0, 6, 0);
            clearFilterBtn = Add("×", delegate { fileFilter.Clear(); fileFilter.Focus(); }, ButtonTone.Ghost);
            clearFilterBtn.MinimumSize = new Size(24, 30); clearFilterBtn.Padding = Padding.Empty; clearFilterBtn.Margin = new Padding(0, 2, 4, 0); clearFilterBtn.Visible = false; clearFilterBtn.AccessibleName = "清空文件筛选";
            fileFilter.Width = 112;
            Native.SetPlaceholder(fileFilter, "筛选文件名…");
            fileFilter.TextChanged += delegate { clearFilterBtn.Visible = fileFilter.TextLength > 0; RefreshFileList(false); };
            toolbar.Resize += delegate
            {
                int targetWidth = Math.Max(80, Math.Min(156, toolbar.ClientSize.Width - 525));
                if (fileFilter.Width != targetWidth) fileFilter.Width = targetWidth;
            };
            actions.Padding = new Padding(0, 6, 0, 0);
            actions.Controls.Add(show);
            actions.Controls.Add(refreshBtn);
            actions.Controls.Add(importFolder);
            actions.Controls.Add(importFiles);
            actions.Controls.Add(clearFilterBtn);
            actions.Controls.Add(fileFilter);
            toolbar.Controls.Add(actions, 1, 0);
            body.Controls.Add(toolbar, 0, 2);

            // Row 3: 内容宿主（未选择态首页 / 已选择态文件表与空状态）
            contentHost = new Panel { Dock = DockStyle.Fill, BackColor = Color.White, Margin = Padding.Empty };
            homePanel = BuildHomePanel();

            fileArea = new Panel { Dock = DockStyle.Fill, Padding = new Padding(1), BackColor = UiTheme.Line, AllowDrop = true };
            files.Columns.Add("名称", 400); files.Columns.Add("大小", 100); files.Columns.Add("修改时间", 170);
            files.SmallImageList = fileImages; files.ShowItemToolTips = true;
            files.OwnerDraw = true;
            files.DrawColumnHeader += delegate(object sender, DrawListViewColumnHeaderEventArgs e)
            {
                using (SolidBrush bg = new SolidBrush(UiTheme.Surface)) e.Graphics.FillRectangle(bg, e.Bounds);
                using (Pen border = new Pen(UiTheme.Line)) e.Graphics.DrawLine(border, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
                string headerText = e.Header.Text + (e.ColumnIndex == sortColumn ? (sortAscending ? " ▲" : " ▼") : "");
                TextRenderer.DrawText(e.Graphics, headerText, new Font(Font.FontFamily, 9f, FontStyle.Bold), Rectangle.Inflate(e.Bounds, -8, 0), e.ColumnIndex == sortColumn ? Green : Muted, TextFormatFlags.Left | TextFormatFlags.VerticalCenter);
            };
            files.DrawItem += delegate(object sender, DrawListViewItemEventArgs e) { e.DrawDefault = true; };
            files.DrawSubItem += delegate(object sender, DrawListViewSubItemEventArgs e) { e.DrawDefault = true; };
            files.ColumnClick += delegate(object sender, ColumnClickEventArgs e)
            {
                if (sortColumn == e.Column) sortAscending = !sortAscending;
                else { sortColumn = e.Column; sortAscending = true; }
                RefreshFileList(false);
                files.Invalidate();
            };
            files.ItemActivate += OpenSelectedFile;
            files.MouseUp += OnFileListMouseUp;

            fileCtxMenu.Font = Font;
            fileCtxMenu.Items.Add(new ToolStripMenuItem("用默认程序打开", null, OpenSelectedFile));
            fileCtxMenu.Items.Add(new ToolStripMenuItem("在资源管理器中定位", null, LocateSelectedFile));
            fileCtxMenu.Items.Add(new ToolStripMenuItem("复制文件名", null, CopySelectedFileName));
            fileCtxMenu.Items.Add(new ToolStripSeparator());
            ToolStripMenuItem removeItem = new ToolStripMenuItem("从编辑区删除", null, RemoveSelectedFile) { ForeColor = UiTheme.Red };
            fileCtxMenu.Items.Add(removeItem);

            DragEventHandler onDragOver = delegate(object s, DragEventArgs e)
            {
                if (!busy && session != null && session.Open && !session.CleanupPending && e.Data.GetDataPresent(DataFormats.FileDrop))
                    e.Effect = DragDropEffects.Copy;
                else e.Effect = DragDropEffects.None;
            };
            DragEventHandler onDragDrop = async delegate(object s, DragEventArgs e)
            {
                if (busy || session == null || !session.Open || session.CleanupPending || !e.Data.GetDataPresent(DataFormats.FileDrop)) return;
                string[] dropped = e.Data.GetData(DataFormats.FileDrop) as string[];
                if (dropped != null && dropped.Length > 0) await ImportDroppedPaths(dropped);
            };
            files.DragEnter += onDragOver; files.DragOver += onDragOver; files.DragDrop += onDragDrop;
            fileArea.DragEnter += onDragOver; fileArea.DragOver += onDragOver; fileArea.DragDrop += onDragDrop;

            emptyUnlockBtn = Add("解锁文件夹", UnlockVault, ButtonTone.Primary);
            emptyUnlockBtn.MinimumSize = new Size(134, 36);
            emptyUnlockBtn.Visible = false;
            emptyPanel.Controls.Add(empty);
            emptyPanel.Controls.Add(emptyUnlockBtn);
            emptyPanel.Resize += delegate { PositionEmptyUnlock(); };
            emptyPanel.Layout += delegate { PositionEmptyUnlock(); };
            emptyUnlockBtn.BringToFront();

            fileArea.Controls.Add(files);
            fileArea.Controls.Add(emptyPanel);
            contentHost.Controls.Add(fileArea);
            contentHost.Controls.Add(homePanel);
            body.Controls.Add(contentHost, 0, 3);
            files.Resize += delegate { FitFileColumns(); };

            // Row 4: 状态栏
            TableLayoutPanel statusBar = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
            statusBar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            statusBar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            status.Font = new Font(Font.FontFamily, 8.5f); status.AccessibleName = "操作结果";
            Label shortcutHint = new Label { Text = "Alt + L 保存并锁定", AutoSize = true, ForeColor = UiTheme.Muted2, Font = new Font(Font.FontFamily, 8.5f), TextAlign = ContentAlignment.MiddleRight, Margin = new Padding(8, 6, 0, 0) };
            statusBar.Controls.Add(status, 0, 0); statusBar.Controls.Add(shortcutHint, 1, 0);
            body.Controls.Add(statusBar, 0, 4);

            watchDebounce.Tick += delegate
            {
                watchDebounce.Stop();
                if (!IsDisposed && !busy && session != null && session.Open && !session.CleanupPending)
                    RefreshFileList(false);
            };

            tips.SetToolTip(show, "在 Windows 资源管理器中打开临时编辑区。");
            tips.SetToolTip(more, "恢复工作区、修复图标入口、右键菜单与永久删除；执行前需先锁定。");
            tips.SetToolTip(lockButton, "先在编辑器中保存并关闭文件。快捷键 Alt + L。");
            tips.SetToolTip(importFiles, "复制到编辑区，保留源文件；同名文件不自动覆盖。");
            tips.SetToolTip(importFolder, "复制整个文件夹，保留原文件夹。");
            tips.SetToolTip(refreshBtn, "刷新列表（编辑区文件变动会自动同步）。");
            tips.SetToolTip(fileFilter, "按文件名快速筛选当前编辑区文件。");

            rightHost.Controls.Add(body);
            rightHost.Controls.Add(startupRecovery);
            shell.Controls.Add(sidebar, 0, 0); shell.Controls.Add(rightHost, 1, 0); Controls.Add(shell);

            FormClosed += delegate
            {
                StopWorkWatcher();
                watchDebounce.Dispose();
                fileImages.Dispose(); tips.Dispose(); moreMenu.Dispose(); fileCtxMenu.Dispose();
                if (brandLogoBitmap != null) { brandLogoBitmap.Dispose(); brandLogoBitmap = null; }
            };
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
                    UpdateStartupRecoveryBanner();
                    if (!String.IsNullOrEmpty(openRoot)) await OpenFromEntry(openRoot);
                }
                finally { handlingLaunch = false; }
            };
            UpdateExplorerMenu();
            RefreshState("尚未选择加密文件夹");
        }

        private Panel BuildHomePanel()
        {
            Panel host = new Panel { Dock = DockStyle.Fill, BackColor = Color.White, Padding = new Padding(8, 6, 8, 6) };
            TableLayoutPanel center = new TableLayoutPanel { Width = 680, Height = 356, ColumnCount = 1, RowCount = 3, BackColor = Color.White };
            center.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            center.RowStyles.Add(new RowStyle(SizeType.Absolute, 192));
            center.RowStyles.Add(new RowStyle(SizeType.Absolute, 114));
            center.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));

            TableLayoutPanel cards = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Padding = new Padding(0, 10, 0, 10) };
            cards.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            cards.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            HomeActionCard createCard = new HomeActionCard("创建加密文件夹", "命名并选址，默认创建后立即解锁，自动生成密封夹入口。", "创建新文件夹") { Dock = DockStyle.Fill, Margin = new Padding(0, 0, 8, 0) };
            createCard.Activated += CreateVault;
            HomeActionCard libraryCard = new HomeActionCard("打开我的加密文件夹", "验证密码查看全部资料，按最近打开排序并支持搜索。", "验证并查看") { Dock = DockStyle.Fill, Margin = new Padding(8, 0, 0, 0) };
            libraryCard.Activated += async delegate { await ShowLibrary(); };
            cards.Controls.Add(createCard, 0, 0); cards.Controls.Add(libraryCard, 1, 0);
            center.Controls.Add(cards, 0, 0);

            homeDropZone = new HomeActionCard("拖入文件或文件夹到这里，直接原地加密", "验证密码、加密核验并生成密封夹图标后，自动清理原位置明文（仅支持本机 NTFS）", "", true) { Dock = DockStyle.Fill, AllowDrop = true, Margin = new Padding(0, 4, 0, 6) };
            homeDropZone.DragEnter += delegate(object s, DragEventArgs e)
            {
                if (!busy && e.Data.GetDataPresent(DataFormats.FileDrop)) { e.Effect = DragDropEffects.Move; homeDropZone.SetDragHighlight(true); }
                else e.Effect = DragDropEffects.None;
            };
            homeDropZone.DragLeave += delegate { homeDropZone.SetDragHighlight(false); };
            homeDropZone.DragDrop += async delegate(object s, DragEventArgs e)
            {
                homeDropZone.SetDragHighlight(false);
                string[] items = e.Data.GetData(DataFormats.FileDrop) as string[];
                if (items == null || items.Length == 0) return;
                if (items.Length > 1) { MessageBox.Show(this, "请一次拖入单个文件或单个文件夹进行原地加密。", "单次原地加密"); return; }
                await SealFromExplorer(items[0]);
            };
            center.Controls.Add(homeDropZone, 0, 1);

            center.Controls.Add(new Label { Text = "AES-256 本地加密  ·  锁定防常规删除与访问  ·  不联网、无密码找回，请妥善保管密码", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter, Font = new Font(Font.FontFamily, 8.5f), ForeColor = UiTheme.Muted2 }, 0, 2);

            host.Controls.Add(center);
            EventHandler layoutCenter = delegate
            {
                int w = Math.Min(680, Math.Max(480, host.ClientSize.Width - 24));
                center.Size = new Size(w, 356);
                center.Location = new Point(Math.Max(8, (host.ClientSize.Width - center.Width) / 2), Math.Max(8, (host.ClientSize.Height - center.Height) / 2 - 6));
            };
            host.Resize += layoutCenter;
            layoutCenter(host, EventArgs.Empty);
            return host;
        }

        private void PositionEmptyUnlock()
        {
            if (!emptyUnlockBtn.Visible) return;
            emptyUnlockBtn.Location = new Point((emptyPanel.ClientSize.Width - emptyUnlockBtn.Width) / 2, (emptyPanel.ClientSize.Height / 2) + 46);
        }

        private void UpdateStartupRecoveryBanner()
        {
            int countDirs = 0;
            try
            {
                if (Directory.Exists(sessionsBase))
                    countDirs = Directory.GetDirectories(sessionsBase).Length;
            }
            catch (Exception) { }
            startupRecovery.Visible = countDirs > 0 && (session == null || !session.Open);
            if (startupRecovery.Visible)
                startupRecoveryText.Text = "检测到 " + countDirs + " 个上次未清理的工作区，其中可能仍有明文资料，建议及时核对并锁定。";
        }

        private void ShowAllPendingWorkspaces()
        {
            if (busy || (session != null && session.Open))
            {
                MessageBox.Show(this, "请先保存并锁定当前文件夹，再处理遗留工作区。", "请先锁定");
                return;
            }
            if (!Directory.Exists(sessionsBase)) { UpdateStartupRecoveryBanner(); return; }
            string[] dirs = Directory.GetDirectories(sessionsBase).OrderByDescending(Directory.GetLastWriteTime).ToArray();
            if (dirs.Length == 0) { UpdateStartupRecoveryBanner(); return; }
            List<string> lines = new List<string>();
            foreach (string dir in dirs)
            {
                string target = ReadWorkspaceTargetRoot(dir) ?? "（未能识别所属加密目录）";
                bool cleanup = File.Exists(Path.Combine(dir, "清理状态.txt"));
                lines.Add("• " + target + "  [" + (cleanup ? "待清理" : "待恢复编辑") + " · " + Directory.GetLastWriteTime(dir).ToString("yyyy-MM-dd HH:mm") + "]");
            }
            MessageBox.Show(this, "检测到以下遗留工作区：\r\n\r\n" + String.Join("\r\n", lines) + "\r\n\r\n请在“我的加密文件夹”中打开对应加密文件夹，然后从顶部“更多 → 恢复未锁定工作区”完成核对与锁定。", "遗留工作区清单", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private static string ReadWorkspaceTargetRoot(string workspaceDir)
        {
            foreach (string noteName in new[] { "清理状态.txt", "工作区说明.txt" })
            {
                string file = Path.Combine(workspaceDir, noteName);
                if (!File.Exists(file)) continue;
                try
                {
                    foreach (string line in File.ReadAllLines(file))
                        if (line.Length >= 3 && line[1] == ':' && line[2] == '\\') return line.Trim();
                }
                catch (Exception) { }
            }
            return null;
        }

        private void StartWorkWatcher(string directory)
        {
            if (String.Equals(watchedWorkDir, directory, StringComparison.OrdinalIgnoreCase) && workWatcher != null) return;
            StopWorkWatcher();
            if (String.IsNullOrEmpty(directory) || !Directory.Exists(directory)) return;
            try
            {
                FileSystemWatcher watcher = new FileSystemWatcher(directory)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite | NotifyFilters.Size
                };
                FileSystemEventHandler onChange = delegate { ScheduleWatchRefresh(); };
                RenamedEventHandler onRename = delegate { ScheduleWatchRefresh(); };
                watcher.Created += onChange; watcher.Deleted += onChange; watcher.Changed += onChange; watcher.Renamed += onRename;
                watcher.EnableRaisingEvents = true;
                workWatcher = watcher;
                watchedWorkDir = directory;
            }
            catch (Exception) { StopWorkWatcher(); }
        }

        private void ScheduleWatchRefresh()
        {
            if (IsDisposed || Disposing || !IsHandleCreated) return;
            try
            {
                BeginInvoke((Action)delegate
                {
                    if (IsDisposed || busy || session == null || !session.Open || session.CleanupPending) return;
                    watchDebounce.Stop();
                    watchDebounce.Start();
                });
            }
            catch (ObjectDisposedException) { }
            catch (InvalidOperationException) { }
        }

        private void StopWorkWatcher()
        {
            watchDebounce.Stop();
            watchedWorkDir = null;
            if (workWatcher != null)
            {
                try { workWatcher.EnableRaisingEvents = false; workWatcher.Dispose(); }
                catch (Exception) { }
                workWatcher = null;
            }
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
        private Task<bool> EnsureMaster(bool requirePassword = false)
        {
            if (!requirePassword && masterPassword != null) return Task.FromResult(true);
            bool creating = !File.Exists(catalog.FilePath);
            if (creating) MessageBox.Show(this, "请设置密码，用于打开所有加密文件夹。以后访问加密资料时输入。\r\n旧文件夹需先验证原密码，再统一使用此密码。\r\n忘记密码无法恢复，请单独妥善保管。", "设置密码");
            Func<string, string> validator = delegate(string supplied)
            {
                try
                {
                    if (creating) catalog.Save(supplied);
                    else { catalog.Load(supplied); if (catalog.NeedsSave) catalog.Save(supplied); }
                    return null;
                }
                catch (Exception error)
                {
                    return "密码错误，或目录表无法读取/保存（未重置目录表）：" + error.Message;
                }
            };
            using (PasswordDialog dialog = new PasswordDialog(creating, creating ? "设置密码" : "输入密码", null, validator))
            {
                if (dialog.ShowDialog(this) != DialogResult.OK) return Task.FromResult(false);
                masterPassword = dialog.Value;
                return Task.FromResult(true);
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
        private void OpenSettingsDialog()
        {
            using (SettingsDialog dialog = new SettingsDialog(
                delegate { try { return ExplorerMenu.Installed(ExplorerMenu.ClassesRoot); } catch (Exception) { return false; } },
                delegate { ToggleExplorerMenu(this, EventArgs.Empty); }))
            {
                dialog.ShowDialog(this);
            }
        }
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
            bool installed = false;
            try { installed = ExplorerMenu.Installed(ExplorerMenu.ClassesRoot); } catch (Exception) { }
            if (explorerMenu != null)
                explorerMenu.Text = installed ? "从资源管理器右键菜单移除" : "添加到资源管理器右键菜单";
            settingsLink.Text = installed ? "右键菜单与设置（已启用）" : "右键菜单与设置";
        }
        private void ShowHelp(object sender, EventArgs e)
        {
            using (Form help = CreateHelpDialog()) help.ShowDialog(this);
        }
        internal Form CreateHelpDialog()
        {
            Form help = new Form { ClientSize = new Size(740, 560), MinimumSize = new Size(570, 420), MinimizeBox = false, MaximizeBox = false };
            UiTheme.StyleDialog(help, "操作与恢复帮助 · 密封夹");

            TableLayoutPanel root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = Padding.Empty };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 62));

            TableLayoutPanel split = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
            split.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 168));
            split.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            split.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            FlowLayoutPanel nav = new FlowLayoutPanel { Dock = DockStyle.Fill, BackColor = UiTheme.Surface, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(10, 14, 10, 10), Margin = Padding.Empty };
            nav.Paint += delegate(object s, PaintEventArgs e) { using (Pen p = new Pen(UiTheme.LineSoft)) e.Graphics.DrawLine(p, nav.Width - 1, 0, nav.Width - 1, nav.Height); };

            Panel contentPad = new Panel { Dock = DockStyle.Fill, Padding = new Padding(20, 16, 16, 12), BackColor = Color.White };
            RichTextBox text = new RichTextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, WordWrap = true, DetectUrls = false, ScrollBars = RichTextBoxScrollBars.Vertical, BorderStyle = BorderStyle.None, BackColor = Color.White, ForeColor = Ink };
            contentPad.Controls.Add(text);

            Tuple<string, Tuple<string, string>[]>[] sections =
            {
                Tuple.Create("全部说明", new[] {
                    Tuple.Create("日常编辑", "输入密码解锁 → 双击文件或在资源管理器中编辑（支持拖放导入与自动同步）→ 保存并关闭文件 → 回到这里保存并锁定。仅关闭资源管理器不会锁定。解锁时，同一 Windows 账户可访问明文。"),
                    Tuple.Create("保存失败", "先关闭可能占用文件的 Word、Excel 等程序，再重试。保存失败时保留当前编辑区，不要自行删除；具体原因以错误提示为准。"),
                    Tuple.Create("密文已保存，清理未完成", "关闭占用文件的程序，点击“重试清理并锁定”。此时只继续清理，不重新生成密文；清理完成前不能继续导入或编辑。"),
                    Tuple.Create("异常退出", "重新启动时顶部会提示遗留工作区。选中对应加密文件夹，在“更多”中选择“恢复未锁定工作区”，按时间和状态核对并验证密码。来源版本不同或无法确认时，程序保留两份内容。"),
                    Tuple.Create("备份与密码", "锁定后备份整个密文目录，包括隐藏目录。密封夹快捷图标不是资料本体。普通导入保留源文件。忘记密码无法找回。"),
                    Tuple.Create("快捷操作", "Alt + L：保存或重试锁定；Enter：打开所选文件或加密文件夹；Esc：关闭弹窗。右键菜单开关位于侧栏底部“右键菜单与设置”。"),
                    Tuple.Create("保护范围", "管理员仍可强制删除。明文采用普通删除，不保证清除磁盘残留、编辑器缓存或历史副本；软件尚未经过独立安全审计。")
                }),
                Tuple.Create("日常使用", new[] {
                    Tuple.Create("创建与导入", "点击“创建加密文件夹”可在单窗口中完成命名与选址，默认创建后保持解锁，方便直接拖入文件或点击导入。普通导入会保留原文件。"),
                    Tuple.Create("编辑与自动同步", "双击文件用默认程序打开，或点击“在资源管理器中打开”批量整理。编辑区文件变动会自动刷新到列表。"),
                    Tuple.Create("保存并锁定", "务必先在外部编辑器保存并关闭文件，再回到密封夹点击“保存并锁定”，看到绿色“已锁定”徽章才算完成。")
                }),
                Tuple.Create("异常与恢复", new[] {
                    Tuple.Create("保存失败处理", "常见原因为文件被 Word/Excel 占用。编辑区明文会完整保留，关闭占用后点击“重试保存并锁定”即可。"),
                    Tuple.Create("明文待清理状态", "代表新密文已安全核验写入，只是清理明文受阻。关闭占用后点击“重试清理并锁定”，不会覆写已保存的密文。"),
                    Tuple.Create("异常退出恢复", "软件启动时检测到残留工作区会在顶部显示提醒条。也可打开目标文件夹，在“更多 → 恢复未锁定工作区”中按时间核对恢复。")
                }),
                Tuple.Create("备份与安全边界", new[] {
                    Tuple.Create("正确备份方式", "锁定后以管理员权限备份完整的隐藏密文目录（包含 内容.egvault 与 上一版本.egvault），并独立备份密码。"),
                    Tuple.Create("无密码找回", "程序完全离线运行，不收集任何数据、无后门。忘记密码无法恢复。"),
                    Tuple.Create("安全边界", "解锁期间同 Windows 账户可访问编辑区明文；普通删除不承诺擦除 SSD 历史块；管理员强行接管权限或格式化不在保护范围。")
                })
            };

            List<ActionButton> tabButtons = new List<ActionButton>();
            Action<int> selectTab = delegate(int index)
            {
                for (int i = 0; i < tabButtons.Count; i++)
                    tabButtons[i].Tone = i == index ? ButtonTone.Tint : ButtonTone.Ghost;
                text.Clear();
                Tuple<string, string>[] items = sections[index].Item2;
                using (Font headingFont = new Font(Font.FontFamily, 10.5f, FontStyle.Bold))
                using (Font bodyFont = new Font(Font.FontFamily, 9.5f))
                {
                    for (int i = 0; i < items.Length; i++)
                    {
                        text.SelectionFont = headingFont;
                        text.SelectionColor = Green;
                        text.AppendText(items[i].Item1 + "\r\n");
                        text.SelectionFont = bodyFont;
                        text.SelectionColor = Ink;
                        text.AppendText(items[i].Item2 + (i + 1 < items.Length ? "\r\n\r\n" : ""));
                    }
                }
                text.SelectionStart = 0; text.ScrollToCaret();
            };

            for (int i = 0; i < sections.Length; i++)
            {
                int captured = i;
                ActionButton tab = UiTheme.CreateButton(sections[i].Item1, delegate { selectTab(captured); }, i == 0 ? ButtonTone.Tint : ButtonTone.Ghost, 146, 36);
                tab.Width = 146; tab.TextAlign = ContentAlignment.MiddleLeft; tab.Margin = new Padding(0, 0, 0, 6);
                tabButtons.Add(tab); nav.Controls.Add(tab);
            }
            selectTab(0);

            split.Controls.Add(nav, 0, 0); split.Controls.Add(contentPad, 1, 0);

            Panel footer = new Panel { Dock = DockStyle.Fill, BackColor = UiTheme.Surface, Padding = new Padding(20, 11, 20, 11) };
            footer.Paint += delegate(object s, PaintEventArgs e) { using (Pen pen = new Pen(UiTheme.LineSoft)) e.Graphics.DrawLine(pen, 0, 0, footer.Width, 0); };
            FlowLayoutPanel buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, WrapContents = false };
            ActionButton close = UiTheme.CreateButton("返回", delegate { help.Close(); }, ButtonTone.Primary, 92, 34); close.DialogResult = DialogResult.Cancel;
            buttons.Controls.Add(close); footer.Controls.Add(buttons);

            root.Controls.Add(split, 0, 0); root.Controls.Add(footer, 0, 1); help.Controls.Add(root);
            help.CancelButton = close;
            return help;
        }
        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            if (keyData == (Keys.Alt | Keys.L) && !busy && session != null && session.Open) { LockVault(this, EventArgs.Empty); return true; }
            return base.ProcessCmdKey(ref msg, keyData);
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                StopWorkWatcher();
                masterPassword = null;
                tips.Dispose(); moreMenu.Dispose(); fileCtxMenu.Dispose();
            }
            base.Dispose(disposing);
        }
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
                bool opened = await Run(UnlockAndRemember);
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
        private ActionButton Add(string text, EventHandler click, ButtonTone tone = ButtonTone.Secondary)
        {
            return UiTheme.CreateButton(text, click, tone, 75, 38);
        }
        private void RefreshState(string message)
        {
            bool has = session != null, open = has && session.Open, cleanup = open && session.CleanupPending;
            bool editable = !busy && open && !cleanup;
            create.Enabled = !busy && !open;
            library.Enabled = !busy && !open;
            unlock.Enabled = !busy && has && !open; unlock.Visible = has && !open;
            lockButton.Enabled = !busy && open; lockButton.Visible = open;
            show.Enabled = importFiles.Enabled = importFolder.Enabled = refreshBtn.Enabled = fileFilter.Enabled = editable;
            toolbar.Visible = editable; body.RowStyles[2].Height = editable ? 50 : 0;
            delete.Enabled = recover.Enabled = repairEntry.Enabled = !busy && has && !open;
            repairEntry.Text = open ? "创建或修复密封夹入口（需先保存并锁定）" : "创建或修复密封夹入口…";
            more.Enabled = has && !busy;
            recover.Text = open ? "恢复未锁定工作区（需先保存并锁定）" : "恢复未锁定工作区";
            delete.Text = open ? "删除加密文件夹…（需先保存并锁定）" : "删除加密文件夹…";
            identityBar.Visible = has; body.RowStyles[0].Height = has ? 66 : 0;
            lockButton.Text = busy ? "处理中，请稍候…" : cleanup ? "重试清理并锁定" : operationFailed ? "重试保存并锁定" : "保存并锁定";
            vaultName.Text = has ? new DirectoryInfo(session.Root).Name : "尚未选择加密文件夹";
            vaultName.AccessibleDescription = has ? session.Root : "";
            pathLink.Text = has ? session.Root + "  [复制路径]" : "";
            pathLink.Visible = has;
            tips.SetToolTip(vaultName, has ? session.Root : "");
            tips.SetToolTip(pathLink, has ? "点击复制完整路径：" + session.Root : "");
            string state = busy ? "处理中" : cleanup ? "清理未完成" : operationFailed ? "操作失败" : open ? "已解锁" : has ? "已锁定" : "未选择";
            badge.Text = state; badge.AccessibleName = "文件夹状态：" + state;
            if (operationFailed && !cleanup)
            {
                badge.BackColor = notice.BackColor = UiTheme.RedBg;
                badge.ForeColor = notice.ForeColor = hint.ForeColor = noticeTitle.ForeColor = UiTheme.Red;
                badge.PillBorder = notice.CardBorder = UiTheme.RedBorder;
                notice.AccentBar = UiTheme.Red;
            }
            else if (open && !busy)
            {
                badge.BackColor = notice.BackColor = UiTheme.AmberBg;
                badge.ForeColor = notice.ForeColor = hint.ForeColor = noticeTitle.ForeColor = UiTheme.Amber;
                badge.PillBorder = notice.CardBorder = UiTheme.AmberBorder;
                notice.AccentBar = UiTheme.AmberBar;
            }
            else
            {
                badge.BackColor = notice.BackColor = UiTheme.PrimaryTint;
                badge.ForeColor = notice.ForeColor = hint.ForeColor = noticeTitle.ForeColor = Green;
                badge.PillBorder = notice.CardBorder = UiTheme.PrimaryBorder;
                notice.AccentBar = Green;
            }
            badge.FitWidth();
            progress.Visible = busy;
            if (busy) { noticeTitle.Text = "正在处理，请等待结果"; hint.Text = "正在执行加密、核验或清理操作。大文件夹可能耗时较长；请勿强制退出或重复点击，完成后将更新状态。"; }
            else if (cleanup) { noticeTitle.Text = "密文已保存，但明文尚未清理完"; hint.Text = "请先关闭占用文件的程序，再点击“重试清理并锁定”。本次只重试清理，不重新生成密文。"; }
            else if (operationFailed) { noticeTitle.Text = open ? "操作未完成，编辑内容仍保留在工作区" : "操作未完成，请查看原因后重试"; hint.Text = lastFailure + (open ? " 请保留编辑区；关闭可能占用文件的程序后再重试。" : " 原有资料请保留。"); }
            else if (open) { noticeTitle.Text = ""; hint.Text = "临时明文编辑区，同一 Windows 账户可访问。双击文件直接编辑或拖入文件导入，保存关闭后再锁定。"; }
            else { noticeTitle.Text = ""; hint.Text = ""; }
            bool pending = !String.IsNullOrEmpty(pendingSource) && File.Exists(pendingSource) && !busy;
            if (pending)
            {
                if (hint.Text.Length > 0) hint.Text += "\r\n";
                else noticeTitle.Text = "待加密文件";
                hint.Text += "待移入：" + Path.GetFileName(pendingSource) + "。请点击“创建加密文件夹”；加密核验成功且源文件未变化后，才会移除源明文。";
            }
            LayoutNotice(busy || cleanup || operationFailed || open || pending, busy || cleanup || operationFailed || pending);

            homePanel.Visible = !has;
            fileArea.Visible = has;
            if (!editable)
            {
                StopWorkWatcher();
                if (fileFilter.TextLength > 0) fileFilter.Clear();
            }
            else
            {
                StartWorkWatcher(session.Work);
            }
            RefreshFileList(false);

            switchReasonCard.Visible = open || busy;
            sidebar.RowStyles[4].Height = open || busy ? 62 : 0;
            switchReason.Text = "已解锁，保存并锁定后可切换文件夹。";
            UpdateStartupRecoveryBanner();
            status.Text = busy || operationFailed || cleanup || (!has && !pending && message == "尚未选择加密文件夹") || (message != null && message.StartsWith("已解锁")) ? "" : message;
            tips.SetToolTip(status, status.Text); tips.SetToolTip(hint, hint.Text);
        }

        private void RefreshFileList(bool force)
        {
            bool has = session != null, open = has && session.Open, cleanup = open && session.CleanupPending;
            bool editable = !busy && open && !cleanup;
            int totalCount = 0;
            string filter = fileFilter.Text.Trim();
            files.BeginUpdate();
            try
            {
                files.Items.Clear();
                if (editable && Directory.Exists(session.Work))
                {
                    List<Tuple<string, long, DateTime, string>> entries = new List<Tuple<string, long, DateTime, string>>();
                    foreach (string file in Paths.Files(session.Work))
                    {
                        FileInfo info = new FileInfo(file);
                        string relative = Paths.NameUnder(session.Work, file);
                        totalCount++;
                        if (filter.Length > 0 && relative.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0) continue;
                        entries.Add(Tuple.Create(relative, info.Length, info.LastWriteTime, file));
                    }
                    IEnumerable<Tuple<string, long, DateTime, string>> sorted;
                    if (sortColumn == 1) sorted = sortAscending ? entries.OrderBy(x => x.Item2) : entries.OrderByDescending(x => x.Item2);
                    else if (sortColumn == 2) sorted = sortAscending ? entries.OrderBy(x => x.Item3) : entries.OrderByDescending(x => x.Item3);
                    else sorted = sortAscending ? entries.OrderBy(x => x.Item1, StringComparer.OrdinalIgnoreCase) : entries.OrderByDescending(x => x.Item1, StringComparer.OrdinalIgnoreCase);

                    foreach (var entry in sorted)
                        files.Items.Add(new ListViewItem(new[] { entry.Item1, FormatSize(entry.Item2), entry.Item3.ToString("yyyy-MM-dd HH:mm") }, FileImage(entry.Item4)) { ToolTipText = entry.Item1 });
                }
            }
            finally { files.EndUpdate(); }
            files.Visible = editable && files.Items.Count > 0;
            emptyPanel.Visible = !files.Visible;
            if (files.Visible) FitFileColumns();
            emptyUnlockBtn.Visible = !busy && has && !open;
            PositionEmptyUnlock();
            empty.Text = busy ? "正在处理，请稍候…\r\n全部步骤完成后才会显示“已锁定”。"
                : cleanup ? "等待完成明文清理\r\n请关闭占用文件的程序，再点击“重试清理并锁定”。"
                : open ? (filter.Length > 0 ? "没有匹配的文件\r\n请修改或清空上方筛选关键词。" : "编辑区还没有文件\r\n直接把文件或文件夹拖到这里，或点击上方“导入文件 / 导入文件夹”。")
                : has ? "文件已锁定\r\n点击“解锁文件夹”并验证密码后查看和编辑。\r\n锁定时不展示文件名称与数量。"
                : "从一个加密文件夹开始\r\n创建新文件夹，或从“我的加密文件夹”打开已有资料。";
            count.Visible = editable;
            count.Text = filter.Length > 0 ? files.Items.Count + " / " + totalCount + " 个文件" : totalCount + " 个文件";
        }

        private void OnFileListMouseUp(object sender, MouseEventArgs e)
        {
            if (e.Button != MouseButtons.Right || busy || session == null || !session.Open || session.CleanupPending) return;
            ListViewItem hit = files.GetItemAt(e.X, e.Y);
            if (hit == null) return;
            hit.Selected = true;
            fileCtxMenu.Show(files, e.Location);
        }

        private void LocateSelectedFile(object sender, EventArgs e)
        {
            try
            {
                string path = SelectedFileToOpen(); if (path == null) return;
                Process.Start(new ProcessStartInfo("explorer.exe", "/select,\"" + path + "\"") { UseShellExecute = true });
            }
            catch (Exception error) { MessageBox.Show(this, error.Message, "无法定位文件"); }
        }

        private void CopySelectedFileName(object sender, EventArgs e)
        {
            if (files.SelectedItems.Count != 1) return;
            string name = files.SelectedItems[0].Text;
            try { Clipboard.SetText(name); status.Text = "已复制文件名：" + name; }
            catch (Exception) { }
        }

        private async void RemoveSelectedFile(object sender, EventArgs e)
        {
            if (busy || session == null || !session.Open || session.CleanupPending || files.SelectedItems.Count != 1) return;
            string relative = files.SelectedItems[0].Text;
            if (MessageBox.Show(this, "确定从当前编辑区删除以下文件吗？\r\n\r\n" + relative + "\r\n\r\n点击“保存并锁定”后才会更新到加密快照。", "从编辑区删除", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            await Run(delegate
            {
                string target = Paths.Target(session.Work, relative);
                Paths.NoLinks(target);
                if (File.Exists(target))
                {
                    Native.RejectHardLink(target);
                    File.SetAttributes(target, File.GetAttributes(target) & ~FileAttributes.ReadOnly);
                    File.Delete(target);
                }
                return "已从编辑区删除：" + relative + "（点击保存并锁定后生效）";
            });
        }

        private async Task ImportDroppedPaths(string[] dropped)
        {
            await Run(delegate
            {
                int fileCount = 0, dirCount = 0;
                foreach (string item in dropped)
                {
                    if (Directory.Exists(item)) { session.ImportFolder(item); dirCount++; }
                    else if (File.Exists(item)) { session.ImportFile(item); fileCount++; }
                }
                return "已拖放复制到编辑区（" + fileCount + " 个文件、" + dirCount + " 个文件夹）· 原文件保留，完成后请保存并锁定";
            });
        }

        private void FitFileColumns()
        {
            int width = files.ClientSize.Width - SystemInformation.VerticalScrollBarWidth - 2;
            if (width < 300) return;
            files.Columns[1].Width = Math.Max(82, width / 7);
            files.Columns[2].Width = Math.Max(136, width / 5);
            files.Columns[0].Width = width - files.Columns[1].Width - files.Columns[2].Width;
            Native.HideHorizontalScrollBar(files);
        }
        private void LayoutNotice(bool visible, bool detailed)
        {
            notice.Visible = visible;
            body.RowStyles[1].Height = !visible ? 0 : detailed ? (operationFailed ? 120 : 94) : 48;
            noticeTitle.Visible = detailed;
            noticeText.RowStyles[0].Height = detailed ? 24 : 0;
            hint.BackColor = notice.BackColor;
            hint.ScrollBars = detailed && HintOverflows() ? ScrollBars.Vertical : ScrollBars.None;
            hint.TabStop = detailed;
            notice.Invalidate();
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
                using (Bitmap bitmap = UiTheme.CreateFileTypeGlyph(extension))
                {
                    fileImages.Images.Add(key, bitmap);
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
            operationFailed = false; lastFailure = null; busy = true; StopWorkWatcher(); RefreshState("处理中，请稍候"); UseWaitCursor = true;
            string result = null; Exception failure = null;
            try { result = await Task.Run(work); }
            catch (Exception error) { failure = error; }
            busy = false; UseWaitCursor = false; operationFailed = failure != null; lastFailure = failure == null ? null : failure.Message;
            try { RefreshState(failure == null ? result : "操作未完成，原有数据请保留"); }
            catch (Exception error)
            {
                failure = failure ?? error; operationFailed = true; lastFailure = failure.Message;
                noticeTitle.Text = "操作未完成，请保留当前资料"; hint.Text = lastFailure;
                notice.BackColor = UiTheme.RedBg; hint.ForeColor = noticeTitle.ForeColor = UiTheme.Red;
                notice.CardBorder = UiTheme.RedBorder; notice.AccentBar = UiTheme.Red;
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
            string defaultParent = File.Exists(pendingSource)
                ? Path.GetDirectoryName(pendingSource)
                : Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            string root;
            bool keepOpen;
            using (CreateVaultDialog dialog = new CreateVaultDialog(defaultParent, File.Exists(pendingSource) ? pendingSource : null))
            {
                if (dialog.ShowDialog(this) != DialogResult.OK) return;
                root = dialog.SelectedRoot;
                keepOpen = dialog.KeepOpen;
            }
            string password = masterPassword;
            string entryWarning = null;
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
                bool shouldLock = source != null || !keepOpen;
                if (shouldLock) session.Lock();
                entryWarning = CreateEntryWarning(root);
                catalog.Add(root, true, DateTime.UtcNow.Ticks); catalog.Save(masterPassword);
                if (source != null)
                {
                    if (!Paths.Equal(sourceHash, Paths.Hash(source))) return "加密并锁定成功；源文件发生变化，原文件已保留";
                    try { File.Delete(source); }
                    catch { return "加密并锁定成功；原文件无法删除，请自行处理明文副本"; }
                    return "创建成功 · 原文件已加密移入，明文工作区已清理";
                }
                return shouldLock
                    ? "创建成功 · 已锁定并启用防误删保护"
                    : "创建成功 · 已保持解锁，可直接拖入或导入文件，完成后请保存并锁定";
            });
            password = null;
            if (entryWarning != null)
                MessageBox.Show(this, entryWarning, "可从列表打开资料", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        private static string CreateEntryWarning(string root, bool protect = true)
        {
            try { FolderEntry.Create(root, protect); return null; }
            catch (Exception error)
            {
                return "资料已加密，图标入口设置未完成。请从“我的加密文件夹”打开，或稍后修复入口。\r\n" + error.Message;
            }
        }
        internal sealed class SealOutcome { internal string Root, Warning; }
        // Explorer entry: seal a file into a same-named vault, or seal a folder in place.
        internal static SealOutcome SealPath(string path, string sessionsBase, string password, bool protect = true)
        {
            string full = Paths.Full(path);
            SealOutcome outcome;
            if (Directory.Exists(full)) outcome = SealDirectory(full, sessionsBase, password, protect);
            else if (File.Exists(full)) outcome = SealFile(full, sessionsBase, password, protect);
            else throw new IOException("路径不存在：" + full);
            string entryWarning = CreateEntryWarning(outcome.Root, protect);
            if (entryWarning != null)
                outcome.Warning = outcome.Warning == null ? entryWarning : outcome.Warning + "\r\n" + entryWarning;
            return outcome;
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
        private async void UnlockVault(object sender, EventArgs e)
        {
            try
            {
                if (!await EnsureMaster(true) || !await PrepareManaged()) return;
                await Run(UnlockAndRemember);
            }
            finally { ReleaseAuthorization(); }
        }
        private string UnlockAndRemember()
        {
            session.Unlock(masterPassword);
            try
            {
                catalog.Add(session.Root, true, DateTime.UtcNow.Ticks);
                catalog.Save(masterPassword);
                return "已解锁 · 使用结束后请保存并锁定";
            }
            catch (IOException) { return "最近打开记录未保存，当前文件夹已解锁。"; }
            catch (UnauthorizedAccessException) { return "最近打开记录未保存，当前文件夹已解锁。"; }
            catch (CryptographicException) { return "最近打开记录未保存，当前文件夹已解锁。"; }
        }
        private async void LockVault(object sender, EventArgs e)
        {
            if (busy || session == null || !session.Open) return;
            if (!session.CleanupPending)
            {
                using (LockConfirmDialog confirm = new LockConfirmDialog(
                    "保存并锁定",
                    "请先保存并关闭正在编辑的文件",
                    "确认后将依次执行：生成新密文快照 → 逐文件核验 SHA-256 → 清理临时明文编辑区。全部完成后才会标记为“已锁定”。",
                    "确认保存并锁定"))
                {
                    if (confirm.ShowDialog(this) != DialogResult.OK) return;
                }
            }
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
            string source = null;
            try { source = VaultFolderPicker.Choose(Handle, "选择要复制进来的文件夹（原文件夹保留）", "导入此文件夹"); }
            catch (COMException)
            {
                using (FolderBrowserDialog dialog = new FolderBrowserDialog { Description = "选择要复制进来的文件夹（原文件夹保留）" })
                    if (dialog.ShowDialog(this) == DialogResult.OK) source = dialog.SelectedPath;
            }
            if (String.IsNullOrEmpty(source)) return;
            await Run(delegate { session.ImportFolder(source); return "文件夹已复制到编辑区 · 请保存并锁定；源文件夹保留"; });
        }
        private async void RepairFolderEntry(object sender, EventArgs e)
        {
            if (busy || session == null || session.Open) return;
            string password = AskPassword(false, "验证密码以创建或修复密封夹入口", session.Root);
            if (password == null) return;
            try
            {
                await Run(delegate
                {
                    session.RepairEntry(password);
                    return "密封夹入口已就绪 · 双击图标并输入密码打开";
                });
            }
            finally { password = null; }
        }
        private async void DeleteVault(object sender, EventArgs e)
        {
            string root = session.Root;
            if (MessageBox.Show(this, "将永久删除以下加密文件夹及其中所有文件：\r\n\r\n" + root + "\r\n\r\n此操作不进入回收站。是否继续验证密码？", "删除加密文件夹", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            string password = AskPassword(false, "删除前再次验证密码", root); if (password == null) return;
            await Run(delegate
            {
                session.Delete(password); session.Dispose(); session = null;
                string result = "加密文件夹已删除";
                try { FolderEntry.Remove(root); }
                catch (Exception) { result += "。图标入口清理失败，可手动删除快捷入口。"; }
                try
                {
                    if (File.Exists(catalog.FilePath))
                    {
                        catalog.Load(password);
                        if (catalog.Locations.RemoveAll(x => String.Equals(x.Path, root, StringComparison.OrdinalIgnoreCase)) > 0)
                            catalog.Save(password);
                    }
                }
                catch (Exception) { return result + "。位置记录未更新，列表可能仍显示不可用条目。"; }
                finally { password = null; ReleaseAuthorization(); }
                return result;
            }); password = null;
        }
        private string PickWorkspace(string[] workspaces)
        {
            using (Form dialog = new Form { ClientSize = new Size(700, 400), MinimumSize = new Size(580, 360), MinimizeBox = false })
            {
                UiTheme.StyleDialog(dialog, "恢复未锁定工作区");
                TableLayoutPanel root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = Padding.Empty };
                root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
                root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
                root.RowStyles.Add(new RowStyle(SizeType.Absolute, 58));

                TableLayoutPanel layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(20, 16, 20, 10), RowCount = 4, ColumnCount = 1 };
                layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
                layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));
                layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
                layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
                layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));

                layout.Controls.Add(new Label { Text = "当前加密文件夹路径（恢复前将核对来源快照，不会用旧工作区覆盖较新密文）", Dock = DockStyle.Fill, ForeColor = UiTheme.Muted, Font = new Font("Microsoft YaHei UI", 8.5f), TextAlign = ContentAlignment.MiddleLeft }, 0, 0);
                TextBox rootPathBox = new TextBox { Text = session.Root, ReadOnly = true, Dock = DockStyle.Top, BackColor = UiTheme.Surface, ForeColor = UiTheme.Ink, AccessibleName = "当前加密文件夹路径" };
                Panel listFrame = new Panel { Dock = DockStyle.Fill, Padding = new Padding(1), BackColor = UiTheme.Line, Margin = new Padding(0, 6, 0, 8) };
                ListView list = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, MultiSelect = false, HideSelection = false, BorderStyle = BorderStyle.None, BackColor = Color.White, OwnerDraw = true, AccessibleName = "此加密文件夹的遗留工作区" };
                list.Columns.Add("最近修改时间", 160); list.Columns.Add("状态", 120); list.Columns.Add("工作区编号", 320);
                list.DrawColumnHeader += delegate(object s, DrawListViewColumnHeaderEventArgs e)
                {
                    using (SolidBrush bg = new SolidBrush(UiTheme.Surface)) e.Graphics.FillRectangle(bg, e.Bounds);
                    using (Pen sep = new Pen(UiTheme.Line)) e.Graphics.DrawLine(sep, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
                    TextRenderer.DrawText(e.Graphics, e.Header.Text, new Font("Microsoft YaHei UI", 9f, FontStyle.Bold), Rectangle.Inflate(e.Bounds, -8, 0), UiTheme.Muted, TextFormatFlags.Left | TextFormatFlags.VerticalCenter);
                };
                list.DrawItem += delegate(object s, DrawListViewItemEventArgs e) { e.DrawDefault = true; };
                list.DrawSubItem += delegate(object s, DrawListViewSubItemEventArgs e) { e.DrawDefault = true; };
                listFrame.Controls.Add(list);

                TextBox path = new TextBox { ReadOnly = true, Dock = DockStyle.Top, BackColor = UiTheme.Surface, ForeColor = UiTheme.Muted, AccessibleName = "所选工作区目录" };
                ActionButton recoverButton = UiTheme.CreateButton("验证并恢复", delegate { dialog.DialogResult = DialogResult.OK; }, ButtonTone.Primary, 118, 34);
                ActionButton cancelButton = UiTheme.CreateButton("取消", delegate { dialog.DialogResult = DialogResult.Cancel; }, ButtonTone.Secondary, 84, 34);
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

                Panel footer = new Panel { Dock = DockStyle.Fill, BackColor = UiTheme.Surface, Padding = new Padding(20, 11, 20, 11) };
                footer.Paint += delegate(object s, PaintEventArgs e) { using (Pen p = new Pen(UiTheme.LineSoft)) e.Graphics.DrawLine(p, 0, 0, footer.Width, 0); };
                FlowLayoutPanel buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, WrapContents = false };
                buttons.Controls.AddRange(new Control[] { recoverButton, cancelButton });
                footer.Controls.Add(buttons);

                layout.Controls.Add(rootPathBox, 0, 1); layout.Controls.Add(listFrame, 0, 2); layout.Controls.Add(path, 0, 3);
                root.Controls.Add(layout, 0, 0); root.Controls.Add(footer, 0, 1);
                dialog.Controls.Add(root); dialog.AcceptButton = recoverButton; dialog.CancelButton = cancelButton;
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
            if (session == null || !session.Open) { StopWorkWatcher(); if (session != null) session.Dispose(); return; }
            e.Cancel = true;
            using (LockConfirmDialog confirm = new LockConfirmDialog(
                "保存后退出",
                "退出前需要加密保存并清理明文工作区",
                "请先关闭外部编辑器中打开的文件。点击“保存并退出”将生成新密文、核验并清理编辑区，完成后自动退出程序。",
                "保存并退出"))
            {
                if (confirm.ShowDialog(this) != DialogResult.OK) return;
            }
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
