// Copyright (c) EurekaGao. Update tests use generated release metadata only.
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FolderSeal;

internal static class UpdateTests
{
    private static int checks;
    private static void Check(bool value, string message) { if (!value) throw new Exception(message); checks++; Console.WriteLine("PASS " + message); }
    private static string Release(string version, bool draft, bool preview, string assetVersion, string url, string extraAsset = null)
    {
        string assets = "{\"name\":\"FolderSeal-" + assetVersion + "-Setup.exe\",\"state\":\"uploaded\",\"size\":123,\"browser_download_url\":\"" + url + "\"}";
        if (!String.IsNullOrEmpty(extraAsset)) assets += "," + extraAsset;
        return "{\"tag_name\":\"v" + version + "\",\"draft\":" + (draft ? "true" : "false") + ",\"prerelease\":" + (preview ? "true" : "false") + ",\"assets\":[" + assets + "]}";
    }
    private static string Valid(string version, bool draft, bool preview, bool withChecksum = false)
    {
        string checksum = withChecksum
            ? "{\"name\":\"SHA256SUMS.txt\",\"state\":\"uploaded\",\"size\":96,\"browser_download_url\":\"https://github.com/RanchoGao/FolderSeal/releases/download/v" + version + "/SHA256SUMS.txt\"}"
            : null;
        return Release(version, draft, preview, version, "https://github.com/RanchoGao/FolderSeal/releases/download/v" + version + "/FolderSeal-" + version + "-Setup.exe", checksum);
    }
    private static UpdateInfo Parse(string json)
    { using (MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(json))) return UpdateChecker.Parse(stream, new Version(2, 5, 0, 0)); }

    private static string Sha256Hex(byte[] data)
    {
        using (SHA256 sha = SHA256.Create())
        {
            byte[] hash = sha.ComputeHash(data);
            StringBuilder sb = new StringBuilder(hash.Length * 2);
            foreach (byte b in hash) sb.Append(b.ToString("X2"));
            return sb.ToString();
        }
    }

    private sealed class LoopbackServer : IDisposable
    {
        private readonly TcpListener listener;
        private readonly CancellationTokenSource cts = new CancellationTokenSource();
        private readonly Func<string, Tuple<int, string, byte[]>> handler;
        public int Port { get { return ((IPEndPoint)listener.LocalEndpoint).Port; } }
        public LoopbackServer(Func<string, Tuple<int, string, byte[]>> handler)
        {
            this.handler = handler;
            listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            Task.Run((Func<Task>)AcceptLoop);
        }
        private async Task AcceptLoop()
        {
            while (!cts.IsCancellationRequested)
            {
                TcpClient client = null;
                try { client = await listener.AcceptTcpClientAsync().ConfigureAwait(false); }
                catch (Exception) { break; }
                TcpClient captured = client;
                ThreadPool.QueueUserWorkItem(delegate { HandleClient(captured); });
            }
        }
        private void HandleClient(TcpClient client)
        {
            using (client)
            using (NetworkStream stream = client.GetStream())
            using (StreamReader reader = new StreamReader(stream, Encoding.ASCII, false, 1024, true))
            {
                try
                {
                    string requestLine = reader.ReadLine();
                    if (String.IsNullOrEmpty(requestLine)) return;
                    string line;
                    while (!String.IsNullOrEmpty(line = reader.ReadLine())) { }
                    string[] parts = requestLine.Split(' ');
                    string path = parts.Length >= 2 ? parts[1] : "/";
                    Tuple<int, string, byte[]> resp = handler(path);
                    int code = resp.Item1;
                    string extraHeader = resp.Item2 ?? "";
                    byte[] body = resp.Item3 ?? new byte[0];
                    string reason = code == 200 ? "OK" : code == 302 ? "Found" : "Error";
                    string head = "HTTP/1.1 " + code + " " + reason + "\r\nContent-Length: " + body.Length + "\r\nConnection: close\r\n" + extraHeader + "\r\n";
                    byte[] headBytes = Encoding.ASCII.GetBytes(head);
                    stream.Write(headBytes, 0, headBytes.Length);
                    if (body.Length > 0) stream.Write(body, 0, body.Length);
                    stream.Flush();
                }
                catch (Exception) { }
            }
        }
        public void Dispose()
        {
            cts.Cancel();
            try { listener.Stop(); } catch (Exception) { }
            cts.Dispose();
        }
    }

    private static int Main(string[] args)
    {
        string tempWork = Path.Combine(Path.GetTempPath(), "folderseal-update-tests-" + Guid.NewGuid().ToString("N"));
        try
        {
            if (args.Length == 1 && args[0] == "--live")
            {
                UpdateInfo live = UpdateChecker.CheckAsync().GetAwaiter().GetResult();
                Console.WriteLine("LIVE current=" + UpdateChecker.CurrentVersion.ToString(3) + "; result=" + (live == null ? "no newer installer" : live.Version.ToString(3)));
                return 0;
            }
            Check(Parse("[]") == null, "empty published releases do not invent an update");
            Check(Parse("[" + Valid("2.5.0", false, false) + "," + Valid("2.4.9", false, false) + "]") == null, "equal and older versions never cause downgrade prompts");
            UpdateInfo newest = Parse("[" + Valid("2.9.0", false, false) + "," + Valid("2.10.0", false, false, true) + "]");
            Check(newest.Version == new Version(2, 10, 0, 0), "numeric version order works across multi-digit components");
            Check(newest.FileName == "FolderSeal-2.10.0-Setup.exe" && newest.ExpectedSize == 123 && newest.ChecksumUrl != null && newest.ChecksumUrl.EndsWith("/SHA256SUMS.txt"), "parse extracts filename, expected size, and optional checksum URL");
            UpdateInfo withoutChecksum = Parse("[" + Valid("2.8.0", false, false, false) + "]");
            Check(withoutChecksum != null && withoutChecksum.ChecksumUrl == null, "releases without SHA256SUMS.txt remain supported");
            Check(Parse("[" + Valid("9.0.0", true, false) + "]") == null, "draft releases are ignored");
            Check(Parse("[{\"tag_name\":\"v9.0.0\",\"assets\":[]}," + Valid("2.6.0", false, false) + "]").Version.Minor == 6, "release without installer does not hide a usable release");
            UpdateInfo preview = Parse("[" + Valid("2.6.0", false, true) + "]");
            Check(preview != null && preview.Prerelease, "published prerelease installers retain warning flag");
            Check(Parse("[" + Release("2.6.0", false, false, "2.5.0", "https://github.com/RanchoGao/FolderSeal/releases/download/v2.6.0/FolderSeal-2.5.0-Setup.exe") + "]") == null, "mismatched installer version is ignored");
            foreach (string url in new[] { "https://example.com/setup.exe", "http://github.com/RanchoGao/FolderSeal/releases/download/v2.6.0/FolderSeal-2.6.0-Setup.exe", "file:///C:/setup.exe", "https://github.com/Other/FolderSeal/releases/download/v2.6.0/FolderSeal-2.6.0-Setup.exe" })
                Check(Parse("[" + Release("2.6.0", false, false, "2.6.0", url) + "]") == null, "untrusted download destination is rejected");
            Check(Parse("[null,{}," + Valid("not-a-version", false, false) + "]") == null, "incomplete and unsupported tags are ignored");
            bool invalid = false;
            try { Parse("not json"); } catch { invalid = true; }
            Check(invalid, "invalid server response is a failure rather than up-to-date");
            Check(Parse("[" + Valid("2.6.0", false, false).Replace("uploaded", "new") + "]") == null, "unfinished asset uploads are ignored");
            Check(Parse("[" + Valid("2.6.0", false, false).Replace("123", "0") + "]") == null, "empty installer assets are ignored");

            // Trusted download redirect validation
            Check(UpdateInstaller.IsTrustedDownloadUri(new Uri("https://github.com/RanchoGao/FolderSeal/releases/download/v2.12.0/FolderSeal-2.12.0-Setup.exe")), "github.com HTTPS download URL is trusted");
            Check(UpdateInstaller.IsTrustedDownloadUri(new Uri("https://objects.githubusercontent.com/github-production-release-asset/123")), "objects.githubusercontent.com HTTPS redirect is trusted");
            Check(UpdateInstaller.IsTrustedDownloadUri(new Uri("https://release-assets.githubusercontent.com/asset/123")), "release-assets.githubusercontent.com HTTPS redirect is trusted");
            foreach (string bad in new[] { "http://github.com/a", "https://evilgithub.com/a", "https://githubusercontent.com.evil.com/a", "https://githubusercontent.com/a", "file:///C:/a.exe" })
                Check(!UpdateInstaller.IsTrustedDownloadUri(new Uri(bad)), "untrusted redirect target rejected: " + bad);

            // SHA256SUMS.txt parsing
            string sampleHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            string parsedHash;
            Check(UpdateInstaller.TryParseSha256(sampleHash + "  FolderSeal-2.12.0-Setup.exe\r\n", "FolderSeal-2.12.0-Setup.exe", out parsedHash) && parsedHash == sampleHash.ToUpperInvariant(), "SHA256SUMS entry matches target filename");
            Check(UpdateInstaller.TryParseSha256("# comment\n" + sampleHash + " *FolderSeal-2.12.0-Setup.exe\n", "FolderSeal-2.12.0-Setup.exe", out parsedHash), "SHA256SUMS binary asterisk format is supported");
            Check(!UpdateInstaller.TryParseSha256(sampleHash + "  Other.exe\n", "FolderSeal-2.12.0-Setup.exe", out parsedHash), "SHA256SUMS ignores unrelated filenames");
            Check(!UpdateInstaller.TryParseSha256("not-a-hash  FolderSeal-2.12.0-Setup.exe\n", "FolderSeal-2.12.0-Setup.exe", out parsedHash), "SHA256SUMS rejects malformed digest");

            // Installed vs portable detection and apply script generation
            Directory.CreateDirectory(tempWork);
            string installedDir = Path.Combine(tempWork, "Installed");
            string portableDir = Path.Combine(tempWork, "Portable");
            Directory.CreateDirectory(installedDir);
            Directory.CreateDirectory(portableDir);
            File.WriteAllText(Path.Combine(installedDir, UpdateInstaller.ProductMarkerFile), UpdateInstaller.ProductMarkerValue);
            string detected;
            Check(UpdateInstaller.TryGetInstalledDirectory(installedDir, out detected) && String.Equals(detected, installedDir, StringComparison.OrdinalIgnoreCase), "installed directory detected via product marker");
            Check(!UpdateInstaller.TryGetInstalledDirectory(portableDir, out detected), "portable directory without marker is not treated as installed");
            string silentScript = UpdateInstaller.BuildApplyScript(@"C:\Temp\FolderSeal-2.12.0-Setup.exe", @"C:\Program Files\EurekaGao\FolderSeal", 4321, @"C:\Temp\apply.ps1", sampleHash.ToUpperInvariant());
            Check(silentScript.Contains("/S /D=") && silentScript.Contains("4321") && silentScript.Contains("FolderSeal.exe") && silentScript.Contains("Get-FileHash") && silentScript.Contains("WaitForExit(180000)") && !silentScript.Contains("} else {\r\n  Start-Process -FilePath $installer"), "silent upgrade script verifies hash, uses bounded wait, and omits blind interactive fallback");
            string portableScript = UpdateInstaller.BuildApplyScript(@"C:\Temp\FolderSeal-2.12.0-Setup.exe", null, 4321, @"C:\Temp\apply.ps1", sampleHash.ToUpperInvariant());
            Check(!portableScript.Contains("/S /D=") && portableScript.Contains("Get-FileHash"), "portable upgrade script verifies hash and launches interactive installer");

            // End-to-end streaming download, redirect following, SHA-256 verification and fail-closed rejection
            byte[] payload = new byte[48 * 1024];
            for (int i = 0; i < payload.Length; i++) payload[i] = (byte)(i % 251);
            string payloadHash = Sha256Hex(payload);
            string badHash = new string('A', 64);
            using (LoopbackServer server = new LoopbackServer(delegate(string path)
            {
                if (path == "/redirect") return Tuple.Create(302, "Location: /setup.exe\r\n", new byte[0]);
                if (path == "/setup.exe") return Tuple.Create(200, "", payload);
                if (path == "/sums-ok") return Tuple.Create(200, "", Encoding.ASCII.GetBytes(payloadHash + "  FolderSeal-2.12.0-Setup.exe\r\n"));
                if (path == "/sums-bad") return Tuple.Create(200, "", Encoding.ASCII.GetBytes(badHash + "  FolderSeal-2.12.0-Setup.exe\r\n"));
                if (path == "/sums-missing") return Tuple.Create(200, "", Encoding.ASCII.GetBytes(payloadHash + "  Other.exe\r\n"));
                return Tuple.Create(404, "", new byte[0]);
            }))
            {
                Func<Uri, bool> allowLocal = delegate(Uri u) { return u != null && u.Host == "127.0.0.1"; };
                string dlDir = Path.Combine(tempWork, "downloads");
                List<int> percents = new List<int>();
                IProgress<UpdateDownloadProgress> progress = new Progress<UpdateDownloadProgress>(delegate(UpdateDownloadProgress p) { lock (percents) percents.Add(p.Percent); });
                UpdateInfo okInfo = new UpdateInfo
                {
                    Version = new Version(2, 12, 0, 0),
                    FileName = "FolderSeal-2.12.0-Setup.exe",
                    ExpectedSize = payload.Length,
                    DownloadUrl = "http://127.0.0.1:" + server.Port + "/redirect",
                    ChecksumUrl = "http://127.0.0.1:" + server.Port + "/sums-ok"
                };
                string saved = UpdateInstaller.DownloadAsync(okInfo, dlDir, allowLocal, progress, CancellationToken.None).GetAwaiter().GetResult();
                Check(File.Exists(saved) && new FileInfo(saved).Length == payload.Length && !File.Exists(saved + ".part"), "redirected download saves verified installer and removes .part");

                UpdateInfo badInfo = new UpdateInfo
                {
                    Version = new Version(2, 12, 0, 0),
                    FileName = "FolderSeal-2.12.0-Setup.exe",
                    ExpectedSize = payload.Length,
                    DownloadUrl = "http://127.0.0.1:" + server.Port + "/setup.exe",
                    ChecksumUrl = "http://127.0.0.1:" + server.Port + "/sums-bad"
                };
                bool hashRejected = false;
                try { UpdateInstaller.DownloadAsync(badInfo, Path.Combine(tempWork, "bad-dl"), allowLocal, null, CancellationToken.None).GetAwaiter().GetResult(); }
                catch (InvalidDataException) { hashRejected = true; }
                Check(hashRejected && !File.Exists(Path.Combine(tempWork, "bad-dl", "FolderSeal-2.12.0-Setup.exe.part")), "SHA-256 mismatch rejects download and cleans temporary file");

                UpdateInfo noChecksumInfo = new UpdateInfo
                {
                    Version = new Version(2, 12, 0, 0),
                    FileName = "FolderSeal-2.12.0-Setup.exe",
                    ExpectedSize = payload.Length,
                    DownloadUrl = "http://127.0.0.1:" + server.Port + "/setup.exe",
                    ChecksumUrl = null
                };
                bool noChecksumRejected = false;
                try { UpdateInstaller.DownloadAsync(noChecksumInfo, Path.Combine(tempWork, "no-sum-dl"), allowLocal, null, CancellationToken.None).GetAwaiter().GetResult(); }
                catch (InvalidDataException) { noChecksumRejected = true; }
                Check(noChecksumRejected && !File.Exists(Path.Combine(tempWork, "no-sum-dl", "FolderSeal-2.12.0-Setup.exe.part")), "missing SHA256SUMS.txt URL fails closed and cleans temporary file");

                UpdateInfo missingEntryInfo = new UpdateInfo
                {
                    Version = new Version(2, 12, 0, 0),
                    FileName = "FolderSeal-2.12.0-Setup.exe",
                    ExpectedSize = payload.Length,
                    DownloadUrl = "http://127.0.0.1:" + server.Port + "/setup.exe",
                    ChecksumUrl = "http://127.0.0.1:" + server.Port + "/sums-missing"
                };
                bool missingEntryRejected = false;
                try { UpdateInstaller.DownloadAsync(missingEntryInfo, Path.Combine(tempWork, "missing-entry-dl"), allowLocal, null, CancellationToken.None).GetAwaiter().GetResult(); }
                catch (InvalidDataException) { missingEntryRejected = true; }
                Check(missingEntryRejected && !File.Exists(Path.Combine(tempWork, "missing-entry-dl", "FolderSeal-2.12.0-Setup.exe.part")), "missing target entry in SHA256SUMS.txt fails closed");

                UpdateInfo badSizeInfo = new UpdateInfo
                {
                    Version = new Version(2, 12, 0, 0),
                    FileName = "FolderSeal-2.12.0-Setup.exe",
                    ExpectedSize = payload.Length - 1,
                    DownloadUrl = "http://127.0.0.1:" + server.Port + "/setup.exe",
                    ChecksumUrl = "http://127.0.0.1:" + server.Port + "/sums-ok"
                };
                bool sizeRejected = false;
                try { UpdateInstaller.DownloadAsync(badSizeInfo, Path.Combine(tempWork, "bad-size-dl"), allowLocal, null, CancellationToken.None).GetAwaiter().GetResult(); }
                catch (InvalidDataException) { sizeRejected = true; }
                Check(sizeRejected && !File.Exists(Path.Combine(tempWork, "bad-size-dl", "FolderSeal-2.12.0-Setup.exe.part")), "size mismatch rejects download and cleans temporary file");

                using (CancellationTokenSource cancelledCts = new CancellationTokenSource())
                {
                    cancelledCts.Cancel();
                    bool cancelled = false;
                    try { UpdateInstaller.DownloadAsync(okInfo, Path.Combine(tempWork, "cancel-dl"), allowLocal, null, cancelledCts.Token).GetAwaiter().GetResult(); }
                    catch (OperationCanceledException) { cancelled = true; }
                    Check(cancelled && !File.Exists(Path.Combine(tempWork, "cancel-dl", "FolderSeal-2.12.0-Setup.exe.part")), "cancelled download throws OperationCanceledException and leaves no .part");
                }
            }

            Console.WriteLine("SUCCESS " + checks + " update checks"); return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
        finally
        {
            try { if (Directory.Exists(tempWork)) Directory.Delete(tempWork, true); } catch (Exception) { }
        }
    }
}
