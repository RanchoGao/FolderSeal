// Copyright (c) EurekaGao. Update tests use generated release metadata only.
using System;
using System.IO;
using System.Text;
using FolderSeal;

internal static class UpdateTests
{
    private static int checks;
    private static void Check(bool value, string message) { if (!value) throw new Exception(message); checks++; Console.WriteLine("PASS " + message); }
    private static string Release(string version, bool draft, bool preview, string assetVersion, string url)
    {
        return "{\"tag_name\":\"v" + version + "\",\"draft\":" + (draft ? "true" : "false") + ",\"prerelease\":" + (preview ? "true" : "false") + ",\"assets\":[{\"name\":\"FolderSeal-" + assetVersion + "-Setup.exe\",\"state\":\"uploaded\",\"size\":123,\"browser_download_url\":\"" + url + "\"}]}";
    }
    private static string Valid(string version, bool draft, bool preview)
    { return Release(version, draft, preview, version, "https://github.com/RanchoGao/FolderSeal/releases/download/v" + version + "/FolderSeal-" + version + "-Setup.exe"); }
    private static UpdateInfo Parse(string json)
    { using (MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(json))) return UpdateChecker.Parse(stream, new Version(2, 5, 0, 0)); }
    private static int Main(string[] args)
    {
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
            UpdateInfo newest = Parse("[" + Valid("2.9.0", false, false) + "," + Valid("2.10.0", false, false) + "]");
            Check(newest.Version == new Version(2, 10, 0, 0), "numeric version order works across multi-digit components");
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
            Console.WriteLine("SUCCESS " + checks + " update checks"); return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
