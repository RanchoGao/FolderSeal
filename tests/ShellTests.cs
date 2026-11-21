// Copyright (c) EurekaGao. Tests use generated fixtures, never personal files.
using System;
using System.IO;
using System.Text;
using Microsoft.Win32;
using FolderSeal;

internal static class ShellTests
{
    private static int checks;
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
        catch (Exception error)
        {
            if (error is IOException || error is UnauthorizedAccessException || error is ArgumentException) failed = true;
            else throw;
        }
        Assert(failed, message);
    }
    private static int Main(string[] args)
    {
        if (args.Length == 0) { Console.Error.WriteLine("Specify an existing writable test parent."); return 2; }
        string parent = Paths.Full(args[0]);
        if (!Directory.Exists(parent)) return 2;
        string container = Path.Combine(parent, "shell-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(container);
        bool passed = false;
        try
        {
            Arguments();
            Menu(container);
            SealSingleFile(container);
            SealFolder(container);
            Guards(container);
            Console.WriteLine("SUCCESS " + checks + " checks");
            passed = true; return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error);
            Console.Error.WriteLine("Generated fixtures retained: " + container);
            return 1;
        }
        finally
        {
            if (passed && Paths.Inside(container, parent) && Path.GetFileName(container).StartsWith("shell-test-"))
            {
                try { Paths.DeleteTree(container); }
                catch (Exception error) { Console.Error.WriteLine("Fixture cleanup: " + error.Message); }
            }
        }
    }
    private static void Arguments()
    {
        string[] seal = InstanceGate.Normalize(new[] { "--seal", Path.Combine(Path.GetTempPath(), "a.txt") });
        Assert(seal[0] == "--seal" && Path.IsPathRooted(seal[1]), "--seal accepted and path normalized");
        Assert(InstanceGate.Normalize(new[] { "--open-vault", Path.Combine(Path.GetTempPath(), "v") })[0] == "--open-vault", "open verb still accepted");
        Fails(delegate { InstanceGate.Normalize(new[] { "--seal", "" }); }, "empty seal path rejected");
        Fails(delegate { InstanceGate.Normalize(new[] { "--seal" }); }, "missing seal path rejected");
        Fails(delegate { InstanceGate.Normalize(new[] { "--unknown", Path.GetTempPath() }); }, "unknown verb rejected");
    }
    private static void Menu(string container)
    {
        string baseKey = @"Software\EurekaGao\FolderSeal\TestMenu-" + Guid.NewGuid().ToString("N");
        try
        {
            Assert(!ExplorerMenu.Installed(baseKey), "menu initially absent");
            ExplorerMenu.Write(baseKey, Path.Combine(container, "FolderSeal.exe"), "加密此文件夹（密封夹）", "加密此文件（密封夹）", "用密封夹打开");
            Assert(ExplorerMenu.Installed(baseKey), "menu installed");
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(baseKey + @"\Directory\shell\" + ExplorerMenu.SealVerb + @"\command"))
            {
                Assert(key != null, "folder seal command exists");
                Assert(((string)key.GetValue(null)).Contains("--seal \"%1\""), "folder seal command quotes the target");
            }
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(baseKey + @"\*\shell\" + ExplorerMenu.SealVerb))
                Assert(key != null && (string)key.GetValue("MultiSelectModel") == "Single", "file verb limits selection to one item");
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(baseKey + @"\Directory\shell\" + ExplorerMenu.OpenVerb + @"\command"))
                Assert(key != null && ((string)key.GetValue(null)).Contains("--open-vault"), "open verb routes to --open-vault");
            ExplorerMenu.Erase(baseKey);
            Assert(!ExplorerMenu.Installed(baseKey), "menu removed");
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(baseKey + @"\Directory\shell")) Assert(key == null || key.SubKeyCount == 0, "menu keys cleaned up");
        }
        finally
        {
            ExplorerMenu.Erase(baseKey);
            Registry.CurrentUser.DeleteSubKeyTree(baseKey, false);
        }
    }
    private static void SealSingleFile(string container)
    {
        string sessions = Path.Combine(container, "sessions");
        string source = Path.Combine(container, "季度 报表.docx");
        File.WriteAllText(source, "fixture-payload", Encoding.UTF8);
        MainForm.SealOutcome outcome = MainForm.SealPath(source, sessions, Password, false);
        Assert(outcome.Root == Path.Combine(container, "季度 报表"), "file becomes a same-named folder without its extension");
        Assert(!File.Exists(source), "plaintext source deleted after sealing");
        Assert(ExplorerMenu.IsVault(outcome.Root), "vault marker written");
        Assert(String.IsNullOrEmpty(outcome.Warning), "clean seal reports no warning");
        using (VaultSession vault = new VaultSession(outcome.Root, sessions, false))
        {
            vault.Unlock(Password);
            Assert(File.ReadAllText(Path.Combine(vault.Work, "季度 报表.docx"), Encoding.UTF8) == "fixture-payload", "sealed file restored on unlock");
            vault.Lock();
        }
    }
    private static void SealFolder(string container)
    {
        string sessions = Path.Combine(container, "sessions");
        string source = Path.Combine(container, "项目资料");
        Directory.CreateDirectory(Path.Combine(source, "子目录"));
        File.WriteAllText(Path.Combine(source, "说明.txt"), "root-file", Encoding.UTF8);
        File.WriteAllText(Path.Combine(source, "子目录", "深层.txt"), "nested-file", Encoding.UTF8);
        MainForm.SealOutcome outcome = MainForm.SealPath(source, sessions, Password, false);
        Assert(outcome.Root == source, "folder is sealed in place at its original path");
        Assert(ExplorerMenu.IsVault(source), "folder became a vault");
        Assert(!File.Exists(Path.Combine(source, "说明.txt")), "original plaintext files removed");
        Assert(Directory.GetDirectories(container, ".项目资料.sealing-*").Length == 0, "parking folder removed after success");
        using (VaultSession vault = new VaultSession(source, sessions, false))
        {
            vault.Unlock(Password);
            Assert(File.ReadAllText(Path.Combine(vault.Work, "说明.txt"), Encoding.UTF8) == "root-file", "top-level file sits at vault root");
            Assert(File.ReadAllText(Path.Combine(vault.Work, "子目录", "深层.txt"), Encoding.UTF8) == "nested-file", "nested file keeps its relative path");
            vault.Lock();
        }
    }
    private static void Guards(string container)
    {
        string sessions = Path.Combine(container, "sessions");
        string vaultRoot = Path.Combine(container, "已有加密");
        using (VaultSession vault = new VaultSession(vaultRoot, sessions, false)) { vault.Create(Password); vault.Lock(); }
        Assert(MainForm.VaultAncestor(Path.Combine(vaultRoot, "任意文件.txt")) == vaultRoot, "paths inside a vault are detected");
        Assert(MainForm.VaultAncestor(container) == null, "plain folder is not inside a vault");
        Fails(delegate { MainForm.SealPath(Path.Combine(container, "不存在.txt"), sessions, Password, false); }, "missing path rejected");
        string first = Path.Combine(container, "重复.docx");
        File.WriteAllText(first, "one", Encoding.UTF8);
        MainForm.SealOutcome one = MainForm.SealPath(first, sessions, Password, false);
        File.WriteAllText(first, "two", Encoding.UTF8);
        MainForm.SealOutcome two = MainForm.SealPath(first, sessions, Password, false);
        Assert(one.Root != two.Root && Directory.Exists(two.Root), "name collision picks a free folder name");
        Assert(one.Root == Path.Combine(container, "重复") && two.Root == Path.Combine(container, "重复 (2)"), "collision suffix increments");
    }
}
