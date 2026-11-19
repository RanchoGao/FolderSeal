// Copyright (c) EurekaGao. UI regression uses generated fixtures only.
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Reflection;
using System.Windows.Forms;
using FolderSeal;

internal static class UiTests
{
    private static int checks;
    private static readonly BindingFlags Private = BindingFlags.Instance | BindingFlags.NonPublic;
    private static object Get(object target, string name) { return target.GetType().GetField(name, Private).GetValue(target); }
    private static void Set(object target, string name, object value) { target.GetType().GetField(name, Private).SetValue(target, value); }
    private static void Refresh(MainForm form) { typeof(MainForm).GetMethod("RefreshState", Private).Invoke(form, new object[] { "UI regression" }); }
    private static void Check(bool value, string message) { if (!value) throw new Exception(message); checks++; Console.WriteLine("PASS " + message); }
    private static Control C(MainForm form, string name) { return (Control)Get(form, name); }
    private static void Render(MainForm form, string output, string name)
    {
        // Mark visible for offscreen rendering without firing Form.Shown or scanning user sessions.
        typeof(Control).GetMethod("SetState", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(form, new object[] { 2, true });
        form.CreateControl(); form.PerformLayout();
        using (Bitmap bitmap = new Bitmap(form.Width, form.Height))
        { form.DrawToBitmap(bitmap, new Rectangle(Point.Empty, bitmap.Size)); bitmap.Save(Path.Combine(output, name + ".png"), ImageFormat.Png); }
    }
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length != 1 || !Directory.Exists(args[0])) return 2;
        string parent = Path.GetFullPath(args[0]);
        string fixture = Path.Combine(parent, "generated-ui-" + Guid.NewGuid().ToString("N"));
        string output = Path.Combine(parent, "ui-preview");
        Directory.CreateDirectory(fixture); Directory.CreateDirectory(output);
        VaultSession vault = null;
        bool passed = false;
        try
        {
            Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
            using (MainForm form = new MainForm(null, null))
            {
                // No Show(): startup discovery never reads or prompts over existing personal sessions.
                Render(form, output, "empty");
                Check(C(form, "primaryCreate").Visible && !C(form, "unlock").Visible, "empty view offers create, not a disabled unlock");
                Check(!C(form, "delete").Enabled && !C(form, "recover").Enabled, "empty view disables management");
                vault = new VaultSession(Path.Combine(fixture, "Generated vault"), Path.Combine(fixture, "sessions"), false);
                vault.Create("UI-Test-Only-927!");
                File.WriteAllText(Path.Combine(vault.Work, "示例笔记.md"), "Generated UI fixture; no personal data.");
                Set(form, "session", vault); Refresh(form);
                Render(form, output, "unlocked");
                Check(C(form, "show").Enabled && !C(form, "create").Enabled && !C(form, "choose").Enabled, "unlocked view prevents switching and permits editing");
                Check(((ListView)C(form, "files")).Items.Count == 1 && C(form, "files").Visible, "unlocked view lists generated file");
                Check(C(form, "lockButton").Visible && !C(form, "unlock").Visible, "one primary action while unlocked");
                Check(!C(form, "delete").Enabled && !C(form, "entryButton").Enabled, "unlocked view prevents destructive management");
                Set(form, "busy", true); Refresh(form);
                Check(!C(form, "lockButton").Enabled && !C(form, "show").Enabled && !C(form, "choose").Enabled, "busy view disables conflicting actions");
                Check(((ListView)C(form, "files")).Items.Count == 0, "busy view removes stale file listing");
                Render(form, output, "busy");
                Set(form, "busy", false); Set(form, "operationFailed", true); Set(form, "lastFailure", "Generated failure example"); Refresh(form);
                Check(C(form, "hint").Text.Contains("Generated failure example") && C(form, "lockButton").Text.Contains("重试"), "failure stays visible with retry action");
                Render(form, output, "failure");
                typeof(VaultSession).GetProperty("CleanupPending").GetSetMethod(true).Invoke(vault, new object[] { true });
                Refresh(form);
                Check(!C(form, "show").Enabled && !C(form, "importFiles").Enabled && !C(form, "importFolder").Enabled, "cleanup pending prevents editing and imports");
                Check(C(form, "lockButton").Text == "重试清理并锁定" && !C(form, "count").Visible, "cleanup pending has explicit retry and hides file count");
                Render(form, output, "cleanup");
                typeof(VaultSession).GetProperty("CleanupPending").GetSetMethod(true).Invoke(vault, new object[] { false });
                Set(form, "operationFailed", false); Set(form, "lastFailure", null); vault.Lock(); Refresh(form);
                Check(C(form, "unlock").Visible && !C(form, "lockButton").Visible && C(form, "create").Enabled, "locked view restores unlock and switching");
                Check(!C(form, "files").Visible && !C(form, "count").Visible && ((ListView)C(form, "files")).Items.Count == 0, "locked view removes file names and counts");
                Check(C(form, "delete").Enabled && C(form, "recover").Enabled, "locked view enables authenticated management");
                Render(form, output, "locked");
                form.Size = form.MinimumSize; Render(form, output, "minimum-size");
                Check(C(form, "unlock").Width > 120 && C(form, "files").Height >= 100, "minimum window retains usable primary action and file area");
                Check(C(form, "recover").Bounds.Right <= C(form, "recover").Parent.ClientSize.Width, "recovery control fits minimum window");
                Check(C(form, "delete").Bounds.Right <= C(form, "delete").Parent.ClientSize.Width, "delete control fits minimum window");
                Set(form, "session", null);
            }
            passed = true; Console.WriteLine("SUCCESS " + checks + " UI checks"); return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
        finally
        {
            if (vault != null) vault.Dispose();
            if (passed && Paths.Inside(fixture, parent) && Path.GetFileName(fixture).StartsWith("generated-ui-")) Paths.DeleteTree(fixture);
        }
    }
}
