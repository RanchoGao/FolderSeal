// Copyright (c) EurekaGao. UI regression uses generated fixtures only.
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Reflection;
using System.Collections.Generic;
using System.Linq;
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
    private static ToolStripMenuItem M(MainForm form, string name) { return (ToolStripMenuItem)Get(form, name); }
    private static IEnumerable<Control> Walk(Control root)
    {
        foreach (Control child in root.Controls) { yield return child; foreach (Control nested in Walk(child)) yield return nested; }
    }
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
            using (MainForm starting = new MainForm(null, Path.Combine(fixture, "Startup vault")))
                Check(starting.LaunchAction(new[] { "--open-vault", Path.Combine(fixture, "Other vault") }) == "busy", "startup entry blocks another request before first Shown event");
            using (MainForm form = new MainForm(null, null))
            {
                // No Show(): startup discovery never reads or prompts over existing personal sessions.
                Render(form, output, "empty");
                Check(Walk(form).OfType<Button>().Count(x => x.Text.Contains("创建加密文件夹")) == 1 && C(form, "create").Visible, "only sidebar contains a create entry");
                Check(!C(form, "identityBar").Visible && !C(form, "notice").Visible && !C(form, "unlock").Visible, "empty view hides identity and notice cards");
                TableLayoutPanel body = (TableLayoutPanel)C(form, "body");
                Check(body.RowStyles[0].Height == 0 && body.RowStyles[1].Height == 0, "hidden status rows consume no space");
                Check(!M(form, "delete").Enabled && !M(form, "recover").Enabled, "empty view disables management");
                Check(Walk(form).OfType<LinkLabel>().Any(x => x.Text.Contains("使用帮助")), "help remains available in sidebar");
                Check(C(form, "create").Right <= C(form, "create").Parent.ClientSize.Width - C(form, "create").Parent.Padding.Right && C(form, "choose").Right <= C(form, "choose").Parent.ClientSize.Width - C(form, "choose").Parent.Padding.Right, "sidebar actions stay within sidebar padding");
                string requestRoot = Path.Combine(fixture, "Generated vault");
                Check(form.LaunchAction(new string[0]) == "activate", "repeat normal launch only activates");
                Check(form.LaunchAction(new[] { "--open-vault", requestRoot }) == "open", "locked or empty view accepts vault entry");
                Check(form.LaunchAction(new[] { "--move-source", Path.Combine(fixture, "sample.txt") }) == "source", "idle view accepts source request");
                Set(form, "handlingLaunch", true);
                Check(form.LaunchAction(new[] { "--open-vault", requestRoot }) == "busy", "entry password flow blocks another entry request");
                Set(form, "handlingLaunch", false);
                form.Enabled = false;
                Check(form.LaunchAction(new[] { "--open-vault", requestRoot }) == "busy", "disabled modal owner blocks switching");
                form.Enabled = true;
                vault = new VaultSession(Path.Combine(fixture, "Generated vault"), Path.Combine(fixture, "sessions"), false);
                vault.Create("UI-Test-Only-927!");
                File.WriteAllText(Path.Combine(vault.Work, "示例笔记.md"), "Generated UI fixture; no personal data.");
                Set(form, "session", vault); Refresh(form);
                Render(form, output, "unlocked");
                Check(form.LaunchAction(new[] { "--open-vault", vault.Root }) == "existing", "same unlocked vault reuses original workspace");
                Check(form.LaunchAction(new[] { "--open-vault", Path.Combine(fixture, "Other vault") }) == "lock-first", "different vault request preserves unlocked session");
                Check(form.LaunchAction(new[] { "--move-source", Path.Combine(fixture, "sample.txt") }) == "lock-first", "source request cannot replace unlocked session");
                Check(C(form, "show").Bottom <= C(form, "show").Parent.ClientSize.Height && C(form, "importFiles").Bottom <= C(form, "importFiles").Parent.ClientSize.Height, "file toolbar buttons fit without vertical clipping");
                Check(C(form, "show").Enabled && !C(form, "create").Enabled && !C(form, "choose").Enabled, "unlocked view prevents switching and permits editing");
                Check(((ListView)C(form, "files")).Items.Count == 1 && C(form, "files").Visible, "unlocked view lists generated file");
                Check(C(form, "lockButton").Visible && !C(form, "unlock").Visible, "one primary action while unlocked");
                Check(!M(form, "delete").Enabled && !M(form, "entryButton").Enabled && !M(form, "recover").Enabled, "unlocked view prevents destructive management");
                Check(C(form, "more").Visible && M(form, "copyPath").Enabled, "unlocked view retains more menu and copy path");
                Check(C(form, "notice").Visible && !C(form, "noticeTitle").Visible && body.RowStyles[1].Height <= 42, "normal editing uses a compact reminder");
                Set(form, "busy", true); Refresh(form);
                Check(form.LaunchAction(new[] { "--open-vault", vault.Root }) == "busy", "busy work refuses new entry operations");
                Check(!C(form, "lockButton").Enabled && !C(form, "show").Enabled && !C(form, "choose").Enabled, "busy view disables conflicting actions");
                Check(!C(form, "more").Enabled && !M(form, "copyPath").Enabled && !M(form, "delete").Enabled, "busy view disables more menu actions");
                Check(((ListView)C(form, "files")).Items.Count == 0, "busy view removes stale file listing");
                Render(form, output, "busy");
                Set(form, "busy", false); Set(form, "operationFailed", true); Set(form, "lastFailure", "Generated failure example"); Refresh(form);
                Check(C(form, "hint").Text.Contains("Generated failure example") && C(form, "lockButton").Text.Contains("重试"), "failure stays visible with retry action");
                Render(form, output, "failure");
                string longError = String.Join("\r\n", Enumerable.Repeat("Generated long error detail; source files remain intact.", 20));
                Set(form, "lastFailure", longError); Refresh(form); Render(form, output, "long-error");
                TextBox detail = (TextBox)C(form, "hint");
                Check(detail.ReadOnly && detail.Multiline && detail.ScrollBars == ScrollBars.Vertical && detail.Text.Contains(longError), "long failure details remain fully available to scroll and copy");
                Check(C(form, "notice").Visible && body.RowStyles[1].Height <= 120 && C(form, "files").Parent.Height >= 200, "long failure preserves usable file area");
                typeof(VaultSession).GetProperty("CleanupPending").GetSetMethod(true).Invoke(vault, new object[] { true });
                Refresh(form);
                Check(!C(form, "show").Enabled && !C(form, "importFiles").Enabled && !C(form, "importFolder").Enabled, "cleanup pending prevents editing and imports");
                Check(form.LaunchAction(new[] { "--open-vault", vault.Root }) == "lock-first", "cleanup pending cannot reopen workspace through entry");
                Check(C(form, "lockButton").Text == "重试清理并锁定" && !C(form, "count").Visible, "cleanup pending has explicit retry and hides file count");
                Render(form, output, "cleanup");
                typeof(VaultSession).GetProperty("CleanupPending").GetSetMethod(true).Invoke(vault, new object[] { false });
                Set(form, "operationFailed", false); Set(form, "lastFailure", null); vault.Lock(); Refresh(form);
                Check(C(form, "unlock").Visible && !C(form, "lockButton").Visible && C(form, "create").Enabled, "locked view restores unlock and switching");
                Check(!C(form, "files").Visible && !C(form, "count").Visible && ((ListView)C(form, "files")).Items.Count == 0, "locked view removes file names and counts");
                Check(M(form, "delete").Enabled && M(form, "recover").Enabled && M(form, "entryButton").Enabled, "locked view enables authenticated management");
                Check(!C(form, "notice").Visible && body.RowStyles[1].Height == 0, "locked view has no persistent explanation panel");
                Check(C(form, "vaultName").AccessibleDescription == vault.Root, "full folder path remains accessible without a path row");
                ContextMenuStrip menu = (ContextMenuStrip)Get(form, "moreMenu");
                Check(menu.Items.Count == 5 && menu.Items[3] is ToolStripSeparator && M(form, "delete").Text.Contains("删除"), "management menu retains actions and separates deletion");
                Render(form, output, "locked");
                form.Size = form.MinimumSize; Render(form, output, "minimum-size");
                Check(C(form, "unlock").Width > 120 && C(form, "files").Height >= 100, "minimum window retains usable primary action and file area");
                Check(C(form, "more").Right <= C(form, "more").Parent.ClientSize.Width && C(form, "more").Height >= 38, "more control fits minimum window");
                C(form, "vaultName").Text = new string('名', 100); Render(form, output, "long-name");
                Check(((Label)C(form, "vaultName")).AutoEllipsis && C(form, "vaultName").Height <= 30 && C(form, "unlock").Width > 120 && C(form, "more").Right <= C(form, "more").Parent.ClientSize.Width, "single-line long folder name cannot crowd out main actions");
                Set(form, "session", null);
            }
            string source = Path.Combine(fixture, "Generated pending file.txt"); File.WriteAllText(source, "Generated fixture.");
            using (MainForm pending = new MainForm(source, null))
            {
                Render(pending, output, "pending-source");
                Check(C(pending, "notice").Visible && C(pending, "hint").Text.Contains(Path.GetFileName(source)), "pending source request remains visible without a duplicate create button");
                Check(Walk(pending).OfType<Button>().Count(x => x.Text.Contains("创建加密文件夹")) == 1, "pending source still uses only sidebar creation");
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
