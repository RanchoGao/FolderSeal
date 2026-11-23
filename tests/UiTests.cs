// Copyright (c) EurekaGao. UI regression uses generated fixtures only.
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Reflection;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using FolderSeal;

internal static class UiTests
{
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern int GetWindowLong(IntPtr window, int index);
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);
    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalAlloc(uint uFlags, UIntPtr dwBytes);
    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalLock(IntPtr hMem);
    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalUnlock(IntPtr hMem);
    private static IntPtr CreateHDrop(params string[] paths)
    {
        byte[] text = System.Text.Encoding.Unicode.GetBytes(String.Join("\0", paths) + "\0\0");
        int headerSize = 20;
        IntPtr hGlobal = GlobalAlloc(0x0042, (UIntPtr)(headerSize + text.Length));
        IntPtr ptr = GlobalLock(hGlobal);
        try
        {
            System.Runtime.InteropServices.Marshal.WriteInt32(ptr, 0, headerSize);
            System.Runtime.InteropServices.Marshal.WriteInt32(ptr, 16, 1);
            System.Runtime.InteropServices.Marshal.Copy(text, 0, IntPtr.Add(ptr, headerSize), text.Length);
        }
        finally { GlobalUnlock(hGlobal); }
        return hGlobal;
    }
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
    private static void Render(Form form, string output, string name)
    {
        // Mark visible for offscreen rendering without firing Form.Shown or scanning user sessions.
        typeof(Control).GetMethod("SetState", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(form, new object[] { 2, true });
        form.CreateControl(); form.PerformLayout();
        using (Bitmap bitmap = new Bitmap(form.Width, form.Height))
        { form.DrawToBitmap(bitmap, new Rectangle(Point.Empty, bitmap.Size)); bitmap.Save(Path.Combine(output, name + ".png"), ImageFormat.Png); }
    }
    private static async Task<int> DrivePassword(MainForm owner, Func<Task> action, bool cancel)
    {
        int prompts = 0; PasswordDialog handled = null;
        using (Timer timer = new Timer { Interval = 100 })
        {
            timer.Tick += delegate
            {
                PasswordDialog password = owner.OwnedForms.OfType<PasswordDialog>().FirstOrDefault(x => x.Visible);
                if (password != null && password != handled)
                {
                    handled = password; prompts++;
                    if (cancel) ((Button)password.CancelButton).PerformClick();
                    else { ((TextBox)Get(password, "first")).Text = "UI-Test-Only-927!"; ((Button)password.AcceptButton).PerformClick(); }
                }
                VaultLibraryForm library = owner.OwnedForms.OfType<VaultLibraryForm>().FirstOrDefault(x => x.Visible);
                if (library != null) { library.DialogResult = DialogResult.Cancel; library.Close(); }
            };
            timer.Start(); await action(); return prompts;
        }
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
                Check(!form.AllowDrop && Walk(form).All(c => !c.AllowDrop), "no control uses OLE AllowDrop so UIPI WM_DROPFILES works when elevated");
                Check(form.CanAcceptFileDrop() && Native.IsFileDropEnabled(form.Handle), "homepage enables WM_DROPFILES drag-and-drop");
                Check(form.Text == "密封夹" && Walk(form).OfType<Label>().Any(x => x.Text == "密封夹"), "Chinese window and sidebar show the product name");
                Check(C(form, "updateLink").Text == "检测升级" && C(form, "updateLink").Visible && C(form, "updateLink").Enabled, "update check entry is available in sidebar");
                Set(form, "updateLookup", new Func<Task<UpdateInfo>>(delegate { return Task.FromResult(new UpdateInfo { Version = new Version(2, 6, 0, 0), Prerelease = true }); }));
                ((Task)typeof(MainForm).GetMethod("CheckForUpdates", Private).Invoke(form, new object[] { false })).GetAwaiter().GetResult();
                Check(C(form, "updateLink").Text == "发现新版 2.6.0" && C(form, "updateLink").Enabled, "background update shows version link without a modal dialog");
                Set(form, "updateLookup", new Func<Task<UpdateInfo>>(delegate { return Task.FromResult<UpdateInfo>(null); }));
                ((Task)typeof(MainForm).GetMethod("CheckForUpdates", Private).Invoke(form, new object[] { false })).GetAwaiter().GetResult();
                Check(C(form, "updateLink").Text == "检测升级" && Get(form, "availableUpdate") == null, "no update restores the normal entry without disturbing work");
                Set(form, "updateLookup", new Func<Task<UpdateInfo>>(delegate { throw new IOException("Generated network failure"); }));
                ((Task)typeof(MainForm).GetMethod("CheckForUpdates", Private).Invoke(form, new object[] { false })).GetAwaiter().GetResult();
                Check(C(form, "updateLink").Enabled && C(form, "updateLink").Text == "检测升级" && !(bool)Get(form, "checkingUpdate"), "startup network failure silently permits retry");
                Check(Walk(form).OfType<Button>().Count(x => x.Text.Contains("创建加密文件夹")) == 1 && C(form, "create").Visible, "only sidebar contains a create entry");
                Check(!C(form, "identityBar").Visible && !C(form, "notice").Visible && !C(form, "unlock").Visible, "empty view hides identity and notice cards");
                TableLayoutPanel body = (TableLayoutPanel)C(form, "body");
                Check(body.RowStyles[0].Height == 0 && body.RowStyles[1].Height == 0, "hidden status rows consume no space");
                Check(!M(form, "delete").Enabled && !M(form, "recover").Enabled, "empty view disables management");
                Check(Walk(form).OfType<LinkLabel>().Any(x => x.Text.Contains("使用帮助")), "help remains available in sidebar");
                TableLayoutPanel sidebar = (TableLayoutPanel)C(form, "sidebar");
                Check(sidebar.Controls.OfType<Button>().SequenceEqual(new[] { C(form, "create"), C(form, "library") }) && C(form, "library").Visible, "sidebar offers only create and library buttons");
                Check(sidebar.Controls.OfType<Button>().All(button => button.Right <= sidebar.ClientSize.Width - sidebar.Padding.Right), "sidebar actions stay within sidebar padding");
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
                Check(form.CanAcceptFileDrop() && Native.IsFileDropEnabled(form.Handle), "unlocked view enables WM_DROPFILES drag-and-drop");
                string dropFixture = Path.Combine(fixture, "拖入测试.txt");
                File.WriteAllText(dropFixture, "wm-dropfiles-fixture");
                IntPtr hDrop = CreateHDrop(dropFixture);
                SendMessage(form.Handle, Native.WM_DROPFILES, hDrop, IntPtr.Zero);
                for (int i = 0; i < 40 && !File.Exists(Path.Combine(vault.Work, "拖入测试.txt")); i++) { Application.DoEvents(); System.Threading.Thread.Sleep(25); }
                Check(File.Exists(Path.Combine(vault.Work, "拖入测试.txt")) && vault.PendingSourceDeleteCount == 1, "WM_DROPFILES imports dropped Unicode file and tracks original for deletion on lock");
                File.Delete(Path.Combine(vault.Work, "拖入测试.txt"));
                Refresh(form);
                Render(form, output, "unlocked");
                ListView styledFiles = (ListView)C(form, "files");
                Check(styledFiles.Items[0].ImageIndex >= 0 && styledFiles.Items[0].ToolTipText == styledFiles.Items[0].Text, "file type marker and full relative name are available");
                Check(C(form, "notice").BackColor == UiTheme.AmberBg && C(form, "hint").Text.Contains("双击"), "normal editing uses warm amber plaintext guidance");
                Check(C(form, "pathLink").Visible && C(form, "pathLink").Text.Contains(vault.Root), "full folder path is shown and clickable in header");
                TextBox filterBox = (TextBox)C(form, "fileFilter");
                filterBox.Text = "示例";
                Check(styledFiles.Items.Count == 1, "file filter matches unlocked workspace files");
                filterBox.Text = "no-match-xyz";
                Check(styledFiles.Items.Count == 0 && !styledFiles.Visible, "unmatched file filter shows clear empty feedback");
                filterBox.Clear();
                Check(styledFiles.Items.Count == 1 && styledFiles.Visible, "clearing file filter restores full file list");
                typeof(MainForm).GetMethod("RefreshState", Private).Invoke(form, new object[] { "已解锁 · 使用结束后请保存并锁定" });
                Check(C(form, "status").Text == "", "unlock does not duplicate persistent guidance");
                File.WriteAllText(Path.Combine(vault.Work, "additional.txt"), "Generated icon fixture");
                File.WriteAllText(Path.Combine(vault.Work, "no-extension"), "Generated icon fixture");
                Refresh(form); Render(form, output, "multiple-types");
                Check(styledFiles.Items.Count == 3 && styledFiles.SmallImageList.Handle != IntPtr.Zero, "multiple image types render after source bitmap disposal");
                File.Delete(Path.Combine(vault.Work, "additional.txt")); File.Delete(Path.Combine(vault.Work, "no-extension"));
                Refresh(form);
                Size originalSize = form.Size;
                form.Size = form.MinimumSize; Render(form, output, "unlocked-minimum");
                Check(C(form, "show").Right <= C(form, "show").Parent.ClientSize.Width && C(form, "importFiles").Left >= 0, "minimum window keeps editing actions inside toolbar");
                form.Size = originalSize;
                Check(form.LaunchAction(new[] { "--open-vault", vault.Root }) == "existing", "same unlocked vault reuses original workspace");
                Check(form.LaunchAction(new[] { "--open-vault", Path.Combine(fixture, "Other vault") }) == "lock-first", "different vault request preserves unlocked session");
                Check(form.LaunchAction(new[] { "--move-source", Path.Combine(fixture, "sample.txt") }) == "lock-first", "source request cannot replace unlocked session");
                Check(C(form, "show").Bottom <= C(form, "show").Parent.ClientSize.Height && C(form, "importFiles").Bottom <= C(form, "importFiles").Parent.ClientSize.Height, "file toolbar buttons fit without vertical clipping");
                Check(C(form, "show").Enabled && !C(form, "create").Enabled && !C(form, "library").Enabled, "unlocked view prevents switching and permits editing");
                Check(((ListView)C(form, "files")).Items.Count == 1 && C(form, "files").Visible, "unlocked view lists generated file");
                ((ListView)C(form, "files")).Items[0].Selected = true;
                Check(form.SelectedFileToOpen() == Path.Combine(vault.Work, "示例笔记.md"), "file activation resolves selected Unicode file inside editing workspace");
                Check(C(form, "lockButton").Visible && !C(form, "unlock").Visible, "one primary action while unlocked");
                Check(!M(form, "delete").Enabled && !M(form, "recover").Enabled, "unlocked view prevents destructive management");
                Check(C(form, "more").Visible && C(form, "more").Enabled, "unlocked view permits opening management menu");
                Check(!M(form, "recover").Enabled && !M(form, "delete").Enabled && M(form, "recover").Text.Contains("需先保存并锁定") && M(form, "delete").Text.Contains("需先保存并锁定"), "unlocked menu explains disabled actions");
                using (Form help = form.CreateHelpDialog())
                {
                    Render(help, output, "help-default");
                    RichTextBox helpText = Walk(help).OfType<RichTextBox>().Single();
                    Check(helpText.ReadOnly && helpText.WordWrap && helpText.ScrollBars == RichTextBoxScrollBars.Vertical, "help uses automatic vertical scrolling and wrapped read-only text");
                    help.ClientSize = new Size(850, 900); Render(help, output, "help-large");
                    Check((GetWindowLong(helpText.Handle, -16) & 0x200000) == 0, "help hides vertical scrollbar when content fits");
                    help.Size = help.MinimumSize; Render(help, output, "help-small");
                    Check((GetWindowLong(helpText.Handle, -16) & 0x200000) != 0, "help shows vertical scrollbar when content overflows");
                    helpText.SelectionStart = helpText.TextLength; helpText.ScrollToCaret(); Render(help, output, "help-scrolled");
                }
                Check(C(form, "notice").Visible && !C(form, "noticeTitle").Visible && body.RowStyles[1].Height <= 52 && C(form, "hint").Text.Contains("同一 Windows 账户可访问"), "normal editing uses a compact reminder about plaintext");
                Set(form, "busy", true); Refresh(form);
                Check(!form.CanAcceptFileDrop() && !Native.IsFileDropEnabled(form.Handle), "busy state disables WM_DROPFILES drag-and-drop");
                Check(form.SelectedFileToOpen() == null, "processing state cannot open a file");
                Check(form.LaunchAction(new[] { "--open-vault", vault.Root }) == "busy", "busy work refuses new entry operations");
                Check(!C(form, "lockButton").Enabled && !C(form, "show").Enabled && !C(form, "library").Enabled, "busy view disables conflicting actions");
                Check(!C(form, "more").Enabled && !M(form, "recover").Enabled && !M(form, "delete").Enabled, "busy view disables more menu actions");
                Check(((ListView)C(form, "files")).Items.Count == 0, "busy view removes stale file listing");
                Check(((TextBox)C(form, "hint")).ScrollBars == ScrollBars.None, "short busy notice shows no scrollbar");
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
                Check(!form.CanAcceptFileDrop() && !Native.IsFileDropEnabled(form.Handle), "cleanup pending disables WM_DROPFILES drag-and-drop");
                Check(form.LaunchAction(new[] { "--open-vault", vault.Root }) == "lock-first", "cleanup pending cannot reopen workspace through entry");
                Check(C(form, "lockButton").Text == "重试清理并锁定" && !C(form, "count").Visible, "cleanup pending has explicit retry and hides file count");
                Render(form, output, "cleanup");
                typeof(VaultSession).GetProperty("CleanupPending").GetSetMethod(true).Invoke(vault, new object[] { false });
                Set(form, "operationFailed", false); Set(form, "lastFailure", null); vault.Lock(); Refresh(form);
                Check(!form.CanAcceptFileDrop() && !Native.IsFileDropEnabled(form.Handle), "locked view disables WM_DROPFILES drag-and-drop");
                Check(C(form, "unlock").Visible && !C(form, "lockButton").Visible && C(form, "create").Enabled, "locked view restores unlock and switching");
                Check(!C(form, "files").Visible && !C(form, "count").Visible && ((ListView)C(form, "files")).Items.Count == 0, "locked view removes file names and counts");
                Check(M(form, "delete").Enabled && M(form, "recover").Enabled, "locked view enables authenticated management");
                Check(!C(form, "notice").Visible && body.RowStyles[1].Height == 0, "locked view has no persistent explanation panel");
                Check(form.SelectedFileToOpen() == null, "locked state cannot open a file");
                Check(C(form, "vaultName").AccessibleDescription == vault.Root, "full folder path remains accessible without a path row");
                ContextMenuStrip menu = (ContextMenuStrip)Get(form, "moreMenu");
                Check(menu.Items.Count == 6 && menu.Items[0] == M(form, "recover") && menu.Items[1] == M(form, "repairEntry") && M(form, "repairEntry").Enabled && menu.Items[2] == M(form, "hideEntry") && M(form, "hideEntry").Enabled && menu.Items[3] == M(form, "explorerMenu") && menu.Items[4] is ToolStripSeparator && menu.Items[5] == M(form, "delete"), "locked vault offers password-gated shortcut repair and hide");
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
            VaultCatalog catalog = new VaultCatalog(Path.Combine(fixture, "settings", "catalog.egcatalog"), true);
            catalog.Add(Path.Combine(fixture, "Missing location"), false);
            catalog.Add(requestFixture(fixture), true, DateTime.UtcNow.Ticks); catalog.Scanned = true; catalog.Summary = "上次扫描已取消，已记住位置；可重新扫描";
            using (VaultLibraryForm library = new VaultLibraryForm(catalog, "UI-Test-Only-927!"))
            {
                library.RefreshRows(); Render(library, output, "library");
                ListView list = (ListView)Get(library, "list"); TextBox search = (TextBox)Get(library, "search");
                Check(list.Items.Count == 2 && list.Items.Cast<ListViewItem>().Any(x => x.SubItems[2].Text == "位置不可用"), "library retains unavailable locations");
                Check((string)list.Items[0].Tag == requestFixture(fixture), "recently opened folder precedes never opened locations");
                search.Text = "missing"; Check(list.Items.Count == 1, "library search matches paths case insensitively");
                list.Items[0].Selected = true;
                Check(!((Button)Get(library, "open")).Enabled && ((Button)Get(library, "path")).Enabled, "unavailable location can be inspected but not opened");
                Button openByPath = (Button)Get(library, "openByPath");
                Check(openByPath.Enabled && openByPath.Text == "按路径打开", "library supports direct opening without an available list selection");
                search.Text = "no-generated-match"; Check(list.Items.Count == 0 && ((Label)Get(library, "info")).Text.Contains("未找到匹配项"), "no search match has a distinct message");
                search.Text = ""; library.Size = library.MinimumSize; Render(library, output, "library-minimum");
                Check(list.Height > 100 && openByPath.Parent.Controls.OfType<Button>().All(button => button.Right <= openByPath.Parent.ClientSize.Width && button.Bottom <= openByPath.Parent.ClientSize.Height), "library minimum size retains list and all actions");
                Check(list.Columns.Cast<ColumnHeader>().Sum(x => x.Width) <= list.ClientSize.Width, "all library status columns fit minimum width");
            }
            using (VaultLibraryForm library = new VaultLibraryForm(catalog, "UI-Test-Only-927!"))
            using (Timer timer = new Timer { Interval = 150 })
            {
                timer.Tick += delegate
                {
                    timer.Stop();
                    Check(Get(library, "scanning") == null, "cached library does not start a disk scan on show");
                    ListView list = (ListView)Get(library, "list");
                    list.Items.Cast<ListViewItem>().Single(x => x.SubItems[2].Text == "已统一密码").Selected = true;
                    typeof(Control).GetMethod("OnKeyDown", Private).Invoke(list, new object[] { new KeyEventArgs(Keys.Enter) });
                    if (library.DialogResult != DialogResult.OK) library.Close();
                };
                timer.Start(); Check(library.ShowDialog() == DialogResult.OK && library.SelectedRoot != null, "Enter opens the selected available location without another password prompt");
            }
            using (VaultPathDialog dialog = new VaultPathDialog())
            {
                string unrecorded = Path.Combine(fixture, "未收录的样例 vault");
                Directory.CreateDirectory(unrecorded);
                SecretRecord.Write(Path.Combine(unrecorded, VaultSession.DataName), new byte[] { 1, 2, 3 }, "UI-Test-Only-927!");
                dialog.Shown += delegate
                {
                    TextBox input = (TextBox)Get(dialog, "input");
                    Check(dialog.ActiveControl == input, "path dialog is ready for keyboard paste");
                    Render(dialog, output, "open-by-path");
                    input.Text = fixture;
                    dialog.AcceptButton.PerformClick();
                    Check(dialog.DialogResult == DialogResult.None && input.Text == fixture && ((Label)Get(dialog, "feedback")).Text.Contains("内容.egvault"), "invalid directory keeps the dialog and input available for correction");
                    input.Text = "\"" + unrecorded + "\"";
                    dialog.AcceptButton.PerformClick();
                };
                Check(dialog.ShowDialog() == DialogResult.OK && dialog.SelectedRoot == unrecorded, "quoted Unicode paths can open a folder without a catalog entry");
            }
            using (NameDialog name = new NameDialog())
                Check(name.CancelButton != null && ((Button)name.CancelButton).DialogResult == DialogResult.Cancel, "name dialog offers explicit keyboard cancellation");
            Check(!PasswordDialog.HasMinimumLength(new string('a', 14)) && PasswordDialog.HasMinimumLength(new string('a', 15)), "first password setup requires 15 characters");
            Check(!PasswordDialog.HasMinimumLength(String.Concat(Enumerable.Repeat("🔒", 14))) && PasswordDialog.HasMinimumLength(String.Concat(Enumerable.Repeat("🔒", 15))), "surrogate pairs count as one password character");
            using (PasswordDialog deletePassword = new PasswordDialog(false, "删除前再次验证密码", requestFixture(fixture)))
                Check(Walk(deletePassword).OfType<TextBox>().Any(x => x.ReadOnly && x.Text == requestFixture(fixture)), "deletion verification shows full target path");
            using (PasswordDialog password = new PasswordDialog(false, "输入密码"))
            {
                Render(password, output, "password");
                Check(Walk(password).OfType<Label>().Any(x => x.Text == "输入密码"), "password prompt uses correct wording");
                Check(Walk(password).OfType<Button>().Any(x => x.Text == "显示"), "password prompt offers visibility toggle");
            }
            using (PasswordDialog firstSetup = new PasswordDialog(true, "设置密码"))
            {
                Render(firstSetup, output, "password-create");
                Check(Walk(firstSetup).OfType<Label>().Any(x => x.Text.Contains("0 / 15")), "first setup shows live character progress");
            }
            using (CreateVaultDialog createDialog = new CreateVaultDialog(fixture, null, true))
            {
                Render(createDialog, output, "create-vault");
                Check(createDialog.KeepOpen && createDialog.HideEntry, "merged create dialog defaults to keeping the new vault unlocked and honors default hide-entry setting");
                Check(createDialog.CancelButton != null && ((Button)createDialog.CancelButton).DialogResult == DialogResult.Cancel, "merged create dialog supports keyboard cancellation");
            }
            using (LockConfirmDialog lockDialog = new LockConfirmDialog("保存并锁定", "请先保存并关闭正在编辑的文件", "确认后将生成新密文并清理明文。", "确认保存并锁定"))
            {
                Render(lockDialog, output, "lock-confirm");
                Check(lockDialog.AcceptButton != null && lockDialog.CancelButton != null, "branded lock confirm dialog provides explicit confirm and cancel");
            }
            using (AppDialog infoDialog = new AppDialog("操作未完成", "编辑区中已有同名文件：示例.txt\r\n明文工作区仍保留。", MessageBoxButtons.OK, AppDialogTone.Warning, false))
            {
                Render(infoDialog, output, "app-dialog-warning");
                Check(infoDialog.AcceptButton != null && infoDialog.CancelButton != null && Walk(infoDialog).OfType<TextBox>().Any(x => x.ReadOnly && x.Text.Contains("示例.txt")), "unified branded dialog renders warning with selectable copyable text");
            }
            using (AppDialog dangerDialog = new AppDialog("删除加密文件夹", "将永久删除以下加密文件夹，此操作不进入回收站。", MessageBoxButtons.YesNo, AppDialogTone.Danger, true))
            {
                Render(dangerDialog, output, "app-dialog-danger");
                Check(dangerDialog.AcceptButton == dangerDialog.CancelButton && dangerDialog.CancelButton != null, "danger confirm dialog defaults keyboard Enter to cancel");
            }
            using (SettingsDialog settingsDialog = new SettingsDialog(delegate { return true; }, delegate { }, delegate { return true; }, delegate { }))
            {
                Render(settingsDialog, output, "settings");
                Check(Walk(settingsDialog).OfType<Label>().Any(x => x.Text.Contains("已启用")) && Walk(settingsDialog).OfType<Label>().Any(x => x.Text.Contains("已开启")), "global settings dialog exposes Explorer menu and hide-entry status");
            }
            string state = Path.Combine(fixture, "startup-state");
            VaultCatalog startup = new VaultCatalog(Path.Combine(state, "catalog.egcatalog")); startup.Scanned = true; startup.Save("UI-Test-Only-927!");
            Exception authenticationFailure = null;
            using (MainForm authenticated = new MainForm(null, null, state))
            {
                authenticated.Shown += async delegate
                {
                    try
                    {
                        Check(!Application.OpenForms.OfType<PasswordDialog>().Any() && !Application.OpenForms.OfType<VaultLibraryForm>().Any(), "normal startup shows homepage without password or library");
                        Check(Get(authenticated, "masterPassword") == null && !((VaultCatalog)Get(authenticated, "catalog")).Scanned, "startup does not decrypt catalog or begin scanning");
                        Render(authenticated, output, "startup-homepage");
                        Func<Task> library = delegate { return (Task)typeof(MainForm).GetMethod("ShowLibrary", Private).Invoke(authenticated, null); };
                        Check(await DrivePassword(authenticated, library, true) == 1, "viewing library requires password and supports cancellation");
                        Check(!authenticated.IsDisposed && Get(authenticated, "masterPassword") == null, "cancelling library authentication keeps homepage without authorization");
                        Check(await DrivePassword(authenticated, library, false) == 1, "library accepts one password before displaying list");
                        VaultCatalog loaded = (VaultCatalog)Get(authenticated, "catalog");
                        Check(Get(authenticated, "masterPassword") == null && loaded.Locations.Count == 0 && !loaded.Scanned, "leaving the library releases the password and plaintext catalog");
                        Set(authenticated, "masterPassword", "UI-Test-Only-927!");
                        Task<bool> listOpen = (Task<bool>)typeof(MainForm).GetMethod("EnsureOpenPassword", Private).Invoke(authenticated, new object[] { true });
                        Check(listOpen.IsCompleted && await listOpen, "opening from verified list reuses authorization without a password dialog");
                        typeof(MainForm).GetMethod("ReleaseAuthorization", Private).Invoke(authenticated, null);
                        Check(await DrivePassword(authenticated, library, true) == 1, "reopening the library in the same process always requires a password");
                        Check(await DrivePassword(authenticated, delegate { return (Task)typeof(MainForm).GetMethod("EnsureOpenPassword", Private).Invoke(authenticated, new object[] { false }); }, true) == 1, "opening outside the library requires password even after list verification");
                        Check(await DrivePassword(authenticated, delegate { ((Button)Get(authenticated, "create")).PerformClick(); return Task.CompletedTask; }, true) == 1, "creation requires password even after list verification");
                        Check(await DrivePassword(authenticated, delegate { return authenticated.HandleLaunch(new[] { "--open-vault", Path.Combine(fixture, "External vault") }); }, true) == 1, "forwarded Explorer entry requires password after list verification");
                        Check(Get(authenticated, "session") == null && Get(authenticated, "masterPassword") == null, "cancelled independent operations leave no authorization and do not open a vault");
                        using (VaultSession existing = new VaultSession(Path.Combine(fixture, "Existing entry vault"), Path.Combine(fixture, "entry-sessions"), false))
                        {
                            await Task.Run(delegate { existing.Create("UI-Test-Only-927!"); });
                            Set(authenticated, "session", existing);
                            try
                            {
                                Check(await DrivePassword(authenticated, delegate { return authenticated.HandleLaunch(new[] { "--open-vault", existing.Root }); }, true) == 1, "Explorer entry to an already unlocked vault still requires password");
                                Check(existing.Open, "cancelling Explorer reauthentication preserves existing editing session");
                            }
                            finally { Set(authenticated, "session", null); existing.Lock(); }
                        }
                        Set(authenticated, "masterPassword", "UI-Test-Only-927!");
                        Check(await DrivePassword(authenticated, library, true) == 1 && Get(authenticated, "masterPassword") == null, "an unrelated operation's password cannot authorize the library");
                    }
                    catch (Exception error) { authenticationFailure = error; }
                    finally { authenticated.Close(); }
                };
                authenticated.ShowDialog();
            }
            if (authenticationFailure != null) throw authenticationFailure;
            using (MainForm external = new MainForm(null, Path.Combine(fixture, "External vault"), state))
            using (Timer timer = new Timer { Interval = 100 })
            {
                int prompts = 0; PasswordDialog handled = null;
                timer.Tick += delegate
                {
                    PasswordDialog password = external.OwnedForms.OfType<PasswordDialog>().FirstOrDefault(x => x.Visible);
                    if (password != null && password != handled) { handled = password; prompts++; ((Button)password.CancelButton).PerformClick(); }
                    else if (prompts > 0) { timer.Stop(); Check(!external.IsDisposed && Get(external, "session") == null, "cancelling initial Explorer password returns to homepage"); external.Close(); }
                };
                timer.Start(); external.ShowDialog(); Check(prompts == 1, "initial Explorer entry requests one password");
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
    private static string requestFixture(string fixture)
    {
        string path = Path.Combine(fixture, "Recorded vault"); Directory.CreateDirectory(path);
        File.WriteAllText(Path.Combine(path, VaultSession.DataName), "UI state fixture only"); return path;
    }
}
