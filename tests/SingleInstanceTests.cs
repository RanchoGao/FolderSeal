// Copyright (c) EurekaGao. Process tests use unique channels and generated fixtures only.
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FolderSeal;

internal static class SingleInstanceTests
{
    private static int checks;
    private static void Check(bool value, string message)
    {
        if (!value) throw new Exception(message);
        checks++; Console.WriteLine("PASS " + message);
    }
    private static void WaitFor(Func<bool> ready)
    {
        Stopwatch watch = Stopwatch.StartNew();
        while (!ready()) { if (watch.ElapsedMilliseconds > 15000) throw new TimeoutException("Fixture timed out."); Thread.Sleep(20); }
    }
    private static string Q(string value) { return "\"" + value + "\""; }
    private static Process Start(string exe, string args)
    {
        return Process.Start(new ProcessStartInfo(exe, args) { UseShellExecute = false, CreateNoWindow = true });
    }
    private static bool Completed(Process process)
    {
        if (!process.WaitForExit(15000)) throw new TimeoutException("Fixture child did not exit.");
        return process.ExitCode == 0;
    }
    private static int Main(string[] args)
    {
        if (args.Length >= 3 && args[0].StartsWith("--host"))
        {
            using (InstanceGate gate = new InstanceGate(args[2]))
            {
                if (!gate.IsPrimary) return 11;
                File.WriteAllText(Path.Combine(args[1], "claimed"), "claimed");
                if (args[0] == "--host-delay") Thread.Sleep(400);
                gate.Listen(delegate(string[] request)
                {
                    File.AppendAllText(Path.Combine(args[1], "requests"), Convert.ToBase64String(Encoding.UTF8.GetBytes(String.Join("\0", request))) + "\r\n");
                });
                File.WriteAllText(Path.Combine(args[1], "ready"), Process.GetCurrentProcess().Id.ToString());
                WaitFor(delegate { return File.Exists(Path.Combine(args[1], "stop")); });
            }
            return 0;
        }
        if (args.Length >= 3 && args[0] == "--client")
        {
            using (InstanceGate gate = new InstanceGate(args[2]))
            {
                if (gate.IsPrimary) return 12;
                gate.Forward(args.Skip(3).ToArray());
            }
            return 0;
        }
        if (args.Length != 1 || !Directory.Exists(args[0])) return 2;
        string fixture = Path.Combine(Path.GetFullPath(args[0]), "generated-instance-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fixture);
        string key = "FolderSeal.Test." + Guid.NewGuid().ToString("N");
        string exe = Process.GetCurrentProcess().MainModule.FileName;
        Process host = null; Process[] children = new Process[0]; bool passed = false;
        try
        {
            string generatedPath = Path.Combine(fixture, "中文 空格资料");
            Check(InstanceGate.Normalize(new string[0]).Length == 0, "normal launch accepted");
            Check(InstanceGate.Normalize(new[] { "--open-vault", generatedPath })[1] == generatedPath, "Unicode path normalized intact");
            bool refused = false; try { InstanceGate.Normalize(new[] { "--password", "not-a-password" }); } catch (ArgumentException) { refused = true; }
            Check(refused, "unknown launch arguments refused");
            host = Start(exe, "--host-delay " + Q(fixture) + " " + Q(key));
            WaitFor(delegate { return File.Exists(Path.Combine(fixture, "claimed")); });
            using (Process early = Start(exe, "--client " + Q(fixture) + " " + Q(key)))
                Check(Completed(early), "second launch waits for primary startup and exits");
            WaitFor(delegate { return File.Exists(Path.Combine(fixture, "ready")); });
            string copyDirectory = Path.Combine(fixture, "portable-copy"); Directory.CreateDirectory(copyDirectory);
            string copy = Path.Combine(copyDirectory, Path.GetFileName(exe)); File.Copy(exe, copy);
            using (Process client = Start(copy, "--client " + Q(fixture) + " " + Q(key) + " --open-vault " + Q(generatedPath)))
                Check(Completed(client), "different executable copy forwards to same primary");
            using (Process client = Start(exe, "--client " + Q(fixture) + " " + Q(key) + " --move-source " + Q(Path.Combine(fixture, "样例 文件.txt"))))
                Check(Completed(client), "source-file request forwarded");
            children = Enumerable.Range(0, 6).Select(i => Start(exe, "--client " + Q(fixture) + " " + Q(key))).ToArray();
            Check(children.All(Completed), "six rapid repeat launches all forward and exit");
            foreach (Process child in children) child.Dispose(); children = new Process[0];
            string[] requests = File.ReadAllLines(Path.Combine(fixture, "requests")).Select(x => Encoding.UTF8.GetString(Convert.FromBase64String(x))).ToArray();
            Check(requests.Length == 9 && requests.Count(x => x.Length == 0) == 7, "primary receives each launch exactly once");
            Check(requests.Contains("--open-vault\0" + generatedPath), "open-vault flag and quoted path preserved");
            Check(!host.HasExited, "repeat launches leave original process alive");
            using (NamedPipeClientStream bad = new NamedPipeClientStream(".", key + ".Launch", PipeDirection.InOut))
            {
                bad.Connect(5000); byte[] pid = new byte[4]; int read = 0;
                while (read < pid.Length) { int count = bad.Read(pid, read, pid.Length - read); if (count == 0) throw new EndOfStreamException(); read += count; }
                byte[] size = BitConverter.GetBytes(32769); bad.Write(size, 0, size.Length);
            }
            using (Process client = Start(exe, "--client " + Q(fixture) + " " + Q(key)))
                Check(Completed(client), "invalid IPC length rejected without breaking next launch");
            using (NamedPipeClientStream stalled = new NamedPipeClientStream(".", key + ".Launch", PipeDirection.InOut, PipeOptions.Asynchronous))
            {
                stalled.Connect(5000); byte[] pid = new byte[4]; int read = 0;
                while (read < pid.Length) { int count = stalled.Read(pid, read, pid.Length - read); if (count == 0) throw new EndOfStreamException(); read += count; }
                byte[] size = BitConverter.GetBytes(10); stalled.Write(size, 0, size.Length);
                Task<int> pending = stalled.ReadAsync(new byte[1], 0, 1); bool closed = false;
                try { closed = pending.Wait(10000) && pending.Result == 0; }
                catch (AggregateException error) { closed = error.InnerException is IOException; }
                Check(closed, "incomplete launch message times out and releases pipe");
            }
            using (Process client = Start(exe, "--client " + Q(fixture) + " " + Q(key)))
                Check(Completed(client), "normal launch succeeds after incomplete IPC timeout");
            File.WriteAllText(Path.Combine(fixture, "stop"), "stop");
            Check(Completed(host), "normal shutdown releases primary ownership"); host.Dispose(); host = null;
            File.Delete(Path.Combine(fixture, "stop")); File.Delete(Path.Combine(fixture, "ready"));
            host = Start(exe, "--host " + Q(fixture) + " " + Q(key));
            WaitFor(delegate { return File.Exists(Path.Combine(fixture, "ready")); });
            Check(!host.HasExited, "new launch succeeds after normal shutdown");
            host.Kill(); host.WaitForExit(); host.Dispose(); host = null;
            File.Delete(Path.Combine(fixture, "ready"));
            host = Start(exe, "--host " + Q(fixture) + " " + Q(key));
            WaitFor(delegate { return File.Exists(Path.Combine(fixture, "ready")); });
            using (Process client = Start(exe, "--client " + Q(fixture) + " " + Q(key)))
                Check(Completed(client), "abandoned ownership recovers after fixture crash");
            File.WriteAllText(Path.Combine(fixture, "stop"), "stop"); Check(Completed(host), "recovered primary shuts down cleanly");
            passed = true; Console.WriteLine("SUCCESS " + checks + " single-instance checks"); return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
        finally
        {
            foreach (Process child in children) { if (!child.HasExited) { child.Kill(); child.WaitForExit(); } child.Dispose(); }
            if (host != null) { if (!host.HasExited) { host.Kill(); host.WaitForExit(); } host.Dispose(); }
            if (passed && Paths.Inside(fixture, Path.GetFullPath(args[0]))) Directory.Delete(fixture, true);
        }
    }
}
