// Copyright (c) EurekaGao. Entry tests use generated fixtures only.
using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Windows.Forms;
using FolderSeal;
class EntryTests {
 [STAThread] static int Main(string[] args) {
 string test=Path.Combine(args[0],"entry-test-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(test);
 try {
 string root=Path.Combine(test,"中文 空格资料");
 using(var v=new VaultSession(root,Path.Combine(test,"sessions"),false)){v.Create("12345678");File.WriteAllText(Path.Combine(v.Work,"sample.txt"),"fixture");v.Lock();}
 byte[] hash=Paths.Hash(Path.Combine(root,VaultSession.DataName));
 string entry=Task.Run(delegate { return FolderEntry.Create(root,false); }).GetAwaiter().GetResult();
 string target, arguments, icon, description;
 if(!FolderEntry.TryReadShortcut(entry, out target, out arguments, out icon, out description)) throw new Exception("Failed to read created Unicode shortcut");
 if(!String.Equals(target, Application.ExecutablePath, StringComparison.OrdinalIgnoreCase) || arguments!="--open-vault \""+root+"\"" || !String.Equals(icon, Application.ExecutablePath+",0", StringComparison.OrdinalIgnoreCase)) throw new Exception("Shortcut routing or brand icon incorrect: " + icon);
 FileAttributes hidden = FileAttributes.Hidden | FileAttributes.System;
 if((File.GetAttributes(root)&hidden)!=hidden || !Paths.Equal(hash,Paths.Hash(Path.Combine(root,VaultSession.DataName))))throw new Exception("Data or hidden state incorrect");
 using (var v = new VaultSession(root, Path.Combine(test, "sessions"), false))
 {
     FolderEntry.Remove(root);
     if (File.Exists(entry)) throw new Exception("Owned entry was not removed");
     File.SetAttributes(root, File.GetAttributes(root) & ~hidden);
     File.WriteAllText(entry, "unrelated");
     bool refused = false;
     try { FolderEntry.Create(root, false); } catch (IOException) { refused = true; }
     if (!refused || File.ReadAllText(entry) != "unrelated" || (File.GetAttributes(root) & hidden) != 0)
         throw new Exception("Collision changed the existing item or hid the vault");
     FolderEntry.Remove(root);
     if (!File.Exists(entry)) throw new Exception("Unrelated entry was removed");
     File.Delete(entry);
     bool wrongPassword = false;
     try { v.RepairEntry("654321"); } catch (CryptographicException) { wrongPassword = true; }
     if (!wrongPassword || File.Exists(entry) || v.Open) throw new Exception("Invalid password repaired entry");
     if (v.RepairEntry("12345678") != entry || v.RepairEntry("12345678") != entry || !Paths.Equal(hash, Paths.Hash(v.Data)))
         throw new Exception("Repair failed to create or update entry without changing ciphertext");
     wrongPassword = false;
     try { v.HideEntry("654321"); } catch (CryptographicException) { wrongPassword = true; }
     if (!wrongPassword || !File.Exists(entry) || v.Open) throw new Exception("Invalid password hid entry");
     v.HideEntry("12345678");
     if (File.Exists(entry) || (File.GetAttributes(root) & hidden) != hidden || !Paths.Equal(hash, Paths.Hash(v.Data)))
         throw new Exception("HideEntry failed to remove shortcut and keep vault hidden");
     if (v.RepairEntry("12345678") != entry || !File.Exists(entry))
         throw new Exception("RepairEntry failed to restore shortcut after HideEntry");
     wrongPassword = false;
     try { v.Unlock("654321"); } catch (CryptographicException) { wrongPassword = true; }
     if (!wrongPassword || v.Open || (v.Work != null && Directory.Exists(v.Work))) throw new Exception("Invalid password unlocked vault");
     v.Unlock("12345678");
     if (File.ReadAllText(Path.Combine(v.Work, "sample.txt")) != "fixture") throw new Exception("Content mismatch");
     v.Lock();
     if (v.Open || !File.Exists(entry)) throw new Exception("Locking removed the entry or left the vault unlocked");
     v.Delete("12345678");
     FolderEntry.Remove(root);
     if (Directory.Exists(root) || File.Exists(entry)) throw new Exception("Authenticated deletion left the vault or entry");
 }
 Console.WriteLine("PASS: branded shortcut, hidden vault, conflict preservation, password-gated repair and unlock, relock and shortcut removal");
 Paths.DeleteTree(test); return 0;
 }catch(Exception e){Console.Error.WriteLine(e);return 1;}
 }
}
