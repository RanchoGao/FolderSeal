using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using FolderSeal;
class EntryTests {
 [STAThread] static int Main(string[] args) {
 string test=Path.Combine(args[0],"entry-test-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(test);
 try {
 string root=Path.Combine(test,"中文 空格资料");
 using(var v=new VaultSession(root,Path.Combine(test,"sessions"),false)){v.Create("123456");File.WriteAllText(Path.Combine(v.Work,"sample.txt"),"fixture");v.Lock();}
 byte[] hash=Paths.Hash(Path.Combine(root,VaultSession.DataName));
 string entry=FolderEntry.Create(root,false);
 object shell=Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell"));
 object link=shell.GetType().InvokeMember("CreateShortcut",BindingFlags.InvokeMethod,null,shell,new object[]{entry});
 string target=(string)link.GetType().InvokeMember("TargetPath",BindingFlags.GetProperty,null,link,null);
 string arguments=(string)link.GetType().InvokeMember("Arguments",BindingFlags.GetProperty,null,link,null);
 string icon=(string)link.GetType().InvokeMember("IconLocation",BindingFlags.GetProperty,null,link,null);
 if(target!=Application.ExecutablePath || arguments!="--open-vault \""+root+"\"" || !icon.EndsWith(",3")) throw new Exception("Shortcut routing incorrect");
 Marshal.FinalReleaseComObject(link); Marshal.FinalReleaseComObject(shell);
 if((File.GetAttributes(root)&FileAttributes.Hidden)==0 || !Paths.Equal(hash,Paths.Hash(Path.Combine(root,VaultSession.DataName))))throw new Exception("Data or hidden state incorrect");
 bool refused=false;try{FolderEntry.Create(root,false);}catch(IOException){refused=true;}if(!refused)throw new Exception("Existing shortcut overwritten");
 using(var v=new VaultSession(root,Path.Combine(test,"sessions"),false)){v.Unlock("123456");if(File.ReadAllText(Path.Combine(v.Work,"sample.txt"))!="fixture")throw new Exception("Content mismatch");v.Lock();}
 Console.WriteLine("PASS: shortcut target, quoted Unicode arguments, folder icon, hidden storage, unchanged ciphertext, overwrite refusal, unlock after entry creation");
 Paths.DeleteTree(test); return 0;
 }catch(Exception e){Console.Error.WriteLine(e);return 1;}
 }
}
