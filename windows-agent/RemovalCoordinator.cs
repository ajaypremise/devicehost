using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Microsoft.Win32;

internal static class RemovalCoordinator {
  internal const string Stage=@"C:\ProgramData\WindowsProtectRemoval";
  internal static bool ValidId(string value){ return Regex.IsMatch(value??"","\\A[a-f0-9]{64}\\z"); }
  internal static string RequestId(string response){
    var match=Regex.Match(response??"",@"""removal_request""\s*:\s*""([a-f0-9]{64})""");
    return match.Success?match.Groups[1].Value:"";
  }
  internal static void SecureDirectory(string path){
    bool existed=Directory.Exists(path);
    Directory.CreateDirectory(path);
    var owner=(SecurityIdentifier)Directory.GetAccessControl(path).GetOwner(typeof(SecurityIdentifier));
    if(existed && owner.Value!="S-1-5-18" && owner.Value!="S-1-5-32-544") throw new IOException("Removal directory has an untrusted owner.");
    if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0) throw new IOException("Removal directory must not be a link.");
    foreach(var entry in Directory.GetFileSystemEntries(path)) if((File.GetAttributes(entry)&FileAttributes.ReparsePoint)!=0) throw new IOException("Removal files must not be links.");
    var security=new DirectorySecurity(); security.SetAccessRuleProtection(true,false); security.SetOwner(new SecurityIdentifier("S-1-5-18"));
    security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-5-18"),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
    security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-5-32-544"),FileSystemRights.ReadAndExecute,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
    Directory.SetAccessControl(path,security);
    TamperProtection.SetDirectory(path,true,false);
  }
  internal static bool Start(string id){
    if(!ValidId(id)) return false;
    SecureDirectory(Stage);
    var executable=Path.Combine(Stage,"WindowsProtect_Remove.exe");
    using(var source=Assembly.GetExecutingAssembly().GetManifestResourceStream("WindowsProtect_Remove.exe")){
      if(source==null) throw new IOException("Removal component is missing. Update WindowsProtect.");
      using(var data=new MemoryStream()){
        source.CopyTo(data); var bytes=data.ToArray();
        if(File.Exists(executable)){
          using(var hash=System.Security.Cryptography.SHA256.Create()){
            if(Convert.ToBase64String(hash.ComputeHash(File.ReadAllBytes(executable)))!=Convert.ToBase64String(hash.ComputeHash(bytes))) throw new IOException("Removal component verification failed.");
          }
        }else File.WriteAllBytes(executable,bytes);
      }
    }
    bool existing=File.Exists(Path.Combine(Stage,"request.txt")) && File.ReadAllText(Path.Combine(Stage,"request.txt")).Trim()==id;
    File.Copy(@"C:\ProgramData\WindowsProtect\device.token",Path.Combine(Stage,"device.token"),true);
    File.WriteAllText(Path.Combine(Stage,"request.txt"),id);
    using(var key=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WindowsProtect")){
      var owners=key==null?null:key.GetValue("CredentialOwnerSids") as string[];
      if(owners==null || owners.Length==0) throw new IOException("Credential owner is missing. Update WindowsProtect using its original installing account.");
      if(!existing) File.WriteAllLines(Path.Combine(Stage,"owners.txt"),owners);
    }
    Run("schtasks.exe","/Create /TN \"WindowsProtect Removal\" /SC MINUTE /MO 5 /RU SYSTEM /RL HIGHEST /F /TR \""+executable+"\"",20000);
    Process.Start(new ProcessStartInfo(executable){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=Stage});
    return true;
  }
  static void Run(string file,string args,int timeout){
    using(var process=new Process{StartInfo=new ProcessStartInfo(file,args){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true}}){
      process.Start();var output=process.StandardOutput.ReadToEndAsync();var errors=process.StandardError.ReadToEndAsync();
      if(!process.WaitForExit(timeout)){try{process.Kill();}catch{}throw new IOException("Removal scheduling timed out.");}
      if(process.ExitCode!=0)throw new IOException("Removal scheduling failed.");
    }
  }
}
