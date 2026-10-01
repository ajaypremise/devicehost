using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

internal static class WindowsProtectRemoval {
  const string Stage=@"C:\ProgramData\WindowsProtectRemoval";
  const string Data=@"C:\ProgramData\WindowsProtect";
  const string Install=@"C:\Program Files\Common Files\DeviceSupport";
  const string Helper=@"C:\Program Files\Common Files\DeviceSupport\WindowsProtect_UserUI.ps1";
  const string BaseUrl="https://devicehost.vercel.app";
  const string Credential="WindowsProtect/LocalWindowsAccount";
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct TestCredential {
    public uint flags,type; public string target,comment; public System.Runtime.InteropServices.ComTypes.FILETIME written;
    public uint size; public IntPtr blob; public uint persist,count; public IntPtr attributes; public string alias,user;
  }
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CredWrite(ref TestCredential credential,uint flags);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CredDelete(string target,uint type,uint flags);
  [DllImport("wtsapi32.dll",SetLastError=true)] static extern bool WTSEnumerateSessions(IntPtr server,int reserved,int version,out IntPtr sessions,out int count);
  [DllImport("wtsapi32.dll",SetLastError=true)] static extern bool WTSQueryUserToken(uint session,out IntPtr token);
  [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr pointer);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  [StructLayout(LayoutKind.Sequential)] struct Session { public int id; public IntPtr station; public int state; }

  static int Main(string[] args){
    if(args.Length==1 && args[0]=="--self-test") return SelfTest();
    if(args.Length!=0 || !new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) return 1;
    bool created;
    using(var mutex=new Mutex(true,@"Global\WindowsProtectRemoval",out created)){
      if(!created) return 0;
      string id="",token="",reason="cleanup_failed";
      try{
        id=File.ReadAllText(Path.Combine(Stage,"request.txt")).Trim();
        if(!Regex.IsMatch(id,"\\A[a-f0-9]{64}\\z")) return 1;
        var encrypted=Convert.FromBase64String(File.ReadAllText(Path.Combine(Stage,"device.token")).Trim());
        token=Encoding.UTF8.GetString(ProtectedData.Unprotect(encrypted,null,DataProtectionScope.LocalMachine));
        // Keep removal durable while offline; authenticate the queued request
        // before changing the machine, and continue after a partially completed retry.
        var validation=Post(token,"{\"removal_id\":\""+id+"\",\"status\":\"pending\",\"reason\":\"cleanup_failed\"}");
        if(validation!=200 && validation!=401) return 1;
        // A 401 is accepted only after the local completion marker exists:
        // it covers a lost response after the server already deleted this record.
        if(validation==401 && (!File.Exists(Path.Combine(Stage,"complete.txt")) || File.ReadAllText(Path.Combine(Stage,"complete.txt")).Trim()!=id)) return 1;
        var supportPaths=ReadSupportPaths();
        reason="waiting_for_user";
        ClearCredentials();
        reason="cleanup_failed";
        StopProtection();
        RemoveHelper();
        DeleteTree(Install);
        DeleteTree(Data);
        Registry.LocalMachine.DeleteSubKeyTree(@"SOFTWARE\WindowsProtect",false);
        Registry.LocalMachine.DeleteSubKeyTree(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WindowsProtect",false);
        reason="support_removal_failed";
        // Remove the approved support agent last. The detached remover uses
        // HTTPS directly, so losing the desktop tunnel cannot interrupt cleanup.
        foreach(var path in supportPaths){
          if(File.Exists(path)) Run(path,"-fulluninstall",90000,true);
        }
        if(ServiceExists("Mesh Agent") || ServiceExists("meshagent") || SupportProcesses(supportPaths)) throw new IOException("Support service is still present.");
        foreach(var path in supportPaths) DeleteTree(Path.GetDirectoryName(path));
        if(ServiceExists("DeviceSupportHost") || Directory.Exists(Install) || Directory.Exists(Data) || HelperProcesses().Count>0) throw new IOException("WindowsProtect cleanup is incomplete.");
        using(var key=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WindowsProtect")) if(key!=null) throw new IOException("Protection settings remain.");
        File.WriteAllText(Path.Combine(Stage,"complete.txt"),id);
        var code=Post(token,"{\"removal_id\":\""+id+"\",\"status\":\"complete\",\"service_removed\":true,\"helper_removed\":true,\"credentials_removed\":true,\"files_removed\":true,\"support_removed\":true}");
        if(code!=200 && code!=401) return 1;
        FinalCleanup(id);
        return 0;
      }catch{
        try{ if(token.Length>0 && id.Length==64) Post(token,"{\"removal_id\":\""+id+"\",\"status\":\"pending\",\"reason\":\""+reason+"\"}"); }catch{}
        return 1;
      }
    }
  }
  internal static int Run(string file,string args,int timeout,bool required){
    using(var process=new Process{StartInfo=new ProcessStartInfo(file,args){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true}}){
      process.Start(); var output=process.StandardOutput.ReadToEndAsync(); var errors=process.StandardError.ReadToEndAsync();
      if(!process.WaitForExit(timeout)){try{process.Kill();}catch{} throw new IOException("Removal operation timed out.");}
      if(required && process.ExitCode!=0) throw new IOException("Removal operation failed.");
      return process.ExitCode;
    }
  }
  static int Post(string token,string body){
    ServicePointManager.SecurityProtocol=SecurityProtocolType.Tls12;
    var request=(HttpWebRequest)WebRequest.Create(BaseUrl+"/api/removal");
    request.Method="POST"; request.ContentType="application/json"; request.Headers.Add("x-device-token",token);
    request.Timeout=15000;request.ReadWriteTimeout=15000;request.AllowAutoRedirect=false;
    var bytes=Encoding.UTF8.GetBytes(body);request.ContentLength=bytes.Length;
    using(var stream=request.GetRequestStream()) stream.Write(bytes,0,bytes.Length);
    try{using(var response=(HttpWebResponse)request.GetResponse()) return (int)response.StatusCode;}
    catch(WebException ex){var response=ex.Response as HttpWebResponse;if(response==null) throw;using(response) return (int)response.StatusCode;}
  }
  static bool ServiceExists(string name){using(var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+name)) return key!=null;}
  static void StopProtection(){
    if(!ServiceExists("DeviceSupportHost")) return;
    Run("sc.exe","config DeviceSupportHost start= disabled",15000,true);
    using(var service=new ServiceController("DeviceSupportHost")){
      if(service.Status!=ServiceControllerStatus.Stopped){service.Stop();service.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(30));}
    }
    Run("sc.exe","delete DeviceSupportHost",15000,true);
    for(int i=0;i<20 && ServiceExists("DeviceSupportHost");i++) Thread.Sleep(500);
    if(ServiceExists("DeviceSupportHost")) throw new IOException("Protection service is still present.");
  }
  static bool DeleteCredential(){
    return CredDelete(Credential,1,0) || Marshal.GetLastWin32Error()==1168;
  }
  static void ClearCredentials(){
    var pending=new HashSet<string>(File.ReadAllLines(Path.Combine(Stage,"owners.txt")));
    using(var current=WindowsIdentity.GetCurrent()) if(pending.Contains(current.User.Value) && DeleteCredential()) pending.Remove(current.User.Value);
    IntPtr sessions;int count;
    if(WTSEnumerateSessions(IntPtr.Zero,0,1,out sessions,out count)){
      try{
        int size=Marshal.SizeOf(typeof(Session));
        for(int i=0;i<count;i++){
          var session=(Session)Marshal.PtrToStructure(IntPtr.Add(sessions,i*size),typeof(Session)); IntPtr token;
          if(!WTSQueryUserToken((uint)session.id,out token)) continue;
          try{
            using(var identity=new WindowsIdentity(token)){
              var sid=identity.User.Value;
              using(var context=identity.Impersonate()) if(DeleteCredential()) pending.Remove(sid);
            }
          }finally{CloseHandle(token);}
        }
      }finally{WTSFreeMemory(sessions);}
    }
    File.WriteAllLines(Path.Combine(Stage,"owners.txt"),new List<string>(pending).ToArray());
    if(pending.Count>0) throw new IOException("Installing user must sign in to clear its stored credential.");
  }
  static List<int> HelperProcesses(){
    var ids=new List<int>();
    using(var query=new ManagementObjectSearcher("SELECT ProcessId,CommandLine FROM Win32_Process WHERE Name='powershell.exe'")){
      foreach(ManagementObject process in query.Get()){
        var command=Convert.ToString(process["CommandLine"]??"");
        if(Regex.IsMatch(command,@"-File\s+""?"+Regex.Escape(Helper)+@"(?:""|\s|$)",RegexOptions.IgnoreCase)) ids.Add(Convert.ToInt32(process["ProcessId"]));
      }
    }
    return ids;
  }
  static void RemoveHelper(){
    using(var key=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",true)) if(key!=null) key.DeleteValue("WindowsProtectUserUI",false);
    foreach(var id in HelperProcesses()){
      try{using(var process=Process.GetProcessById(id)){process.Kill();process.WaitForExit(5000);}}catch(ArgumentException){}
    }
  }
  static bool SupportProcesses(List<string> paths){
    foreach(var name in new[]{"meshagent","meshagent64","MeshAgent"}){
      foreach(var process in Process.GetProcessesByName(name)){
        using(process){if(paths.Count==0) return true;try{foreach(var path in paths) if(process.MainModule.FileName.Equals(path,StringComparison.OrdinalIgnoreCase)) return true;}catch{return true;}}
      }
    }
    return false;
  }
  internal static bool SafeSupportPath(string value){
    if(String.IsNullOrWhiteSpace(value) || value.StartsWith(@"\\") || !Path.IsPathRooted(value)) return false;
    var full=Path.GetFullPath(value);
    if(!Path.GetFileName(full).Equals("MeshAgent.exe",StringComparison.OrdinalIgnoreCase) && !Path.GetFileName(full).Equals("meshagent64.exe",StringComparison.OrdinalIgnoreCase)) return false;
    foreach(var root in new[]{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)}){
      if(String.IsNullOrWhiteSpace(root)) continue;
      foreach(var folder in new[]{"Mesh Agent","MeshAgent"}) if(Path.GetDirectoryName(full).Equals(Path.Combine(root,folder),StringComparison.OrdinalIgnoreCase)) return true;
    }
    return false;
  }
  static List<string> ReadSupportPaths(){
    var file=Path.Combine(Stage,"support.txt");var paths=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    if(File.Exists(file)) foreach(var path in File.ReadAllLines(file)){if(!SafeSupportPath(path)) throw new IOException("Unsupported support installation path.");paths.Add(path);}
    foreach(var name in new[]{"Mesh Agent","meshagent"}){
      using(var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+name)){
        if(key==null) continue;
        var image=Convert.ToString(key.GetValue("ImagePath")??"").Trim();string path="";
        if(image.StartsWith("\"")){var end=image.IndexOf('"',1);if(end>1) path=image.Substring(1,end-1);}
        else {var end=image.IndexOf(".exe",StringComparison.OrdinalIgnoreCase);if(end>=0) path=image.Substring(0,end+4);}
        if(!SafeSupportPath(path)) throw new IOException("Unsupported support installation path.");
        paths.Add(path);
      }
    }
    File.WriteAllLines(file,new List<string>(paths).ToArray());return new List<string>(paths);
  }
  internal static void DeleteTree(string path){
    if(!Directory.Exists(path)) return;
    var directory=new DirectoryInfo(path);
    if((directory.Attributes&FileAttributes.ReparsePoint)!=0){directory.Delete();return;}
    foreach(var item in directory.GetFileSystemInfos()){
      if(item is DirectoryInfo) DeleteTree(item.FullName);
      else {item.Attributes=FileAttributes.Normal;item.Delete();}
    }
    directory.Delete();
  }
  static void FinalCleanup(string id){
    // Fixed paths, hex ID only. The detached script deletes its own temporary
    // file after the remover exits and releases its executable.
    var script=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"Temp","WindowsProtectCleanup-"+id+".cmd");
    File.WriteAllText(script,"@echo off\r\nfor /l %%i in (1,1,30) do (\r\n ping 127.0.0.1 -n 3 >nul\r\n rmdir /s /q \""+Stage+"\" 2>nul\r\n if not exist \""+Stage+"\" goto done\r\n)\r\n:done\r\ndel \"%~f0\"\r\n");
    Process.Start(new ProcessStartInfo("cmd.exe","/d /c \""+script+"\""){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=Path.GetPathRoot(Stage)});
    Run("schtasks.exe","/Delete /TN \"WindowsProtect Removal\" /F",15000,false);
  }
  static int SelfTest(){
    if(SafeSupportPath(@"C:\Users\Public\meshagent.exe") || SafeSupportPath(@"\\server\share\meshagent.exe")) return 1;
    var path=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"Mesh Agent","MeshAgent.exe");
    if(!SafeSupportPath(path)) return 1;
    var fixture=Path.Combine(Path.GetTempPath(),"WindowsProtectRemovalFixture-"+Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(Path.Combine(fixture,"child"));File.WriteAllText(Path.Combine(fixture,"child","test.txt"),"fixture");
    DeleteTree(fixture);if(Directory.Exists(fixture)) return 1;
    var target="WindowsProtect/RemovalFixture/"+Guid.NewGuid().ToString("N");
    var bytes=Encoding.Unicode.GetBytes("Fixture password");var memory=Marshal.AllocCoTaskMem(bytes.Length);
    try{
      Marshal.Copy(bytes,0,memory,bytes.Length);
      var credential=new TestCredential{type=1,target=target,size=(uint)bytes.Length,blob=memory,persist=2,user="Fixture"};
      if(!CredWrite(ref credential,0) || !CredDelete(target,1,0)) return 1;
      if(CredDelete(target,1,0) || Marshal.GetLastWin32Error()!=1168) return 1;
    }finally{CredDelete(target,1,0);Marshal.FreeCoTaskMem(memory);Array.Clear(bytes,0,bytes.Length);}
    bool timedOut=false;
    try{Run("powershell.exe","-NoProfile -NonInteractive -Command Start-Sleep -Seconds 10",200,true);}catch(IOException){timedOut=true;}
    if(!timedOut) return 1;
    Console.WriteLine("Removal self-test: fixed support paths validated; fixture files and Windows credential removed; hung operation bounded; no production services or credentials touched.");
    return 0;
  }
}
