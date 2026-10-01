using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32;

// Managed, visible installation. These ACLs resist normal removal operations;
// an administrator with ownership/restore privileges can override them.
internal static class TamperProtection {
  internal const string Install=@"C:\Program Files\Common Files\DeviceSupport";
  internal const string Data=@"C:\ProgramData\WindowsProtect";
  internal const string ProductKey=@"SOFTWARE\WindowsProtect";
  internal const string ProductEntry=@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WindowsProtect";
  internal const string LockedService="O:SYG:SYD:P(A;;0xF01FF;;;SY)(A;;0x2019D;;;BA)(A;;0x2008D;;;BU)";
  internal const string MaintenanceService="O:BAG:SYD:P(A;;0xF01FF;;;SY)(A;;0xF01FF;;;BA)(A;;0x2008D;;;BU)";
  [StructLayout(LayoutKind.Sequential)] struct Luid { public uint low; public int high; }
  [StructLayout(LayoutKind.Sequential)] struct TokenPrivileges { public uint count; public Luid luid; public uint attributes; }
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out Luid luid);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token,bool disable,ref TokenPrivileges privileges,int length,IntPtr previous,IntPtr returned);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenSCManager(string machine,string database,uint access);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenService(IntPtr manager,string name,uint access);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool SetServiceObjectSecurity(IntPtr service,uint information,IntPtr descriptor);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr descriptor,out uint size);
  [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr handle);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr handle);
  static SecurityIdentifier Sid(string sid){return new SecurityIdentifier(sid);}
  internal static bool IsSystem(){using(var identity=WindowsIdentity.GetCurrent()) return identity.User.Value=="S-1-5-18";}
  internal static bool Enabled(){using(var key=Registry.LocalMachine.OpenSubKey(ProductKey)) return key!=null && Convert.ToString(key.GetValue("TamperProtectionEnabled"))=="1";}
  internal static bool Maintenance(){
    using(var key=Registry.LocalMachine.OpenSubKey(ProductKey)){
      DateTime end;
      if(key==null || !DateTime.TryParse(Convert.ToString(key.GetValue("MaintenanceUntilUtc")),CultureInfo.InvariantCulture,DateTimeStyles.RoundtripKind,out end)) return false;
      var left=end.ToUniversalTime()-DateTime.UtcNow;
      return left.TotalSeconds>0 && left.TotalMinutes<=10;
    }
  }
  internal static void Enable(){
    using(var key=Registry.LocalMachine.CreateSubKey(ProductKey)){key.SetValue("TamperProtectionEnabled",1,RegistryValueKind.DWord);key.SetValue("HardeningNonce",Guid.NewGuid().ToString("N"));key.DeleteValue("MaintenanceUntilUtc",false);}
  }
  static void Privilege(string name){
    IntPtr token; if(!OpenProcessToken(GetCurrentProcess(),0x20|0x8,out token)) throw new Win32Exception();
    try{
      Luid luid;if(!LookupPrivilegeValue(null,name,out luid)) throw new Win32Exception();
      var privileges=new TokenPrivileges{count=1,luid=luid,attributes=2};
      if(!AdjustTokenPrivileges(token,false,ref privileges,0,IntPtr.Zero,IntPtr.Zero) || Marshal.GetLastWin32Error()==1300) throw new Win32Exception();
    }finally{CloseHandle(token);}
  }
  internal static void SetService(string name,bool locked){
    IntPtr manager=OpenSCManager(null,null,1);if(manager==IntPtr.Zero) throw new Win32Exception();
    IntPtr service=IntPtr.Zero,descriptor=IntPtr.Zero;
    try{
      service=OpenService(manager,name,0x80000|0x40000);
      if(service==IntPtr.Zero && !locked){
        // SeTakeOwnership permits an elevated, password-verified installer to
        // take ownership before granting its temporary update permissions.
        service=OpenService(manager,name,0x80000);
        if(service!=IntPtr.Zero){
          uint ownerSize;IntPtr owner;
          if(!ConvertStringSecurityDescriptorToSecurityDescriptor("O:BA",1,out owner,out ownerSize)) throw new Win32Exception();
          try{if(!SetServiceObjectSecurity(service,1,owner)) throw new Win32Exception();}finally{LocalFree(owner);}
          CloseServiceHandle(service);service=OpenService(manager,name,0x80000|0x40000);
        }
      }
      if(service==IntPtr.Zero){if(Marshal.GetLastWin32Error()==1060) return;throw new Win32Exception();}
      uint size;if(!ConvertStringSecurityDescriptorToSecurityDescriptor(locked?LockedService:MaintenanceService,1,out descriptor,out size)) throw new Win32Exception();
      if(!SetServiceObjectSecurity(service,1|4,descriptor)) throw new Win32Exception();
    }finally{if(descriptor!=IntPtr.Zero)LocalFree(descriptor);if(service!=IntPtr.Zero)CloseServiceHandle(service);CloseServiceHandle(manager);}
  }
  static void NotLink(string path){if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0) throw new IOException("Protection path must not be a link.");}
  internal static void SetDirectory(string path,bool locked,bool users){
    if(!Directory.Exists(path)) return;
    NotLink(path);
    if(!locked){
      var owner=new DirectorySecurity();owner.SetOwner(Sid("S-1-5-32-544"));Directory.SetAccessControl(path,owner);
    }
    var security=new DirectorySecurity();security.SetAccessRuleProtection(true,false);security.SetOwner(Sid(locked?"S-1-5-18":"S-1-5-32-544"));
    security.AddAccessRule(new FileSystemAccessRule(Sid("S-1-5-18"),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
    security.AddAccessRule(new FileSystemAccessRule(Sid("S-1-5-32-544"),locked?FileSystemRights.ReadAndExecute:FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
    if(users) security.AddAccessRule(new FileSystemAccessRule(Sid("S-1-5-32-545"),FileSystemRights.ReadAndExecute,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
    Directory.SetAccessControl(path,security);
    foreach(var child in Directory.GetDirectories(path)) SetDirectory(child,locked,users);
    foreach(var file in Directory.GetFiles(path)){
      NotLink(file);
      if(!locked){var owner=new FileSecurity();owner.SetOwner(Sid("S-1-5-32-544"));File.SetAccessControl(file,owner);}
      var fileSecurity=new FileSecurity();fileSecurity.SetAccessRuleProtection(true,false);fileSecurity.SetOwner(Sid(locked?"S-1-5-18":"S-1-5-32-544"));
      fileSecurity.AddAccessRule(new FileSystemAccessRule(Sid("S-1-5-18"),FileSystemRights.FullControl,AccessControlType.Allow));
      fileSecurity.AddAccessRule(new FileSystemAccessRule(Sid("S-1-5-32-544"),locked?FileSystemRights.ReadAndExecute:FileSystemRights.FullControl,AccessControlType.Allow));
      if(users)fileSecurity.AddAccessRule(new FileSystemAccessRule(Sid("S-1-5-32-545"),FileSystemRights.ReadAndExecute,AccessControlType.Allow));
      File.SetAccessControl(file,fileSecurity);
    }
  }
  internal static void SetRegistry(string path,bool locked){
    if(!locked){
      using(var ownerKey=Registry.LocalMachine.OpenSubKey(path,RegistryKeyPermissionCheck.ReadWriteSubTree,RegistryRights.TakeOwnership)){
        if(ownerKey==null)return;var owner=new RegistrySecurity();owner.SetOwner(Sid("S-1-5-32-544"));ownerKey.SetAccessControl(owner);
      }
    }
    using(var key=Registry.LocalMachine.OpenSubKey(path,RegistryKeyPermissionCheck.ReadWriteSubTree,RegistryRights.ChangePermissions|RegistryRights.TakeOwnership|RegistryRights.ReadKey)){
      if(key==null)return;
      var security=new RegistrySecurity();security.SetAccessRuleProtection(true,false);security.SetOwner(Sid(locked?"S-1-5-18":"S-1-5-32-544"));
      security.AddAccessRule(new RegistryAccessRule(Sid("S-1-5-18"),RegistryRights.FullControl,InheritanceFlags.ContainerInherit,PropagationFlags.None,AccessControlType.Allow));
      security.AddAccessRule(new RegistryAccessRule(Sid("S-1-5-32-544"),locked?RegistryRights.ReadKey:RegistryRights.FullControl,InheritanceFlags.ContainerInherit,PropagationFlags.None,AccessControlType.Allow));
      key.SetAccessControl(security);
    }
  }
  internal static string SupportPath(string service){
    using(var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+service)){
      if(key==null)return "";var image=Convert.ToString(key.GetValue("ImagePath")??"").Trim();string path="";
      if(image.StartsWith("\"")){var end=image.IndexOf('"',1);if(end>1)path=image.Substring(1,end-1);}
      else {var end=image.IndexOf(".exe",StringComparison.OrdinalIgnoreCase);if(end>=0)path=image.Substring(0,end+4);}
      if(!Path.IsPathRooted(path) || path.StartsWith(@"\\")) throw new IOException("Support path is not an owned installation.");
      path=Path.GetFullPath(path);var name=Path.GetFileName(path);
      if(!name.Equals("MeshAgent.exe",StringComparison.OrdinalIgnoreCase) && !name.Equals("meshagent64.exe",StringComparison.OrdinalIgnoreCase)) throw new IOException("Unsupported support executable.");
      foreach(var root in new[]{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)}){
        if(String.IsNullOrWhiteSpace(root))continue;
        foreach(var folder in new[]{"Mesh Agent","MeshAgent"})if(Path.GetDirectoryName(path).Equals(Path.Combine(root,folder),StringComparison.OrdinalIgnoreCase)){NotLink(Path.GetDirectoryName(path));return path;}
      }
      throw new IOException("Support path is not an owned installation.");
    }
  }
  // This is called only by the visible, elevated installer during its bounded
  // maintenance window. It does not disable blocking or extend the deadline.
  internal static void EnableMaintenancePrivileges(){Privilege("SeTakeOwnershipPrivilege");Privilege("SeRestorePrivilege");}
  static void Exclusive(Action action){
    var security=new MutexSecurity();
    security.AddAccessRule(new MutexAccessRule(Sid("S-1-5-18"),MutexRights.FullControl,AccessControlType.Allow));
    security.AddAccessRule(new MutexAccessRule(Sid("S-1-5-32-544"),MutexRights.FullControl,AccessControlType.Allow));
    bool created;
    using(var mutex=new Mutex(false,@"Global\WindowsProtectHardening",out created,security)){
      bool held=false;
      try{
        try{held=mutex.WaitOne(TimeSpan.FromSeconds(30));}catch(AbandonedMutexException){held=true;}
        if(!held)throw new IOException("Another protection maintenance operation is still running. Retry shortly.");
        action();
      }finally{if(held)mutex.ReleaseMutex();}
    }
  }
  internal static void BeginMaintenance(){Exclusive(BeginMaintenanceCore);}
  static void BeginMaintenanceCore(){
    EnableMaintenancePrivileges();
    SetRegistry(ProductKey,false);
    using(var key=Registry.LocalMachine.CreateSubKey(ProductKey))key.SetValue("MaintenanceUntilUtc",DateTime.UtcNow.AddMinutes(10).ToString("o",CultureInfo.InvariantCulture));
    SetService("DeviceSupportHost",false);SetRegistry(@"SYSTEM\CurrentControlSet\Services\DeviceSupportHost",false);
    SetDirectory(Install,false,true);SetDirectory(Data,false,false);
    var ready=Path.Combine(Data,"tamper.ready");if(File.Exists(ready))File.Delete(ready);
    foreach(var name in new[]{"Mesh Agent","meshagent"}){
      var path=SupportPath(name);if(path.Length==0)continue;
      SetService(name,false);SetRegistry(@"SYSTEM\CurrentControlSet\Services\"+name,false);SetDirectory(Path.GetDirectoryName(path),false,true);UnlockSupportEntry(path);
    }
  }
  internal static void Apply(){Exclusive(ApplyCore);}
  static void ApplyCore(){
    if(!IsSystem())throw new UnauthorizedAccessException("Service hardening must run as SYSTEM.");
    if(!Enabled() || Maintenance())return;
    SetDirectory(Install,true,true);SetDirectory(Data,true,false);
    var ui=Path.Combine(Data,"UI");
    if(Directory.Exists(ui)){
      var security=Directory.GetAccessControl(ui);
      security.AddAccessRule(new FileSystemAccessRule(Sid("S-1-5-32-545"),FileSystemRights.Modify,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
      Directory.SetAccessControl(ui,security);
      foreach(var file in Directory.GetFiles(ui)){
        var rules=File.GetAccessControl(file);rules.AddAccessRule(new FileSystemAccessRule(Sid("S-1-5-32-545"),FileSystemRights.Modify,AccessControlType.Allow));File.SetAccessControl(file,rules);
      }
    }
    BrandEntry(ProductEntry,"WindowsProtect",true);
    var support=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    foreach(var name in new[]{"Mesh Agent","meshagent"}){
      var path=SupportPath(name);if(path.Length==0)continue;
      SetService(name,true);SetRegistry(@"SYSTEM\CurrentControlSet\Services\"+name,true);
      if(support.Add(path)){
        SetDirectory(Path.GetDirectoryName(path),true,true);
        BrandSupport(path);
        Run("sc.exe","failure \""+name+"\" reset= 86400 actions= restart/5000/restart/15000/restart/30000");
        Run("sc.exe","failureflag \""+name+"\" 1");
      }
    }
    SetService("DeviceSupportHost",true);SetRegistry(@"SYSTEM\CurrentControlSet\Services\DeviceSupportHost",true);SetRegistry(ProductKey,true);SetRegistry(ProductEntry,true);
    using(var key=Registry.LocalMachine.OpenSubKey(ProductKey))File.WriteAllText(Path.Combine(Data,"tamper.ready"),"0.5.14|"+Convert.ToString(key.GetValue("HardeningNonce")));
  }
  static void BrandEntry(string path,string title,bool create){
    using(var key=create?Registry.LocalMachine.CreateSubKey(path):Registry.LocalMachine.OpenSubKey(path,true)){
      if(key==null)return;key.SetValue("DisplayName",title);key.SetValue("Publisher","WindowsProtect");key.SetValue("DisplayVersion","0.5.14");
      key.SetValue("NoRemove",1,RegistryValueKind.DWord);key.SetValue("NoModify",1,RegistryValueKind.DWord);key.SetValue("NoRepair",1,RegistryValueKind.DWord);
      key.SetValue("SystemComponent",0,RegistryValueKind.DWord);key.SetValue("Comments","Managed protection component. Authorized removal is available through the WindowsProtect dashboard.");key.SetValue("HelpLink","https://devicehost.vercel.app");
    }
  }
  static void UnlockSupportEntry(string executable){
    foreach(var view in new[]{RegistryView.Registry64,RegistryView.Registry32}){
      using(var hive=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,view))using(var root=hive.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",true)){
        if(root==null)continue;
        foreach(var name in root.GetSubKeyNames()){
          string command;
          using(var read=root.OpenSubKey(name)){if(read==null)continue;command=Convert.ToString(read.GetValue("UninstallString")??"").Trim();}
          if(!command.StartsWith("\""+executable+"\"",StringComparison.OrdinalIgnoreCase) && !command.StartsWith(executable+" ",StringComparison.OrdinalIgnoreCase) && !command.Equals(executable,StringComparison.OrdinalIgnoreCase))continue;
          using(var ownerKey=root.OpenSubKey(name,RegistryKeyPermissionCheck.ReadWriteSubTree,RegistryRights.TakeOwnership)){
            var owner=new RegistrySecurity();owner.SetOwner(Sid("S-1-5-32-544"));ownerKey.SetAccessControl(owner);
          }
          using(var key=root.OpenSubKey(name,RegistryKeyPermissionCheck.ReadWriteSubTree,RegistryRights.ChangePermissions|RegistryRights.ReadKey)){
            var security=new RegistrySecurity();security.SetAccessRuleProtection(true,false);security.SetOwner(Sid("S-1-5-32-544"));
            foreach(var sid in new[]{"S-1-5-18","S-1-5-32-544"})security.AddAccessRule(new RegistryAccessRule(Sid(sid),RegistryRights.FullControl,InheritanceFlags.ContainerInherit,PropagationFlags.None,AccessControlType.Allow));key.SetAccessControl(security);
          }
        }
      }
    }
  }
  static void BrandSupport(string executable){
    // Identify by the exact registered executable path, not display-name alone.
    foreach(var view in new[]{RegistryView.Registry64,RegistryView.Registry32}){
      using(var hive=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,view))using(var root=hive.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",true)){
        if(root==null)continue;
        foreach(var name in root.GetSubKeyNames())using(var key=root.OpenSubKey(name,true)){
          if(key==null)continue;var command=Convert.ToString(key.GetValue("UninstallString")??"").Trim();
          bool owned=command.StartsWith("\""+executable+"\"",StringComparison.OrdinalIgnoreCase) || command.StartsWith(executable+" ",StringComparison.OrdinalIgnoreCase) || command.Equals(executable,StringComparison.OrdinalIgnoreCase);
          if(!owned)continue;
          key.SetValue("DisplayName","WindowsProtect Support");key.SetValue("Publisher","WindowsProtect");key.SetValue("NoRemove",1,RegistryValueKind.DWord);key.SetValue("NoModify",1,RegistryValueKind.DWord);key.SetValue("NoRepair",1,RegistryValueKind.DWord);key.SetValue("SystemComponent",0,RegistryValueKind.DWord);key.SetValue("Comments","WindowsProtect managed support component. Remove through the authorized dashboard.");
          var security=new RegistrySecurity();security.SetAccessRuleProtection(true,false);security.SetOwner(Sid("S-1-5-18"));
          security.AddAccessRule(new RegistryAccessRule(Sid("S-1-5-18"),RegistryRights.FullControl,InheritanceFlags.ContainerInherit,PropagationFlags.None,AccessControlType.Allow));
          security.AddAccessRule(new RegistryAccessRule(Sid("S-1-5-32-544"),RegistryRights.ReadKey,InheritanceFlags.ContainerInherit,PropagationFlags.None,AccessControlType.Allow));key.SetAccessControl(security);
        }
      }
    }
  }
  internal static void Run(string file,string arguments){
    using(var p=new Process{StartInfo=new ProcessStartInfo(file,arguments){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true}}){
      p.Start();var output=p.StandardOutput.ReadToEndAsync();var errors=p.StandardError.ReadToEndAsync();
      if(!p.WaitForExit(15000)){try{p.Kill();}catch{}throw new IOException("Protection configuration timed out.");}
      if(p.ExitCode!=0)throw new IOException("Protection configuration failed: "+file);
    }
  }
}
