using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using Microsoft.Win32;

// Remote-control applications only. Ordinary applications remain permitted.
internal static class RemoteToolPolicy {
  internal static readonly string[] Names={
    "AnyDesk","TeamViewer","TeamViewer_Service","TeamViewerQS","TeamViewer_Host","TeamViewer_Desktop",
    "UltraViewer","UltraViewer_Desktop","RustDesk","rustdesk_host","Supremo","SupremoService","AeroAdmin",
    "dwagent","dwagsvc","rutserv","rfusclient","rutview","ScreenConnect.Client","ScreenConnect.ClientService",
    "ZohoAssist","ZA_Connect","ZAService","ZohoURS","LogMeIn","LMIGuardianSvc","g2ax_service",
    "SplashtopRemoteService","SRManager","SRService","SRAgent","remoting_host","tvnserver","winvnc","vncserver",
    "ammyy","ROMServer","LiteManager","IperiusRemote","getscreen","QuickAssist","msra","RemoteHelp",
    "meshagent","meshagent64"
  };
  static readonly HashSet<string> names=new HashSet<string>(Names,StringComparer.OrdinalIgnoreCase);
  static readonly string[] brands={"anydesk","teamviewer","ultraviewer","rustdesk","supremo","aeroadmin","dwagent","dwservice",
    "remote utilities","screenconnect","connectwise control","zoho assist","zohoassist","logmein","gotoassist","goto assist",
    "splashtop","chrome remote desktop","tightvnc","ultravnc","realvnc","ammyy","litemanager","iperius remote","iperiusremote",
    "getscreen","quick assist","remote help","mesh agent","meshagent","meshcentral agent"};
  sealed class Verdict {internal string stamp;internal bool blocked;}
  static readonly ConcurrentDictionary<string,Verdict> cache=new ConcurrentDictionary<string,Verdict>(StringComparer.OrdinalIgnoreCase);
  static readonly ConcurrentQueue<string> events=new ConcurrentQueue<string>();
  internal static bool KnownName(string name){return names.Contains(name??"") || (name??"").StartsWith("ScreenConnect.Client.",StringComparison.OrdinalIgnoreCase);}
  internal static bool KnownMetadata(string product,string description,string original,string internalName){
    if(KnownName(Path.GetFileNameWithoutExtension(original??"")) || KnownName(Path.GetFileNameWithoutExtension(internalName??"")))return true;
    foreach(var value in new[]{product,description}){
      var text=(value??"").ToLowerInvariant();
      foreach(var brand in brands)if(text.IndexOf(brand,StringComparison.Ordinal)>=0)return true;
    }
    return false;
  }
  internal static bool ApprovedPath(string path){
    if(String.IsNullOrEmpty(path))return false;
    foreach(var name in new[]{"Mesh Agent","meshagent"}){
      try{var approved=TamperProtection.SupportPath(name);if(approved.Length>0 && Path.GetFullPath(path).Equals(approved,StringComparison.OrdinalIgnoreCase))return true;}catch{}
    }
    return false;
  }
  static string ImagePath(Process process){try{return process.MainModule.FileName;}catch{return "";}}
  static bool BinaryBlocked(string path){
    if(String.IsNullOrWhiteSpace(path) || path.StartsWith(@"\\") || !Path.IsPathRooted(path))return false;
    try{
      var file=new FileInfo(path);var stamp=file.Length+":"+file.LastWriteTimeUtc.Ticks;
      Verdict value;if(cache.TryGetValue(path,out value) && value.stamp==stamp)return value.blocked;
      var info=FileVersionInfo.GetVersionInfo(path);
      bool blocked=KnownMetadata(info.ProductName,info.FileDescription,info.OriginalFilename,info.InternalName);
      if(cache.Count>=1024)cache.Clear();cache[path]=new Verdict{stamp=stamp,blocked=blocked};return blocked;
    }catch{return false;}
  }
  static bool Kill(Process process){
    try{var name=process.ProcessName;process.Kill();if(events.Count<100)events.Enqueue(name);return true;}catch{return false;}
  }
  // Fast enforcement never reads version resources, scans services or waits for
  // telemetry. Renamed-binary discovery runs independently below.
  internal static bool CheckAndBlock(Process process,bool identity){
    try{
      bool known=KnownName(process.ProcessName);
      if(!known && !identity)return false;
      var path=ImagePath(process);if(ApprovedPath(path))return false;
      if(known || (identity && BinaryBlocked(path)))return Kill(process);
    }catch{}
    return false;
  }
  internal static void EnforceNames(){
    foreach(var process in Process.GetProcesses())using(process)CheckAndBlock(process,false);
  }
  internal static void ScanIdentities(){
    foreach(var process in Process.GetProcesses())using(process)CheckAndBlock(process,true);
  }
  internal static void StopServices(){
    foreach(var service in ServiceController.GetServices())using(service){
      try{
        string path="";
        using(var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+service.ServiceName)){
          if(key!=null){var image=Convert.ToString(key.GetValue("ImagePath")??"").Trim();
            if(image.StartsWith("\"")){var end=image.IndexOf('"',1);if(end>1)path=image.Substring(1,end-1);}
            else{var end=image.IndexOf(".exe",StringComparison.OrdinalIgnoreCase);if(end>=0)path=image.Substring(0,end+4);}
          }
        }
        if(ApprovedPath(path))continue;
        if(!KnownName(service.ServiceName) && !KnownMetadata(service.DisplayName,"","","") && !BinaryBlocked(path))continue;
        // SYSTEM owns this operation. No global service policy or broad
        // company-name match is used, and unrelated services are untouched.
        using(var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+service.ServiceName,true))if(key!=null)key.SetValue("Start",4,RegistryValueKind.DWord);
        if(service.Status!=ServiceControllerStatus.Stopped)service.Stop();
      }catch{}
    }
  }
  internal static bool NextEvent(out string name){return events.TryDequeue(out name);}
}
