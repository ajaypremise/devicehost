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
    "UltraViewer","UltraViewer_Desktop","UltraViewer_Service","RustDesk","rustdesk_host","Supremo","SupremoService","AeroAdmin",
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
  sealed class Verdict {internal string stamp;internal bool blocked;internal bool ultraViewer;}
  static readonly ConcurrentDictionary<string,Verdict> cache=new ConcurrentDictionary<string,Verdict>(StringComparer.OrdinalIgnoreCase);
  static readonly ConcurrentQueue<string> events=new ConcurrentQueue<string>();
  internal static bool KnownName(string name){return names.Contains(name??"") || (name??"").StartsWith("ScreenConnect.Client.",StringComparison.OrdinalIgnoreCase);}
  internal static bool IsUltraViewerName(string name){return (name??"").StartsWith("UltraViewer",StringComparison.OrdinalIgnoreCase);}
  internal static bool IsUltraViewerMetadata(params string[] values){foreach(var value in values)if((value??"").IndexOf("ultraviewer",StringComparison.OrdinalIgnoreCase)>=0)return true;return false;}
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
  static string ServiceImagePath(string serviceName){
    try{using(var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+serviceName)){if(key==null)return "";var image=Environment.ExpandEnvironmentVariables(Convert.ToString(key.GetValue("ImagePath")??"").Trim());if(image.StartsWith("\"")){var end=image.IndexOf('"',1);return end>1?image.Substring(1,end-1):"";}var exe=image.IndexOf(".exe",StringComparison.OrdinalIgnoreCase);return exe>=0?image.Substring(0,exe+4):"";}}catch{return "";}
  }
  static Verdict BinaryVerdict(string path){
    if(String.IsNullOrWhiteSpace(path) || path.StartsWith(@"\\") || !Path.IsPathRooted(path))return new Verdict();
    try{
      var file=new FileInfo(path);var stamp=file.Length+":"+file.LastWriteTimeUtc.Ticks;
      Verdict value;if(cache.TryGetValue(path,out value) && value.stamp==stamp)return value;
      var info=FileVersionInfo.GetVersionInfo(path);
      bool blocked=KnownMetadata(info.ProductName,info.FileDescription,info.OriginalFilename,info.InternalName);
      value=new Verdict{stamp=stamp,blocked=blocked,ultraViewer=IsUltraViewerMetadata(info.ProductName,info.FileDescription,info.OriginalFilename,info.InternalName)};
      if(cache.Count>=1024)cache.Clear();cache[path]=value;return value;
    }catch{return new Verdict();}
  }
  static bool BinaryBlocked(string path){return BinaryVerdict(path).blocked;}
  internal static bool UltraViewerAllowed(){
    try{using(var key=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WindowsProtect")){DateTime until;return key!=null && DateTime.TryParse(Convert.ToString(key.GetValue("UltraViewerAllowedUntilUtc")??""),null,System.Globalization.DateTimeStyles.RoundtripKind,out until) && until.ToUniversalTime()>DateTime.UtcNow;}}catch{return false;}
  }
  internal static void SetUltraViewerAllowance(string value){
    DateTime until;bool allowed=!String.IsNullOrWhiteSpace(value) && DateTime.TryParse(value,null,System.Globalization.DateTimeStyles.RoundtripKind,out until) && until.ToUniversalTime()>DateTime.UtcNow;
    try{using(var key=Registry.LocalMachine.CreateSubKey(@"SOFTWARE\WindowsProtect")){if(allowed)key.SetValue("UltraViewerAllowedUntilUtc",until.ToUniversalTime().ToString("o"));else key.DeleteValue("UltraViewerAllowedUntilUtc",false);}}catch{}
    if(allowed)EnableUltraViewerServices();
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
      var verdict=identity?BinaryVerdict(path):new Verdict();
      if((IsUltraViewerName(process.ProcessName)||verdict.ultraViewer) && UltraViewerAllowed())return false;
      if(known || (identity && verdict.blocked))return Kill(process);
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
        var path=ServiceImagePath(service.ServiceName);
        if(ApprovedPath(path))continue;
        var verdict=BinaryVerdict(path);var ultra=IsUltraViewerName(service.ServiceName)||IsUltraViewerMetadata(service.DisplayName)||verdict.ultraViewer;
        if(ultra && UltraViewerAllowed())continue;
        if(!KnownName(service.ServiceName) && !KnownMetadata(service.DisplayName,"","","") && !verdict.blocked)continue;
        // SYSTEM owns this operation. No global service policy or broad
        // company-name match is used, and unrelated services are untouched.
        using(var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+service.ServiceName,true))if(key!=null)key.SetValue("Start",4,RegistryValueKind.DWord);
        if(service.Status!=ServiceControllerStatus.Stopped)service.Stop();
      }catch{}
    }
  }
  static void EnableUltraViewerServices(){
    foreach(var service in ServiceController.GetServices())using(service){
      try{
        var path=ServiceImagePath(service.ServiceName);
        var verdict=BinaryVerdict(path);if(!IsUltraViewerName(service.ServiceName)&&!IsUltraViewerMetadata(service.DisplayName)&&!verdict.ultraViewer)continue;
        using(var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+service.ServiceName,true))if(key!=null && Convert.ToInt32(key.GetValue("Start",3))==4)key.SetValue("Start",3,RegistryValueKind.DWord);
        try{if(service.Status==ServiceControllerStatus.Stopped)service.Start();}catch{}
      }catch{}
    }
  }
  internal static bool NextEvent(out string name){return events.TryDequeue(out name);}
}
