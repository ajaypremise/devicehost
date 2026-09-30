using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Security.Cryptography;
using System.ServiceProcess;
using Microsoft.Win32;

public sealed class DeviceSupportHost : ServiceBase {
  const string BaseUrl="https://devicehost.vercel.app";
  const string DataDir=@"C:\ProgramData\WindowsProtect";
  Timer timer;
  public DeviceSupportHost(){ ServiceName="DeviceSupportHost"; CanStop=true; AutoLog=false; }
  protected override void OnStart(string[] args){ timer=new Timer(_=>SendHeartbeat(),null,5000,60000); }
  protected override void OnStop(){ if(timer!=null) timer.Dispose(); }
  static string ReadToken(){
    var p=Path.Combine(DataDir,"device.token");
    if(!File.Exists(p)) return null;
    var enc=Convert.FromBase64String(File.ReadAllText(p).Trim());
    return Encoding.UTF8.GetString(ProtectedData.Unprotect(enc,null,DataProtectionScope.LocalMachine));
  }
  static string PS(string command){
    try{
      var p=new Process{StartInfo=new ProcessStartInfo("powershell.exe","-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \""+command.Replace("\"","\\\"")+"\""){UseShellExecute=false,RedirectStandardOutput=true,CreateNoWindow=true}};
      p.Start(); var s=p.StandardOutput.ReadToEnd().Trim(); p.WaitForExit(10000); return s;
    }catch{return "";}
  }
  static string JsonEscape(string s){ return (s??"").Replace("\\","\\\\").Replace("\"","\\\"").Replace("\r"," ").Replace("\n"," "); }
  static bool BoolPS(string cmd){ return PS(cmd).Trim().Equals("True",StringComparison.OrdinalIgnoreCase); }
  static string RustDeskVersion(){
    foreach(var root in new[]{Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")}){
      if(root==null) continue; using(root) foreach(var n in root.GetSubKeyNames()){ using(var k=root.OpenSubKey(n)){ var d=(k.GetValue("DisplayName") as string)??""; if(d.IndexOf("RustDesk",StringComparison.OrdinalIgnoreCase)>=0) return (k.GetValue("DisplayVersion") as string)??""; } }
    } return "";
  }
  static List<string> RemoteTools(){
    var hits=new List<string>(); string[] needles={"AnyDesk","TeamViewer","UltraViewer","Supremo","AeroAdmin","DWAgent","Remote Utilities","ScreenConnect","ConnectWise Control","Zoho Assist","LogMeIn","GoTo Assist","Splashtop","Chrome Remote Desktop","TightVNC","UltraVNC","RealVNC","Ammyy","LiteManager","Iperius Remote","Getscreen","Remote Help"};
    foreach(var path in new[]{@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"}){
      using(var root=Registry.LocalMachine.OpenSubKey(path)){ if(root==null) continue; foreach(var n in root.GetSubKeyNames()){ using(var k=root.OpenSubKey(n)){ var d=(k.GetValue("DisplayName") as string)??""; foreach(var x in needles) if(d.IndexOf(x,StringComparison.OrdinalIgnoreCase)>=0 && !hits.Contains(d)) hits.Add(d); } } }
    } return hits;
  }
  static int InstalledCount(){
    var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    foreach(var path in new[]{@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"}){
      using(var root=Registry.LocalMachine.OpenSubKey(path)){ if(root==null) continue; foreach(var n in root.GetSubKeyNames()){ using(var k=root.OpenSubKey(n)){ var d=k.GetValue("DisplayName") as string; if(!String.IsNullOrWhiteSpace(d)) names.Add(d); } } }
    } return names.Count;
  }
  static bool ServiceRunning(string name){ try{ using(var s=new ServiceController(name)) return s.Status==ServiceControllerStatus.Running; }catch{return false;} }
  static bool MeshCentralRunning(){ return ServiceRunning("Mesh Agent") || ServiceRunning("meshagent"); }
  static string MeshCentralVersion(){
    try{
      foreach(var serviceName in new[]{"Mesh Agent","meshagent"}){
        using(var k=Registry.LocalMachine.OpenSubKey(@"SYSTEM\\CurrentControlSet\\Services\\"+serviceName)){
          if(k==null) continue;
          var image=(k.GetValue("ImagePath") as string)??"";
          image=image.Trim();
          string exe=image;
          if(image.StartsWith("\"")){
            var end=image.IndexOf("\"",1);
            if(end>1) exe=image.Substring(1,end-1);
          }else{
            var end=image.IndexOf(".exe",StringComparison.OrdinalIgnoreCase);
            if(end>=0) exe=image.Substring(0,end+4);
          }
          if(File.Exists(exe)){
            var v=FileVersionInfo.GetVersionInfo(exe).FileVersion;
            if(!String.IsNullOrWhiteSpace(v)) return v;
          }
        }
      }
    }catch{}
    return "";
  }
  static void SendHeartbeat(){
    try{
      var token=ReadToken(); if(String.IsNullOrEmpty(token)) return;
      var defender=BoolPS("(Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusEnabled");
      var firewall=BoolPS("((Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object {$_.Enabled -eq $false}).Count -eq 0)");
      var smart=PS("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Name SmartScreenEnabled -ErrorAction SilentlyContinue).SmartScreenEnabled");
      var smartOn=!smart.Equals("Off",StringComparison.OrdinalIgnoreCase);
      var rdRunning=Process.GetProcessesByName("rustdesk").Length>0;
      var rdService=ServiceRunning("RustDesk");
      var meshRunning=MeshCentralRunning();
      var meshVersion=MeshCentralVersion();
      var tools=RemoteTools();
      var posture=(!defender||!firewall||!smartOn)?"warning":(tools.Count>0?"warning":"healthy");
      var arr=new StringBuilder("["); for(int i=0;i<tools.Count;i++){if(i>0)arr.Append(",");arr.Append("\"").Append(JsonEscape(tools[i])).Append("\"");} arr.Append("]");
      var json="{\"computer_name\":\""+JsonEscape(Environment.MachineName)+"\",\"rustdesk_running\":"+(rdRunning?"true":"false")+",\"protection_status\":\"protected\",\"os_version\":\""+JsonEscape(Environment.OSVersion.VersionString)+"\",\"agent_version\":\"0.4.0-test\",\"defender_enabled\":"+(defender?"true":"false")+",\"firewall_enabled\":"+(firewall?"true":"false")+",\"smartscreen_enabled\":"+(smartOn?"true":"false")+",\"rustdesk_version\":\""+JsonEscape(RustDeskVersion())+"\",\"rustdesk_service_running\":"+(rdService?"true":"false")+",\"temporary_support_enabled\":false,\"uptime_seconds\":"+((long)(uint)Environment.TickCount/1000)+",\"installed_apps_count\":"+InstalledCount()+",\"remote_tools_detected\":"+arr+",\"security_posture\":\""+posture+"\",\"remote_access_provider\":\"meshcentral\",\"meshcentral_connected\":"+(meshRunning?"true":"false")+",\"meshcentral_agent_version\":\""+JsonEscape(meshVersion)+"\"}";
      using(var wc=new WebClient()){ wc.Headers[HttpRequestHeader.ContentType]="application/json"; wc.Headers.Add("x-device-token",token); wc.UploadString(BaseUrl+"/api/heartbeat","POST",json); }
    }catch{}
  }
  public static void Main(){ ServiceBase.Run(new DeviceSupportHost()); }
}