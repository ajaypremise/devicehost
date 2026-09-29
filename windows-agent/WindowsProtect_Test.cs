using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

class WindowsProtectTest {
  const string BaseUrl="https://devicehost.vercel.app";

  static string Esc(string s){return (s??"").Replace("\\","\\\\").Replace("\"","\\\"").Replace("\r"," ").Replace("\n"," ");}
  static string PS(string command){
    try{
      var p=new Process{StartInfo=new ProcessStartInfo("powershell.exe","-NoProfile -NonInteractive -Command \""+command.Replace("\"","\\\"")+"\""){UseShellExecute=false,RedirectStandardOutput=true,CreateNoWindow=true}};
      p.Start(); var s=p.StandardOutput.ReadToEnd().Trim(); p.WaitForExit(10000); return s;
    }catch{return "";}
  }
  static bool BoolPS(string command){return PS(command).Trim().Equals("True",StringComparison.OrdinalIgnoreCase);}
  static string WindowsName(){
    try{
      using(var k=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion")){
        var name=(k.GetValue("ProductName") as string)??"Windows";
        var display=(k.GetValue("DisplayVersion") as string)??"";
        var build=(k.GetValue("CurrentBuildNumber") as string)??"";
        return name+(display==""?"":" "+display)+(build==""?"":" Build "+build);
      }
    }catch{return Environment.OSVersion.VersionString;}
  }
  static List<string> RemoteTools(){
    var hits=new List<string>();
    string[] needles={"AnyDesk","TeamViewer","UltraViewer","Supremo","AeroAdmin","DWAgent","Remote Utilities","ScreenConnect","ConnectWise Control","Zoho Assist","LogMeIn","GoTo Assist","Splashtop","Chrome Remote Desktop","TightVNC","UltraVNC","RealVNC","MeshCentral","Ammyy","LiteManager","Iperius Remote","Getscreen","Remote Help"};
    foreach(var path in new[]{@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"}){
      using(var root=Registry.LocalMachine.OpenSubKey(path)){ if(root==null) continue; foreach(var n in root.GetSubKeyNames()){ using(var k=root.OpenSubKey(n)){ var d=(k.GetValue("DisplayName") as string)??""; foreach(var x in needles) if(d.IndexOf(x,StringComparison.OrdinalIgnoreCase)>=0 && !hits.Contains(d)) hits.Add(d); } } }
    }
    return hits;
  }
  static int InstalledCount(){
    var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    foreach(var path in new[]{@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"}){
      using(var root=Registry.LocalMachine.OpenSubKey(path)){ if(root==null) continue; foreach(var n in root.GetSubKeyNames()){ using(var k=root.OpenSubKey(n)){ var d=k.GetValue("DisplayName") as string; if(!String.IsNullOrWhiteSpace(d)) names.Add(d); } } }
    }
    return names.Count;
  }
  static string RustDeskVersion(){
    foreach(var path in new[]{@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"}){
      using(var root=Registry.LocalMachine.OpenSubKey(path)){ if(root==null) continue; foreach(var n in root.GetSubKeyNames()){ using(var k=root.OpenSubKey(n)){ var d=(k.GetValue("DisplayName") as string)??""; if(d.IndexOf("RustDesk",StringComparison.OrdinalIgnoreCase)>=0) return (k.GetValue("DisplayVersion") as string)??""; } } }
    }
    return "";
  }

  static void Main(){
    Console.Title="WindowsProtect Test";
    Console.WriteLine("WindowsProtect v0.3 - DeviceHost telemetry test\n");
    Console.Write("Person/device owner name: "); var person=Console.ReadLine(); if(String.IsNullOrWhiteSpace(person)) person="Test User";
    Console.Write("Device label [Kamatera Test]: "); var label=Console.ReadLine(); if(String.IsNullOrWhiteSpace(label)) label="Kamatera Test";
    Console.Write("DEVICE_ENROLLMENT_KEY: "); var key=Console.ReadLine();
    if(String.IsNullOrWhiteSpace(key)){Console.WriteLine("Enrollment key required."); Console.ReadKey(); return;}
    try{
      ServicePointManager.SecurityProtocol=SecurityProtocolType.Tls12;
      var os=WindowsName();
      var enroll="{\"person_name\":\""+Esc(person)+"\",\"device_name\":\""+Esc(label)+"\",\"computer_name\":\""+Esc(Environment.MachineName)+"\",\"protection_status\":\"pending\",\"migration_status\":\"not_started\",\"os_version\":\""+Esc(os)+"\",\"agent_version\":\"0.3.1-test\"}";
      string response;
      using(var wc=new WebClient()){wc.Headers[HttpRequestHeader.ContentType]="application/json";wc.Headers.Add("x-enrollment-key",key);response=wc.UploadString(BaseUrl+"/api/enroll","POST",enroll);}
      var tm=Regex.Match(response,"\"device_token\"\\s*:\\s*\"([^\"]+)\"");
      var cm=Regex.Match(response,"\"device_code\"\\s*:\\s*\"([^\"]+)\"");
      if(!tm.Success) throw new Exception("DeviceHost did not return a device token.");
      var token=tm.Groups[1].Value;

      var defender=BoolPS("(Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusEnabled");
      var firewall=BoolPS("((Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object {$_.Enabled -eq $false}).Count -eq 0)");
      var smart=PS("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Name SmartScreenEnabled -ErrorAction SilentlyContinue).SmartScreenEnabled");
      var smartOn=!smart.Equals("Off",StringComparison.OrdinalIgnoreCase) && smart!="";
      var tools=RemoteTools();
      var arr=new StringBuilder("["); for(int i=0;i<tools.Count;i++){if(i>0)arr.Append(",");arr.Append("\"").Append(Esc(tools[i])).Append("\"");} arr.Append("]");
      var posture=(!defender||!firewall||!smartOn||tools.Count>0)?"warning":"healthy";
      var rdRunning=Process.GetProcessesByName("rustdesk").Length>0;
      var hb="{\"computer_name\":\""+Esc(Environment.MachineName)+"\",\"protection_status\":\"protected\",\"os_version\":\""+Esc(os)+"\",\"agent_version\":\"0.3.1-test\",\"defender_enabled\":"+(defender?"true":"false")+",\"firewall_enabled\":"+(firewall?"true":"false")+",\"smartscreen_enabled\":"+(smartOn?"true":"false")+",\"rustdesk_running\":"+(rdRunning?"true":"false")+",\"rustdesk_version\":\""+Esc(RustDeskVersion())+"\",\"rustdesk_service_running\":false,\"temporary_support_enabled\":false,\"installed_apps_count\":"+InstalledCount()+",\"remote_tools_detected\":"+arr+",\"security_posture\":\""+posture+"\"}";
      using(var wc=new WebClient()){wc.Headers[HttpRequestHeader.ContentType]="application/json";wc.Headers.Add("x-device-token",token);wc.UploadString(BaseUrl+"/api/heartbeat","POST",hb);}

      var data=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"WindowsProtect");
      Directory.CreateDirectory(data);
      var protectedBytes=ProtectedData.Protect(Encoding.UTF8.GetBytes(token),null,DataProtectionScope.LocalMachine);
      File.WriteAllText(Path.Combine(data,"device.token"),Convert.ToBase64String(protectedBytes));

      Console.WriteLine("\nSUCCESS");
      if(cm.Success) Console.WriteLine("Device ID: "+cm.Groups[1].Value);
      Console.WriteLine("Enrollment + security telemetry completed.");
      Console.WriteLine("Open https://devicehost.vercel.app");
    }catch(WebException e){
      string detail=e.Message; try{using(var r=new StreamReader(e.Response.GetResponseStream())) detail=r.ReadToEnd();}catch{}
      Console.WriteLine("\nFAILED: "+detail);
    }catch(Exception e){Console.WriteLine("\nFAILED: "+e.Message);}
    Console.WriteLine("\nPress any key to close."); Console.ReadKey();
  }
}