using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

public sealed class DeviceSupportHost : ServiceBase {
  const string BaseUrl="https://devicehost.vercel.app";
  const string DataDir=@"C:\ProgramData\WindowsProtect";
  const string AgentVersion="0.5.7-test";

  static readonly string[] BlockedProcessNames = new[]{
    "AnyDesk","TeamViewer","TeamViewer_Service","UltraViewer","UltraViewer_Desktop",
    "Supremo","AeroAdmin","dwagent","dwagsvc","rutserv","rfusclient",
    "ScreenConnect.Client","ScreenConnect.ClientService","ZohoAssist","ZA_Connect",
    "LogMeIn","LMIGuardianSvc","g2ax_service","SplashtopRemoteService","SRManager",
    "remoting_host","tvnserver","winvnc","vncserver","ammyy","ROMServer","rutview",
    "LiteManager","IperiusRemote","getscreen","QuickAssist","msra","RemoteHelp"
  };

  static readonly string[] RemoteToolDisplayNames = new[]{
    "AnyDesk","TeamViewer","UltraViewer","Supremo","AeroAdmin","DWAgent",
    "Remote Utilities","ScreenConnect","ConnectWise Control","Zoho Assist",
    "LogMeIn","GoTo Assist","Splashtop","Chrome Remote Desktop",
    "TightVNC","UltraVNC","RealVNC","Ammyy","LiteManager",
    "Iperius Remote","Getscreen","Remote Help"
  };

  readonly Dictionary<string,DateTime> lastBlocked = new Dictionary<string,DateTime>(StringComparer.OrdinalIgnoreCase);
  DateTime lastInventoryUpload=DateTime.MinValue;
  DateTime lastMeshRepair=DateTime.MinValue;
  DateTime lastMeshMissingEvent=DateTime.MinValue;
  Timer timer,policyTimer;
  volatile bool protectionActive;
  bool baselineApplied;
  int ticking,policyTicking;

  public DeviceSupportHost(){
    ServiceName="DeviceSupportHost";
    CanStop=true;
    AutoLog=false;
  }

  protected override void OnStart(string[] args){
    ServicePointManager.SecurityProtocol=SecurityProtocolType.Tls12;
    Directory.CreateDirectory(DataDir);
    Log("Service started.");
    protectionActive=ProtectionActivation.IsActive();
    policyTimer=new Timer(_=>EnforceActivation(),null,0,1000);
    timer=new Timer(_=>Tick(),null,3000,30000);
  }

  protected override void OnStop(){
    if(timer!=null) timer.Dispose();
    if(policyTimer!=null) policyTimer.Dispose();
    Log("Service stopped.");
  }

  protected override void OnCustomCommand(int command){
    if(command==128){ EnforceActivation(); ThreadPool.QueueUserWorkItem(_=>Tick()); }
  }

  void Tick(){
    if(Interlocked.CompareExchange(ref ticking,1,0)!=0) return;
    try{
      if(!protectionActive && ProtectionActivation.IsActive()) protectionActive=true;
      if(protectionActive){
        BlockUnauthorizedRemoteTools();
        if(!baselineApplied){ ApplySecurityBaseline(); baselineApplied=true; }
        ProtectionActivation.ConfirmServiceReady();
      }
      EnsureApprovedRemoteAccess();
      SendHeartbeat(protectionActive);
      if((DateTime.UtcNow-lastInventoryUpload).TotalMinutes>=60){ SendInventory(); lastInventoryUpload=DateTime.UtcNow; }
    }catch(Exception ex){
      Log("Tick failed: "+ex.GetType().Name+" - "+ex.Message);
    }finally{ Interlocked.Exchange(ref ticking,0); }
  }

  // Independent local enforcement: never wait for telemetry, PowerShell,
  // inventory uploads or a control-plane response before closing the window.
  void EnforceActivation(){
    if(Interlocked.CompareExchange(ref policyTicking,1,0)!=0) return;
    try{
      ProtectionActivation.Evaluate();
      if(!protectionActive && ProtectionActivation.IsActive()){
        protectionActive=true;
        ThreadPool.QueueUserWorkItem(_=>Tick());
      }
      if(protectionActive){
        foreach(var name in BlockedProcessNames){
          try{
            foreach(var process in Process.GetProcessesByName(name)){
              using(process){ try{ process.Kill(); }catch{} }
            }
          }catch{}
        }
      }
    }catch(Exception ex){ Log("Activation check failed: "+ex.GetType().Name); }
    finally{ Interlocked.Exchange(ref policyTicking,0); }
  }

  sealed class BoundedWebClient : WebClient {
    protected override WebRequest GetWebRequest(Uri address){
      var request=base.GetWebRequest(address);
      request.Timeout=10000;
      var http=request as HttpWebRequest;
      if(http!=null) http.ReadWriteTimeout=10000;
      return request;
    }
  }

  static void Log(string message){
    try{
      Directory.CreateDirectory(DataDir);
      File.AppendAllText(Path.Combine(DataDir,"agent.log"),DateTime.UtcNow.ToString("o")+" "+message+Environment.NewLine);
    }catch{}
  }

  static string ReadToken(){
    var p=Path.Combine(DataDir,"device.token");
    if(!File.Exists(p)) return null;
    var enc=Convert.FromBase64String(File.ReadAllText(p).Trim());
    return Encoding.UTF8.GetString(ProtectedData.Unprotect(enc,null,DataProtectionScope.LocalMachine));
  }

  static string PS(string command){
    try{
      var psi=new ProcessStartInfo("powershell.exe","-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \""+command.Replace("\"","\\\"")+"\""){
        UseShellExecute=false,
        RedirectStandardOutput=true,
        RedirectStandardError=true,
        CreateNoWindow=true
      };
      using(var p=new Process{StartInfo=psi}){
        p.Start();
        var output=p.StandardOutput.ReadToEndAsync();
        var errors=p.StandardError.ReadToEndAsync();
        if(!p.WaitForExit(15000)){ try{ p.Kill(); }catch{} return ""; }
        if(!output.Wait(1000)) return "";
        return output.Result.Trim();
      }
    }catch{return "";}
  }

  static bool BoolPS(string cmd){
    return PS(cmd).Trim().Equals("True",StringComparison.OrdinalIgnoreCase);
  }

  static string JsonEscape(string s){
    return (s??"").Replace("\0","").Replace("\\","\\\\").Replace("\"","\\\"").Replace("\r"," ").Replace("\n"," ");
  }

  static bool ServiceRunning(string name){
    try{ using(var s=new ServiceController(name)) return s.Status==ServiceControllerStatus.Running; }
    catch{return false;}
  }

  static bool ProcessRunning(params string[] names){
    foreach(var n in names){
      try{ if(Process.GetProcessesByName(n).Length>0) return true; }catch{}
    }
    return false;
  }

  static bool MeshCentralRunning(){
    return ServiceRunning("Mesh Agent") || ServiceRunning("meshagent") ||
      ProcessRunning("meshagent","meshagent64","MeshAgent");
  }

  static string MeshCentralNodeId(){
    try{
      using(var root=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Open Source")){
        if(root!=null){
          var preferred=new[]{"Mesh Agent","meshagent"};
          foreach(var name in preferred){
            using(var k=root.OpenSubKey(name)){
              if(k==null) continue;
              var raw=Convert.ToString(k.GetValue("NodeId")??"").Trim();
              if(!String.IsNullOrWhiteSpace(raw)) return "node//"+raw;
            }
          }
          foreach(var name in root.GetSubKeyNames()){
            using(var k=root.OpenSubKey(name)){
              if(k==null) continue;
              var raw=Convert.ToString(k.GetValue("NodeId")??"").Trim();
              if(!String.IsNullOrWhiteSpace(raw)) return "node//"+raw;
            }
          }
        }
      }
    }catch{}
    return "";
  }

  static string MeshCentralVersion(){
    try{
      foreach(var serviceName in new[]{"Mesh Agent","meshagent"}){
        using(var k=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+serviceName)){
          if(k==null) continue;
          var image=Convert.ToString(k.GetValue("ImagePath")??"").Trim();
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
    try{
      foreach(var n in new[]{"meshagent","meshagent64","MeshAgent"}){
        foreach(var p in Process.GetProcessesByName(n)){
          try{
            var v=p.MainModule.FileVersionInfo.FileVersion;
            if(!String.IsNullOrWhiteSpace(v)) return v;
          }catch{}
        }
      }
    }catch{}
    return "";
  }

  static List<string> RemoteTools(){
    var hits=new List<string>();
    foreach(var path in new[]{@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"}){
      using(var root=Registry.LocalMachine.OpenSubKey(path)){
        if(root==null) continue;
        foreach(var n in root.GetSubKeyNames()){
          using(var k=root.OpenSubKey(n)){
            var d=Convert.ToString(k.GetValue("DisplayName")??"");
            foreach(var x in RemoteToolDisplayNames){
              if(d.IndexOf(x,StringComparison.OrdinalIgnoreCase)>=0 && !hits.Contains(d)) hits.Add(d);
            }
          }
        }
      }
    }
    return hits;
  }

  static string InstalledAppsJson(){
    var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    var sb=new StringBuilder("[");
    bool first=true;
    foreach(var path in new[]{@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"}){
      using(var root=Registry.LocalMachine.OpenSubKey(path)){
        if(root==null) continue;
        foreach(var n in root.GetSubKeyNames()){
          using(var k=root.OpenSubKey(n)){
            var name=Convert.ToString(k.GetValue("DisplayName")??"").Trim();
            if(String.IsNullOrWhiteSpace(name)||!seen.Add(name)) continue;
            var version=Convert.ToString(k.GetValue("DisplayVersion")??"").Trim();
            var publisher=Convert.ToString(k.GetValue("Publisher")??"").Trim();
            bool remote=false;
            foreach(var x in RemoteToolDisplayNames) if(name.IndexOf(x,StringComparison.OrdinalIgnoreCase)>=0){ remote=true; break; }
            if(!first) sb.Append(","); first=false;
            sb.Append("{\"app_name\":\"").Append(JsonEscape(name)).Append("\",\"app_version\":\"").Append(JsonEscape(version)).Append("\",\"publisher\":\"").Append(JsonEscape(publisher)).Append("\",\"is_remote_access\":").Append(remote?"true":"false").Append("}");
          }
        }
      }
    }
    sb.Append("]");
    return sb.ToString();
  }

  static int InstalledCount(){
    var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    foreach(var path in new[]{@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"}){
      using(var root=Registry.LocalMachine.OpenSubKey(path)){
        if(root==null) continue;
        foreach(var n in root.GetSubKeyNames()){
          using(var k=root.OpenSubKey(n)){
            var d=k.GetValue("DisplayName") as string;
            if(!String.IsNullOrWhiteSpace(d)) names.Add(d);
          }
        }
      }
    }
    return names.Count;
  }

  static void ApplySecurityBaseline(){
    try{
      PS("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue");
      PS("Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue");
      using(var k=Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")){
        if(k!=null) k.SetValue("EnableLUA",1,RegistryValueKind.DWord);
      }
      using(var k=Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore")){
        if(k!=null) { }
      }
      using(var k=Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\Remote Assistance")){
        if(k!=null) k.SetValue("fAllowToGetHelp",0,RegistryValueKind.DWord);
      }
      try{
        using(var rr=new ServiceController("RemoteRegistry")){
          if(rr.Status!=ServiceControllerStatus.Stopped) rr.Stop();
        }
      }catch{}
      PS("Set-Service -Name RemoteRegistry -StartupType Disabled -ErrorAction SilentlyContinue");
      Log("Security baseline applied.");
    }catch(Exception ex){
      Log("Security baseline warning: "+ex.Message);
    }
  }

  void BlockUnauthorizedRemoteTools(){
    foreach(var name in BlockedProcessNames){
      Process[] ps;
      try{ ps=Process.GetProcessesByName(name); }catch{ continue; }
      foreach(var p in ps){
        try{
          var key=name.ToLowerInvariant();
          p.Kill();
          var now=DateTime.UtcNow;
          DateTime last;
          if(!lastBlocked.TryGetValue(key,out last) || (now-last).TotalMinutes>=5){
            lastBlocked[key]=now;
            SendEvent("remote_tool_blocked","critical","Blocked unauthorized remote-access tool","Process: "+name);
          }
          Log("Blocked process "+name+".");
        }catch{}
      }
    }

    try{
      PS("$rx='AnyDesk|TeamViewer|UltraViewer|Supremo|AeroAdmin|DWAgent|Remote Utilities|ScreenConnect|ConnectWise|Zoho Assist|LogMeIn|GoTo Assist|Splashtop|Chrome Remote Desktop|TightVNC|UltraVNC|RealVNC|Ammyy|LiteManager|Iperius|Getscreen|Remote Help'; Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'meshagent' -and $_.DisplayName -notmatch 'Mesh Agent' -and ($_.Name -match $rx -or $_.DisplayName -match $rx) } | ForEach-Object { Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue; Set-Service -Name $_.Name -StartupType Disabled -ErrorAction SilentlyContinue }");
    }catch{}
  }

  void EnsureApprovedRemoteAccess(){
    try{
      foreach(var name in new[]{"Mesh Agent","meshagent"}){
        try{
          using(var sc=new ServiceController(name)){
            if(sc.Status==ServiceControllerStatus.Running) return;
            if((DateTime.UtcNow-lastMeshRepair).TotalSeconds>=30){
              lastMeshRepair=DateTime.UtcNow;
              try{
                if(sc.StartType==ServiceStartMode.Disabled){
                  PS("Set-Service -Name '"+name.Replace("'","''")+"' -StartupType Automatic -ErrorAction SilentlyContinue");
                }
              }catch{}
              try{
                sc.Start();
                sc.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromSeconds(15));
              }catch{}
              if(sc.Status==ServiceControllerStatus.Running){
                SendEvent("protection_repaired","warning","Approved remote support restarted","WindowsProtect restarted the approved MeshCentral service.");
                Log("Approved MeshCentral service restarted: "+name);
                return;
              }
            }
          }
        }catch{}
      }

      if(!MeshCentralRunning() && (DateTime.UtcNow-lastMeshMissingEvent).TotalMinutes>=10){
        lastMeshMissingEvent=DateTime.UtcNow;
        SendEvent("protection_tamper","critical","Approved remote support unavailable","MeshCentral service/process is missing or stopped. Administrator attention may be required.");
        Log("MeshCentral unavailable; tamper event sent.");
      }
    }catch(Exception ex){
      Log("MeshCentral watchdog warning: "+ex.Message);
    }
  }

  static void SendEvent(string eventType,string severity,string title,string detail){
    try{
      var token=ReadToken();
      if(String.IsNullOrWhiteSpace(token)) return;
      var body="{\"event_type\":\""+JsonEscape(eventType)+"\",\"severity\":\""+JsonEscape(severity)+"\",\"title\":\""+JsonEscape(title)+"\",\"details\":{\"message\":\""+JsonEscape(detail)+"\"}}";
      using(var wc=new BoundedWebClient()){
        wc.Headers[HttpRequestHeader.ContentType]="application/json";
        wc.Headers.Add("x-device-token",token);
        wc.UploadString(BaseUrl+"/api/events","POST",body);
      }
    }catch{}
  }

  static void SendInventory(){
    try{
      var token=ReadToken();
      if(String.IsNullOrWhiteSpace(token)) return;
      var body="{\"apps\":"+InstalledAppsJson()+"}";
      using(var wc=new BoundedWebClient()){
        wc.Headers[HttpRequestHeader.ContentType]="application/json";
        wc.Headers.Add("x-device-token",token);
        wc.UploadString(BaseUrl+"/api/inventory","POST",body);
      }
      Log("Software inventory uploaded.");
    }catch(Exception ex){
      Log("Inventory failed: "+ex.GetType().Name+" - "+ex.Message);
    }
  }

  static void SendHeartbeat(bool active){
    try{
      ServicePointManager.SecurityProtocol=SecurityProtocolType.Tls12;
      var token=ReadToken();
      if(String.IsNullOrWhiteSpace(token)){ Log("Heartbeat skipped: device token missing."); return; }

      var defender=BoolPS("(Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusEnabled");
      var firewall=BoolPS("((Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object {$_.Enabled -eq $false}).Count -eq 0)");
      var smart=PS("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Name SmartScreenEnabled -ErrorAction SilentlyContinue).SmartScreenEnabled");
      var smartOn=!smart.Equals("Off",StringComparison.OrdinalIgnoreCase) && !String.IsNullOrWhiteSpace(smart);
      var meshRunning=MeshCentralRunning();
      var meshVersion=MeshCentralVersion();
      var meshNodeId=MeshCentralNodeId();
      var tools=RemoteTools();
      var posture=(!defender||!firewall||!smartOn)?"warning":(tools.Count>0?"warning":"healthy");

      var arr=new StringBuilder("[");
      for(int i=0;i<tools.Count;i++){
        if(i>0) arr.Append(",");
        arr.Append("\"").Append(JsonEscape(tools[i])).Append("\"");
      }
      arr.Append("]");

      var json="{\"computer_name\":\""+JsonEscape(Environment.MachineName)+
        "\",\"protection_status\":\""+(active?"protected":"pending")+"\""+
        ",\"migration_status\":\""+(active?"completed":ProtectionActivation.MigrationStatus())+"\""+
        ",\"os_version\":\""+JsonEscape(Environment.OSVersion.VersionString)+
        "\",\"agent_version\":\""+AgentVersion+
        "\",\"defender_enabled\":"+(defender?"true":"false")+
        ",\"firewall_enabled\":"+(firewall?"true":"false")+
        ",\"smartscreen_enabled\":"+(smartOn?"true":"false")+
        ",\"temporary_support_enabled\":false"+
        ",\"uptime_seconds\":"+((long)(uint)Environment.TickCount/1000)+
        ",\"installed_apps_count\":"+InstalledCount()+
        ",\"remote_tools_detected\":"+arr+
        ",\"security_posture\":\""+posture+
        "\",\"remote_access_provider\":\"meshcentral\""+
        ",\"meshcentral_connected\":"+(meshRunning?"true":"false")+
        ",\"meshcentral_node_id\":\""+JsonEscape(meshNodeId)+"\""+
        ",\"meshcentral_agent_version\":\""+JsonEscape(meshVersion)+"\"}";

      using(var wc=new BoundedWebClient()){
        wc.Headers[HttpRequestHeader.ContentType]="application/json";
        wc.Headers.Add("x-device-token",token);
        wc.UploadString(BaseUrl+"/api/heartbeat","POST",json);
      }
      Log("Heartbeat success. MeshCentral="+meshRunning+" version="+meshVersion);
    }catch(Exception ex){
      Log("Heartbeat failed: "+ex.GetType().Name+" - "+ex.Message);
    }
  }

  public static void Main(){
    ServiceBase.Run(new DeviceSupportHost());
  }
}
