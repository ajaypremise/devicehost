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
  const string AgentVersion="0.5.19";
  const string SupportAgentUrlFile=@"C:\ProgramData\WindowsProtect\support-agent.url";

  static readonly string[] RemoteToolDisplayNames = new[]{
    "AnyDesk","TeamViewer","UltraViewer","RustDesk","Supremo","AeroAdmin","DWAgent",
    "Remote Utilities","ScreenConnect","ConnectWise Control","Zoho Assist",
    "LogMeIn","GoTo Assist","Splashtop","Chrome Remote Desktop",
    "TightVNC","UltraVNC","RealVNC","Ammyy","LiteManager",
    "Iperius Remote","Getscreen","Remote Help"
  };

  readonly Dictionary<string,DateTime> lastBlocked = new Dictionary<string,DateTime>(StringComparer.OrdinalIgnoreCase);
  DateTime lastInventoryUpload=DateTime.MinValue;
  DateTime lastMeshRepair=DateTime.MinValue;
  DateTime lastMeshInstallRepair=DateTime.MinValue;
  DateTime lastMeshMissingEvent=DateTime.MinValue;
  Timer timer,policyTimer,identityTimer;
  int identityTicking;
  volatile bool protectionActive;
  bool baselineApplied;
  DateTime lastHardening=DateTime.MinValue, lastHardeningError=DateTime.MinValue;
  int ticking,policyTicking;
  static bool removalLaunched;

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
    identityTimer=new Timer(_=>ScanRemoteIdentities(),null,2000,2000);
  }

  protected override void OnStop(){
    if(timer!=null) timer.Dispose();
    if(policyTimer!=null) policyTimer.Dispose();
    if(identityTimer!=null)identityTimer.Dispose();
    Log("Service stopped.");
  }

  protected override void OnCustomCommand(int command){
    if(command==128){ lastHardening=DateTime.MinValue; EnforceActivation(); ThreadPool.QueueUserWorkItem(_=>Tick()); }
  }

  void Tick(){
    if(Interlocked.CompareExchange(ref ticking,1,0)!=0) return;
    try{
      if(TamperProtection.Enabled() && !TamperProtection.Maintenance() && (DateTime.UtcNow-lastHardening).TotalMinutes>=5){
        try{TamperProtection.Apply();lastHardening=DateTime.UtcNow;}
        catch(Exception ex){
          Log("Removal protection configuration failed: "+ex.GetType().Name+" - "+ex.Message);
          if((DateTime.UtcNow-lastHardeningError).TotalMinutes>=10){lastHardeningError=DateTime.UtcNow;SendEvent("protection_tamper","critical","Removal protection needs attention","WindowsProtect could not confirm its service/file permissions. Check the PC before treating it as protected against removal.");}
        }
      }
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
        RemoteToolPolicy.EnforceNames();
      }
    }catch(Exception ex){ Log("Activation check failed: "+ex.GetType().Name); }
    finally{ Interlocked.Exchange(ref policyTicking,0); }
  }

  sealed class BoundedWebClient : WebClient {
    readonly int timeoutMilliseconds;
    public BoundedWebClient(int timeoutMilliseconds=10000){
      this.timeoutMilliseconds=timeoutMilliseconds;
    }
    protected override WebRequest GetWebRequest(Uri address){
      var request=base.GetWebRequest(address);
      request.Timeout=timeoutMilliseconds;
      var http=request as HttpWebRequest;
      if(http!=null) http.ReadWriteTimeout=timeoutMilliseconds;
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

  static int RegistryDword(string path,string name,int fallback){
    try{using(var key=Registry.LocalMachine.OpenSubKey(path)){if(key==null)return fallback;return Convert.ToInt32(key.GetValue(name,fallback));}}catch{return fallback;}
  }
  static bool DefenderEnabled(){return ServiceRunning("WinDefend") && RegistryDword(@"SOFTWARE\Policies\Microsoft\Windows Defender","DisableAntiSpyware",0)!=1;}
  static bool FirewallEnabled(){
    if(!ServiceRunning("MpsSvc"))return false;
    foreach(var profile in new[]{"DomainProfile","PublicProfile","StandardProfile"})if(RegistryDword(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\"+profile,"EnableFirewall",1)==0)return false;
    return true;
  }
  static bool SmartScreenEnabled(){
    try{using(var policy=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\System")){if(policy!=null && Convert.ToInt32(policy.GetValue("EnableSmartScreen",1))==0)return false;}}
    catch{}
    try{using(var key=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer")){return key!=null && !Convert.ToString(key.GetValue("SmartScreenEnabled")??"").Equals("Off",StringComparison.OrdinalIgnoreCase);}}
    catch{return false;}
  }

  static void ApplySecurityBaseline(){
    try{
      foreach(var profile in new[]{"DomainProfile","PublicProfile","StandardProfile"})using(var key=Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\"+profile))if(key!=null)key.SetValue("EnableFirewall",1,RegistryValueKind.DWord);
      try{using(var key=Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"))if(key!=null)key.SetValue("PUAProtection",1,RegistryValueKind.DWord);}catch{}
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
      try{WindowsServiceTools.SetStartType("RemoteRegistry",4);}catch{}
      Log("Security baseline applied.");
    }catch(Exception ex){
      Log("Security baseline warning: "+ex.Message);
    }
  }

  void ScanRemoteIdentities(){
    if(!protectionActive || Interlocked.CompareExchange(ref identityTicking,1,0)!=0)return;
    try{RemoteToolPolicy.ScanIdentities();}catch(Exception ex){Log("Remote identity scan failed: "+ex.GetType().Name);}
    finally{Interlocked.Exchange(ref identityTicking,0);}
  }
  void BlockUnauthorizedRemoteTools(){
    RemoteToolPolicy.EnforceNames();RemoteToolPolicy.StopServices();
    string name;int reported=0;
    while(reported<3 && RemoteToolPolicy.NextEvent(out name)){
      DateTime previous;var now=DateTime.UtcNow;
      if(lastBlocked.TryGetValue(name,out previous) && (now-previous).TotalMinutes<5)continue;
      lastBlocked[name]=now;reported++;
      QueueLocalRemoteAccessWarning(name);
      SendRemoteAccessAlert(name);
      Log("Blocked remote-control application "+name+".");
    }
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
                  WindowsServiceTools.SetStartType(name,2);
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

      // A stopped service can be restarted above. If the service registration
      // or binary was removed, reinstall only from the HTTPS enrollment URL
      // saved by setup in the SYSTEM/admin-only WindowsProtect data folder.
      if(!MeshCentralRunning() && (DateTime.UtcNow-lastMeshInstallRepair).TotalMinutes>=10){
        lastMeshInstallRepair=DateTime.UtcNow;
        if(RepairApprovedRemoteAccess()){
          SendEvent("protection_repaired","warning","Approved remote support repaired","WindowsProtect restored the approved remote-support component after it was missing.");
          Log("Approved MeshCentral component reinstalled.");
          return;
        }
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

  static bool RepairApprovedRemoteAccess(){
    string temporary=null;
    try{
      if(!File.Exists(SupportAgentUrlFile) || new FileInfo(SupportAgentUrlFile).Length>4096)return false;
      var raw=File.ReadAllText(SupportAgentUrlFile).Trim();Uri source;
      if(!Uri.TryCreate(raw,UriKind.Absolute,out source) || source.Scheme!=Uri.UriSchemeHttps || !String.IsNullOrEmpty(source.UserInfo))return false;
      temporary=Path.Combine(Path.GetTempPath(),"WindowsProtect-MeshAgent-repair-"+Guid.NewGuid().ToString("N")+".exe");
      using(var wc=new BoundedWebClient(60000))wc.DownloadFile(source,temporary);
      var length=new FileInfo(temporary).Length;if(length<100000 || length>200L*1024*1024)return false;
      using(var process=new Process{StartInfo=new ProcessStartInfo(temporary,"-fullinstall"){UseShellExecute=false,CreateNoWindow=true}}){
        process.Start();
        if(!process.WaitForExit(90000)){try{process.Kill();}catch{}return false;}
        if(process.ExitCode!=0)return false;
      }
      for(int i=0;i<20;i++){if(MeshCentralRunning())return true;Thread.Sleep(1500);}
      return false;
    }catch(Exception ex){Log("MeshCentral repair failed: "+ex.GetType().Name+" - "+ex.Message);return false;}
    finally{if(!String.IsNullOrWhiteSpace(temporary))try{File.Delete(temporary);}catch{}}
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

  static void SendRemoteAccessAlert(string tool){
    try{
      var token=ReadToken();
      if(String.IsNullOrWhiteSpace(token))return;
      var body="{\"event_type\":\"remote_access_blocked\",\"severity\":\"critical\",\"title\":\"Unauthorized remote access blocked\",\"details\":{\"tool\":\""+JsonEscape(tool)+"\",\"action\":\"blocked\",\"detected_at\":\""+DateTime.UtcNow.ToString("o")+"\"}}";
      using(var wc=new BoundedWebClient()){
        wc.Headers[HttpRequestHeader.ContentType]="application/json";
        wc.Headers.Add("x-device-token",token);
        wc.UploadString(BaseUrl+"/api/events","POST",body);
      }
    }catch{}
  }

  static void QueueLocalRemoteAccessWarning(string tool){
    try{
      var directory=Path.Combine(DataDir,"UI");Directory.CreateDirectory(directory);
      var id=Guid.NewGuid().ToString("N");
      var title=Convert.ToBase64String(Encoding.UTF8.GetBytes("Remote access blocked"));
      var message=Convert.ToBase64String(Encoding.UTF8.GetBytes("WindowsProtect stopped "+(String.IsNullOrWhiteSpace(tool)?"an unauthorized remote-access tool":tool)+".\r\n\r\nIf you did not expect this, do not share passwords or payment information. Contact CYBERSHIELD on Tollfree for Help."));
      var destination=Path.Combine(directory,"command-"+id+".txt");var temporary=destination+".tmp";
      File.WriteAllText(temporary,"message|"+title+"|"+message+"|standard|center|error|",Encoding.UTF8);
      if(File.Exists(destination))File.Delete(destination);File.Move(temporary,destination);
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

      var defender=DefenderEnabled();
      var firewall=FirewallEnabled();
      var smartOn=SmartScreenEnabled();
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
        var response=wc.UploadString(BaseUrl+"/api/heartbeat","POST",json);
        ApplyServerControls(response);
        var removalId=RemovalCoordinator.RequestId(response);
        if(!removalLaunched && !String.IsNullOrWhiteSpace(removalId)) removalLaunched=RemovalCoordinator.Start(removalId);
        AutomaticUpdater.Check(token,AgentVersion);
      }
      Log("Heartbeat success. MeshCentral="+meshRunning+" version="+meshVersion);
    }catch(Exception ex){
      Log("Heartbeat failed: "+ex.GetType().Name+" - "+ex.Message);
    }
  }

  static void ApplyServerControls(string response){
    try{
      const string marker="\"ultraviewer_allowed_until\":";var index=(response??"").IndexOf(marker,StringComparison.OrdinalIgnoreCase);if(index<0)return;index+=marker.Length;
      while(index<response.Length && Char.IsWhiteSpace(response[index]))index++;
      if(index>=response.Length || response.Substring(index).StartsWith("null",StringComparison.OrdinalIgnoreCase)){RemoteToolPolicy.SetUltraViewerAllowance(null);return;}
      if(response[index]!='\"')return;var end=response.IndexOf('\"',index+1);if(end>index)RemoteToolPolicy.SetUltraViewerAllowance(response.Substring(index+1,end-index-1));
    }catch{}
  }

  public static void Main(){
    ServiceBase.Run(new DeviceSupportHost());
  }
}
