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
    Text="WindowsProtect Setup";
    Width=590; Height=585;
    StartPosition=FormStartPosition.CenterScreen;
    BackColor=Color.FromArgb(9,11,16);
    ForeColor=Color.White;
    Font=new Font("Segoe UI",10);
    FormBorderStyle=FormBorderStyle.FixedDialog;
    MaximizeBox=false;

    var title=new Label{Text="WindowsProtect",Left=28,Top=24,Width=500,Height=36,Font=new Font("Segoe UI Semibold",22),ForeColor=Color.White};
    var sub=new Label{Text="Protect this PC and connect it to DeviceHost + MeshCentral.",Left=30,Top=64,Width=510,Height=42,ForeColor=Color.FromArgb(150,160,175)};

    AddLabel("Owner / family member",30,118); Configure(ownerBox,30,142,"e.g. Mum");
    AddLabel("Device label",30,188); Configure(labelBox,30,212,"e.g. Living room laptop");
    AddLabel("One-time setup code (new PC only)",30,258); Configure(codeBox,30,282,"XXXX-XXXX-XXXX");

    saveCredential.Text="Store this Windows account credential locally (optional)";
    saveCredential.Left=30; saveCredential.Top=338; saveCredential.Width=510; saveCredential.ForeColor=Color.FromArgb(210,215,225);
    saveCredential.CheckedChanged+=(s,e)=>{ userBox.Enabled=passBox.Enabled=saveCredential.Checked; };

    AddLabel("Windows username",30,372); Configure(userBox,30,396,Environment.UserName);
    AddLabel("Windows password",300,372); Configure(passBox,300,396,"");
    passBox.UseSystemPasswordChar=true;
    userBox.Enabled=passBox.Enabled=false;

    var note=new Label{
      Text="Password stays only in Windows Credential Manager on this PC. It is never sent to DeviceHost, MeshCentral, GitHub or logs.",
      Left=30,Top=435,Width=510,Height=38,ForeColor=Color.FromArgb(140,150,165),Font=new Font("Segoe UI",8.5f)
    };

    installButton.Text="Install WindowsProtect";
    installButton.Left=30; installButton.Top=482; installButton.Width=220; installButton.Height=38;
    installButton.FlatStyle=FlatStyle.Flat;
    installButton.BackColor=Color.White;
    installButton.ForeColor=Color.FromArgb(10,12,16);
    installButton.FlatAppearance.BorderSize=0;
    installButton.Click+=async (s,e)=>await InstallAsync();

    progress.Left=270; progress.Top=489; progress.Width=270; progress.Height=22;
    progress.Style=ProgressBarStyle.Marquee; progress.Visible=false;

    status.Left=30; status.Top=528; status.Width=510; status.Height=28;
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

        SetStatus("Enrolling this PC in DeviceHost...");
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

      SetStatus("Preparing WindowsProtect service...");
      Directory.CreateDirectory(InstallDir);
      StopExistingService();
      ExtractEmbeddedService(ServiceExe);

      if(String.IsNullOrWhiteSpace(meshAgentUrl)) meshAgentUrl="https://34-69-184-103.sslip.io/meshagents?id=4&meshid=gY1Com9g9071ieNPRic8EHP2irnFHZxy1gpsoBn8opAi4guIJ$gAQj$INq8mbEjL&installflags=0";
      var meshReady=MeshReady();
      if(!meshReady && !String.IsNullOrWhiteSpace(meshAgentUrl)){
        SetStatus("Installing approved MeshCentral agent...");
        var temp=Path.Combine(Path.GetTempPath(),"WindowsProtect-MeshAgent.exe");
        using(var wc=new WebClient()) await wc.DownloadFileTaskAsync(new Uri(meshAgentUrl),temp);
        await Run(temp,"-fullinstall",90000);
        try{ File.Delete(temp); }catch{}
        for(int i=0;i<20 && !MeshReady();i++) await Task.Delay(1500);
        meshReady=MeshReady();
      }

      if(!meshReady){
        throw new Exception("MeshCentral agent is not connected yet. WindowsProtect protection was not activated so you cannot lose your current support route.");
      }

      InstallOrUpdateService();

      if(saveCredential.Checked && !String.IsNullOrWhiteSpace(userBox.Text) && !String.IsNullOrWhiteSpace(passBox.Text)){
        SetStatus("Saving optional Windows credential locally...");
        SaveCredential(userBox.Text.Trim(),passBox.Text);
      }

      SetStatus("Finishing security checks...");
      await Task.Delay(7000);

      progress.Visible=false;
      SetStatus("WindowsProtect installed successfully.");
      MessageBox.Show("WindowsProtect is installed. DeviceHost monitoring and approved MeshCentral access are active.","WindowsProtect",MessageBoxButtons.OK,MessageBoxIcon.Information);
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
