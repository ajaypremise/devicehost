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
using System.Web.Script.Serialization;

[assembly: AssemblyTitle("WindowsProtect")]
[assembly: AssemblyProduct("WindowsProtect")]
[assembly: AssemblyDescription("Family PC protection and secure support setup")]
[assembly: AssemblyVersion("0.5.17.0")]
[assembly: AssemblyFileVersion("0.5.17.0")]

public class WindowsProtectSetup : Form {
  string assignedAgent="";
  const string BaseUrl="https://devicehost.vercel.app";
  const string InstallDir=@"C:\Program Files\Common Files\DeviceSupport";
  const string ServiceExe=@"C:\Program Files\Common Files\DeviceSupport\DeviceSupportHost.exe";
  const string UserUIExe=@"C:\Program Files\Common Files\DeviceSupport\WindowsProtect_UserUI.exe";
  const string UpdateExe=@"C:\Program Files\Common Files\DeviceSupport\WindowsProtect_Update.exe";
  const string UnlockDll=@"C:\Program Files\Common Files\DeviceSupport\WindowsProtectCredentialProvider.dll";
  const string DataDir=@"C:\ProgramData\WindowsProtect";
  const string UnlockClsid="{7CE6877B-3F4A-4C5B-9201-61D486EF7B77}";
  const string UnlockStore=@"SOFTWARE\WindowsProtect\RemoteUnlock";

  TextBox ownerBox=new TextBox();
  TextBox labelBox=new TextBox();
  TextBox codeBox=new TextBox();
  TextBox userBox=new TextBox();
  TextBox passBox=new TextBox();
  CheckBox showPassword=new CheckBox();
  CheckBox skipPassword=new CheckBox();
  bool installing;
  bool supportOnlyRetry;
  Label credentialHint=new Label();
  Button installButton=new Button();
  Label status=new Label();
  ProgressBar progress=new ProgressBar();

  [DllImport("advapi32.dll", EntryPoint="LogonUserW", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  static extern bool LogonUser(string username,string domain,string password,int logonType,int provider,out IntPtr token);

  [DllImport("kernel32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  static extern bool CloseHandle(IntPtr handle);

  // An actual Windows logon check, not a check that the field contains text.
  // INTERACTIVE authenticates now; NEW_CREDENTIALS would accept unchecked passwords.
  static string ValidateWindowsCredential(string username,string password){
    if(String.IsNullOrWhiteSpace(username) || String.IsNullOrWhiteSpace(password) ||
       username.IndexOf('\0')>=0 || password.IndexOf('\0')>=0)
      throw new Win32Exception(1326,"Windows did not accept this username or password. Use your Windows password, not your PIN.");
    var name=username.Trim();
    string domain=".";
    var separator=name.IndexOf('\\');
    if(separator>=0){
      domain=name.Substring(0,separator);
      name=name.Substring(separator+1);
      if(String.IsNullOrWhiteSpace(domain) || String.IsNullOrWhiteSpace(name) || name.IndexOf('\\')>=0)
        throw new Win32Exception(1326,"Enter a Windows username, PC\\username, or account email.");
    }else if(name.IndexOf('@')>=0){
      domain=null; // Windows UPN format.
    }
    IntPtr token=IntPtr.Zero;
    try{
      if(!LogonUser(name,domain,password,2,0,out token)){
        var error=Marshal.GetLastWin32Error();
        string message="Windows did not accept this username or password. Use your Windows password, not your PIN.";
        if(error==1909) message="This Windows account is locked. Unlock it before trying again.";
        else if(error==1331) message="This Windows account is disabled.";
        else if(error==1330 || error==1907) message="Change this Windows account's password before continuing.";
        else if(error==1385) message="This Windows account is not allowed to sign in to this PC.";
        else if(error!=1326) message="Windows could not verify this account (error "+error+"). Check the account and try again.";
        throw new Win32Exception(error,message);
      }
      using(var identity=new WindowsIdentity(token)) return identity.User.Value;
    }finally{
      if(token!=IntPtr.Zero) CloseHandle(token);
    }
  }

  public WindowsProtectSetup(){
    Text="WindowsProtect";
    AutoScaleDimensions=new SizeF(96,96);
    AutoScaleMode=AutoScaleMode.Dpi;
    ClientSize=new Size(600,704);
    StartPosition=FormStartPosition.CenterScreen;
    BackColor=Color.White;
    ForeColor=Color.FromArgb(28,33,40);
    Font=new Font("Segoe UI",10);
    FormBorderStyle=FormBorderStyle.FixedDialog;
    MaximizeBox=false;
    Icon=Icon.ExtractAssociatedIcon(Assembly.GetExecutingAssembly().Location);

    // A scrolling body keeps every field reachable on small screens and high DPI.
    var scroll=new Panel{Dock=DockStyle.Fill,AutoScroll=true};
    var body=new TableLayoutPanel{
      Dock=DockStyle.Top,AutoSize=true,ColumnCount=1,RowCount=0,
      Padding=new Padding(28,20,28,12),BackColor=BackColor
    };
    body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
    scroll.Controls.Add(body);
    Controls.Add(scroll);

    AddRow(body,TextLabel("WINDOWSPROTECT",9,Color.FromArgb(72,80,92),FontStyle.Bold),0,10);
    AddRow(body,TextLabel("A safer PC. Peace of mind.",22,ForeColor,FontStyle.Bold),0,8);
    AddRow(body,new Panel{Height=6},0,8);

    var identity=Section("THIS PC");
    Configure(ownerBox,"e.g. Mum"); Configure(labelBox,"e.g. Living room laptop");
    AddRow(identity,FieldPair("Owner / family member",ownerBox,"Device label",labelBox),0,0);
    AddRow(body,identity,0,10);

    var enrollment=Section("ONE-TIME SETUP CODE");
    Configure(codeBox,"XXXX-XXXX-XXXX"); AddRow(enrollment,codeBox,0,6);
    AddRow(enrollment,TextLabel("Needed for a new PC. Updates keep your existing registration.",9,Color.FromArgb(100,108,120)),0,0);
    AddRow(body,enrollment,0,10);

    var credential=Section("WINDOWS ACCOUNT");
    Configure(userBox,"Username"); userBox.Text=Environment.UserDomainName+"\\"+Environment.UserName;
    Configure(passBox,""); passBox.UseSystemPasswordChar=true;
    AddRow(credential,FieldPair("Windows username",userBox,"Windows password",passBox),0,8);
    showPassword.Text="Show password";showPassword.AutoSize=true;showPassword.ForeColor=Color.FromArgb(84,94,106);showPassword.Margin=new Padding(0,0,0,7);
    showPassword.CheckedChanged+=(sender,e)=>passBox.UseSystemPasswordChar=!showPassword.Checked;
    AddRow(credential,showPassword,0,5);
    skipPassword.Text="Skip Windows password";skipPassword.AutoSize=true;skipPassword.ForeColor=Color.FromArgb(84,94,106);skipPassword.Margin=new Padding(0,0,0,7);
    skipPassword.CheckedChanged+=(sender,e)=>{
      var usePassword=!skipPassword.Checked;
      userBox.Enabled=passBox.Enabled=showPassword.Enabled=usePassword;
      if(!usePassword){passBox.Text="";showPassword.Checked=false;credentialHint.Text="Password check skipped. You can continue with installation.";}
      else credentialHint.Text="Enter the Windows password normally. If it is not known, choose Skip. The password stays encrypted on this PC and can be used only for an authorised one-time unlock.";
    };
    AddRow(credential,skipPassword,0,5);
    credentialHint=TextLabel("Enter the Windows password normally. If it is not known, choose Skip. The password stays encrypted on this PC and can be used only for an authorised one-time unlock.",9,Color.FromArgb(100,108,120));
    AddRow(credential,credentialHint,0,0);
    AddRow(body,credential,0,0);

    var footer=new TableLayoutPanel{Dock=DockStyle.Bottom,Height=116,ColumnCount=1,RowCount=0,
      Padding=new Padding(28,10,28,12),BackColor=BackColor};
    footer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
    Controls.Add(footer);
    installButton.Text="Protect this PC";
    installButton.Dock=DockStyle.Top; installButton.Height=46;
    installButton.FlatStyle=FlatStyle.Flat;
    installButton.BackColor=Color.FromArgb(32,38,46);
    installButton.ForeColor=Color.White;
    installButton.Font=new Font("Segoe UI",11,FontStyle.Bold);
    installButton.FlatAppearance.BorderSize=0;
    installButton.FlatAppearance.MouseOverBackColor=Color.FromArgb(48,56,67);
    installButton.Cursor=Cursors.Hand;
    installButton.Click+=async (sender,e)=>await InstallAsync();
    AddRow(footer,installButton,0,8);
    AcceptButton=installButton;

    progress.Dock=DockStyle.Top; progress.Height=5;
    progress.Style=ProgressBarStyle.Marquee; progress.Visible=false;
    AddRow(footer,progress,0,4);
    status=TextLabel("Ready to protect this PC.",9,Color.FromArgb(100,108,120));
    AddRow(footer,status,0,0);


    try{
      var tokenPath=Path.Combine(DataDir,"device.token");
      if(File.Exists(tokenPath) && new FileInfo(tokenPath).Length>20){
        ownerBox.Enabled=labelBox.Enabled=codeBox.Enabled=false;
        codeBox.Text="Already registered";
        installButton.Text="Update / repair protection";
        status.Text="This PC is registered. No new setup code needed.";
      }
    }catch{}
    if(codeBox.Enabled)LoadSetupPackage(identity,enrollment);
    FormClosing+=(sender,e)=>{ if(installing) e.Cancel=true; };
    Shown+=(sender,e)=>{
      var area=Screen.FromControl(this).WorkingArea;
      if(Height>area.Height-32){ Height=Math.Max(300,area.Height-32); Top=area.Top+16; }
    };
  }

  void LoadSetupPackage(Control identity,Control enrollment){
    var path=Path.Combine(Path.GetDirectoryName(typeof(WindowsProtectSetup).Assembly.Location),"WindowsProtect_Setup.json");
    if(!File.Exists(path))return;
    try{
      if(new FileInfo(path).Length>4096)throw new IOException();
      var package=new JavaScriptSerializer().Deserialize<System.Collections.Generic.Dictionary<string,string>>(File.ReadAllText(path,Encoding.UTF8));
      DateTime expiry;
      if(!package.ContainsKey("code") || !Regex.IsMatch(package["code"]??"","\\A[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}\\z") || !package.ContainsKey("expires_at") || !DateTime.TryParse(package["expires_at"],System.Globalization.CultureInfo.InvariantCulture,System.Globalization.DateTimeStyles.RoundtripKind,out expiry))throw new IOException();
      if(expiry.ToUniversalTime()<=DateTime.UtcNow){status.Text="This setup download has expired. Get a new download from your dashboard.";return;}
      codeBox.Text=package["code"].ToUpperInvariant();
      if(package.ContainsKey("owner"))ownerBox.Text=(package["owner"]??"").Trim().Substring(0,Math.Min(120,(package["owner"]??"").Trim().Length));
      if(package.ContainsKey("label"))labelBox.Text=(package["label"]??"").Trim().Substring(0,Math.Min(120,(package["label"]??"").Trim().Length));
      if(package.ContainsKey("agent") && (package["agent"]=="Koko" || package["agent"]=="Ashu"))assignedAgent=package["agent"];
      identity.Visible=false;enrollment.Visible=false;ClientSize=new Size(600,548);status.Text="Details loaded. Enter your Windows password or choose Skip.";
    }catch{status.Text="Setup authorization could not be read. Download a fresh installer package.";}
  }

  static Label TextLabel(string text,float size,Color color,FontStyle style=FontStyle.Regular){
    return new Label{Text=text,AutoSize=true,Dock=DockStyle.Top,
      Font=new Font("Segoe UI",size,style),ForeColor=color,Margin=Padding.Empty};
  }

  static TableLayoutPanel Section(string title){
    var section=new TableLayoutPanel{Dock=DockStyle.Top,AutoSize=true,ColumnCount=1,RowCount=0,
      Padding=new Padding(16,12,16,12),BackColor=Color.FromArgb(247,248,250)};
    section.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
    AddRow(section,TextLabel(title,9,Color.FromArgb(72,80,92),FontStyle.Bold),0,12);
    return section;
  }

  static TableLayoutPanel FieldPair(string leftTitle,TextBox left,string rightTitle,TextBox right){
    var fields=new TableLayoutPanel{Dock=DockStyle.Top,AutoSize=true,ColumnCount=2,RowCount=2,Margin=Padding.Empty};
    fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,50));
    fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,50));
    fields.RowStyles.Add(new RowStyle(SizeType.AutoSize));
    fields.RowStyles.Add(new RowStyle(SizeType.AutoSize));
    var leftLabel=TextLabel(leftTitle,9,Color.FromArgb(64,72,84));
    var rightLabel=TextLabel(rightTitle,9,Color.FromArgb(64,72,84));
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
    box.BackColor=Color.White; box.ForeColor=Color.FromArgb(28,33,40);
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
    string verifiedUserSid="";
    string verifiedUsername="";
    string verifiedPassword="";

    if(!supportOnlyRetry){
      if(!alreadyEnrolled && (String.IsNullOrWhiteSpace(owner)||String.IsNullOrWhiteSpace(label)||String.IsNullOrWhiteSpace(code))){
        SetStatus("Enter the owner, device label and one-time setup code."); return;
      }
      if(!skipPassword.Checked && (String.IsNullOrWhiteSpace(userBox.Text) || String.IsNullOrWhiteSpace(passBox.Text))){
        SetStatus("Enter your Windows username and password to continue.");
        if(String.IsNullOrWhiteSpace(userBox.Text)) userBox.Focus(); else passBox.Focus(); return;
      }
      if(!skipPassword.Checked && Encoding.Unicode.GetByteCount(passBox.Text)>2560){
        SetStatus("The Windows password is too long to verify safely."); passBox.Focus(); return;
      }
      if(!skipPassword.Checked){
        SetStatus("Verifying Windows account...");
        try{
          verifiedUserSid=ValidateWindowsCredential(userBox.Text.Trim(),passBox.Text);
          verifiedUsername=userBox.Text.Trim();
          verifiedPassword=passBox.Text;
          credentialHint.Text="Windows password verified. It will be encrypted on this PC and will never be uploaded.";
          credentialHint.ForeColor=Color.FromArgb(100,108,120);
        }catch(Win32Exception ex){
          SetStatus("Windows account verification failed.");
          credentialHint.Text=ex.Message; credentialHint.ForeColor=Color.FromArgb(153,43,43);
          passBox.Text=""; passBox.Focus(); return;
        }
      }
    }

    installing=true;
    ownerBox.Enabled=labelBox.Enabled=codeBox.Enabled=userBox.Enabled=passBox.Enabled=showPassword.Enabled=skipPassword.Enabled=false;
    installButton.Enabled=false; progress.Visible=true;
    bool completed=false;
    try{
      ServicePointManager.SecurityProtocol=SecurityProtocolType.Tls12;
      SetStatus("Preparing installation...");
      TamperProtection.BeginMaintenance();
      if(!supportOnlyRetry){
        passBox.Text="";
        string meshAgentUrl="";
        if(!alreadyEnrolled){
          SetStatus("Verifying setup...");
          var redeem=await PostJson(BaseUrl+"/api/setup/redeem","{\"code\":\""+Esc(code)+"\"}",null);
          var enrollKey=JsonValue(redeem,"device_enrollment_key");
          meshAgentUrl=JsonValue(redeem,"mesh_agent_url");
          if(String.IsNullOrWhiteSpace(enrollKey)) throw new Exception("Setup code was invalid or expired.");
          SetStatus("Registering this PC...");
          var enroll="{\"person_name\":\""+Esc(owner)+"\",\"device_name\":\""+Esc(label)+"\",\"computer_name\":\""+Esc(Environment.MachineName)+"\",\"protection_status\":\"pending\",\"migration_status\":\"not_started\",\"os_version\":\""+Esc(Environment.OSVersion.VersionString)+"\",\"agent_version\":\"0.5.17\",\"assigned_agent\":\""+Esc(assignedAgent)+"\",\"remote_access_provider\":\"meshcentral\"}";
          var enrolled=await PostJson(BaseUrl+"/api/enroll",enroll,enrollKey);
          var token=JsonValue(enrolled,"device_token");
          if(String.IsNullOrWhiteSpace(token)) throw new Exception("The registration server did not return a device token.");
          Directory.CreateDirectory(DataDir);
          var protectedBytes=ProtectedData.Protect(Encoding.UTF8.GetBytes(token),null,DataProtectionScope.LocalMachine);
          File.WriteAllText(tokenPath,Convert.ToBase64String(protectedBytes));
          if(!String.IsNullOrWhiteSpace(meshAgentUrl)) File.WriteAllText(Path.Combine(DataDir,"support-agent.url"),meshAgentUrl);
        }
        // Initialize ONCE. Pending remains pending across retries/reboots;
        // an already protected legacy installation stays active during updates.
        ProtectionActivation.Initialize(alreadyEnrolled && LegacyProtectionInstalled());
        Directory.CreateDirectory(InstallDir);
        Directory.CreateDirectory(Path.Combine(DataDir,"Setup"));
        HardenWindowsProtect();
        SetStatus("Installing protection components...");
        StopExistingService(); ExtractResource("DeviceSupportHost.exe",ServiceExe);ExtractResource("WindowsProtect_Update.exe",UpdateExe);ExtractResource("WindowsProtect_UserUI.exe",UserUIExe);InstallUserUI();
        if(String.IsNullOrWhiteSpace(meshAgentUrl)){
          var saved=Path.Combine(DataDir,"support-agent.url");
          if(File.Exists(saved)) meshAgentUrl=File.ReadAllText(saved).Trim();
        }
        if(String.IsNullOrWhiteSpace(meshAgentUrl)) throw new Exception("Secure support setup is unavailable. Generate a fresh WindowsProtect download and try again.");
        if(!MeshReady()){
          SetStatus("Connecting secure support...");
          var temp=Path.Combine(Path.GetTempPath(),"WindowsProtect-MeshAgent.exe");
          try{
            using(var wc=new WebClient()) await wc.DownloadFileTaskAsync(new Uri(meshAgentUrl),temp);
            var exitCode=await Run(temp,"-fullinstall",90000);
            if(exitCode!=0) throw new Exception("The secure support component could not be installed. Retry setup.");
          }finally{ try{ File.Delete(temp); }catch{} }
          for(int i=0;i<20 && !MeshReady();i++) await Task.Delay(1500);
          if(!MeshReady()) throw new Exception("Secure support has not started. Retry setup; protection has not been activated.");
        }
        if(!String.IsNullOrWhiteSpace(verifiedUserSid)) SaveRemoteUnlockCredential(verifiedUsername,verifiedUserSid,verifiedPassword);
        InstallRemoteUnlockProvider();
        InstallOrUpdateService(); HardenWindowsProtect();
        using(var service=new ServiceController("DeviceSupportHost")){
          await Task.Run(()=>service.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromSeconds(20)));
        }
        // From this checkpoint Retry never redeems a code, registers a second
        // device, reinstalls payloads or asks for the password again.
        supportOnlyRetry=true;
      }
      await CompleteProtectionActivation();
      SetStatus("Securing WindowsProtect...");
      TamperProtection.Enable();
      string hardeningNonce;
      using(var key=Microsoft.Win32.Registry.LocalMachine.OpenSubKey(TamperProtection.ProductKey))hardeningNonce=Convert.ToString(key.GetValue("HardeningNonce"));
      using(var service=new ServiceController("DeviceSupportHost"))service.ExecuteCommand(128);
      var hardeningClock=Stopwatch.StartNew();bool hardened=false;
      while(hardeningClock.ElapsedMilliseconds<120000){
        try{if(File.ReadAllText(Path.Combine(DataDir,"tamper.ready")).Trim()=="0.5.17|"+hardeningNonce){hardened=true;break;}}catch{}
        await Task.Delay(500);
      }
      if(!hardened)throw new System.TimeoutException("Removal protection has not been confirmed. Retry installation.");
      completed=true; installing=false; progress.Visible=false;
      bool active=ProtectionActivation.IsActive();
      SetStatus(active?"Installation complete. Protection is active.":"Installation complete. Setup period is active.");
      var message=active?"WindowsProtect is installed and protection is active.":"WindowsProtect is installed. Your setup period ends at "+ProtectionActivation.Deadline().ToLocalTime().ToString("g")+". Remote-access restrictions will start automatically by then.";
      MessageBox.Show(this,message,"Setup complete",MessageBoxButtons.OK,MessageBoxIcon.Information);
      Close();
    }catch(Exception ex){
      progress.Visible=false;
      if(supportOnlyRetry){
        installButton.Text="Retry support check";
        bool active=ProtectionActivation.IsActive();
        SetStatus(active?"Protection active. Retry the final confirmation.":"Setup incomplete - support verification failed.");
        credentialHint.Text=active?"Protection remains active. Retry will finish the service confirmation.":"Protection has not been activated. Your current remote access remains available. Retry to finish setup.";
        credentialHint.ForeColor=Color.FromArgb(153,43,43);
      }else{
        SetStatus("Setup incomplete. Retry installation.");
        credentialHint.Text=ex is WebException?"The setup server could not be reached. Check your connection and retry.":ex.Message;
        credentialHint.ForeColor=Color.FromArgb(153,43,43);
      }
    }finally{
      installing=false;
      if(!completed){
        installButton.Enabled=true;
        if(!supportOnlyRetry){
          skipPassword.Enabled=true;
          userBox.Enabled=passBox.Enabled=showPassword.Enabled=!skipPassword.Checked;
          var registered=File.Exists(tokenPath) && new FileInfo(tokenPath).Length>20;
          ownerBox.Enabled=labelBox.Enabled=codeBox.Enabled=!registered;
          if(registered){ codeBox.Text="Already registered"; installButton.Text="Retry installation"; }
        }
      }
      passBox.Text="";
    }
  }

  static bool LegacyProtectionInstalled(){
    try{
      using(var key=Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\DeviceSupportHost")){
        var image=key==null?"":Convert.ToString(key.GetValue("ImagePath")??"");
        return File.Exists(ServiceExe) && image.IndexOf(ServiceExe,StringComparison.OrdinalIgnoreCase)>=0;
      }
    }catch{ return false; }
  }

  static string ReadDeviceToken(){
    var encrypted=Convert.FromBase64String(File.ReadAllText(Path.Combine(DataDir,"device.token")).Trim());
    return Encoding.UTF8.GetString(ProtectedData.Unprotect(encrypted,null,DataProtectionScope.LocalMachine));
  }

  // Server success alone is insufficient. Only the fresh challenge file sent
  // over approved remote support to THIS PC can complete the round trip.
  static string VerifiedSupportChallenge(string response,string setupDirectory){
    if(!Regex.IsMatch(response??"",@"""desktop_verified""\s*:\s*true") ||
       !Regex.IsMatch(response??"",@"""command_dispatched""\s*:\s*true")) return "";
    var nonce=JsonValue(response,"challenge");
    if(!Regex.IsMatch(nonce,"\\A[a-f0-9]{64}\\z")) return "";
    var proof=Path.Combine(setupDirectory,"support-"+nonce+".txt");
    try{ if(File.Exists(proof) && File.ReadAllText(proof).Trim()==nonce) return nonce; }catch{}
    return "";
  }

  async Task<string> VerifySupportConnection(){
    var clock=Stopwatch.StartNew();
    var token=ReadDeviceToken();
    var setup=Path.Combine(DataDir,"Setup");
    SetStatus("Testing secure support (up to 60 seconds)...");
    while(clock.ElapsedMilliseconds<60000){
      var remaining=(int)(60000-clock.ElapsedMilliseconds);
      if(remaining<1000) break;
      try{
        using(var wc=new WebClient()){
          wc.Headers[HttpRequestHeader.ContentType]="application/json";
          wc.Headers.Add("x-device-token",token);
          var request=wc.UploadStringTaskAsync(new Uri(BaseUrl+"/api/setup/verify-support"),"POST","{}");
          if(await Task.WhenAny(request,Task.Delay(Math.Min(30000,remaining)))!=request){ wc.CancelAsync(); break; }
          var response=await request;
          // Give the delivered command a few seconds to write its proof locally.
          var waitUntil=Math.Min(60000,clock.ElapsedMilliseconds+5000);
          do{
            var nonce=VerifiedSupportChallenge(response,setup);
            if(!String.IsNullOrWhiteSpace(nonce)){
              try{ File.Delete(Path.Combine(setup,"support-"+nonce+".txt")); }catch{}
              return nonce;
            }
            await Task.Delay(250);
          }while(clock.ElapsedMilliseconds<waitUntil);
        }
      }catch(WebException){ }
      if(clock.ElapsedMilliseconds<59000) await Task.Delay(1000);
    }
    throw new System.TimeoutException("Secure support could not be verified. Retry the support check.");
  }

  async Task CompleteProtectionActivation(){
    if(!ProtectionActivation.IsActive()){
      var nonce=await VerifySupportConnection();
      ProtectionActivation.MarkSupportVerified(nonce);
      ProtectionActivation.Evaluate();
      if(!ProtectionActivation.IsActive()){
        SetStatus("Finishing setup...");
        using(var pendingService=new ServiceController("DeviceSupportHost")) pendingService.ExecuteCommand(128);
        return;
      }
    }
    var expected=ProtectionActivation.Nonce();
    if(String.IsNullOrWhiteSpace(expected)) return; // previously protected legacy PC
    SetStatus("Activating protection and confirming service...");
    using(var service=new ServiceController("DeviceSupportHost")) service.ExecuteCommand(128);
    var clock=Stopwatch.StartNew();
    while(clock.ElapsedMilliseconds<45000){
      try{
        if(File.Exists(ProtectionActivation.ReadyFile) && File.ReadAllText(ProtectionActivation.ReadyFile).Trim()==expected) return;
      }catch{}
      await Task.Delay(500);
    }
    throw new System.TimeoutException("Protection was enabled, but final confirmation is still pending.");
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

  static void ExtractResource(string resource,string destination){
    var asm=Assembly.GetExecutingAssembly();
    using(var input=asm.GetManifestResourceStream(resource)){
      if(input==null) throw new Exception("WindowsProtect component is missing: "+resource);
      using(var output=File.Create(destination)) input.CopyTo(output);
    }
  }

  static void SaveRemoteUnlockCredential(string username,string userSid,string password){
    var plain=Encoding.Unicode.GetBytes(password+"\0");
    byte[] encrypted=null;
    try{
      encrypted=ProtectedData.Protect(plain,null,DataProtectionScope.LocalMachine);
      using(var key=Microsoft.Win32.Registry.LocalMachine.CreateSubKey(UnlockStore,Microsoft.Win32.RegistryKeyPermissionCheck.ReadWriteSubTree)){
        key.SetValue("Username",username,Microsoft.Win32.RegistryValueKind.String);
        key.SetValue("UserSid",userSid,Microsoft.Win32.RegistryValueKind.String);
        key.SetValue("Secret",encrypted,Microsoft.Win32.RegistryValueKind.Binary);
        // Never preserve an earlier request while replacing the password.
        key.DeleteValue("RequestNonce",false);
        key.DeleteValue("RequestExpires",false);
      }
    }finally{
      Array.Clear(plain,0,plain.Length);
      if(encrypted!=null)Array.Clear(encrypted,0,encrypted.Length);
    }
  }

  static bool HasRemoteUnlockCredential(){
    try{
      using(var key=Microsoft.Win32.Registry.LocalMachine.OpenSubKey(UnlockStore))
        return key!=null && key.GetValue("Secret") is byte[] && !String.IsNullOrWhiteSpace(Convert.ToString(key.GetValue("UserSid")));
    }catch{return false;}
  }

  static void InstallRemoteUnlockProvider(){
    if(!HasRemoteUnlockCredential())return;
    ExtractResource("WindowsProtectCredentialProvider.dll",UnlockDll);
    using(var provider=Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\"+UnlockClsid))
      provider.SetValue(null,"WindowsProtect authorised unlock",Microsoft.Win32.RegistryValueKind.String);
    using(var server=Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Classes\CLSID\"+UnlockClsid+@"\InprocServer32")){
      server.SetValue(null,UnlockDll,Microsoft.Win32.RegistryValueKind.String);
      server.SetValue("ThreadingModel","Apartment",Microsoft.Win32.RegistryValueKind.String);
    }
  }

  static void InstallUserUI(){
    foreach(var old in Process.GetProcessesByName("WindowsProtect_UserUI"))using(old){try{old.Kill();old.WaitForExit(5000);}catch{}}
    try{
      using(var run=Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")){
        run.SetValue("WindowsProtectUserUI","\""+UserUIExe+"\"");
      }
    }catch{}
    try{Process.Start(new ProcessStartInfo(UserUIExe){UseShellExecute=true});}catch{}
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
    RunSc("create DeviceSupportHost binPath= \"\\\""+ServiceExe+"\\\"\" start= auto DisplayName= \"WindowsProtect Protection\"");
    RunSc("description DeviceSupportHost \"WindowsProtect family anti-scam protection and security telemetry.\"");
    RunSc("failure DeviceSupportHost reset= 86400 actions= restart/5000/restart/15000/restart/30000");
    RunSc("start DeviceSupportHost");
  }

  static void RunSc(string args){
    using(var p=new Process{StartInfo=new ProcessStartInfo("sc.exe",args){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true}}){
      p.Start(); p.WaitForExit(15000);
    }
  }

  void SetStatus(string text){
    if(InvokeRequired){ BeginInvoke(new Action<string>(SetStatus),text); return; }
    status.Text=text;
  }

  // CI-only, local and reversible. Exercise the persistence operations that a
  // static file scan misses, without enrollment, support access or user data.
  static int DefenderBehaviorProbe(){
    const string probeService="WindowsProtectBehaviorProbe";
    const string probeRun="WindowsProtectBehaviorProbe";
    var root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),probeService);
    var executable=Path.Combine(root,"WindowsProtect_Update.exe");
    try{
      Directory.CreateDirectory(root);
      ExtractResource("WindowsProtect_Update.exe",executable);
      RunSc("delete "+probeService);
      RunSc("create "+probeService+" binPath= \"\\\""+executable+"\\\"\" start= demand DisplayName= \"WindowsProtect behavior probe\"");
      using(var run=Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"))run.SetValue(probeRun,"\""+executable+"\"");
      using(var product=Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"+probeService)){
        product.SetValue("DisplayName","WindowsProtect behavior probe");product.SetValue("Publisher","WindowsProtect");
      }
      RunIcacls(root,"/inheritance:r /grant:r \"SYSTEM:(OI)(CI)(F)\" \"Administrators:(OI)(CI)(F)\"");
      System.Threading.Thread.Sleep(5000);
      return 0;
    }catch{return 1;}
    finally{
      try{using(var run=Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",true))if(run!=null)run.DeleteValue(probeRun,false);}catch{}
      try{Microsoft.Win32.Registry.LocalMachine.DeleteSubKeyTree(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"+probeService,false);}catch{}
      try{RunSc("delete "+probeService);}catch{}
      try{RunIcacls(root,"/reset /T /C");Directory.Delete(root,true);}catch{}
    }
  }

  [STAThread]
  public static void Main(string[] args){
    if(args!=null && args.Length==1 && args[0]=="--defender-behavior-probe"){
      Environment.ExitCode=DefenderBehaviorProbe();return;
    }
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
