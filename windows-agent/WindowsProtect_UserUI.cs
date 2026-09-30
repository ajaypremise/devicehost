using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows.Forms;

public sealed class WindowsProtectUserUI : ApplicationContext {
  const string DataDir=@"C:\ProgramData\WindowsProtect";
  const string CommandFile=@"C:\ProgramData\WindowsProtect\ui-command.txt";
  readonly System.Windows.Forms.Timer timer=new System.Windows.Forms.Timer();

  public WindowsProtectUserUI(){
    timer.Interval=750;
    timer.Tick+=(s,e)=>CheckCommand();
    timer.Start();
    CheckCommand();
  }

  static string Decode(string value){
    try{return Encoding.UTF8.GetString(Convert.FromBase64String(value??""));}
    catch{return "";}
  }

  void CheckCommand(){
    try{
      if(!File.Exists(CommandFile)) return;
      var text=File.ReadAllText(CommandFile,Encoding.UTF8);
      try{File.Delete(CommandFile);}catch{}
      var p=text.Split('|');
      if(p.Length<3) return;

      if(p[0]=="url"){
        var url=Decode(p[1]);
        Uri uri;
        if(Uri.TryCreate(url,UriKind.Absolute,out uri) && (uri.Scheme=="http"||uri.Scheme=="https")){
          Process.Start(new ProcessStartInfo(url){UseShellExecute=true});
        }
        return;
      }

      if(p[0]=="message" && p.Length>=6){
        var title=Decode(p[1]);
        var message=Decode(p[2]);
        var size=(p[3]=="compact"||p[3]=="large")?p[3]:"standard";
        var placement=(p[4]=="top_right"||p[4]=="bottom_right")?p[4]:"center";
        ShowMessage(title,message,size,placement);
      }
    }catch{}
  }

  static void ShowMessage(string title,string message,string size,string placement){
    int w=520,h=240;
    if(size=="compact"){w=420;h=180;}
    else if(size=="large"){w=640;h=320;}

    using(var f=new Form()){
      f.Text=String.IsNullOrWhiteSpace(title)?"WindowsProtect":title;
      f.ClientSize=new Size(w,h);
      f.FormBorderStyle=FormBorderStyle.FixedDialog;
      f.MaximizeBox=false;
      f.MinimizeBox=false;
      f.ShowInTaskbar=true;
      f.TopMost=true;
      f.StartPosition=FormStartPosition.Manual;
      f.BackColor=Color.White;
      f.Font=new Font("Segoe UI",10);

      var wa=Screen.PrimaryScreen.WorkingArea;
      int x,y;
      if(placement=="top_right"){x=wa.Right-w-24;y=wa.Top+24;}
      else if(placement=="bottom_right"){x=wa.Right-w-24;y=wa.Bottom-h-24;}
      else{x=wa.Left+Math.Max(0,(wa.Width-w)/2);y=wa.Top+Math.Max(0,(wa.Height-h)/2);}
      f.Location=new Point(x,y);

      var header=new Panel{Dock=DockStyle.Top,Height=56,BackColor=Color.FromArgb(17,24,39)};
      var headerText=new Label{
        Text=f.Text,Dock=DockStyle.Fill,ForeColor=Color.White,
        Font=new Font("Segoe UI Semibold",14),TextAlign=ContentAlignment.MiddleLeft,
        Padding=new Padding(18,0,18,0)
      };
      header.Controls.Add(headerText);

      var body=new Label{
        Text=message,Left=20,Top=78,Width=w-40,Height=h-142,
        ForeColor=Color.FromArgb(31,41,55),Font=new Font("Segoe UI",10.5f),
        TextAlign=ContentAlignment.TopLeft,AutoEllipsis=true
      };

      var ok=new Button{
        Text="OK",Width=92,Height=34,Left=w-112,Top=h-52,
        FlatStyle=FlatStyle.Flat,BackColor=Color.FromArgb(37,99,235),
        ForeColor=Color.White,Font=new Font("Segoe UI Semibold",9)
      };
      ok.FlatAppearance.BorderSize=0;
      ok.Click+=(s,e)=>f.Close();

      f.Controls.Add(header);
      f.Controls.Add(body);
      f.Controls.Add(ok);
      f.AcceptButton=ok;
      f.ShowDialog();
    }
  }

  [STAThread]
  public static void Main(){
    bool created;
    using(var mutex=new Mutex(true,"WindowsProtectUserUI",out created)){
      if(!created) return;
      Directory.CreateDirectory(DataDir);
      Application.EnableVisualStyles();
      Application.SetCompatibleTextRenderingDefault(false);
      Application.Run(new WindowsProtectUserUI());
    }
  }
}
