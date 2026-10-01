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

      if(p[0]=="message" && p.Length>=5){
        var title=Decode(p[1]);
        var message=Decode(p[2]);
        var size=(p[3]=="compact"||p[3]=="large")?p[3]:"standard";
        var placement=(p[4]=="top_right"||p[4]=="bottom_right")?p[4]:"center";
        var kind=p.Length>=6&&(p[5]=="information"||p[5]=="error")?p[5]:"warning";
        ShowMessage(title,message,size,placement,kind);
      }
    }catch{}
  }

  static void ShowMessage(string title,string message,string size,string placement,string kind){
    using(var form=BuildMessage(title,message,size,placement,kind))form.ShowDialog();
  }
  internal static Form BuildMessage(string title,string message,string size,string placement,string kind){
    int w=540,h=310;
    if(size=="compact"){w=440;h=240;}
    else if(size=="large"){w=680;h=440;}

    var f=new Form();
      f.Text="WindowsProtect";
      f.ClientSize=new Size(w,h);
      f.FormBorderStyle=FormBorderStyle.FixedDialog;
      f.MaximizeBox=false;
      f.MinimizeBox=false;
      f.ShowInTaskbar=true;
      f.TopMost=true;
      f.StartPosition=FormStartPosition.Manual;
      f.BackColor=SystemColors.Window;
      f.ForeColor=SystemColors.WindowText;
      f.Font=new Font("Segoe UI",10);

      var wa=Screen.PrimaryScreen.WorkingArea;
      int x,y;
      if(placement=="top_right"){x=wa.Right-w-24;y=wa.Top+24;}
      else if(placement=="bottom_right"){x=wa.Right-w-24;y=wa.Bottom-h-24;}
      else{x=wa.Left+Math.Max(0,(wa.Width-w)/2);y=wa.Top+Math.Max(0,(wa.Height-h)/2);}
      f.Location=new Point(x,y);

      var footer=new Panel{Name="DialogFooter",Dock=DockStyle.Bottom,Height=62,BackColor=SystemColors.Control};
      var ok=new Button{
        Name="DialogOK",
        Text="OK",Width=90,Height=30,Left=w-110,Top=16,
        Anchor=AnchorStyles.Right|AnchorStyles.Bottom,UseVisualStyleBackColor=true,
        DialogResult=DialogResult.OK,AccessibleName="Close WindowsProtect message"
      };
      footer.Controls.Add(ok);f.Controls.Add(footer);f.AcceptButton=ok;f.CancelButton=ok;
      var icon=kind=="information"?SystemIcons.Information:kind=="error"?SystemIcons.Error:SystemIcons.Warning;
      f.Icon=icon;
      var picture=new PictureBox{Name="DialogIcon",Image=icon.ToBitmap(),SizeMode=PictureBoxSizeMode.CenterImage,Location=new Point(24,22),Size=new Size(40,40)};
      var heading=new Label{
        Text=String.IsNullOrWhiteSpace(title)?"WindowsProtect":title,AutoSize=false,
        Font=new Font("Segoe UI",13),Location=new Point(84,22),Size=new Size(w-108,58),ForeColor=SystemColors.WindowText
      };
      var body=new RichTextBox{
        Name="DialogMessage",
        Text=message,ReadOnly=true,BorderStyle=BorderStyle.None,BackColor=SystemColors.Window,ForeColor=SystemColors.WindowText,
        Font=f.Font,DetectUrls=false,WordWrap=true,ScrollBars=RichTextBoxScrollBars.Vertical,
        Location=new Point(84,86),Size=new Size(w-108,h-164),TabStop=false
      };
      f.Controls.Add(picture);f.Controls.Add(heading);f.Controls.Add(body);
      return f;
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
