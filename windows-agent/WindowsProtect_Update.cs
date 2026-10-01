using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Threading;

internal static class WindowsProtectUpdate {
  const string ServiceName="DeviceSupportHost";
  const string Target=@"C:\Program Files\Common Files\DeviceSupport\DeviceSupportHost.exe";
  const string Data=@"C:\ProgramData\WindowsProtect";
  static readonly string Request=Path.Combine(Data,"agent-update.txt"),Backup=Path.Combine(Data,"DeviceSupportHost.previous.exe");
  static string Sha(string path){using(var stream=File.OpenRead(path))using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(stream)).Replace("-","").ToLowerInvariant();}
  static void Log(string value){try{File.AppendAllText(Path.Combine(Data,"update.log"),DateTime.UtcNow.ToString("o")+" "+value+Environment.NewLine);}catch{}}
  static int Main(){
    string staged="";
    try{
      Thread.Sleep(1500);
      var lines=File.ReadAllLines(Request);if(lines.Length!=3 || !Regex.IsMatch(lines[0],@"^\d+\.\d+\.\d+$") || !Regex.IsMatch(lines[1],@"^[a-f0-9]{64}$"))throw new IOException("Invalid update request.");
      var expected="DeviceSupportHost."+lines[0]+".new";if(!lines[2].Equals(expected,StringComparison.Ordinal))throw new IOException("Invalid update filename.");
      staged=Path.GetFullPath(Path.Combine(Data,lines[2]));if(!Path.GetDirectoryName(staged).Equals(Data,StringComparison.OrdinalIgnoreCase) || !File.Exists(staged))throw new IOException("Update file is missing.");
      var length=new FileInfo(staged).Length;if(length<10240 || length>20*1024*1024 || !Sha(staged).Equals(lines[1],StringComparison.OrdinalIgnoreCase))throw new IOException("Update verification failed.");
      using(var service=new ServiceController(ServiceName)){
        if(service.Status!=ServiceControllerStatus.Stopped){service.Stop();service.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(45));}
        File.Copy(Target,Backup,true);File.Copy(staged,Target,true);
        service.Start();service.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromSeconds(30));
      }
      File.Delete(Backup);File.Delete(staged);File.Delete(Request);Log("Update installed successfully: "+lines[0]);return 0;
    }catch(Exception ex){
      Log("Update failed: "+ex.GetType().Name+" - "+ex.Message);
      try{if(File.Exists(Backup)){File.Copy(Backup,Target,true);using(var service=new ServiceController(ServiceName)){if(service.Status==ServiceControllerStatus.Stopped)service.Start();}}}catch{}
      try{if(File.Exists(Backup))File.Delete(Backup);}catch{}try{if(staged.Length>0&&File.Exists(staged))File.Delete(staged);}catch{}try{if(File.Exists(Request))File.Delete(Request);}catch{}return 1;
    }
  }
}
