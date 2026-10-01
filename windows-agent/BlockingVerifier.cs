using System;
using System.Diagnostics;
using System.IO;
internal static class BlockingVerifier {
 static void Check(bool value,string message){if(!value)throw new Exception(message);}
 static int Main(string[] args){
  if(args.Length!=2)return 1;
  try{
   foreach(var name in RemoteToolPolicy.Names)Check(RemoteToolPolicy.KnownName(name),"Missing known alias: "+name);
   Check(RemoteToolPolicy.KnownName("ScreenConnect.Client.abcd"),"ScreenConnect instance alias missed.");
   Check(RemoteToolPolicy.KnownMetadata("TeamViewer",null,null,null),"Product identity missed.");
   Check(RemoteToolPolicy.KnownMetadata(null,null,"UltraViewer.exe",null),"Original filename missed.");
   foreach(var name in new[]{"Microsoft Word","Google Chrome","Python","Windows PowerShell","Visual Studio Code","ConnectWise Manage","WindowsProtect"})Check(!RemoteToolPolicy.KnownMetadata(name,name,"ordinary.exe",null),"Ordinary product falsely blocked: "+name);
   Check(!RemoteToolPolicy.ApprovedPath(Path.Combine(Path.GetDirectoryName(args[0]),"meshagent.exe")),"Unregistered support binary was allowed.");
   using(var remote=Process.Start(new ProcessStartInfo(args[0]){UseShellExecute=false,CreateNoWindow=true})){
    System.Threading.Thread.Sleep(250);
    Check(!RemoteToolPolicy.CheckAndBlock(remote,false),"Renamed fixture matched a generic process name.");
    Check(RemoteToolPolicy.CheckAndBlock(remote,true),"Renamed remote fixture escaped executable identity check.");
    Check(remote.WaitForExit(3000),"Renamed remote fixture did not stop.");
   }
   using(var ordinary=Process.Start(new ProcessStartInfo(args[1]){UseShellExecute=false,CreateNoWindow=true})){
    try{System.Threading.Thread.Sleep(250);Check(!RemoteToolPolicy.CheckAndBlock(ordinary,true),"Ordinary fixture was blocked.");Check(!ordinary.HasExited,"Ordinary fixture exited unexpectedly.");}finally{if(!ordinary.HasExited)ordinary.Kill();}
   }
   var alias=Path.Combine(Path.GetDirectoryName(args[1]),"UltraViewer.exe");File.Copy(args[1],alias,true);
   try{using(var named=Process.Start(new ProcessStartInfo(alias){UseShellExecute=false,CreateNoWindow=true})){
    System.Threading.Thread.Sleep(250);Check(RemoteToolPolicy.CheckAndBlock(named,false),"Fast alias enforcement missed UltraViewer.");Check(named.WaitForExit(3000),"Named fixture did not stop.");
   }}finally{File.Delete(alias);}
   Console.WriteLine("Remote-tool policy: known aliases, renamed executable identity and ScreenConnect variants blocked; ordinary application and approved-path checks passed; only disposable fixture processes touched.");return 0;
  }catch(Exception ex){Console.Error.WriteLine(ex);return 1;}
 }
}
