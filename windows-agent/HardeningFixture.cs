using System;
using System.IO;
using System.ServiceProcess;
using System.Threading;
using Microsoft.Win32;

internal sealed class HardeningFixture : ServiceBase {
  HardeningFixture(string name){ServiceName=name;CanStop=true;AutoLog=false;}
  static int Main(string[] args){
    if(args.Length==2 && args[0]=="--service"){ServiceBase.Run(new HardeningFixture(args[1]));return 0;}
    if(args.Length!=4)return 1;
    var mode=args[0].Substring(2);var root=args[1];var service=args[2];var key=args[3];
    // Fixture mutation is bounded to one freshly generated, dedicated CI name.
    if(!service.StartsWith("WindowsProtectFixture") || key!="SOFTWARE\\"+service || root!=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),service))return 1;
    try{
      if(mode=="maintenance"){
        TamperProtection.EnableMaintenancePrivileges();
        TamperProtection.SetService(service,false);TamperProtection.SetRegistry(key,false);TamperProtection.SetDirectory(root,false,false);
        return 0;
      }
      if(!TamperProtection.IsSystem())return 1;
      if(mode=="lock"){
        TamperProtection.SetDirectory(root,true,false);TamperProtection.SetRegistry(key,true);TamperProtection.SetService(service,true);
      }else if(mode=="remove" || mode=="cleanup"){
        TamperProtection.SetService(service,false);TamperProtection.SetRegistry(key,false);TamperProtection.SetDirectory(root,false,false);
        using(var sc=new ServiceController(service)){
          try{if(sc.Status!=ServiceControllerStatus.Stopped){sc.Stop();sc.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(10));}}catch(InvalidOperationException){}
        }
        try{TamperProtection.Run("sc.exe","delete "+service);}catch{if(mode!="cleanup")throw;}
        Registry.LocalMachine.DeleteSubKeyTree(key,false);
        var file=Path.Combine(root,"protected.txt");if(File.Exists(file))File.Delete(file);
        for(int i=0;i<20;i++){
          using(var registry=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+service))if(registry==null)break;
          Thread.Sleep(200);
        }
      }else return 1;
      File.WriteAllText(Path.Combine(root,mode+".txt"),"ok");return 0;
    }catch(Exception ex){try{File.WriteAllText(Path.Combine(root,mode+".txt"),ex.ToString());}catch{}return 1;}
  }
}
