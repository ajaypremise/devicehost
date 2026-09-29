using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

class WindowsProtectTest {
  const string BaseUrl="https://devicehost.vercel.app";
  static string Esc(string s){return (s??"").Replace("\\","\\\\").Replace("\"","\\\"");}
  static void Main(){
    Console.Title="WindowsProtect Test";
    Console.WriteLine("WindowsProtect v0.3 - DeviceHost enrollment test\n");
    Console.Write("Person/device owner name: ");
    var person=Console.ReadLine();
    if(String.IsNullOrWhiteSpace(person)) person="Test User";
    Console.Write("Device label [Kamatera Test]: ");
    var label=Console.ReadLine();
    if(String.IsNullOrWhiteSpace(label)) label="Kamatera Test";
    Console.Write("DEVICE_ENROLLMENT_KEY: ");
    var key=Console.ReadLine();
    if(String.IsNullOrWhiteSpace(key)){Console.WriteLine("Enrollment key required."); Console.ReadKey(); return;}
    try{
      ServicePointManager.SecurityProtocol=SecurityProtocolType.Tls12;
      var body="{\"person_name\":\""+Esc(person)+"\",\"device_name\":\""+Esc(label)+"\",\"computer_name\":\""+Esc(Environment.MachineName)+"\",\"protection_status\":\"pending\",\"migration_status\":\"not_started\",\"os_version\":\""+Esc(Environment.OSVersion.VersionString)+"\",\"agent_version\":\"0.3.0-test\"}";
      string response;
      using(var wc=new WebClient()){
        wc.Headers[HttpRequestHeader.ContentType]="application/json";
        wc.Headers.Add("x-enrollment-key",key);
        response=wc.UploadString(BaseUrl+"/api/enroll","POST",body);
      }
      var tm=Regex.Match(response,"\"device_token\"\\s*:\\s*\"([^\"]+)\"");
      var cm=Regex.Match(response,"\"device_code\"\\s*:\\s*\"([^\"]+)\"");
      if(!tm.Success) throw new Exception("DeviceHost did not return a device token.");
      var token=tm.Groups[1].Value;
      var hb="{\"computer_name\":\""+Esc(Environment.MachineName)+"\",\"protection_status\":\"protected\",\"os_version\":\""+Esc(Environment.OSVersion.VersionString)+"\",\"agent_version\":\"0.3.0-test\",\"security_posture\":\"unknown\"}";
      using(var wc=new WebClient()){
        wc.Headers[HttpRequestHeader.ContentType]="application/json";
        wc.Headers.Add("x-device-token",token);
        wc.UploadString(BaseUrl+"/api/heartbeat","POST",hb);
      }
      var data=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"WindowsProtect");
      Directory.CreateDirectory(data);
      var protectedBytes=ProtectedData.Protect(Encoding.UTF8.GetBytes(token),null,DataProtectionScope.LocalMachine);
      File.WriteAllText(Path.Combine(data,"device.token"),Convert.ToBase64String(protectedBytes));
      Console.WriteLine("\nSUCCESS");
      if(cm.Success) Console.WriteLine("Device ID: "+cm.Groups[1].Value);
      Console.WriteLine("Enrollment and first heartbeat completed.");
      Console.WriteLine("Check https://devicehost.vercel.app");
    }catch(WebException e){
      string detail=e.Message;
      try{using(var r=new StreamReader(e.Response.GetResponseStream())) detail=r.ReadToEnd();}catch{}
      Console.WriteLine("\nFAILED: "+detail);
    }catch(Exception e){Console.WriteLine("\nFAILED: "+e.Message);}
    Console.WriteLine("\nPress any key to close.");
    Console.ReadKey();
  }
}