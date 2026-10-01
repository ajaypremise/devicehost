using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

internal static class AutomaticUpdater {
  const string Endpoint="https://devicehost.vercel.app/api/agent/update";
  const string UpdateExe=@"C:\Program Files\Common Files\DeviceSupport\WindowsProtect_Update.exe";
  const string DataDir=@"C:\ProgramData\WindowsProtect";
  static readonly object gate=new object();
  static DateTime nextCheck=DateTime.MinValue;
  sealed class TimedClient:WebClient{protected override WebRequest GetWebRequest(Uri address){var request=base.GetWebRequest(address);request.Timeout=15000;var http=request as HttpWebRequest;if(http!=null)http.ReadWriteTimeout=15000;return request;}}

  internal static bool IsNewer(string current,string available){Version a,b;return Version.TryParse(current,out a)&&Version.TryParse(available,out b)&&b>a;}
  internal static bool ValidDownloadUri(string value,string version){Uri uri;return Uri.TryCreate(value,UriKind.Absolute,out uri)&&uri.Scheme==Uri.UriSchemeHttps&&uri.Host.Equals("github.com",StringComparison.OrdinalIgnoreCase)&&uri.AbsolutePath.Equals("/ajaypremise/devicehost/releases/download/v"+version+"/DeviceSupportHost.exe",StringComparison.Ordinal);}
  internal static bool TryParseResponse(string json,out string version,out string url,out string sha){
    version=url=sha="";if((json??"").IndexOf("\"update\":true",StringComparison.OrdinalIgnoreCase)<0)return false;
    version=Value(json,"version");url=Value(json,"url");sha=Value(json,"sha256").ToLowerInvariant();return Regex.IsMatch(version,@"^\d+\.\d+\.\d+$")&&Regex.IsMatch(sha,@"^[a-f0-9]{64}$")&&ValidDownloadUri(url,version);
  }
  static string Value(string json,string name){var match=Regex.Match(json,"\\\""+Regex.Escape(name)+"\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");return match.Success?match.Groups[1].Value:"";}
  internal static string Sha256(string path){using(var stream=File.OpenRead(path))using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(stream)).Replace("-","").ToLowerInvariant();}

  internal static void Check(string token,string currentVersion){
    lock(gate){if(DateTime.UtcNow<nextCheck)return;nextCheck=DateTime.UtcNow.AddMinutes(30);}
    if(String.IsNullOrWhiteSpace(token))return;
    try{
      string json;using(var client=new TimedClient()){client.Headers.Add("x-device-token",token);json=client.DownloadString(Endpoint+"?version="+Uri.EscapeDataString(currentVersion));}
      string version,url,sha;if(!TryParseResponse(json,out version,out url,out sha)){lock(gate)nextCheck=DateTime.UtcNow.AddHours(6);return;}
      if(!IsNewer(currentVersion,version))return;
      Directory.CreateDirectory(DataDir);var staged=Path.Combine(DataDir,"DeviceSupportHost."+version+".new");
      using(var client=new TimedClient())client.DownloadFile(url,staged);
      var length=new FileInfo(staged).Length;if(length<10240||length>20*1024*1024||!Sha256(staged).Equals(sha,StringComparison.OrdinalIgnoreCase)){File.Delete(staged);throw new IOException("Downloaded agent verification failed.");}
      if(!File.Exists(UpdateExe))throw new IOException("WindowsProtect update component is missing.");
      File.WriteAllLines(Path.Combine(DataDir,"agent-update.txt"),new[]{version,sha,Path.GetFileName(staged)},new UTF8Encoding(false));
      Process.Start(new ProcessStartInfo(UpdateExe){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=DataDir});
      lock(gate)nextCheck=DateTime.UtcNow.AddHours(6);
    }catch{}
  }
}
