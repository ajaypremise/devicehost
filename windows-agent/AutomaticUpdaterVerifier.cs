using System;
using System.IO;
class AutomaticUpdaterVerifier{
 static void Check(bool condition,string message){if(!condition)throw new Exception(message);}
 static int Main(){
  Check(AutomaticUpdater.IsNewer("0.5.11","0.5.12"),"New version not detected");Check(!AutomaticUpdater.IsNewer("0.5.12","0.5.12"),"Equal version accepted");Check(!AutomaticUpdater.ValidDownloadUri("https://evil.example/DeviceSupportHost.exe","0.5.12"),"Untrusted update host accepted");
  string version,url,sha;var json="{\"update\":true,\"version\":\"0.5.12\",\"url\":\"https://github.com/ajaypremise/devicehost/releases/download/v0.5.12/DeviceSupportHost.exe\",\"sha256\":\""+new string('a',64)+"\"}";
  Check(AutomaticUpdater.TryParseResponse(json,out version,out url,out sha),"Valid update response rejected");Check(version=="0.5.12"&&sha.Length==64,"Update response fields incorrect");
  var file=Path.GetTempFileName();File.WriteAllText(file,"fixture");Check(AutomaticUpdater.Sha256(file)=="f16d05ec6b29248d2c61adb1e9263f78e4f7bace1b955014a2d17872cfe4064d","Hash verification failed");File.Delete(file);
  Console.WriteLine("Automatic updates: version ordering, fixed HTTPS release URL, response validation and SHA-256 verification passed.");return 0;
 }
}
