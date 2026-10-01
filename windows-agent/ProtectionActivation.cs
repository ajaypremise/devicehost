using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;
using Microsoft.Win32;

internal static class ProtectionActivation {
  internal const string KeyPath=@"SOFTWARE\WindowsProtect";
  internal const string ReadyFile=@"C:\ProgramData\WindowsProtect\protection.ready";
  internal const string RequestFile=@"C:\ProgramData\WindowsProtect\Setup\activation.request";
  static readonly Stopwatch clock=Stopwatch.StartNew();
  static DateTime anchor=DateTime.UtcNow;

  internal static bool IsActive(){
    using(var key=Registry.LocalMachine.OpenSubKey(KeyPath)){
      return key!=null && Convert.ToString(key.GetValue("ActivationState"))=="active";
    }
  }
  internal static void Initialize(bool legacyProtected){
    using(var key=Registry.LocalMachine.CreateSubKey(KeyPath)){
      var state=Convert.ToString(key.GetValue("ActivationState")??"");
      if(state=="active") return;
      if(state!="pending") key.SetValue("ActivationState",legacyProtected?"active":"pending");
      if(state!="pending" && legacyProtected) return;
      // A retry/repair never extends an existing window.
      if(key.GetValue("ActivationDeadlineUtc")==null){
        key.SetValue("ActivationDeadlineUtc",DateTime.UtcNow.AddHours(4).ToString("o",CultureInfo.InvariantCulture));
      }
    }
  }
  internal static DateTime Deadline(){
    using(var key=Registry.LocalMachine.OpenSubKey(KeyPath)){
      DateTime value;
      if(key!=null && DateTime.TryParse(Convert.ToString(key.GetValue("ActivationDeadlineUtc")),CultureInfo.InvariantCulture,DateTimeStyles.RoundtripKind,out value)) return value.ToUniversalTime();
      return DateTime.MinValue; // Missing/corrupt deadline fails closed in service.
    }
  }
  internal static DateTime EffectiveNow(){
    using(var key=Registry.LocalMachine.CreateSubKey(KeyPath)){
      DateTime previous;
      var now=DateTime.UtcNow;
      if(DateTime.TryParse(Convert.ToString(key.GetValue("LastObservedUtc")),CultureInfo.InvariantCulture,DateTimeStyles.RoundtripKind,out previous) && previous.ToUniversalTime()>now) now=previous.ToUniversalTime();
      if(now>anchor.Add(clock.Elapsed)){ anchor=now; clock.Restart(); }
      now=anchor.Add(clock.Elapsed)>now?anchor.Add(clock.Elapsed):now;
      // Persist once per minute, and do not permit ordinary clock rollback to
      // extend the window while this process is running.
      if(previous==default(DateTime) || (now-previous.ToUniversalTime()).TotalSeconds>=60) key.SetValue("LastObservedUtc",now.ToString("o",CultureInfo.InvariantCulture));
      return now;
    }
  }
  internal static void MarkSupportVerified(string nonce){
    if(!ValidNonce(nonce)) throw new ArgumentException("Invalid support proof.");
    using(var key=Registry.LocalMachine.CreateSubKey(KeyPath)) key.SetValue("SupportVerified",1,RegistryValueKind.DWord);
  }
  internal static bool SupportVerified(){
    using(var key=Registry.LocalMachine.OpenSubKey(KeyPath)) return key!=null && Convert.ToString(key.GetValue("SupportVerified"))=="1";
  }
  internal static bool ValidNonce(string nonce){ return Regex.IsMatch(nonce??"","\\A[a-f0-9]{64}\\z"); }
  internal static void Activate(string nonce){
    if(!ValidNonce(nonce)) throw new ArgumentException("Invalid activation proof.");
    using(var key=Registry.LocalMachine.CreateSubKey(KeyPath)){
      key.SetValue("ActivationNonce",nonce); key.SetValue("ActivationState","active");
    }
  }
  internal static void Evaluate(){
    if(IsActive()) return;
    if(EffectiveNow()>=Deadline()){
      Activate(Guid.NewGuid().ToString("N")+Guid.NewGuid().ToString("N")); return;
    }
    TryActivateRequest(RequestFile);
  }
  internal static bool TryActivateRequest(string requestFile){
    if(IsActive() || !SupportVerified() || !File.Exists(requestFile)) return false;
    var nonce=File.ReadAllText(requestFile).Trim();
    if(!ValidNonce(nonce)) return false;
    var proof=Path.Combine(Path.GetDirectoryName(requestFile),"support-"+nonce+".txt");
    if(!File.Exists(proof) || File.ReadAllText(proof).Trim()!=nonce) return false;
    Activate(nonce);
    try{ File.Delete(requestFile); File.Delete(proof); }catch{}
    return true;
  }
  internal static string MigrationStatus(){
    return (SupportVerified()?"awaiting_activation:":"verifying_support:")+Deadline().ToString("o",CultureInfo.InvariantCulture);
  }
  internal static string Nonce(){
    using(var key=Registry.LocalMachine.OpenSubKey(KeyPath)) return key==null?"":Convert.ToString(key.GetValue("ActivationNonce")??"");
  }
  internal static void ConfirmServiceReady(){
    var nonce=Nonce(); if(ValidNonce(nonce)) File.WriteAllText(ReadyFile,nonce);
  }
}
