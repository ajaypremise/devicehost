using System;
using System.IO;
using System.Text.RegularExpressions;
using Microsoft.Win32;

// HKLM is writable only by administrators/SYSTEM. State survives setup retries
// and reboots. Once the service sees active, it also latches it in memory.
internal static class ProtectionActivation {
  internal const string KeyPath=@"SOFTWARE\WindowsProtect";
  internal const string ReadyFile=@"C:\ProgramData\WindowsProtect\protection.ready";

  internal static bool IsActive(){
    using(var key=Registry.LocalMachine.OpenSubKey(KeyPath)){
      return key!=null && String.Equals(Convert.ToString(key.GetValue("ActivationState")),"active",StringComparison.Ordinal);
    }
  }

  internal static void Initialize(bool legacyProtected){
    using(var key=Registry.LocalMachine.CreateSubKey(KeyPath)){
      var state=Convert.ToString(key.GetValue("ActivationState")??"");
      if(state=="active" || state=="pending") return;
      key.SetValue("ActivationState",legacyProtected?"active":"pending",RegistryValueKind.String);
    }
  }

  internal static void Activate(string nonce){
    if(!Regex.IsMatch(nonce??"","\\A[a-f0-9]{64}\\z")) throw new ArgumentException("Invalid activation proof.");
    using(var key=Registry.LocalMachine.CreateSubKey(KeyPath)){
      key.SetValue("ActivationNonce",nonce,RegistryValueKind.String);
      key.SetValue("ActivationState","active",RegistryValueKind.String);
    }
  }

  internal static string Nonce(){
    using(var key=Registry.LocalMachine.OpenSubKey(KeyPath)){
      return key==null?"":Convert.ToString(key.GetValue("ActivationNonce")??"");
    }
  }

  internal static void ConfirmServiceReady(){
    using(var key=Registry.LocalMachine.OpenSubKey(KeyPath)){
      var nonce=key==null?"":Convert.ToString(key.GetValue("ActivationNonce")??"");
      if(Regex.IsMatch(nonce,"\\A[a-f0-9]{64}\\z")) File.WriteAllText(ReadyFile,nonce);
    }
  }
}
