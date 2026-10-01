export function buildDeliveryScript(commandId, payload64) {
  if (!/^[a-f0-9]{32}$/.test(commandId)) throw new Error("Invalid command ID");
  if (!/^[A-Za-z0-9+/=]+$/.test(payload64)) throw new Error("Invalid command payload");
  return "$ErrorActionPreference='Stop'; $d='C:\\ProgramData\\WindowsProtect\\UI'; New-Item -ItemType Directory -Path $d -Force | Out-Null; " +
    "$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + payload64 + "')); " +
    "$c=Join-Path $d 'command-" + commandId + ".txt'; $a=Join-Path $d 'ack-" + commandId + ".txt'; " +
    "[IO.File]::WriteAllText($c,$p,[Text.Encoding]::UTF8); " +
    "$end=[DateTime]::UtcNow.AddSeconds(20); while([DateTime]::UtcNow -lt $end -and -not(Test-Path $a)){Start-Sleep -Milliseconds 250}; " +
    "if(-not(Test-Path $a)){throw 'The active Windows session did not confirm the action.'}; " +
    "$proof=[IO.File]::ReadAllText($a,[Text.Encoding]::ASCII); Remove-Item $a -Force; " +
    "if($proof -notlike '" + commandId + "|*'){throw 'Invalid PC acknowledgement.'}; 'OK'";
}
