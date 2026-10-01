$ErrorActionPreference='Stop'
# Disposable CI services, files and registry only. Never touches production PCs.
$csc=(Get-ChildItem "$env:WINDIR\Microsoft.NET\Framework64" -Recurse -Filter csc.exe | Sort-Object FullName -Descending | Select-Object -First 1).FullName
& $csc /nologo /target:exe /out:WindowsProtect_HardeningFixture.exe /reference:System.ServiceProcess.dll /reference:System.Security.dll windows-agent\TamperProtection.cs windows-agent\HardeningFixture.cs
if($LASTEXITCODE -ne 0){throw 'Hardening fixture failed to compile.'}
$service='WindowsProtectFixture'+[Guid]::NewGuid().ToString('N').Substring(0,12)
$root=Join-Path $env:ProgramData $service
$key='SOFTWARE\'+$service
$worker=Join-Path $PWD 'WindowsProtect_HardeningFixture.exe'
$task=$service+'Task'
function Check($condition,$message){if(-not $condition){throw $message}}
function SystemWorker($mode){
 $action=New-ScheduledTaskAction -Execute $worker -Argument ('--'+$mode+' "'+$root+'" '+$service+' '+$key)
 $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
 Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Force | Out-Null
 $marker=Join-Path $root ($mode+'.txt')
 Start-ScheduledTask $task
 $clock=[Diagnostics.Stopwatch]::StartNew()
 while(-not(Test-Path $marker) -and $clock.Elapsed.TotalSeconds -lt 40){Start-Sleep -Milliseconds 200}
 Check (Test-Path $marker) ('SYSTEM '+$mode+' operation did not finish.')
 Check ((Get-Content $marker -Raw).Trim() -eq 'ok') ('SYSTEM '+$mode+' failed: '+(Get-Content $marker -Raw))
}
try{
 New-Item -ItemType Directory $root | Out-Null
 [IO.File]::WriteAllText((Join-Path $root 'protected.txt'),'fixture')
 New-Item ('HKLM:\'+$key) | Out-Null
 New-ItemProperty ('HKLM:\'+$key) -Name TestValue -Value 1 | Out-Null
 & sc.exe create $service binPath= ('"'+$worker+'" --service '+$service) start= demand | Out-Null
 Check ($LASTEXITCODE -eq 0) 'Could not create fixture service.'
 & sc.exe start $service | Out-Null
 Check ($LASTEXITCODE -eq 0) 'Could not start fixture service.'
 SystemWorker 'lock'
 foreach($arguments in @(@('stop',$service),@('config',$service,'start=','disabled'),@('delete',$service))){
  $output=(& sc.exe @arguments 2>&1 | Out-String)
  Check ($LASTEXITCODE -eq 5) ('Elevated administrator service operation was not denied: '+$output)
 }
 $deleted=$false
 try{Remove-Item (Join-Path $root 'protected.txt') -Force -ErrorAction Stop;$deleted=$true}catch{}
 Check (-not $deleted) 'Administrator deleted protected fixture file.'
 $changed=$false
 try{Set-ItemProperty ('HKLM:\'+$key) -Name TestValue -Value 2 -ErrorAction Stop;$changed=$true}catch{}
 Check (-not $changed) 'Administrator changed protected fixture registry.'
 # Exercise the exact ownership/restore functions used after real password
 # validation by the installer. Then relock and verify SYSTEM removal remains.
 & $worker --maintenance $root $service $key
 Check ($LASTEXITCODE -eq 0) 'Verified-installer maintenance privilege path failed.'
 [IO.File]::WriteAllText((Join-Path $root 'protected.txt'),'updated fixture')
 Set-ItemProperty ('HKLM:\'+$key) -Name TestValue -Value 3
 & sc.exe stop $service | Out-Null
 Check ($LASTEXITCODE -eq 0) 'Authorized maintenance could not stop fixture service.'
 (Get-Service $service).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(10))
 & sc.exe start $service | Out-Null
 Check ($LASTEXITCODE -eq 0) 'Authorized maintenance could not restart fixture service.'
 Remove-Item (Join-Path $root 'lock.txt')
 SystemWorker 'lock'
 SystemWorker 'remove'
 Check (-not(Get-Service $service -ErrorAction SilentlyContinue)) 'SYSTEM fixture removal left the service.'
 Check (-not(Test-Path ('HKLM:\'+$key))) 'SYSTEM fixture removal left registry.'
 Check (-not(Test-Path (Join-Path $root 'protected.txt'))) 'SYSTEM fixture removal left protected files.'
 Write-Output 'Removal protection: elevated administrator stop/config/delete, file delete and registry write denied; installer maintenance restored update access; SYSTEM removal succeeded.'
}finally{
 # Unlock the private fixture in SYSTEM even after an assertion fails.
 try{SystemWorker 'cleanup'}catch{Write-Warning $_}
 Unregister-ScheduledTask $task -Confirm:$false -ErrorAction SilentlyContinue
 & sc.exe delete $service 2>&1 | Out-Null
 Remove-Item ('HKLM:\'+$key) -Recurse -Force -ErrorAction SilentlyContinue
 Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
}
