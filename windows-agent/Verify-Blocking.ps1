$ErrorActionPreference='Stop'
$csc=(Get-ChildItem "$env:WINDIR\Microsoft.NET\Framework64" -Recurse -Filter csc.exe | Sort-Object FullName -Descending | Select-Object -First 1).FullName
$root=Join-Path $env:TEMP ('wp-blocking-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $root | Out-Null
try{
 & $csc /nologo /target:exe /define:REMOTE ('/out:'+(Join-Path $root 'renamed-remote.exe')) windows-agent\BlockingFixture.cs
 if($LASTEXITCODE -ne 0){throw 'Remote fixture compilation failed.'}
 & $csc /nologo /target:exe ('/out:'+(Join-Path $root 'ordinary.exe')) windows-agent\BlockingFixture.cs
 if($LASTEXITCODE -ne 0){throw 'Ordinary fixture compilation failed.'}
 & $csc /nologo /target:exe ('/out:'+(Join-Path $root 'verify.exe')) /reference:System.ServiceProcess.dll /reference:System.Security.dll windows-agent\BlockingVerifier.cs windows-agent\RemoteToolPolicy.cs windows-agent\TamperProtection.cs
 if($LASTEXITCODE -ne 0){throw 'Policy verifier compilation failed.'}
 & (Join-Path $root 'verify.exe') (Join-Path $root 'renamed-remote.exe') (Join-Path $root 'ordinary.exe')
 if($LASTEXITCODE -ne 0){throw 'Blocking policy checks failed.'}
}finally{Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue}
