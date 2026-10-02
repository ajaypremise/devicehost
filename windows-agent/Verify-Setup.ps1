$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$assembly = [Reflection.Assembly]::LoadFile((Join-Path $PWD 'WindowsProtect_Setup.exe'))
$form = $assembly.CreateInstance('WindowsProtectSetup')
$flags = [Reflection.BindingFlags]'Instance,NonPublic'
function Field($name) { $form.GetType().GetField($name,$flags).GetValue($form) }
function Check($condition,$message) { if (-not $condition) { throw $message } }
function Walk($control) {
  foreach ($child in $control.Controls) { $child; Walk $child }
}
try {
  $form.Show()
  [Windows.Forms.Application]::DoEvents()
  $controls = @(Walk $form)
  $button = Field 'installButton'
  $buttonBounds = $form.RectangleToClient($button.RectangleToScreen($button.ClientRectangle))
  Check ($form.ClientRectangle.Contains($buttonBounds)) 'Primary action is clipped or outside the window.'
  $checks=@($controls | Where-Object { $_ -is [Windows.Forms.CheckBox] })
  $show=@($checks | Where-Object {$_.Text -eq 'Show password'})[0]
  $skip=@($checks | Where-Object {$_.Text -eq 'Skip Windows password'})[0]
  Check ($checks.Count -eq 2 -and $null -ne $show -and $null -ne $skip) 'Installer password choices are missing or duplicated.'
  $show.Checked=$true;Check (-not (Field 'passBox').UseSystemPasswordChar) 'Show password does not reveal the field.';$show.Checked=$false
  $skip.Checked=$true
  Check (-not (Field 'userBox').Enabled -and -not (Field 'passBox').Enabled) 'Skip password did not disable credential fields.'
  Check ((Field 'credentialHint').Text -like '*skipped*') 'Skip password is not explained.'
  $skip.Checked=$false
  Check ((Field 'userBox').Enabled -and (Field 'passBox').Enabled) 'Credential fields did not return after unchecking Skip.'
  Check (-not [bool]($controls | Where-Object { $_.Text -match 'Block known scam remote-access tools' })) 'Removed installer marketing line is still visible.'
  Check (-not [bool]($controls | Where-Object { $_.Text -match 'MeshCentral|MeshControl' })) 'Internal provider name visible.'
  Check (-not [bool]($controls | Where-Object { $_.Text -match 'TEST BUILD|admin approval|dashboard activation' })) 'Internal build/approval wording visible.'
  Check ((Field 'ownerBox').Text -eq '') 'Owner placeholder submitted as text.'
  Check ((Field 'labelBox').Text -eq '') 'Device placeholder submitted as text.'
  Check ((Field 'codeBox').Text -eq '') 'Setup code placeholder submitted as text.'
  Check ((Field 'passBox').UseSystemPasswordChar) 'Password is not masked.'
  # A dashboard-prepared sidecar fills setup authorization automatically.
  $packageFile=Join-Path $PWD 'WindowsProtect_Setup.json'
  Check (-not(Test-Path $packageFile)) 'Unexpected setup sidecar on CI runner.'
  $enrollment=(Field 'codeBox').Parent;$identity=(Field 'ownerBox').Parent.Parent
  try {
    @{code='A1B2-C3D4-E5F6';owner='Mum';label='Living room';agent='Koko';expires_at=[DateTime]::UtcNow.AddMinutes(30).ToString('o')} | ConvertTo-Json -Compress | Set-Content $packageFile -Encoding UTF8
    $form.GetType().GetMethod('LoadSetupPackage',$flags).Invoke($form,@($identity,$enrollment))
    Check ((Field 'codeBox').Text -eq 'A1B2-C3D4-E5F6') 'Prepared setup code was not loaded automatically.'
    Check ((Field 'ownerBox').Text -eq 'Mum') 'Prepared owner was not loaded.'
    Check ((Field 'labelBox').Text -eq 'Living room') 'Prepared device label was not loaded.'
    Check ((Field 'assignedAgent') -eq 'Koko') 'Prepared support agent was not loaded.'
    Check (-not $enrollment.Visible) 'Prepared installer still asks the user for a manual setup code.'
    Check (-not $identity.Visible) 'Prepared installer still asks for customer or PC details.'
    (Field 'codeBox').Text=''
    @{code='A1B2-C3D4-E5F6';owner='Mum';label='Living room';agent='Koko';expires_at=[DateTime]::UtcNow.AddMinutes(-1).ToString('o')} | ConvertTo-Json -Compress | Set-Content $packageFile -Encoding UTF8
    $form.GetType().GetMethod('LoadSetupPackage',$flags).Invoke($form,@($identity,$enrollment))
    Check ((Field 'codeBox').Text -eq '') 'Expired package code was accepted.'
    Check ((Field 'status').Text -like '*expired*') 'Expired package does not explain how to recover.'
    Write-Output 'Prepared installer: one-time code and identity loaded automatically; manual code section hidden; expired package rejected.'
  } finally {
    Remove-Item $packageFile -Force
    (Field 'codeBox').Text='';(Field 'ownerBox').Text='';(Field 'labelBox').Text='';$identity.Visible=$true;$enrollment.Visible=$true
  }
  # Supply dummy identity fields and leave password blank. This must return before
  # any credential write, network enrollment, or service operation.
  (Field 'ownerBox').Text = 'Test owner'
  (Field 'labelBox').Text = 'Test PC'
  (Field 'codeBox').Text = 'TEST-CODE'
  (Field 'passBox').Text = ''
  $task = $form.GetType().GetMethod('InstallAsync',$flags).Invoke($form,@())
  $task.GetAwaiter().GetResult()
  Check ((Field 'status').Text -eq 'Enter your Windows username and password to continue.') 'Blank password was accepted.'
  Check (-not (Field 'installing')) 'Blank password started installation.'
  (Field 'passBox').Text = '   '
  $form.GetType().GetMethod('InstallAsync',$flags).Invoke($form,@()).GetAwaiter().GetResult()
  Check (-not (Field 'installing')) 'Whitespace password started installation.'
  (Field 'passBox').Text = 'example'
  (Field 'userBox').Text = ' '
  $form.GetType().GetMethod('InstallAsync',$flags).Invoke($form,@()).GetAwaiter().GetResult()
  Check (-not (Field 'installing')) 'Blank username started installation.'
  # Create an isolated throwaway Windows account on this disposable CI runner.
  # Use Windows authentication itself to verify the correct password and reject
  # an incorrect one; no real user account or password is used in this test.
  $testUser = 'wpv' + [Guid]::NewGuid().ToString('N').Substring(0,12)
  $testPassword = 'Wp!' + [Guid]::NewGuid().ToString('N') + '9a'
  $validate = $form.GetType().GetMethod('ValidateWindowsCredential',[Reflection.BindingFlags]'Static,NonPublic')
  $created = $false
  try {
    $securePassword = ConvertTo-SecureString $testPassword -AsPlainText -Force
    New-LocalUser -Name $testUser -Password $securePassword -AccountNeverExpires | Out-Null
    $created = $true
    $usersGroup = Get-LocalGroup -SID 'S-1-5-32-545'
    Add-LocalGroupMember -Group $usersGroup -Member $testUser
    foreach ($username in @($testUser,('.\' + $testUser),([Environment]::MachineName + '\' + $testUser))) {
      $validate.Invoke($null,@($username,$testPassword))
    }
    $credentialBefore = (& cmdkey.exe /list:WindowsProtect/LocalWindowsAccount | Out-String)
    $remoteUnlockBefore = Test-Path 'HKLM:\SOFTWARE\WindowsProtect\RemoteUnlock'
    $tokenBefore = Test-Path 'C:\ProgramData\WindowsProtect\device.token'
    (Field 'userBox').Text = '.\' + $testUser
    (Field 'passBox').Text = 'Wrong!' + [Guid]::NewGuid().ToString('N')
    $form.GetType().GetMethod('InstallAsync',$flags).Invoke($form,@()).GetAwaiter().GetResult()
    Check ((Field 'status').Text -eq 'Windows account verification failed.') 'Wrong Windows password was accepted.'
    Check ((Field 'credentialHint').Text -like 'Windows did not accept*') 'Authentication failure did not explain the rejection.'
    Check ((Field 'passBox').Text -eq '') 'Rejected password was not cleared.'
    Check (-not (Field 'installing')) 'Wrong password started installation.'
    Check ((Field 'installButton').Enabled) 'Cannot retry after an incorrect password.'
    Check ((Test-Path 'C:\ProgramData\WindowsProtect\device.token') -eq $tokenBefore) 'Invalid password changed enrollment state.'
    Check ((& cmdkey.exe /list:WindowsProtect/LocalWindowsAccount | Out-String) -eq $credentialBefore) 'Invalid password was stored.'
    Check ((Test-Path 'HKLM:\SOFTWARE\WindowsProtect\RemoteUnlock') -eq $remoteUnlockBefore) 'Invalid password created remote-unlock storage.'
    # A failed attempt must not break validation of the correct password.
    $validate.Invoke($null,@(('.\' + $testUser),$testPassword))
    Write-Output 'Real Windows authentication: correct password accepted; wrong password blocked before enrollment or credential storage.'

    # Exercise the exact local-at-rest format without installing or registering
    # the LogonUI provider on the hosted runner.
    $save = $form.GetType().GetMethod('SaveRemoteUnlockCredential',[Reflection.BindingFlags]'Static,NonPublic')
    $sid = (Get-LocalUser -Name $testUser).SID.Value
    $save.Invoke($null,@(('.\' + $testUser),$sid,$testPassword))
    $stored = Get-ItemProperty 'HKLM:\SOFTWARE\WindowsProtect\RemoteUnlock'
    Check ($stored.UserSid -eq $sid) 'Remote-unlock credential was stored for the wrong account.'
    Check ($stored.Secret -is [byte[]] -and $stored.Secret.Length -gt 0) 'Encrypted remote-unlock credential is missing.'
    Check (-not ([Text.Encoding]::Unicode.GetString($stored.Secret) -like "*$testPassword*")) 'Password was stored as readable text.'
    $decrypted = [Security.Cryptography.ProtectedData]::Unprotect($stored.Secret,$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
    try { Check ([Text.Encoding]::Unicode.GetString($decrypted).TrimEnd([char]0) -eq $testPassword) 'Machine-encrypted password could not be recovered by the local unlock provider.' }
    finally { [Array]::Clear($decrypted,0,$decrypted.Length) }
    Write-Output 'Remote unlock storage: verified account-bound, machine-encrypted DPAPI data; no password upload path.'
  } finally {
    Remove-Item 'HKLM:\SOFTWARE\WindowsProtect\RemoteUnlock' -Recurse -Force -ErrorAction SilentlyContinue
    if ($created) { Remove-LocalUser -Name $testUser }
    $testPassword = $null
    if ($securePassword) { $securePassword.Dispose() }
  }
  # Persistent activation policy: a pending retry/reboot cannot arm blocking,
  # and a repair cannot reset a previously active installation.
  $activation = $assembly.GetType('ProtectionActivation')
  $staticFlags = [Reflection.BindingFlags]'Static,NonPublic'
  $statePath = 'HKLM:\SOFTWARE\WindowsProtect'
  $ownedValues = @('ActivationState','ActivationNonce','ActivationDeadlineUtc','LastObservedUtc','SupportVerified')
  $hadKey = Test-Path $statePath
  $previousValues = @{}
  if ($hadKey) {
    $old = Get-ItemProperty $statePath
    foreach ($name in $ownedValues) { if ($null -ne $old.$name) { $previousValues[$name]=$old.$name } }
  }
  try {
    if ($hadKey) { Remove-ItemProperty $statePath -Name $ownedValues -ErrorAction SilentlyContinue }
    $activation.GetMethod('Initialize',$staticFlags).Invoke($null,@($false))
    Check (-not $activation.GetMethod('IsActive',$staticFlags).Invoke($null,@())) 'New install activated before support verification.'
    $activation.GetMethod('Initialize',$staticFlags).Invoke($null,@($true))
    Check (-not $activation.GetMethod('IsActive',$staticFlags).Invoke($null,@())) 'Pending retry was treated as a protected legacy install.'
    $deadline = $activation.GetMethod('Deadline',$staticFlags).Invoke($null,@())
    Check (($deadline - [DateTime]::UtcNow).TotalHours -le 4) 'Setup window exceeds four hours.'
    Check (($deadline - [DateTime]::UtcNow).TotalHours -gt 3.9) 'New setup window is missing.'
    $activation.GetMethod('Initialize',$staticFlags).Invoke($null,@($false))
    Check ($activation.GetMethod('Deadline',$staticFlags).Invoke($null,@()) -eq $deadline) 'Retry extended the deadline.'
    $activation.GetMethod('MarkSupportVerified',$staticFlags).Invoke($null,@(('a' * 64)))
    Check (-not $activation.GetMethod('IsActive',$staticFlags).Invoke($null,@())) 'Support verification immediately blocked remote tools.'
    Check ($activation.GetMethod('MigrationStatus',$staticFlags).Invoke($null,@()).StartsWith('awaiting_activation:')) 'Verified setup is not waiting for dashboard activation.'
    $manualDir = Join-Path $env:TEMP ('wp-manual-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $manualDir | Out-Null
    try {
      $requestFile = Join-Path $manualDir 'activation.request'
      $manualNonce = 'd' * 64
      $requestCheck = $activation.GetMethod('TryActivateRequest',$staticFlags)
      [IO.File]::WriteAllText($requestFile,$manualNonce)
      Check (-not $requestCheck.Invoke($null,@([string]$requestFile))) 'Manual request without round-trip proof activated protection.'
      [IO.File]::WriteAllText((Join-Path $manualDir ('support-' + $manualNonce + '.txt')),('e' * 64))
      Check (-not $requestCheck.Invoke($null,@([string]$requestFile))) 'Manual request with wrong proof activated protection.'
      [IO.File]::WriteAllText((Join-Path $manualDir ('support-' + $manualNonce + '.txt')),$manualNonce)
      Check ($requestCheck.Invoke($null,@([string]$requestFile))) 'Verified dashboard request was not accepted.'
      Check ($activation.GetMethod('IsActive',$staticFlags).Invoke($null,@())) 'Dashboard request did not activate protection.'
      Check (-not (Test-Path $requestFile)) 'Activation request can be replayed.'
    } finally { Remove-Item $manualDir -Recurse -Force }
    Set-ItemProperty $statePath -Name ActivationState -Value 'pending'
    Set-ItemProperty $statePath -Name ActivationDeadlineUtc -Value ([DateTime]::UtcNow.AddSeconds(-10).ToString('o'))
    $activation.GetMethod('Evaluate',$staticFlags).Invoke($null,@())
    Check ($activation.GetMethod('IsActive',$staticFlags).Invoke($null,@())) 'Expired setup did not activate offline.'
    $nonce = 'a' * 64
    $activation.GetMethod('Activate',$staticFlags).Invoke($null,@($nonce))
    $activation.GetMethod('Initialize',$staticFlags).Invoke($null,@($false))
    Check ($activation.GetMethod('IsActive',$staticFlags).Invoke($null,@())) 'Repair downgraded active protection.'
    Check ($activation.GetMethod('Nonce',$staticFlags).Invoke($null,@()) -eq $nonce) 'Activation proof was lost.'
    Remove-ItemProperty $statePath -Name ActivationState,ActivationNonce
    $activation.GetMethod('Initialize',$staticFlags).Invoke($null,@($true))
    Check ($activation.GetMethod('IsActive',$staticFlags).Invoke($null,@())) 'Protected legacy upgrade lost protection.'
  } finally {
    if (-not $hadKey) { Remove-Item $statePath -Recurse -Force }
    else {
      Remove-ItemProperty $statePath -Name $ownedValues -ErrorAction SilentlyContinue
      foreach ($name in $previousValues.Keys) { Set-ItemProperty $statePath -Name $name -Value $previousValues[$name] }
    }
  }
  $proofDir = Join-Path $env:TEMP ('wp-proof-' + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory $proofDir | Out-Null
  $proofCheck = $form.GetType().GetMethod('VerifiedSupportChallenge',$staticFlags)
  try {
    $nonce = 'b' * 64
    $goodResponse = '{"desktop_verified":true,"command_dispatched":true,"challenge":"' + $nonce + '"}'
    Check ($proofCheck.Invoke($null,@([string]$goodResponse,[string]$proofDir)) -eq '') 'Server acknowledgment alone activated protection.'
    [IO.File]::WriteAllText((Join-Path $proofDir ('support-' + $nonce + '.txt')),('c' * 64))
    Check ($proofCheck.Invoke($null,@([string]$goodResponse,[string]$proofDir)) -eq '') 'Wrong local challenge activated protection.'
    [IO.File]::WriteAllText((Join-Path $proofDir ('support-' + $nonce + '.txt')),$nonce)
    Check ($proofCheck.Invoke($null,@([string]$goodResponse,[string]$proofDir)) -eq $nonce) 'Fresh round-trip proof was rejected.'
    $noDesktop = $goodResponse.Replace('"desktop_verified":true','"desktop_verified":false')
    Check ($proofCheck.Invoke($null,@([string]$noDesktop,[string]$proofDir)) -eq '') 'A command without desktop verification activated protection.'
    Write-Output 'Support activation: verified setup waits for dashboard activation; four-hour deadline survives retries; expiry activates offline; active repairs preserve protection.'
  } finally { Remove-Item $proofDir -Recurse -Force }
  (Field 'credentialHint').Text = 'Enter the Windows password normally. If it is not known, choose Skip. The password stays encrypted on this PC and can be used only for an authorised one-time unlock.'
  (Field 'credentialHint').ForeColor = [Drawing.Color]::FromArgb(100,108,120)
  (Field 'userBox').Text = [Environment]::UserDomainName + '\' + [Environment]::UserName
  (Field 'passBox').Text = ''
  (Field 'ownerBox').Text = ''; (Field 'labelBox').Text = ''; (Field 'codeBox').Text = ''
  (Field 'status').Text = 'Ready to protect this PC.'
  $form.PerformLayout(); [Windows.Forms.Application]::DoEvents()
  $image = New-Object Drawing.Bitmap $form.Width,$form.Height
  try { $form.DrawToBitmap($image,(New-Object Drawing.Rectangle 0,0,$form.Width,$form.Height)); $image.Save((Join-Path $PWD 'WindowsProtect_Setup_Preview.png')) } finally { $image.Dispose() }
  Write-Output 'Installer UI and optional-password checks passed.'
} finally { $form.Close(); $form.Dispose() }
