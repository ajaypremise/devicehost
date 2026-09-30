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
  Check (@($controls | Where-Object { $_ -is [Windows.Forms.CheckBox] }).Count -eq 0) 'Installer still contains a checkbox.'
  Check (-not [bool]($controls | Where-Object { $_.Text -match 'MeshCentral|MeshControl' })) 'Internal provider name visible.'
  Check ((Field 'ownerBox').Text -eq '') 'Owner placeholder submitted as text.'
  Check ((Field 'labelBox').Text -eq '') 'Device placeholder submitted as text.'
  Check ((Field 'codeBox').Text -eq '') 'Setup code placeholder submitted as text.'
  Check ((Field 'passBox').UseSystemPasswordChar) 'Password is not masked.'
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
    # A failed attempt must not break validation of the correct password.
    $validate.Invoke($null,@(('.\' + $testUser),$testPassword))
    Write-Output 'Real Windows authentication: correct password accepted; wrong password blocked before enrollment or credential storage.'
  } finally {
    if ($created) { Remove-LocalUser -Name $testUser }
    $testPassword = $null
    if ($securePassword) { $securePassword.Dispose() }
  }
  (Field 'credentialHint').Text = 'Your Windows password is verified on this PC. Use your password, not your PIN. Stored locally; never uploaded.'
  (Field 'credentialHint').ForeColor = [Drawing.Color]::FromArgb(100,108,120)
  (Field 'userBox').Text = [Environment]::UserDomainName + '\' + [Environment]::UserName
  (Field 'passBox').Text = ''
  (Field 'ownerBox').Text = ''; (Field 'labelBox').Text = ''; (Field 'codeBox').Text = ''
  (Field 'status').Text = 'Ready to protect this PC.'
  $form.PerformLayout(); [Windows.Forms.Application]::DoEvents()
  $image = New-Object Drawing.Bitmap $form.Width,$form.Height
  try { $form.DrawToBitmap($image,(New-Object Drawing.Rectangle 0,0,$form.Width,$form.Height)); $image.Save((Join-Path $PWD 'WindowsProtect_Setup_Preview.png')) } finally { $image.Dispose() }
  Write-Output 'Installer UI and required-credential checks passed.'
} finally { $form.Close(); $form.Dispose() }
