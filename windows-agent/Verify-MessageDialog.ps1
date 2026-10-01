$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$assembly=[Reflection.Assembly]::LoadFile((Join-Path $PWD 'WindowsProtect_UserUI.exe'))
$type=$assembly.GetType('WindowsProtectUserUI')
$build=$type.GetMethod('BuildMessage',[Reflection.BindingFlags]'Static,NonPublic')
function Check($condition,$message){if(-not $condition){throw $message}}
foreach($size in @('compact','standard','large')){
 $form=$build.Invoke($null,@('WindowsProtect support notice',('Long message content. '*60),$size,'center','warning'))
 try{
  $form.Show();[Windows.Forms.Application]::DoEvents()
  Check ($form.Text -eq 'WindowsProtect') 'Dialog does not identify WindowsProtect.'
  Check ($form.BackColor -eq [Drawing.SystemColors]::Window) 'Dialog background does not use Windows colors.'
  $body=$form.Controls['DialogMessage'];$footer=$form.Controls['DialogFooter'];$ok=$footer.Controls['DialogOK']
  Check ($body.ScrollBars -eq 'Vertical') 'Long messages cannot scroll.'
  Check ($body.Bounds.Bottom -lt $footer.Bounds.Top) 'Message overlaps the button area.'
  Check ($footer.ClientRectangle.Contains($ok.Bounds)) 'OK button is clipped.'
  Check ($ok.UseVisualStyleBackColor) 'OK button is not Windows styled.'
  Check ($form.ClientRectangle.Contains($form.Controls['DialogIcon'].Bounds)) 'Warning icon is clipped.'
  if($size -eq 'standard'){
   $bitmap=New-Object Drawing.Bitmap($form.Width,$form.Height)
   $form.DrawToBitmap($bitmap,(New-Object Drawing.Rectangle(0,0,$form.Width,$form.Height)))
   $bitmap.Save((Join-Path $PWD 'WindowsProtect_Message_Preview.png'));$bitmap.Dispose()
  }
  $ok.PerformClick();[Windows.Forms.Application]::DoEvents()
 }finally{$form.Dispose()}
}
Write-Output 'Windows dialogs: WindowsProtect identity, Windows colors and icon, native OK button, long-text scrolling and all three sizes verified.'
