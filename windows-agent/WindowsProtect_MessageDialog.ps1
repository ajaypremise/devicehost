Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
function New-WindowsProtectDialog {
 param([string]$Title,[string]$Message,[string]$Size='standard',[string]$Placement='center',[string]$Kind='warning')
 $form=New-Object Windows.Forms.Form
 $form.Text='WindowsProtect'
 $form.Font=New-Object Drawing.Font('Segoe UI',10)
 $form.BackColor=[Drawing.SystemColors]::Window
 $form.ForeColor=[Drawing.SystemColors]::WindowText
 $form.FormBorderStyle='FixedDialog';$form.MaximizeBox=$false;$form.MinimizeBox=$false
 $form.TopMost=$true;$form.ShowInTaskbar=$true;$form.StartPosition='Manual'
 $form.AutoScaleDimensions=New-Object Drawing.SizeF(96,96);$form.AutoScaleMode='Dpi'
 $width=540;$height=310
 if($Size -eq 'compact'){$width=440;$height=240}elseif($Size -eq 'large'){$width=680;$height=440}
 $area=[Windows.Forms.Screen]::PrimaryScreen.WorkingArea
 $width=[Math]::Min($width,$area.Width-40);$height=[Math]::Min($height,$area.Height-80)
 $form.ClientSize=New-Object Drawing.Size($width,$height)
 $footer=New-Object Windows.Forms.Panel
 $footer.Name='DialogFooter';$footer.Dock='Bottom';$footer.Height=62;$footer.BackColor=[Drawing.SystemColors]::Control
 $footer.Size=New-Object Drawing.Size($width,62)
 $ok=New-Object Windows.Forms.Button
 $ok.Name='DialogOK';$ok.Text='OK';$ok.Size=New-Object Drawing.Size(90,30)
 $ok.Location=New-Object Drawing.Point(($width-110),16);$ok.Anchor='Right,Bottom'
 $ok.UseVisualStyleBackColor=$true;$ok.DialogResult='OK';$ok.AccessibleName='Close WindowsProtect message'
 $footer.Controls.Add($ok);$form.Controls.Add($footer);$form.AcceptButton=$ok;$form.CancelButton=$ok
 $icon=[Drawing.SystemIcons]::Warning
 if($Kind -eq 'information'){$icon=[Drawing.SystemIcons]::Information}elseif($Kind -eq 'error'){$icon=[Drawing.SystemIcons]::Error}
 $form.Icon=$icon
 $picture=New-Object Windows.Forms.PictureBox
 $picture.Name='DialogIcon';$picture.Image=$icon.ToBitmap();$picture.SizeMode='CenterImage'
 $picture.Location=New-Object Drawing.Point(24,22);$picture.Size=New-Object Drawing.Size(40,40)
 $heading=New-Object Windows.Forms.Label
 $heading.Name='DialogHeading';$heading.Text=$Title;$heading.AutoSize=$false
 $heading.Font=New-Object Drawing.Font('Segoe UI',13,[Drawing.FontStyle]::Regular)
 $heading.Location=New-Object Drawing.Point(84,22);$heading.Size=New-Object Drawing.Size(($width-108),58)
 $heading.ForeColor=[Drawing.SystemColors]::WindowText
 $body=New-Object Windows.Forms.RichTextBox
 $body.Name='DialogMessage';$body.Text=$Message;$body.ReadOnly=$true;$body.BorderStyle='None'
 $body.BackColor=[Drawing.SystemColors]::Window;$body.ForeColor=[Drawing.SystemColors]::WindowText
 $body.Font=$form.Font;$body.DetectUrls=$false;$body.WordWrap=$true;$body.ScrollBars='Vertical'
 $body.Location=New-Object Drawing.Point(84,86);$body.Size=New-Object Drawing.Size(($width-108),($height-164))
 $body.TabStop=$false
 $form.Controls.Add($picture);$form.Controls.Add($heading);$form.Controls.Add($body)
 if($Placement -eq 'top_right'){$x=$area.Right-$form.Width-20;$y=$area.Top+20}
 elseif($Placement -eq 'bottom_right'){$x=$area.Right-$form.Width-20;$y=$area.Bottom-$form.Height-20}
 else{$x=$area.Left+[int](($area.Width-$form.Width)/2);$y=$area.Top+[int](($area.Height-$form.Height)/2)}
 $form.Location=New-Object Drawing.Point($x,$y)
 return $form
}
