$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
# Create a WindowsProtect shield icon without third-party artwork or fonts.
$bitmap = New-Object Drawing.Bitmap 64,64
$g = [Drawing.Graphics]::FromImage($bitmap)
$g.SmoothingMode = 'AntiAlias'
$g.Clear([Drawing.Color]::Transparent)
$shield = [Drawing.Point[]]@(
  (New-Object Drawing.Point 32,3), (New-Object Drawing.Point 58,13),
  (New-Object Drawing.Point 54,39), (New-Object Drawing.Point 45,52),
  (New-Object Drawing.Point 32,61), (New-Object Drawing.Point 19,52),
  (New-Object Drawing.Point 10,39), (New-Object Drawing.Point 6,13)
)
$brush = New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(32,38,46))
$g.FillPolygon($brush,$shield)
$pen = New-Object Drawing.Pen ([Drawing.Color]::White),5
$pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
$g.DrawLines($pen,[Drawing.Point[]]@((New-Object Drawing.Point 20,32),(New-Object Drawing.Point 29,41),(New-Object Drawing.Point 44,24)))
$stream = [IO.File]::Create((Join-Path $PWD 'WindowsProtect.ico'))
$icon = [Drawing.Icon]::FromHandle($bitmap.GetHicon())
try { $icon.Save($stream) } finally { $stream.Dispose(); $icon.Dispose(); $g.Dispose(); $brush.Dispose(); $pen.Dispose(); $bitmap.Dispose() }
