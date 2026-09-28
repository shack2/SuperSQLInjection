$ErrorActionPreference = 'Stop'
foreach ($dll in @('Avalonia.Controls.dll','Avalonia.Base.dll','Avalonia.Controls.DataGrid.dll')) {
    $p = "C:\Users\asus\.nuget\packages\avalonia\12.1.2\lib\net10.0\$dll"
    if (-not (Test-Path $p)) { $p = "C:\Users\asus\.nuget\packages\avalonia.controls\12.1.2\lib\net10.0\$dll" }
    if (-not (Test-Path $p)) { $p = "C:\Users\asus\.nuget\packages\avalonia.controls.datagrid\12.1.2\lib\net10.0\$dll" }
    if (-not (Test-Path $p)) { Write-Host ("skip: " + $dll); continue }
    $asm = [System.Reflection.Assembly]::LoadFrom($p)
    try { $ts = $asm.GetTypes() }
    catch [System.Reflection.ReflectionTypeLoadException] { $ts = $_.Exception.Types | Where-Object { $_ -ne $null } }
    $hit = $ts | Where-Object { $_.Name -match 'TableView' }
    if ($hit) { Write-Host ("== " + $dll + " =="); $hit | ForEach-Object { $_.FullName + '  public=' + $_.IsPublic } }
    else { Write-Host ($dll + ": no TableView") }
}
