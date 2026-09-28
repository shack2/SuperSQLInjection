$exe = "F:\MyCoding\c#\AI\SuperSQLInjectionV2\SuperSQLInjectionV2.Desktop\bin\Release\net10.0\win-x64\publish\SuperSQLInjectionV2.Desktop.exe"
Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe)
Start-Sleep -Seconds 10
$p = Get-Process -Name "SuperSQLInjectionV2.Desktop" -ErrorAction SilentlyContinue
if ($p) { Write-Output ("ALIVE pid=" + $p.Id + " title=" + $p.MainWindowTitle + " responding=" + $p.Responding) }
else { Write-Output "NOT_RUNNING" }
