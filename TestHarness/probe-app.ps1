$exe = 'F:\MyCoding\c#\AI\SuperSQLInjectionV2\SuperSQLInjectionV2.Desktop\bin\Debug\net10.0\SuperSQLInjectionV2.Desktop.exe'
$wd = Split-Path $exe
$err = 'F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\app-err.log'
$out = 'F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\app-out.log'
$p = Start-Process -FilePath $exe -WorkingDirectory $wd -PassThru -RedirectStandardError $err -RedirectStandardOutput $out
Start-Sleep -Seconds 15
if ($p.HasExited) {
    Write-Output ("EXITED code=" + $p.ExitCode)
} else {
    Write-Output ("ALIVE handle=" + $p.MainWindowHandle + " title=" + $p.MainWindowTitle)
    Stop-Process -Id $p.Id -Force
}
