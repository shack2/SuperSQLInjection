$exe = 'F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\bin\smoke-debug\SuperSQLInjectionV2.Desktop.exe'
$wd = Split-Path $exe
$p = Start-Process -FilePath $exe -WorkingDirectory $wd -PassThru
Start-Sleep -Seconds 15
if (-not $p.HasExited) {
    Write-Output "ALIVE title=$($p.MainWindowTitle)"
    Stop-Process -Id $p.Id -Force
} else {
    Write-Output "EXITED code=$($p.ExitCode)"
}
