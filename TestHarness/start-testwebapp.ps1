$ErrorActionPreference = "Stop"
$appDir = "F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestWebApp"
Set-Location $appDir
# 已在跑则跳过
try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:5099/num?id=1" -UseBasicParsing -TimeoutSec 3
    Write-Output "ALREADY-RUNNING $($r.StatusCode)"
    exit 0
} catch {}
$p = Start-Process -FilePath "C:\Program Files\dotnet\dotnet.exe" -ArgumentList "run --no-restore" -WorkingDirectory $appDir -RedirectStandardOutput "$appDir\app-run.log" -RedirectStandardError "$appDir\app-err.log" -PassThru -WindowStyle Hidden
$p.Id | Out-File "$appDir\app.pid" -Force
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Seconds 1
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:5099/num?id=1" -UseBasicParsing -TimeoutSec 2
        Write-Output "STARTED pid=$($p.Id) status=$($r.StatusCode)"
        exit 0
    } catch {}
}
Write-Output "FAILED-TO-START"
Get-Content "$appDir\app-err.log" -Tail 20 -ErrorAction SilentlyContinue
exit 1
