$ErrorActionPreference = "Stop"
$src = "F:\MyCoding\c#\AI\SuperSQLInjectionV2\SuperSQLInjectionV2\bin\Debug\net10.0"
$dst = "F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\bin\smoke-debug"
Copy-Item "$src\SuperSQLInjectionV2.dll" "$dst\SuperSQLInjectionV2.dll" -Force
if (Test-Path "$src\SuperSQLInjectionV2.pdb") { Copy-Item "$src\SuperSQLInjectionV2.pdb" "$dst\SuperSQLInjectionV2.pdb" -Force }
#宿主配置同步（依赖增删后 deps.json 必须跟随，否则宿主按旧依赖清单解析失败）
$desktopBin = "F:\MyCoding\c#\AI\SuperSQLInjectionV2\SuperSQLInjectionV2.Desktop\bin\Debug\net10.0"
Copy-Item "$desktopBin\SuperSQLInjectionV2.Desktop.runtimeconfig.json" "$dst\" -Force
Copy-Item "$desktopBin\SuperSQLInjectionV2.Desktop.deps.json" "$dst\" -Force
#payload模板等运行期资源（缺失时启动即抛 FileNotFoundException）
if (-not (Test-Path "$dst\config\payload\mysql.txt")) { Copy-Item "$desktopBin\config" "$dst\" -Recurse -Force }
Write-Output "SYNCED $(Get-Item "$dst\SuperSQLInjectionV2.dll" | Select-Object -ExpandProperty LastWriteTime)"

$exe = "$dst\SuperSQLInjectionV2.Desktop.exe"
$p = Start-Process -FilePath $exe -WorkingDirectory $dst -PassThru
Start-Sleep -Seconds 15
if (-not $p.HasExited) {
    Write-Output "ALIVE title=$($p.MainWindowTitle)"
    Stop-Process -Id $p.Id -Force
} else {
    Write-Output "EXITED code=$($p.ExitCode)"
}
