$procs = Get-Process -Name 'SuperSQLInjectionV2.Desktop' -ErrorAction SilentlyContinue
if ($procs) {
    foreach ($p in $procs) { Write-Output "PID=$($p.Id) Start=$($p.StartTime) Title=$($p.MainWindowTitle)" }
} else { Write-Output 'NONE' }
