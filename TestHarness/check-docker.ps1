Get-Process | Where-Object { $_.ProcessName -like '*docker*' } | Select-Object Id, ProcessName | Format-Table -AutoSize
