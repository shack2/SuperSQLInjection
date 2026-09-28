try {
    $c = New-Object System.Data.SqlClient.SqlConnection('Server=127.0.0.1,11433;User Id=sa;Password=Sa@123456;Database=master;TrustServerCertificate=true;Encrypt=false;Connect Timeout=8')
    $c.Open()
    $cmd = $c.CreateCommand()
    $cmd.CommandText = 'select @@version'
    $v = $cmd.ExecuteScalar()
    $c.Close()
    Write-Output ("OK: " + $v.Substring(0, 60))
} catch {
    Write-Output ("ERR: " + $_.Exception.Message)
}
