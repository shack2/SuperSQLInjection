# 多点点击后截图：Start-Process 启动 → 依次点击指定屏幕坐标 → 截图
param([string]$Clicks = "", [string]$Hover = "", [string]$Shot1 = "F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\shot-nav.png")
$ErrorActionPreference = "Continue"
Add-Type -AssemblyName System.Drawing

$sig = @'
using System;
using System.Runtime.InteropServices;
public class Win32C2 {
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint dwFlags, int dx, int dy, uint dwData, int dwExtraInfo);
    public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
    public static void Click(int x, int y) {
        SetCursorPos(x, y);
        System.Threading.Thread.Sleep(150);
        mouse_event(0x0002, 0, 0, 0, 0);
        mouse_event(0x0004, 0, 0, 0, 0);
    }
}
'@
Add-Type -TypeDefinition $sig -ReferencedAssemblies System.Drawing

$exe = 'F:\MyCoding\c#\AI\SuperSQLInjectionV2\SuperSQLInjectionV2.Desktop\bin\Debug\net10.0\SuperSQLInjectionV2.Desktop.exe'
$wd = Split-Path $exe
$p = Start-Process -FilePath $exe -WorkingDirectory $wd -PassThru
# 等窗口句柄和标题就绪（最多30秒）
$h = [IntPtr]::Zero
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    $p.Refresh()
    if ($p.HasExited) { Write-Output "EXITED code=$($p.ExitCode)"; exit 1 }
    if ($p.MainWindowHandle -ne 0 -and $p.MainWindowTitle -ne "") { $h = $p.MainWindowHandle; break }
}
if ($h -eq [IntPtr]::Zero) { Write-Output "NO WINDOW"; Stop-Process -Id $p.Id -Force; exit 1 }
Write-Output ("WINDOW title=" + $p.MainWindowTitle)

[Win32C2]::ShowWindow($h, 9) | Out-Null
# 反复尝试置前直到成为前台窗口（最多5秒）
for ($i = 0; $i -lt 15; $i++) {
    [Win32C2]::SetForegroundWindow($h) | Out-Null
    Start-Sleep -Milliseconds 300
    if ([Win32C2]::GetForegroundWindow() -eq $h) { break }
}
Write-Output ("FOREGROUND=" + ([Win32C2]::GetForegroundWindow() -eq $h))
[Win32C2]::SetWindowPos($h, [IntPtr]::New(-1), 0, 0, 0, 0, 0x3) | Out-Null
Start-Sleep -Milliseconds 600

foreach ($pt in $Clicks -split ';') {
    if ($pt -match '(\d+),(\d+)') {
        [Win32C2]::Click([int]$Matches[1], [int]$Matches[2])
        Start-Sleep -Milliseconds 700
    }
}
if ($Hover -match '(\d+),(\d+)') {
    [Win32C2]::SetCursorPos([int]$Matches[1], [int]$Matches[2])
    Start-Sleep -Milliseconds 900
}
Start-Sleep -Milliseconds 400

$rc = New-Object Win32C2+RECT
[Win32C2]::GetWindowRect($h, [ref]$rc) | Out-Null
$w = $rc.Right - $rc.Left; $hh = $rc.Bottom - $rc.Top
$bmp = New-Object System.Drawing.Bitmap($w, $hh)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($rc.Left, $rc.Top, 0, 0, $bmp.Size)
$bmp.Save($Shot1, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Output ("SAVED " + $Shot1 + " (w=" + $w + " h=" + $hh + ") winpos=(" + $rc.Left + "," + $rc.Top + ")")
Stop-Process -Id $p.Id -Force
Write-Output "DONE"
