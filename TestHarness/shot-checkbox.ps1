# 截取主窗口（可选：点击后二次截图）
param([int]$ClickX = 0, [int]$ClickY = 0, [string]$Shot1 = "", [string]$Shot2 = "")
$ErrorActionPreference = "Continue"
Add-Type -AssemblyName System.Drawing

$sig = @'
using System;
using System.Runtime.InteropServices;
public class Win32C {
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
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

function Snap($h, $out) {
    [Win32C]::ShowWindow($h, 9) | Out-Null
    [Win32C]::SetForegroundWindow($h) | Out-Null
    Start-Sleep -Milliseconds 500
    $rc = New-Object Win32C+RECT
    [Win32C]::GetWindowRect($h, [ref]$rc) | Out-Null
    $w = $rc.Right - $rc.Left; $hh = $rc.Bottom - $rc.Top
    $bmp = New-Object System.Drawing.Bitmap($w, $hh)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($rc.Left, $rc.Top, 0, 0, $bmp.Size)
    $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Output ("SAVED {0} (w={1} h={2}) winpos=({3},{4})" -f $out, $w, $hh, $rc.Left, $rc.Top)
}

if ($Shot1 -eq "") { $Shot1 = "F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\shot-cb-1.png" }
$exe = 'F:\MyCoding\c#\AI\SuperSQLInjectionV2\SuperSQLInjectionV2.Desktop\bin\Debug\net10.0\SuperSQLInjectionV2.Desktop.exe'
$wd = Split-Path $exe
$p = Start-Process -FilePath $exe -WorkingDirectory $wd -PassThru
Start-Sleep -Seconds 12
if ($p.HasExited) { Write-Output "EXITED code=$($p.ExitCode)"; exit 1 }
Snap $p.MainWindowHandle $Shot1
if ($ClickX -gt 0 -and $Shot2 -ne "") {
    [Win32C]::Click($ClickX, $ClickY)
    Start-Sleep -Milliseconds 600
    Snap $p.MainWindowHandle $Shot2
}
Stop-Process -Id $p.Id -Force
Write-Output "DONE"
