param([int]$Step = 1, [double]$Fx = 0, [double]$Fy = 0, [double]$Fx2 = 0, [double]$Fy2 = 0)
$ErrorActionPreference = "Continue"
Add-Type -AssemblyName System.Drawing

$sig = @'
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint dwFlags, int dx, int dy, uint dwData, int dwExtraInfo);
    public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
    public static void Click(int x, int y) {
        SetCursorPos(x, y);
        System.Threading.Thread.Sleep(120);
        mouse_event(0x0002, 0, 0, 0, 0);
        mouse_event(0x0004, 0, 0, 0, 0);
    }
}
'@
Add-Type -TypeDefinition $sig -ReferencedAssemblies System.Drawing

function Snap($p, $out) {
    $h = $p.MainWindowHandle
    [Win32]::ShowWindow($h, 9) | Out-Null
    [Win32]::SetForegroundWindow($h) | Out-Null
    Start-Sleep -Milliseconds 600
    $rc = New-Object Win32+RECT
    [Win32]::GetWindowRect($h, [ref]$rc) | Out-Null
    $w = $rc.Right - $rc.Left; $hh = $rc.Bottom - $rc.Top
    $bmp = New-Object System.Drawing.Bitmap($w, $hh)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($rc.Left, $rc.Top, 0, 0, $bmp.Size)
    $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Output "SAVED $out (w=$w h=$hh)"
}

$dst = "F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\bin\smoke-debug"
$exe = "$dst\SuperSQLInjectionV2.Desktop.exe"
$p = Start-Process -FilePath $exe -WorkingDirectory $dst -PassThru
try {
    Start-Sleep -Seconds 18
    if ($p.HasExited) { Write-Output "EXITED"; exit 1 }
    $h = $p.MainWindowHandle
    $rc = New-Object Win32+RECT
    [Win32]::GetWindowRect($h, [ref]$rc) | Out-Null
    $w = $rc.Right - $rc.Left; $hh = $rc.Bottom - $rc.Top

    if ($Step -eq 1) {
        Snap $p "F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\shot-step1.png"
    } elseif ($Step -eq 7) {
        # 检测用例页
        [Win32]::SetForegroundWindow($h) | Out-Null
        Start-Sleep -Milliseconds 300
        [Win32]::Click($rc.Left + [int]($w * 0.0437), $rc.Top + [int]($hh * 0.1420))
        Start-Sleep -Seconds 3
        Snap $p "F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\shot-payload.png"
    } elseif ($Step -eq 8) {
        # 一次会话内连续导航：数据管理 → 请求配置
        [Win32]::SetForegroundWindow($h) | Out-Null
        Start-Sleep -Milliseconds 300
        [Win32]::Click($rc.Left + [int]($w * 0.0437), $rc.Top + [int]($hh * 0.2450))
        Start-Sleep -Seconds 2
        [Win32]::Click($rc.Left + [int]($w * 0.1980), $rc.Top + [int]($hh * 0.1780))
        Start-Sleep -Seconds 3
        Snap $p "F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\shot-reqcfg.png"
    } elseif ($Step -eq 9) {
        # 一次会话内连续导航：防护绕过 → 编码处理
        [Win32]::SetForegroundWindow($h) | Out-Null
        Start-Sleep -Milliseconds 300
        [Win32]::Click($rc.Left + [int]($w * 0.0437), $rc.Top + [int]($hh * 0.3836))
        Start-Sleep -Seconds 2
        [Win32]::Click($rc.Left + [int]($w * 0.3200), $rc.Top + [int]($hh * 0.0550))
        Start-Sleep -Seconds 3
        Snap $p "F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\shot-step3.png"
    } elseif ($Step -eq 10) {
        # 全页面巡检：逐个点左侧菜单并截图
        $pages = @(
            @{ Name = "01-inject-detect"; Fy = 0.107 },
            @{ Name = "02-payload-cases"; Fy = 0.142 },
            @{ Name = "03-inject-records"; Fy = 0.175 },
            @{ Name = "04-data-manage"; Fy = 0.245 },
            @{ Name = "05-templates"; Fy = 0.281 },
            @{ Name = "06-network"; Fy = 0.347 },
            @{ Name = "07-bypass"; Fy = 0.384 },
            @{ Name = "08-encode-tools"; Fy = 0.419 },
            @{ Name = "09-http-log"; Fy = 0.456 }
        )
        foreach ($pg in $pages) {
            [Win32]::SetForegroundWindow($h) | Out-Null
            Start-Sleep -Milliseconds 200
            [Win32]::Click($rc.Left + [int]($w * 0.0437), $rc.Top + [int]($hh * $pg.Fy))
            Start-Sleep -Seconds 2
            Snap $p ("F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\shots\" + $pg.Name + ".png")
        }
    } elseif ($Step -eq 11) {
        # 各页面内部选项卡巡检：页面菜单 → 逐个点选项卡并截图
        # 每次点击前强制置前 + 双击容错（第一次点击可能只激活窗口）
        function ClickAt($fx, $fy) {
            [Win32]::SetForegroundWindow($h) | Out-Null
            Start-Sleep -Milliseconds 350
            [Win32]::Click($rc.Left + [int]($w * $fx), $rc.Top + [int]($hh * $fy))
            Start-Sleep -Milliseconds 400
            [Win32]::Click($rc.Left + [int]($w * $fx), $rc.Top + [int]($hh * $fy))
        }
        $tabSets = @(
            @{ Page = "01-inject-detect"; MFy = 0.107; Ty = 0.150; Tabs = @(
                @{ N = "t1-request";  Fx = 0.194 }, @{ N = "t2-random";   Fx = 0.263 },
                @{ N = "t3-second";   Fx = 0.317 }, @{ N = "t4-skip";     Fx = 0.372 }) },
            @{ Page = "04-data-manage"; MFy = 0.245; Ty = 0.177; Tabs = @(
                @{ N = "t1-reqcfg";   Fx = 0.201 }, @{ N = "t2-env";      Fx = 0.263 },
                @{ N = "t3-hash";     Fx = 0.319 }, @{ N = "t4-role";     Fx = 0.377 },
                @{ N = "t5-file";     Fx = 0.434 }, @{ N = "t6-cmd";      Fx = 0.495 },
                @{ N = "t7-sql";      Fx = 0.557 }, @{ N = "t8-dataop";   Fx = 0.621 }) },
            @{ Page = "06-network";    MFy = 0.347; Ty = 0.172; Tabs = @(
                @{ N = "t1-auth";     Fx = 0.201 }, @{ N = "t2-proxy";    Fx = 0.266 },
                @{ N = "t3-dnslog";   Fx = 0.324 }, @{ N = "t4-uapool";   Fx = 0.368 },
                @{ N = "t5-dict";     Fx = 0.421 }, @{ N = "t6-resend";   Fx = 0.482 },
                @{ N = "t7-update";   Fx = 0.543 }) },
            @{ Page = "07-bypass";     MFy = 0.384; Ty = 0.056; Tabs = @(
                @{ N = "t1-freq";     Fx = 0.198 }, @{ N = "t2-replace";  Fx = 0.261 },
                @{ N = "t3-encode";   Fx = 0.322 }) },
            @{ Page = "09-http-log";   MFy = 0.456; Ty = 0.553; Tabs = @(
                @{ N = "t1-req";      Fx = 0.194 }, @{ N = "t2-resp";     Fx = 0.246 }) }
        )
        New-Item -ItemType Directory -Force -Path "F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\shots\tabs" | Out-Null
        foreach ($set in $tabSets) {
            ClickAt 0.0437 $set.MFy
            Start-Sleep -Seconds 2
            foreach ($tb in $set.Tabs) {
                ClickAt $tb.Fx $set.Ty
                Start-Sleep -Milliseconds 1500
                Snap $p ("F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\shots\tabs\" + $set.Page + "-" + $tb.N + ".png")
            }
        }
    } elseif ($Step -eq 13) {
        # 补拍：04 数据操作 + 06 DNSLog/UA池/字典/重发/软件更新
        function ClickAt($fx, $fy) {
            [Win32]::SetForegroundWindow($h) | Out-Null
            Start-Sleep -Milliseconds 350
            [Win32]::Click($rc.Left + [int]($w * $fx), $rc.Top + [int]($hh * $fy))
            Start-Sleep -Milliseconds 400
            [Win32]::Click($rc.Left + [int]($w * $fx), $rc.Top + [int]($hh * $fy))
        }
        $sets = @(
            @{ Page = "04-data-manage"; MFy = 0.245; Ty = 0.177; Tabs = @(@{ N = "t8-dataop"; Fx = 0.655 }) },
            @{ Page = "06-network"; MFy = 0.347; Ty = 0.172; Tabs = @(
                @{ N = "t3-dnslog"; Fx = 0.333 }, @{ N = "t4-uapool"; Fx = 0.385 },
                @{ N = "t5-dict";   Fx = 0.447 }, @{ N = "t6-resend"; Fx = 0.512 },
                @{ N = "t7-update"; Fx = 0.580 }) }
        )
        foreach ($set in $sets) {
            ClickAt 0.0437 $set.MFy
            Start-Sleep -Seconds 2
            foreach ($tb in $set.Tabs) {
                ClickAt $tb.Fx $set.Ty
                Start-Sleep -Milliseconds 1500
                Snap $p ("F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\shots\tabs\" + $set.Page + "-" + $tb.N + ".png")
            }
        }
    } elseif ($Step -eq 14) {
        # UA池选项卡：网络设置 → UA池（tab行 y≈0.133）
        [Win32]::SetForegroundWindow($h) | Out-Null
        Start-Sleep -Milliseconds 350
        [Win32]::Click($rc.Left + [int]($w * 0.0437), $rc.Top + [int]($hh * 0.347))
        Start-Sleep -Seconds 2
        [Win32]::SetForegroundWindow($h) | Out-Null
        Start-Sleep -Milliseconds 350
        [Win32]::Click($rc.Left + [int]($w * 0.394), $rc.Top + [int]($hh * 0.133))
        Start-Sleep -Milliseconds 400
        [Win32]::Click($rc.Left + [int]($w * 0.394), $rc.Top + [int]($hh * 0.133))
        Start-Sleep -Milliseconds 1500
        Snap $p "F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\shots\tabs\06-network-t4-uapool.png"
    } elseif ($Step -eq 15) {
        # 注入记录页：点首行操作列"查看"图标，验证详情弹窗
        [Win32]::SetForegroundWindow($h) | Out-Null
        Start-Sleep -Milliseconds 350
        [Win32]::Click($rc.Left + [int]($w * 0.0437), $rc.Top + [int]($hh * 0.175))
        Start-Sleep -Seconds 2
        [Win32]::SetForegroundWindow($h) | Out-Null
        Start-Sleep -Milliseconds 350
        [Win32]::Click($rc.Left + [int]($w * 0.933), $rc.Top + [int]($hh * 0.131))
        Start-Sleep -Seconds 2
        Snap $p "F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\shot-record-detail.png"
    } elseif ($Step -eq 12) {
        # 诊断：输出窗口矩形，点菜单→截图→点选项卡→截图
        Write-Output ("RECT L=" + $rc.Left + " T=" + $rc.Top + " R=" + $rc.Right + " B=" + $rc.Bottom)
        [Win32]::SetForegroundWindow($h) | Out-Null
        Start-Sleep -Milliseconds 400
        [Win32]::Click($rc.Left + [int]($w * 0.0437), $rc.Top + [int]($hh * 0.107))
        Start-Sleep -Seconds 2
        Snap $p "F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\shot-diag-menu.png"
        $rc2 = New-Object Win32+RECT
        [Win32]::GetWindowRect($h, [ref]$rc2) | Out-Null
        Write-Output ("RECT2 L=" + $rc2.Left + " T=" + $rc2.Top + " R=" + $rc2.Right + " B=" + $rc2.Bottom)
        [Win32]::Click($rc.Left + [int]($w * 0.185), $rc.Top + [int]($hh * 0.150))
        Start-Sleep -Seconds 2
        Snap $p "F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\shot-diag-tab.png"
    } elseif ($Step -eq 17) {
        # 两次自定义点击（导航→页内选项卡）
        [Win32]::SetForegroundWindow($h) | Out-Null
        Start-Sleep -Milliseconds 300
        [Win32]::Click($rc.Left + [int]($w * $Fx), $rc.Top + [int]($hh * $Fy))
        Start-Sleep -Seconds 3
        if ($Fx2 -gt 0 -and $Fy2 -gt 0) {
            [Win32]::Click($rc.Left + [int]($w * $Fx2), $rc.Top + [int]($hh * $Fy2))
            Start-Sleep -Seconds 2
        }
        Snap $p "F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\shot-step17.png"
    } elseif ($Step -eq 16) {
        # 检测用例页 → 报错指纹选项卡
        [Win32]::SetForegroundWindow($h) | Out-Null
        Start-Sleep -Milliseconds 300
        [Win32]::Click($rc.Left + [int]($w * 0.0437), $rc.Top + [int]($hh * 0.1420))
        Start-Sleep -Seconds 3
        [Win32]::Click($rc.Left + [int]($w * $Fx), $rc.Top + [int]($hh * $Fy))
        Start-Sleep -Seconds 2
        Snap $p "F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\shot-fingerprint.png"
    } elseif ($Step -eq 2) {
        [Win32]::SetForegroundWindow($h) | Out-Null
        Start-Sleep -Milliseconds 300
        [Win32]::Click($rc.Left + [int]($w * $Fx), $rc.Top + [int]($hh * $Fy))
        Start-Sleep -Seconds 2
        Snap $p "F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\shot-step2.png"
    } else {
        [Win32]::SetForegroundWindow($h) | Out-Null
        Start-Sleep -Milliseconds 300
        [Win32]::Click($rc.Left + [int]($w * $Fx), $rc.Top + [int]($hh * $Fy))
        Start-Sleep -Seconds 2
        Snap $p "F:\MyCoding\c#\AI\SuperSQLInjectionV2\TestHarness\shot-step3.png"
    }
} finally {
    if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }
}
