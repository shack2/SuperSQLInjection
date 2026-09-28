using SuperSQLInjectionV2.Tools;
using SuperSQLInjectionV2.Tools.Dns;
using SuperSQLInjectionV2.ViewModels;
using System;

namespace SuperSQLInjectionV2.Models.Data
{
    /// <summary>
    /// 内置DNS接收服务生命周期管理（P2-8本机形态）：按DataConfig.DnsServerEnable/DnsServerPort/DnsLogDomain
    /// 启停单例DnsLogServerCore。EnsureState幂等，配置不变不重启；启动失败（端口占用/权限不足）降级为关闭并告警。
    /// </summary>
    public static class DnsServerManager
    {
        private static DnsLogServerCore? _server;
        private static string _stateKey = "";

        /// <summary>当前运行的接收端（未运行返回null，供DnsExfilTool本机回收判活）</summary>
        public static DnsLogServerCore? Current => _server?.Running == true ? _server : null;

        /// <summary>按配置保证服务状态：启用且配置变化→重启；关闭→停止。返回是否处于运行中</summary>
        public static bool EnsureState(AppConfig config)
        {
            var dc = config.DataConfig;
            bool wantRun = dc.DnsServerEnable && !string.IsNullOrWhiteSpace(dc.DnsLogDomain);
            string key = wantRun ? dc.DnsServerPort + "|" + dc.DnsLogDomain.Trim().ToLowerInvariant() : "";

            if (key == _stateKey)
            {
                return Current != null;
            }
            _stateKey = key;

            try { _server?.Stop(); } catch { }
            _server = null;

            if (!wantRun)
            {
                SetStatus(dc, "未启用");
                return false;
            }
            try
            {
                var server = new DnsLogServerCore
                {
                    ZoneDomain = dc.DnsLogDomain.Trim(),
                    Logger = msg => Log.SysLog("[内置DNS] " + msg)
                };
                server.Start(dc.DnsServerPort);
                _server = server;
                SetStatus(dc, "运行中 UDP:" + dc.DnsServerPort);
                Log.Show("内置DNS接收服务已启动：UDP " + dc.DnsServerPort + "，权威区 " + dc.DnsLogDomain
                    + "（取数/检测的DNS回收将优先走本机记录）");
                return true;
            }
            catch (Exception e)
            {
                SetStatus(dc, "启动失败:" + e.Message);
                Log.Warning("内置DNS接收服务启动失败（UDP " + dc.DnsServerPort
                    + "）：" + e.Message + "。53端口需管理员/root权限且不能被占用，可改用高位端口测试；已回退第三方DNSLog平台通道。");
                return false;
            }
        }

        /// <summary>停止服务（程序退出时调用）</summary>
        public static void Shutdown()
        {
            try { _server?.Stop(); } catch { }
            _server = null;
            _stateKey = "";
        }

        private static void SetStatus(DataConfig dc, string text)
        {
            try
            {
                if (LogTools.Headless)
                {
                    dc.DnsServerStatus = text;
                }
                else
                {
                    Avalonia.Threading.Dispatcher.UIThread.Post( ()=> dc.DnsServerStatus = text);
                }
            }
            catch { }
        }
    }
}
