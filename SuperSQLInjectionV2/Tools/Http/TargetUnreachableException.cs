using System;

namespace SuperSQLInjectionV2.Tools.Http
{
    /// <summary>
    /// 目标不可达异常：TCP连接被拒绝/DNS解析失败/网络或主机不可达/代理连接失败等基础设施级错误。
    /// 与超时区分——超时可能是WAF丢包或慢响应，值得重试；不可达重试无意义，
    /// 抛出后跳过发包重试，并逐层上抛终止当前目标剩余的检测阶段（对齐sqlmap连不上即abort的行为）。
    /// </summary>
    public class TargetUnreachableException : Exception
    {
        public TargetUnreachableException(string host, int port, Exception inner)
            : base("目标主机" + host + ":" + port + "无法连接（" + RootMessage(inner) + "）", inner)
        {
        }

        public TargetUnreachableException(string message)
            : base(message)
        {
        }

        /// <summary>取异常链最底层原因作为可读描述（SocketException本地化消息在根部）</summary>
        private static string RootMessage(Exception e)
        {
            Exception cur = e;
            while (cur.InnerException != null)
            {
                cur = cur.InnerException;
            }
            return cur.Message;
        }
    }
}
