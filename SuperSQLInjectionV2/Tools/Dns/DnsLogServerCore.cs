using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.Tools.Dns
{
    /// <summary>一条DNS解析记录</summary>
    public sealed class DnsQueryRecord
    {
        public string Name = "";       //完整查询名（小写规范化）
        public string ClientIp = "";   //发起解析的来源IP（目标侧的DNS出口）
        public DateTime Time = DateTime.Now;
    }

    /// <summary>
    /// 自建DNS外带接收端核心（P2-8）：UDP监听 + 极简DNS协议解析 + 区内查询记录 + A记录应答。
    /// 双形态共用：主程序内嵌（本机直连监听，53需管理员/root，可用高位端口测试）；
    /// 独立服务端（SuperSQLInjectionV2.DnsServer，部署VPS，附ceye兼容HTTP查询API）。
    /// 外带记录形态：i{序号}.{hex}.{域名}（取数）/ {token}.{域名}（注入检测），与DnsExfilTool约定一致。
    /// 本类不依赖主程序任何类型（日志走回调），保证独立服务端单文件链接复用。
    /// </summary>
    public sealed class DnsLogServerCore : IDisposable
    {
        /// <summary>日志回调（主程序接Log.SysLog，独立服务端接Console）</summary>
        public Action<string>? Logger { get; set; }

        /// <summary>权威区域名（只记录该后缀的查询；空=记录全部，仅调试用）</summary>
        public string ZoneDomain { get; set; } = "";

        /// <summary>应答A记录的IP（默认127.0.0.1；部分数据库触发器需要解析成功才走完流程）</summary>
        public string AnswerIp { get; set; } = "127.0.0.1";

        /// <summary>记录容量上限（超限剔最旧，防内存膨胀）</summary>
        public int Capacity { get; set; } = 10000;

        private readonly ConcurrentQueue<DnsQueryRecord> _records = new ConcurrentQueue<DnsQueryRecord>();
        private UdpClient? _udp;
        private CancellationTokenSource? _cts;
        private Task? _loop;
        private int _port;

        public bool Running => _udp != null;
        public int Port => _port;

        /// <summary>启动UDP监听。绑定失败（端口占用/权限不足）抛异常，由调用方提示</summary>
        public void Start(int port)
        {
            Stop();
            _port = port;
            _cts = new CancellationTokenSource();
            _udp = new UdpClient(new IPEndPoint(IPAddress.Any, port));
            //Windows下避免ICMP端口不可达导致ReceiveAsync抛SocketException炸掉循环
            try { _udp.Client.IOControl(-1744830452 /*SIO_UDP_CONNRESET*/, new byte[] { 0 }, null); } catch { }
            _loop = Task.Run( ()=> ReceiveLoop(_cts.Token));
            Log("DNS接收服务已启动：UDP " + port + (ZoneDomain.Length > 0 ? "，权威区=" + ZoneDomain : ""));
        }

        public void Stop()
        {
            try { _cts?.Cancel(); } catch { }
            try { _udp?.Close(); } catch { }
            _udp = null;
            _cts = null;
        }

        public void Dispose() => Stop();

        /// <summary>清空全部记录（开始新一轮外带/检测前调用，防旧记录串读）</summary>
        public void Clear()
        {
            while (_records.TryDequeue(out _)) { }
        }

        /// <summary>快照当前记录（按时间升序）</summary>
        public List<DnsQueryRecord> Snapshot()
        {
            return _records.ToList();
        }

        /// <summary>
        /// 导出ceye兼容JSON（{"data":[{"name":...}]}），供DnsExfilTool现有解析方法（ParseCeyeRecords/CollectTokenHits）零改动复用。
        /// filter非空时只导出以 .filter 结尾的记录
        /// </summary>
        public string ToCeyeJson(string filter)
        {
            var sb = new StringBuilder(256);
            sb.Append("{\"data\":[");
            bool first = true;
            string suffix = string.IsNullOrEmpty(filter) ? "" : "." + filter.Trim('.').ToLowerInvariant();
            foreach (var r in _records)
            {
                if (suffix.Length > 0 && !r.Name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                if (!first)
                {
                    sb.Append(',');
                }
                first = false;
                sb.Append("{\"name\":\"").Append(r.Name).Append("\"}");
            }
            sb.Append("]}");
            return sb.ToString();
        }

        private async Task ReceiveLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                UdpReceiveResult packet;
                try
                {
                    packet = await _udp!.ReceiveAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (SocketException)
                {
                    continue; //对端RST/瞬时错误，继续收
                }
                catch
                {
                    break;
                }
                try
                {
                    HandlePacket(packet);
                }
                catch (Exception e)
                {
                    Log("DNS报文处理异常：" + e.Message);
                }
            }
        }

        private void HandlePacket(UdpReceiveResult packet)
        {
            byte[] data = packet.Buffer;
            if (data.Length < 12)
            {
                return;
            }
            //QR位=0才是查询
            if ((data[2] & 0x80) != 0)
            {
                return;
            }
            int qdCount = (data[4] << 8) | data[5];
            if (qdCount < 1)
            {
                return;
            }
            if (!TryParseQName(data, 12, out string qname, out int qEnd))
            {
                return;
            }
            qname = qname.ToLowerInvariant();

            //区内记录（ZoneDomain为空=调试模式全记）
            string zone = ZoneDomain.Trim('.').ToLowerInvariant();
            bool inZone = zone.Length == 0
                || qname.Equals(zone, StringComparison.Ordinal)
                || qname.EndsWith("." + zone, StringComparison.Ordinal);
            if (inZone)
            {
                _records.Enqueue(new DnsQueryRecord
                {
                    Name = qname,
                    ClientIp = packet.RemoteEndPoint.Address.ToString(),
                    Time = DateTime.Now
                });
                while (_records.Count > Capacity && _records.TryDequeue(out _)) { }
                Log("DNS解析记录：" + qname + " <- " + packet.RemoteEndPoint.Address);
            }

            //应答A记录（让目标侧解析流程走完；EDNS/附加段直接忽略不回）
            byte[] resp = BuildAResponse(data, qEnd);
            if (resp != null)
            {
                try { _udp!.Send(resp, resp.Length, packet.RemoteEndPoint); } catch { }
            }
        }

        /// <summary>解析question段的qname（不支持指针压缩——question段合法报文不出现压缩），返回结束偏移（指向QTYPE）</summary>
        private static bool TryParseQName(byte[] data, int offset, out string qname, out int qEnd)
        {
            var sb = new StringBuilder(255);
            qEnd = offset;
            int guard = 0;
            while (qEnd < data.Length && guard++ < 128)
            {
                int len = data[qEnd];
                if (len == 0)
                {
                    qEnd++;
                    qname = sb.ToString();
                    return qname.Length > 0;
                }
                if (len > 63 || qEnd + 1 + len > data.Length)
                {
                    qname = "";
                    return false;
                }
                if (sb.Length > 0)
                {
                    sb.Append('.');
                }
                sb.Append(Encoding.ASCII.GetString(data, qEnd + 1, len));
                qEnd += 1 + len;
            }
            qname = "";
            return false;
        }

        /// <summary>构造A记录应答：ID/问题段原样回显，flags=QR|RD|RA，answer指向问题段(0xC00C)</summary>
        private byte[] BuildAResponse(byte[] query, int questionEnd)
        {
            if (questionEnd + 4 > query.Length)
            {
                return Array.Empty<byte>();
            }
            int questionTotal = questionEnd + 4; //qname + QTYPE + QCLASS
            var resp = new byte[questionTotal + 16];
            Array.Copy(query, resp, questionTotal);
            //flags: QR=1 RD=copy RA=1 RCODE=0
            resp[2] = (byte)((query[2] & 0x01) | 0x80);
            resp[3] = 0x80;
            //ANCOUNT=1
            resp[6] = 0; resp[7] = 1;
            //NS/AR清零（不回EDNS）
            resp[8] = 0; resp[9] = 0; resp[10] = 0; resp[11] = 0;
            int p = questionTotal;
            resp[p++] = 0xC0; resp[p++] = 0x0C;      //name指针
            resp[p++] = 0x00; resp[p++] = 0x01;      //TYPE A
            resp[p++] = 0x00; resp[p++] = 0x01;      //CLASS IN
            resp[p++] = 0x00; resp[p++] = 0x00; resp[p++] = 0x00; resp[p++] = 60; //TTL 60s
            resp[p++] = 0x00; resp[p++] = 0x04;      //RDLENGTH
            string[] parts = (AnswerIp ?? "127.0.0.1").Split('.');
            for (int i = 0; i < 4; i++)
            {
                resp[p++] = parts.Length == 4 && byte.TryParse(parts[i], out byte b) ? b : (byte)127;
            }
            return resp;
        }

        private void Log(string msg)
        {
            try { Logger?.Invoke(msg); } catch { }
        }
    }
}
