using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SuperSQLInjection.tools.http
{
    class SocketProxy
    {

        private static byte[] s5_hello = new Byte[] { 5, 1, 0 };
        public int CreatProxyUseTime = 0;
        public int ConectProxyUseTime = 0;
        private Stopwatch sw = new Stopwatch();

        /// <summary>异步版代理TCP连接：原生await ConnectAsync，不占线程池线程空等（请求热路径使用）</summary>
        public async System.Threading.Tasks.Task<TcpClient> CreatProxySocketAsync(string host, int port, int timeout, System.Threading.CancellationToken ct = default)
        {
            TcpClient client = new TcpClient();
            long ts = Stopwatch.GetTimestamp();
            try
            {
                using var cts = System.Threading.CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(timeout);
                await client.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
                CreatProxyUseTime = (int)Stopwatch.GetElapsedTime(ts).TotalMilliseconds;
                return client;
            }
            catch
            {
                client.Close();
                throw;
            }
        }

        public byte[] GetLoginByte(string username,string password) {

            byte[] bUser = Encoding.Default.GetBytes(username);
            byte[] bPass = Encoding.Default.GetBytes(password);

            int len = 3 + bUser.Length + bPass.Length;

            byte[]  data = new Byte[len];
            data[0] = 5;
            data[1] = (byte)bUser.Length;
            Array.Copy(bUser, 0, data, 2, bUser.Length);
            data[2 + bUser.Length] = (byte)bPass.Length;
            Array.Copy(bPass, 0, data, 3 + bUser.Length, bPass.Length);
            return data;
        }

        public byte[] GetConectTargetByte(string hsot, int port)
        {
            byte[] data = new byte[10];
            data[0] = 5;
            data[1] = 1;
            data[2] = 0;
            data[3] = 1;

            IPAddress ipAdd = Dns.GetHostAddresses(hsot)[0];
            string strIp = ipAdd.ToString();
            string[] strAryTemp = strIp.Split('.');
            data[4] = Convert.ToByte(strAryTemp[0]);
            data[5] = Convert.ToByte(strAryTemp[1]);
            data[6] = Convert.ToByte(strAryTemp[2]);
            data[7] = Convert.ToByte(strAryTemp[3]);

            data[8] = (byte)(port / 256);
            data[9] = (byte)(port % 256);
            return data;
        }

        /// <summary>
        /// 异步版Socks5握手（请求热路径使用）：全程异步读写，取消令牌贯穿，不占线程池线程空等
        /// </summary>
        public async System.Threading.Tasks.Task<bool> ConnectProxyServerAsync(string host, int port, TcpClient sProxyServer, string username, string password, int timeout, System.Threading.CancellationToken ct = default)
        {
            try
            {
                sw.Restart();
                NetworkStream stream = sProxyServer.GetStream();
                using var cts = System.Threading.CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(Math.Max(1000, (timeout * 1000) - CreatProxyUseTime));
                System.Threading.CancellationToken token = cts.Token;

                //第一握手：无认证则发hello，有账号密码则直接发认证协商
                byte[] hello = (String.IsNullOrEmpty(username) && String.IsNullOrEmpty(password))
                    ? s5_hello
                    : GetLoginByte(username, password);
                await stream.WriteAsync(hello, token).ConfigureAwait(false);
                byte[] resp = new byte[10];
                int readCount = await stream.ReadAsync(resp, token).ConfigureAwait(false);
                if (readCount < 2)
                {
                    throw new Exception("不能获得代理服务器正确响应。");
                }
                if (resp[0] != 5 || (resp[1] != 0 && resp[1] != 2))
                {
                    throw new Exception("代理服务其返回的响应错误。");
                }
                if (resp[1] == 2 && String.IsNullOrEmpty(username) && String.IsNullOrEmpty(password))
                {
                    throw new Exception("代理服务器需要进行身份确认,您未设置代理账号和密码。");
                }
                if (resp[1] != 0)
                {
                    return false;
                }
                //连接目标（DNS解析异步化）
                byte[] data = await GetConectTargetByteAsync(host, port).ConfigureAwait(false);
                await stream.WriteAsync(data, token).ConfigureAwait(false);
                byte[] readData = new byte[100];
                readCount = await stream.ReadAsync(readData, token).ConfigureAwait(false);
                return readCount >= 2 && readData[0] == 5 && readData[1] == 0;
            }
            finally
            {
                sw.Stop();
                ConectProxyUseTime = (int)sw.ElapsedMilliseconds;
                sw.Reset();
            }
        }

        /// <summary>异步版目标地址构造（DNS解析异步化）</summary>
        public async System.Threading.Tasks.Task<byte[]> GetConectTargetByteAsync(string hsot, int port)
        {
            byte[] data = new byte[10];
            data[0] = 5;
            data[1] = 1;
            data[2] = 0;
            data[3] = 1;

            IPAddress[] addrs = await Dns.GetHostAddressesAsync(hsot).ConfigureAwait(false);
            string strIp = addrs[0].ToString();
            string[] strAryTemp = strIp.Split('.');
            data[4] = Convert.ToByte(strAryTemp[0]);
            data[5] = Convert.ToByte(strAryTemp[1]);
            data[6] = Convert.ToByte(strAryTemp[2]);
            data[7] = Convert.ToByte(strAryTemp[3]);

            data[8] = (byte)(port / 256);
            data[9] = (byte)(port % 256);
            return data;
        }
    }
}
