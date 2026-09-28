using System.Collections.Concurrent;
using System.Net.Sockets;

namespace SuperSQLInjectionV2.Tools.Http
{
    /// <summary>
    /// 池化连接：TcpClient + 已就绪传输流（SSL或明文），按 host:port:ssl:proxy 键复用。
    /// 盲注/取数场景对同一主机连续发包，省掉每请求的TCP+TLS握手。
    /// </summary>
    public sealed class PooledConnection : IDisposable
    {
        public required TcpClient Client { get; init; }
        public required Stream Stream { get; init; }
        public required string Key { get; init; }
        public DateTime LastUsedUtc { get; set; } = DateTime.UtcNow;

        /// <summary>NTLM连接级认证标记：认证通过的连接归还池复用，后续请求免握手（NTLM为连接绑定认证）</summary>
        public bool NtlmAuthenticated { get; set; }

        /// <summary>租借时占用的槽位状态（归还/丢弃时释放信号量），由连接池内部维护</summary>
        internal HttpConnectionPool.KeyState? State { get; set; }

        /// <summary>
        /// 探测连接是否仍然可用（对端关闭/网络断开返回false）
        /// </summary>
        public bool IsAlive()
        {
            try
            {
                if (Client == null || !Client.Connected) return false;
                //SelectRead=true且Available=0：对端已正常关闭连接
                if (Client.Client.Poll(0, SelectMode.SelectRead) && Client.Available == 0) return false;
                return true;
            }
            catch
            {
                return false;
            }
        }

        public void Dispose()
        {
            try { Stream?.Dispose(); } catch { }
            try { Client?.Close(); } catch { }
        }
    }

    /// <summary>
    /// 轻量HTTP连接池（Keep-Alive复用）。仅在响应被完整读取且服务端未声明close时归还连接。
    /// 并发上限由每键信号量保证：租不到空闲连接时排队等待归还，
    /// 不再"新建-归还即丢弃"造成线程数大于池大小时的TCP+TLS握手风暴。
    /// </summary>
    public static class HttpConnectionPool
    {
        /// <summary>每键状态：空闲连接栈 + 并发槽位信号量（槽位=在途+池内连接总数上限）</summary>
        internal sealed class KeyState
        {
            public required SemaphoreSlim Slots { get; set; }
            public int Limit { get; set; }
            public ConcurrentStack<PooledConnection> Stack { get; } = new();
        }

        private static readonly ConcurrentDictionary<string, KeyState> States = new();

        /// <summary>空闲连接存活秒数，超期取出即丢弃</summary>
        public static int IdleTtlSeconds = 30;

        /// <summary>每个键最大连接数（在途+池内合计），1-10，默认5</summary>
        public static int MaxPerKey = 5;

        /// <summary>
        /// 租用一个可用连接：占槽后有空闲且健康的连接则返回；
        /// 无空闲连接时返回null（槽位已占，调用方负责新建连接并在成功后AttachSlot，失败时ReleaseSlot）；
        /// 槽位满时异步排队等待归还，不再新建-丢弃。
        /// </summary>
        public static async Task<PooledConnection?> RentAsync(string key, CancellationToken ct)
        {
            KeyState st = States.GetOrAdd(key, _ => new KeyState { Slots = new SemaphoreSlim(MaxPerKey), Limit = MaxPerKey });
            //配置变更（1-10）：全部槽位空闲时安全替换信号量（在途连接持有旧实例引用，释放回旧实例，无碍）
            if (st.Limit != MaxPerKey && st.Stack.IsEmpty && st.Slots.CurrentCount == st.Limit)
            {
                st.Slots = new SemaphoreSlim(MaxPerKey);
                st.Limit = MaxPerKey;
            }
            await st.Slots.WaitAsync(ct).ConfigureAwait(false);
            while (st.Stack.TryPop(out PooledConnection? conn))
            {
                if ((DateTime.UtcNow - conn.LastUsedUtc).TotalSeconds <= IdleTtlSeconds && conn.IsAlive())
                {
                    conn.State = st;
                    return conn;
                }
                conn.Dispose();
            }
            return null;
        }

        /// <summary>RentAsync 返回 null 后新建连接成功：登记槽位状态（归还/丢弃时释放信号量）</summary>
        public static void AttachSlot(PooledConnection conn)
        {
            if (States.TryGetValue(conn.Key, out KeyState? st))
            {
                conn.State = st;
            }
        }

        /// <summary>RentAsync 占槽后新建连接失败：释放槽位，避免泄漏导致后续请求永久排队</summary>
        public static void ReleaseSlot(string key)
        {
            if (States.TryGetValue(key, out KeyState? st))
            {
                st.Slots.Release();
            }
        }

        /// <summary>归还连接到池（仅当响应完整读取且连接健康时调用）</summary>
        public static void Return(PooledConnection conn)
        {
            conn.LastUsedUtc = DateTime.UtcNow;
            KeyState? st = conn.State;
            if (st == null)
            {
                conn.Dispose();
                return;
            }
            st.Stack.Push(conn);
            st.Slots.Release();
        }

        /// <summary>丢弃连接（读异常/超时/服务端关闭时调用）</summary>
        public static void Discard(PooledConnection? conn)
        {
            if (conn == null) return;
            KeyState? st = conn.State;
            conn.State = null;
            conn.Dispose();
            st?.Slots.Release();
        }

        /// <summary>清空全部连接（停止任务/切换代理时调用）</summary>
        public static void Clear()
        {
            foreach (var kv in States)
            {
                while (kv.Value.Stack.TryPop(out PooledConnection? c)) c.Dispose();
            }
            States.Clear();
        }
    }
}
