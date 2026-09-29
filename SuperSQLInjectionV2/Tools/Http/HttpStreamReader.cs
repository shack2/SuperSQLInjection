using System;
using System.Buffers;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.Tools.Http
{
    /// <summary>
    /// 带缓冲的HTTP流读取器：内部缓冲池化（ArrayPool），支持跨读边界的分隔符查找，
    /// over-read字节留在缓冲中供后续body读取，替代旧的逐字节ReadByte实现。
    /// 注意：Dispose只归还缓冲，不关闭底层流（连接池复用）。
    /// </summary>
    internal sealed class HttpStreamReader : IDisposable
    {
        private readonly Stream _stream;
        private readonly byte[] _buf;
        private int _pos;
        private int _len;

        public HttpStreamReader(Stream stream, int capacity = 16384)
        {
            _stream = stream;
            _buf = ArrayPool<byte>.Shared.Rent(capacity);
        }

        private async ValueTask<int> FillMoreAsync(CancellationToken ct)
        {
            if (_pos > 0)
            {
                Array.Copy(_buf, _pos, _buf, 0, _len - _pos);
                _len -= _pos;
                _pos = 0;
            }
            if (_len == _buf.Length) return -1; //缓冲满且未消费完，调用方分隔符过大的异常场景
            int n = await _stream.ReadAsync(_buf.AsMemory(_len, _buf.Length - _len), ct).ConfigureAwait(false);
            _len += n;
            return n;
        }

        /// <summary>
        /// 读取直到delimiter（含delimiter在内返回）。对端关闭仍未找到时返回已累计内容。
        /// </summary>
        public async Task<byte[]> ReadUntilAsync(byte[] delimiter, CancellationToken ct)
        {
            using MemoryStream ms = new MemoryStream();
            int keep = delimiter.Length - 1;
            while (true)
            {
                if (_len - _pos > 0)
                {
                    int idx = IndexOf(_buf, _pos, _len - _pos, delimiter);
                    if (idx >= 0)
                    {
                        int take = idx + delimiter.Length - _pos;
                        ms.Write(_buf, _pos, take);
                        _pos += take;
                        return ms.ToArray();
                    }
                    //保留尾部keep字节（分隔符可能跨缓冲边界），其余先写出
                    int writable = _len - _pos - keep;
                    if (writable > 0)
                    {
                        ms.Write(_buf, _pos, writable);
                        _pos += writable;
                    }
                }
                int n = await FillMoreAsync(ct).ConfigureAwait(false);
                if (n <= 0) return ms.ToArray(); //EOF或缓冲满
            }
        }

        /// <summary>读一行（以\n结尾），返回不含\r\n的ASCII字符串；EOF且无数据返回null</summary>
        public async Task<string?> ReadLineAsync(CancellationToken ct)
        {
            using MemoryStream ms = new MemoryStream();
            while (true)
            {
                if (_len - _pos > 0)
                {
                    int idx = Array.IndexOf(_buf, (byte)'\n', _pos, _len - _pos);
                    if (idx >= 0)
                    {
                        ms.Write(_buf, _pos, idx - _pos + 1);
                        _pos = idx + 1;
                        return Encoding.ASCII.GetString(ms.ToArray()).TrimEnd('\r', '\n');
                    }
                    ms.Write(_buf, _pos, _len - _pos);
                    _pos = _len;
                }
                int n = await FillMoreAsync(ct).ConfigureAwait(false);
                if (n <= 0)
                {
                    return ms.Length > 0 ? Encoding.ASCII.GetString(ms.ToArray()).TrimEnd('\r', '\n') : null;
                }
            }
        }

        /// <summary>精确读取count字节到dst，返回实际读取数（EOF提前返回不足count）</summary>
        public async Task<long> ReadExactAsync(MemoryStream dst, long count, CancellationToken ct)
        {
            long read = 0;
            while (read < count)
            {
                if (_len - _pos == 0)
                {
                    int n = await FillMoreAsync(ct).ConfigureAwait(false);
                    if (n <= 0) break;
                }
                int take = (int)Math.Min(_len - _pos, count - read);
                dst.Write(_buf, _pos, take);
                _pos += take;
                read += take;
            }
            return read;
        }

        /// <summary>读到对端关闭（connection: close语义），EOF结束</summary>
        public async Task ReadToEndAsync(MemoryStream dst, CancellationToken ct)
        {
            while (true)
            {
                if (_len - _pos > 0)
                {
                    dst.Write(_buf, _pos, _len - _pos);
                    _pos = _len;
                }
                int n = await FillMoreAsync(ct).ConfigureAwait(false);
                if (n <= 0) break;
            }
        }

        private static int IndexOf(byte[] src, int start, int count, byte[] pattern)
        {
            int end = start + count - pattern.Length;
            for (int i = start; i <= end; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (src[i + j] != pattern[j]) { match = false; break; }
                }
                if (match) return i;
            }
            return -1;
        }

        public void Dispose()
        {
            ArrayPool<byte>.Shared.Return(_buf);
        }
    }
}
