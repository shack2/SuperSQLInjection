using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Models.Detect;
using System.Collections.Generic;
using System.Linq;

namespace SuperSQLInjectionV2.Tools.Inject
{
    /// <summary>
    /// 跨参数信号共享（同一次检测会话）：同一请求的多个参数共享同一后端SQL构造代码与数据库实例，
    /// 参数A检出的注入边界（引号/括号形态）与命中库对参数B大概率同样成立。
    /// 共享方式为「优先排序非限定」：B参数把共享boundary排到最前、共享库专属用例优先测试，
    /// 未命中则自然走完剩余全量矩阵，不会漏检。
    /// 线程安全：多参数并行检测时发布/读取均加锁。
    /// </summary>
    public sealed class DetectSessionState
    {
        private readonly object _gate = new object();
        private PayloadBoundary? _boundary;
        private readonly List<DBType> _dbs = new List<DBType>();
        /// <summary>首个发布信号的参数名（日志追溯用）</summary>
        private string _sourceParam = "";

        /// <summary>是否有可共享信号</summary>
        public bool HasSignal
        {
            get { lock (_gate) { return _boundary != null || _dbs.Count > 0; } }
        }

        /// <summary>发布命中信号：首个命中boundary + 命中库（参数内命中/错误指纹均可发布）</summary>
        public void Publish(PayloadBoundary? boundary, DBType db, string paramName)
        {
            lock (_gate)
            {
                if (boundary != null && _boundary == null)
                {
                    _boundary = boundary;
                    _sourceParam = paramName;
                }
                if (db != DBType.UnKnow && !_dbs.Contains(db))
                {
                    _dbs.Add(db);
                    if (string.IsNullOrEmpty(_sourceParam))
                    {
                        _sourceParam = paramName;
                    }
                }
            }
        }

        /// <summary>共享boundary快照（无则null）</summary>
        public PayloadBoundary? Boundary
        {
            get { lock (_gate) { return _boundary; } }
        }

        /// <summary>共享命中库快照（无则空表）</summary>
        public List<DBType> Dbs
        {
            get { lock (_gate) { return _dbs.ToList(); } }
        }

        /// <summary>信号来源参数名</summary>
        public string SourceParam
        {
            get { lock (_gate) { return _sourceParam; } }
        }

        /// <summary>共享boundary排到boundary枚举最前（其余保持原顺序，未命中自然回退全量）</summary>
        public List<PayloadBoundary> OrderBoundaries(IEnumerable<PayloadBoundary> boundaries)
        {
            PayloadBoundary? shared = Boundary;
            List<PayloadBoundary> list = boundaries.ToList();
            if (shared == null)
            {
                return list;
            }
            int idx = list.FindIndex(b => ReferenceEquals(b, shared));
            if (idx > 0)
            {
                list.RemoveAt(idx);
                list.Insert(0, shared);
            }
            return list;
        }
    }
}
