using SuperSQLInjectionV2.Models;

namespace SuperSQLInjectionV2.Payload
{
    /// <summary>每个注入目标配置独立的数据库方言与回显标记状态。</summary>
    public sealed class PayloadSession
    {
        public BasePayload Base { get; private set; } = null!;
        public IDbDialect Dialect { get; private set; } = null!;
        public string ForkName { get; set; } = "";
        public MarkerSet Markers { get; } = new MarkerSet();

        public void Init(DBType dbType, string? forkName = null)
        {
            if (forkName != null) ForkName = forkName;
            Base = new BasePayload(dbType, ForkName);
            Dialect = DialectFactory.Create(dbType, Base);
            Markers.Init(Base);
        }
    }

    /// <summary>会话内回显标记，不再有进程级共享Start/End/Split。</summary>
    public sealed class MarkerSet
    {
        public string Start { get; set; } = "data_";
        public string End { get; set; } = "_data";
        public string Split { get; set; } = "_s_p_";

        public void Init(BasePayload bp)
        {
            Start = bp.DataStartStr;
            End = bp.DataEndStr;
            Split = bp.DataSplitStr;
        }

        public void Use(string? start, string? end, string? split, BasePayload bp)
        {
            if (!string.IsNullOrEmpty(start) && !string.IsNullOrEmpty(end) && !string.IsNullOrEmpty(split))
            {
                Start = start;
                End = end;
                Split = split;
            }
            else
            {
                Init(bp);
            }
        }
    }
}
