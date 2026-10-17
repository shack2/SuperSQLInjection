using System.ComponentModel;

namespace SuperSQLInjectionV2.Tools.Http;

public enum ProxyType
{
    [Description("固定")] Fixed,
    [Description("随机")] Rand
}