using System.ComponentModel;
using VYaml.Annotations;


namespace SuperSQLInjectionV2.Tools.Http;

[YamlObject]
public enum ProxyType
{
    [Description("固定")] Fixed,
    [Description("随机")] Rand
}