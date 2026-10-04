using SuperSQLInjectionV2.Models;

namespace SuperSQLInjectionV2.Payload
{
    public class PayloadFactory
    {

        public static BasePayload BasePayload = null!;

        public static IDbDialect BPTool = null!;

        /// <summary>当前fork/衍生库名（如KingbaseES/openGauss/DM/MariaDB；空=族宿主本库）。Init时若磁盘存在 fork_&lt;归一化名&gt;.txt overlay则叠加到族模板</summary>
        public static string ForkName = "";

        /// <summary>
        /// 初始化当前数据库类型的取数方言：加载 config/payload/xx.txt 模板（fork非空且存在 fork_*.txt 时叠加fork差异），
        /// 由 <see cref="DialectFactory"/> 按 DBType 选择方言开关生成统一的 <see cref="TemplateDialect"/>。
        /// </summary>
        public static void Init(DBType dBType)
        {
            BasePayload = new BasePayload(dBType, ForkName);
            BPTool = DialectFactory.Create(dBType, BasePayload);
            //回显标记随模板重置（注入记录恢复时会再覆盖为记录携带的随机标记）
            EchoMarkers.Init(BasePayload);
        }
    }

}
