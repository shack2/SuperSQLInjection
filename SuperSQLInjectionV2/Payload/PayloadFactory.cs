using SuperSQLInjectionV2.Models;

namespace SuperSQLInjectionV2.Payload
{
    public class PayloadFactory
    {

        public static BasePayload BasePayload = null!;

        public static IDbDialect BPTool = null!;

        /// <summary>
        /// 初始化当前数据库类型的取数方言：加载 config/payload/xx.txt 模板，
        /// 由 <see cref="DialectFactory"/> 按 DBType 选择方言开关生成统一的 <see cref="TemplateDialect"/>。
        /// </summary>
        public static void Init(DBType dBType)
        {
            BasePayload = new BasePayload(dBType);
            BPTool = DialectFactory.Create(dBType, BasePayload);
            //回显标记随模板重置（注入记录恢复时会再覆盖为记录携带的随机标记）
            EchoMarkers.Init(BasePayload);
        }
    }

}
