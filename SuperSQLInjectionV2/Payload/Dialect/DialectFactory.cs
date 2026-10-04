using SuperSQLInjectionV2.Models;

namespace SuperSQLInjectionV2.Payload
{
    /// <summary>
    /// 方言工厂：DBType → <see cref="DialectOptions"/> 映射。
    /// 选项声明统一收拢到 <see cref="DbProfile"/> 注册表，此处仅做转发；
    /// DM 复用 Oracle 方言、Kingbase/OpenGauss 复用 PostgreSQL 方言（SQL 模板仍来自各自 txt）。
    /// </summary>
    public static class DialectFactory
    {
        public static IDbDialect Create(DBType dbType, BasePayload bp)
        {
            return new TemplateDialect(bp, OptionsFor(dbType));
        }

        public static DialectOptions OptionsFor(DBType dbType)
        {
            return DbProfile.OptionsFor(dbType);
        }
    }
}
