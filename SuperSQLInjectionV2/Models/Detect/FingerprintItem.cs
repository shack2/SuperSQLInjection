using CommunityToolkit.Mvvm.ComponentModel;

namespace SuperSQLInjectionV2.Models.Detect
{
    /// <summary>报错指纹管理项：对应 config/injection/errors.xml 中一条 error 条目</summary>
    public partial class FingerprintItem : ObservableObject
    {
        /// <summary>所属 DBMS 节点名（如 MySQL / IBM DB2 / DM）</summary>
        [ObservableProperty] private string _dbms = "";

        /// <summary>fork 衍生库名（如 MariaDB/TiDB，可空）</summary>
        [ObservableProperty] private string _fork = "";

        /// <summary>正则表达式（.NET 语法；的 \_ 写法加载时已规整）</summary>
        [ObservableProperty] private string _regexp = "";
    }
}
