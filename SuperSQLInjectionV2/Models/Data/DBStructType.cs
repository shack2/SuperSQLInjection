using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.Models.Data
{
    public enum DBStructType
    {
        [Description("数据库名")] DBName,
        [Description("表名")] TableName,
        [Description("字段名")] ColumnName,
    }
}
