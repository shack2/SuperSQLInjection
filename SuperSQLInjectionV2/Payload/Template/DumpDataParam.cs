using SuperSQLInjectionV2.Models;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace SuperSQLInjectionV2.Payload
{
    public class DumpDataParam
    {

        public List<string> Columns { get; set; } = new List<string>();
        public string DBName { get; set; } = "";
    
        public string TableName { get; set; } = "";

        public int SumCount { get; set; } = 1;

        public int ShowIndex { get; set; } = 1;

        public int DataIndex { get; set; } = 1;

        /// <summary>自定义WHERE过滤条件（不含where关键字；空=不过滤）</summary>
        public string Where { get; set; } = "";

        /// <summary>no-cast：取数列不做cast/convert类型转换包装（no-cast 能力）</summary>
        public bool NoCast { get; set; } = false;

        /// <summary>Union非显示列填充字符（空=方言层回退模板UnionFillStr；人工配置/注入记录检测值优先）</summary>
        public string UnionFill { get; set; } = "";

        /// <summary>可选稳定分页键（必须是本次选取的唯一列）；为空保持原有OFFSET/ROWNUM行为。</summary>
        public string StableKey { get; set; } = "";
        /// <summary>上一行稳定键值；非空且方言提供Keyset模板时改用键集分页。</summary>
        public string? LastKeyValue { get; set; }

        public DumpDataParam(List<string> columns,string dbName,string tableName,int sumCount, int showIndex, int dataIndex) {
            Columns = columns;
            DBName = dbName;
            TableName = tableName;
            ShowIndex = showIndex;
            SumCount = sumCount;
            DataIndex = dataIndex;
        }

        public DumpDataParam(List<string> columns, string dbName, string tableName, int dataStartIndex)
        {
            Columns = columns;
            DBName = dbName;
            TableName = tableName;
            DataIndex= dataStartIndex;
        }

        public DumpDataParam(List<string> columns, string dbName, string tableName, int sumCount,int showIndex)
        {
            Columns = columns;
            DBName = dbName;
            TableName = tableName;
            ShowIndex = showIndex;
            SumCount = sumCount;
            ShowIndex = showIndex;
        }
    }
}
