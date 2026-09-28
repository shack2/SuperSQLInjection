using SuperSQLInjectionV2.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.Msg
{
    public class AddColumnMsg
    {
        public string TableName { get; set; } = "";
        public string ColumnName { get; set; } = "";
        public string DBName { get; set; } = "";
        public bool isAdd { get; set; } = false;
    }
}
