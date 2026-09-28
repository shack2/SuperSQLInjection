using SuperSQLInjectionV2.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.Msg
{
    public class AddStatusInfoMsg
    {
        public int TablesCount { get; set; } = 0;
        public int ColumnsCount { get; set; } = 0;
    }
}
