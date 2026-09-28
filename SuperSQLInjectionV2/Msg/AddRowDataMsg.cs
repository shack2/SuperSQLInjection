using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Models.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.Msg
{
    public class AddRowDataMsg
    {
        public DynamicDataItem Data=new();
    }
}
