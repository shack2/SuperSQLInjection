using CommunityToolkit.Mvvm.ComponentModel;
using System.Collections.Generic;

namespace SuperSQLInjectionV2.Models.Detect
{
    /// <summary>
    /// 检测payload管理项：对应config/injection下某XML文件中的一条test用例，字段均为字符串便于界面直接编辑。
    /// Index=-1表示新增未落盘；FileName为所在文件名（不含目录）。
    /// </summary>
    public partial class PayloadItem : ObservableObject
    {
        /// <summary>所在XML文件名（不含目录，如 boolean_blind.xml / custom_user.xml / dns_blind.xml）</summary>
        [ObservableProperty] private string _fileName = "";
        /// <summary>在文件内test元素的序号（0基）；-1=新增未落盘</summary>
        [ObservableProperty] private int _index = -1;
        [ObservableProperty] private string _title = "";
        /// <summary>技术类型：1布尔盲注 2报错 3内联 4堆叠 5时间 6Union 7DNS外带</summary>
        [ObservableProperty] private int _sType = 1;
        [ObservableProperty] private int _level = 1;
        [ObservableProperty] private int _risk = 1;
        /// <summary>子句适用范围，逗号分隔（1,2,3,8,9）</summary>
        [ObservableProperty] private string _clause = "1,2,3,8,9";
        /// <summary>拼接方式，逗号分隔（1=拼原值后 2=负值替换 3=整体替换）</summary>
        [ObservableProperty] private string _where = "1";
        [ObservableProperty] private string _vector = "";
        [ObservableProperty] private string _payload = "";
        [ObservableProperty] private string _comment = "";
        [ObservableProperty] private string _dbms = "";
        [ObservableProperty] private string _dbmsExclude = "";
        /// <summary>检测命中次数（持久化在config/injection/hit_count.json，随用例库加载合并）</summary>
        [ObservableProperty] private int _hitCount;

        /// <summary>技术类型显示名（界面下拉用，get/set与SType联动）</summary>
        public string STypeName
        {
            get => SType switch
            {
                1 => "布尔盲注",
                2 => "报错注入",
                3 => "内联查询",
                4 => "堆叠查询",
                5 => "时间盲注",
                6 => "Union查询",
                7 => "DNS外带探测",
                _ => "未知"
            };
            set
            {
                int v = value switch
                {
                    "布尔盲注" => 1,
                    "报错注入" => 2,
                    "内联查询" => 3,
                    "堆叠查询" => 4,
                    "时间盲注" => 5,
                    "Union查询" => 6,
                    "DNS外带探测" => 7,
                    _ => 1
                };
                SType = v;
                OnPropertyChanged(nameof(STypeName));
            }
        }

        public static readonly List<string> STypeNames = new List<string>
            { "布尔盲注", "报错注入", "内联查询", "堆叠查询", "时间盲注", "Union查询", "DNS外带探测" };
    }
}
