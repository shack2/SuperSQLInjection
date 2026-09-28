using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.Models.Data
{
    /// <summary>
    /// 列信息配置
    /// </summary>
    public class ColumnInfo
    {
        /// <summary>
        /// 列头显示文本
        /// </summary>
        public string Header { get; set; } = string.Empty;

        /// <summary>
        /// 绑定的属性名
        /// </summary>
        public string PropertyName { get; set; } = string.Empty;

        /// <summary>
        /// 列宽权重
        /// </summary>
        public double Width { get; set; } = 1.0;

        /// <summary>
        /// 是否只读
        /// </summary>
        public bool IsReadOnly { get; set; } = false;

        /// <summary>
        /// 最小宽度
        /// </summary>
        public double MinWidth { get; set; } = 80;

        /// <summary>
        /// 列类型
        /// </summary>
        public ColumnType Type { get; set; } = ColumnType.Text;

        /// <summary>
        /// 数据格式化字符串
        /// </summary>
        public string? Format { get; set; }
    }
}
