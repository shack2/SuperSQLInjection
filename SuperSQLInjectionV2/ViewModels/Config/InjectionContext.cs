using CommunityToolkit.Mvvm.ComponentModel;
using SuperSQLInjectionV2.ViewModels;

namespace SuperSQLInjectionV2.Models
{
    /// <summary>
    /// 注入上下文来源
    /// </summary>
    public enum InjectContextSource
    {
        /// <summary>未建立</summary>
        None,
        /// <summary>自动检测命中</summary>
        AutoDetect,
        /// <summary>从注入记录恢复</summary>
        InjectRecord,
        /// <summary>手工指定/覆盖</summary>
        Manual
    }

    /// <summary>
    /// 注入上下文：检测确认的结论（注入类型/数据库/编码/Union列位等），
    /// 数据读取、命令执行、文件读写等利用链路统一消费它；
    /// 与检测参数（Level/Risk/线程）分离，避免两个阶段配置混淆。
    /// </summary>
    public partial class InjectionContext : ViewModelBase
    {
        /// <summary>上下文来源</summary>
        [ObservableProperty] private InjectContextSource _source = InjectContextSource.None;

        /// <summary>来源说明（如：注入记录 参数id / 自动检测）</summary>
        [ObservableProperty] private string _sourceDetail = "";

        /// <summary>注入参数名</summary>
        [ObservableProperty] private string _paramName = "";

        /// <summary>注入类型（UnKnow=未确认）</summary>
        [ObservableProperty] private InjectType _injectType = InjectType.UnKnow;

        /// <summary>数据库类型（UnKnow=未识别）</summary>
        [ObservableProperty] private DBType _dbType = DBType.UnKnow;

        /// <summary>数据库编码</summary>
        [ObservableProperty] private string _dbEncoding = "UTF-8";

        /// <summary>Union 总列数</summary>
        [ObservableProperty] private int _sumColumnCount = 4;

        /// <summary>Union 显示列下标</summary>
        [ObservableProperty] private int _showColumnIndex = 2;

        /// <summary>来源显示文本</summary>
        public string SourceText => Source switch
        {
            InjectContextSource.AutoDetect => "自动检测",
            InjectContextSource.InjectRecord => "注入记录",
            InjectContextSource.Manual => "手工指定",
            _ => "未建立"
        };

        partial void OnSourceChanged(InjectContextSource value)
        {
            OnPropertyChanged(nameof(SourceText));
        }

        /// <summary>是否存在可用上下文</summary>
        public bool IsValid => Source != InjectContextSource.None && InjectType != InjectType.UnKnow;
    }
}
