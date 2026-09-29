using CommunityToolkit.Mvvm.ComponentModel;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading;

namespace SuperSQLInjectionV2.Models
{
    public partial class ByPassConfig : ViewModelBase
    {
        public ByPassConfig()
        {
            Hook(ReplaceItems);
            Hook(EncodeTools);
            Hook(UaItemList);
            //标量属性变更（Enable/DelayMs/HppEnabled...）同样使计划失效；Revision自身变更除外
            PropertyChanged += (_, e) =>
            {
                if (e.PropertyName != nameof(Revision))
                {
                    Interlocked.Increment(ref _revision);
                }
            };
        }

        //---- 配置修订号与执行计划缓存（P0-2：配置低频变更、请求高频执行；计划随修订号失效重建）----

        private long _revision;
        /// <summary>配置修订号：任何绕过配置（标量/集合/集合项属性）变更时递增</summary>
        [JsonIgnore]
        public long Revision => _revision;

        private Bypass.BypassPlan? _plan;
        /// <summary>当前有效执行计划（修订号不一致时重建；并发重建产生重复实例无害，委托均为无状态）</summary>
        [JsonIgnore]
        public Bypass.BypassPlan Plan
        {
            get
            {
                Bypass.BypassPlan? p = _plan;
                if (p == null || p.Revision != _revision)
                {
                    _plan = p = Bypass.BypassPlan.Build(this);
                }
                return p;
            }
        }

        private void Hook(ObservableCollection<ReplaceModel> c) => HookCore(c);
        private void Hook(ObservableCollection<EncodeToolModel> c) => HookCore(c);
        private void Hook(ObservableCollection<UaItem> c) => HookCore(c);
        private void Unhook(System.Collections.IEnumerable? c)
        {
            if (c == null) return;
            foreach (var item in c)
            {
                if (item is INotifyPropertyChanged npc) npc.PropertyChanged -= ItemPropertyChanged;
            }
            if (c is INotifyCollectionChanged ncc) ncc.CollectionChanged -= CollectionChangedCore;
        }

        private void HookCore(System.Collections.IEnumerable c)
        {
            if (c is INotifyCollectionChanged ncc) ncc.CollectionChanged += CollectionChangedCore;
            foreach (var item in c)
            {
                if (item is INotifyPropertyChanged npc) npc.PropertyChanged += ItemPropertyChanged;
            }
        }

        private void CollectionChangedCore(object? sender, NotifyCollectionChangedEventArgs e)
        {
            if (e.OldItems != null)
            {
                foreach (var item in e.OldItems)
                {
                    if (item is INotifyPropertyChanged npc) npc.PropertyChanged -= ItemPropertyChanged;
                }
            }
            if (e.NewItems != null)
            {
                foreach (var item in e.NewItems)
                {
                    if (item is INotifyPropertyChanged npc) npc.PropertyChanged += ItemPropertyChanged;
                }
            }
            //编码工具链序号重编号（序号列=加载/执行顺序；Add/Remove/Move/整体替换均经此路径）
            if (ReferenceEquals(sender, _encodeTools))
            {
                for (int i = 0; i < _encodeTools.Count; i++)
                {
                    _encodeTools[i].Seq = i + 1;
                }
            }
            Interlocked.Increment(ref _revision);
        }

        private void ItemPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            Interlocked.Increment(ref _revision);
        }

        //---- 集合（setter内重新挂钩：反序列化整体替换实例时保持修订追踪）----

        private ObservableCollection<ReplaceModel> _replaceItems = new();
        //规则与状态分离：字符替换规则独立持久化到 config/rules/replace-rules.json（RuleStore），不进 lastconfig.json
        [JsonIgnore]
        public ObservableCollection<ReplaceModel> ReplaceItems
        {
            get => _replaceItems;
            set { Unhook(_replaceItems); _replaceItems = value; Hook(value); }
        }

        [JsonIgnore]
        [ObservableProperty] public partial ReplaceModel AddReplaceItem { get; set; } = new ReplaceModel();

        /// <summary>统一编码工具链（编码处理/tamper合并）：内置项按Key走C#注册表，自定义项为JS脚本；Payload级在Encode块内按序执行，报文级在发送前按序执行</summary>
        private ObservableCollection<EncodeToolModel> _encodeTools = new();
        //规则与状态分离：编码工具链独立持久化到 config/rules/tampers/（RuleStore），不进 lastconfig.json
        [JsonIgnore]
        public ObservableCollection<EncodeToolModel> EncodeTools
        {
            get => _encodeTools;
            set { Unhook(_encodeTools); _encodeTools = value; Hook(value); }
        }

        /// <summary>添加面板当前选中的内置工具Key（UI"添加内置工具"ComboBox绑定）</summary>
        [JsonIgnore]
        [ObservableProperty] public partial Bypass.EncodeTool? AddBuiltinTool { get; set; }

        //---- 频率控制与请求指纹（延时/限速/随机UA）----
        /// <summary>每次HTTP请求前固定延时（毫秒，0=不延时）</summary>
        [ObservableProperty] public partial int DelayMs { get; set; } = 0;

        /// <summary>每秒最大请求数（0=不限速，多线程发包全局生效）</summary>
        [ObservableProperty] public partial int SafeFreq { get; set; } = 0;

        /// <summary>随机User-Agent（每次请求从UA池随机选取）</summary>
        [ObservableProperty] public partial bool RandomUa { get; set; } = false;

        /// <summary>自定义UA池（带类型标签；非空时优先于内置UA池；配合RandomUa每请求轮换，不启用RandomUa则保留报文自身UA）</summary>
        private ObservableCollection<UaItem> _uaItemList = new();
        public ObservableCollection<UaItem> UaItemList
        {
            get => _uaItemList;
            set { Unhook(_uaItemList); _uaItemList = value; Hook(value); }
        }

        /// <summary>发包用UA字符串列表（只取勾选项；全部不勾选返回空，由调用方回落内置池）</summary>
        public List<string> AllUaStrings()
        {
            return UaItemList.Where(x => x.IsSelected).Select(x => x.Ua).Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
        }

        /// <summary>HPP参数污染：把注入参数值按空格拆分到多个同名参数（用于绕过参数级WAF）</summary>
        [ObservableProperty] public partial bool HppEnabled { get; set; } = false;

        /// <summary>chunked分块发包：POST体按Transfer-Encoding: chunked发送（绕过长 body WAF检测）</summary>
        [ObservableProperty] public partial bool ChunkedEnabled { get; set; } = false;

        /// <summary>随机源IP：伪造X-Forwarded-For/X-Real-IP/Client-IP头（绕过基于源IP的访问控制与频率限制）</summary>
        [ObservableProperty] public partial bool RandomIpEnabled { get; set; } = false;

        /// <summary>参数名大小写混淆：注入参数名每请求随机大小写（绕过按参数名精确匹配的参数级WAF）</summary>
        [ObservableProperty] public partial bool ParamCaseRandEnabled { get; set; } = false;
    }
}
