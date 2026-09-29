using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SuperSQLInjectionV2.Tools.Http;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text.Json.Serialization;
using VYaml.Annotations;

namespace SuperSQLInjectionV2.Models
{

    public partial class ProxyConfig : ViewModelBase

    {
        [ObservableProperty] public partial bool ProxyEnable { get; set; } = true;

        [ObservableProperty] public partial ProxyType? SelectProxyType { get; set; } = ProxyType.Fixed;

        //规则与状态分离：代理池独立持久化到 config/rules/proxies.json（RuleStore），不进 lastconfig.json
        [JsonIgnore]
        public ObservableCollection<Proxy> ProxyItems { get; set; } = new ObservableCollection<Proxy>();

        [JsonIgnore]
        public List<ProxyType> ProxyTypeItems { get; set; } = [ProxyType.Fixed, ProxyType.Rand];

        [ObservableProperty] public partial Proxy? AddProxy { get; set; } = new Proxy();

        /// <summary>
        /// 当前正在使用的代理显示文本
        /// </summary>
        [ObservableProperty] public partial string CurrentProxyText { get; set; } = "未使用代理";

        public Random rd = new Random();

    }
}
