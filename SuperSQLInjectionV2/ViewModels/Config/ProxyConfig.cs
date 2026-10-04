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

        /// <summary>添加代理表单的类型选项（字符串直绑 Proxy.proxyType，避免 ComboBoxItem 对象误入数据）</summary>
        [JsonIgnore]
        public List<string> ProxyTypeNameItems { get; } = new() { "Socks5", "HTTP" };

        /// <summary>添加代理表单的草稿对象：纯界面状态不入盘（旧配置持久化的空proxyType会导致类型下拉显示空白）</summary>
        [JsonIgnore]
        [ObservableProperty] public partial Proxy? AddProxy { get; set; } = new Proxy();

        /// <summary>
        /// 当前正在使用的代理显示文本
        /// </summary>
        [ObservableProperty] public partial string CurrentProxyText { get; set; } = "未使用代理";

        /// <summary>代理验证时访问的测试地址（验证代理真实转发能力，而非仅TCP连通代理端口）</summary>
        [ObservableProperty] public partial string ProxyTestUrl { get; set; } = "http://www.baidu.com";

        public Random rd = new Random();

    }
}
