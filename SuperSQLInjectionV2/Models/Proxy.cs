using CommunityToolkit.Mvvm.ComponentModel;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;
using System.Text.Json.Serialization;
using VYaml.Annotations;

namespace SuperSQLInjectionV2.Models
{
    public partial class Proxy: ViewModelBase
    {
       
        private IPAddress _ip { get; set; } = IPAddress.Parse("0.0.0.0");

        [JsonIgnore]
        public IPAddress IP
        {
            get
            {

                return _ip;
            }
            set
            {
                _ip= value;
                Host= _ip.ToString();
            }
        }


        [ObservableProperty]
        public partial string Host { get; set; } = "";

        [ObservableProperty]
        public partial int Port { get; set; } = 80;
        [ObservableProperty]
        public partial string proxyType { get; set; } = "Socks5";//Socks5 或 HTTP
        public string username { get; set; } = "";//代理账户
        public string password { get; set; } = "";//代理密码

        [ObservableProperty]
        public partial bool IsOk { get; set; } = false;//是否验证通过

        [ObservableProperty]
        public partial int UseTime { get; set; } = 0;//连接使用时间（毫秒）

        [ObservableProperty]
        public partial string? CheckTime { get; set; } = "";//验证时间

        [ObservableProperty]
        public partial bool IsEnabled { get; set; } = false;//是否启用


    }
}
