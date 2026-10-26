using CommunityToolkit.Mvvm.ComponentModel;
using SuperSQLInjectionV2.ViewModels;
using System.Net;
using System.Text.Json.Serialization;

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

        /// <summary>以下均为运行时健康状态，不持久化，也不让高频更新刷新UI。</summary>
        [JsonIgnore] public long SuccessCount;
        [JsonIgnore] public long FailureCount;
        [JsonIgnore] public int ConsecutiveFailures;
        [JsonIgnore] public DateTime CooldownUntil { get; set; } = DateTime.MinValue;

        [JsonIgnore]
        public double SelectionWeight
        {
            get
            {
                double health = 1d + Math.Min(10, SuccessCount) * 0.1d;
                health /= 1d + ConsecutiveFailures * 2d;
                if (UseTime > 0) health *= Math.Clamp(1000d / UseTime, 0.25d, 2d);
                return Math.Max(0.01d, health);
            }
        }

        public void MarkSuccess()
        {
            Interlocked.Increment(ref SuccessCount);
            Interlocked.Exchange(ref ConsecutiveFailures, 0);
            CooldownUntil = DateTime.MinValue;
        }

        public void MarkFailure()
        {
            Interlocked.Increment(ref FailureCount);
            int failures = Interlocked.Increment(ref ConsecutiveFailures);
            if (failures >= 2)
            {
                CooldownUntil = DateTime.UtcNow.AddSeconds(Math.Min(300, Math.Pow(2, Math.Min(8, failures))));
            }
        }
    }
}
