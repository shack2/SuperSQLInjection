using AvaloniaEdit.Document;
using CommunityToolkit.Mvvm.ComponentModel;
using SuperSQLInjectionV2.Tools.Http;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading;

namespace SuperSQLInjectionV2.Models
{
    public partial class AppConfig: ViewModelBase
    {

        [ObservableProperty]
        public partial bool IsRuning { get; set; } = false;

        /// <summary>
        /// 停止信号，停止按钮置为true，所有发包与循环逻辑检测到后立即中断
        /// </summary>
        [JsonIgnore]
        public bool StopSignal { get; set; } = false;

        /// <summary>
        /// 运行取消令牌：贯穿发包/socket读取/并行调度，停止时立即生效（秒级停止）
        /// </summary>
        [JsonIgnore]
        public CancellationTokenSource RunCts { get; private set; } = new CancellationTokenSource();

        /// <summary>
        /// 开始新任务前重置停止状态（替换旧的 StopSignal=false 写法）
        /// </summary>
        public void ResetStop()
        {
            StopSignal = false;
            if (RunCts.IsCancellationRequested)
            {
                RunCts.Dispose();
                RunCts = new CancellationTokenSource();
            }
        }

        /// <summary>
        /// 发出停止信号并取消所有在飞操作
        /// </summary>
        public void SignalStop()
        {
            StopSignal = true;
            try { RunCts.Cancel(); } catch { }
        }

        /// <summary>
        /// 检查停止信号，一旦发出停止信号立即抛出中断异常
        /// </summary>
        public void CheckStop()
        {
            if (StopSignal || RunCts.IsCancellationRequested)
            {
                throw new OperationCanceledException("用户发出停止信号！");
            }
        }

        [ObservableProperty]
        public partial bool IsOpenHTTPLog { get; set; } = true;

        [ObservableProperty]
        public partial int RetryCount { get; set; } = 1;

        [ObservableProperty]
        public partial int TimeOut { get; set; } = 10;

        [ObservableProperty]
        public partial bool FollowRedirect { get; set; } = false;

        /// <summary>HTTP连接池每主机最大连接数（1-10，默认5；Keep-Alive复用省TCP+TLS握手，多线程盲注场景每线程一条连接）</summary>
        [ObservableProperty]
        public partial int PoolSize { get; set; } = 5;

        partial void OnPoolSizeChanged(int value)
        {
            Tools.Http.HttpConnectionPool.MaxPerKey = Math.Max(1, Math.Min(10, value));
        }

        /// <summary>时间盲注延时秒数调整后，若当前注入点CheckValue为数字（时间通道），同步刷新使取数立即生效</summary>
        partial void OnSleepInjectMaxTimeChanged(int value)
        {
            if (DataConfig != null && DataConfig.IsTimeChannel && Tools.MyTools.ConvertToInt(DataConfig.CheckValue) > 0)
            {
                DataConfig.CheckValue = value.ToString();
            }
        }


        [ObservableProperty]
        public partial int MaxColumnCount { get; set; } = 500;


        [JsonIgnore]
        [ObservableProperty]
        public partial RuningInfo RuningInfo { get; set; } = new RuningInfo();

        [ObservableProperty]
        public partial bool RedirectDoGet { get; set; } = true;

        [ObservableProperty]
        public partial int SleepInjectMaxTime { get; set; } = 5;

        public string TestPayload { get; set; } = "";

        public long RequestTmpCount  = 0;

        [ObservableProperty]
        public partial long RequestCount { get; set; } = 0;


        [ObservableProperty]
        public partial bool IsSSL { get; set; } = false;


        [JsonIgnore]
        [ObservableProperty]
        public partial string TxtLog { get; set; } = "";

        [ObservableProperty]
        public partial string Host { get; set; } = "127.0.0.1";

        [ObservableProperty]
        public partial int Port { get; set; } = 8080;

        [ObservableProperty]
        public partial bool AutoEncode { get; set; } = true;

        /// <summary>HTTP认证类型（auth-type 能力）：空=关闭，Basic/Digest/NTLM</summary>
        [ObservableProperty]
        public partial string AuthType { get; set; } = "";

        /// <summary>HTTP认证用户名（--auth-cred user:pass 的user部分）</summary>
        [ObservableProperty]
        public partial string AuthUser { get; set; } = "";

        /// <summary>HTTP认证密码</summary>
        [ObservableProperty]
        public partial string AuthPass { get; set; } = "";

        /// <summary>HTTP认证域（NTLM用，可空）</summary>
        [ObservableProperty]
        public partial string AuthDomain { get; set; } = "";

        /// <summary>HTTP认证类型下拉项（UI显示用，"关闭"映射为空串）</summary>
        [JsonIgnore]
        public List<string> AuthTypeItems { get; } = new List<string> { "关闭", "Basic", "Digest", "NTLM" };

        /// <summary>HTTP认证类型显示文本（双向映射：UI"关闭"↔存储""）</summary>
        [JsonIgnore]
        public string AuthTypeText
        {
            get => string.IsNullOrEmpty(AuthType) ? "关闭" : AuthType;
            set
            {
                AuthType = value == "关闭" ? "" : value;
                OnPropertyChanged(nameof(AuthTypeText));
            }
        }


        public EncodeConfig EncodeConfig { get; set; } = new EncodeConfig();
        public ProxyConfig ProxyConfig { get; set; } = new ProxyConfig();

        public ByPassConfig ByPassConfig { get; set; } = new ByPassConfig();

        public DataConfig DataConfig { get; set; } = new DataConfig();


        [JsonIgnore]
        public DataDumpViewModel DataDump { get; set; }

        [JsonIgnore]
        public FileCmdViewModel FileCmd { get; set; }


        [ObservableProperty] public partial int ThreadSize { get; set; } = 4;


        [ObservableProperty] public partial string PageEncoding { get; set; } = HttpConst.DefaultEncoding;
  

        [JsonIgnore]
        public List<int?> ThreadSizeItems { get; set; } = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20];

        [JsonIgnore]
        public List<int?> TimeItems { get; set; } = [5, 10, 15, 20, 30, 60];

        [JsonIgnore]
        public TextDocument TxtRequest { get; set; } = new TextDocument();

        public string RequestTxt { get; set; } = "";

        /// <summary>注入检测页请求报文文档（与取数页TxtRequest相互独立：检测页永不写入利用标记，取数页随注入记录恢复载入标记报文）</summary>
        [JsonIgnore]
        public TextDocument TxtDetectRequest { get; set; } = new TextDocument();

        /// <summary>注入检测页的HTTP请求包文本（TxtDetectRequest的同步镜像，检测链路以此为输入）</summary>
        public string DetectRequestTxt { get; set; } = "";

        [JsonIgnore]
        public List<string> TokenMethods { get; } = ["GET", "POST"];

        [JsonIgnore]
        public List<string> TokenFetchModes { get; } = ["请求报文", "URL请求"];

        /// <summary>动态值脚本列表（JS，请求抓取=输入抓取响应报文，自主生成=输入主请求报文，输出动态值）</summary>
        //规则与状态分离：动态值脚本独立持久化到 config/rules/token-scripts/（RuleStore），不进 lastconfig.json
        [JsonIgnore]
        public ObservableCollection<ScriptTamperModel> TokenScripts { get; set; } = new ObservableCollection<ScriptTamperModel>();

        /// <summary>解析当前生效的动态值脚本：按规则ScriptName匹配（类型不限）→指定类型第一个启用脚本→任意第一个启用脚本；kind=-1不按类型过滤</summary>
        public ScriptTamperModel? ResolveTokenScript(CompanionRequestConfig? rule = null, int kind = -1)
        {
            ScriptTamperModel? found = null;
            string? scriptName = rule?.ScriptName;
            if (!string.IsNullOrEmpty(scriptName))
            {
                foreach (ScriptTamperModel s in TokenScripts)
                {
                    if (s.Name == scriptName) { found = s; break; }
                }
            }
            if (found == null && kind >= 0)
            {
                foreach (ScriptTamperModel s in TokenScripts)
                {
                    if (s.Enable && s.Kind == kind) { found = s; break; }
                }
            }
            if (found == null)
            {
                foreach (ScriptTamperModel s in TokenScripts)
                {
                    if (s.Enable) { found = s; break; }
                }
            }
            return found;
        }

        //---- 绕过管道实例状态（原static字典按AppConfig键控常驻内存，收归实例随配置生命周期回收；均不参与序列化）----

        /// <summary>脚本Token的上次计算值（链式token脚本的输入）</summary>
        [JsonIgnore]
        public string LastToken { get; set; } = "";

        /// <summary>限速状态（BypassPipeline Stage4）：上次预约发包时刻，实例级隔离（多目标互不占槽）</summary>
        [JsonIgnore]
        internal DateTime ThrottleLastSend = DateTime.MinValue;
        /// <summary>限速信号量（BypassPipeline Stage4）：预约时间槽串行化，等待在锁外Task.Delay</summary>
        [JsonIgnore]
        internal SemaphoreSlim ThrottleSem { get; } = new SemaphoreSlim(1, 1);

        //---- 伴随请求规则集合（随机值抓取与二次注入统一为前置/后置伴随请求规则，TableView管理）----

        /// <summary>
        /// 动态规则列表：动态值（Kind=0，抓取/生成动态值回填&lt;DRule&gt;）与二次注入（Kind=1，响应替代主响应取数）混合存储。
        /// 动态值规则可同时启用多条（按标记名区分，无标记名取第一条）；二次注入规则同时只能启用一条（开启自动关闭其余）。
        /// 规则与状态分离：独立持久化到 config/rules/dynamic-rules.json（RuleStore），不进 lastconfig.json。
        /// </summary>
        [JsonIgnore]
        public ObservableCollection<CompanionRequestConfig> CompanionRules
        {
            get => _companionRules;
            set
            {
                _companionRules = value;
                HookCompanionRules();
            }
        }
        private ObservableCollection<CompanionRequestConfig> _companionRules = new ObservableCollection<CompanionRequestConfig>();

        /// <summary>挂载规则集合监听：新增规则自动挂载属性监听 + 二次注入单开强制（最新意图生效）。
        /// 集合整体替换（反序列化）时同步规则报文文档：RequestTxt 是纯字符串镜像，TxtRequest 需以它回填，否则编辑弹窗显示空报文</summary>
        private void HookCompanionRules()
        {
            foreach (CompanionRequestConfig r in _companionRules)
            {
                HookAfterRule(r);
                if (r.TxtRequest.Text != r.RequestTxt)
                {
                    r.TxtRequest.Text = r.RequestTxt;
                }
            }
            _companionRules.CollectionChanged += (_, e) =>
            {
                if (e.NewItems != null)
                {
                    foreach (object item in e.NewItems)
                    {
                        if (item is CompanionRequestConfig r)
                        {
                            HookAfterRule(r);
                            //新增已启用的二次注入规则时，以新规则为准关闭其余
                            if (r.Kind == 1 && r.Enabled)
                            {
                                EnforceSingleAfterRule(r);
                            }
                        }
                    }
                }
            };
            EnforceSingleAfterRule(null);
        }

        /// <summary>规则启用状态监听：二次注入规则被启用时自动关闭其余二次注入规则（动态值规则不限数量）</summary>
        private void HookAfterRule(CompanionRequestConfig rule)
        {
            rule.PropertyChanged += (_, e) =>
            {
                if (e.PropertyName == nameof(CompanionRequestConfig.Enabled) && rule.Kind == 1 && rule.Enabled)
                {
                    EnforceSingleAfterRule(rule);
                }
            };
        }

        /// <summary>二次注入单开强制：winner非空时保留winner，否则保留第一条已启用规则，其余二次注入规则全部关闭</summary>
        private void EnforceSingleAfterRule(CompanionRequestConfig? winner)
        {
            CompanionRequestConfig? keep = winner ?? _companionRules.FirstOrDefault(r => r.Kind == 1 && r.Enabled);
            foreach (CompanionRequestConfig r in _companionRules)
            {
                if (r.Kind == 1 && r.Enabled && !ReferenceEquals(r, keep))
                {
                    r.Enabled = false;
                }
            }
        }

        /// <summary>当前生效的前置规则（第一条启用的前置规则；未配置时返回null）</summary>
        [JsonIgnore]
        public CompanionRequestConfig? ActiveCompanionBefore =>
            CompanionRules.FirstOrDefault(r => r.Kind == 0 && r.Enabled);

        /// <summary>当前生效的后置规则（第一条启用且已配置的后置规则；未配置时返回null）</summary>
        [JsonIgnore]
        public CompanionRequestConfig? ActiveCompanionAfter =>
            CompanionRules.FirstOrDefault(r => r.Kind == 1 && r.Enabled && r.IsConfigured);

        /// <summary>按标记名查找已启用的伴随规则（&lt;DRule&gt;标记名&lt;DRule&gt;/&lt;Sencond:标记名&gt;关联；大小写不敏感）</summary>
        public CompanionRequestConfig? FindCompanionRule(int kind, string? tagName)
        {
            if (string.IsNullOrEmpty(tagName))
            {
                return null;
            }
            return CompanionRules.FirstOrDefault(r => r.Kind == kind && r.Enabled
                && string.Equals(r.TagName, tagName, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// 重发数据包关键词列表，当HTTP响应内容中包含任一关键词时重新发送数据包
        /// </summary>
        public ObservableCollection<string> RetryKeyItems { get; set; } = new ObservableCollection<string>();

        /// <summary>
        /// 判断响应内容是否包含重发关键词
        /// </summary>
        public bool FindRetryKey(string? body)
        {
            if (string.IsNullOrEmpty(body))
            {
                return false;
            }
            foreach (string key in RetryKeyItems)
            {
                if (!string.IsNullOrEmpty(key) && body.Contains(key, StringComparison.Ordinal))
                {
                    return true;
                }
            }
            return false;
        }

        public AppConfig (){

            DataDump = new DataDumpViewModel { AppConfig = this };
            FileCmd = new FileCmdViewModel(this);
            TxtRequest.TextChanged += TxtRequest_TextChanged;
            TxtDetectRequest.TextChanged += TxtDetectRequest_TextChanged;
            HookCompanionRules();
            //数据库类型变化时，刷新文件操作方式列表
            DataConfig.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(DataConfig.SelectedDBType))
                {
                    try
                    {
                        Avalonia.Threading.Dispatcher.UIThread.Post( ()=> FileCmd?.RefreshFileMethods());
                    }
                    catch
                    {
                        // 无UI线程（控制台/测试）环境下直接刷新
                        FileCmd?.RefreshFileMethods();
                    }
                    //注释符联动：请求报文中注入标记后的注释符跟随数据库类型重写（MySQL=#，Access/未知=无，其他=-- ）
                    //TxtRequest是AvaloniaEdit文档，读写都必须在其创建线程；属性变化可能来自工作线程，整体调度
                    try
                    {
                        void SyncComment()
                        {
                            string oldTxt = TxtRequest.Text;
                            string newTxt = Tools.InjectTools.UpdateMarkedComment(oldTxt, DataConfig.SelectedDBType);
                            if (!newTxt.Equals(oldTxt, StringComparison.Ordinal))
                            {
                                TxtRequest.Text = newTxt;
                            }
                        }
                        if (Avalonia.Application.Current == null || Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
                        {
                            SyncComment();
                        }
                        else
                        {
                            Avalonia.Threading.Dispatcher.UIThread.Post(SyncComment);
                        }
                    }
                    catch
                    {
                        //注释符联动失败不影响主流程
                    }
                }
            };
        }

        private void TxtRequest_TextChanged(object? sender, EventArgs e)
        {
            RequestTxt = ((sender as TextDocument)?.Text ?? "");
        }

        private void TxtDetectRequest_TextChanged(object? sender, EventArgs e)
        {
            DetectRequestTxt = ((sender as TextDocument)?.Text ?? "");
        }

        [JsonIgnore]
        public RequestLogModel RequestLog { get; set; } = new RequestLogModel();

        [JsonIgnore]
        public List<string?> PageEncodings { get; set; } =
        [
            "UTF-8", "GB2312", "ISO-8859-1", "GBK", "EUC-KR"
        ];

       
        [ObservableProperty] public partial string Url { get; set; } = "http://127.0.0.1:8080/JVApp/mysql.jsp?id=1";

        /// <summary>注入检测页URL（与取数页Url完全隔离：注入记录恢复只回写取数页目标Url，检测页URL/报文不受联动覆盖）</summary>
        [ObservableProperty] public partial string DetectUrl { get; set; } = "http://127.0.0.1:8080/JVApp/mysql.jsp?id=1";

        partial void OnDetectUrlChanged(string value)
        {
            //与OnUrlChanged同款：同步SSL/主机/端口兜底配置（检测发包以报文Host头为准，此处保持展示一致）
            if (string.IsNullOrEmpty(value))
            {
                return;
            }
            IsSSL = value.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
            try
            {
                Uri uri = new Uri(value);
                Host = uri.Host;
                Port = uri.Port;
            }
            catch
            {

            }
        }

        /// <summary>注入检测页请求方式（GET/POST，URL栏前下拉；与检测报文双向联动：切换方式重新生成报文，改报文回同步）</summary>
        [ObservableProperty] public partial string DetectMethod { get; set; } = "GET";

        /// <summary>请求方式下拉选项（ComboBox的SelectedValue无法从ComboBoxItem取值，故用字符串ItemsSource+SelectedItem绑定）</summary>
        [JsonIgnore]
        public List<string> DetectMethods { get; } = new List<string> { "GET", "POST" };

        /// <summary>历史脏数据兜底：旧版绑定缺陷可能把null/空串/非法值写进配置，统一回落GET</summary>
        partial void OnDetectMethodChanged(string value)
        {
            if (value != "GET" && value != "POST")
            {
                DetectMethod = "GET";
            }
        }

        partial void OnUrlChanged(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return;
            }
            bool isSsl = Url.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
            if (isSsl)
            {
                IsSSL = true;
            }
            else
            {
                IsSSL = false;
            }
            try
            {
                Uri uri = new Uri(value);
                Host = uri.Host;
                Port = uri.Port;
            }
            catch
            {

            }
        }
        //---- 软件更新（SoftUpdate 自托管更新服务，接口见 docs/API.md）----
        //连接配置（服务地址/应用标识/渠道/Key）统一收敛到 config/update.ini（Tools/Update/UpdateSettings.cs），UI 不提供修改
        /// <summary>启动时自动检测新版本</summary>
        [ObservableProperty] public partial bool UpdateCheckEnable { get; set; } = true;

        /// <summary>忽略提示的版本号（点对某版本"不再提示"后跳过该版本的启动弹窗，仍可在更新页手动检测）</summary>
        [ObservableProperty] public partial string UpdateSkipVersion { get; set; } = "";


    }
}
