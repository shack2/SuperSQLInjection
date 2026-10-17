using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using SuperSQLInjectionV2.Payload;
using SuperSQLInjectionV2.ViewModels;
using SuperSQLInjectionV2.ViewModels.Tools;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text.Json.Serialization;

namespace SuperSQLInjectionV2.Models
{
    public partial class DataConfig : ViewModelBase
    {
        /// <summary>
        /// 启动初始化：未切换过数据库类型（如恢复配置为UnKnow）时，也保证取数模板与报错方式下拉就绪
        /// </summary>
        public DataConfig()
        {
            OnSelectedDBTypeChanged(SelectedDBType);
        }

        /// <summary>当前注入参数名（检测命中/恢复记录时写入，检测概览实时显示）</summary>
        [ObservableProperty] public partial string InjectParamName { get; set; } = "";

        /// <summary>数据库族宿主选项（主下拉用：仅族宿主库，衍生/变体库走Fork库下拉；判定取DbProfile.CompatDb注册表）</summary>
        [JsonIgnore]
        public List<DBType> DbFamilies { get; set; } =
        [
            DBType.UnKnow,
            DBType.MySQL,
            DBType.SQLServer,
            DBType.Oracle,
            DBType.PostgreSQL,
            DBType.Access,
            DBType.DB2,
            DBType.SQLite,
            DBType.Informix,
            DBType.H2,
            DBType.HSQLDB,
            DBType.ClickHouse
        ];

        /// <summary>当前库可用的报错方式（默认=模板ErrorData key，其余来自模板 ErrorData@方法名 变体行），随数据库类型切换刷新。运行时派生数据，不持久化（否则旧配置里的空列表会覆盖初始化结果）</summary>
        [JsonIgnore]
        public ObservableCollection<string> ErrorMethods { get; set; } = new();

        /// <summary>当前选中的报错方式，切换后实时替换报错取数触发函数</summary>
        [ObservableProperty] public partial string SelectedErrorMethod { get; set; } = BasePayload.DefaultErrorMethodName;

        /// <summary>报错方式人工覆盖标记：用户手工选择非默认方式时置真（取数停用检出vector原文复用，改用模板变体）；自动反推/切库复位不置真</summary>
        [JsonIgnore]
        public bool ErrorMethodManualOverride { get; private set; } = false;

        /// <summary>自动反推写入标记（检测命中/恢复记录/切库复位的程序性赋值不视为人手工覆盖）</summary>
        private bool _errorMethodAuto = false;

        /// <summary>检测命中或恢复注入记录时自动反推报错方式（程序性赋值，不触发人工覆盖标记）；
        /// 同时清除人工覆盖标记——切库/切fork的程序性复位亦走本方法，若保留旧的覆盖标记，
        /// 下拉已复位「默认」但vector原文复用仍被停用（IsVectorMode恒假），取数偏离检出payload</summary>
        public void AutoSelectErrorMethod(string method)
        {
            _errorMethodAuto = true;
            try
            {
                SelectedErrorMethod = method;
            }
            finally
            {
                _errorMethodAuto = false;
            }
            ErrorMethodManualOverride = false;
        }

        partial void OnSelectedErrorMethodChanged(string value)
        {
            if (!_errorMethodAuto)
            {
                ErrorMethodManualOverride = !string.IsNullOrEmpty(value)
                    && !value.Equals(BasePayload.DefaultErrorMethodName, StringComparison.OrdinalIgnoreCase);
                //人工切换为非默认方式：检出vector原文复用停用，明确告知取数触发函数已偏离检出payload
                if (ErrorMethodManualOverride && !string.IsNullOrWhiteSpace(VectorTemplate))
                {
                    SuperSQLInjectionV2.Tools.Log.Show("报错方式已手工切换为「" + value + "」，取数将使用模板变体而非检出payload原文（切回「默认」恢复原文复用）");
                }
            }
            //实时切换报错取数触发函数（无对应变体时恢复默认ErrorData）
            PayloadFactory.BasePayload?.SetErrorMethod(value);
            //报错方式回显容量不同（updatexml≈32/extractvalue≈64），切换后清空实测值强制重新探测
            MeasuredErrorChunkLen = 0;
        }

        /// <summary>注入类型选项（随数据库类型过滤：无报错通道的库隐藏"报错注入"，无DNS外带通道的库隐藏"DNS盲注"）</summary>
        [JsonIgnore]
        public ObservableCollection<InjectType> InjectTypes { get; } =
        [
            InjectType.UnKnow,
            InjectType.Blind,
            InjectType.Time,
            InjectType.Error,
            InjectType.Union,
            InjectType.Stacked,
            InjectType.Dns
        ];

        /// <summary>当前数据库是否有报错注入通道（控制报错配置组显隐，运行时派生不持久化）</summary>
        [JsonIgnore]
        [ObservableProperty] public partial bool ErrorChannelVisible { get; set; } = true;

        /// <summary>
        /// 按数据库能力刷新注入类型选项：无报错通道的库（SQLite/HSQLDB/DB2/DM/Access/Informix，
        /// 错误消息不回显求值结果）隐藏"报错注入"，避免误导手工选择
        /// </summary>
        public void RefreshInjectTypes(DBType db)
        {
            bool hasError = DbCapabilities.HasErrorChannel(db);
            ErrorChannelVisible = hasError;
            bool listed = InjectTypes.Contains(InjectType.Error);
            if (hasError && !listed)
            {
                InjectTypes.Insert(InjectTypes.IndexOf(InjectType.Union), InjectType.Error);
            }
            else if (!hasError && listed)
            {
                InjectTypes.Remove(InjectType.Error);
            }
            //无DNS外带通道的库（SQLite/H2/HSQLDB/DB2/Access/ClickHouse等）隐藏"DNS盲注"
            bool hasDns = DbCapabilities.HasDnsChannel(db);
            bool dnsListed = InjectTypes.Contains(InjectType.Dns);
            if (hasDns && !dnsListed)
            {
                InjectTypes.Add(InjectType.Dns);
            }
            else if (!hasDns && dnsListed)
            {
                InjectTypes.Remove(InjectType.Dns);
            }
        }

        [ObservableProperty] public partial DBType SelectedDBType { get; set; } = DBType.UnKnow;

        /// <summary>当前fork/衍生库名（识别或手工选择；空=族宿主本库）。取数=族模板+fork overlay差异文件（config/payload|vers/fork_*.txt）</summary>
        [ObservableProperty] public partial string SelectedForkName { get; set; } = "";

        [ObservableProperty] public partial InjectType SelectedInjectType { get; set; } = InjectType.UnKnow;
        [ObservableProperty] public partial int SumColumnCount { get; set; } = 4;
        [ObservableProperty] public partial int ShowColumnIndex { get; set; } = 2;

        /// <summary>Union非显示列填充字符（空=自动：注入记录检测值优先，其次按库模板UnionFillStr；人工可填 NULL/1/'a' 等）。
        /// 恢复Union注入记录时自动回填检测成功的填充值，人工修改后以人工值为准</summary>
        [ObservableProperty] public partial string UnionFill { get; set; } = "";

        /// <summary>取数实际生效的Union填充字符：人工/记录值（Trim后非空）优先，空串=交方言层回退模板UnionFillStr</summary>
        [JsonIgnore]
        public string EffectiveUnionFill => string.IsNullOrWhiteSpace(UnionFill) ? "" : UnionFill.Trim();


        public ObservableCollection<VersModel> VersItems { get; set; } = new ObservableCollection<VersModel>();

        /// <summary>Hash读取选项卡条目（取数模板中Hash/DBA/sysadmin类条目自动分流到此，与环境变量同级独立选项卡）</summary>
        public ObservableCollection<VersModel> HashItems { get; set; } = new ObservableCollection<VersModel>();

        /// <summary>权限角色选项卡条目（取数模板中权限/角色类条目自动分流到此，对标业界同类工具 --privileges/--roles）</summary>
        public ObservableCollection<VersModel> PrivItems { get; set; } = new ObservableCollection<VersModel>();


        public ObservableCollection<VersModel> SelectVers { get; set; } = new ObservableCollection<VersModel>();

        private static readonly object _dbTypeChangeLock = new object();

        /// <summary>fork化归一中（防止族宿主回写时清空刚设置的Fork名）</summary>
        private bool _forkNormalizing;

        /// <summary>fork切换后重建模板/方言/词表/报错方式（与切库同链路，fork overlay差异即时生效）</summary>
        partial void OnSelectedForkNameChanged(string value)
        {
            PayloadFactory.ForkName = value ?? "";
            lock (_dbTypeChangeLock)
            {
                PayloadFactory.Init(SelectedDBType);
            }
            RefreshInjectTypes(SelectedDBType);
            MeasuredErrorChunkLen = 0;
            ReloadVersAndErrorMethods();
        }

        partial void OnSelectedDBTypeChanged(DBType value)
        {
            //fork化归一：金仓/openGauss/达梦等forkMode库不再作为独立取数库型，
            //归一到族宿主库型+Fork名（取数=族模板+fork overlay差异文件）
            var prof = SuperSQLInjectionV2.Payload.DbProfile.Get(value);
            if (prof.ForkMode && prof.CompatDb != value && prof.CompatDb != DBType.UnKnow)
            {
                _forkNormalizing = true;
                SelectedForkName = prof.DbmsName;
                SelectedDBType = prof.CompatDb;
                _forkNormalizing = false;
                return;
            }
            //显式切到族宿主库时清空Fork名（归一化回写除外）；fork由识别/记录恢复重新写入
            if (!_forkNormalizing && !string.IsNullOrEmpty(SelectedForkName)
                && !SuperSQLInjectionV2.Payload.DbProfile.ForkDisplayNamesOf(value).Contains(SelectedForkName))
            {
                SelectedForkName = "";
            }
            PayloadFactory.ForkName = SelectedForkName ?? "";
            //Payload模板加载是纯文件读取，与UI线程无关，直接同步完成（保证后续取数模板就绪）
            lock (_dbTypeChangeLock)
            {
                PayloadFactory.Init(value);
            }
            //按库能力过滤注入类型选项（无报错通道的库隐藏"报错注入"）
            RefreshInjectTypes(value);
            //切换库后实测报错容量作废（容量随注入点+报错方式而变，恢复记录时会重新写入）
            MeasuredErrorChunkLen = 0;
            ReloadVersAndErrorMethods();
        }

        /// <summary>重载环境变量词表（fork overlay生效）+ 报错方式下拉（默认+ErrorData@变体，复位默认）</summary>
        private void ReloadVersAndErrorMethods()
        {
            void RefreshErrorMethods()
            {
                ErrorMethods.Clear();
                ErrorMethods.Add(BasePayload.DefaultErrorMethodName);
                if (PayloadFactory.BasePayload != null)
                {
                    foreach (string name in PayloadFactory.BasePayload.ErrorDataVariants.Keys)
                    {
                        ErrorMethods.Add(name);
                    }
                }
                //切库/切fork的程序性复位：清除人工覆盖标记（变体随库变化，人工选择不跨库保留）
                AutoSelectErrorMethod(BasePayload.DefaultErrorMethodName);
            }
            if (Avalonia.Application.Current == null || Dispatcher.UIThread.CheckAccess())
            {
                VersItems.Clear();
                HashItems.Clear();
                PrivItems.Clear();
                VersTools.ReadVersByDBType(SelectedDBType, VersItems, HashItems, PrivItems, SelectedForkName);
                RefreshErrorMethods();
            }
            else
            {
                //不用Invoke：后台线程同步等待UI线程会死锁/卡顿，改为Post异步派发
                string fork = SelectedForkName;
                Dispatcher.UIThread.Post( ()=>
                {
                    VersItems.Clear();
                    HashItems.Clear();
                    PrivItems.Clear();
                    VersTools.ReadVersByDBType(SelectedDBType, VersItems, HashItems, PrivItems, fork);
                    RefreshErrorMethods();
                });
            }
        }

        [ObservableProperty] public partial BoolInjectType SelectBoolInject { get; set; } = BoolInjectType.KeyWord;

        /// <summary>Bool盲注判断方式选项（代码内置清单，不随配置持久化；时间盲注已升级为独立注入类型，不在此列）</summary>
        [JsonIgnore]
        public List<BoolInjectType> BoolInjectTypes { get; set; } =
        [
            BoolInjectType.KeyWord,
            BoolInjectType.RegexWord,
            BoolInjectType.Code,
            BoolInjectType.BodyLength,
            BoolInjectType.MaxLength,
            BoolInjectType.MinLength,
            BoolInjectType.Similarity
        ];

        /// <summary>相似度判定比对基准（BoolInjectType=Similarity时有效）：检测期确定后随注入记录恢复；会话级，不持久化到全局配置</summary>
        [JsonIgnore] public string SimilarTemplate { get; set; } = "";
        /// <summary>相似度投影模式（""=清动态模板 / "skeleton"=结构骨架 / "text"=纯文本）</summary>
        [JsonIgnore] public string SimilarMode { get; set; } = "";
        /// <summary>相似度判定阈值：ratio≥该值判真</summary>
        [JsonIgnore] public double SimilarCutoff { get; set; } = 0.95;
        /// <summary>动态特征表（SimilarMode=""时取数oracle先清动态再比对；随注入记录恢复）</summary>
        [JsonIgnore] public List<SuperSQLInjectionV2.Tools.ChangeFeature>? SimilarFeatures { get; set; } = null;

        /// <summary>取数实际判定方式：注入类型为时间盲注/堆叠时强制按响应耗时判定（堆叠取数回退时间通道，CheckValue=延时秒数），否则用所选Bool盲注判断方式</summary>
        [JsonIgnore]
        public BoolInjectType EffectiveBoolType => SelectedInjectType is InjectType.Time or InjectType.Stacked ? BoolInjectType.Time : SelectBoolInject;

        /// <summary>当前是否时间盲注通道（时间盲注注入类型；兼容旧配置的 Bool盲注+时间判定 组合）</summary>
        [JsonIgnore]
        public bool IsTimeChannel => EffectiveBoolType == BoolInjectType.Time
            && (SelectedInjectType == InjectType.Time || SelectedInjectType == InjectType.Blind);
        [ObservableProperty] public partial bool Reverse { get; set; } = false;
        [ObservableProperty] public partial string CheckValue { get; set; } = "JVApp";

        /// <summary>
        /// 数据库编码，盲注获取多字节数据（hex/unicode方式）时按此编码解码
        /// </summary>
        [ObservableProperty] public partial string DbEncoding { get; set; } = "UTF-8";

        /// <summary>
        /// 中文识别（hex 能力）：开启后Union/报错通道取值表达式统一 HEX(CAST(x)) 包装，
        /// 回显为纯ASCII hex串，客户端按DbEncoding解码还原，中文等多字节数据不乱码；
        /// 盲注通道默认已走hex/unicode多字节安全方式，不受影响。手工开关，默认关
        /// </summary>
        [ObservableProperty] public partial bool HexDecode { get; set; } = false;

        /// <summary>
        /// 盲注读取方式：自动（按库选最快方案：MySQL系ord/PG·金仓·openGauss·SQLite·H2码点/SQLServer unicode/Access ascw/其余hex）、
        /// Ord打包值（强制MySQL ord路径）、Hex编码（强制hex，多字节安全兜底，ord语义异常目标用）
        /// </summary>
        [ObservableProperty] public partial string BlindReadMode { get; set; } = "自动";

        /// <summary>盲注读取方式可选项</summary>
        [JsonIgnore]
        public List<string> BlindReadModes { get; } = new List<string> { "自动", "Ord打包值", "Hex编码" };

        /// <summary>
        /// 检测级别（1-5，越高测试payload越多）
        /// </summary>
        [ObservableProperty] public partial int DetectLevel { get; set; } = 1;

        /// <summary>
        /// 检测风险（1-3，越高payload越激进）
        /// </summary>
        [ObservableProperty] public partial int DetectRisk { get; set; } = 1;

        /// <summary>智能模式（sqlmap --smart 同款，默认开）：启发式无任何迹象（非动态参数+无错误指纹）时跳过深度检测；
        /// 非动态+无指纹但 Level≥3 时保留时间盲注/堆叠检测（这两类不依赖页面回显，是静态页面注入的唯一通道）；
        /// 非动态+有指纹仍全技术检测。头注入/写入型低Level目标可关闭本开关全量重测</summary>
        [ObservableProperty] public partial bool SmartMode { get; set; } = true;

        /// <summary>穷举模式（G2）：某技术命中后继续测完其余技术，注入记录给出完整画像；默认关（命中即跳到下一技术省时）</summary>
        [ObservableProperty] public partial bool DetectExhaustive { get; set; } = false;

        /// <summary>WAF拦截停止：检测过程中被拦截（HTTP 401/403/406/429/501）累计5次即停止整个检测，避免持续触发防护/封禁；默认关</summary>
        [ObservableProperty] public partial bool DetectStopOnWaf { get; set; } = false;

        /// <summary>检出即停（sqlmap「keep testing the others」默认N同款）：某参数检出注入后停止其余参数的检测（省时）；默认开；
        /// 需要完整画像（所有参数×所有技术）时关闭本开关或配合穷举模式使用</summary>
        [ObservableProperty] public partial bool DetectStopOnHit { get; set; } = true;

        /// <summary>多参数并行检测：多参数目标按线程数并发执行单参数多技术检测（参数间上下文天然隔离）；默认关（串行逐个检测）</summary>
        [ObservableProperty] public partial bool DetectParamParallel { get; set; } = false;

        /// <summary>DNS外带探测（本工具扩展能力）：检测期触发数据库向DNSLog域名发起解析，平台侧回收确认；需配置DNSLog域名+API Token</summary>
        [ObservableProperty] public partial bool DetectDnsOob { get; set; } = false;

        [JsonIgnore]
        public List<int> DetectLevels { get; set; } = [1, 2, 3, 4, 5];
        [JsonIgnore]
        public List<int> DetectRisks { get; set; } = [1, 2, 3];

        /// <summary>
        /// DNSLog域名（dns-domain 能力，DNS外带取数用，如 abc.ceye.io / xxxx.dnslog.cn）
        /// </summary>
        [ObservableProperty] public partial string DnsLogDomain { get; set; } = "";

        /// <summary>
        /// DNSLog平台API Token（ceye.io的API Token；配置后DNS外带结果自动轮询回收，无需人工到平台拼接）
        /// </summary>
        [ObservableProperty] public partial string DnsLogApiToken { get; set; } = "";

        /// <summary>
        /// DNSLog记录查询API地址模板（{token}=API Token，{domain}=DNSLog域名；默认ceye.io格式，兼容自建ceye镜像）
        /// </summary>
        [ObservableProperty] public partial string DnsLogApiUrl { get; set; } = "http://api.ceye.io/v1/records?token={token}&type=dns&filter={domain}";

        /// <summary>
        /// 内置DNS接收服务（P2-8本机形态）：开启后主程序直接监听UDP端口接收DNS外带记录，
        /// 取数/检测回收优先走本机内存记录（不再依赖第三方DNSLog平台HTTP API）。
        /// 域名NS记录需指向本机；53端口需管理员/root，可用高位端口（如5353）本机测试
        /// </summary>
        [ObservableProperty] public partial bool DnsServerEnable { get; set; } = false;

        /// <summary>内置DNS接收服务监听端口（默认53；本机测试可用5353等高位端口）</summary>
        [ObservableProperty] public partial int DnsServerPort { get; set; } = 53;

        /// <summary>内置DNS接收服务运行状态文本（UI状态栏/设置页显示）</summary>
        [JsonIgnore]
        [ObservableProperty] public partial string DnsServerStatus { get; set; } = "未启用";

        /// <summary>
        /// Access表名字典外部txt路径（每行一个表名；留空=内置config/dict/access_tables.txt）
        /// </summary>
        [ObservableProperty] public partial string AccessTableDictPath { get; set; } = "";

        /// <summary>
        /// Access字段名字典外部txt路径（每行一个字段名；留空=内置config/dict/access_columns.txt）
        /// </summary>
        [ObservableProperty] public partial string AccessColumnDictPath { get; set; } = "";

        /// <summary>
        /// 全库字典猜解开（common-tables/common-columns 能力）：开启后任意库的获取表/字段都走
        /// exists布尔字典猜解，用于information_schema不可用的低权限点；Access始终默认字典猜解（无元数据可读）
        /// </summary>
        [ObservableProperty] public partial bool DictGuessAll { get; set; } = false;

        /// <summary>
        /// 常见值预测（predict-output 能力）：盲注读取库名/表名/列名/用户/密码哈希等常见值时，
        /// 先按common-outputs字典同长候选做整值等值探测，命中即1次请求整串收工（如information_schema从~90次压到几次）；
        /// 猜错只是多1次请求，不会取错数据。仅Blind/Time通道生效
        /// </summary>
        [ObservableProperty] public partial bool PredictOutput { get; set; } = true;

        /// <summary>
        /// n-gram 在线学习：开启后成功读取的值（≤64字符纯ASCII可打印）增量训练会话级 trigram/bigram 计数，
        /// 以3倍权重合并进字符预测分布（目标站点的命名习惯比通用字典更贴），并持久化增量到
        /// config/sessions/char_ngram_delta.json（不污染基座模型，删delta即恢复）；
        /// 只影响分组权重不影响正确性，仅在 PredictOutput 开启时生效。测试可用SQLI_NGRAM_LEARN=0关闭
        /// </summary>
        [ObservableProperty] public partial bool NgramOnlineLearn { get; set; } = true;

        /// <summary>
        /// 取数自动通道升级：盲注/时间通道取数前探测同参数的Union/Error通道（来自注入记录），
        /// 可用则本次读取自动走快通道（数量级提速）；探测每注入点会话只进行一次，失败自动回退盲注
        /// </summary>
        [ObservableProperty] public partial bool ChannelUpgrade { get; set; } = true;

        /// <summary>
        /// Union批量取数行数（Q3）：&gt;1且当前库模板配置了UnionDataRows时，用聚合函数把k行拼成单行一次回显（k行数据k次请求→1次）；
        /// 聚合容量截断/取空自动回退逐行。1=关闭批量（逐行）。建议值5-20，hex模式数据量翻倍适当调小
        /// </summary>
        [ObservableProperty] public partial int UnionBatchRows { get; set; } = 10;

        /// <summary>跨会话值缓存（结构类元数据取值持久化复用到config/sessions/value_cache.json，行数据不缓存防脏读）；测试可用SQLI_CACHE=0关闭</summary>
        [ObservableProperty] public partial bool ValueCache { get; set; } = true;

        /// <summary>
        /// 值缓存校验（默认开）：缓存命中后先发1次整值等值探测确认目标值未变化——目标库结构更新（加表/改名）时
        /// 自动剔除陈旧值并重读更新，避免读到过期数据；关闭则命中即返回（0请求，可能读到旧值）。测试可用SQLI_CACHE_VERIFY=0关闭
        /// </summary>
        [ObservableProperty] public partial bool ValueCacheVerify { get; set; } = true;

        /// <summary>where语义（1=原值追加/2=负值替换/3=参数整体替换），恢复注入记录时写入；运行时派生不持久化</summary>
        [JsonIgnore]
        public int Where { get; set; } = 1;

        /// <summary>where=3参数替换点的vector模板（取数复用检出用例的[INFERENCE]/[QUERY]槽位），恢复注入记录时写入；运行时派生不持久化</summary>
        [JsonIgnore]
        public string VectorTemplate { get; set; } = "";

        /// <summary>注入参数原始值（where=3替换点的vector渲染[ORIGVALUE]用），恢复注入记录时写入；运行时派生不持久化</summary>
        [JsonIgnore]
        public string OrigValue { get; set; } = "";

        /// <summary>是否为vector原文复用取数模式（取数payload直接进检出用例vector槽位，不走"and"胶水/报错触发模板）：
        /// where=3参数替换点全技术适用；报错技术where=1/2同样原文复用（检出payload的触发函数/包装结构与取数完全一致），
        /// 人工切换非默认报错方式（ErrorMethodManualOverride）时报错通道回退模板变体</summary>
        [JsonIgnore]
        public bool IsVectorMode => !string.IsNullOrWhiteSpace(VectorTemplate)
            && (Where == 3 || (SelectedInjectType == InjectType.Error && !ErrorMethodManualOverride));

        /// <summary>vector报错裸表达式模式：vector含[QUERY]数据槽时，槽位塞裸表达式——
        /// vector分隔符烘焙时已对齐回显标记组合（EchoMarkers.Start+Split/Split+End），
        /// 分隔符本身就是提取标记，不再叠ConcatData第二层标记（报错回显容量仅~31字符，双重标记会吃光容量）</summary>
        [JsonIgnore]
        public bool IsBareVectorQuery => IsVectorMode && VectorTemplate.Contains("[QUERY]", StringComparison.Ordinal);

        /// <summary>实测报错回显净容量（取数时探针二分测得，随注入记录恢复；>0时报错分片优先用此步长替代模板ErrorChunkLen）。运行时派生不持久化，注入记录侧持久化</summary>
        [JsonIgnore]
        public int MeasuredErrorChunkLen { get; set; } = 0;

        /// <summary>检测期真值页HTTP状态码（防脏数据校验，随注入记录恢复；0=未记录不做意外码校验）</summary>
        [JsonIgnore]
        public int TrueCode { get; set; } = 0;

        /// <summary>检测期假值页HTTP状态码（与TrueCode构成合法状态码集合），随注入记录恢复</summary>
        [JsonIgnore]
        public int FalseCode { get; set; } = 0;

        /// <summary>取数期间是否已见过意外状态码（布尔通道字符复核触发条件之一：见过意外码才逐字符NOT复核，健康时零额外请求）</summary>
        [JsonIgnore]
        public bool SawUnexpectedCode { get; set; } = false;

        /// <summary>防脏数据校验总开关（默认开；测试可通过环境变量SQLI_DIRTY_GUARD=0关闭）</summary>
        [JsonIgnore]
        public bool DirtyDataGuard { get; set; } = true;

        /// <summary>复位vector取数模式（手工指定上下文/手工标记时调用，防止残留记录状态污染新注入点）</summary>
        public void ResetVectorMode()
        {
            Where = 1;
            VectorTemplate = "";
            OrigValue = "";
        }

    }
}
