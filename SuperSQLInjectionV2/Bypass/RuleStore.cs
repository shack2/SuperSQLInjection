using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Source;
using SuperSQLInjectionV2.Tools;

namespace SuperSQLInjectionV2.Bypass
{
    /// <summary>
    /// 规则库持久化（规则与状态分离）：GUI 界面状态仍走 config/lastconfig.json，
    /// 五类规则独立落 config/rules/ 便于人工编辑与 CLI 共用——
    ///   scripts/         统一脚本库（所有 JS 一脚本一文件，前置 //@ 元数据头：
    ///                    name/usage/enable/description；usage=payload|request|extract|generate 见 ScriptUsage）。
    ///                    sqlmap对齐tamper、独有能力（urlencode/hex/altcase/unicode/includecomment）、
    ///                    示例脚本与用户脚本同库同格式，编码链变换脚本与动态值脚本按用途分流加载，无内置/自定义区分。
    ///   tampers/         编码工具链引用：chain.json（scripts/ 文件名+启停+Order，数组序=全局执行顺序）
    ///   token-scripts/   动态值脚本引用：chain.json（scripts/ 文件名+启停，顺序=回退选择优先级）
    ///   dynamic-rules.json   动态规则（DRule/二次注入）
    ///   replace-rules.json   字符替换规则
    ///   proxies.json         代理池
    /// 旧布局迁移（一次性）：tampers/*.js（按 //@scope）与 token-scripts/*.js（按 //@kind）移入 scripts/ 并重写统一元数据头；
    /// builtin_*.js 前缀脚本改名去前缀（剥 //@builtin 头）；tampers/builtin.json+custom.json 双链与旧版 chain.json
    /// （含 Builtin 字段）归并为新 chain.json（Builtin项按 key.js 引用脚本文件）；迁移后旧文件删除。
    /// 内存模型说明：EncodeToolModel（编码链行）与 ScriptTamperModel（动态值脚本）刻意不合并——
    /// 二者是同一磁盘脚本实体的两个视图，按 usage 只加载进其中一个集合，内存无双份，引擎/BypassPlan/CLI 零改动。
    /// 加载容错：目录/文件缺失按空规则处理，单项损坏跳过并记日志，不影响其余项与主程序启动。
    /// </summary>
    public static class RuleStore
    {
        //======== 旧版内置链条目（仅迁移读取 builtin.json 用，新格式不再写出）========
        public sealed class BuiltinEntry
        {
            public string? Key { get; set; }              // 内置工具 Key → 迁移为 scripts/<key>.js 引用
            public bool Enable { get; set; }
            public int Scope { get; set; } = 0;
            public int Order { get; set; }                // 全局执行顺序（与 custom.json 按序归并）
        }

        //======== 编码链条目（tampers/chain.json，数组序=执行顺序，Order 供人工编辑参考）========
        public sealed class ScriptEntry
        {
            public string? Script { get; set; }           // scripts/ 下的脚本文件名（.js）
            public bool Enable { get; set; } = true;      // 启停覆盖脚本文件头（高频操作集中在链文件）
            public int Order { get; set; }                // 全局执行顺序
        }

        //======== 链文件条目（token-scripts 用；tampers 旧版 chain.json 迁移读取兼容 Builtin 字段）========
        public sealed class ChainEntry
        {
            public string? Builtin { get; set; }          // 旧版内置工具 Key（迁移为 <key>.js 引用）
            public string? Script { get; set; }           // 脚本文件名（.js）
            public bool Enable { get; set; } = true;
            public int Scope { get; set; } = 0;           // 旧版字段，新格式忽略（以脚本文件头 usage 为准）
        }

        //======== 动态规则 DTO（干净的人工可编辑 schema，剔除界面态字段）========
        public sealed class DynamicRuleDto
        {
            public int Kind { get; set; }                 // 0=动态值(前置) 1=二次注入(后置)
            public string Name { get; set; } = "新规则";
            public string TagName { get; set; } = "";
            public bool Enabled { get; set; } = false;
            public int SourceMode { get; set; } = 0;      // 0=请求报文 1=URL请求 2=脚本生成
            public string Url { get; set; } = "";
            public string Method { get; set; } = "GET";
            public string RequestTxt { get; set; } = "";
            public bool UseScript { get; set; } = false;  // 动态值取值方式：false=字符串截取 true=脚本提取
            public string SubStart { get; set; } = "";
            public string SubEnd { get; set; } = "";
            public string ScriptName { get; set; } = "";
        }

        //======== 代理 DTO（Proxy.proxyType 是公共字段默认不参与序列化，用 DTO 固定 schema）========
        public sealed class ProxyDto
        {
            public string Host { get; set; } = "";
            public int Port { get; set; } = 80;
            public string Type { get; set; } = "HTTP/HTTPS"; // socks5 或 HTTP/HTTPS
            public string Username { get; set; } = "";
            public string Password { get; set; } = "";
        }

        public static string DefaultDir =>
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config", "rules");

        //================================================ 加载 ================================================

        /// <summary>统一脚本库目录（config/rules/scripts/）</summary>
        public static string ScriptsDir(string rulesDir) => Path.Combine(rulesDir, "scripts");

        /// <summary>当前活动规则目录（LoadAll/SaveAll 入口设置；LoadToolByKey 按此目录解析磁盘脚本）</summary>
        private static string _activeRulesDir = DefaultDir;

        /// <summary>旧版内置脚本文件名前缀（仅迁移识别用，新格式不再写出）</summary>
        private const string LegacyBuiltinPrefix = "builtin_";

        /// <summary>
        /// tamper脚本落盘（config/rules/scripts/&lt;key&gt;.js）：注册表（BuiltinTampers，sqlmap对齐）中
        /// 缺失的脚本按内嵌JS代码补写（用户改动不覆盖）。脚本即磁盘文件，可见可改可删；
        /// 删除后重启按注册表重新生成官方版本。
        /// </summary>
        public static void EnsureScripts(string? rulesDir = null)
        {
            try
            {
                string dir = ScriptsDir(rulesDir ?? DefaultDir);
                Directory.CreateDirectory(dir);
                foreach (EncodeTool t in EncodeToolRegistry.All.Values)
                {
                    string file = Path.Combine(dir, t.Key + ".js");
                    if (File.Exists(file))
                    {
                        continue;
                    }
                    WriteScript(file, new Dictionary<string, string>
                    {
                        ["name"] = t.Name,
                        ["usage"] = ScriptUsages.ToMeta(t.Scope == ScriptScope.Request ? ScriptUsage.RequestTransform : ScriptUsage.PayloadTransform),
                        ["enable"] = "false",
                        ["description"] = t.Description
                    }, t.JsCode);
                }
            }
            catch (Exception e)
            {
                Log.SysLog("规则库：tamper脚本落盘失败 -- " + e.Message);
            }
        }

        /// <summary>
        /// 按Key取编码链脚本（注入记录恢复/CLI --tamper/检测期自动适配用）：
        /// 磁盘 scripts/&lt;key&gt;.js 优先（用户改动生效），缺失回退注册表内嵌JS实现；均未找到返回null。
        /// </summary>
        public static EncodeToolModel? LoadToolByKey(string key, string? rulesDir = null)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                return null;
            }
            string file = Path.Combine(ScriptsDir(rulesDir ?? _activeRulesDir), key + ".js");
            if (File.Exists(file))
            {
                LibScript? s = LoadLibScript(file, "编码脚本");
                if (s != null)
                {
                    return ToEncodeTool(s, key);
                }
            }
            if (EncodeToolRegistry.TryGet(key, out EncodeTool tool))
            {
                return new EncodeToolModel
                {
                    Name = tool.DisplayName,
                    Key = tool.Key,
                    Code = tool.JsCode,
                    Scope = tool.Scope,
                    Description = tool.Description,
                    Enable = false
                };
            }
            return null;
        }

        /// <summary>从 rules 目录加载全部规则到 config（目录缺失=空规则，逐项容错）</summary>
        public static void LoadAll(AppConfig config, string? rulesDir = null)
        {
            string dir = rulesDir ?? DefaultDir;
            _activeRulesDir = dir;
            try
            {
                //旧布局脚本迁移（tampers/*.js、token-scripts/*.js → scripts/），返回 旧文件名→新文件名 映射供链引用改名
                Dictionary<string, string> renames = MigrateScripts(dir);
                //旧版 builtin_*.js 前缀脚本改名去前缀（剥 //@builtin 头），链引用同步改名
                foreach (var kv in MigrateBuiltinPrefixScripts(dir))
                {
                    renames[kv.Key] = kv.Value;
                }
                LoadTampers(config, dir, renames);
                LoadTokenScripts(config, dir, renames);
                LoadDynamicRules(config, Path.Combine(dir, "dynamic-rules.json"));
                LoadReplaceRules(config, Path.Combine(dir, "replace-rules.json"));
                LoadProxies(config, Path.Combine(dir, "proxies.json"));
            }
            catch (Exception e)
            {
                Log.SysLog("规则库加载异常（已加载部分有效）：" + e.Message);
            }
        }

        /// <summary>
        /// 旧版 builtin_*.js 脚本迁移：改名去前缀（目标已存在则删除前缀副本，以无前缀版为准），
        /// 重写统一元数据头（剥 //@builtin，缺 enable 头补 false 保持默认停用语义）。
        /// 返回 旧文件名→新文件名 映射（无迁移=空表）。
        /// </summary>
        private static Dictionary<string, string> MigrateBuiltinPrefixScripts(string rulesDir)
        {
            var renames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string scriptsDir = ScriptsDir(rulesDir);
            if (!Directory.Exists(scriptsDir))
            {
                return renames;
            }
            foreach (string f in Directory.GetFiles(scriptsDir, LegacyBuiltinPrefix + "*.js").OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    string oldName = Path.GetFileName(f);
                    string stem = Path.GetFileNameWithoutExtension(f)[LegacyBuiltinPrefix.Length..];
                    //历史遗留键名可能带前导下划线（如 builtin__unicode.js），归一化
                    if (stem.StartsWith('_') && stem.Length > 1)
                    {
                        stem = stem.TrimStart('_');
                    }
                    string target = stem + ".js";
                    string targetPath = Path.Combine(scriptsDir, target);
                    if (File.Exists(targetPath))
                    {
                        File.Delete(f); //无前缀版已存在，以前者为准
                    }
                    else
                    {
                        var (meta, code) = ParseScript(f);
                        meta.Remove("builtin");
                        if (!meta.ContainsKey("enable"))
                        {
                            meta["enable"] = "false";
                        }
                        WriteScript(targetPath, meta, code);
                        File.Delete(f);
                    }
                    renames[oldName] = target;
                    Log.SysLog("规则库：内置前缀脚本迁移 " + oldName + " → scripts/" + target);
                }
                catch (Exception e)
                {
                    Log.SysLog("规则库：内置前缀脚本迁移失败（留原处下次再试）" + f + " -- " + e.Message);
                }
            }
            return renames;
        }

        /// <summary>
        /// 旧布局一次性迁移：tampers/*.js（usage 按 //@scope 推断）与 token-scripts/*.js（usage 按 //@kind 推断）
        /// 移入统一脚本库 scripts/ 并重写统一元数据头（name/usage/enable），返回旧文件名→新文件名映射（无迁移=空表）。
        /// 文件名冲突自动加 _2 后缀；迁移失败的文件留原处下次再试。
        /// </summary>
        private static Dictionary<string, string> MigrateScripts(string rulesDir)
        {
            var renames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string scriptsDir = ScriptsDir(rulesDir);
            //(旧目录, usage推断器)
            (string dir, Func<Dictionary<string, string>, ScriptUsage> usageOf)[] legacy =
            {
                (Path.Combine(rulesDir, "tampers"), m => ScriptUsages.FromLegacyScope(m.TryGetValue("scope", out string? sc) ? sc : null)),
                (Path.Combine(rulesDir, "token-scripts"), m => ScriptUsages.FromLegacyKind(m.TryGetValue("kind", out string? k) && int.TryParse(k, out int k2) ? k2 : 0))
            };
            foreach ((string legacyDir, Func<Dictionary<string, string>, ScriptUsage> usageOf) in legacy)
            {
                if (!Directory.Exists(legacyDir))
                {
                    continue;
                }
                foreach (string f in Directory.GetFiles(legacyDir, "*.js").OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
                {
                    try
                    {
                        var (meta, code) = ParseScript(f);
                        ScriptUsage usage = usageOf(meta);
                        string name = meta.TryGetValue("name", out string? n) && !string.IsNullOrWhiteSpace(n)
                            ? n : Path.GetFileNameWithoutExtension(f);
                        bool enable = !meta.TryGetValue("enable", out string? en) || !"false".Equals(en, StringComparison.OrdinalIgnoreCase);
                        Directory.CreateDirectory(scriptsDir);
                        //目标文件名：优先保留原名，冲突加后缀（用于集合预占已迁移/已存在的文件名）
                        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        if (Directory.Exists(scriptsDir))
                        {
                            foreach (string ex in Directory.GetFiles(scriptsDir, "*.js"))
                            {
                                used.Add(Path.GetFileName(ex));
                            }
                        }
                        string baseName = Path.GetFileName(f);
                        string target = baseName;
                        if (used.Contains(target))
                        {
                            string stem = Path.GetFileNameWithoutExtension(baseName);
                            for (int i = 2; ; i++)
                            {
                                target = stem + "_" + i + ".js";
                                if (!used.Contains(target))
                                {
                                    break;
                                }
                            }
                        }
                        WriteScript(Path.Combine(scriptsDir, target), new Dictionary<string, string>
                        {
                            ["name"] = name,
                            ["usage"] = ScriptUsages.ToMeta(usage),
                            ["enable"] = enable ? "true" : "false"
                        }, code);
                        File.Delete(f);
                        if (!string.Equals(baseName, target, StringComparison.OrdinalIgnoreCase))
                        {
                            renames[baseName] = target;
                        }
                        Log.SysLog("规则库：脚本迁移 " + Path.GetFileName(legacyDir) + "/" + baseName + " → scripts/" + target);
                    }
                    catch (Exception e)
                    {
                        Log.SysLog("规则库：脚本迁移失败（留原处下次再试）" + f + " -- " + e.Message);
                    }
                }
            }
            return renames;
        }

        /// <summary>链文件引用改名：迁移导致脚本文件名变化时同步（仅替换文件名部分，引用本来就是裸文件名）</summary>
        private static string ResolveScriptRef(string scriptFile, Dictionary<string, string> renames)
        {
            return renames.TryGetValue(scriptFile, out string? renamed) ? renamed : scriptFile;
        }

        private static List<ChainEntry> ReadChain(string file)
        {
            if (!File.Exists(file))
            {
                return new List<ChainEntry>();
            }
            try
            {
                return JsonSerializer.Deserialize(File.ReadAllText(file), JsonCtx.IndentedInfo<List<ChainEntry>>()) ?? new List<ChainEntry>();
            }
            catch (Exception e)
            {
                Log.SysLog("链文件解析失败（按空链处理）：" + file + " -- " + e.Message);
                return new List<ChainEntry>();
            }
        }

        /// <summary>解析 .js 脚本：前置 //@key: value 元数据头 + 正文代码</summary>
        private static (Dictionary<string, string> meta, string code) ParseScript(string file)
        {
            var meta = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var sb = new StringBuilder();
            foreach (string raw in File.ReadAllLines(file))
            {
                string line = raw.TrimEnd();
                if (line.StartsWith("//@", StringComparison.Ordinal))
                {
                    int colon = line.IndexOf(':', 3);
                    if (colon > 3)
                    {
                        meta[line[3..colon].Trim()] = line[(colon + 1)..].Trim();
                        continue;
                    }
                }
                sb.AppendLine(raw);
            }
            return (meta, sb.ToString().Trim());
        }

        /// <summary>通用列表文件读取：缺失=空表，损坏记日志按空处理</summary>
        private static List<T> ReadList<T>(string file, System.Text.Json.Serialization.Metadata.JsonTypeInfo<List<T>> typeInfo, string tag)
        {
            if (!File.Exists(file))
            {
                return new List<T>();
            }
            try
            {
                return JsonSerializer.Deserialize(File.ReadAllText(file), typeInfo) ?? new List<T>();
            }
            catch (Exception e)
            {
                Log.SysLog("规则库：" + tag + "解析失败（按空处理）：" + file + " -- " + e.Message);
                return new List<T>();
            }
        }

        /// <summary>统一脚本库脚本读取：前置 //@ 元数据头（name/usage/enable/description）+ 正文代码</summary>
        private sealed class LibScript
        {
            public string Name = "";
            public string Code = "";
            public bool Enable = true;
            public ScriptUsage Usage = ScriptUsage.PayloadTransform;
            public string Description = "";
        }

        private static LibScript? LoadLibScript(string file, string tag)
        {
            if (!File.Exists(file))
            {
                Log.SysLog("规则库：" + tag + "缺失 " + file + "（已跳过）");
                return null;
            }
            try
            {
                var (meta, code) = ParseScript(file);
                return new LibScript
                {
                    Name = meta.TryGetValue("name", out string? n) && !string.IsNullOrWhiteSpace(n)
                        ? n : Path.GetFileNameWithoutExtension(file),
                    Code = code,
                    Enable = !meta.TryGetValue("enable", out string? en) || !"false".Equals(en, StringComparison.OrdinalIgnoreCase),
                    //无 usage 元数据（手工丢入的裸脚本）按 Payload变换 兜底，编码处理页可见可改
                    Usage = meta.TryGetValue("usage", out string? u) ? ScriptUsages.FromMeta(u) : ScriptUsage.PayloadTransform,
                    Description = meta.TryGetValue("description", out string? ds) ? ds : ""
                };
            }
            catch (Exception e)
            {
                Log.SysLog("规则库：" + tag + "解析失败 " + file + " -- " + e.Message);
                return null;
            }
        }

        /// <summary>LibScript → 编码链行（仅变换类用法；Key=脚本文件名主干，注册表收录的同步填充中文显示名缓存）</summary>
        private static EncodeToolModel ToEncodeTool(LibScript s, string fileStem)
        {
            EncodeToolRegistry.RegisterCnName(fileStem, s.Name);
            return new EncodeToolModel
            {
                Name = s.Name,
                Key = fileStem,
                Code = s.Code,
                Enable = s.Enable,
                Scope = ScriptUsages.ToScope(s.Usage),
                Description = s.Description
            };
        }

        private static void LoadTampers(AppConfig config, string rulesDir, Dictionary<string, string> renames)
        {
            string dir = Path.Combine(rulesDir, "tampers");
            //tamper脚本落盘（缺失即补，用户改动不覆盖）
            EnsureScripts(rulesDir);
            string scriptsDir = ScriptsDir(rulesDir);
            //(order, model, scriptFile)：scriptFile=脚本在 scripts/ 下的磁盘文件名，合并落盘时保持脚本引用不丢
            var entries = new List<(int order, EncodeToolModel m, string scriptFile)>();
            var chained = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string chainFile = Path.Combine(dir, "chain.json");
            string builtinFile = Path.Combine(dir, "builtin.json");
            string customFile = Path.Combine(dir, "custom.json");
            bool migrated = false;
            //(scriptFile, enable)：数组序=执行顺序
            var raw = new List<(string scriptFile, bool enable)>();
            if (File.Exists(builtinFile) || File.Exists(customFile))
            {
                //旧版双链文件迁移（builtin.json 内置项 + custom.json 脚本项，Order 全局混排）：归并为统一 chain.json
                migrated = true;
                var merged = new List<(int order, string scriptFile, bool enable)>();
                foreach (BuiltinEntry e in ReadList(builtinFile, JsonCtx.IndentedInfo<List<BuiltinEntry>>(), "内置编码链文件"))
                {
                    if (!string.IsNullOrWhiteSpace(e.Key))
                    {
                        merged.Add((e.Order, e.Key + ".js", e.Enable));
                    }
                }
                foreach (ScriptEntry e in ReadList(customFile, JsonCtx.IndentedInfo<List<ScriptEntry>>(), "自定义编码链文件"))
                {
                    if (!string.IsNullOrWhiteSpace(e.Script))
                    {
                        merged.Add((e.Order, e.Script!, e.Enable));
                    }
                }
                foreach ((int order, string scriptFile, bool enable) in merged.OrderBy(x => x.order))
                {
                    raw.Add((scriptFile, enable));
                }
            }
            else if (File.Exists(chainFile))
            {
                foreach (ChainEntry e in ReadChain(chainFile))
                {
                    if (!string.IsNullOrWhiteSpace(e.Builtin))
                    {
                        //旧版单链文件（含 Builtin 字段）：内置项按 key.js 引用脚本文件
                        raw.Add((e.Builtin + ".js", e.Enable));
                        migrated = true;
                    }
                    else if (!string.IsNullOrWhiteSpace(e.Script))
                    {
                        raw.Add((e.Script!, e.Enable));
                    }
                }
            }
            foreach ((string scriptFile0, bool enable) in raw)
            {
                string scriptFile = ResolveScriptRef(scriptFile0, renames);
                LibScript? s = LoadLibScript(Path.Combine(scriptsDir, scriptFile), "编码脚本");
                if (s != null && ScriptUsages.IsTransform(s.Usage))
                {
                    chained.Add(scriptFile);
                    EncodeToolModel m = ToEncodeTool(s, Path.GetFileNameWithoutExtension(scriptFile));
                    m.Enable = enable; // 链文件启停覆盖文件头（启停是高频操作，集中在链文件）
                    entries.Add((entries.Count, m, scriptFile));
                }
            }
            //自动发现：scripts/ 下未入链的变换类脚本追加到链尾（手工丢文件即生效；动态值类脚本按用途分流到动态值链）
            if (Directory.Exists(scriptsDir))
            {
                foreach (string f in Directory.GetFiles(scriptsDir, "*.js").OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
                {
                    string fname = Path.GetFileName(f);
                    if (chained.Contains(fname))
                    {
                        continue;
                    }
                    LibScript? s = LoadLibScript(f, "编码脚本");
                    if (s != null && ScriptUsages.IsTransform(s.Usage))
                    {
                        entries.Add((int.MaxValue, ToEncodeTool(s, Path.GetFileNameWithoutExtension(fname)), fname));
                    }
                }
            }
            //内置示例脚本种子：链中（含自动发现）无同名脚本时写入 scripts/ 并以停用状态挂到链尾——
            //每次加载比对、缺失即补（删除会重新生成，不想用请保持停用）
            int seedAdded = 0;
            {
                var usedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (Directory.Exists(scriptsDir))
                {
                    foreach (string f in Directory.GetFiles(scriptsDir, "*.js"))
                    {
                        usedFiles.Add(Path.GetFileName(f));
                    }
                }
                foreach (SeedScripts.Item seed in SeedScripts.All)
                {
                    bool exists = entries.Any(x => string.Equals(x.m.Name, seed.Name, StringComparison.OrdinalIgnoreCase));
                    if (exists)
                    {
                        continue;
                    }
                    try
                    {
                        Directory.CreateDirectory(scriptsDir);
                        string file = ScriptFileName(seed.Name, usedFiles);
                        WriteScript(Path.Combine(scriptsDir, file), new Dictionary<string, string>
                        {
                            ["name"] = seed.Name,
                            ["usage"] = ScriptUsages.ToMeta(seed.Usage),
                            ["enable"] = "false"
                        }, seed.Code);
                        entries.Add((int.MaxValue, new EncodeToolModel
                        {
                            Name = seed.Name,
                            Key = Path.GetFileNameWithoutExtension(file),
                            Code = seed.Code,
                            Enable = false,
                            Scope = ScriptUsages.ToScope(seed.Usage)
                        }, file));
                        seedAdded++;
                        Log.SysLog("规则库：内置示例脚本已生成 scripts/" + file + "（默认停用，脚本库页开启生效）");
                    }
                    catch (Exception e)
                    {
                        Log.SysLog("规则库：内置示例脚本生成失败 " + seed.Name + " -- " + e.Message);
                    }
                }
            }
            //按 Order 归并还原混排链（OrderBy 稳定排序）
            var list = entries.OrderBy(x => x.order).Select(x => (x.m, x.scriptFile)).ToList();
            if (migrated || seedAdded > 0)
            {
                try
                {
                    Directory.CreateDirectory(dir);
                    WriteTamperChain(dir, list);
                    foreach (string stale in new[] { builtinFile, customFile })
                    {
                        if (File.Exists(stale))
                        {
                            try { File.Delete(stale); } catch { /* 占用时留待下次 */ }
                        }
                    }
                }
                catch (Exception e)
                {
                    Log.SysLog("规则库：编码链迁移落盘失败 -- " + e.Message);
                }
            }
            foreach ((EncodeToolModel m, _) in list)
            {
                config.ByPassConfig.EncodeTools.Add(m);
            }
        }

        /// <summary>按当前链顺序写 tampers/chain.json（Order=链内位置；脚本是既有文件名引用，不重写 .js）</summary>
        private static void WriteTamperChain(string dir, List<(EncodeToolModel m, string scriptFile)> list)
        {
            var chain = new List<ScriptEntry>();
            for (int i = 0; i < list.Count; i++)
            {
                chain.Add(new ScriptEntry { Script = list[i].scriptFile, Enable = list[i].m.Enable, Order = i });
            }
            File.WriteAllText(Path.Combine(dir, "chain.json"), JsonSerializer.Serialize(chain, JsonCtx.IndentedInfo<List<ScriptEntry>>()));
        }

        private static void LoadTokenScripts(AppConfig config, string rulesDir, Dictionary<string, string> renames)
        {
            string scriptsDir = ScriptsDir(rulesDir);
            var chained = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (ChainEntry e in ReadChain(Path.Combine(rulesDir, "token-scripts", "chain.json")))
            {
                if (string.IsNullOrWhiteSpace(e.Script))
                {
                    continue;
                }
                string scriptFile = ResolveScriptRef(e.Script!, renames);
                LibScript? s = LoadLibScript(Path.Combine(scriptsDir, scriptFile), "动态值脚本");
                if (s != null && !ScriptUsages.IsTransform(s.Usage))
                {
                    chained.Add(scriptFile);
                    config.TokenScripts.Add(new ScriptTamperModel
                    {
                        Name = s.Name,
                        Code = s.Code,
                        Enable = e.Enable, // 链文件启停覆盖文件头
                        Kind = ScriptUsages.ToKind(s.Usage)
                    });
                }
            }
            //自动发现：scripts/ 下未入链的动态值类脚本追加到链尾（变换类由编码链负责，按用途分流）
            if (Directory.Exists(scriptsDir))
            {
                foreach (string f in Directory.GetFiles(scriptsDir, "*.js").OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
                {
                    if (chained.Contains(Path.GetFileName(f)))
                    {
                        continue;
                    }
                    LibScript? s = LoadLibScript(f, "动态值脚本");
                    if (s != null && !ScriptUsages.IsTransform(s.Usage))
                    {
                        config.TokenScripts.Add(new ScriptTamperModel
                        {
                            Name = s.Name,
                            Code = s.Code,
                            Enable = s.Enable,
                            Kind = ScriptUsages.ToKind(s.Usage)
                        });
                    }
                }
            }
        }

        private static void LoadDynamicRules(AppConfig config, string file)
        {
            if (!File.Exists(file))
            {
                return;
            }
            try
            {
                List<DynamicRuleDto>? dtos = JsonSerializer.Deserialize(File.ReadAllText(file), JsonCtx.IndentedInfo<List<DynamicRuleDto>>());
                if (dtos == null)
                {
                    return;
                }
                //整体替换赋值（非逐条Add）：触发CompanionRules setter的HookCompanionRules，
                //完成TxtRequest编辑器文档回填与二次注入单开强制（与GUI反序列化路径行为一致）
                var col = new ObservableCollection<CompanionRequestConfig>();
                foreach (DynamicRuleDto d in dtos)
                {
                    col.Add(new CompanionRequestConfig
                    {
                        Kind = d.Kind, Name = d.Name, TagName = d.TagName, Enabled = d.Enabled,
                        SourceMode = d.SourceMode, Url = d.Url, Method = d.Method, RequestTxt = d.RequestTxt,
                        UseScript = d.UseScript, SubStart = d.SubStart, SubEnd = d.SubEnd, ScriptName = d.ScriptName
                    });
                }
                config.CompanionRules = col;
            }
            catch (Exception e)
            {
                Log.SysLog("动态规则解析失败（按空处理）：" + e.Message);
            }
        }

        private static void LoadReplaceRules(AppConfig config, string file)
        {
            if (!File.Exists(file))
            {
                return;
            }
            try
            {
                List<ReplaceModel>? items = JsonSerializer.Deserialize(File.ReadAllText(file), JsonCtx.IndentedInfo<List<ReplaceModel>>());
                if (items != null)
                {
                    foreach (ReplaceModel m in items)
                    {
                        config.ByPassConfig.ReplaceItems.Add(m);
                    }
                }
            }
            catch (Exception e)
            {
                Log.SysLog("字符替换规则解析失败（按空处理）：" + e.Message);
            }
        }

        private static void LoadProxies(AppConfig config, string file)
        {
            if (!File.Exists(file))
            {
                return;
            }
            try
            {
                List<ProxyDto>? dtos = JsonSerializer.Deserialize(File.ReadAllText(file), JsonCtx.IndentedInfo<List<ProxyDto>>());
                if (dtos != null)
                {
                    foreach (ProxyDto d in dtos)
                    {
                        config.ProxyConfig.ProxyItems.Add(new Proxy
                        {
                            Host = d.Host, Port = d.Port, proxyType = NormalizeProxyType(d.Type), username = d.Username, password = d.Password
                        });
                    }
                }
            }
            catch (Exception e)
            {
                Log.SysLog("代理池解析失败（按空处理）：" + e.Message);
            }
        }

        /// <summary>代理类型归一化：仅 Socks5/HTTP 两值合法，脏数据（旧版误存的 ComboBoxItem 文本等）归一为 HTTP</summary>
        private static string NormalizeProxyType(string? type)
        {
            return "Socks5".Equals(type, StringComparison.Ordinal) ? "Socks5" : "HTTP";
        }

        //================================================ 保存 ================================================

        /// <summary>把 config 中的五类规则写回 rules 目录（原子性按文件级尽力而为，目录自动创建）</summary>
        public static void SaveAll(AppConfig config, string? rulesDir = null)
        {
            string dir = rulesDir ?? DefaultDir;
            _activeRulesDir = dir;
            try
            {
                SaveScripts(config, dir);
                SaveDynamicRules(config, Path.Combine(dir, "dynamic-rules.json"));
                SaveReplaceRules(config, Path.Combine(dir, "replace-rules.json"));
                SaveProxies(config, Path.Combine(dir, "proxies.json"));
            }
            catch (Exception e)
            {
                Log.SysLog("规则库保存异常：" + e.Message);
            }
        }

        /// <summary>脚本文件名：按名称净化（非法字符转_），同目录内唯一</summary>
        private static string ScriptFileName(string name, HashSet<string> used)
        {
            var sb = new StringBuilder(name.Length);
            foreach (char c in name)
            {
                sb.Append(char.IsLetterOrDigit(c) || c is '-' or '_' or '.' ? c : '_');
            }
            string baseName = sb.Length == 0 ? "script" : sb.ToString();
            string file = baseName + ".js";
            for (int i = 2; used.Contains(file); i++)
            {
                file = baseName + "_" + i + ".js";
            }
            used.Add(file);
            return file;
        }

        /// <summary>编码链项的脚本文件名：Key 为磁盘文件名主干（加载时建立）则保持原名不变；
        /// 无 Key/旧版 js: 前缀键（新建项）按名称净化生成，同目录唯一</summary>
        private static string ScriptFileNameOf(EncodeToolModel m, HashSet<string> used)
        {
            string stem = m.Key ?? "";
            if (!string.IsNullOrWhiteSpace(stem) && !stem.StartsWith("js:", StringComparison.OrdinalIgnoreCase))
            {
                string file = stem + ".js";
                if (!used.Contains(file))
                {
                    used.Add(file);
                    return file;
                }
            }
            return ScriptFileName(m.Name, used);
        }

        private static void WriteScript(string file, Dictionary<string, string> meta, string code)
        {
            var sb = new StringBuilder();
            foreach (var kv in meta)
            {
                sb.Append("//@").Append(kv.Key).Append(": ").Append(kv.Value).Append('\n');
            }
            sb.Append(code ?? "");
            File.WriteAllText(file, sb.ToString());
        }

        /// <summary>
        /// 统一脚本库保存：一脚本一 .js 写入 scripts/（统一元数据头 name/usage/enable/description，文件名共享去重），
        /// 再写 tampers/chain.json（编码链脚本引用，数组序=执行顺序）与 token-scripts/chain.json（动态值脚本引用）；
        /// 清理 scripts/ 下无引用文件与旧布局（tampers/、token-scripts/、builtin_*.js、builtin.json/custom.json）残留。
        /// </summary>
        private static void SaveScripts(AppConfig config, string rulesDir)
        {
            string scriptsDir = ScriptsDir(rulesDir);
            string tampersDir = Path.Combine(rulesDir, "tampers");
            string tokenDir = Path.Combine(rulesDir, "token-scripts");
            Directory.CreateDirectory(scriptsDir);
            Directory.CreateDirectory(tampersDir);
            Directory.CreateDirectory(tokenDir);

            //1) 全部脚本写 scripts/（共享 used 集合保证文件名全局唯一），记录 模型→实际文件名
            var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var keep = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var fileOf = new Dictionary<object, string>(ReferenceEqualityComparer.Instance);
            foreach (EncodeToolModel m in config.ByPassConfig.EncodeTools)
            {
                string file = ScriptFileNameOf(m, used);
                keep.Add(file);
                fileOf[m] = file;
                var meta = new Dictionary<string, string>
                {
                    ["name"] = m.Name,
                    ["usage"] = ScriptUsages.ToMeta(ScriptUsages.FromScope(m.Scope)),
                    ["enable"] = m.Enable ? "true" : "false"
                };
                if (!string.IsNullOrWhiteSpace(m.Description))
                {
                    meta["description"] = m.Description;
                }
                WriteScript(Path.Combine(scriptsDir, file), meta, m.Code);
            }
            foreach (ScriptTamperModel m in config.TokenScripts)
            {
                string file = ScriptFileName(m.Name, used);
                keep.Add(file);
                fileOf[m] = file;
                WriteScript(Path.Combine(scriptsDir, file), new Dictionary<string, string>
                {
                    ["name"] = m.Name,
                    ["usage"] = ScriptUsages.ToMeta(ScriptUsages.FromKind(m.Kind)),
                    ["enable"] = m.Enable ? "true" : "false"
                }, m.Code);
            }

            //2) 编码链：tampers/chain.json（数组序=链内执行顺序）
            var chain = new List<ScriptEntry>();
            int order = 0;
            foreach (EncodeToolModel m in config.ByPassConfig.EncodeTools)
            {
                chain.Add(new ScriptEntry { Script = fileOf[m], Enable = m.Enable, Order = order++ });
            }
            File.WriteAllText(Path.Combine(tampersDir, "chain.json"), JsonSerializer.Serialize(chain, JsonCtx.IndentedInfo<List<ScriptEntry>>()));

            //3) 动态值脚本引用链（顺序=回退选择优先级）
            var tokenChain = new List<ChainEntry>();
            foreach (ScriptTamperModel m in config.TokenScripts)
            {
                tokenChain.Add(new ChainEntry { Script = fileOf[m], Enable = m.Enable });
            }
            File.WriteAllText(Path.Combine(tokenDir, "chain.json"), JsonSerializer.Serialize(tokenChain, JsonCtx.IndentedInfo<List<ChainEntry>>()));

            //4) 清理 scripts/ 下无引用文件（已删除脚本的遗留）
            foreach (string f in Directory.GetFiles(scriptsDir, "*.js"))
            {
                if (!keep.Contains(Path.GetFileName(f)))
                {
                    try { File.Delete(f); } catch { /* 占用时留待下次 */ }
                }
            }
            //5) 清理旧布局残留（tampers/*.js、token-scripts/*.js 已迁移入 scripts/；双链文件已归并 chain.json）
            foreach (string legacyDir in new[] { tampersDir, tokenDir })
            {
                foreach (string f in Directory.GetFiles(legacyDir, "*.js"))
                {
                    try { File.Delete(f); } catch { /* 占用时留待下次 */ }
                }
            }
            foreach (string stale in new[] { "builtin.json", "custom.json" })
            {
                string p = Path.Combine(tampersDir, stale);
                if (File.Exists(p))
                {
                    try { File.Delete(p); } catch { /* 占用时留待下次 */ }
                }
            }
        }

        private static void SaveDynamicRules(AppConfig config, string file)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(file)!);
            var dtos = config.CompanionRules.Select(r => new DynamicRuleDto
            {
                Kind = r.Kind, Name = r.Name, TagName = r.TagName, Enabled = r.Enabled,
                SourceMode = r.SourceMode, Url = r.Url, Method = r.Method, RequestTxt = r.RequestTxt,
                UseScript = r.UseScript, SubStart = r.SubStart, SubEnd = r.SubEnd, ScriptName = r.ScriptName
            }).ToList();
            File.WriteAllText(file, JsonSerializer.Serialize(dtos, JsonCtx.IndentedInfo<List<DynamicRuleDto>>()));
        }

        private static void SaveReplaceRules(AppConfig config, string file)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(file)!);
            File.WriteAllText(file, JsonSerializer.Serialize(config.ByPassConfig.ReplaceItems.ToList(), JsonCtx.IndentedInfo<List<ReplaceModel>>()));
        }

        private static void SaveProxies(AppConfig config, string file)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(file)!);
            var dtos = config.ProxyConfig.ProxyItems.Select(p => new ProxyDto
            {
                Host = p.Host, Port = p.Port, Type = p.proxyType, Username = p.username, Password = p.password
            }).ToList();
            File.WriteAllText(file, JsonSerializer.Serialize(dtos, JsonCtx.IndentedInfo<List<ProxyDto>>()));
        }
    }
}
