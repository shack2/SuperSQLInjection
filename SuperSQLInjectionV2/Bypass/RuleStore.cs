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
    ///   tampers/         编码工具链，内置/自定义分两个文件：builtin.json（内置项启停/参数/Order）+
    ///                    custom.json（自定义脚本链顺序/启停/Order）+ 一脚本一 .js（前置 //@ 元数据头）；
    ///                    两个文件的 Order 为全局执行顺序，加载时按 Order 归并还原混排链
    ///   token-scripts/   动态值脚本（chain.json + 一脚本一 .js，同构）
    ///   dynamic-rules.json   动态规则（DRule/二次注入）
    ///   replace-rules.json   字符替换规则
    ///   proxies.json         代理池
    /// 加载容错：目录/文件缺失按空规则处理，单项损坏跳过并记日志，不影响其余项与主程序启动。
    /// </summary>
    public static class RuleStore
    {
        //======== tampers 双文件条目（内置/自定义分开持久化，Order 保持混排执行顺序）========
        public sealed class BuiltinEntry
        {
            public string? Key { get; set; }              // 内置工具 Key（EncodeToolRegistry）
            public bool Enable { get; set; }
            public int Scope { get; set; } = 0;           // ScriptScope（内置项固定 Payload 级，UI 锁定）
            public int DoCount { get; set; } = 1;         // 执行次数
            public int Order { get; set; }                // 全局执行顺序（与 custom.json 按序归并）
        }

        public sealed class ScriptEntry
        {
            public string? Script { get; set; }           // 自定义脚本文件名（.js）
            public bool Enable { get; set; } = true;      // 启停覆盖脚本文件头（高频操作集中在链文件）
            public int Order { get; set; }                // 全局执行顺序
        }

        //======== 链文件条目（token-scripts 用；tampers 旧版 chain.json 仅作迁移读取）========
        public sealed class ChainEntry
        {
            public string? Builtin { get; set; }          // 内置工具 Key（与 script 二选一）
            public string? Script { get; set; }           // 自定义脚本文件名（.js）
            public bool Enable { get; set; } = true;
            public int Scope { get; set; } = 0;           // ScriptScope（仅内置项有意义，脚本项以文件头为准）
            public int DoCount { get; set; } = 1;         // 执行次数（仅内置项）
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

        /// <summary>从 rules 目录加载全部规则到 config（目录缺失=空规则，逐项容错）</summary>
        public static void LoadAll(AppConfig config, string? rulesDir = null)
        {
            string dir = rulesDir ?? DefaultDir;
            try
            {
                LoadTampers(config, Path.Combine(dir, "tampers"));
                LoadTokenScripts(config, Path.Combine(dir, "token-scripts"));
                LoadDynamicRules(config, Path.Combine(dir, "dynamic-rules.json"));
                LoadReplaceRules(config, Path.Combine(dir, "replace-rules.json"));
                LoadProxies(config, Path.Combine(dir, "proxies.json"));
            }
            catch (Exception e)
            {
                Log.SysLog("规则库加载异常（已加载部分有效）：" + e.Message);
            }
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

        private static void LoadTampers(AppConfig config, string dir)
        {
            //(order, model, scriptFile)：scriptFile=脚本项磁盘文件名（内置项为null），合并落盘时保持脚本引用不丢
            var entries = new List<(int order, EncodeToolModel m, string? scriptFile)>();
            var chained = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string builtinFile = Path.Combine(dir, "builtin.json");
            string customFile = Path.Combine(dir, "custom.json");
            string legacyFile = Path.Combine(dir, "chain.json");
            bool migrated = false;
            if (!File.Exists(builtinFile) && !File.Exists(customFile) && File.Exists(legacyFile))
            {
                //旧版单链文件迁移（chain.json 内置/自定义混排）：按序读入，落盘时自动拆成 builtin.json + custom.json 并删除旧文件
                migrated = true;
                int order = 0;
                foreach (ChainEntry e in ReadChain(legacyFile))
                {
                    if (!string.IsNullOrWhiteSpace(e.Builtin))
                    {
                        if (EncodeToolRegistry.TryGet(e.Builtin!, out EncodeTool tool))
                        {
                            entries.Add((order++, new EncodeToolModel
                            {
                                Name = tool.Name, Key = tool.Key, Builtin = true, Enable = e.Enable,
                                Scope = (ScriptScope)e.Scope, DoCount = Math.Max(1, e.DoCount)
                            }, null));
                        }
                        else
                        {
                            Log.SysLog("规则库：未知内置编码工具 " + e.Builtin + "（已跳过）");
                        }
                    }
                    else if (!string.IsNullOrWhiteSpace(e.Script))
                    {
                        chained.Add(e.Script!);
                        EncodeToolModel? m = LoadTamperFile(Path.Combine(dir, e.Script!));
                        if (m != null)
                        {
                            m.Enable = e.Enable;
                            entries.Add((order++, m, e.Script!));
                        }
                    }
                }
            }
            else
            {
                foreach (BuiltinEntry e in ReadList(builtinFile, JsonCtx.IndentedInfo<List<BuiltinEntry>>(), "内置编码链文件"))
                {
                    if (string.IsNullOrWhiteSpace(e.Key))
                    {
                        continue;
                    }
                    if (EncodeToolRegistry.TryGet(e.Key!, out EncodeTool tool))
                    {
                        entries.Add((e.Order, new EncodeToolModel
                        {
                            Name = tool.Name, Key = tool.Key, Builtin = true, Enable = e.Enable,
                            Scope = (ScriptScope)e.Scope, DoCount = Math.Max(1, e.DoCount)
                        }, null));
                    }
                    else
                    {
                        Log.SysLog("规则库：未知内置编码工具 " + e.Key + "（已跳过）");
                    }
                }
                foreach (ScriptEntry e in ReadList(customFile, JsonCtx.IndentedInfo<List<ScriptEntry>>(), "自定义编码链文件"))
                {
                    if (string.IsNullOrWhiteSpace(e.Script))
                    {
                        continue;
                    }
                    chained.Add(e.Script!);
                    EncodeToolModel? m = LoadTamperFile(Path.Combine(dir, e.Script!));
                    if (m != null)
                    {
                        m.Enable = e.Enable; // 链文件启停覆盖文件头（启停是高频操作，集中在链文件）
                        entries.Add((e.Order, m, e.Script!));
                    }
                }
            }
            //自动发现：未入链的 .js 追加到链尾（手工丢文件即生效）
            if (Directory.Exists(dir))
            {
                foreach (string f in Directory.GetFiles(dir, "*.js").OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
                {
                    if (chained.Contains(Path.GetFileName(f)))
                    {
                        continue;
                    }
                    EncodeToolModel? m = LoadTamperFile(f);
                    if (m != null)
                    {
                        entries.Add((int.MaxValue, m, Path.GetFileName(f)));
                    }
                }
            }
            //按 Order 归并还原混排链（OrderBy 稳定排序：同序时内置项先于自定义项）
            var list = entries.OrderBy(x => x.order).Select(x => (x.m, x.scriptFile)).ToList();
            //默认数据生成（仅磁盘无内置规则数据时：全新安装/旧版空链迁移/builtin.json 被删或被清空）——
            //按内置注册表生成全量默认项（停用、固定Payload级）并落盘，编码处理页打开即是完整策略清单；
            //磁盘已有内置数据则原样加载（启停/顺序保留，不做逐项补齐；内置项UI不可删除，不会意外丢失）。
            int added = 0;
            if (!list.Any(x => x.m.Builtin))
            {
                foreach (EncodeTool t in EncodeToolRegistry.VisibleTools)
                {
                    list.Add((new EncodeToolModel
                    {
                        Name = t.Name, Key = t.Key, Builtin = true, Enable = false,
                        Scope = ScriptScope.Payload, DoCount = 1
                    }, (string?)null));
                    added++;
                }
            }
            if (added > 0 || migrated)
            {
                try
                {
                    Directory.CreateDirectory(dir);
                    WriteTamperFiles(dir, list);
                    if (migrated)
                    {
                        try { File.Delete(legacyFile); } catch { /* 占用时留待下次 */ }
                    }
                }
                catch (Exception e)
                {
                    Log.SysLog("规则库：内置编码工具合并落盘失败 -- " + e.Message);
                }
            }
            foreach ((EncodeToolModel m, _) in list)
            {
                config.ByPassConfig.EncodeTools.Add(m);
            }
        }

        /// <summary>按当前链顺序写 builtin.json + custom.json（Order=链内位置；脚本是既有文件名引用，不重写 .js）</summary>
        private static void WriteTamperFiles(string dir, List<(EncodeToolModel m, string? scriptFile)> list)
        {
            var builtins = new List<BuiltinEntry>();
            var customs = new List<ScriptEntry>();
            for (int i = 0; i < list.Count; i++)
            {
                (EncodeToolModel m, string? scriptFile) = list[i];
                if (m.Builtin)
                {
                    builtins.Add(new BuiltinEntry { Key = m.Key, Enable = m.Enable, Scope = (int)m.Scope, DoCount = m.DoCount, Order = i });
                }
                else if (!string.IsNullOrWhiteSpace(scriptFile))
                {
                    customs.Add(new ScriptEntry { Script = scriptFile, Enable = m.Enable, Order = i });
                }
            }
            File.WriteAllText(Path.Combine(dir, "builtin.json"), JsonSerializer.Serialize(builtins, JsonCtx.IndentedInfo<List<BuiltinEntry>>()));
            File.WriteAllText(Path.Combine(dir, "custom.json"), JsonSerializer.Serialize(customs, JsonCtx.IndentedInfo<List<ScriptEntry>>()));
        }

        private static EncodeToolModel? LoadTamperFile(string file)
        {
            if (!File.Exists(file))
            {
                Log.SysLog("规则库：脚本文件缺失 " + file + "（已跳过）");
                return null;
            }
            try
            {
                var (meta, code) = ParseScript(file);
                string name = meta.TryGetValue("name", out string? n) && !string.IsNullOrWhiteSpace(n)
                    ? n : Path.GetFileNameWithoutExtension(file);
                return new EncodeToolModel
                {
                    Name = name,
                    Key = "js:" + name,
                    Builtin = false,
                    Code = code,
                    Enable = !meta.TryGetValue("enable", out string? en) || !"false".Equals(en, StringComparison.OrdinalIgnoreCase),
                    Scope = meta.TryGetValue("scope", out string? sc) && Enum.TryParse(sc, true, out ScriptScope s2) ? s2 : ScriptScope.Payload,
                    DoCount = meta.TryGetValue("doCount", out string? dc) && int.TryParse(dc, out int d2) ? Math.Max(1, d2) : 1
                };
            }
            catch (Exception e)
            {
                Log.SysLog("规则库：脚本解析失败 " + file + " -- " + e.Message);
                return null;
            }
        }

        private static void LoadTokenScripts(AppConfig config, string dir)
        {
            var chained = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (ChainEntry e in ReadChain(Path.Combine(dir, "chain.json")))
            {
                if (string.IsNullOrWhiteSpace(e.Script))
                {
                    continue;
                }
                chained.Add(e.Script!);
                ScriptTamperModel? m = LoadTokenFile(Path.Combine(dir, e.Script!));
                if (m != null)
                {
                    m.Enable = e.Enable;
                    config.TokenScripts.Add(m);
                }
            }
            if (Directory.Exists(dir))
            {
                foreach (string f in Directory.GetFiles(dir, "*.js").OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
                {
                    if (chained.Contains(Path.GetFileName(f)))
                    {
                        continue;
                    }
                    ScriptTamperModel? m = LoadTokenFile(f);
                    if (m != null)
                    {
                        config.TokenScripts.Add(m);
                    }
                }
            }
        }

        private static ScriptTamperModel? LoadTokenFile(string file)
        {
            if (!File.Exists(file))
            {
                Log.SysLog("规则库：动态值脚本缺失 " + file + "（已跳过）");
                return null;
            }
            try
            {
                var (meta, code) = ParseScript(file);
                return new ScriptTamperModel
                {
                    Name = meta.TryGetValue("name", out string? n) && !string.IsNullOrWhiteSpace(n)
                        ? n : Path.GetFileNameWithoutExtension(file),
                    Code = code,
                    Enable = !meta.TryGetValue("enable", out string? en) || !"false".Equals(en, StringComparison.OrdinalIgnoreCase),
                    Kind = meta.TryGetValue("kind", out string? k) && int.TryParse(k, out int k2) ? k2 : 0
                };
            }
            catch (Exception e)
            {
                Log.SysLog("规则库：动态值脚本解析失败 " + file + " -- " + e.Message);
                return null;
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
                            Host = d.Host, Port = d.Port, proxyType = d.Type, username = d.Username, password = d.Password
                        });
                    }
                }
            }
            catch (Exception e)
            {
                Log.SysLog("代理池解析失败（按空处理）：" + e.Message);
            }
        }

        //================================================ 保存 ================================================

        /// <summary>把 config 中的五类规则写回 rules 目录（原子性按文件级尽力而为，目录自动创建）</summary>
        public static void SaveAll(AppConfig config, string? rulesDir = null)
        {
            string dir = rulesDir ?? DefaultDir;
            try
            {
                SaveTampers(config, Path.Combine(dir, "tampers"));
                SaveTokenScripts(config, Path.Combine(dir, "token-scripts"));
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

        private static void SaveTampers(AppConfig config, string dir)
        {
            Directory.CreateDirectory(dir);
            var builtins = new List<BuiltinEntry>();
            var customs = new List<ScriptEntry>();
            var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var keep = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int order = 0;
            foreach (EncodeToolModel m in config.ByPassConfig.EncodeTools)
            {
                if (m.Builtin)
                {
                    builtins.Add(new BuiltinEntry { Key = m.Key, Enable = m.Enable, Scope = (int)m.Scope, DoCount = m.DoCount, Order = order++ });
                }
                else
                {
                    string file = ScriptFileName(m.Name, used);
                    keep.Add(file);
                    customs.Add(new ScriptEntry { Script = file, Enable = m.Enable, Order = order++ });
                    WriteScript(Path.Combine(dir, file), new Dictionary<string, string>
                    {
                        ["name"] = m.Name,
                        ["enable"] = m.Enable ? "true" : "false",
                        ["scope"] = m.Scope.ToString(),
                        ["doCount"] = m.DoCount.ToString()
                    }, m.Code);
                }
            }
            //清理已删除脚本的遗留文件（只清本目录 .js，不动 json 链文件）
            foreach (string f in Directory.GetFiles(dir, "*.js"))
            {
                if (!keep.Contains(Path.GetFileName(f)))
                {
                    try { File.Delete(f); } catch { /* 占用时留待下次 */ }
                }
            }
            File.WriteAllText(Path.Combine(dir, "builtin.json"), JsonSerializer.Serialize(builtins, JsonCtx.IndentedInfo<List<BuiltinEntry>>()));
            File.WriteAllText(Path.Combine(dir, "custom.json"), JsonSerializer.Serialize(customs, JsonCtx.IndentedInfo<List<ScriptEntry>>()));
            //旧版单链文件已拆分，清理遗留
            string legacy = Path.Combine(dir, "chain.json");
            if (File.Exists(legacy))
            {
                try { File.Delete(legacy); } catch { /* 占用时留待下次 */ }
            }
        }

        private static void SaveTokenScripts(AppConfig config, string dir)
        {
            Directory.CreateDirectory(dir);
            var chain = new List<ChainEntry>();
            var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var keep = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (ScriptTamperModel m in config.TokenScripts)
            {
                string file = ScriptFileName(m.Name, used);
                keep.Add(file);
                chain.Add(new ChainEntry { Script = file, Enable = m.Enable });
                WriteScript(Path.Combine(dir, file), new Dictionary<string, string>
                {
                    ["name"] = m.Name,
                    ["enable"] = m.Enable ? "true" : "false",
                    ["kind"] = m.Kind.ToString()
                }, m.Code);
            }
            foreach (string f in Directory.GetFiles(dir, "*.js"))
            {
                if (!keep.Contains(Path.GetFileName(f)))
                {
                    try { File.Delete(f); } catch { /* 占用时留待下次 */ }
                }
            }
            File.WriteAllText(Path.Combine(dir, "chain.json"), JsonSerializer.Serialize(chain, JsonCtx.IndentedInfo<List<ChainEntry>>()));
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
