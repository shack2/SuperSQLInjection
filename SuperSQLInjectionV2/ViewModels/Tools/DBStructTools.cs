using SuperSQLInjectionV2.Tools;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Styling;
using Avalonia.Threading;
using AvaloniaEdit.Utils;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Models.Data;
using SuperSQLInjectionV2.Payload;
using SuperSQLInjectionV2.Tools.Http;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Data;
using System.Linq;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.ViewModels.Tools
{
    /// <summary>
    /// 库/表/列三层结构枚举。三通道（盲注/Union/报错）×三层级的9个入口收敛为：
    /// 层级描述符（EnumLevel，payload生成差异）× 通道模板方法（EnumerateByBool/ByUnion/ByError，遍历与回填骨架），
    /// 公开API保持9个薄包装不变。新增元数据层级只需加一个 EnumLevel。
    /// </summary>
    public class DBStructTools
    {
        // ================== 层级描述符 ==================

        /// <summary>一个元数据层级的payload差异定义（parent=null表示根/库级）</summary>
        private sealed class EnumLevel
        {
            public required DBStructType NodeType;
            /// <summary>表/列级支持字典猜解（Access无元数据或低权限点）</summary>
            public bool SupportsDictGuess;
            /// <summary>字典猜解时isTable参数（true猜表名，false猜字段名）</summary>
            public bool DictGuessIsTable;
            public required Func<DBStruct?, string> CountPayload;
            public required Func<DBStruct?, string> NamesPayload;
            public required Func<DBStruct?, int, string> NamePayloadAt;
        }

        private static readonly EnumLevel DbLevel = new ()
        {
            NodeType = DBStructType.DBName,
            SupportsDictGuess = false,
            CountPayload = _ => PayloadFactory.BasePayload.DBCount,
            NamesPayload = _ => PayloadFactory.BasePayload.DBNames,
            NamePayloadAt = (_, i) => PayloadFactory.BPTool.GetDBName(i)
        };

        private static readonly EnumLevel TableLevel = new ()
        {
            NodeType = DBStructType.TableName,
            SupportsDictGuess = true,
            DictGuessIsTable = true,
            CountPayload = p => PayloadFactory.BPTool.GetTableCount(p!.Value),
            NamesPayload = p => PayloadFactory.BPTool.GetTableNames(p!.Value),
            NamePayloadAt = (p, i) => PayloadFactory.BPTool.GetTableName(p!.Value, i)
        };

        private static readonly EnumLevel ColumnLevel = new ()
        {
            NodeType = DBStructType.ColumnName,
            SupportsDictGuess = true,
            DictGuessIsTable = false,
            CountPayload = p => PayloadFactory.BPTool.GetColumnCount(p!.Parent?.Value ?? "", p.Value),
            NamesPayload = p => PayloadFactory.BPTool.GetColumnNames(p!.Parent?.Value ?? "", p.Value),
            NamePayloadAt = (p, i) => PayloadFactory.BPTool.GetColumnName(p!.Parent?.Value ?? "", p.Value, i)
        };

        /// <summary>父节点枚举：库级=单个隐式根（null）；表级=选中的库；列级=所有库下选中的表</summary>
        private static IEnumerable<DBStruct?> EnumerateParents(AppConfig config, DBStructType nodeType) => nodeType switch
        {
            DBStructType.DBName => new DBStruct?[] { null },
            DBStructType.TableName => config.DataDump.DBStructItems.Where(x => x.IsSelected).Cast<DBStruct?>(),
            _ => config.DataDump.DBStructItems.SelectMany(d => d.SubItems.Where(t => t.IsSelected)).Cast<DBStruct?>()
        };

        // ================== 通道模板方法 ==================

        /// <summary>盲注通道：count→逐节点占位→GetStringByBool读名→回填</summary>
        private static async Task EnumerateByBool(AppConfig config, EnumLevel level)
        {
            foreach (DBStruct? parent in EnumerateParents(config, level.NodeType))
            {
                config.CheckStop();
                if (level.SupportsDictGuess && (config.DataConfig.SelectedDBType.Equals(DBType.Access) || config.DataConfig.DictGuessAll))
                {
                    //Access无元数据/字典猜解模式（低权限点）：字典猜解（common-tables/common-columns 能力）
                    await GuessAccessDictByBool(config, parent!, level.DictGuessIsTable).ConfigureAwait(false);
                    continue;
                }
                int count = await DataComm.GetValueLen(config, level.CountPayload(parent), 0, 1000).ConfigureAwait(false);
                ObservableCollection<DBStruct> container = parent == null ? config.DataDump.DBStructItems : parent.SubItems;
                //清空子节点
                container.Clear();
                for (int i = 0; i < count; i++)
                {
                    config.CheckStop();
                    //多字节安全的盲注取值（hex/unicode/ascw），内部通过stp并行取字符
                    string name = (await DataComm.GetStringByBool(config, level.NamePayloadAt(parent, i), 256).ConfigureAwait(false)) ?? "";
                    //事件通知：取到名称后一次派发挂完整节点（原"先挂空节点再回填"每节点2次MaxValue派发，且空节点闪现）
                    UiNotifier.Post( ()=> container.Add(new DBStruct { Parent = parent!, Type = level.NodeType, Value = name }));
                }
            }
        }

        /// <summary>Union通道：聚合一次取回（截断回退逐行）→整批回填</summary>
        private static async Task EnumerateByUnion(AppConfig config, EnumLevel level)
        {
            foreach (DBStruct? parent in EnumerateParents(config, level.NodeType))
            {
                config.CheckStop();
                if (level.SupportsDictGuess && config.DataConfig.DictGuessAll)
                {
                    //全库字典猜解：exists布尔判断通道逐词猜解，与当前注入类型无关
                    await GuessAccessDictByBool(config, parent!, level.DictGuessIsTable).ConfigureAwait(false);
                    continue;
                }
                List<string> names = await GetUnionNames(config, level.NamesPayload(parent), level.CountPayload(parent),
                    i => level.NamePayloadAt(parent, i)).ConfigureAwait(false);
                ObservableCollection<DBStruct> container = parent == null ? config.DataDump.DBStructItems : parent.SubItems;
                if (parent != null)
                {
                    container.Clear();
                }
                if (names.Count == 0)
                {
                    continue;
                }
                ObservableCollection<DBStruct> ocItems = new ObservableCollection<DBStruct>();
                names.ForEach(name => ocItems.Add(new DBStruct
                {
                    Type = level.NodeType,
                    Parent = parent!,
                    IsExpanded = parent != null,
                    Value = name
                }));
                UiNotifier.Post( ()=>
                {
                    if (parent == null)
                    {
                        config.DataDump.DBStructItems = ocItems;
                    }
                    else
                    {
                        container.AddRange(ocItems);
                    }
                });
            }
        }

        /// <summary>报错通道：count→并行逐值（WorkRunner）→回填</summary>
        private static async Task EnumerateByError(AppConfig config, EnumLevel level)
        {
            foreach (DBStruct? parent in EnumerateParents(config, level.NodeType))
            {
                config.CheckStop();
                if (level.SupportsDictGuess && config.DataConfig.DictGuessAll)
                {
                    await GuessAccessDictByBool(config, parent!, level.DictGuessIsTable).ConfigureAwait(false);
                    continue;
                }
                ObservableCollection<DBStruct> container = parent == null ? config.DataDump.DBStructItems : parent.SubItems;
                if (parent != null)
                {
                    container.Clear();
                }
                string countStr = await DataComm.DataDumpWithError(config, level.CountPayload(parent)).ConfigureAwait(false);
                int.TryParse(countStr, out int count);
                List<(DBStruct node, string payload)> tasks = new List<(DBStruct, string)>();
                for (int i = 0; i < count; i++)
                {
                    config.CheckStop();
                    DBStruct node = new DBStruct
                    {
                        Type = level.NodeType,
                        Parent = parent!,
                        IsExpanded = parent != null
                    };
                    tasks.Add((node, level.NamePayloadAt(parent, i)));
                }
                WorkRunner.FireAndForgetAsync(tasks, config, async t => await GetOneDataError(config, container, t.node, t.payload));
            }
        }

        // ================== 公开入口（9个薄包装） ==================

        public static async Task GetDBSByBool(AppConfig config)
        {
            if (config.DataConfig.SelectedDBType.Equals(DBType.Access))
            {
                //Access无库概念：直接给出固定库节点，表/字段走字典猜解
                config.DataDump.DBStructItems.Clear();
                DBStruct accessDb = new DBStruct { Type = DBStructType.DBName, Value = "Access", IsExpanded = true };
                UiNotifier.Post( ()=> config.DataDump.DBStructItems.Add(accessDb));
                return;
            }
            await EnumerateByBool(config, DbLevel).ConfigureAwait(false);
        }

        public static async Task GetTablesByBool(AppConfig config)
        {
            await EnumerateByBool(config, TableLevel).ConfigureAwait(false);
        }

        public static async Task GetColumnsByBool(AppConfig config)
        {
            await EnumerateByBool(config, ColumnLevel).ConfigureAwait(false);
        }

        public static async Task GetDBSByUnion(AppConfig config)
        {
            if (config.DataConfig.SelectedDBType.Equals(DBType.Access))
            {
                config.DataDump.DBStructItems.Add(new DBStruct
                {
                    Type = DBStructType.DBName,
                    Value = "Access"
                });
                return;
            }
            await EnumerateByUnion(config, DbLevel).ConfigureAwait(false);
        }

        public static async Task GetTablesByUnion(AppConfig config)
        {
            if (config.DataConfig.SelectedDBType.Equals(DBType.Access))
            {
                Log.Warning("Access无法读取系统表元数据，获取表仅支持盲注通道（字典猜解）！请将注入类型切换为盲注。");
                return;
            }
            await EnumerateByUnion(config, TableLevel).ConfigureAwait(false);
        }

        public static async Task GetColumnsByUnion(AppConfig config)
        {
            if (config.DataConfig.SelectedDBType.Equals(DBType.Access))
            {
                Log.Warning("Access无列元数据视图，获取字段仅支持盲注通道（字典猜解）！请将注入类型切换为盲注。");
                return;
            }
            await EnumerateByUnion(config, ColumnLevel).ConfigureAwait(false);
        }

        public static async Task GetDBSByError(AppConfig config)
        {
            if (config.DataConfig.SelectedDBType.Equals(DBType.Access))
            {
                config.DataDump.DBStructItems.Clear();
                DBStruct accessDb = new DBStruct { Type = DBStructType.DBName, Value = "Access", IsExpanded = true };
                UiNotifier.Post( ()=> config.DataDump.DBStructItems.Add(accessDb));
                return;
            }
            await EnumerateByError(config, DbLevel).ConfigureAwait(false);
        }

        public static async Task GetTablesByError(AppConfig config)
        {
            if (config.DataConfig.SelectedDBType.Equals(DBType.Access))
            {
                Log.Warning("Access无法读取系统表元数据，获取表仅支持盲注通道（字典猜解）！请将注入类型切换为盲注。");
                return;
            }
            await EnumerateByError(config, TableLevel).ConfigureAwait(false);
        }

        public static async Task GetColumnsByError(AppConfig config)
        {
            if (config.DataConfig.SelectedDBType.Equals(DBType.Access))
            {
                Log.Warning("Access无列元数据视图，获取字段仅支持盲注通道（字典猜解）！请将注入类型切换为盲注。");
                return;
            }
            await EnumerateByError(config, ColumnLevel).ConfigureAwait(false);
        }

        // ================== 字典猜解 ==================

        /// <summary>
        /// 加载字典文件：customPath非空且文件存在时用外部txt（每行一词），否则用内置config/dict/下文件；去空白/注释/重复
        /// </summary>
        private static List<string> LoadDict(string fileName, string? customPath)
        {
            try
            {
                List<string> lines;
                if (!string.IsNullOrWhiteSpace(customPath) && System.IO.File.Exists(customPath))
                {
                    lines = System.IO.File.ReadAllLines(customPath, System.Text.Encoding.UTF8).ToList();
                }
                else
                {
                    lines = FileTool.readFileToList("/config/dict/" + fileName);
                }
                return lines
                    .Select(w => w.Trim())
                    .Where(w => w.Length > 0 && !w.StartsWith('#'))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }
            catch
            {
                return new List<string>();
            }
        }

        /// <summary>
        /// 字典猜解（common-tables/common-columns 能力）：
        /// Access无元数据可读默认走此链路；其他库在取数页开启"字典猜解"后也走此链路
        /// （场景：information_schema不可用的低权限点）。
        /// 用字典逐项构造 exists 子查询做布尔存在性判断，命中项挂为树节点。
        /// isTable=true猜表名（节点挂在库下），false猜字段名（节点挂在表下）。
        /// 字典文件：Access用config/dict/access_tables.txt、access_columns.txt；
        /// 其他库用config/dict/common_tables.txt、common_columns.txt，均可自定义外部txt覆盖
        /// </summary>
        private static async Task GuessAccessDictByBool(AppConfig config, DBStruct parent, bool isTable)
        {
            bool isAccess = config.DataConfig.SelectedDBType.Equals(DBType.Access);
            string dictFile = isAccess
                ? (isTable ? "access_tables.txt" : "access_columns.txt")
                : (isTable ? "common_tables.txt" : "common_columns.txt");
            string? customPath = isTable ? config.DataConfig.AccessTableDictPath : config.DataConfig.AccessColumnDictPath;
            bool useCustom = !string.IsNullOrWhiteSpace(customPath) && System.IO.File.Exists(customPath);
            List<string> words = LoadDict(dictFile, customPath);
            string dictDesc = useCustom ? customPath! : "内置config/dict/" + dictFile;
            if (words.Count == 0)
            {
                Log.Warning($"Access{(isTable ? "表名" : "字段")}字典为空或读取失败：{dictDesc}");
                return;
            }
            string template = PayloadFactory.BasePayload.Get(isTable ? "exists_table" : "exists_column");
            string targetDesc = isTable ? "" : $"（表 {parent.Value}）";
            string dbDesc = isAccess ? "Access无元数据可读" : "字典猜解模式（低权限点/元数据不可用场景）";
            Log.Show($"{dbDesc}，启用{(isTable ? "表名" : "字段")}字典猜解{targetDesc}：字典 {words.Count} 项（{dictDesc}）……");

            parent.SubItems.Clear();
            var hits = new System.Collections.Concurrent.ConcurrentBag<string>();
            await WorkRunner.RunAsync(words, config, async w =>
            {
                config.CheckStop();
                string condition = isTable
                    ? TemplateRenderer.Render(template, ("table", w))
                    : TemplateRenderer.Render(template, ("cols", w), ("table", parent.Value));
                bool exists = await DataComm.CheckCondition(config, condition).ConfigureAwait(false);
                if (exists)
                {
                    hits.Add(w);
                    //命中即通知挂节点（实时反馈猜解进度）
                    UiNotifier.Post( ()=> parent.SubItems.Add(new DBStruct
                    {
                        Type = isTable ? DBStructType.TableName : DBStructType.ColumnName,
                        Parent = parent,
                        Value = w,
                        IsExpanded = true
                    }));
                }
            }).ConfigureAwait(false);
            if (hits.Count > 0)
            {
                Log.Success($"字典猜解完成{targetDesc}：命中 {hits.Count} 个（{string.Join(",", hits)}）");
            }
            else
            {
                Log.Warning($"字典猜解完成{targetDesc}：未命中，可扩充字典后在网络设置中更换字典文件重试（当前：{dictDesc}）");
            }
        }

        // ================== Union 聚合取名称 ==================

        /// <summary>
        /// Union通道取名称列表（库/表/列通用）：先试单发group_concat聚合（一次请求拿回全部），
        /// 结果为空时回退count+逐行LIMIT取值。应对目标显示列长度受限截断聚合串丢失结束标记
        /// （如varchar(360)列、group_concat_max_len过小）的场景，union逐行（LIMIT n,1）取值策略
        /// </summary>
        private static async Task<List<string>> GetUnionNames(AppConfig config, string namesPayload, string countPayload, Func<int, string> namePayloadAt)
        {
            string data = await DataComm.DataDumpWithNoFrom(config, namesPayload).ConfigureAwait(false);
            List<string> items = data.Split(',', StringSplitOptions.RemoveEmptyEntries).ToList();
            if (items.Count > 0)
            {
                return items;
            }
            //单发为空：聚合结果可能被截断丢失结束标记，回退count+逐行取值（单行数值/短名不会被截断）
            string countStr = await DataComm.DataDumpWithNoFrom(config, countPayload).ConfigureAwait(false);
            if (!int.TryParse(countStr, out int count) || count <= 0)
            {
                return items;
            }
            Log.Warning("Union聚合结果未取到（目标显示列长度受限截断），已回退逐行取值模式，共 " + count + " 条");
            List<string> names = new List<string>(count);
            for (int i = 0; i < count; i++)
            {
                config.CheckStop();
                string name = await DataComm.DataDumpWithNoFrom(config, namePayloadAt(i)).ConfigureAwait(false);
                if (string.IsNullOrEmpty(name))
                {
                    break;
                }
                names.Add(name);
            }
            return names;
        }

        public static async Task GetOneDataError(AppConfig config, ObservableCollection<DBStruct> items, DBStruct db, string paylaod)
        {
            string dbName = await DataComm.DataDumpWithError(config, paylaod).ConfigureAwait(false);

            Dispatcher.UIThread.Post( ()=>
            {
                db.Value = dbName;
                items.Add(db);
            });
        }
    }
}
