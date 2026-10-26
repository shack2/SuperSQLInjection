using Avalonia.Collections;
using Avalonia.Controls;
using Avalonia.Data;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CommunityToolkit.Mvvm.Messaging;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Models.Data;
using SuperSQLInjectionV2.Msg;
using SuperSQLInjectionV2.Tools;
using SuperSQLInjectionV2.ViewModels;
using SuperSQLInjectionV2.ViewModels.Tools;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Ursa.Controls;

namespace SuperSQLInjectionV2.ViewModels
{
    public partial class DataDumpViewModel : ViewModelBase, IRecipient<AddColumnMsg>, IRecipient<AddRowDataMsg>, IRecipient<AddStatusInfoMsg>
    {
        private static readonly char[] s_cellSplitChars = { '\t', '\r', '\n' };


        [ObservableProperty] private ObservableCollection<DBStruct> _dBStructItems = new ObservableCollection<DBStruct>();

        [ObservableProperty] private int _dataCount = 0;

        [ObservableProperty] private int _dumpCount = 0;

        [ObservableProperty] private int __dataDumpStart = 0;

        [ObservableProperty] private int __tablesCount = 0;



        [ObservableProperty] private int __columnsCount = 0;


        private string DBName = "";

        [ObservableProperty] private string _tableName = "";

       
        /// <summary>
        /// 情况上一次获取数据
        /// </summary>
        [ObservableProperty]
        private bool _clearLastData = true;

        private int _columnCounter = 0;

        public DataDumpViewModel()
        {
            WeakReferenceMessenger.Default.Register<AddColumnMsg>(this);
            WeakReferenceMessenger.Default.Register<AddRowDataMsg>(this);
            WeakReferenceMessenger.Default.Register<AddStatusInfoMsg>(this);
        }

        /// <summary>
        /// 添加列
        /// </summary>
        private void AddColumn(ColumnInfo column)
        {
            _columnCounter++;
            if (Columns.Where(x => x.Header.Equals(column.Header, StringComparison.Ordinal)).Count ()> 0)
            {

                // 如果已有数据行，更新所有行的该列
                foreach (var row in Rows)
                {
                    row[_columnCounter.ToString()] = string.Empty;
                }
            }
            else {
                Columns.Add(column);

            }

        }

        /// <summary>
        /// 删除列
        /// </summary>
        private void RemoveColumn(ColumnInfo? column)
        {
            if (column != null)
            {
                List<ColumnInfo> list= Columns.Where(x => x.Header.Equals(column.Header, StringComparison.Ordinal)).ToList();
                if (list.Count > 0)
                {
                    // 从列集合中删除
                    Columns.Remove(list[0]);

                    // 从所有行中删除对应的数据
                    foreach (var row in Rows)
                    {
                        row.Remove(column.PropertyName);
                    }
                }

            }
        }

        /// <summary>
        /// 添加带有数据的行
        /// </summary>
        private void AddRowWithData(DynamicDataItem data)
        {
            Rows.Add(data);
        }

        // 接收通用数据变化消息
        public void Receive(AddColumnMsg message)
        {
            if (!TableName.EndsWith(message.TableName, StringComparison.Ordinal)) { 
                Columns=new();
            }
            TableName = message.TableName;
            DBName = message.DBName;
            ColumnInfo c = new ColumnInfo
            {
                Header = message.ColumnName,
                PropertyName = message.ColumnName,
                Width = 1.0,
                IsReadOnly = true
            };

            if (message.isAdd)
            {
                AddColumn(c);
            }
            else {
                RemoveColumn(c);
            }

        }

        public void Receive(AddRowDataMsg msg)
        {
            Dispatcher.UIThread.Post( ()=>
            {
                 AddRowWithData(msg.Data);
            });

        }

        public void Receive(AddStatusInfoMsg msg)
        {
            int sumTables = 0;
            int columnTables = 0;
            IEnumerator<DBStruct> db= DBStructItems.GetEnumerator();
            while (db.MoveNext()) {
                sumTables += db.Current.SubItems.Count;
                IEnumerator<DBStruct> table = db.Current.SubItems.GetEnumerator();
                while (table.MoveNext())
                {
                    columnTables += table.Current.SubItems.Count;
                }
            }

            TablesCount = sumTables;
            ColumnsCount = columnTables;
        }
        public AppConfig AppConfig { get; set; } = null!;

        /// <summary>自定义SQL（sql-query 能力）：按当前注入通道执行并回显标量结果</summary>
        [ObservableProperty] private string _customSql = "";

        /// <summary>自定义SQL执行结果</summary>
        [ObservableProperty] private string _customSqlResult = "";

        /// <summary>dump行数据自定义WHERE过滤（无需where关键字；同步作用于总数统计与行数据取数SQL）</summary>
        [ObservableProperty] private string _dumpWhere = "";

        /// <summary>可选稳定分页键：须为已选择的唯一列；支持模板时首行后自动改Keyset，避免动态表OFFSET重复/漏行。</summary>
        [ObservableProperty] private string _stablePagingKey = "";

        /// <summary>dump取数no-cast开关（取数列不做cast/convert类型转换包装）</summary>
        [ObservableProperty] private bool _dumpNoCast = false;

        /// <summary>
        /// 执行自定义SQL：SQL需返回单行单列（多行自行LIMIT，多列自行concat拼接），
        /// 通道选择由RunUserSql按当前注入类型处理（Union/Error/Blind/Stacked）
        /// </summary>
        [RelayCommand]
        private async Task ExecCustomSql()
        {
            if (string.IsNullOrWhiteSpace(CustomSql))
            {
                Log.Warning("大侠，请先输入要执行的SQL！");
                return;
            }
            if (AppConfig.DataConfig.SelectedDBType == DBType.UnKnow || AppConfig.DataConfig.SelectedInjectType == InjectType.UnKnow)
            {
                Log.Warning("请先建立注入上下文（选择注入记录或手工指定注入类型/数据库类型）！");
                return;
            }
            AppConfig.ResetStop();
            if (!MainViewViewModel.EnsureDataOpReady(AppConfig))
            {
                return;
            }
            AppConfig.IsRuning = true;
            try
            {
                Log.Show("执行自定义SQL：" + CustomSql);
                string result = await DataComm.RunUserSql(AppConfig, CustomSql).ConfigureAwait(false);
                if (LogTools.Headless || Avalonia.Application.Current == null || Dispatcher.UIThread.CheckAccess())
                {
                    CustomSqlResult = result;
                }
                else
                {
                    string r = result;
                    Dispatcher.UIThread.Post( ()=> CustomSqlResult = r);
                }
                if (string.IsNullOrEmpty(result))
                {
                    Log.Show("执行完成，无回显数据（若为写操作请人工确认执行效果）。");
                }
                else
                {
                    Log.Success("自定义SQL执行完成，结果长度：" + result.Length);
                }
            }
            catch (Exception e)
            {
                Log.Error("自定义SQL执行异常：" + e.Message);
            }
            finally
            {
                AppConfig.IsRuning = false;
            }
        }


        /// <summary>
        /// 列配置集合
        /// </summary>
        [ObservableProperty]
        private ObservableCollection<ColumnInfo> _columns = new ObservableCollection<ColumnInfo>();


        /// <summary>
        /// 数据行集合
        /// </summary>
        [ObservableProperty]
        private ObservableCollection<DynamicDataItem> _rows = new ObservableCollection<DynamicDataItem>();



        /// <summary>
        /// 保存文件对话框回调（由View注入）
        /// </summary>
        public Func<Task<string?>>? SaveFilePicker { get; set; }

        /// <summary>CSV统一转义，默认防止外部数据触发Excel公式。</summary>
        private string EscapeCsv(string? value) => CsvExport.Cell(value, !AppConfig.RawCsvExport);

        /// <summary>
        /// 导出数据到CSV文件
        /// </summary>
        [RelayCommand]
        private async Task ExportData()
        {
            if (Rows.Count == 0)
            {
                Log.Warning("没有数据可导出！");
                return;
            }
            if (SaveFilePicker == null)
            {
                Log.Warning("文件保存对话框未初始化！");
                return;
            }
            string? path = await SaveFilePicker.Invoke();
            if (string.IsNullOrEmpty(path))
            {
                return;
            }
            try
            {
                var csv = new StringBuilder();
                csv.AppendLine(string.Join(",", Columns.Select(c => EscapeCsv(c.Header))));
                foreach (var row in Rows)
                {
                    csv.AppendLine(string.Join(",", Columns.Select(c => EscapeCsv(row[c.PropertyName]))));
                }
                await File.WriteAllTextAsync(path, csv.ToString(), new UTF8Encoding(true));
                Log.Show("导出数据完成！" + path);
            }
            catch (Exception ex)
            {
                Log.Show("导出数据异常！" + ex.Message);
            }
        }

        /// <summary>
        /// 打开文件对话框回调（由View注入）
        /// </summary>
        public Func<Task<string?>>? OpenFilePicker { get; set; }

        /// <summary>
        /// 添加数据库节点
        /// </summary>
        [RelayCommand]
        private void AddDBStructNode()
        {
            DBStructItems.Add(new DBStruct { Type = DBStructType.DBName, Value = "NewDataBase", IsEdit = true });
        }

        /// <summary>
        /// 清空所有库表列结构
        /// </summary>
        [RelayCommand]
        private void ClearDBStruct()
        {
            DBStructItems.Clear();
            Log.Show("已清空所有库表列结构！");
        }

        /// <summary>
        /// 递归设置子节点选中状态
        /// </summary>
        public static void SetSubNodesSelected(DBStruct node, bool selected)
        {
            foreach (var sub in node.SubItems)
            {
                sub.IsSelected = selected;
                SetSubNodesSelected(sub, selected);
            }
        }

        /// <summary>
        /// 递归反选子节点
        /// </summary>
        public static void ReverseSubNodesSelected(DBStruct node)
        {
            foreach (var sub in node.SubItems)
            {
                sub.IsSelected = !sub.IsSelected;
                ReverseSubNodesSelected(sub);
            }
        }

        /// <summary>
        /// 库表列结构序列化DTO（避免Parent循环引用）
        /// </summary>
        public class DBStructNodeDto
        {
            public string Type { get; set; } = "";
            public string Value { get; set; } = "";
            public bool IsSelected { get; set; }
            public List<DBStructNodeDto> SubItems { get; set; } = new List<DBStructNodeDto>();
        }

        private static DBStructNodeDto ToDto(DBStruct node)
        {
            return new DBStructNodeDto
            {
                Type = node.Type.ToString(),
                Value = node.Value,
                IsSelected = node.IsSelected,
                SubItems = node.SubItems.Select(ToDto).ToList()
            };
        }

        private static DBStruct FromDto(DBStructNodeDto dto, DBStruct? parent)
        {
            DBStruct node = new DBStruct
            {
                Type = Enum.TryParse(dto.Type, out DBStructType t) ? t : DBStructType.DBName,
                Value = dto.Value,
                Parent = parent,
                IsExpanded = true
            };
            foreach (var sub in dto.SubItems)
            {
                node.SubItems.Add(FromDto(sub, node));
            }
            //最后设置选中状态，避免级联选择干扰父子关系
            node.IsSelected = dto.IsSelected;
            return node;
        }

        /// <summary>
        /// 保存库表列结构到JSON文件
        /// </summary>
        [RelayCommand]
        private async Task SaveDBStruct()
        {
            if (DBStructItems.Count == 0)
            {
                Log.Warning("没有库表列结构可保存！");
                return;
            }
            if (SaveFilePicker == null)
            {
                Log.Warning("文件保存对话框未初始化！");
                return;
            }
            string? path = await SaveFilePicker.Invoke();
            if (string.IsNullOrEmpty(path))
            {
                return;
            }
            try
            {
                List<DBStructNodeDto> dtos = DBStructItems.Select(ToDto).ToList();
                string json = System.Text.Json.JsonSerializer.Serialize(dtos, Source.JsonCtx.IndentedInfo<List<DBStructNodeDto>>());
                await File.WriteAllTextAsync(path, json, new UTF8Encoding(true));
                Log.Show("保存库表列结构完成！" + path);
            }
            catch (Exception ex)
            {
                Log.Show("保存库表列结构异常！" + ex.Message);
            }
        }

        /// <summary>
        /// 从JSON文件加载库表列结构
        /// </summary>
        [RelayCommand]
        private async Task LoadDBStruct()
        {
            if (OpenFilePicker == null)
            {
                Log.Warning("文件打开对话框未初始化！");
                return;
            }
            string? path = await OpenFilePicker.Invoke();
            if (string.IsNullOrEmpty(path))
            {
                return;
            }
            try
            {
                string json = await File.ReadAllTextAsync(path);
                List<DBStructNodeDto>? dtos = System.Text.Json.JsonSerializer.Deserialize(json, Source.JsonCtx.IndentedInfo<List<DBStructNodeDto>>());
                if (dtos == null)
                {
                    Log.Warning("库表列结构文件格式错误！");
                    return;
                }
                DBStructItems.Clear();
                foreach (var dto in dtos)
                {
                    DBStructItems.Add(FromDto(dto, null));
                }
                Log.Show("加载库表列结构完成！");
            }
            catch (Exception ex)
            {
                Log.Show("加载库表列结构异常！" + ex.Message);
            }
        }





        // ================== 库表列树搜索（对标 --search） ==================

        /// <summary>搜索类型：0=库 1=表 2=列</summary>
        [ObservableProperty] private int _searchTypeIndex = 0;

        /// <summary>搜索关键词</summary>
        [ObservableProperty] private string _searchKeyword = "";

        /// <summary>搜索结果提示</summary>
        [ObservableProperty] private string _searchResultInfo = "";

        private static IEnumerable<DBStruct> WalkTree(IEnumerable<DBStruct> items)
        {
            foreach (var item in items)
            {
                yield return item;
                foreach (var sub in WalkTree(item.SubItems))
                {
                    yield return sub;
                }
            }
        }

        private void ClearSearchHits()
        {
            foreach (var node in WalkTree(DBStructItems))
            {
                if (node.IsSearchHit)
                {
                    node.IsSearchHit = false;
                }
            }
        }

        private string SearchTypeName => SearchTypeIndex switch { 1 => "表", 2 => "列", _ => "库" };

        /// <summary>本地搜索：遍历已加载的树节点，命中节点标红并展开父级，提示命中数量</summary>
        [RelayCommand]
        private void LocalSearch()
        {
            string kw = (SearchKeyword ?? "").Trim();
            ClearSearchHits();
            if (kw.Length == 0)
            {
                SearchResultInfo = "";
                return;
            }
            DBStructType type = SearchTypeIndex switch
            {
                1 => DBStructType.TableName,
                2 => DBStructType.ColumnName,
                _ => DBStructType.DBName,
            };
            int hits = 0;
            foreach (var node in WalkTree(DBStructItems))
            {
                if (node.Type == type && node.Value.Contains(kw, StringComparison.OrdinalIgnoreCase))
                {
                    node.IsSearchHit = true;
                    hits++;
                    //展开父链便于定位命中节点
                    DBStruct? p = node.Parent;
                    while (p != null)
                    {
                        p.IsExpanded = true;
                        p = p.Parent;
                    }
                }
            }
            SearchResultInfo = $"本地搜索{SearchTypeName}命中 {hits} 个";
            Log.Show(SearchResultInfo + (hits == 0 ? "（树中未加载的节点不参与本地搜索，可尝试服务端搜索）" : "，命中节点已标红"));
        }

        /// <summary>清空搜索高亮</summary>
        [RelayCommand]
        private void ClearSearch()
        {
            ClearSearchHits();
            SearchResultInfo = "";
        }

        /// <summary>
        /// 构造服务端搜索SQL：返回单行单列标量，多个命中用TAB(\t)分隔。
        /// 搜表返回"库.表"，搜列返回"库.表.列"，便于自动补齐上级节点。
        /// 不支持的库返回null。
        /// </summary>
        private static string? BuildSearchSql(DBType dbType, int kind, string kw)
        {
            bool upper = dbType == DBType.Oracle || dbType == DBType.DM;
            //关键词净化：剔除括号（用户常从环境变量/函数名复制 user()、version() 这类串搜索同名库表列，
            //括号在标识符中几乎不出现，保留只会让LIKE永不命中）；单引号转义防注入语法错误
            string cleaned = kw.Replace("(", "", StringComparison.Ordinal).Replace(")", "", StringComparison.Ordinal);
            string like = "%" + (upper ? cleaned.ToUpperInvariant() : cleaned).Replace("'", "''", StringComparison.Ordinal) + "%";
            switch (dbType)
            {
                case DBType.MySQL:
                    return kind switch
                    {
                        0 => $"select group_concat(schema_name separator 0x09) from information_schema.schemata where schema_name like '{like}'",
                        1 => $"select group_concat(concat(table_schema,'.',table_name) separator 0x09) from information_schema.tables where table_name like '{like}'",
                        _ => $"select group_concat(concat(table_schema,'.',table_name,'.',column_name) separator 0x09) from information_schema.columns where column_name like '{like}'",
                    };
                case DBType.PostgreSQL:
                case DBType.OpenGauss:
                case DBType.Kingbase:
                    return kind switch
                    {
                        0 => $"select string_agg(datname, chr(9)) from pg_database where datname like '{like}'",
                        1 => $"select string_agg(table_schema||'.'||table_name, chr(9)) from information_schema.tables where table_name like '{like}'",
                        _ => $"select string_agg(table_schema||'.'||table_name||'.'||column_name, chr(9)) from information_schema.columns where column_name like '{like}'",
                    };
                case DBType.SQLServer:
                    return kind switch
                    {
                        0 => $"select stuff((select char(9)+name from master..sysdatabases where name like '{like}' for xml path('')),1,1,'')",
                        1 => $"select stuff((select char(9)+table_schema+'.'+table_name from information_schema.tables where table_name like '{like}' for xml path('')),1,1,'')",
                        _ => $"select stuff((select char(9)+table_schema+'.'+table_name+'.'+column_name from information_schema.columns where column_name like '{like}' for xml path('')),1,1,'')",
                    };
                case DBType.Oracle:
                case DBType.DM:
                    return kind switch
                    {
                        0 => $"select listagg(username, chr(9)) within group (order by username) from all_users where username like '{like}'",
                        1 => $"select listagg(owner||'.'||table_name, chr(9)) within group (order by owner) from all_tables where table_name like '{like}'",
                        _ => $"select listagg(owner||'.'||table_name||'.'||column_name, chr(9)) within group (order by owner) from all_tab_columns where column_name like '{like}'",
                    };
                case DBType.SQLite:
                    if (kind == 0)
                    {
                        return null; //SQLite无库概念
                    }
                    return kind == 1
                        ? $"select group_concat(name, char(9)) from sqlite_master where type='table' and name like '{like}'"
                        : $"select group_concat(m.name||'.'||p.name, char(9)) from sqlite_master m join pragma_table_info(m.name) p where m.type='table' and p.name like '{like}'";
                case DBType.ClickHouse:
                    return kind switch
                    {
                        0 => $"select arrayStringConcat(groupArray(name), '\\t') from system.databases where name like '{like}'",
                        1 => $"select arrayStringConcat(groupArray(database || '.' || name), '\\t') from system.tables where name like '{like}'",
                        _ => $"select arrayStringConcat(groupArray(database || '.' || table || '.' || name), '\\t') from system.columns where name like '{like}'",
                    };
                case DBType.H2:
                    return kind switch
                    {
                        0 => $"select group_concat(schema_name separator char(9)) from information_schema.schemata where schema_name like '{like}'",
                        1 => $"select group_concat(table_schema||'.'||table_name separator char(9)) from information_schema.tables where table_name like '{like}'",
                        _ => $"select group_concat(table_schema||'.'||table_name||'.'||column_name separator char(9)) from information_schema.columns where column_name like '{like}'",
                    };
                default:
                    return null;
            }
        }

        /// <summary>查找或新增树节点（按类型+值不区分大小写匹配）</summary>
        private static DBStruct FindOrAddNode(ObservableCollection<DBStruct> items, DBStructType type, string value, DBStruct? parent)
        {
            DBStruct? node = items.FirstOrDefault(x => x.Type == type && x.Value.Equals(value, StringComparison.OrdinalIgnoreCase));
            if (node == null)
            {
                node = new DBStruct { Type = type, Value = value, Parent = parent, IsExpanded = true };
                items.Add(node);
            }
            node.IsExpanded = true;
            return node;
        }

        /// <summary>服务端搜索：按当前注入通道执行LIKE过滤SQL，命中结果自动挂到树（自动补齐上级库/表节点）并标红</summary>
        [RelayCommand]
        private async Task ServerSearch()
        {
            string kw = (SearchKeyword ?? "").Trim();
            if (kw.Length == 0)
            {
                Log.Warning("大侠，请先输入搜索关键词！");
                return;
            }
            DBType dbType = AppConfig.DataConfig.SelectedDBType;
            if (dbType == DBType.UnKnow || AppConfig.DataConfig.SelectedInjectType == InjectType.UnKnow)
            {
                Log.Warning("请先建立注入上下文（选择注入记录或手工指定注入类型/数据库类型）！");
                return;
            }
            if (dbType == DBType.Access)
            {
                Log.Warning("Access无元数据视图，服务端搜索不可用，请用本地搜索或字典猜解！");
                return;
            }
            string? sql = BuildSearchSql(dbType, SearchTypeIndex, kw);
            if (sql == null)
            {
                Log.Warning($"当前数据库（{dbType}）暂不支持该类型服务端搜索，请用本地搜索或全量枚举！");
                return;
            }
            AppConfig.ResetStop();
            if (!MainViewViewModel.EnsureDataOpReady(AppConfig))
            {
                return;
            }
            AppConfig.IsRuning = true;
            try
            {
                string typeName = SearchTypeName;
                Log.Show($"服务端搜索{typeName}：{kw} ……");
                string result = await DataComm.RunUserSql(AppConfig, sql).ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(result))
                {
                    Dispatcher.UIThread.Post( ()=> SearchResultInfo = $"服务端搜索{typeName}命中 0 个");
                    Log.Show("服务端搜索无命中结果。");
                    return;
                }
                //统一分隔符：TAB为主；个别通道聚合符失效时兼容逗号
                string[] entries = result.Split(s_cellSplitChars, StringSplitOptions.RemoveEmptyEntries)
                    .SelectMany(e => e.Contains('\t', StringComparison.Ordinal) || result.Contains('\t', StringComparison.Ordinal) ? new[] { e } : e.Split(',', StringSplitOptions.RemoveEmptyEntries))
                    .Select(e => e.Trim())
                    .Where(e => e.Length > 0)
                    .ToArray();
                int kind = SearchTypeIndex;
                int hits = 0;
                Dispatcher.UIThread.Post( ()=>
                {
                    ClearSearchHits();
                    foreach (string entry in entries)
                    {
                        string[] parts = entry.Split('.');
                        if (kind == 0)
                        {
                            FindOrAddNode(DBStructItems, DBStructType.DBName, entry, null).IsSearchHit = true;
                            hits++;
                            continue;
                        }
                        //搜表：db.table；搜列：db.table.column（SQLite缺省db段）
                        string dbName;
                        string tableName;
                        string? columnName = null;
                        if (kind == 1)
                        {
                            dbName = parts.Length >= 2 ? parts[parts.Length - 2] : (DBStructItems.Count == 1 ? DBStructItems[0].Value : "main");
                            tableName = parts[parts.Length - 1];
                        }
                        else
                        {
                            dbName = parts.Length >= 3 ? parts[parts.Length - 3] : (DBStructItems.Count == 1 ? DBStructItems[0].Value : "main");
                            tableName = parts.Length >= 2 ? parts[parts.Length - 2] : "";
                            columnName = parts[parts.Length - 1];
                            if (tableName.Length == 0)
                            {
                                continue;
                            }
                        }
                        DBStruct dbNode = FindOrAddNode(DBStructItems, DBStructType.DBName, dbName, null);
                        DBStruct tableNode = FindOrAddNode(dbNode.SubItems, DBStructType.TableName, tableName, dbNode);
                        if (kind == 1)
                        {
                            tableNode.IsSearchHit = true;
                            hits++;
                        }
                        else
                        {
                            FindOrAddNode(tableNode.SubItems, DBStructType.ColumnName, columnName!, tableNode).IsSearchHit = true;
                            hits++;
                        }
                    }
                    SearchResultInfo = $"服务端搜索{SearchTypeName}命中 {hits} 个";
                });
                Log.Success($"服务端搜索完成：命中 {hits} 个，结果已挂到库表列树并标红（未命中的上级节点已自动补齐）。");
            }
            catch (OperationCanceledException)
            {
                Log.Show("已停止服务端搜索！");
            }
            catch (Exception e)
            {
                Log.Error("服务端搜索异常：" + e.Message);
            }
            finally
            {
                AppConfig.IsRuning = false;
            }
        }


        [RelayCommand]
        private void StartGetDataBase()
        {
            AppConfig.ResetStop();
            if (!MainViewViewModel.EnsureDataOpReady(AppConfig))
            {
                return;
            }
            if (AppConfig.DataConfig.SelectedDBType.Equals(DBType.UnKnow))
            {
                Log.Warning("未识别数据库类型，无法确定取数模板！请执行注入检测自动识别，或在数据操作页手动选择数据库类型。");
                return;
            }
            if (AppConfig.DataConfig.SelectedDBType.Equals(DBType.Access))
            {
                DBStruct dbs = new DBStruct();
                dbs.Type = DBStructType.DBName;
                dbs.Value = DBType.Access.ToString();
                return;
            }
            Task RunTask = GetDataBase();
            AppConfig.IsRuning = true;
            WorkRunner.OnCompletedSurfaced(RunTask, (Action)( ()=>
            {
                AppConfig.IsRuning = false;
                Log.Success("获取数据库完成！");
            }));
        }


        [RelayCommand]
        private void StartGetDataTables()
        {
            AppConfig.ResetStop();
            if (!MainViewViewModel.EnsureDataOpReady(AppConfig))
            {
                return;
            }
            if (AppConfig.DataConfig.SelectedDBType.Equals(DBType.UnKnow))
            {
                Log.Warning("未识别数据库类型，无法确定取数模板！请执行注入检测自动识别，或在数据操作页手动选择数据库类型。");
                return;
            }
            int dbSelect = DBStructItems.Where(x => x.IsSelected && x.Type.Equals(DBStructType.DBName)).Count();
            if (dbSelect<1) {
                return;
            }
            Task RunTask = GetTables();
            AppConfig.IsRuning = true;
            WorkRunner.OnCompletedSurfaced(RunTask, (Action)( ()=>
            {
                AppConfig.IsRuning = false;
                Log.Success("获取表完成！");
            }));
        }




        [RelayCommand]
        private void StartGetDataColumns()
        {
            AppConfig.ResetStop();
            if (!MainViewViewModel.EnsureDataOpReady(AppConfig))
            {
                return;
            }
            if (AppConfig.DataConfig.SelectedDBType.Equals(DBType.UnKnow))
            {
                Log.Warning("未识别数据库类型，无法确定取数模板！请执行注入检测自动识别，或在数据操作页手动选择数据库类型。");
                return;
            }
            int dbSelect = DBStructItems.Where(d => d.IsSelected && d.SubItems.Where(t => t.IsSelected).Count()>0).Count();
            if (dbSelect < 1)
            {
                return;
            }
            Task RunTask = GetColumns();
            AppConfig.IsRuning = true;
            WorkRunner.OnCompletedSurfaced(RunTask, (Action)( ()=>
            {
                AppConfig.IsRuning = false;
                Log.Success("获取列完成！");
            }));
        }


        [RelayCommand]
        private void StartGetData()
        {
            AppConfig.ResetStop();
            if (!MainViewViewModel.EnsureDataOpReady(AppConfig))
            {
                return;
            }
            if (AppConfig.DataConfig.SelectedDBType.Equals(DBType.UnKnow))
            {
                Log.Warning("未识别数据库类型，无法确定取数模板！请执行注入检测自动识别，或在数据操作页手动选择数据库类型。");
                return;
            }
            if (AppConfig.DataDump.DumpCount <= 0)
            {
                Log.Show("请设置获取条数！");
                return;

            }

            Task RunTask = GetData();
            AppConfig.IsRuning = true;
            WorkRunner.OnCompletedSurfaced(RunTask, (Action)( ()=>
            {
                AppConfig.IsRuning = false;
                Log.Success("获取数据完成！");
            }));
        }


        private async Task GetData()
        {
            try
            {

            int count = AppConfig.DataDump.DumpCount;
            int start = AppConfig.DataDump.DataDumpStart;
            if (count <= 0 || start < 0 || start + count <= 0)
            {
                Log.Warning("数据下标设置不对，请调整！");
                return;
            }


            List<string> columns = Columns.Select(s => s.Header).ToList();
            DataTools tools = new DataTools(DBName, TableName, columns);
            AppConfig.DataDump.Rows = new ObservableCollection<DynamicDataItem>();

            await InjectChannelRouter.DispatchAsync(AppConfig, "读取表数据",
                async  ()=> await tools.GetDataByBool(AppConfig),
                async  ()=> await tools.GetDataUnion(AppConfig),
                async  ()=> await tools.GetDataError(AppConfig));
            }
            catch (OperationCanceledException)
            {
                Log.Show("已停止获取数据！");
            }
        }

        private async Task GetDataBase()
        {
            try
            {
            if (AppConfig.DataConfig.SelectedDBType.Equals(DBType.Access))
            {
                AppConfig.DataDump.DBStructItems.Add(new DBStruct
                {
                    Type = DBStructType.DBName,
                    Value = "Access"
                });
                return;
            }

            AppConfig.DataDump.DBStructItems = new();


            await InjectChannelRouter.DispatchAsync(AppConfig, "枚举数据库",
                async  ()=> await DBStructTools.GetDBSByBool(AppConfig),
                async  ()=> await DBStructTools.GetDBSByUnion(AppConfig),
                async  ()=> await DBStructTools.GetDBSByError(AppConfig));
            }
            catch (OperationCanceledException)
            {
                Log.Show("已停止获取数据库！");
            }
        }


        private async Task GetTables()
        {
            try
            {

            await InjectChannelRouter.DispatchAsync(AppConfig, "",
                async  ()=> await DBStructTools.GetTablesByBool(AppConfig),
                async  ()=> await DBStructTools.GetTablesByUnion(AppConfig),
                async  ()=> await DBStructTools.GetTablesByError(AppConfig));
            }
            catch (OperationCanceledException)
            {
                Log.Show("已停止获取表！");
            }
        }

        private async Task GetColumns()
        {
            try
            {

            await InjectChannelRouter.DispatchAsync(AppConfig, "",
                async  ()=> await DBStructTools.GetColumnsByBool(AppConfig),
                async  ()=> await DBStructTools.GetColumnsByUnion(AppConfig),
                async  ()=> await DBStructTools.GetColumnsByError(AppConfig));
            }
            catch (OperationCanceledException)
            {
                Log.Show("已停止获取列！");
            }
        }
    }
}
