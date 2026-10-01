using Avalonia.Threading;
using CommunityToolkit.Mvvm.Messaging;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Models.Data;
using SuperSQLInjectionV2.Msg;
using SuperSQLInjectionV2.Payload;
using SuperSQLInjectionV2.Tools;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.ViewModels.Tools
{
    public class DataTools
    {
        public string DBName = "";
		public string TableName = "";

		public List<string> Columns= new List<string>();
		public DataTools(string dbName, string tableName, List<string> columns) {

			DBName= dbName;
            TableName= tableName;
			Columns = columns;

		}

        /// <summary>
        /// dump任务级断点续传（P2-7）：同任务（注入点+库表列+where+通道）存在未完成进度时，
        /// UI弹窗询问/无头自动续传，返回(实际起始行, 任务键)；选否则清断点从头开始
        /// </summary>
        private async Task<(int start, string key)> ResolveDumpStart(AppConfig config, string channel, int start, int dumpCount, List<string> cols)
        {
            string key = DumpProgress.BuildKey(config, channel, DBName, TableName, cols, config.DataDump.DumpWhere);
            int resume = DumpProgress.GetResumeIndex(key);
            if (resume > start && resume < start + dumpCount)
            {
                bool useResume = true;
                if (!LogTools.Headless)
                {
                    var result = await Ursa.Controls.OverlayMessageBox.ShowAsync(
                        $"检测到表 {TableName} 有未完成的取数任务（{channel}通道，已取 {resume} 行）。\n是否从断点续传？选「否」将清除断点从头开始。",
                        "断点续传", button: Ursa.Controls.MessageBoxButton.YesNo);
                    useResume = Ursa.Controls.MessageBoxResult.Yes.Equals(result);
                }
                if (useResume)
                {
                    Log.Show($"dump断点续传：表{TableName}（{channel}）从第 {resume + 1} 行继续，跳过已取的 {resume} 行");
                    return (resume, key);
                }
                DumpProgress.Complete(key);
            }
            return (start, key);
        }

        public async Task GetDataByBool(AppConfig config)
        {
            //MIN 值链分页（Access）：Jet 标量子查询 TOP+ORDER BY 并列语义导致行索引分页不可用，走 sqlmap 风格值链
            if (PayloadFactory.BPTool.MinValueChainPaging)
            {
                await GetDataByBoolValueChain(config).ConfigureAwait(false);
                return;
            }

            string countPaylaod = PayloadFactory.BPTool.GetDataCount(DBName, TableName, config.DataDump.DumpWhere);
            int count= await DataComm.GetValueLen(config, countPaylaod, 0, 65556).ConfigureAwait(false);

            config.DataDump.DataCount = count;

            int start = config.DataDump.DataDumpStart;

            int dumpCount = config.DataDump.DumpCount;


            if (count < (dumpCount + start))
            {
                Log.Warning("表" + TableName + "只有" + count + "行数据，你需要获取的数据没有这么多呀！");
                return;
            }

            //dump断点续传（P2-7）
            int end = start + dumpCount;
            var (boolStart, boolKey) = await ResolveDumpStart(config, "Bool", start, dumpCount, Columns).ConfigureAwait(false);
            start = boolStart;

            for (int i = start; i < end; i++)
            {
                config.CheckStop();
                var row = new DynamicDataItem();

                AddRowDataMsg msg = new AddRowDataMsg { Data = row };
                WeakReferenceMessenger.Default.Send(msg);

                foreach (var item in Columns)
                {
                    config.CheckStop();
                    List<string> list = new List<string>();
                    list.Add(item);
                    DumpDataParam dp = new DumpDataParam(list, DBName, TableName,i);
                    dp.Where = config.DataDump.DumpWhere;
                    dp.NoCast = config.DataDump.DumpNoCast;

                    string payload = PayloadFactory.BPTool.DataValue(dp);

                    string colName = item;

                    Log.SysLog("开始获取表" + TableName + ",行:" + (i + 1) + "列:" + colName + "的数据");
                    //设置临时数据，后续动态更新
                    row.Add(colName, "");

                    //多字节安全的盲注取值（hex/unicode/ascw），内部通过stp并行取字符
                    string val = (await DataComm.GetStringByBool(config, payload, 4096).ConfigureAwait(false)) ?? "";

                    UiNotifier.Post(()=> row.Update(colName, val));
                }
                //行完成，推进断点
                DumpProgress.Save(boolKey, i + 1);
            }
            DumpProgress.Complete(boolKey);

        }

        /// <summary>
        /// MIN 值链盲注 dump（Access 专用）：Jet 标量子查询中 TOP+ORDER BY 对并列值返回多行报错，
        /// 行索引分页不可用（docker/ODBC 实测），改用 sqlmap 风格 MIN(col)&gt;last 值链。
        /// 逐列顺序取回 distinct 值（重复值折叠，与 sqlmap 同语义），按最长列对齐装配行；
        /// 断点续传/start 偏移通过从头重放链跳过（盲取成本不可避免，仅不落行）。
        /// </summary>
        private async Task GetDataByBoolValueChain(AppConfig config)
        {
            int start = config.DataDump.DataDumpStart;
            int dumpCount = config.DataDump.DumpCount; //0=全量
            var columnValues = new List<(string col, List<string> vals)>();
            foreach (string col in Columns)
            {
                config.CheckStop();
                var dp = new DumpDataParam(new List<string> { col }, DBName, TableName, 0);
                dp.Where = config.DataDump.DumpWhere;
                dp.NoCast = config.DataDump.DumpNoCast;
                int count = await DataComm.GetValueLen(config, PayloadFactory.BPTool.DataCountDistinct(dp), 0, 65535).ConfigureAwait(false);
                if (count <= 0)
                {
                    Log.Warning($"表{TableName}列{col} distinct 计数为 0，跳过该列");
                    columnValues.Add((col, new List<string>()));
                    continue;
                }
                int target = dumpCount <= 0 ? count : Math.Min(count, start + dumpCount);
                Log.Show($"表{TableName}列{col}共 {count} 个distinct值（MIN值链取值，重复值折叠）");
                var vals = new List<string>();
                string? last = null;
                for (int i = 0; i < target; i++)
                {
                    config.CheckStop();
                    Log.SysLog($"开始获取表{TableName},列:{col}的第 {i + 1} 个distinct值");
                    string payload = PayloadFactory.BPTool.DataValueChain(dp, last);
                    //多字节安全的盲注取值（unicodechar/ascw），内部通过stp并行取字符
                    string val = (await DataComm.GetStringByBool(config, payload, 4096).ConfigureAwait(false)) ?? "";
                    if (string.IsNullOrEmpty(val))
                    {
                        break; //链终止（MIN 返回 NULL / 空串）
                    }
                    if (i >= start)
                    {
                        vals.Add(val);
                    }
                    last = val;
                }
                columnValues.Add((col, vals));
            }
            //按最长列对齐装配行，短列补空
            int rowCount = columnValues.Count > 0 ? columnValues.Max(c => c.vals.Count) : 0;
            for (int r = 0; r < rowCount; r++)
            {
                config.CheckStop();
                var row = new DynamicDataItem();
                WeakReferenceMessenger.Default.Send(new AddRowDataMsg { Data = row });
                foreach (var (col, vals) in columnValues)
                {
                    row.Add(col, r < vals.Count ? vals[r] : "");
                }
            }
            Log.Success($"MIN值链取数完成：{rowCount} 行（distinct 语义，重复值已折叠）");
        }

        /// <summary>中文识别（--hex）开启时，取数列逐字段 HEX(CAST) 包装（回显纯ASCII，客户端按DbEncoding逐字段解码还原）</summary>
        private static List<string> HexWrapColumns(AppConfig config, List<string> cols)
        {
            if (!DataComm.HexActive(config))
            {
                return cols;
            }
            string cast = PayloadFactory.BasePayload.Cast;
            return cols.Select(c => TemplateRenderer.Render(PayloadFactory.BasePayload.Hex,
                ("expr", string.IsNullOrEmpty(cast) ? c : TemplateRenderer.Render(cast, ("expr", c))))).ToList();
        }

        public async Task GetDataUnion(AppConfig config)
        {
            string countPaylaod = PayloadFactory.BPTool.GetDataCount(DBName, TableName, config.DataDump.DumpWhere);

            //中文识别（--hex）：逐字段hex包装，防中文等多字节数据经Union回显乱码
            List<string> cols = HexWrapColumns(config, Columns);
			DumpDataParam dp = new DumpDataParam(cols, DBName, TableName, (int)config.DataConfig.SumColumnCount,(int)config.DataConfig.ShowColumnIndex);
            dp.Where = config.DataDump.DumpWhere;
            dp.NoCast = config.DataDump.DumpNoCast;

			string data = await DataComm.DataDumpWithNoFrom(config, countPaylaod).ConfigureAwait(false);

			int count = 0;
            int.TryParse(data, out count);

            config.DataDump.DataCount = count;

            int start= config.DataDump.DataDumpStart;

            int dumpCount = config.DataDump.DumpCount;


            if (count < (dumpCount + start))
            {
                Log.Warning("表" + TableName + "只有" + count + "行数据，你需要获取的数据没有这么多呀！");
                return;
            }

            //dump断点续传（P2-7）：键用hex包装后的列串，与盲注通道互不污染
            int end = start + dumpCount;
            var (unionStart, unionKey) = await ResolveDumpStart(config, "Union", start, dumpCount, cols).ConfigureAwait(false);
            start = unionStart;

            //行数据块→表格行（多列按DataSplitStr拆分，hex模式逐字段解码还原）
            void EmitRow(string datas)
            {
                string[] values = datas.Split(EchoMarkers.Split, StringSplitOptions.RemoveEmptyEntries);
                if (values == null || values.Length == 0)
                {
                    return;
                }
                var row = new DynamicDataItem();
                for (int c = 0; c < Columns.Count; c++)
                {
                    string colName = Columns[c];
                    string val = "";
                    if (c < values.Length)
                    {
                        //中文识别（--hex）：逐字段解码还原
                        val = DataComm.HexUnwrapIfNeeded(config, values[c]);
                    }
                    row.Add(colName, val);
                }
                AddRowDataMsg msg = new AddRowDataMsg { Data = row };
                WeakReferenceMessenger.Default.Send(msg);
            }

            //Union批量取数（Q3）：聚合函数多行拼单行一次回显，k行1次请求；模板缺失/取空/截断自动回退逐行
            int batch = config.DataConfig.UnionBatchRows;
            if (batch < 1)
            {
                batch = 1;
            }
            bool batchSupport = batch > 1 && !string.IsNullOrWhiteSpace(PayloadFactory.BasePayload.UnionDataRows);

            int i = start;
            while (i < end)
            {
                config.CheckStop();
                if (batchSupport)
                {
                    dp.DataIndex = i;
                    int want = (int)Math.Min(batch, end - i);
                    string rowsPayload = BasePayloadTool.UnionDataRows(PayloadFactory.BPTool, dp, want);
                    List<string> chunks = await DataComm.DataDumpRows(config, rowsPayload).ConfigureAwait(false);
                    if (chunks.Count == 0)
                    {
                        //批量未取到数据（模板不适用/聚合被拦），回退逐行模式
                        Log.Warning("Union批量取数未取到数据，回退逐行模式！");
                        batchSupport = false;
                        continue;
                    }
                    foreach (string chunk in chunks)
                    {
                        EmitRow(chunk);
                    }
                    i += chunks.Count;
                    DumpProgress.Save(unionKey, i);
                    if (chunks.Count < want)
                    {
                        //聚合容量截断（如MySQL group_concat_max_len默认1024），按实际行数推进，剩余逐行补齐
                        Log.Warning("Union批量取数仅返回" + chunks.Count + "/" + want + "行（疑聚合长度截断），剩余数据回退逐行读取！");
                        batchSupport = false;
                    }
                    continue;
                }

                dp.DataIndex = i;
                string dataPaylaod = PayloadFactory.BPTool.UnionData(dp);
				string datas = await DataComm.DataDump(config, dataPaylaod).ConfigureAwait(false);
                EmitRow(datas);
                i++;
                DumpProgress.Save(unionKey, i);
			}
            DumpProgress.Complete(unionKey);
        }

        public async Task GetDataError(AppConfig config)
        {
            string countPaylaod = PayloadFactory.BPTool.GetDataCount(DBName, TableName, config.DataDump.DumpWhere);

            //中文识别（--hex）：逐字段hex包装，防中文等多字节数据经报错回显乱码
            List<string> cols = HexWrapColumns(config, Columns);
            DumpDataParam dp = new DumpDataParam(cols, DBName, TableName, (int)config.DataConfig.SumColumnCount, (int)config.DataConfig.ShowColumnIndex);
            dp.Where = config.DataDump.DumpWhere;
            dp.NoCast = config.DataDump.DumpNoCast;

            string data = await DataComm.DataDumpWithError(config, countPaylaod).ConfigureAwait(false);

            int count = 0;
            int.TryParse(data, out count);

            config.DataDump.DataCount = count;

            int start = config.DataDump.DataDumpStart;

            int dumpCount = config.DataDump.DumpCount;


            if (count < (dumpCount + start))
            {
                Log.Warning("表" + TableName + "只有" + count + "行数据，你需要获取的数据没有这么多呀！");
                return;
            }

            //dump断点续传（P2-7）
            int end = start + dumpCount;
            var (errorStart, errorKey) = await ResolveDumpStart(config, "Error", start, dumpCount, cols).ConfigureAwait(false);
            start = errorStart;

            for (int i = start; i < end; i++)
            {
                config.CheckStop();
                dp.DataIndex = i;
                dp.Columns = new List<string>();
                string dataPaylaod = PayloadFactory.BPTool.ConcatData(cols);
                dp.Columns.Add(dataPaylaod);
                string dataValue = PayloadFactory.BPTool.DataValue(dp);
                string dataLenPaylaod = PayloadFactory.BPTool.DataLen(dataValue);
                string lenStr = await DataComm.DataDumpWithError(config, dataLenPaylaod).ConfigureAwait(false);
                int sumlen = 0;
                int.TryParse(lenStr,out sumlen);
              
                int s = 1;
                //报错分片步长：实测回显容量优先（探针二分测得并缓存到注入记录），回退模板ErrorChunkLen
                int step = await DataComm.GetErrorChunkStep(config).ConfigureAwait(false);
                StringBuilder sb = new StringBuilder();
                while (s <= sumlen)
                {
                    config.CheckStop();
                    string sdataPayload=PayloadFactory.BPTool.ErrorDataSubstr(dataValue, s,step);
                    //ErrorDataSubstr已完成报错包装，直接发送，不能再经DataDumpWithError二次包装
                    string sdata = await DataComm.DataDump(config, sdataPayload).ConfigureAwait(false);
                    sb.Append(sdata);
                    s += step;
                }
                string datas = sb.ToString();
                //报错分片是原样拼接（含行首data_与行尾_data标记），拆分列前必须先剥离起止标记，
                //否则首列残留"data_"、整体列错位且末列丢失；截断场景结束标记可能已被服务器截掉，EndsWith判断兼容
                if (datas.StartsWith(EchoMarkers.Start, StringComparison.Ordinal))
                {
                    datas = datas.Substring(EchoMarkers.Start.Length);
                }
                if (datas.EndsWith(EchoMarkers.End, StringComparison.Ordinal))
                {
                    datas = datas.Substring(0, datas.Length - EchoMarkers.End.Length);
                }
                string[] values = datas.Split(EchoMarkers.Split, StringSplitOptions.RemoveEmptyEntries);

                if (values != null && values.Length > 0)
                {
                    var row = new DynamicDataItem();
                    for (int c = 0; c < Columns.Count; c++)
                    {
                        string colName = Columns[c];
                        string val = "";
                        if (c < values.Length)
                        {
                            //中文识别（--hex）：逐字段解码还原
                            val = DataComm.HexUnwrapIfNeeded(config, values[c]);
                        }
                        row.Add(colName, val);
                    }
                    AddRowDataMsg msg = new AddRowDataMsg { Data = row };
                    WeakReferenceMessenger.Default.Send(msg);
                }
                //行完成，推进断点
                DumpProgress.Save(errorKey, i + 1);
            }
            DumpProgress.Complete(errorKey);
        }

       


    }


}
