using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Tools;
using SuperSQLInjectionV2.ViewModels.Tools;
using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.ViewModels
{
    /// <summary>
    /// 文件操作与命令执行
    /// </summary>
    public partial class FileCmdViewModel : ViewModelBase
    {
        public AppConfig AppConfig { get; set; }

        [ObservableProperty] private string _filePath = "";

        [ObservableProperty] private string _fileEncoding = "UTF-8";

        [ObservableProperty] private string _fileContent = "";

        /// <summary>二进制文件内容（二进制上传=待写字节；二进制下载=取回的字节）</summary>
        [ObservableProperty] private byte[]? _fileBytes;

        /// <summary>二进制模式选择的本地文件路径（上传源文件/下载保存路径）</summary>
        [ObservableProperty] private string _localFilePath = "";

        /// <summary>当前操作方式是否为二进制通道（选中方式变化时联动）</summary>
        [ObservableProperty] private bool _isBinaryMethod;

        /// <summary>二进制上传时已选本地文件的大小提示</summary>
        [ObservableProperty] private string _localFileHint = "";

        [ObservableProperty] private string _selectedFileMethod = "";

        public ObservableCollection<string> FileMethods { get; } = new ObservableCollection<string>();

        [ObservableProperty] private string _cmdText = "";

        [ObservableProperty] private bool _cmdShowResult = true;

        [ObservableProperty] private string _cmdResult = "";

        /// <summary>命令会话模式（os-shell 能力）：开启后执行结果以"> 命令+回显"追加到历史记录，通道保持复用；关闭则每次替换显示</summary>
        [ObservableProperty] private bool _cmdSessionMode = true;

        /// <summary>当前数据库对应的命令执行方式提示，随数据库类型切换自动更新</summary>
        [ObservableProperty] private string _cmdMethodHint = "";

        /// <summary>命令执行方式选项（随数据库类型联动刷新）</summary>
        public ObservableCollection<string> CmdMethods { get; } = new ObservableCollection<string>();

        /// <summary>当前选中的命令执行方式</summary>
        [ObservableProperty] private string _selectedCmdMethod = "";

        /// <summary>当前数据库是否有可用命令执行通道（无则禁用命令区控件，防误点）</summary>
        [ObservableProperty] private bool _cmdSupported;

        /// <summary>当前数据库不支持文件操作时的提示（支持时为空）</summary>
        [ObservableProperty] private string _fileMethodHint = "";

        public FileCmdViewModel(AppConfig appConfig)
        {
            AppConfig = appConfig;
            RefreshFileMethods();
            //取数操作处数据库类型变化时，联动刷新文件操作方式与命令执行提示
            AppConfig.DataConfig.PropertyChanged += (_, e) =>
            {
                if (e.PropertyName == nameof(Models.DataConfig.SelectedDBType))
                {
                    if (LogTools.Headless || Avalonia.Application.Current == null || Dispatcher.UIThread.CheckAccess())
                    {
                        RefreshFileMethods();
                    }
                    else
                    {
                        Dispatcher.UIThread.Post(RefreshFileMethods);
                    }
                }
            };
        }

        partial void OnSelectedFileMethodChanged(string value)
        {
            IsBinaryMethod = (value ?? "").Contains("二进制", StringComparison.Ordinal);
        }

        /// <summary>后台线程更新二进制文件内容（字节数写日志，内容不进文本框）</summary>
        public void SetFileBytes(byte[]? data)
        {
            if (LogTools.Headless) { FileBytes = data; return; }
            Dispatcher.UIThread.Post( ()=> FileBytes = data);
        }

        /// <summary>GUI选择本地文件后装载字节（二进制上传用）</summary>
        public void LoadLocalFile(string path)
        {
            try
            {
                FileBytes = System.IO.File.ReadAllBytes(path);
                LocalFilePath = path;
                LocalFileHint = System.IO.Path.GetFileName(path) + "（" + FileBytes.Length + "字节）";
            }
            catch (Exception e)
            {
                Log.Warning("读取本地文件失败：" + e.Message);
            }
        }

        /// <summary>GUI保存下载的二进制文件</summary>
        public void SaveFileBytesTo(string path)
        {
            try
            {
                System.IO.File.WriteAllBytes(path, FileBytes ?? Array.Empty<byte>());
                LocalFilePath = path;
                Log.Success("二进制文件已保存：" + path + "（" + (FileBytes?.Length ?? 0) + "字节）");
            }
            catch (Exception e)
            {
                Log.Warning("保存文件失败：" + e.Message);
            }
        }

        /// <summary>
        /// 根据当前数据库类型刷新支持的文件操作方式与命令执行提示
        /// </summary>
        public void RefreshFileMethods()
        {
            RefreshFileMethods(AppConfig.DataConfig.SelectedDBType);
        }

        /// <summary>
        /// 按指定数据库类型刷新支持的文件操作方式与命令执行方式/提示（数据操作页数据库下拉变化时直接联动，无需先点"应用"）
        /// </summary>
        public void RefreshFileMethods(DBType dbType)
        {
            FileMethods.Clear();
            CmdMethods.Clear();
            switch (dbType)
            {
                case DBType.MySQL:
                    FileMethods.Add("Load_File读文件");
                    FileMethods.Add("Union写文件");
                    FileMethods.Add("日志写WebShell");
                    FileMethods.Add("二进制下载(load_file)");
                    FileMethods.Add("二进制上传(dumpfile)");
                    CmdMethods.Add("UDF sys_eval");
                    CmdMethodHint = "UDF sys_eval（需Union/堆叠注入，自动上传 lib_mysqludf_sys）";
                    FileMethodHint = "日志写WebShell需堆叠注入；Union写文件需Union注入；二进制下载全通道可用，二进制上传需Union(小文件)/堆叠(分片)";
                    break;
                case DBType.PostgreSQL:
                    string pgFork = AppConfig.DataConfig.SelectedForkName ?? "";
                    if (pgFork.Equals("openGauss", StringComparison.OrdinalIgnoreCase)
                        || pgFork.Equals("MogDB", StringComparison.OrdinalIgnoreCase))
                    {
                        //openGauss系fork：COPY FROM PROGRAM已移除，不支持命令执行；COPY文件读写保留
                        FileMethods.Add("Copy读文件");
                        FileMethods.Add("Copy写文件");
                        CmdMethodHint = pgFork + " 不支持 COPY FROM PROGRAM，命令执行不可用";
                        FileMethodHint = "Copy读写需堆叠注入+superuser（fork overlay模板控制具体能力）";
                        break;
                    }
                    FileMethods.Add("Copy读文件");
                    FileMethods.Add("Copy写文件");
                    FileMethods.Add("大对象读文件");
                    FileMethods.Add("大对象写文件");
                    FileMethods.Add("二进制下载(大对象)");
                    FileMethods.Add("二进制上传(大对象)");
                    CmdMethods.Add("COPY FROM PROGRAM");
                    CmdMethods.Add("PlPython命令执行(COPY兜底)");
                    CmdMethods.Add("UDF sys_eval");
                    CmdMethodHint = "COPY FROM PROGRAM（9.3+，需superuser/pg_execute_server_program，执行前实测探针验证）；PlPython（plpython3u扩展函数，纯SQL部署，需superuser+可装扩展）；UDF sys_eval（8.2~9.4，需堆叠注入）"
                        + (string.IsNullOrEmpty(pgFork) ? "" : "；当前fork：" + pgFork);
                    FileMethodHint = "Copy读写需堆叠注入；大对象读写需superuser或pg_read/write_server_files；二进制上传堆叠分片，小文件可Union/报错单发";
                    break;
                case DBType.SQLServer:
                    FileMethods.Add("FileSystemObject读文件");
                    FileMethods.Add("BULK INSERT读文件");
                    FileMethods.Add("FileSystemObject写文件");
                    FileMethods.Add("Sp_MakeWebTask写文件");
                    FileMethods.Add("备份写WebShell(有多余数据)");
                    FileMethods.Add("二进制下载(OPENROWSET)");
                    FileMethods.Add("二进制上传(ADODB.Stream)");
                    CmdMethods.Add("xp_cmdshell");
                    CmdMethods.Add("sp_OACreate(xp被删时备用)");
                    CmdMethodHint = "xp_cmdshell（自动 sp_configure 开启，仅 Windows 版 SQL Server）；sp_OACreate(wscript.shell) 需 sysadmin+堆叠，输出经BULK INSERT回读";
                    FileMethodHint = "二进制上传走sp_OACreate+ADODB.Stream（自动开启Ole Automation，需堆叠）；二进制下载走OPENROWSET SINGLE_BLOB（需堆叠建表，取数全通道可用）";
                    break;
                case DBType.OpenGauss:
                    //openGauss兼容PG的COPY文件读写；COPY FROM PROGRAM已移除，不支持命令执行
                    FileMethods.Add("Copy读文件");
                    FileMethods.Add("Copy写文件");
                    CmdMethodHint = "openGauss 不支持 COPY FROM PROGRAM，命令执行不可用";
                    FileMethodHint = "";
                    break;
                case DBType.Kingbase:
                    //KingbaseES兼容PG协议与COPY语法，复用PG通道（UDF二进制为PG专用，不接）
                    FileMethods.Add("Copy读文件");
                    FileMethods.Add("Copy写文件");
                    CmdMethods.Add("COPY FROM PROGRAM");
                    CmdMethodHint = "KingbaseES 复用 PostgreSQL COPY FROM PROGRAM 通道（需superuser）";
                    FileMethodHint = "Copy读写需堆叠注入+superuser（KingbaseES V8兼容PG语法）";
                    break;
                case DBType.H2:
                    //H2嵌入式：读写的是应用服务器本地文件；CSVREAD/CSVWRITE
                    FileMethods.Add("CSVREAD读文件");
                    FileMethods.Add("CSVWRITE写文件");
                    FileMethods.Add("二进制下载(FILE_READ)");
                    FileMethods.Add("二进制上传(FILE_WRITE)");
                    CmdMethods.Add("CREATE ALIAS命令执行");
                    CmdMethodHint = "CREATE ALIAS（需JDK编译器javax.tools可用，H2 1.x/2.x均支持；JRE环境不可用）；管道/重定向请自行加 /bin/sh -c 或 cmd /c";
                    FileMethodHint = "二进制走FILE_READ(BLOB)+RAWTOHEX / FILE_WRITE(x'hex')内置函数（需admin权限）；上传大文件自动切CREATE ALIAS分片（需JDK编译器）";
                    break;
                case DBType.HSQLDB:
                    //HSQLDB JDBC不支持堆叠多语句，TEXT TABLE文件读写需多条语句配合，注入场景不可用
                    CmdMethodHint = "HSQLDB 不支持命令执行";
                    FileMethodHint = "HSQLDB 暂不支持文件操作（TEXT TABLE为CSV文本且需多条DDL配合；Java例程需预置classpath类，纯注入无二进制通道）";
                    break;
                case DBType.SQLite:
                    //SQLite：ATTACH DATABASE 附加新库文件写shell（需堆叠）；readfile()默认不可用，load_extension默认禁用
                    FileMethods.Add("ATTACH写WebShell");
                    FileMethods.Add("二进制下载(readfile扩展)");
                    FileMethods.Add("二进制上传(writefile扩展)");
                    CmdMethodHint = "SQLite 不支持命令执行（load_extension 默认禁用）";
                    FileMethodHint = "ATTACH写WebShell需堆叠注入（attach/create/insert三条语句）；二进制走官方fileio扩展的readfile/writefile（blob无损，仅加载了该扩展的目标可用，如Calibre；无扩展时函数不存在报错）";
                    break;
                case DBType.ClickHouse:
                    //ClickHouse：file()表函数读user_files目录；不提供写文件（INTO OUTFILE为客户端侧功能，HTTP接口固定报错358不可用）
                    FileMethods.Add("file()读文件");
                    FileMethods.Add("二进制下载(file RawBLOB)");
                    CmdMethodHint = "ClickHouse 不支持命令执行";
                    FileMethodHint = "file()仅能读 user_files 目录内文件；二进制下载走RawBLOB整读+hex传输；不支持写文件（INTO OUTFILE仅clickhouse-client客户端侧生效，HTTP接口注入不可用）";
                    break;
                case DBType.Oracle:
                    string oraFork = AppConfig.DataConfig.SelectedForkName ?? "";
                    if (oraFork.Equals("DM", StringComparison.OrdinalIgnoreCase))
                    {
                        //达梦fork（实测2026-09 DM8）：无DBMS_XMLQUERY/DBMS_JAVA包；DmProvider堆叠批内禁DDL；UTL_FILE需预建目录对象。
                        //纯Web注入下无可用通道，不提供文件/命令操作。
                        CmdMethodHint = "DM 暂不支持命令执行（无DBMS_XMLQUERY，驱动堆叠禁DDL；Java外部函数需jar预置external_jar目录+ENABLE_EXTERNAL_CALL开参+重启）";
                        FileMethodHint = "DM 暂不支持文件操作（UTL_FILE需DBA预建DIRECTORY对象，Java外部函数需预置jar，纯注入均不可达）";
                        break;
                    }
                    //GETXML Java通道：dbms_xmlquery.getxml可执行匿名PL/SQL块（实测23ai拒绝PL/SQL仅收SELECT，
                    //社区资料确认适用9i~11g；18c弃用该包/21c起移除）。借此免堆叠部署Java存储过程。
                    FileMethods.Add("Java读文件");
                    FileMethods.Add("Java写文件");
                    FileMethods.Add("二进制下载(Java)");
                    FileMethods.Add("二进制上传(Java)");
                    CmdMethods.Add("Java命令执行(GETXML)");
                    CmdMethodHint = "GETXML+Java存储过程：适用Oracle 9i~11g（DBMS_XMLQUERY可执行匿名PL/SQL；12c未验证，18c弃用/21c+移除）。需CREATE PROCEDURE权限+JVM，返回值限4000字符";
                    FileMethodHint = "Java通道读写文件（同版本限制），免堆叠；写文件内容限约2000字节（hex后受varchar2(4000)限制）；二进制走Java hex分片（1500字节/片）";
                    break;
                case DBType.DM:
                    //实测（2026-09 DM8）：无DBMS_XMLQUERY/DBMS_JAVA包；DmProvider堆叠批内禁DDL；UTL_FILE需预建目录对象。
                    //纯Web注入下无可用通道，不提供文件/命令操作。
                    CmdMethodHint = "DM 暂不支持命令执行（无DBMS_XMLQUERY，驱动堆叠禁DDL；Java外部函数需jar预置external_jar目录+ENABLE_EXTERNAL_CALL开参+重启）";
                    FileMethodHint = "DM 暂不支持文件操作（UTL_FILE需DBA预建DIRECTORY对象，Java外部函数需预置jar，纯注入均不可达）";
                    break;
                case DBType.DB2:
                    //DB2命令执行需CREATE EXTERNAL PROCEDURE（C/Java外部例程DDL），客户端驱动不支持堆叠，纯注入不可达
                    CmdMethodHint = "DB2 不支持命令执行（需CREATE EXTERNAL PROCEDURE外部例程DDL，纯注入不可达）";
                    FileMethodHint = "DB2 暂不支持文件操作（ADMIN_CMD仅EXPORT/LOAD文本级IO且需SYSADM，非字节无损；无纯注入二进制通道）";
                    break;
                default:
                    CmdMethodHint = "当前数据库暂不支持命令执行";
                    FileMethodHint = "当前数据库暂不支持文件操作（支持 MySQL / PostgreSQL / SQLServer / openGauss / Kingbase / H2 / SQLite / ClickHouse / Oracle / DM）";
                    break;
            }
            if (FileMethods.Count > 0)
            {
                SelectedFileMethod = FileMethods[0];
            }
            else
            {
                SelectedFileMethod = "";
            }
            SelectedCmdMethod = CmdMethods.Count > 0 ? CmdMethods[0] : "";
            CmdSupported = CmdMethods.Count > 0;
        }

        /// <summary>
        /// 开始文件操作（读取或写入）
        /// </summary>
        [RelayCommand]
        private void StartFileOperate()
        {
            DBType dbType = AppConfig.DataConfig.SelectedDBType;
            if (dbType != DBType.MySQL
                && dbType != DBType.PostgreSQL
                && dbType != DBType.SQLServer
                && dbType != DBType.OpenGauss
                && dbType != DBType.Kingbase
                && dbType != DBType.H2
                && dbType != DBType.SQLite
                && dbType != DBType.ClickHouse
                && dbType != DBType.Oracle)
            {
                Log.Warning("当前数据库类型不支持文件操作，支持：MySQL、PostgreSQL、SQLServer、openGauss、Kingbase、H2、SQLite（ATTACH写）、ClickHouse、Oracle（Java通道，限9i~11g）！");
                return;
            }
            if (string.IsNullOrEmpty(FilePath))
            {
                Log.Warning("大侠，请先输入文件路径！");
                return;
            }
            if (string.IsNullOrEmpty(SelectedFileMethod))
            {
                RefreshFileMethods();
                if (string.IsNullOrEmpty(SelectedFileMethod))
                {
                    Log.Warning("大侠，请先选择操作方式！");
                    return;
                }
            }
            if (SelectedFileMethod.Contains("二进制上传", StringComparison.Ordinal))
            {
                if (FileBytes == null || FileBytes.Length == 0)
                {
                    Log.Warning("请先点击「选择文件」选择要上传的本地文件！");
                    return;
                }
            }
            else if (SelectedFileMethod.Contains("写文件", StringComparison.Ordinal) || SelectedFileMethod.Contains("WebShell", StringComparison.Ordinal))
            {
                if (string.IsNullOrEmpty(FileContent))
                {
                    Log.Warning("请在下面输入您要写入文件的内容，请注意，GET方式的注入提交数据不能超过1024个字节！");
                    return;
                }
            }
            AppConfig.ResetStop();
            AppConfig.IsRuning = true;
            Task runTask = FileCmdTools.ExecuteFile(AppConfig, this);
            WorkRunner.OnCompletedSurfaced(runTask,  ()=>
            {
                AppConfig.IsRuning = false;
            });
        }

        /// <summary>
        /// 开始执行命令
        /// </summary>
        [RelayCommand]
        private void StartExecCmd()
        {
            DBType cmdDbType = AppConfig.DataConfig.SelectedDBType;
            if (!cmdDbType.Equals(DBType.SQLServer)
                && !cmdDbType.Equals(DBType.PostgreSQL)
                && !cmdDbType.Equals(DBType.MySQL)
                && !cmdDbType.Equals(DBType.Kingbase)
                && !cmdDbType.Equals(DBType.H2)
                && !cmdDbType.Equals(DBType.Oracle))
            {
                Log.Warning("目前命令执行支持：SQLServer（xp_cmdshell/sp_OACreate）、PostgreSQL（COPY FROM PROGRAM/UDF）、Kingbase（COPY FROM PROGRAM）、MySQL（UDF sys_eval）、H2（CREATE ALIAS）、Oracle（GETXML+Java，限9i~11g）！");
                return;
            }
            if (string.IsNullOrEmpty(CmdText))
            {
                Log.Warning("大侠，请先输入要执行的命令！");
                return;
            }
            AppConfig.ResetStop();
            AppConfig.IsRuning = true;
            Task runTask = FileCmdTools.ExecuteCmd(AppConfig, this);
            WorkRunner.OnCompletedSurfaced(runTask,  ()=>
            {
                AppConfig.IsRuning = false;
            });
        }

        /// <summary>
        /// UDF痕迹清理（cleanup 能力）：删除UDF库文件+drop sys_eval/sys_exec函数（MySQL/PostgreSQL）
        /// </summary>
        [RelayCommand]
        private void CleanupUdf()
        {
            if (!AppConfig.DataConfig.SelectedDBType.Equals(DBType.MySQL)
                && !AppConfig.DataConfig.SelectedDBType.Equals(DBType.PostgreSQL))
            {
                Log.Warning("UDF清理仅适用于MySQL与PostgreSQL（UDF sys_eval通道）！");
                return;
            }
            AppConfig.ResetStop();
            AppConfig.IsRuning = true;
            Task runTask = FileCmdTools.CleanupUdf(AppConfig);
            WorkRunner.OnCompletedSurfaced(runTask,  ()=>
            {
                AppConfig.IsRuning = false;
            });
        }

        /// <summary>
        /// 后台线程更新文件内容
        /// </summary>
        public void SetFileContent(string content)
        {
            if (LogTools.Headless) { FileContent = content; return; }
            Dispatcher.UIThread.Post( ()=> FileContent = content);
        }

        /// <summary>
        /// 后台线程追加命令执行结果
        /// </summary>
        public void AppendCmdResult(string content)
        {
            //读到即更新（实时回显命令输出）
            UiNotifier.Post( ()=> CmdResult += content);
        }

        /// <summary>
        /// 后台线程更新命令执行结果。
        /// 会话模式（os-shell 能力）：结果以"> 命令 + 回显"形式追加到历史记录，通道（UDF/xp_cmdshell）保持复用；
        /// 非会话模式：替换显示本次结果
        /// </summary>
        public void SetCmdResult(string content)
        {
            if (CmdSessionMode)
            {
                string line = (string.IsNullOrEmpty(CmdResult) ? "" : "\r\n") + "> " + CmdText + "\r\n" + (content ?? "") + "\r\n";
                AppendCmdResult(line);
                return;
            }
            if (LogTools.Headless) { CmdResult = content; return; }
            Dispatcher.UIThread.Post( ()=> CmdResult = content);
        }

        /// <summary>
        /// 清空命令会话历史
        /// </summary>
        [RelayCommand]
        private void ClearCmdSession()
        {
            if (LogTools.Headless) { CmdResult = ""; return; }
            Dispatcher.UIThread.Post( ()=> CmdResult = "");
        }
    }
}
