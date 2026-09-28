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
                    CmdMethods.Add("UDF sys_eval");
                    CmdMethodHint = "UDF sys_eval（需Union/堆叠注入，自动上传 lib_mysqludf_sys）";
                    FileMethodHint = "";
                    break;
                case DBType.PostgreSQL:
                    FileMethods.Add("Copy读文件");
                    FileMethods.Add("Copy写文件");
                    CmdMethods.Add("COPY FROM PROGRAM");
                    CmdMethods.Add("UDF sys_eval");
                    CmdMethodHint = "COPY FROM PROGRAM（9.3+，需superuser/pg_execute_server_program）；UDF sys_eval（8.2~9.4，需堆叠注入）";
                    FileMethodHint = "";
                    break;
                case DBType.SQLServer:
                    FileMethods.Add("FileSystemObject读文件");
                    FileMethods.Add("BULK INSERT读文件");
                    FileMethods.Add("FileSystemObject写文件");
                    FileMethods.Add("Sp_MakeWebTask写文件");
                    FileMethods.Add("备份写WebShell(有多余数据)");
                    CmdMethods.Add("xp_cmdshell");
                    CmdMethodHint = "xp_cmdshell（自动 sp_configure 开启，仅 Windows 版 SQL Server）";
                    FileMethodHint = "";
                    break;
                case DBType.OpenGauss:
                    //openGauss兼容PG的COPY文件读写；COPY FROM PROGRAM已移除，不支持命令执行
                    FileMethods.Add("Copy读文件");
                    FileMethods.Add("Copy写文件");
                    CmdMethodHint = "openGauss 不支持 COPY FROM PROGRAM，命令执行不可用";
                    FileMethodHint = "";
                    break;
                case DBType.H2:
                    //H2嵌入式：读写的是应用服务器本地文件；CSVREAD/CSVWRITE
                    FileMethods.Add("CSVREAD读文件");
                    FileMethods.Add("CSVWRITE写文件");
                    CmdMethodHint = "H2 不支持命令执行";
                    FileMethodHint = "";
                    break;
                case DBType.HSQLDB:
                    //HSQLDB JDBC不支持堆叠多语句，TEXT TABLE文件读写需多条语句配合，注入场景不可用
                    CmdMethodHint = "HSQLDB 不支持命令执行";
                    FileMethodHint = "HSQLDB 暂不支持文件操作（TEXT TABLE需多条DDL配合，单语句注入不可用）";
                    break;
                case DBType.Oracle:
                case DBType.DM:
                    //实测结论（2026-09）：Oracle经ODP.NET不支持分号堆叠（ORA-00933），UTL_FILE需DBA预建DIRECTORY，
                    //XEE file://被ACL拦截（ORA-31001）；DM的DmProvider堆叠批内禁DDL（"不支持的语句类型"），
                    //UTL_FILE包存在但无预置目录对象，XEE需SP_INIT_XML加载XML库。两侧命令执行均需Java存储过程（CREATE JAVA属DDL）。
                    //以上前提在纯Web注入场景默认不成立，与业界同类工具能力边界一致，故不提供文件/命令操作。
                    CmdMethodHint = "Oracle/DM 命令执行需 Java 存储过程（CREATE JAVA 属 DDL，注入场景不可用）";
                    FileMethodHint = "Oracle/DM 文件读写需 DBA 预建 DIRECTORY 后 UTL_FILE（堆叠禁DDL/驱动不支持堆叠），不可用";
                    break;
                default:
                    CmdMethodHint = "当前数据库暂不支持命令执行";
                    FileMethodHint = "当前数据库暂不支持文件操作（支持 MySQL / PostgreSQL / SQLServer）";
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
            if (AppConfig.DataConfig.SelectedDBType != DBType.MySQL
                && AppConfig.DataConfig.SelectedDBType != DBType.PostgreSQL
                && AppConfig.DataConfig.SelectedDBType != DBType.SQLServer
                && AppConfig.DataConfig.SelectedDBType != DBType.OpenGauss
                && AppConfig.DataConfig.SelectedDBType != DBType.H2)
            {
                Log.Warning("当前数据库类型不支持文件操作，目前支持MySQL、PostgreSQL、SQLServer、openGauss（COPY）、H2（CSVREAD/CSVWRITE）！");
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
            if (SelectedFileMethod.Contains("写文件", StringComparison.Ordinal) || SelectedFileMethod.Contains("WebShell", StringComparison.Ordinal))
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
            if (!AppConfig.DataConfig.SelectedDBType.Equals(DBType.SQLServer)
                && !AppConfig.DataConfig.SelectedDBType.Equals(DBType.PostgreSQL)
                && !AppConfig.DataConfig.SelectedDBType.Equals(DBType.MySQL))
            {
                Log.Warning("目前命令执行支持SQLServer（xp_cmdshell）、PostgreSQL（COPY FROM PROGRAM / UDF sys_eval需堆叠）和MySQL（UDF sys_eval，需Union/堆叠注入）！Oracle等需Java存储过程，暂不支持！");
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
