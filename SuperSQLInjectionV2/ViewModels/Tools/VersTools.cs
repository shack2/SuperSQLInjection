using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Models.Data;
using SuperSQLInjectionV2.Payload;
using SuperSQLInjectionV2.Tools;
using SuperSQLInjectionV2.Tools.Http;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Data;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Threading.Tasks;
namespace SuperSQLInjectionV2.ViewModels.Tools
{
    public class VersTools
    {
        public static void ReadVersByDBType(DBType dbType, ObservableCollection<VersModel> vers)
        {
            ReadVersByDBType(dbType, vers, null);
        }
        /// <summary>
        /// 按数据库类型加载取数模板：哈希/DBA类条目分流到 hash 集合（Hash读取选项卡），
        /// 权限/角色类条目分流到 priv 集合（权限角色选项卡），其余进环境变量集合；
        /// hash/priv 为 null 时全部进环境变量集合（兼容旧调用）
        /// </summary>
        public static void ReadVersByDBType(DBType dbType, ObservableCollection<VersModel> vers, ObservableCollection<VersModel>? hash, ObservableCollection<VersModel>? priv = null)
        {
           if (dbType.Equals(DBType.UnKnow)) return;
           string versPath = "/config/vers/" + dbType.ToString().ToLower() + ".txt";
           //无取数模板的数据库（如 Access 无环境变量函数）：提示不支持而不是抛文件不存在异常
           if (!System.IO.File.Exists(AppDomain.CurrentDomain.BaseDirectory + versPath))
           {
               Log.Show($"当前数据库（{dbType}）不支持环境变量读取！");
               return;
           }
           List<string> list=FileTool.readFileToList(versPath);
           list.ForEach(x => {
               string[] data=x.Split("：");
               if (data.Length == 2) {
                   VersModel vm=new VersModel();
                   vm.Name=data[0];
                   vm.VerPayload = data[1];
                   //默认勾选：加载后即可直接点"读取"，避免未勾选导致空循环不发包
                   vm.IsChecked = true;
                   if (hash != null && IsHashItem(vm.Name))
                   {
                       hash.Add(vm);
                   }
                   else if (priv != null && IsPrivItem(vm.Name))
                   {
                       priv.Add(vm);
                   }
                   else
                   {
                       vers.Add(vm);
                   }
               }
           });
        }
        /// <summary>哈希/权限类条目判定（Hash读取选项卡分流规则）</summary>
        private static bool IsHashItem(string name)
        {
            return !string.IsNullOrEmpty(name)
                && (name.Contains("Hash", StringComparison.OrdinalIgnoreCase)
                    || name.Contains("哈希", StringComparison.Ordinal)
                    || name.Contains("DBA", StringComparison.OrdinalIgnoreCase)
                    || name.Contains("sysadmin", StringComparison.OrdinalIgnoreCase)
                    || name.Contains("口令", StringComparison.Ordinal)
                    || name.Contains("密码", StringComparison.Ordinal));
        }
        /// <summary>权限/角色类条目判定（权限角色选项卡分流规则，对标业界同类工具 --privileges/--roles）</summary>
        private static bool IsPrivItem(string name)
        {
            return !string.IsNullOrEmpty(name)
                && (name.Contains("权限", StringComparison.Ordinal)
                    || name.Contains("角色", StringComparison.Ordinal)
                    || name.Contains("privilege", StringComparison.OrdinalIgnoreCase)
                    || name.Contains("role", StringComparison.OrdinalIgnoreCase)
                    || name.Contains("grants", StringComparison.OrdinalIgnoreCase));
        }
        
        private static async Task GetUnionData(AppConfig config,VersModel vm)
        {
            if (config.DataConfig.SelectedInjectType.Equals(InjectType.Error))
            {
                //报错通道：走截断处理链路（单发为空→实测容量分片取回+断点续传+截断兜底抢救）
                vm.Value = await DataComm.DataDumpWithError(config, vm.VerPayload).ConfigureAwait(false);
                return;
            }
            //Union通道：走截断处理链路（单发截断→substr分片取回）
            vm.Value = await DataComm.DataDumpWithNoFrom(config, vm.VerPayload).ConfigureAwait(false);
        }
        /// <summary>Union/报错回显通道读取（内部按配置的注入类型分支；items为空时默认环境变量集合，Hash读取选项卡传HashItems）</summary>
        public static void GetVersByEcho(AppConfig config, IEnumerable<VersModel>? items = null)
        {
            if (config.DataConfig.SelectedDBType.Equals(DBType.Access)) {
                Log.Show("Access数据库不支持获取环境信息！");
                return;
            }
            IEnumerable<VersModel> SelectedVers = (items ?? config.DataConfig.VersItems).Where(x =>x.IsChecked);
            if (!SelectedVers.Any())
            {
                Log.Warning("未勾选需要读取的项！");
                return;
            }
            WorkRunner.FireAndForgetAsync(SelectedVers, config, async item => await GetUnionData(config, item));
        }
        /// <summary>Bool盲注通道读取；maxLen按场景收窄（环境变量1024，Hash类值有明确上界传256省长度探测请求）</summary>
        public static async Task GetVersByBool(AppConfig config, IEnumerable<VersModel>? items = null, int maxLen = 1024)
        {
            if (config.DataConfig.SelectedDBType.Equals(DBType.Access))
            {
                Log.Show("Access数据库不支持获取环境信息！");
                return;
            }
            IEnumerable<VersModel> SelectedVers = (items ?? config.DataConfig.VersItems).Where(x => x.IsChecked);
            if (!SelectedVers.Any())
            {
                Log.Warning("未勾选需要读取的项！");
                return;
            }
            foreach (var item in SelectedVers)
            {
                config.CheckStop();
                //多字节安全的盲注取值（hex/unicode/ascw），内部通过stp并行取字符
                item.Value = (await DataComm.GetStringByBool(config, item.VerPayload, maxLen).ConfigureAwait(false)) ?? "";
            }
        }
    }
}