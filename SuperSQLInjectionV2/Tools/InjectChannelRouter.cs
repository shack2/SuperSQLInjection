using SuperSQLInjectionV2.Models;
using System;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.Tools
{
    /// <summary>
    /// 注入通道分发路由器：收敛原先复制在 GetVersInfo/GetHashInfo/GetPrivInfo/GetData/GetDataBase/GetTables/GetColumns
    /// 七处的 switch(SelectedInjectType) 分发逻辑。
    /// 语义约定：
    /// - Blind/Time：布尔逐值通道；
    /// - Stacked：堆叠点无通用回显，回退注入点自带的时间盲注通道（scene非空时输出回退提示）；
    /// - Dns：走布尔入口，由取数原语（DataComm.GetStringByBoolInner等）内部按Dns类型路由到外带；
    /// - Union/Error：回显通道。
    /// 新增通道类型时只需修改本类一处。
    /// </summary>
    public static class InjectChannelRouter
    {
        /// <summary>
        /// 按当前注入类型分发取数通道。
        /// </summary>
        /// <param name="config">全局配置</param>
        /// <param name="scene">场景名（仅用于堆叠回退提示，如"读取环境变量"；空串=不提示）</param>
        /// <param name="byBool">盲注系通道（Blind/Time/Stacked/Dns 共用）</param>
        /// <param name="byUnion">Union回显通道</param>
        /// <param name="byError">报错回显通道（null=与Union共用同一入口）</param>
        public static async Task DispatchAsync(AppConfig config, string scene, Func<Task> byBool, Func<Task> byUnion, Func<Task>? byError = null)
        {
            using var payloadScope = Payload.PayloadFactory.Activate(config);
            switch (config.DataConfig.SelectedInjectType)
            {
                case InjectType.Time:
                case InjectType.Blind:
                case InjectType.Dns:
                    await byBool().ConfigureAwait(false);
                    break;
                case InjectType.Stacked:
                    if (!string.IsNullOrEmpty(scene))
                    {
                        Log.Show("堆叠注入点" + scene + "：回退时间盲注通道逐值获取……");
                    }
                    await byBool().ConfigureAwait(false);
                    break;
                case InjectType.Union:
                    await byUnion().ConfigureAwait(false);
                    break;
                case InjectType.Error:
                    await (byError ?? byUnion)().ConfigureAwait(false);
                    break;
                default:
                    Log.Warning("未选择注入类型！请先在配置中心选择注入类型（Union/Error/Blind/Stacked），或执行注入检测自动标注。");
                    break;
            }
        }
    }
}
