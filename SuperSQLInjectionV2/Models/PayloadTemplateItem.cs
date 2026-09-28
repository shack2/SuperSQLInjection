using CommunityToolkit.Mvvm.ComponentModel;
using SuperSQLInjectionV2.ViewModels;

namespace SuperSQLInjectionV2.Models
{
    /// <summary>
    /// 取数模板项：对应config/payload/&lt;db&gt;.txt中的一行key:value。
    /// 用于UI可视化编辑取数模板（如MySQL8下floor(rand)失效时换成updatexml等），保存后热生效。
    /// </summary>
    public partial class PayloadTemplateItem : ViewModelBase
    {
        [ObservableProperty]
        private string _key = "";

        [ObservableProperty]
        private string _value = "";

        /// <summary>该key的用途描述（来自BasePayload.KeyDescriptions，Key修改时联动刷新）</summary>
        [ObservableProperty]
        private string _desc = "";

        public PayloadTemplateItem (){ }

        public PayloadTemplateItem(string key, string value)
        {
            _key = key;
            _value = value;
            _desc = Payload.BasePayload.GetKeyDescription(key);
        }

        partial void OnKeyChanged(string value)
        {
            Desc = Payload.BasePayload.GetKeyDescription(value);
        }
    }
}
