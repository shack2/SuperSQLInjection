using AvaloniaEdit.Document;
using CommunityToolkit.Mvvm.ComponentModel;
using SuperSQLInjectionV2.ViewModels;
using System.Collections.ObjectModel;

namespace SuperSQLInjectionV2.Models
{
    public partial class RequestLogModel : ViewModelBase
    {
        /// <summary>请求日志环形缓冲上限（P2：超出剔最旧，防长会话内存膨胀）</summary>
        public const int MaxItems = 2000;



        [ObservableProperty]
        private ObservableCollection<RequestLog>  _items = new ObservableCollection<RequestLog>();

        [ObservableProperty]
        private TextDocument _requestTxt  = new TextDocument("");

        [ObservableProperty]
        private TextDocument _responseText  = new TextDocument("");

        [ObservableProperty]
        private RequestLog? _selectItem;

        partial void OnSelectItemChanged(RequestLog? value)
        {
            if (value != null)
            {
                RequestTxt.Text = value.Request.HeaderAndBody;
                ResponseText.Text = value.Response.HeaderAndBody;
            }

        }
    }
}
