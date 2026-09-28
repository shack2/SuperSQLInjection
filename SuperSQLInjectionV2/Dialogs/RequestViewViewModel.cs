using Avalonia.Threading;
using AvaloniaEdit.Document;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Irihi.Avalonia.Shared.Contracts;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Payload;
using SuperSQLInjectionV2.Tools.Http;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using System.Windows.Input;
using Ursa.Controls;

namespace SuperSQLInjectionV2.Dialogs;

public partial class RequestViewViewModel : ObservableObject, IDialogContext
{

    [ObservableProperty] private TextDocument _txtRequest=new TextDocument();
    [ObservableProperty] private TextDocument _txtResponse = new TextDocument();
    [ObservableProperty] private bool _isLoadding=true;
    private AppConfig Config;
    /// <summary>指定发送的报文文本（检测页传入干净报文）；null时按取数页报文（Config.RequestTxt）发送</summary>
    private readonly string? _requestTxt;
    public RequestViewViewModel(AppConfig config, string? requestTxt = null)
    {
        this.Config = config;
        this._requestTxt = requestTxt;
        //Task<HttpResponse> re = new Task<HttpResponse>(Request);
         _ = UpdateTextThreadAsync();
        //re.GetAwaiter.OnCompleted( => {
        //    TxtRequest.Text = Config.HttpRequest.HeaderAndBody;
        //    TxtResponse.Text = re.Result.HeaderAndBody;
        //});
        //re.Start;
    }


    public async Task UpdateTextThreadAsync()
    {
        HttpRequest hr = string.IsNullOrWhiteSpace(_requestTxt) ? new HttpRequest(Config) : new HttpRequest(Config, _requestTxt);
        try
        {
            //全异步发送，不阻塞UI线程
            HttpResponse response = await Request(hr);
            TxtRequest.Text = hr.HeaderAndBody;
            TxtResponse.Text = response.HeaderAndBody;
        }
        catch (Exception e)
        {
            TxtResponse.Text = "请求异常：" + e.Message;
        }
        finally
        {
            IsLoadding = false;
        }
    }

    public void Close()
    {
        RequestClose?.Invoke(this, null);
    }

    public async Task<HttpResponse> Request(HttpRequest request)
    {
        return await HTTPTool.SendRequestRetryAsync(request);
    }

    public event EventHandler<object?>? RequestClose;
   
}