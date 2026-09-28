using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using SuperSQLInjectionV2.Tools.Http;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;

namespace SuperSQLInjectionV2.Models;

public partial class VersModel : ViewModelBase
{
    public string Name { get; set; } = "";
    public string VerPayload { get; set; } = "";

    public int _charValueLen = 0;

    public int charValueLen
    {
        get
        {

            return _charValueLen;
        }
        set
        {
            CharValue = new char[value];
            //Array.Fill(CharValue, '_');
            _charValueLen = value;
        }
    }

    [ObservableProperty] public partial char[] CharValue { get; set; }

    [ObservableProperty] public partial bool IsChecked { get; set; } = false;
    [ObservableProperty] public partial string Value { get; set; } = "";
    public VersModel()
    {
    }
    public VersModel(string Name, string Value) {

        this.Name = Name;
        this.Value = Value;
    }
    public VersModel(string Name, string Value,bool IsChecked)
    {
        this.Name = Name;
        this.Value = Value;
        this.IsChecked = IsChecked;
    }
}