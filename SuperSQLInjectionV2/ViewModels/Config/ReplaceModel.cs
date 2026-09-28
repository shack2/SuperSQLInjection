using CommunityToolkit.Mvvm.ComponentModel;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace SuperSQLInjectionV2.Models
{
    public partial class ReplaceModel : ViewModelBase
    {

        [ObservableProperty] public partial string Src { get; set; } = "";
        [ObservableProperty] public partial string Target { get; set; } = "";
        [ObservableProperty] public partial int Index { get; set; } = 0;
        [ObservableProperty] public partial bool Enable { get; set; } = true;
        [ObservableProperty] public partial bool BeforEncode { get; set; } = true;
        [ObservableProperty] public partial bool IsRegex { get; set; } = false;
        

    }
}
