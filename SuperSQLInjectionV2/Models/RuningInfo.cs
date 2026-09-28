using CommunityToolkit.Mvvm.ComponentModel;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.Models
{
    public partial class RuningInfo : ViewModelBase
    {

        [ObservableProperty] private int _runThreadCount = 0;
        [ObservableProperty] private int _maxThreaadCount= 0;
        [ObservableProperty] private bool _requestCount = false;

        [ObservableProperty] private int _progress = 0;
    }
}
