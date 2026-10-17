using Avalonia;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using AvaloniaEdit.Editing;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Messaging;
using SuperSQLInjectionV2.Models.Data;
using SuperSQLInjectionV2.Msg;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Ursa.Controls;
namespace SuperSQLInjectionV2.Models
{
    public partial class DBStruct : ViewModelBase
    {
        private DBStructType _dbType;
        [ObservableProperty] private DBStruct? _parent;
        [ObservableProperty] private string _value = "";
        [ObservableProperty] private bool _isExpanded = false;
        [ObservableProperty] private bool _isSelected = false;
        [ObservableProperty] private bool _isEdit = false;
        /// <summary>树搜索命中标记：命中节点背景标红</summary>
        [ObservableProperty] private bool _isSearchHit = false;
        /// <summary>搜索命中背景色（绑定到节点文本背景）</summary>
        public IBrush SearchHitBrush => IsSearchHit ? new SolidColorBrush(Color.Parse("#FFE05252")) : Brushes.Transparent;
        partial void OnIsSearchHitChanged(bool value)
        {
            OnPropertyChanged(nameof(SearchHitBrush));
        }
        [ObservableProperty] private ObservableCollection<DBStruct> _subItems = new ObservableCollection<DBStruct>();
        /// <summary>子节点计数文本：库节点显示表数量、表节点显示字段数（列节点/空节点不显示）</summary>
        public string ChildCountText
        {
            get
            {
                if (DBStructType.ColumnName.Equals(Type) || SubItems.Count == 0)
                {
                    return "";
                }
                return "[" + SubItems.Count + "]";
            }
        }
        public DBStruct (){
            _subItems.CollectionChanged += OnMyCollectionChanged;
        }
        private void OnMyCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
        {
            switch (e.Action)
            {
                case NotifyCollectionChangedAction.Add:
                    WeakReferenceMessenger.Default.Send(new AddStatusInfoMsg { });
                    OnPropertyChanged(nameof(ChildCountText));
                    break;
                case NotifyCollectionChangedAction.Remove:
                    WeakReferenceMessenger.Default.Send(new AddStatusInfoMsg { });
                    OnPropertyChanged(nameof(ChildCountText));
                    break;
                default:
                    OnPropertyChanged(nameof(ChildCountText));
                    break;
            }
        }
        public DBStructType Type
        {
            get
            {
                return _dbType;
            }
            set
            {
                _dbType = value;
            }
        }
        public Bitmap Icon { get; set; } = null!;
        public int _charValueLen = 0;
        public int CharValueLen
        {
            get
            {
                return _charValueLen;
            }
            set
            {
                CharValues = new char[value];
                Array.Fill(CharValues, '_');
                _charValueLen = value;
            }
        }
        public char[] CharValues { get; set; } = Array.Empty<char>();
        partial void OnIsSelectedChanged(bool value)
        {
            //通知datagrid添加列
            if (DBStructType.ColumnName.Equals(Type)&&Parent!=null) {
                //当前表字段选中时，其他表已经选中需要取消选中
                if (value) {
                    var db= Parent.Parent;
                    if (db == null) return;
                    foreach (var table in db.SubItems)
                    {
                        if (!table.Value.Equals(Parent.Value)) {
                            foreach (var column in table.SubItems)
                            {
                                if (column.IsSelected) {
                                    column.IsSelected = false;
                                }
                            }
                        }
                    }
                }
                //添加
                WeakReferenceMessenger.Default.Send(new AddColumnMsg { ColumnName = Value, TableName = Parent!.Value, isAdd = value, DBName = Parent.Parent?.Value ?? "" });
            }
            //级联选择更新
            if (value)
            {
                if (Parent != null) {
                    Parent.IsSelected = value;
                }
                
            }
            else {
                if (Parent != null&& Parent.SubItems.Where(x => x.IsSelected).Count()<=0)
                {
                    Parent.IsSelected = false;
                     ;
                }
            }
        }
    }
}