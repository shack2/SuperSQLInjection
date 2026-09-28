using Avalonia;
using Avalonia.Controls;
using Avalonia.Data;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.Models.Data
{

    // 动态数据项类，实现INotifyPropertyChanged接口 
    public class DynamicDataItem : ObservableObject
    { 
        // 存储动态属性的字典 
        private readonly Dictionary<string, string> _properties = new();

        // 索引器，用于访问动态属性
        public string this[string propertyName]
        {
            get
            {
                if (_properties.TryGetValue(propertyName, out var value))
                {
                    return value;
                }
                return string.Empty;
            }
            set
            {
                if (_properties.TryGetValue(propertyName, out var oldValue) && oldValue == value)
                {
                    return;
                }

                _properties[propertyName] = value;
                OnPropertyChanged("Item");
                OnPropertyChanged($"Item[{propertyName}]");
            }
        }

        // 添加动态属性
        public void Add(string propertyName, string value)
        {
            _properties[propertyName] = value;
            OnPropertyChanged("Item");
            OnPropertyChanged($"Item[{propertyName}]");
        }

        // 更新动态属性
        public void Update(string propertyName, string value)
        {
            if (_properties.TryGetValue(propertyName, out var oldValue) && oldValue == value)
            {
                return;
            }

            if (_properties.ContainsKey(propertyName))
            {
                _properties[propertyName] = value;
                OnPropertyChanged("Item");
                OnPropertyChanged($"Item[{propertyName}]");
            }
        }

        // 移除动态属性
        public void Remove(string propertyName)
        {
            if (_properties.ContainsKey(propertyName))
            {
                _properties.Remove(propertyName);
                OnPropertyChanged("Item");
                OnPropertyChanged($"Item[{propertyName}]");
            }
        }

        // 清空所有属性
        public void Clear()
        {
            var propertiesToClear = _properties.Keys.ToList();
            _properties.Clear();

            // 通知所有属性已更改
            OnPropertyChanged("Item");
            foreach (var propertyName in propertiesToClear)
            {
                OnPropertyChanged($"Item[{propertyName}]");
            }
        }
    }

}
