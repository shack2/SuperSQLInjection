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

    public enum DataValueState
    {
        Normal,
        Null,
        Empty,
        Failed,
        Truncated
    }

    /// <summary>动态表格行；原始值与读取状态分开保存，避免NULL、空串和失败都显示为空。</summary>
    public class DynamicDataItem : ObservableObject
    {
        private readonly Dictionary<string, string> _properties = new();
        private readonly Dictionary<string, DataValueState> _states = new();

        /// <summary>表格/复制/CSV使用的显示值；原始值通过GetRawValue读取。</summary>
        public string this[string propertyName]
        {
            get => GetDisplayValue(propertyName);
            set => Set(propertyName, value, InferState(value));
        }

        public string GetRawValue(string propertyName)
        {
            return _properties.TryGetValue(propertyName, out string? value) ? value : string.Empty;
        }

        public DataValueState GetState(string propertyName)
        {
            return _states.TryGetValue(propertyName, out DataValueState state) ? state : DataValueState.Empty;
        }

        public string GetDisplayValue(string propertyName)
        {
            string value = GetRawValue(propertyName);
            return GetState(propertyName) switch
            {
                DataValueState.Null => "[NULL]",
                DataValueState.Failed => "[读取失败]",
                DataValueState.Truncated => "[截断] " + value,
                _ => value
            };
        }

        public void Add(string propertyName, string value) => Set(propertyName, value, InferState(value));

        public void Add(string propertyName, string? value, DataValueState state)
        {
            Set(propertyName, value ?? string.Empty, state);
        }

        public void Update(string propertyName, string value)
        {
            if (_properties.ContainsKey(propertyName)) Set(propertyName, value, InferState(value));
        }

        public void Update(string propertyName, string? value, DataValueState state)
        {
            if (_properties.ContainsKey(propertyName)) Set(propertyName, value ?? string.Empty, state);
        }

        public void SetState(string propertyName, DataValueState state)
        {
            if (_properties.ContainsKey(propertyName)) Set(propertyName, GetRawValue(propertyName), state);
        }

        private void Set(string propertyName, string value, DataValueState state)
        {
            if (_properties.TryGetValue(propertyName, out string? oldValue)
                && oldValue == value && GetState(propertyName) == state) return;
            _properties[propertyName] = value;
            _states[propertyName] = state;
            OnPropertyChanged("Item");
            OnPropertyChanged($"Item[{propertyName}]");
        }

        private static DataValueState InferState(string? value)
        {
            return value == null ? DataValueState.Failed : value.Length == 0 ? DataValueState.Empty : DataValueState.Normal;
        }

        public void Remove(string propertyName)
        {
            if (_properties.Remove(propertyName))
            {
                _states.Remove(propertyName);
                OnPropertyChanged("Item");
                OnPropertyChanged($"Item[{propertyName}]");
            }
        }

        public void Clear()
        {
            var properties = _properties.Keys.ToList();
            _properties.Clear();
            _states.Clear();
            OnPropertyChanged("Item");
            foreach (string propertyName in properties) OnPropertyChanged($"Item[{propertyName}]");
        }
    }

}
