using Avalonia;
using Avalonia.Controls;
using Avalonia.Data;
using Avalonia.Layout;
using Avalonia.Threading;
using System.Collections.ObjectModel;

namespace SuperSQLInjectionV2.Models.Data
{
    /// <summary>
    /// TableView 列构建器（表数据动态列，随查询结果列集运行时生成）- AOT友好
    /// </summary>
    public static class DataGridColumnBuilder
    {
        public static readonly AttachedProperty<ObservableCollection<ColumnInfo>> ColumnsProperty =
            AvaloniaProperty.RegisterAttached<TableView, ObservableCollection<ColumnInfo>>(
                "Columns",
                typeof(DataGridColumnBuilder)
            );

        static DataGridColumnBuilder()
        {
            ColumnsProperty.Changed.AddClassHandler<TableView>((grid, e) =>
            {
                if (e.NewValue is ObservableCollection<ColumnInfo> columns)
                {
                    // 监听集合变化
                    columns.CollectionChanged += (s, args) => UpdateGridColumns(grid, columns);
                    UpdateGridColumns(grid, columns);
                }
            });
        }

        /// <summary>
        /// 获取列配置
        /// </summary>
        public static ObservableCollection<ColumnInfo> GetColumns(TableView element)
        {
            return element.GetValue(ColumnsProperty);
        }

        /// <summary>
        /// 设置列配置
        /// </summary>
        public static void SetColumns(TableView element, ObservableCollection<ColumnInfo> value)
        {
            element.SetValue(ColumnsProperty, value);
        }

        /// <summary>
        /// 更新 TableView 的列
        /// </summary>
        private static void UpdateGridColumns(TableView grid, ObservableCollection<ColumnInfo> columns)
        {
            Dispatcher.UIThread.Post( ()=>
            {
                // 清空现有列
                grid.Columns.Clear();

                // 根据列配置创建新的列
                foreach (var colInfo in columns)
                {
                    var column = CreateColumn(colInfo);
                    grid.Columns.Add(column);
                }
            }, DispatcherPriority.Background);
        }

        /// <summary>
        /// 根据列配置创建 TableViewColumn（TableView只读，无MinWidth，退化为Auto宽度）
        /// </summary>
        /// <remarks>
        /// 运行时反射绑定[PropertyName]索引器：DynamicDataItem是自有类型，索引器通过DynamicDependency保活，
        /// 不会被裁剪，AOT下绑定工作正常，故抑制IL2026/IL3050。
        /// </remarks>
        [System.Diagnostics.CodeAnalysis.DynamicDependency(
            System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicProperties, typeof(DynamicDataItem))]
        [System.Diagnostics.CodeAnalysis.UnconditionalSuppressMessage("Trimming", "IL2026",
            Justification = "动态列绑定到自有类型DynamicDataItem的索引器，已通过DynamicDependency保活")]
        [System.Diagnostics.CodeAnalysis.UnconditionalSuppressMessage("AOT", "IL3050",
            Justification = "动态列绑定到自有类型DynamicDataItem的索引器，无需动态代码生成")]
        private static TableViewColumn CreateColumn(ColumnInfo colInfo)
        {
            var column = new TableViewColumn
            {
                Header = colInfo.Header,
                Binding = new Binding($"[{colInfo.PropertyName}]"),
                Width = GridLength.Auto,
                //列头与单元格内容统一居中（表数据为短值场景，居中更易扫读）
                HorizontalContentAlignment = HorizontalAlignment.Center
            };

            return column;
        }
    }
}
