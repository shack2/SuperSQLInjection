using CommunityToolkit.Mvvm.ComponentModel;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace SuperSQLInjectionV2.Models
{
    /// <summary>
    /// 脚本库表格行（防护绕过-脚本库页的统一展示模型）：
    /// 包装同一磁盘脚本实体（config/rules/scripts/*.js）的两个内存视图之一——
    /// 变换类（payload/request）持有 EncodeToolModel（编码链节点），动态值类（extract/generate）持有 ScriptTamperModel。
    /// 属性委托到底层模型，编辑/启用/删除直接作用于源集合；动态值脚本不参与编码链排序（序号列留空、上移/下移/拖拽不适用）。
    /// </summary>
    public partial class ScriptLibRow : ViewModelBase
    {
        /// <summary>动态值类脚本（extract/generate）；变换类行为null</summary>
        public ScriptTamperModel? Token { get; private set; }

        /// <summary>变换类脚本（payload/request，编码链节点）；动态值类行为null</summary>
        public EncodeToolModel? Tool { get; private set; }

        /// <summary>是否编码链变换类（payload/request）</summary>
        public bool IsTransform => Tool != null;

        /// <summary>TableView行勾选（工具栏"删除选中"批量操作目标）</summary>
        [ObservableProperty]
        public partial bool RowChecked { get; set; }

        public string Name
        {
            get => Tool?.Name ?? Token?.Name ?? "";
            set
            {
                if (Tool != null)
                {
                    Tool.Name = value;
                }
                else if (Token != null)
                {
                    Token.Name = value;
                }
            }
        }

        public bool Enable
        {
            get => Tool?.Enable ?? Token?.Enable ?? false;
            set
            {
                if (Tool != null)
                {
                    Tool.Enable = value;
                }
                else if (Token != null)
                {
                    Token.Enable = value;
                }
            }
        }

        /// <summary>用途显示名（Payload变换/报文变换/响应提取/值生成）</summary>
        public string UsageName => Tool != null
            ? ScriptUsages.Name(ScriptUsages.FromScope(Tool.Scope))
            : ScriptUsages.Name(ScriptUsages.FromKind(Token?.Kind ?? 0));

        /// <summary>动态值脚本展示序号（编码链数量+集合内位置，RefreshScriptLibFilter 组装时赋号；变换类行不用，直接读 Tool.Seq）</summary>
        public int TokenSeq { get; set; }

        /// <summary>序号列文本（变换类=编码链加载/执行顺序；动态值=全库连续加载序号）</summary>
        public string SeqText => Tool != null ? Tool.Seq.ToString() : (TokenSeq > 0 ? TokenSeq.ToString() : "");

        /// <summary>功能说明（优先 //@description 元数据，空则取代码首行注释）</summary>
        public string DescText
        {
            get
            {
                if (Tool != null)
                {
                    return Tool.DescText;
                }
                string first = (Token?.Code ?? "").TrimStart().Split('\n')[0].Trim();
                return first.StartsWith("//", StringComparison.Ordinal) ? first.TrimStart('/').Trim() : "";
            }
        }

        private ScriptLibRow()
        {
        }

        public static ScriptLibRow FromTool(EncodeToolModel tool)
        {
            var row = new ScriptLibRow { Tool = tool };
            row.Hook(tool);
            return row;
        }

        public static ScriptLibRow FromToken(ScriptTamperModel token)
        {
            var row = new ScriptLibRow { Token = token };
            row.Hook(token);
            return row;
        }

        /// <summary>底层模型属性变化转发为行属性通知（名称/启用/用途/序号/说明等列实时刷新）</summary>
        private void Hook(INotifyPropertyChanged src)
        {
            src.PropertyChanged += (_, e) =>
            {
                switch (e.PropertyName)
                {
                    case nameof(Name):
                        OnPropertyChanged(nameof(Name));
                        break;
                    case nameof(Enable):
                        OnPropertyChanged(nameof(Enable));
                        break;
                    case nameof(EncodeToolModel.Scope):
                    case nameof(ScriptTamperModel.Kind):
                        OnPropertyChanged(nameof(UsageName));
                        break;
                    case nameof(EncodeToolModel.Seq):
                        OnPropertyChanged(nameof(SeqText));
                        break;
                    case nameof(EncodeToolModel.Key):
                    case nameof(EncodeToolModel.Description):
                    case "Code": //EncodeToolModel.Code / ScriptTamperModel.Code 同名
                        OnPropertyChanged(nameof(DescText));
                        break;
                }
            };
        }
    }
}
