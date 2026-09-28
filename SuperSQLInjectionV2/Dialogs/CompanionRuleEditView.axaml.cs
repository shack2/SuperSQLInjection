using Avalonia.Controls;
using SuperSQLInjectionV2.Tools;

namespace SuperSQLInjectionV2.Dialogs;

public partial class CompanionRuleEditView : UserControl
{
    public CompanionRuleEditView()
    {
        InitializeComponent();
        //规则请求报文编辑器：与主界面请求报文一致的HTTP语法高亮（浅/暗主题跟随）
        var editors = new[] { PacketEditor };
        EditorThemeTool.ApplyHttpEditorTheme(editors);
        EditorThemeTool.FollowAppTheme(editors);
    }
}
