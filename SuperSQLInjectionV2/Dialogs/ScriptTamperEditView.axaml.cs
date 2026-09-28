using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using SuperSQLInjectionV2.Tools;

namespace SuperSQLInjectionV2.Dialogs;

public partial class ScriptTamperEditView : UserControl
{
    public ScriptTamperEditView()
    {
        InitializeComponent();

        //AvaloniaEdit 内置 JavaScript 高亮（JS-only 引擎，语法高亮固定为 JS），外观色随主题
        EditorThemeTool.ApplyJsEditorTheme(CodeEditor);
        EditorThemeTool.FollowAppThemeJs(CodeEditor);

        //Ctrl+滚轮缩放字体
        CodeEditor.AddHandler(PointerWheelChangedEvent, (o, i) =>
        {
            if (i.KeyModifiers != KeyModifiers.Control) return;
            if (i.Delta.Y > 0) CodeEditor.FontSize++;
            else CodeEditor.FontSize = CodeEditor.FontSize > 1 ? CodeEditor.FontSize - 1 : 1;
        }, RoutingStrategies.Bubble, true);
    }
}
