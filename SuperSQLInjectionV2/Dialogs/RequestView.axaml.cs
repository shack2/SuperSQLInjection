using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using SuperSQLInjectionV2.Tools;

namespace SuperSQLInjectionV2.Dialogs;

public partial class RequestView : UserControl
{
    public RequestView()
    {
        InitializeComponent();

        //HTTP报文编辑器主题：与主界面一致的自定义xshd高亮（浅/深两套），跟随应用主题切换
        EditorThemeTool.ApplyHttpEditorTheme(RequestBox);
        EditorThemeTool.FollowAppTheme(RequestBox);
        //响应区用 HttpData 高亮（SQL报错指纹/HTML标签/hex段等响应特征）
        EditorThemeTool.ApplyHttpDataEditorTheme(ResponseBox);
        EditorThemeTool.FollowAppThemeData(ResponseBox);
    }



}