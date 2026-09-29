using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SuperSQLInjectionV2.Tools;
using System;
using System.Collections.Generic;
using System.Text;

namespace SuperSQLInjectionV2.ViewModels
{
    /// <summary>
    /// 编码转换工具
    /// </summary>
    public partial class EncodeToolsViewModel : ViewModelBase
    {
        [ObservableProperty] private string _input = "";

        [ObservableProperty] private string _output = "";

        [ObservableProperty] private string _selectedEncode = "URL编码";

        [ObservableProperty] private string _selectedDecode = "URL解码";

        public List<string> EncodeMethods { get; } =
        [
            "URL编码", "Base64", "ASCII", "Hex16进制", "MD5-16", "MD5-32", "Unicode", "HTML实体编码", "MySQL chr", "SQLServer char"
        ];

        public List<string> DecodeMethods { get; } =
        [
            "URL解码", "Base64", "ASCII", "Hex16进制", "Unicode", "HTML实体解码", "MySQL chr还原", "SQLServer char还原"
        ];

        /// <summary>
        /// 编码
        /// </summary>
        [RelayCommand]
        private void Encode()
        {
            if (string.IsNullOrEmpty(Input))
            {
                Log.Warning("请输入要编码的字符！");
                return;
            }
            try
            {
                switch (SelectedEncode)
                {
                    case "URL编码":
                        Output = URLEncode.UrlEncode(Input, Encoding.UTF8);
                        break;
                    case "Base64":
                        Output = Convert.ToBase64String(Encoding.UTF8.GetBytes(Input));
                        break;
                    case "ASCII":
                        Output = TextCodec.StringToAscii(Input);
                        break;
                    case "Hex16进制":
                        Output = TextCodec.StrToHex(Input, "UTF-8");
                        break;
                    case "MD5-16":
                        Output = MyTools.Md5_16(Input);
                        break;
                    case "MD5-32":
                        Output = MyTools.Md5_32(Input);
                        break;
                    case "Unicode":
                        Output = TextCodec.String2Unicode(Input);
                        break;
                    case "HTML实体编码":
                        Output = System.Net.WebUtility.HtmlEncode(Input);
                        break;
                    case "MySQL chr":
                        Output = TextCodec.StrToChrOrChar(Input, "chr", " ", "UTF-8");
                        break;
                    case "SQLServer char":
                        Output = TextCodec.StrToChrOrChar(Input, "char", " ", "UTF-8");
                        break;
                }
            }
            catch (Exception e)
            {
                Log.Show("编码发生异常！" + e.Message);
            }
        }

        /// <summary>
        /// 解码
        /// </summary>
        [RelayCommand]
        private void Decode()
        {
            if (string.IsNullOrEmpty(Input))
            {
                Log.Warning("请输入要解码的字符！");
                return;
            }
            try
            {
                Output = DecodeByMethod(SelectedDecode, Input);
            }
            catch (Exception e)
            {
                Log.Show("解码发生异常！" + e.Message);
            }
        }

        /// <summary>按解码方式名解码（编码工具页与请求日志右键解码菜单共用的唯一实现）</summary>
        public static string DecodeByMethod(string method, string input)
        {
            switch (method)
            {
                case "URL解码":
                    return System.Web.HttpUtility.UrlDecode(input);
                case "Base64":
                    return Encoding.UTF8.GetString(Convert.FromBase64String(input));
                case "ASCII":
                    return TextCodec.AsciiToString(input);
                case "Hex16进制":
                    return TextCodec.unHex(input, "UTF-8");
                case "Unicode":
                    return UnicodeToString(input);
                case "HTML实体解码":
                    return System.Net.WebUtility.HtmlDecode(input);
                case "MySQL chr还原":
                    return TextCodec.ChrOrCharToStr(input, "chr", "UTF-8");
                case "SQLServer char还原":
                    return TextCodec.ChrOrCharToStr(input, "char", "UTF-8");
                default:
                    return input;
            }
        }

        /// <summary>
        /// Unicode（\\uXXXX）转字符串
        /// </summary>
        private static string UnicodeToString(string source)
        {
            return System.Text.RegularExpressions.Regex.Replace(source, @"\\u([0-9a-fA-F]{4})", m =>
            {
                return ((char)Convert.ToInt32(m.Groups[1].Value, 16)).ToString();
            });
        }


        /// <summary>
        /// 将结果交换到输入框
        /// </summary>
        [RelayCommand]
        private void Swap()
        {
            Input = Output;
        }

        /// <summary>
        /// 清空输入输出
        /// </summary>
        [RelayCommand]
        private void Clear()
        {
            Input = "";
            Output = "";
        }
    }
}
