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
            "URL编码", "Base64", "ASCII", "Hex16进制", "MD5-16", "MD5-32", "Unicode", "MySQL chr", "SQLServer char"
        ];

        public List<string> DecodeMethods { get; } =
        [
            "URL解码", "Base64", "ASCII", "Hex16进制", "Unicode", "MySQL chr还原", "SQLServer char还原"
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
                switch (SelectedDecode)
                {
                    case "URL解码":
                        Output = System.Web.HttpUtility.UrlDecode(Input);
                        break;
                    case "Base64":
                        Output = Encoding.UTF8.GetString(Convert.FromBase64String(Input));
                        break;
                    case "ASCII":
                        Output = TextCodec.AsciiToString(Input);
                        break;
                    case "Hex16进制":
                        Output = TextCodec.unHex(Input, "UTF-8");
                        break;
                    case "Unicode":
                        Output = UnicodeToString(Input);
                        break;
                    case "MySQL chr还原":
                        Output = TextCodec.ChrOrCharToStr(Input, "chr", "UTF-8");
                        break;
                    case "SQLServer char还原":
                        Output = TextCodec.ChrOrCharToStr(Input, "char", "UTF-8");
                        break;
                }
            }
            catch (Exception e)
            {
                Log.Show("解码发生异常！" + e.Message);
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
