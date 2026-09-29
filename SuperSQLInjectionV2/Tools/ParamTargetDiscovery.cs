using System.Collections.Generic;
using System.Text.RegularExpressions;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Tools.Http;

namespace SuperSQLInjectionV2.Tools
{
    /// <summary>
    /// 扩展注入位置的检测目标枚举（GUI 检测与 CLI 共用，保证两端参数发现面一致）：
    /// URI路径段（数字/hex段任意level）、JSON体/XML体/Multipart（任意level）、
    /// Cookie键值（level>=2）、User-Agent/Referer/Host头（level>=3）。
    /// Query/Form 主参数由调用方各自解析（GUI 取编辑器标记参数，CLI 走 DiscoverParams）。
    /// </summary>
    public static class ParamTargetDiscovery
    {
        public readonly record struct Target(string Name, string Value, ParamPlace Place, string Header, string Desc, int UriIdx);

        public static List<Target> DiscoverExtended(HttpRequest request, string requestTxt, int level)
        {
            var targets = new List<Target>();

            //URI路径段自动识别：数字段与hex/uuid形态段（RESTful 风格 /api/user/1/ 的id位）任意level都测
            foreach (var seg in RequestRewriter.GetUriSegments(requestTxt))
            {
                if (Regex.IsMatch(seg.value, @"^-?\d+(\.\d+)?$") || Regex.IsMatch(seg.value, @"^[0-9a-fA-F]{8,}$"))
                {
                    targets.Add(new Target("uri_seg_" + (seg.index + 1), seg.value, ParamPlace.Uri, "", "URI路径段[" + (seg.index + 1) + "]", seg.index));
                }
            }

            if (request.IsJsonBody)
            {
                foreach (var kv in request.JsonParams)
                {
                    if (ConstData.JumpkeyList.ContainsKey(kv.Key)) continue;
                    targets.Add(new Target(kv.Key, kv.Value, ParamPlace.BodyJson, "", "JSON体", -1));
                }
            }
            if (request.IsXmlBody)
            {
                //SOAP/XML结构化注入：叶子元素文本作为注入参数（任意level）
                foreach (var kv in request.XmlParams)
                {
                    if (ConstData.JumpkeyList.ContainsKey(kv.Key)) continue;
                    targets.Add(new Target(kv.Key, kv.Value, ParamPlace.BodyXml, "", "XML/SOAP体", -1));
                }
            }
            if (request.IsMultipartBody)
            {
                foreach (var kv in request.MultipartParams)
                {
                    if (ConstData.JumpkeyList.ContainsKey(kv.Key)) continue;
                    targets.Add(new Target(kv.Key, kv.Value, ParamPlace.BodyMultipart, "", "Multipart表单", -1));
                }
            }
            if (level >= 2)
            {
                foreach (var kv in request.CookieParams)
                {
                    if (ConstData.JumpkeyList.ContainsKey(kv.Key)) continue;
                    targets.Add(new Target(kv.Key, kv.Value, ParamPlace.Cookie, "", "Cookie", -1));
                }
            }
            if (level >= 3)
            {
                string? ua = request.GetHeader("User-Agent");
                if (ua != null) targets.Add(new Target("User-Agent", ua, ParamPlace.Header, "User-Agent", "HTTP头", -1));
                string? referer = request.GetHeader("Referer");
                if (referer != null) targets.Add(new Target("Referer", referer, ParamPlace.Header, "Referer", "HTTP头", -1));
                //Host头自动检测（虚拟主机路由/日志记录场景的注入面；连接按URL寻址不受影响，仅改写头文本）
                string? host = request.GetHeader("Host");
                if (!string.IsNullOrEmpty(host))
                {
                    targets.Add(new Target("Host", host, ParamPlace.Header, "Host", "HTTP头", -1));
                }
            }
            return targets;
        }
    }
}
