using SuperSQLInjectionV2.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SuperSQLInjectionV2.Payload
{
    /// <summary>单个族/Fork合并后的真实模板能力，不维护第二份手工支持表。</summary>
    public sealed class SupportMatrixEntry
    {
        public string Database { get; set; } = "";
        public string Fork { get; set; } = "";
        public string Template { get; set; } = "";
        public bool OverlayApplied { get; set; }
        public string EnvironmentFile { get; set; } = "";
        public bool EnvironmentVariables { get; set; }
        public bool BooleanChannel { get; set; }
        public bool UnionChannel { get; set; }
        public bool StablePaging { get; set; }
        public bool ErrorChannel { get; set; }
        public bool TimeChannel { get; set; }
        public bool DnsChannel { get; set; }
        public string[] ErrorMethods { get; set; } = [];
        public string[] FileKeys { get; set; } = [];
        public string[] CommandKeys { get; set; } = [];
    }

    public static class SupportMatrixGenerator
    {
        /// <summary>
        /// 按DbProfile和BasePayload.ReadTemplateMerged实时生成支持矩阵。
        /// Fork overlay空值会删除继承key，因此这里不能直接读族模板或磁盘单行判断能力。
        /// </summary>
        public static List<SupportMatrixEntry> Generate()
        {
            var rows = new List<SupportMatrixEntry>();
            foreach (DBType dbType in Enum.GetValues<DBType>())
            {
                if (dbType == DBType.UnKnow || DbProfile.Get(dbType).ForkMode) continue;
                rows.Add(Build(dbType, ""));
                foreach (string fork in DbProfile.ForkDisplayNamesOf(dbType))
                {
                    rows.Add(Build(dbType, fork));
                }
            }
            return rows;
        }

        private static SupportMatrixEntry Build(DBType family, string fork)
        {
            string template = DbProfile.TemplatePathOf(family);
            bool overlay = false;
            if (!string.IsNullOrWhiteSpace(fork))
            {
                string forkPath = "config/payload/fork_" + DbProfile.ForkKeyOf(fork) + ".txt";
                if (File.Exists(Resolve(forkPath)))
                {
                    template = forkPath;
                    overlay = true;
                }
            }
            Dictionary<string, string> sql = BasePayload.ReadTemplateMerged(template);

            DBType envType = family;
            if (!string.IsNullOrWhiteSpace(fork))
            {
                DBType candidate = DbProfile.DbTypeForName(fork);
                if (candidate != DBType.UnKnow && DbProfile.Get(candidate).ForkMode) envType = candidate;
            }
            string? vers = DbProfile.VersPathOf(envType);
            string envPath = vers?.TrimStart('/') ?? "";
            bool hasEnv = !string.IsNullOrEmpty(envPath) && File.Exists(Resolve(envPath));

            return new SupportMatrixEntry
            {
                Database = DbProfile.DbmsNameOf(family),
                Fork = fork,
                Template = template,
                OverlayApplied = overlay,
                EnvironmentFile = hasEnv ? envPath : "",
                EnvironmentVariables = hasEnv,
                BooleanChannel = Has(sql, "BoolData"),
                UnionChannel = Has(sql, "UnionAll") && Has(sql, "UnionData"),
                StablePaging = Has(sql, "DataValueOrdered") && Has(sql, "DataValueKeyset")
                    && Has(sql, "UnionDataOrdered") && Has(sql, "UnionDataKeyset"),
                ErrorChannel = Has(sql, "ErrorData") || sql.Keys.Any(k => k.StartsWith(BasePayload.ErrorVariantPrefix, StringComparison.OrdinalIgnoreCase)),
                TimeChannel = Has(sql, "SleepBoolData"),
                DnsChannel = sql.TryGetValue("DnsChannel", out string? dns) && string.Equals(dns?.Trim(), "yes", StringComparison.OrdinalIgnoreCase),
                ErrorMethods = sql.Keys.Where(k => k.Equals("ErrorData", StringComparison.OrdinalIgnoreCase)
                        || k.StartsWith(BasePayload.ErrorVariantPrefix, StringComparison.OrdinalIgnoreCase)).Order(StringComparer.OrdinalIgnoreCase).ToArray(),
                FileKeys = sql.Keys.Where(k => k.StartsWith("File", StringComparison.OrdinalIgnoreCase)).Order(StringComparer.OrdinalIgnoreCase).ToArray(),
                CommandKeys = sql.Keys.Where(k => k.StartsWith("Cmd", StringComparison.OrdinalIgnoreCase)).Order(StringComparer.OrdinalIgnoreCase).ToArray()
            };
        }

        private static bool Has(Dictionary<string, string> sql, string key)
        {
            return sql.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value);
        }

        private static string Resolve(string relative)
        {
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, relative.Replace('/', Path.DirectorySeparatorChar));
        }
    }
}
