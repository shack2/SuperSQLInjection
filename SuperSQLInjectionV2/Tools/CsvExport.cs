namespace SuperSQLInjectionV2.Tools;

/// <summary>CSV导出统一转义；默认阻止Excel将外部数据解释为公式。</summary>
public static class CsvExport
{
    /// <param name="protectFormula">true时在危险单元格前加英文单引号；false保留原始文本。</param>
    public static string Cell(string? value, bool protectFormula = true)
    {
        value ??= "";
        if (protectFormula && IsFormulaLike(value))
        {
            value = "'" + value;
        }
        return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }

    public static bool IsFormulaLike(string value)
    {
        if (string.IsNullOrEmpty(value)) return false;
        int i = 0;
        while (i < value.Length && (value[i] == ' ' || value[i] == '\t')) i++;
        if (i >= value.Length) return false;
        return value[i] is '=' or '+' or '-' or '@' or '\r' or '\n';
    }
}
