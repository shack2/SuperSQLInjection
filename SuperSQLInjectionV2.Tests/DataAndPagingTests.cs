using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Models.Data;
using SuperSQLInjectionV2.Payload;
using SuperSQLInjectionV2.Tools;
using Xunit;

namespace SuperSQLInjectionV2.Tests;

public sealed class DataAndPagingTests
{
    [Theory]
    [InlineData("=1+1", "\"'=1+1\"")]
    [InlineData("\t@cmd", "\"'\t@cmd\"")]
    [InlineData("normal", "\"normal\"")]
    [InlineData("a\"b", "\"a\"\"b\"")]
    public void Csv_ProtectsFormulaAndEscapesQuotes(string input, string expected)
    {
        Assert.Equal(expected, CsvExport.Cell(input));
        Assert.Equal("\"" + input.Replace("\"", "\"\"") + "\"", CsvExport.Cell(input, false));
    }

    [Fact]
    public void Fingerprint_DistinguishesPathRequestAndParameter()
    {
        string a = TargetFingerprint.Create("localhost", 80, false, "GET /a?id=1 HTTP/1.1\r\nHost: localhost\r\n\r\n", "id");
        string b = TargetFingerprint.Create("localhost", 80, false, "GET /b?id=1 HTTP/1.1\r\nHost: localhost\r\n\r\n", "id");
        string c = TargetFingerprint.Create("localhost", 80, false, "GET /a?id=2 HTTP/1.1\r\nHost: localhost\r\n\r\n", "id");
        Assert.NotEqual(a, b);
        Assert.NotEqual(a, c);
        Assert.Equal(a, TargetFingerprint.Create("localhost", 80, false, "GET /a?id=1 HTTP/1.1\r\nHost: localhost\r\n\r\n", "id"));
    }

    [Fact]
    public void DataCell_PreservesEmptyNullFailureAndTruncationStates()
    {
        var row = new DynamicDataItem();
        row.Add("empty", "", DataValueState.Empty);
        row.Add("null", null, DataValueState.Null);
        row.Add("failed", null, DataValueState.Failed);
        row.Add("cut", "abc", DataValueState.Truncated);
        Assert.Equal("", row["empty"]);
        Assert.Equal("[NULL]", row["null"]);
        Assert.Equal("[读取失败]", row["failed"]);
        Assert.Equal("[截断] abc", row["cut"]);
        Assert.Equal(DataValueState.Empty, row.GetState("empty"));
        Assert.Equal(DataValueState.Null, row.GetState("null"));
    }

    [Fact]
    public void StablePaging_UsesOrderedOffsetThenKeysetAndPreservesWhere()
    {
        var bp = new BasePayload(DBType.MySQL);
        IDbDialect dialect = DialectFactory.Create(DBType.MySQL, bp);
        var dp = new DumpDataParam(new List<string> { "id" }, "shop", "users", 3)
        {
            StableKey = "id",
            Where = "where enabled=1 and name='a'"
        };
        string first = dialect.DataValue(dp);
        Assert.Contains("order by id", first);
        Assert.Contains("limit 3,1", first);
        Assert.DoesNotContain("id>'", first);

        dp.LastKeyValue = "O'Reilly";
        string next = dialect.DataValue(dp);
        Assert.Contains("where (enabled=1 and name='a') and id>'O''Reilly'", next);
        Assert.Contains("order by id limit 1)", next);
        Assert.DoesNotContain("limit 3,1", next);
    }

    [Fact]
    public void StablePaging_UnionUsesKeysetWithoutOffset()
    {
        var session = new PayloadSession();
        session.Init(DBType.PostgreSQL);
        using var scope = PayloadFactory.Activate(session);
        var dp = new DumpDataParam(new List<string> { "id", "name" }, "public", "users", 4, 2)
        {
            StableKey = "id",
            LastKeyValue = "41",
            Where = "enabled"
        };
        string sql = session.Dialect.UnionData(dp);
        Assert.Contains("where (enabled) and id>'41'", sql);
        Assert.Contains("order by id limit 1", sql);
        Assert.DoesNotContain("offset", sql, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SupportMatrix_UsesMergedOverlaySemantics()
    {
        var rows = SupportMatrixGenerator.Generate();
        SupportMatrixEntry mysql = rows.Single(r => r.Database == "MySQL" && r.Fork == "");
        Assert.True(mysql.StablePaging);
        Assert.True(mysql.ErrorChannel);
        SupportMatrixEntry openGauss = rows.Single(r => r.Fork == "openGauss");
        Assert.True(openGauss.OverlayApplied);
        Assert.False(openGauss.DnsChannel);
        Assert.DoesNotContain("CmdExec", openGauss.CommandKeys);
        Assert.DoesNotContain("FileReadCopy", openGauss.FileKeys);
        SupportMatrixEntry access = rows.Single(r => r.Database == "Microsoft Access" && r.Fork == "");
        Assert.False(access.EnvironmentVariables);
        Assert.False(access.StablePaging);
    }
}
