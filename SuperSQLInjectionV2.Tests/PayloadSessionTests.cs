using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Payload;
using Xunit;

namespace SuperSQLInjectionV2.Tests;

public sealed class PayloadSessionTests
{
    [Fact]
    public async Task ConcurrentTargets_DoNotShareDialectOrEchoMarkers()
    {
        var mysql = new AppConfig();
        mysql.DataConfig.SelectedDBType = DBType.MySQL;
        mysql.Payload.Markers.Use("my_start", "my_end", "my_split", mysql.Payload.Base);
        var sqlite = new AppConfig();
        sqlite.DataConfig.SelectedDBType = DBType.SQLite;
        sqlite.Payload.Markers.Use("lite_start", "lite_end", "lite_split", sqlite.Payload.Base);
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        async Task<(string start, string split, string dbNames)> Read(AppConfig config)
        {
            using var scope = PayloadFactory.Activate(config);
            await gate.Task;
            await Task.Yield();
            return (EchoMarkers.Start, EchoMarkers.Split, PayloadFactory.BasePayload.DBNames);
        }

        Task<(string start, string split, string dbNames)> t1 = Read(mysql);
        Task<(string start, string split, string dbNames)> t2 = Read(sqlite);
        gate.SetResult();
        var results = await Task.WhenAll(t1, t2);
        Assert.Equal("my_start", results[0].start);
        Assert.Equal("my_split", results[0].split);
        Assert.Equal("lite_start", results[1].start);
        Assert.Equal("lite_split", results[1].split);
        Assert.NotEqual(results[0].dbNames, results[1].dbNames);
        Assert.Same(mysql.Payload.Base, mysql.Payload.Dialect.Payload);
        Assert.Same(sqlite.Payload.Base, sqlite.Payload.Dialect.Payload);
    }

    [Fact]
    public void NestedScope_RestoresPreviousSession_AndUdfStateIsPerConfig()
    {
        PayloadSession outer = PayloadFactory.Current;
        var a = new AppConfig();
        var b = new AppConfig();
        a.UdfSession.MySql.InstalledPath = "/tmp/a.so";
        a.UdfSession.MySql.Sha256 = "abc";
        Assert.Empty(b.UdfSession.PendingSummary());
        using (PayloadFactory.Activate(a))
        {
            Assert.Same(a.Payload, PayloadFactory.Current);
            using (PayloadFactory.Activate(b)) Assert.Same(b.Payload, PayloadFactory.Current);
            Assert.Same(a.Payload, PayloadFactory.Current);
        }
        Assert.Same(outer, PayloadFactory.Current);
        Assert.Contains("/tmp/a.so", a.UdfSession.PendingSummary());
        a.UdfSession.MySql.Reset();
        Assert.Empty(a.UdfSession.PendingSummary());
    }
}
