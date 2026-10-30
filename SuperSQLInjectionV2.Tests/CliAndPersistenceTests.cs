using SuperSQLInjectionV2.Cmd;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Tools;
using System.Text;
using Xunit;

namespace SuperSQLInjectionV2.Tests;

public sealed class CliAndPersistenceTests
{
    [Fact]
    public void Cli_ParsesNetworkOutputAndSupportMatrixOptions()
    {
        CliOptions opt = CliOptions.Parse(["--cookie-jar", "--auth-type=Digest", "--auth-cred=u:p:x", "--batch-output=result.csv", "--support-matrix=matrix.json", "-u", "http://localhost/"]);
        Assert.True(opt.CookieJar);
        Assert.Equal("Digest", opt.AuthType);
        Assert.Equal("u:p:x", opt.AuthCred);
        Assert.Equal("result.csv", opt.BatchOutput);
        Assert.Equal("matrix.json", opt.SupportMatrix);
        Assert.Equal("http://localhost/", opt.Url);
    }

    [Fact]
    public void Cli_RejectsUnknownOption()
    {
        Assert.Throws<ArgumentException>(() => CliOptions.Parse(["--not-a-real-option"]));
    }

    [Fact]
    public void Cli_ParsesForceSsl()
    {
        CliOptions opt = CliOptions.Parse(["-r", "request.txt", "--force-ssl"]);
        Assert.True(opt.ForceSsl);
    }

    [Fact]
    public void RawRequest_AppliesHttpsAndIpv6TargetSettings()
    {
        var absolute = new AppConfig();
        Program.ApplyHostFromRequest(absolute, "GET https://example.test/login?id=1 HTTP/1.1\r\nHost: example.test\r\n\r\n");
        Assert.True(absolute.IsSSL);
        Assert.Equal(443, absolute.Port);
        Assert.Equal("example.test", absolute.Host);

        var forced = new AppConfig();
        Program.ApplyHostFromRequest(forced, "GET /?id=1 HTTP/1.1\r\nHost: [::1]:8443\r\n\r\n", forceSsl: true);
        Assert.True(forced.IsSSL);
        Assert.Equal(8443, forced.Port);
        Assert.Equal("::1", forced.Host);
    }

    [Fact]
    public void DumpRange_ConvertsInclusiveRowsToOffsetAndCount()
    {
        Assert.Equal((4, 6), Program.GetDumpRange(new CliOptions { Start = 5, Stop = 10 }));
        Assert.Equal((2, 0), Program.GetDumpRange(new CliOptions { Start = 3 }));
        Assert.Throws<ArgumentException>(() => Program.GetDumpRange(new CliOptions { Start = 10, Stop = 5 }));
        Assert.Throws<ArgumentException>(() => Program.GetDumpRange(new CliOptions { Start = 0 }));
    }

    [Fact]
    public void SessionFingerprint_ChangesWithRequestAndDetectionSettings()
    {
        var config = new AppConfig();
        var opt = new CliOptions { Level = 1, RulesDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config", "rules") };
        const string request = "GET /?id=1 HTTP/1.1\r\nHost: localhost\r\n\r\n";
        string original = SessionStore.Fingerprint(config, opt, request);
        Assert.Equal(original, SessionStore.Fingerprint(config, opt, request));
        opt.Level = 2;
        Assert.NotEqual(original, SessionStore.Fingerprint(config, opt, request));
        opt.Level = 1;
        Assert.NotEqual(original, SessionStore.Fingerprint(config, opt, request.Replace("id=1", "id=2")));
    }

    [Fact]
    public void AtomicFile_ReplacesContentWithoutTempArtifacts()
    {
        string dir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, ".test-data", Guid.NewGuid().ToString("N"));
        string file = Path.Combine(dir, "state.json");
        try
        {
            AtomicFile.WriteAllText(file, "first", new UTF8Encoding(false));
            AtomicFile.WriteAllText(file, "second", new UTF8Encoding(false));
            Assert.Equal("second", File.ReadAllText(file));
            Assert.Equal("state.json", Path.GetFileName(Assert.Single(Directory.GetFiles(dir))));
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }
}
