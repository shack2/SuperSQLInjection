using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Tools.Http;
using System.IO.Compression;
using System.Text;
using Xunit;
using HttpMethod = SuperSQLInjectionV2.Tools.Http.HttpMethod;

namespace SuperSQLInjectionV2.Tests;

public sealed class HttpProtocolTests
{
    private static HttpRequest Request(string raw)
    {
        var config = new AppConfig();
        return new HttpRequest(config, raw);
    }

    [Fact]
    public void Redirect307_PreservesMethodAndBody_AndStripsCrossOriginSecrets()
    {
        var request = Request("POST /login HTTP/1.1\r\nHost: example.com\r\nCookie: a=b\r\nAuthorization: Bearer secret\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\na=1&b=2");
        bool applied = HTTPTool.ApplyRedirect(request, "https://other.example/next?q=1", 307);
        Assert.True(applied);
        Assert.Equal(HttpMethod.POST, request.Method);
        Assert.Equal("a=1&b=2", request.BodyText);
        Assert.Equal("other.example", request.Host);
        Assert.True(request.IsSSL);
        Assert.DoesNotContain("Cookie:", request.HeaderAndBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Authorization:", request.HeaderAndBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("POST /next?q=1 HTTP/1.1", request.HeaderAndBody);
    }

    [Fact]
    public void Redirect303_TurnsPostIntoGet_AndDropsBody()
    {
        var request = Request("POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\nbody");
        Assert.True(HTTPTool.ApplyRedirect(request, "/result", 303));
        Assert.Equal(HttpMethod.GET, request.Method);
        Assert.Null(request.Body);
        Assert.StartsWith("GET /result HTTP/1.1", request.HeaderAndBody);
        Assert.DoesNotContain("Content-Type:", request.HeaderAndBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("body", request.HeaderAndBody, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Redirect302_NonPostKeepsMethod()
    {
        var request = Request("PUT /item HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\n\r\nx");
        Assert.True(HTTPTool.ApplyRedirect(request, "/item2", 302));
        Assert.Equal(HttpMethod.PUT, request.Method);
        Assert.Equal("x", request.BodyText);
    }

    [Fact]
    public void RetryAfter_SupportsSecondsAndHttpDate()
    {
        var config = new AppConfig();
        var response = new HttpResponse(config);
        response.Headers["Retry-After"] = "2";
        Assert.Equal(2000, HTTPTool.GetRetryDelayMs(response, 1));
        response.Headers["Retry-After"] = DateTimeOffset.UtcNow.AddSeconds(4).ToString("R");
        int delay = HTTPTool.GetRetryDelayMs(response, 1);
        Assert.InRange(delay, 250, 5000);
    }

    [Fact]
    public async Task ContentLength_ShortReadIsDetected()
    {
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes("abc"));
        using var reader = new HttpStreamReader(stream, 2);
        using var body = new MemoryStream();
        long read = await reader.ReadExactAsync(body, 5, CancellationToken.None);
        Assert.Equal(3, read);
        Assert.NotEqual(5, read);
        Assert.Equal("abc", Encoding.ASCII.GetString(body.ToArray()));
    }

    [Fact]
    public async Task Chunked_ReadsAcrossBufferBoundaries_AndRejectsIncomplete()
    {
        byte[] raw = Encoding.ASCII.GetBytes("4\r\nWiki\r\n5;ext=x\r\npedia\r\n0\r\nX-End: yes\r\n\r\n");
        using (var reader = new HttpStreamReader(new MemoryStream(raw), 3))
        using (var body = new MemoryStream())
        {
            Assert.True(await HTTPTool.ReadChunkedAsync(reader, body, CancellationToken.None, 1024));
            Assert.Equal("Wikipedia", Encoding.ASCII.GetString(body.ToArray()));
        }
        using var incompleteReader = new HttpStreamReader(new MemoryStream(Encoding.ASCII.GetBytes("5\r\nabc")), 2);
        using var incompleteBody = new MemoryStream();
        Assert.False(await HTTPTool.ReadChunkedAsync(incompleteReader, incompleteBody, CancellationToken.None, 1024));
    }

    [Fact]
    public async Task BodyLimits_CoverRawAndDecompressedSizes()
    {
        var config = new AppConfig { MaxDecompressedBodyBytes = 4 };
        byte[] compressed;
        using (var ms = new MemoryStream())
        {
            using (var gzip = new GZipStream(ms, CompressionMode.Compress, true))
                gzip.Write(Encoding.ASCII.GetBytes("0123456789"));
            compressed = ms.ToArray();
        }
        var response = new HttpResponse(config);
        response.Headers[HttpConst.Content_Encoding] = "gzip";
        response.BodyData = new MemoryStream(compressed);
        Assert.True(response.IsTruncated);
        Assert.False(response.IsBodyComplete);
        Assert.Empty(response.Body!);

        config.MaxResponseBodyBytes = 2;
        var rawResponse = new HttpResponse(config);
        await using var raw = new MemoryStream(Encoding.ASCII.GetBytes("abc"));
        using var reader = new HttpStreamReader(raw);
        await Assert.ThrowsAsync<HttpResponseLimitException>(() => reader.ReadToEndAsync(new MemoryStream(), CancellationToken.None, config.MaxResponseBodyBytes));
    }
}
