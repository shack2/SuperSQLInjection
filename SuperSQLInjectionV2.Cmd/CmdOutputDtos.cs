using System.Text.Json.Serialization;

namespace SuperSQLInjectionV2.Cmd;

/// <summary>批量检测 JSON 输出 DTO；显式类型保证 Native AOT 可源生成序列化。</summary>
internal sealed class BatchResultJson
{
    [JsonPropertyName("url")] public string Url { get; set; } = "";
    [JsonPropertyName("status")] public string Status { get; set; } = "";
    [JsonPropertyName("elapsedMs")] public long ElapsedMs { get; set; }
    [JsonPropertyName("resumed")] public bool Resumed { get; set; }
    [JsonPropertyName("error")] public string Error { get; set; } = "";
    [JsonPropertyName("hits")] public BatchHitJson[] Hits { get; set; } = [];
}

internal sealed class BatchHitJson
{
    [JsonPropertyName("parameter")] public string? Parameter { get; set; }
    [JsonPropertyName("technique")] public string Technique { get; set; } = "";
    [JsonPropertyName("dbms")] public string Dbms { get; set; } = "";
    [JsonPropertyName("fork")] public string? Fork { get; set; }
    [JsonPropertyName("payload")] public string? Payload { get; set; }
}
