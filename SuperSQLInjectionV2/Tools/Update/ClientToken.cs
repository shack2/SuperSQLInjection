using System.Security.Cryptography;
using System.Text;

namespace SuperSQLInjectionV2.Tools.Update;

/// <summary>
/// 客户端访问令牌（AES-256-GCM）：加密 "unix毫秒时间戳|appId"，
/// 输出 base64url 字符串，供服务端校验（防无 Key 垃圾请求）。
/// 移植自 SoftUpdate.Client.Core。
/// </summary>
public static class ClientToken
{
    /// <summary>用十六进制 AES Key 生成令牌；Key 为空或非法时返回 null（不携带）。</summary>
    public static string? Create(string? hexKey, string appId)
    {
        if (string.IsNullOrWhiteSpace(hexKey)) return null;

        byte[] key;
        try { key = Convert.FromHexString(hexKey.Trim()); }
        catch { return null; }
        if (key.Length != 32) return null;

        var plain = Encoding.UTF8.GetBytes($"{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}|{appId}");
        var nonce = RandomNumberGenerator.GetBytes(12);
        var cipher = new byte[plain.Length + 16]; // 密文 + 16 字节 GCM tag
        using (var aes = new AesGcm(key, 16))
        {
            aes.Encrypt(nonce, plain, cipher.AsSpan(0, plain.Length), cipher.AsSpan(plain.Length), default);
        }

        return Convert.ToBase64String(nonce.Concat(cipher).ToArray())
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
