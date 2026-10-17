using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using ZfTools.Data;

namespace ZfTools.Services;

public sealed class DssService(ToolDbContext db, IConfiguration configuration, ILogger<DssService> logger, IDataProtectionProvider protection)
{
    private readonly IDataProtector secretProtector = protection.CreateProtector("ZfTools.DssSupplierSecrets.v1");
    public async Task<(bool Success, string? Signature, string? Error)> SignAsync(AppUser user, int keyId, string mode, string input, CancellationToken ct)
    {
        if (user.Module != ToolModule.Dss || user.DssProjectId is null)
            return (false, null, "DSS 账号未绑定有效项目。");

        var key = await db.DssKeys.Include(x => x.Project).SingleOrDefaultAsync(
            x => x.Id == keyId && x.Active && x.Project!.Active && x.DssProjectId == user.DssProjectId, ct);
        if (key?.Project is null) return (false, null, "所选密钥不属于您的项目，操作已拒绝。");

        byte[] bytes;
        try
        {
            bytes = mode == "hash" ? Convert.FromHexString(input) : Encoding.UTF8.GetBytes(input);
        }
        catch (FormatException) { return (false, null, "摘要必须是偶数位十六进制字符串。"); }
        var limit = configuration.GetValue("Dss:MaxInputBytes", 1024 * 1024);
        if (bytes.Length > limit) return (false, null, $"签名输入最大为 {limit} 字节。");

        var record = new DssSigningRecord
        {
            UserId = user.Id, DssProjectId = key.DssProjectId, DssKeyId = key.Id, InputMode = mode,
            InputValue = input,
            InputSha256 = Convert.ToHexString(SHA256.HashData(bytes)), SignAlgorithm = key.SignAlgorithm
        };
        try
        {
            string signature;
            if (configuration.GetValue<bool>("Suppliers:Dss:UseMock"))
            {
                signature = "DEMO ONLY - no supplier call\n" + Convert.ToHexString(SHA256.HashData(bytes));
            }
            else
            {
                if (key.SignAlgorithm != "Ed25519") throw new InvalidOperationException("当前只启用了 Ed25519。新增算法需与供应商接口能力确认后配置。");
                if (!Uri.TryCreate(key.Project.BaseUrl, UriKind.Absolute, out var baseUri) || baseUri.Scheme != Uri.UriSchemeHttps)
                    throw new InvalidOperationException("当前项目的 DSS HTTPS 接口地址尚未配置。");
                if (string.IsNullOrWhiteSpace(key.Project.AppKey) || string.IsNullOrWhiteSpace(key.Project.AppSecret))
                    throw new InvalidOperationException("当前项目的 DSS API 凭据尚未配置。");
                if (string.IsNullOrWhiteSpace(key.Project.ClientCertificatePath) || !File.Exists(key.Project.ClientCertificatePath))
                    throw new InvalidOperationException("当前项目的 DSS mTLS 客户端证书尚未配置。");

                var endpoint = new Uri(baseUri, "/api/kms/v4/key-sign-text");
                var payload = JsonSerializer.Serialize(new { keyName = key.Name, signAlgorithm = key.SignAlgorithm, data = Convert.ToHexString(bytes) });
                var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
                var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
                string appSecret;
                string certificatePassword;
                try
                {
                    appSecret = secretProtector.Unprotect(key.Project.AppSecret);
                    certificatePassword = string.IsNullOrWhiteSpace(key.Project.ClientCertificatePassword) ? "" : secretProtector.Unprotect(key.Project.ClientCertificatePassword);
                }
                catch (System.Security.Cryptography.CryptographicException)
                {
                    throw new InvalidOperationException("DSS 项目凭据无法解密。请管理员重新保存项目密钥，并在公网部署时持久化 Data Protection 密钥环。");
                }
                var canonical = "POST" + endpoint.AbsolutePath + "es-auth-appkey:" + key.Project.AppKey + "es-auth-nonce:" + nonce +
                    "es-auth-timestamp:" + timestamp + "json=" + payload + appSecret;
                var authSign = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JavaFormUrlEncode(canonical)))).ToLowerInvariant();
                var cert = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadPkcs12FromFile(key.Project.ClientCertificatePath, certificatePassword);
                var handler = new HttpClientHandler();
                handler.ClientCertificates.Add(cert);
                using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
                using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
                request.Headers.Add("es-auth-appkey", key.Project.AppKey);
                request.Headers.Add("es-auth-nonce", nonce);
                request.Headers.Add("es-auth-timestamp", timestamp);
                request.Headers.Add("es-auth-sign", authSign);
                request.Content = new StringContent(payload, Encoding.UTF8, "application/json");
                using var response = await client.SendAsync(request, ct);
                var json = await response.Content.ReadAsStringAsync(ct);
                if (!response.IsSuccessStatusCode)
                {
                    var supplierCode = response.Headers.TryGetValues("KMS-Error", out var codes) ? codes.FirstOrDefault() : null;
                    var supplierMessage = response.Headers.TryGetValues("KMS-Error-Message", out var messages) ? messages.FirstOrDefault() : null;
                    throw new HttpRequestException($"DSS 接口返回 HTTP {(int)response.StatusCode}：{supplierCode} {supplierMessage}".Trim());
                }
                using var parsed = JsonDocument.Parse(json);
                signature = parsed.RootElement.GetProperty("signData").GetString() ?? throw new InvalidOperationException("DSS 接口返回的签名值为空。");
            }
            record.Succeeded = true;
            record.SignatureValue = signature;
            db.DssSigningRecords.Add(record);
            await db.SaveChangesAsync(ct);
            return (true, signature, null);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or InvalidOperationException or IOException or CryptographicException)
        {
            logger.LogWarning(ex, "DSS signing failed for user {UserId} in project {ProjectCode}", user.Id, key.Project.Code);
            record.ErrorMessage = ex.Message;
            db.DssSigningRecords.Add(record);
            await db.SaveChangesAsync(ct);
            return (false, null, ex.Message);
        }
    }

    private static string JavaFormUrlEncode(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        var result = new StringBuilder(bytes.Length);
        foreach (var b in bytes)
        {
            if (b is >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z' or >= (byte)'0' and <= (byte)'9' or (byte)'-' or (byte)'_' or (byte)'.' or (byte)'*')
                result.Append((char)b);
            else if (b == (byte)' ')
                result.Append('+');
            else
                result.Append('%').Append(b.ToString("X2"));
        }
        return result.ToString();
    }
}
