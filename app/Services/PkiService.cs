using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using ZfTools.Data;

namespace ZfTools.Services;

public sealed class PkiService(ToolDbContext db, IConfiguration configuration, ILogger<PkiService> logger)
{
    public async Task<(bool Success, string? Certificate, string? RequestId, string? Error)> ApplyAsync(
        AppUser user, PkiTemplate template, string csr, string variantId, string? uniqueId, string? commonName, string sourceIp, CancellationToken ct)
    {
        var record = new PkiApplicationRecord
        {
            UserId = user.Id, PkiTemplateId = template.Id, EnvironmentName = template.EnvironmentName,
            CommonName = commonName, EcuVariantId = variantId, EcuUniqueId = uniqueId,
            CsrSha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(csr))), CreatedAtUtc = DateTime.UtcNow
        };
        var requestId = Guid.NewGuid().ToString("N");
        try
        {
            string certificate;
            if (configuration.GetValue<bool>("Suppliers:Pki:UseMock"))
            {
                certificate = "DEMO ONLY - PKI supplier API is not configured.\n" + csr;
            }
            else
            {
                var url = configuration["Suppliers:Pki:ApplyUrl"];
                if (!Uri.TryCreate(url, UriKind.Absolute, out var endpoint) || endpoint.Scheme != Uri.UriSchemeHttps)
                    throw new InvalidOperationException("PKI 接口尚未配置。请联系管理员设置 HTTPS 接口地址和 mTLS 客户端证书。");

                var handler = new HttpClientHandler();
                var certificatePath = configuration["Suppliers:Pki:ClientCertificatePath"];
                var password = configuration["Suppliers:Pki:ClientCertificatePassword"];
                if (string.IsNullOrWhiteSpace(certificatePath) || !File.Exists(certificatePath))
                    throw new InvalidOperationException("PKI mTLS 客户端证书未配置。");
                handler.ClientCertificates.Add(System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadPkcs12FromFile(certificatePath, password));
                using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
                var body = new
                {
                    requestParams = new { cert_profile = template.CertProfile, csr = Convert.ToBase64String(Encoding.UTF8.GetBytes(csr)) },
                    requestMetadata = new { requestID = requestId, userSourceIP = sourceIp, ecuVariant = variantId }
                };
                using var response = await client.PostAsJsonAsync(endpoint, body, ct);
                var json = await response.Content.ReadAsStringAsync(ct);
                response.EnsureSuccessStatusCode();
                using var parsed = JsonDocument.Parse(json);
                if (parsed.RootElement.TryGetProperty("code", out var code) && code.GetString() != "000000")
                {
                    var message = parsed.RootElement.TryGetProperty("msg", out var msg) ? msg.GetString() : null;
                    if (string.IsNullOrWhiteSpace(message) && parsed.RootElement.TryGetProperty("description", out var description)) message = description.GetString();
                    throw new InvalidOperationException($"PKI 接口拒绝请求（{code.GetString()}）：{message ?? "未提供错误说明"}");
                }
                var data = parsed.RootElement.TryGetProperty("data", out var dataNode) ? dataNode : parsed.RootElement;
                if (!data.TryGetProperty("certificate", out var certificateNode))
                    throw new InvalidOperationException("PKI 接口响应缺少 data.certificate 字段。");
                certificate = certificateNode.GetString() ?? throw new InvalidOperationException("PKI 接口返回的证书为空。");
                if (LooksLikeBase64(certificate)) certificate = Encoding.UTF8.GetString(Convert.FromBase64String(certificate));
            }
            record.Succeeded = true;
            record.CertificatePem = certificate;
            record.RequestId = requestId;
            db.PkiApplications.Add(record);
            await db.SaveChangesAsync(ct);
            return (true, certificate, requestId, null);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or InvalidOperationException or IOException or CryptographicException)
        {
            logger.LogWarning(ex, "PKI request {RequestId} failed for user {UserId}", requestId, user.Id);
            record.Succeeded = false;
            record.RequestId = requestId;
            record.ErrorMessage = ex.Message;
            db.PkiApplications.Add(record);
            await db.SaveChangesAsync(ct);
            return (false, null, requestId, ex.Message);
        }
    }

    private static bool LooksLikeBase64(string value) => value.Length > 32 && value.All(c => char.IsLetterOrDigit(c) || c is '+' or '/' or '=' or '\r' or '\n');

    public static bool IsValidVariantId(string value, out string error)
    {
        var normalized = Regex.Replace(value, "\\s+", "");
        if (normalized.Length == 0 || normalized.Length % 2 != 0 || !Regex.IsMatch(normalized, "\\A[0-9A-Fa-f]+\\z"))
        {
            error = "ECU Variant ID 必须是偶数位十六进制字符串。";
            return false;
        }
        if (normalized.Length > 32)
        {
            error = "ECU Variant ID 最多 16 字节。";
            return false;
        }
        error = "";
        return true;
    }

    public static bool IsValidUniqueId(string? value, out string error)
    {
        if (value is null) { error = ""; return true; }
        if (Encoding.UTF8.GetByteCount(value) > 32)
        {
            error = "ECU Unique ID 按 UTF-8 编码后最多 32 字节。";
            return false;
        }
        error = "";
        return true;
    }
}
