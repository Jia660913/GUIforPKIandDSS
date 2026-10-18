using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using ZfTools.Data;

namespace ZfTools.Services;

public sealed record PkiApplyResult(bool Success, string? Certificate, string? RequestId, string? Error, string Status);
public sealed record PkiSupplierResponse(string CertificatePem, string SupplierRequestId);

public sealed class PkiService(ToolDbContext db, IConfiguration configuration, SupplierHttpClientFactory clients, ILogger<PkiService> logger)
{
    public const string ApplyPath = "/esca/api/v1/cert/apply";
    private const int MaximumResponseBytes = 1024 * 1024;

    public async Task<PkiApplyResult> ApplyAsync(AppUser user, PkiTemplate template, string csr, string variantId, string? uniqueId, string? commonName, string sourceIp, CancellationToken ct)
    {
        // Do not trust a browser selection or a previously loaded user/template when authorizing issuance.
        if (!await db.Users.AsNoTracking().AnyAsync(x => x.Id == user.Id && x.Active && x.Module == ToolModule.Pki, ct))
            return new(false, null, null, "This account is not authorized to use PKI.", "failed");
        var selected = await db.PkiTemplates.AsNoTracking().Include(x => x.Connection).SingleOrDefaultAsync(x => x.Id == template.Id && x.Active && !x.Archived, ct);
        if (selected is null) return new(false, null, null, "The selected certificate template is unavailable.", "failed");
        var requestId = Guid.NewGuid().ToString("N");
        var record = new PkiApplicationRecord
        {
            UserId = user.Id, PkiTemplateId = selected.Id, EnvironmentName = selected.EnvironmentName,
            TemplateNameSnapshot = selected.DisplayName, CertProfileSnapshot = selected.CertProfile,
            RoleSnapshot = PkiRoleCatalog.Normalize(selected.DiagUserRole) ?? selected.DiagUserRole,
            TrustGradeSnapshot = selected.TrustGrade, ConnectionNameSnapshot = selected.Connection?.Name ?? "",
            CsrSha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(csr))),
            RequestId = requestId, Status = "pending", CreatedAtUtc = DateTime.UtcNow
        };
        var requestMayHaveBeenProcessed = false;
        try
        {
            var parsed = CsrService.ParseAndValidate(csr, selected);
            record.CommonName = parsed.CommonName; record.EcuVariantId = parsed.VariantId; record.EcuUniqueId = parsed.UniqueId;
            // Input metadata is always taken from the verified CSR, never from hidden form values.
            if (configuration.GetValue<bool>("Suppliers:Pki:UseMock"))
            {
                record.Status = "demo";
                db.PkiApplications.Add(record);
                await db.SaveChangesAsync(ct);
                return new(false, null, requestId, "CSR validation completed in demo mode. No supplier request was sent and no certificate was issued.", "demo");
            }
            var errors = GetReadinessErrors(selected);
            if (errors.Count != 0) throw new InvalidOperationException(string.Join(" ", errors));
            if (!IPAddress.TryParse(sourceIp, out var sourceAddress) || sourceAddress.AddressFamily != AddressFamily.InterNetwork)
                throw new InvalidOperationException("The PKI interface requires an IPv4 source address. Configure the trusted gateway before issuing from IPv6 clients.");
            var connection = selected.Connection!;
            var client = clients.CreateClient(connection);
            var endpoint = new Uri(new Uri(connection.BaseUrl.TrimEnd('/') + "/"), ApplyPath);
            var body = new
            {
                requestParams = new { cert_profile = selected.CertProfile, csr = Convert.ToBase64String(Encoding.UTF8.GetBytes(parsed.Pem)) },
                requestMetadata = new { requestID = requestId, userSourceIP = sourceAddress.ToString(), ecuVariant = parsed.VariantId }
            };
            db.PkiApplications.Add(record);
            await db.SaveChangesAsync(ct);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(connection.TimeoutSeconds));
            using var request = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json") };
            requestMayHaveBeenProcessed = true;
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (!response.IsSuccessStatusCode)
            {
                // A gateway/server error can occur after issuance; do not assert that nothing was issued.
                requestMayHaveBeenProcessed = (int)response.StatusCode >= 500;
                throw new InvalidOperationException($"The PKI API returned HTTP {(int)response.StatusCode}.");
            }
            var json = await ReadBoundedResponseAsync(response, timeout.Token);
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String && code.GetString() != "000000")
            {
                requestMayHaveBeenProcessed = false;
                var safeCode = code.GetString()!;
                if (!Regex.IsMatch(safeCode, "\\A[A-Za-z0-9_-]{1,32}\\z")) safeCode = "unrecognized";
                if (safeCode == "100003")
                    throw new InvalidOperationException("The PKI API could not find the requested certificate profile (code 100003). Check the exact supplier profile name and target environment. This does not establish whether other profiles exist.");
                throw new InvalidOperationException($"The PKI API rejected the application (code {safeCode}). Check the supplier log using the request ID.");
            }
            var received = ParseSuccessResponse(json);
            record.SupplierRequestId = received.SupplierRequestId;
            record.CertificatePem = received.CertificatePem;
            PkiCertificateValidator.Validate(received.CertificatePem, parsed, selected, connection.IssuerCaChainPath);
            record.Succeeded = true; record.Status = "succeeded";
            requestMayHaveBeenProcessed = false;
            await db.SaveChangesAsync(CancellationToken.None);
            return new(true, received.CertificatePem, requestId, null, record.Status);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or JsonException or InvalidOperationException or IOException or CryptographicException or FormatException or ArgumentException or Org.BouncyCastle.Security.GeneralSecurityException)
        {
            record.Succeeded = false; record.Status = requestMayHaveBeenProcessed ? "unknown" : "failed";
            var message = ex is OperationCanceledException ? "The request was cancelled or timed out." :
                ex is HttpRequestException ? "The supplier connection could not complete." :
                ex is JsonException or FormatException ? "The supplier returned an invalid response." : ex.Message;
            record.ErrorMessage = message + (requestMayHaveBeenProcessed ? " Issuance may already have occurred. Ask an administrator to check the supplier log before submitting another application." : "");
            logger.LogWarning("PKI request {RequestId} ended with status {Status}; failure type {FailureType}", requestId, record.Status, ex.GetType().Name);
            if (db.Entry(record).State == EntityState.Detached) db.PkiApplications.Add(record);
            await db.SaveChangesAsync(CancellationToken.None);
            return new(false, null, requestId, record.ErrorMessage, record.Status);
        }
    }

    public static IReadOnlyList<string> GetReadinessErrors(PkiTemplate template)
    {
        var errors = SupplierConnectionRules.GetErrors(template.Connection, ToolModule.Pki).ToList();
        if (!template.Active || template.Archived) errors.Add("This template is disabled.");
        if (!template.CsrPolicyConfirmed) errors.Add("The administrator has not confirmed the supplier CSR policy.");
        if (string.IsNullOrWhiteSpace(template.CertProfile)) errors.Add("The exact supplier profile name is missing.");
        if (template.Connection is not null && template.Connection.EnvironmentName != template.EnvironmentName) errors.Add("The template and connection environments do not match.");
        if (template.EnvironmentName is not ("development" or "production")) errors.Add("The environment is invalid.");
        if (template.TrustGrade != (template.EnvironmentName == "production" ? "field" : "dev")) errors.Add("The template trust grade does not match its environment.");
        if (PkiRoleCatalog.Find(template.DiagUserRole) is null) errors.Add("The diagnostic role is not available.");
        return errors;
    }

    public static PkiSupplierResponse ParseSuccessResponse(string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("code", out var code) || code.ValueKind != JsonValueKind.String || code.GetString() != "000000")
            throw new InvalidOperationException("The PKI response does not contain the required success code 000000.");
        if (!root.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Object || !data.TryGetProperty("certificate", out var cert) || cert.ValueKind != JsonValueKind.String)
            throw new InvalidOperationException("The PKI response is missing data.certificate.");
        var encoded = cert.GetString()!;
        if (encoded.Length == 0 || encoded.Length > MaximumResponseBytes) throw new InvalidOperationException("The PKI response certificate is empty or too large.");
        var decoded = new UTF8Encoding(false, true).GetString(Convert.FromBase64String(encoded));
        if (!decoded.TrimStart().StartsWith("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
            throw new InvalidOperationException("data.certificate must contain Base64 of a complete PEM certificate.");
        if (!data.TryGetProperty("requestId", out var supplierId) || supplierId.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(supplierId.GetString()) || supplierId.GetString()!.Length > 256)
            throw new InvalidOperationException("The PKI response is missing a valid data.requestId.");
        return new(decoded, supplierId.GetString()!);
    }

    private static async Task<string> ReadBoundedResponseAsync(HttpResponseMessage response, CancellationToken ct)
    {
        if (response.Content.Headers.ContentLength > MaximumResponseBytes) throw new InvalidOperationException("The PKI response exceeds 1 MiB.");
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(chunk, ct)) > 0)
        {
            if (buffer.Length + read > MaximumResponseBytes) throw new InvalidOperationException("The PKI response exceeds 1 MiB.");
            buffer.Write(chunk, 0, read);
        }
        return new UTF8Encoding(false, true).GetString(buffer.ToArray());
    }

    public static bool IsValidVariantId(string? value, out string error)
    {
        var normalized = Regex.Replace(value ?? "", "\\s+", "");
        if (normalized.Length == 0 || normalized.Length % 2 != 0 || !Regex.IsMatch(normalized, "\\A[0-9A-Fa-f]+\\z")) { error = "ECU Variant ID must be hexadecimal with an even number of characters."; return false; }
        if (normalized.Length > 32) { error = "ECU Variant ID must not exceed 16 bytes."; return false; }
        error = ""; return true;
    }
    public static bool IsValidUniqueId(string? value, out string error)
    {
        if (value is not null && (Encoding.UTF8.GetByteCount(value) > 32 || value.Any(char.IsControl))) { error = "ECU Unique ID must not exceed 32 UTF-8 bytes or contain control characters."; return false; }
        error = ""; return true;
    }
}
