using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ZfTools.Data;

namespace ZfTools.Services;

public sealed record DssSignResult(bool Success, string? Signature, string? Error, long? RecordId = null,
    string Status = "failed", bool SignatureVerified = false, bool ResponseAuthenticated = false);
public sealed record DssKeyRefreshResult(bool Success, string? Error);

public sealed class DssService(ToolDbContext db, IConfiguration configuration, ILogger<DssService> logger,
    SupplierHttpClientFactory clients, SupplierSecrets secrets)
{
    public async Task<DssKeyRefreshResult> RefreshKeyMetadataAsync(AppUser suppliedUser, int keyId, CancellationToken ct)
    {
        var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(x => x.Id == suppliedUser.Id && x.Active, ct);
        if (user?.Module != ToolModule.Dss)
            return new(false, "Access denied. An active DSS account is required.");
        var key = await db.DssKeys.Include(x => x.Project).Include(x => x.Connection)
            .SingleOrDefaultAsync(x => x.Id == keyId && !x.Archived && x.Project!.Active, ct);
        if (key?.Project is null) return new(false, "Select a registered key in an active project.");
        if (user.Role != UserRole.Admin && (!key.Active || user.DssProjectId is null || user.DssProjectId != key.DssProjectId))
            return new(false, "Access denied. The selected key is not enabled for your assigned project.");
        if (configuration.GetValue<bool>("Suppliers:Dss:UseMock"))
            return new(false, "Supplier metadata cannot be refreshed in demo mode.");
        try
        {
            ValidateKeyConnection(key);
            var connection = key.Connection!;
            await FetchMetadataAsync(key, clients.CreateClient(connection), connection, secrets.Unprotect(connection.AppSecret), ct);
            return new(true, null);
        }
        catch (Exception ex) when (IsExpectedFailure(ex))
        {
            logger.LogWarning("DSS metadata refresh for key {KeyId} failed with {FailureType}", keyId, ex.GetType().Name);
            return new(false, SafeError(ex, false));
        }
    }

    public async Task<DssSignResult> SignAsync(AppUser suppliedUser, int projectId, string environmentName, int keyId,
        string mode, string input, CancellationToken ct, string signAlgorithm = "Ed25519")
    {
        // Read current authorization from the database, including after account/project changes.
        var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(x => x.Id == suppliedUser.Id && x.Active, ct);
        if (user?.Module != ToolModule.Dss) return Failure("Access denied. Sign in with an active DSS account.");
        if (environmentName is not ("development" or "production")) return Failure("Select a valid environment.");
        if (user.Role != UserRole.Admin && (user.DssProjectId is null || user.DssProjectId != projectId))
            return Failure("Access denied. The selected project is not assigned to your account.");

        var key = await db.DssKeys.Include(x => x.Project).Include(x => x.Connection)
            .SingleOrDefaultAsync(x => x.Id == keyId && x.Active && !x.Archived && x.Project!.Active &&
                x.DssProjectId == projectId && x.EnvironmentName == environmentName, ct);
        if (key?.Project is null) return Failure("Access denied. Select an active key assigned to your project and environment.");
        if (key.Connection is not null && (key.Connection.Module != ToolModule.Dss ||
            key.Connection.DssProjectId != projectId || key.Connection.EnvironmentName != environmentName))
            return Failure("Access denied. The signing connection does not match the authorized project and environment.");
        if (!string.Equals(signAlgorithm, "Ed25519", StringComparison.Ordinal) ||
            !string.Equals(key.SignAlgorithm, signAlgorithm, StringComparison.Ordinal))
            return Failure("Only Ed25519 is enabled for this integration.");

        var globalLimit = configuration.GetValue("Dss:MaxInputBytes", 1024 * 1024);
        var limit = key.Connection is null ? globalLimit : Math.Min(globalLimit, key.Connection.MaxInputBytes);
        byte[] bytes;
        try { bytes = DssProtocol.DecodeInput(mode, input, limit); }
        catch (InvalidOperationException ex) { return Failure(ex.Message); }

        var record = new DssSigningRecord
        {
            UserId = user.Id, DssProjectId = projectId, DssKeyId = key.Id, InputMode = mode, InputValue = input,
            InputSha256 = Convert.ToHexString(SHA256.HashData(bytes)), SignAlgorithm = key.SignAlgorithm,
            EnvironmentName = environmentName, ProjectCodeSnapshot = key.Project.Code, KeyNameSnapshot = key.Name,
            ConnectionNameSnapshot = key.Connection?.Name ?? "", Status = "pending"
        };
        db.DssSigningRecords.Add(record);
        await db.SaveChangesAsync(ct);

        var requestStarted = false;
        try
        {
            if (configuration.GetValue<bool>("Suppliers:Dss:UseMock"))
            {
                record.Status = "demo";
                record.Succeeded = false;
                await db.SaveChangesAsync(CancellationToken.None);
                return new(true, null, null, record.Id, "demo");
            }

            ValidateKeyConnection(key);
            var connection = key.Connection!;
            var appSecret = secrets.Unprotect(connection.AppSecret);
            var client = clients.CreateClient(connection);
            // A known name can be queried, but this API does not discover projects or keys.
            // Refresh before every real sign so revocation/algorithm changes take effect immediately.
            await FetchMetadataAsync(key, client, connection, appSecret, ct);
            if (!DssProtocol.MetadataSupportsSigning(key))
                throw new InvalidOperationException("The supplier key is not an active asymmetric Ed25519 signing key. Refresh or select another registered key.");
            record.SignAlgorithm = key.SignAlgorithm;
            var data = Convert.ToHexString(bytes);
            var payload = JsonSerializer.Serialize(new { keyName = key.Name, signAlgorithm, data });
            requestStarted = true;
            var signedResponse = await PostAuthenticatedAsync(client, connection, DssProtocol.SignPath, payload, appSecret, ct);
            record.ResponseAuthenticated = true;
            var signature = DssProtocol.ParseSignature(signedResponse);
            record.SignatureValue = signature;
            // Preserve a received value even when a later verification is interrupted.
            await db.SaveChangesAsync(CancellationToken.None);

            bool verified;
            if (!string.IsNullOrWhiteSpace(key.PublicKeyPem))
            {
                verified = DssProtocol.VerifyEd25519(key.PublicKeyPem, bytes, signature);
            }
            else
            {
                var verificationPayload = JsonSerializer.Serialize(new { keyName = key.Name, signAlgorithm, data, signData = signature });
                record.ResponseAuthenticated = false;
                var verificationResponse = await PostAuthenticatedAsync(client, connection, DssProtocol.VerifyPath, verificationPayload, appSecret, ct);
                record.ResponseAuthenticated = true;
                verified = DssProtocol.ParseVerification(verificationResponse);
            }
            if (!verified) throw new DssVerificationException("The returned signature did not pass Ed25519 verification. The result is retained in history for investigation.");
            record.SignatureVerified = true;
            record.Succeeded = true;
            record.Status = "succeeded";
            await db.SaveChangesAsync(CancellationToken.None);
            return new(true, signature, null, record.Id, record.Status, true, record.ResponseAuthenticated);
        }
        catch (Exception ex) when (IsExpectedFailure(ex))
        {
            // A disconnected signing request may have completed. Never retry it automatically.
            record.Status = requestStarted && ex is not DssSupplierRejectedException && ex is not DssVerificationException ? "unknown" : "failed";
            var error = SafeError(ex, requestStarted);
            if (record.Status == "unknown" && ex is not (OperationCanceledException or HttpRequestException))
                error += " The request outcome is unconfirmed; no automatic retry was made.";
            record.ErrorMessage = error;
            record.Succeeded = false;
            logger.LogWarning("DSS operation {RecordId} ended with status {Status}, failure {FailureType}", record.Id, record.Status, ex.GetType().Name);
            await db.SaveChangesAsync(CancellationToken.None);
            return new(false, null, error, record.Id, record.Status, record.SignatureVerified, record.ResponseAuthenticated);
        }
    }

    private static void ValidateKeyConnection(DssKey key)
    {
        var errors = SupplierConnectionRules.GetErrors(key.Connection, ToolModule.Dss, key.DssProjectId).ToList();
        if (key.EnvironmentName is not ("development" or "production")) errors.Add("Select a valid key environment.");
        if (key.Connection is not null)
        {
            if (key.Connection.EnvironmentName != key.EnvironmentName) errors.Add("The key connection does not match the selected environment.");
            errors.AddRange(DssProtocol.ResponseContractErrors(key.Connection));
        }
        if (errors.Count != 0) throw new InvalidOperationException(string.Join(" ", errors));
    }

    private async Task FetchMetadataAsync(DssKey key, HttpClient client, SupplierConnection connection, string appSecret, CancellationToken ct)
    {
        var payload = JsonSerializer.Serialize(new { keyName = key.Name });
        var response = await PostAuthenticatedAsync(client, connection, DssProtocol.GetKeyPath, payload, appSecret, ct);
        var metadata = DssProtocol.ParseKeyMetadata(response, key.Name);
        key.SupplierKeyAlgorithm = metadata.KeyAlgorithm;
        key.SupplierKeyCurve = metadata.Curve;
        key.SupplierKeyType = metadata.KeyType;
        key.SupplierKeyStatus = metadata.KeyStatus;
        key.SupplierKeyLength = metadata.KeyLength;
        key.SignAlgorithm = metadata.SignAlgorithm;
        key.PublicKeyPem = metadata.PublicKeyPem;
        key.SupplierMetadataUpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);
    }

    private static bool IsExpectedFailure(Exception ex) => ex is HttpRequestException or OperationCanceledException or JsonException or
        InvalidOperationException or IOException or CryptographicException or FormatException or ArgumentException;

    private static string SafeError(Exception ex, bool signStarted) => ex switch
    {
        OperationCanceledException => signStarted
            ? "The DSS signing request was interrupted or timed out. Its outcome is unknown; check history before submitting again."
            : "The DSS metadata request was interrupted or timed out. No signing request was sent.",
        HttpRequestException => signStarted
            ? "The DSS connection failed. The supplier may have received the signing request; check history before submitting again."
            : "The DSS connection failed while reading key metadata. No signing request was sent.",
        CryptographicException => "The DSS credentials or certificate could not be loaded. Ask an administrator to check the connection and persisted Data Protection keys.",
        IOException => "The DSS connection files or response could not be read.",
        JsonException => "The DSS API returned an invalid JSON response.",
        FormatException or ArgumentException => "The DSS connection or response has an invalid format.",
        _ => ex.Message
    };

    private static async Task<string> PostAuthenticatedAsync(HttpClient client, SupplierConnection connection, string path,
        string exactJson, string appSecret, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(connection.TimeoutSeconds));
        var requestToken = deadline.Token;
        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture);
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(new Uri(connection.BaseUrl), path));
        request.Headers.Add("es-auth-appkey", connection.AppKey);
        request.Headers.Add("es-auth-nonce", nonce);
        request.Headers.Add("es-auth-timestamp", timestamp);
        request.Headers.Add("es-auth-sign", DssProtocol.BuildRequestSignature(path, connection.AppKey, nonce, timestamp, exactJson, appSecret));
        request.Content = new StringContent(exactJson, Encoding.UTF8, "application/json");
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, requestToken);
        var body = await ReadBoundedResponseAsync(response, requestToken);
        if (!DssProtocol.AuthenticateResponse(connection, response, path, nonce, timestamp, body, appSecret))
            throw new InvalidOperationException("The DSS response failed authentication. No result was accepted.");
        if (!response.IsSuccessStatusCode)
        {
            var code = response.Headers.TryGetValues("KMS-Error", out var values) ? values.FirstOrDefault() : null;
            var safeCode = code is not null && code.Length <= 20 && code.All(char.IsAsciiDigit) ? $" (code {code})" : "";
            throw new DssSupplierRejectedException($"The DSS API rejected the operation with HTTP {(int)response.StatusCode}{safeCode}.");
        }
        return body;
    }

    private static async Task<string> ReadBoundedResponseAsync(HttpResponseMessage response, CancellationToken ct)
    {
        const int maxResponseBytes = 64 * 1024;
        if (response.Content.Headers.ContentLength > maxResponseBytes) throw new InvalidOperationException("The DSS response exceeds the allowed size.");
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var buffer = new MemoryStream();
        var chunk = new byte[4096];
        int read;
        while ((read = await stream.ReadAsync(chunk, ct)) != 0)
        {
            if (buffer.Length + read > maxResponseBytes) throw new InvalidOperationException("The DSS response exceeds the allowed size.");
            buffer.Write(chunk, 0, read);
        }
        try { return new UTF8Encoding(false, true).GetString(buffer.ToArray()); }
        catch (DecoderFallbackException) { throw new InvalidOperationException("The DSS response is not valid UTF-8."); }
    }

    private static DssSignResult Failure(string message) => new(false, null, message);
    private sealed class DssSupplierRejectedException(string message) : InvalidOperationException(message);
    private sealed class DssVerificationException(string message) : InvalidOperationException(message);
}
