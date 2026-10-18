using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using ZfTools.Data;
using ZfTools.Services;
using BcCertificate = Org.BouncyCastle.X509.X509Certificate;

/// <summary>Local contract fixtures only; these tests never use a supplier endpoint or delivered credential.</summary>
public static class SupplierRoundTripChecks
{
    private const string AppKey = "local-fixture-app";
    private const string AppSecret = "local-fixture-secret + * ~";
    // Deliberately a test-only response contract, not an assertion about the supplier's undocumented formula.
    private const string ResponseTemplate = "{method}{path}{requestNonce}{requestTimestamp}{appKey}{body}{appSecret}";

    public static async Task RunAsync(Action<bool, string> check)
    {
        var directory = Path.Combine(Path.GetTempPath(), "zf-local-mtls-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try { await RunInDirectoryAsync(directory, check); }
        finally
        {
            var full = Path.GetFullPath(directory);
            var parent = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!full.StartsWith(parent, StringComparison.OrdinalIgnoreCase) || !Path.GetFileName(full).StartsWith("zf-local-mtls-", StringComparison.Ordinal))
                throw new InvalidOperationException("Refusing to remove a test directory outside its temporary root.");
            Directory.Delete(full, true);
        }
    }

    private static async Task RunInDirectoryAsync(string directory, Action<bool, string> check)
    {
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root = TransportCa(rootKey, "local-mtls-root");
        using var serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var server = TransportLeaf(root, serverKey, true);
        using var clientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var client = TransportLeaf(root, clientKey, false);
        using var unrelatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var unrelatedCa = TransportCa(unrelatedKey, "unrelated-root");
        var trustPath = Path.Combine(directory, "server-trust.pem");
        var clientPath = Path.Combine(directory, "client.pem");
        var keyPath = Path.Combine(directory, "client-key.pem");
        var unrelatedPath = Path.Combine(directory, "unrelated-trust.pem");
        await File.WriteAllTextAsync(trustPath, root.ExportCertificatePem());
        await File.WriteAllTextAsync(clientPath, client.ExportCertificatePem());
        await File.WriteAllTextAsync(keyPath, clientKey.ExportPkcs8PrivateKeyPem());
        await File.WriteAllTextAsync(unrelatedPath, unrelatedCa.ExportCertificatePem());

        var businessRootKey = EdKeyPair();
        var businessRoot = BusinessCa("fixture-root", businessRootKey, null, null);
        var businessIssuerKey = EdKeyPair();
        var businessIssuer = BusinessCa("fixture-diag-ca", businessIssuerKey, businessRoot, businessRootKey.Private);
        var businessChainPath = Path.Combine(directory, "business-ca.pem");
        await File.WriteAllTextAsync(businessChainPath, Pem("CERTIFICATE", businessRoot.GetEncoded()) + Pem("CERTIFICATE", businessIssuer.GetEncoded()));
        var signingKey = EdKeyPair();
        var state = new FixtureState(signingKey, businessIssuer, businessIssuerKey.Private);

        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { EnvironmentName = "Testing", ContentRootPath = directory });
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(https =>
        {
            https.ServerCertificate = server;
            https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
            https.ClientCertificateValidation = (certificate, _, _) => ValidateTransportChain(certificate, root, "1.3.6.1.5.5.7.3.2");
            // Every fixture connection must negotiate its own identity, including negative cases.
            https.OnAuthenticate = (_, options) => options.AllowTlsResume = false;
        })));
        await using var app = builder.Build();
        app.MapGet("/", () => "fixture");
        app.MapPost(DssProtocol.SignPath, context => HandleDssAsync(context, state, false));
        app.MapPost(DssProtocol.VerifyPath, context => HandleDssAsync(context, state, true));
        app.MapPost(DssProtocol.GetKeyPath, context => HandleGetKeyAsync(context, state));
        app.MapPost(PkiService.ApplyPath, context => HandlePkiAsync(context, state));
        await app.StartAsync();
        var origin = app.Urls.Single().Replace("127.0.0.1", "localhost", StringComparison.Ordinal);

        // Run the absent-identity handshake before authenticated connections. On Windows,
        // Schannel may reuse their client identity even across separate HttpClient handlers.
        using var noIdentityHandler = new SocketsHttpHandler
        {
            SslOptions = new SslClientAuthenticationOptions
            {
                AllowTlsResume = false,
                // Explicitly decline certificate selection for this negative fixture.
                LocalCertificateSelectionCallback = (_, _, _, _, _) => null,
                CertificateChainPolicy = new X509ChainPolicy
                {
                    TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck,
                    DisableCertificateDownloads = true, CustomTrustStore = { root }, ApplicationPolicy = { new Oid("1.3.6.1.5.5.7.3.1") }
                }
            }
        };
        using var noIdentityClient = new HttpClient(noIdentityHandler) { Timeout = TimeSpan.FromSeconds(5) };
        check(await TransportRejectedAsync(noIdentityClient, origin), "Local mTLS supplier refuses a request without a client certificate");

        await using var sqlite = new SqliteConnection("Data Source=:memory:");
        await sqlite.OpenAsync();
        await using var db = new ToolDbContext(new DbContextOptionsBuilder<ToolDbContext>().UseSqlite(sqlite).Options);
        await db.Database.EnsureCreatedAsync();
        var secrets = new SupplierSecrets(new EphemeralDataProtectionProvider());
        using var clients = new SupplierHttpClientFactory(secrets);
        var project = new DssProject { Code = "LOCAL", DisplayName = "Local fixture" };
        db.DssProjects.Add(project);
        await db.SaveChangesAsync();
        var dssConnection = new SupplierConnection
        {
            Module = ToolModule.Dss, Name = "Local mTLS DSS", BaseUrl = origin, DssProjectId = project.Id,
            ClientCertificatePath = clientPath, ClientPrivateKeyPath = keyPath, ServerCaChainPath = trustPath,
            AppKey = AppKey, AppSecret = secrets.Protect(AppSecret), DssResponseAuthConfirmed = true,
            ResponseSignatureTemplate = ResponseTemplate, TimeoutSeconds = 5
        };
        var pkiConnection = new SupplierConnection
        {
            Module = ToolModule.Pki, Name = "Local mTLS PKI", BaseUrl = origin,
            ClientCertificatePath = clientPath, ClientPrivateKeyPath = keyPath, ServerCaChainPath = trustPath,
            IssuerCaChainPath = businessChainPath, TimeoutSeconds = 5
        };
        var key = new DssKey { Project = project, Name = "local-ed25519", Connection = dssConnection };
        var dssUser = new AppUser { Username = "dss-fixture", Module = ToolModule.Dss, DssProjectId = project.Id };
        var dssAdmin = new AppUser { Username = "dss-admin-fixture", Module = ToolModule.Dss, Role = UserRole.Admin };
        var outsider = new AppUser { Username = "dss-outsider-fixture", Module = ToolModule.Dss };
        var pkiUser = new AppUser { Username = "pki-fixture", Module = ToolModule.Pki };
        var template = new PkiTemplate
        {
            DisplayName = "OEM Development fixture", CertProfile = "local-oem-dev", DiagUserRole = "00800000",
            Connection = pkiConnection, CsrPolicyConfirmed = true, VariantExactBytes = 8
        };
        state.Template = template;
        db.AddRange(dssConnection, pkiConnection, key, dssUser, dssAdmin, outsider, pkiUser, template);
        await db.SaveChangesAsync();
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Suppliers:Dss:UseMock"] = "false", ["Suppliers:Pki:UseMock"] = "false"
        }).Build();
        var dss = new DssService(db, configuration, NullLogger<DssService>.Instance, clients, secrets);
        var pki = new PkiService(db, configuration, clients, NullLogger<PkiService>.Instance);

        async Task<DssSignResult> SignAsync(string mode, string input) => await dss.SignAsync(dssUser, project.Id, "development", key.Id, mode, input, CancellationToken.None);
        using (var probe = await clients.CreateClient(dssConnection).GetAsync(origin))
            check(probe.IsSuccessStatusCode, "Local mTLS transport accepts the configured client and server identities");
        var deniedRefresh = await dss.RefreshKeyMetadataAsync(outsider, key.Id, default);
        check(!deniedRefresh.Success && state.GetKeyCalls == 0, "Known-key metadata refresh enforces ordinary users' assigned project before any supplier request");
        var refreshed = await dss.RefreshKeyMetadataAsync(dssAdmin, key.Id, default);
        check(refreshed.Success && state.GetKeyCalls == 1 && key.SupplierKeyAlgorithm == "EdDSA" && key.SupplierKeyCurve == "Ed25519" &&
            key.SupplierKeyStatus == "1" && key.SupplierKeyType == "asymmetric" && key.SignAlgorithm == "Ed25519" &&
            DssProtocol.MetadataSupportsSigning(key) && !key.PublicKeyPem.Contains("NEVER_IMPORT", StringComparison.Ordinal),
            "Known-key refresh authenticates key-get, persists public signing metadata and never imports returned private material");
        var text = "ECU Ω * ~";
        var signed = await SignAsync("text", text);
        check(signed.Success && signed.Status == "succeeded" && signed.SignatureVerified && signed.ResponseAuthenticated,
            "DSS completes real local HTTPS mTLS signing with authenticated responses and refreshed-public-key verification: " + signed.Error + " " + string.Join(";", state.Errors));
        check(state.LastData.SequenceEqual(Encoding.UTF8.GetBytes(text)) && state.SignCalls == 1 && state.VerifyCalls == 0 && state.GetKeyCalls == 2,
            "DSS sends exact UTF-8 bytes, refreshes public key metadata before signing and verifies locally");
        check(state.Errors.IsEmpty, "DSS fixture independently validates documented request headers, signing canonicalization and payload");
        var stored = await db.DssSigningRecords.AsNoTracking().SingleAsync(x => x.Id == signed.RecordId);
        check(stored.Succeeded && stored.SignatureValue == signed.Signature && stored.InputValue == text && stored.ProjectCodeSnapshot == "LOCAL",
            "DSS stores verified signature, original input and project snapshot after roundtrip");

        var digest = await SignAsync("hash", "00017f80ff");
        check(digest.Success && state.LastData.SequenceEqual(new byte[] { 0, 1, 127, 128, 255 }),
            "DSS digest roundtrip signs original decoded bytes without hashing again");

        state.Fault = FixtureFault.BadSignAuth;
        var beforeVerify = state.VerifyCalls;
        var badAuth = await SignAsync("text", "bad-auth");
        check(!badAuth.Success && badAuth.Status == "unknown" && !badAuth.ResponseAuthenticated && state.VerifyCalls == beforeVerify,
            "DSS rejects unauthenticated sign response before verification and does not retry");

        state.Fault = FixtureFault.MalformedSignature;
        var malformed = await SignAsync("text", "malformed");
        check(!malformed.Success && malformed.Status == "unknown" && malformed.ResponseAuthenticated && state.VerifyCalls == beforeVerify,
            "DSS rejects authenticated signature with wrong Ed25519 length");

        state.Fault = FixtureFault.CorruptSignature;
        var badVerification = await SignAsync("text", "wrong-verification");
        var failedRecord = await db.DssSigningRecords.AsNoTracking().SingleAsync(x => x.Id == badVerification.RecordId);
        check(!badVerification.Success && badVerification.Status == "failed" && !failedRecord.Succeeded && failedRecord.SignatureValue?.Length == 128,
            "DSS retains a returned signature but marks failed local public-key verification as failed");

        state.Fault = FixtureFault.BadMetadataAuth;
        var signBeforeMetadataFailure = state.SignCalls;
        var metadataTimestamp = key.SupplierMetadataUpdatedAtUtc;
        var badMetadataAuth = await SignAsync("text", "bad-metadata-auth");
        check(!badMetadataAuth.Success && badMetadataAuth.Status == "failed" && !badMetadataAuth.ResponseAuthenticated &&
            state.SignCalls == signBeforeMetadataFailure && key.SupplierMetadataUpdatedAtUtc == metadataTimestamp,
            "DSS rejects unauthenticated metadata before signing and preserves previously authenticated metadata");

        state.Fault = FixtureFault.None;
        state.SupplierKeyStatus = "2";
        var revoked = await SignAsync("text", "revoked-key");
        check(!revoked.Success && revoked.Status == "failed" && state.SignCalls == signBeforeMetadataFailure &&
            key.SupplierKeyStatus == "2" && !DssProtocol.MetadataSupportsSigning(key) && key.Active,
            "Supplier revocation immediately blocks signing while retaining local key registration for later refresh");
        state.SupplierKeyStatus = "1";
        check((await dss.RefreshKeyMetadataAsync(dssUser, key.Id, default)).Success && DssProtocol.MetadataSupportsSigning(key),
            "Authorized ordinary users can refresh a registered key and observe restored supplier status");

        state.Fault = FixtureFault.None;
        key.PublicKeyPem = Pem("PUBLIC KEY", SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(signingKey.Public).GetEncoded());
        await db.SaveChangesAsync();
        beforeVerify = state.VerifyCalls;
        var localVerified = await SignAsync("text", "local-verification");
        check(localVerified.Success && localVerified.SignatureVerified && state.VerifyCalls == beforeVerify,
            "DSS verifies with configured Ed25519 public key without an extra supplier verify call");
        key.PublicKeyPem = "";
        await db.SaveChangesAsync();
        state.Fault = FixtureFault.SlowSign;
        var beforeSign = state.SignCalls;
        var timedOut = await SignAsync("text", "timeout");
        check(!timedOut.Success && timedOut.Status == "unknown" && state.SignCalls == beforeSign + 1,
            $"DSS timeout records unknown outcome and does not automatically retry signing (status={timedOut.Status}, calls={state.SignCalls - beforeSign}, error={timedOut.Error})");
        state.Fault = FixtureFault.None;

        var generated = new CsrService().Generate("0040000100000000", "LOCAL-ECU", "local-pki-user", template);
        var issued = await pki.ApplyAsync(pkiUser, template, generated.CsrPem, "FORGED", "FORGED", "FORGED", "127.0.0.1", CancellationToken.None);
        check(issued.Success && issued.Status == "succeeded" && issued.Certificate?.Contains("BEGIN CERTIFICATE", StringComparison.Ordinal) == true,
            "PKI completes local mTLS apply and validates returned Ed25519 three-level certificate chain");
        var issuedRecord = await db.PkiApplications.AsNoTracking().SingleAsync(x => x.RequestId == issued.RequestId);
        check(issuedRecord.SupplierRequestId == "local-" + issued.RequestId && issuedRecord.EcuVariantId == "0040000100000000" && issuedRecord.EcuUniqueId == "LOCAL-ECU" && issuedRecord.CommonName == "local-pki-user",
            "PKI uses parsed CSR fields rather than submitted metadata and preserves supplier request ID");
        check(state.PkiCalls == 1 && state.Errors.IsEmpty, "PKI fixture checks documented JSON envelope, Base64 PEM CSR and absence of DSS authentication headers");

        state.Fault = FixtureFault.PkiReject;
        var rejected = await pki.ApplyAsync(pkiUser, template, generated.CsrPem, "", null, null, "127.0.0.1", CancellationToken.None);
        check(!rejected.Success && rejected.Status == "failed", "PKI supplier rejection code is recorded as failed");
        state.Fault = FixtureFault.PkiMissingCode;
        var missingCode = await pki.ApplyAsync(pkiUser, template, generated.CsrPem, "", null, null, "127.0.0.1", CancellationToken.None);
        check(!missingCode.Success && missingCode.Status == "unknown", "PKI response without success code never becomes a successful issuance");
        state.Fault = FixtureFault.None;

        var wrongHost = CopyTransport(dssConnection);
        wrongHost.BaseUrl = origin.Replace("localhost", "127.0.0.1", StringComparison.Ordinal);
        check(await TransportRejectedAsync(clients.CreateClient(wrongHost), wrongHost.BaseUrl), "Production transport rejects server hostname mismatch");
        var wrongTrust = CopyTransport(dssConnection);
        wrongTrust.ServerCaChainPath = unrelatedPath;
        check(await TransportRejectedAsync(clients.CreateClient(wrongTrust), wrongTrust.BaseUrl), "Production transport rejects a server outside the configured trust chain");
        var pfxPath = Path.Combine(directory, "client.pfx");
        const string pfxPassword = "fixture-pfx-password";
        await File.WriteAllBytesAsync(pfxPath, client.Export(X509ContentType.Pkcs12, pfxPassword));
        var pfxConnection = CopyTransport(dssConnection);
        pfxConnection.ClientCertificatePath = pfxPath;
        pfxConnection.ClientPrivateKeyPath = "";
        pfxConnection.ClientCertificatePassword = secrets.Protect(pfxPassword);
        using (var pfxResponse = await clients.CreateClient(pfxConnection).GetAsync(origin))
            check(pfxResponse.IsSuccessStatusCode, "Production transport loads a password-protected PFX identity and completes mTLS");
        check(state.Errors.IsEmpty, "All local supplier requests satisfy their separate PKI and DSS contracts");
        await app.StopAsync();
    }

    private static async Task HandleGetKeyAsync(HttpContext context, FixtureState state)
    {
        Interlocked.Increment(ref state.GetKeyCalls);
        try
        {
            if (context.Connection.ClientCertificate is null) throw new InvalidOperationException("DSS key-get request has no TLS identity.");
            var json = await new StreamReader(context.Request.Body, Encoding.UTF8).ReadToEndAsync(context.RequestAborted);
            var path = context.Request.Path.Value!;
            var nonce = context.Request.Headers["es-auth-nonce"].ToString();
            var timestamp = context.Request.Headers["es-auth-timestamp"].ToString();
            var canonical = "POST" + path + "es-auth-appkey:" + AppKey + "es-auth-nonce:" + nonce + "es-auth-timestamp:" + timestamp + "json=" + json + AppSecret;
            if (context.Request.Headers["es-auth-appkey"] != AppKey || nonce.Length != 16 || !nonce.All(Uri.IsHexDigit) ||
                !long.TryParse(timestamp, out var time) || Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - time) > 30000 ||
                context.Request.Headers["es-auth-sign"] != IndependentHash(canonical))
                throw new InvalidOperationException("DSS key-get request authentication contract failed.");
            using var parsed = JsonDocument.Parse(json);
            if (!parsed.RootElement.EnumerateObject().Select(x => x.Name).SequenceEqual(new[] { "keyName" }) ||
                parsed.RootElement.GetProperty("keyName").GetString() != "local-ed25519")
                throw new InvalidOperationException("DSS key-get must query exactly one registered name.");
            var response = JsonSerializer.Serialize(new
            {
                keyName = "local-ed25519", keyAlgorithm = "EdDSA", encrycurve = "Ed25519", keyType = "asymmetric",
                keyLength = "256", keyStatus = state.SupplierKeyStatus,
                publicKey = Convert.ToHexString(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(state.SigningKey.Public).GetEncoded()),
                privateKey = "NEVER_IMPORT_PRIVATE_KEY", secretkey = "NEVER_IMPORT_SECRET_KEY"
            });
            context.Response.Headers["es-auth-appkey"] = AppKey;
            context.Response.Headers["es-auth-sign"] = state.Fault == FixtureFault.BadMetadataAuth
                ? new string('0', 64) : IndependentHash("POST" + path + nonce + timestamp + AppKey + response + AppSecret);
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(response, context.RequestAborted);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            state.Errors.Enqueue(ex.Message);
            context.Response.StatusCode = 500;
        }
    }

    private static async Task HandleDssAsync(HttpContext context, FixtureState state, bool verify)
    {
        if (verify) Interlocked.Increment(ref state.VerifyCalls); else Interlocked.Increment(ref state.SignCalls);
        try
        {
            if (context.Connection.ClientCertificate is null) throw new InvalidOperationException("DSS request has no TLS identity.");
            var json = await new StreamReader(context.Request.Body, Encoding.UTF8).ReadToEndAsync(context.RequestAborted);
            var path = context.Request.Path.Value!;
            var nonce = context.Request.Headers["es-auth-nonce"].ToString();
            var timestamp = context.Request.Headers["es-auth-timestamp"].ToString();
            var canonical = "POST" + path + "es-auth-appkey:" + AppKey + "es-auth-nonce:" + nonce + "es-auth-timestamp:" + timestamp + "json=" + json + AppSecret;
            if (context.Request.Headers["es-auth-appkey"] != AppKey || nonce.Length != 16 || !nonce.All(Uri.IsHexDigit) ||
                !long.TryParse(timestamp, out var time) || Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - time) > 30000 ||
                context.Request.Headers["es-auth-sign"] != IndependentHash(canonical))
                throw new InvalidOperationException("DSS request authentication contract failed.");
            using var parsed = JsonDocument.Parse(json);
            var body = parsed.RootElement;
            var allowed = verify ? new[] { "keyName", "signAlgorithm", "data", "signData" } : new[] { "keyName", "signAlgorithm", "data" };
            if (!body.EnumerateObject().Select(x => x.Name).Order().SequenceEqual(allowed.Order()) || body.GetProperty("keyName").GetString() != "local-ed25519" || body.GetProperty("signAlgorithm").GetString() != "Ed25519")
                throw new InvalidOperationException("DSS payload shape or key mapping is invalid.");
            var data = Convert.FromHexString(body.GetProperty("data").GetString()!);
            state.LastData = data;
            var fault = state.Fault;
            if (!verify && fault == FixtureFault.SlowSign)
            {
                try { await Task.Delay(TimeSpan.FromSeconds(10), context.RequestAborted); }
                catch (OperationCanceledException) { return; }
            }
            string response;
            if (verify)
            {
                var verifier = new Ed25519Signer();
                verifier.Init(false, state.SigningKey.Public);
                verifier.BlockUpdate(data, 0, data.Length);
                var valid = verifier.VerifySignature(Convert.FromHexString(body.GetProperty("signData").GetString()!));
                response = JsonSerializer.Serialize(new { verifyResult = valid && fault != FixtureFault.FalseVerification ? "true" : "false" });
            }
            else
            {
                var signer = new Ed25519Signer(); signer.Init(true, state.SigningKey.Private); signer.BlockUpdate(data, 0, data.Length);
                var signature = signer.GenerateSignature();
                if (fault == FixtureFault.CorruptSignature) signature[0] ^= 0xff;
                response = JsonSerializer.Serialize(new { signData = fault == FixtureFault.MalformedSignature ? "AA" : Convert.ToHexString(signature) });
            }
            context.Response.Headers["es-auth-appkey"] = AppKey;
            context.Response.Headers["es-auth-sign"] = (!verify && fault == FixtureFault.BadSignAuth) || (verify && fault == FixtureFault.BadVerifyAuth)
                ? new string('0', 64) : IndependentHash("POST" + path + nonce + timestamp + AppKey + response + AppSecret);
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(response, context.RequestAborted);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            state.Errors.Enqueue(ex.Message);
            context.Response.StatusCode = 500;
        }
    }

    private static async Task HandlePkiAsync(HttpContext context, FixtureState state)
    {
        Interlocked.Increment(ref state.PkiCalls);
        try
        {
            if (context.Connection.ClientCertificate is null || context.Request.Headers.Keys.Any(x => x.StartsWith("es-auth-", StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException("PKI transport identity or separated authentication failed.");
            using var json = await JsonDocument.ParseAsync(context.Request.Body, cancellationToken: context.RequestAborted);
            var root = json.RootElement;
            if (!root.EnumerateObject().Select(x => x.Name).Order().SequenceEqual(new[] { "requestMetadata", "requestParams" }))
                throw new InvalidOperationException("PKI request envelope is invalid.");
            var parameters = root.GetProperty("requestParams");
            var metadata = root.GetProperty("requestMetadata");
            if (parameters.GetProperty("cert_profile").GetString() != "local-oem-dev" || metadata.GetProperty("userSourceIP").GetString() != "127.0.0.1")
                throw new InvalidOperationException("PKI profile or source IP is invalid.");
            var csr = Encoding.UTF8.GetString(Convert.FromBase64String(parameters.GetProperty("csr").GetString()!));
            var parsed = CsrService.ParseAndValidate(csr, state.Template!);
            if (metadata.GetProperty("ecuVariant").GetString() != parsed.VariantId || csr.Contains("PRIVATE KEY", StringComparison.Ordinal))
                throw new InvalidOperationException("PKI CSR and public metadata are invalid.");
            var requestId = metadata.GetProperty("requestID").GetString()!;
            var certificate = Pem("CERTIFICATE", BusinessLeaf(parsed, state.Template!, state.Issuer, state.IssuerKey).GetEncoded());
            object response = state.Fault switch
            {
                FixtureFault.PkiReject => new { code = "123456", description = "Rejected test request" },
                FixtureFault.PkiMissingCode => new { data = new { requestId = "local-" + requestId, certificate = Convert.ToBase64String(Encoding.UTF8.GetBytes(certificate)) } },
                _ => new { code = "000000", description = "SUCCESS", data = new { requestId = "local-" + requestId, certificate = Convert.ToBase64String(Encoding.UTF8.GetBytes(certificate)) } }
            };
            await context.Response.WriteAsJsonAsync(response, context.RequestAborted);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            state.Errors.Enqueue(ex.Message);
            context.Response.StatusCode = 500;
        }
    }

    private static string IndependentHash(string canonical)
    {
        var encoded = Uri.EscapeDataString(canonical).Replace("%20", "+", StringComparison.Ordinal).Replace("%2A", "*", StringComparison.Ordinal).Replace("~", "%7E", StringComparison.Ordinal);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(encoded))).ToLowerInvariant();
    }

    private static SupplierConnection CopyTransport(SupplierConnection source) => new()
    {
        Id = source.Id + 100, Module = source.Module, DssProjectId = source.DssProjectId, BaseUrl = source.BaseUrl,
        ClientCertificatePath = source.ClientCertificatePath, ClientPrivateKeyPath = source.ClientPrivateKeyPath,
        ServerCaChainPath = source.ServerCaChainPath, AppKey = source.AppKey, AppSecret = source.AppSecret, TimeoutSeconds = 5
    };

    private static async Task<bool> TransportRejectedAsync(HttpClient client, string origin)
    {
        try { using var response = await client.GetAsync(origin); return !response.IsSuccessStatusCode; }
        catch (HttpRequestException) { return true; }
    }

    private static X509Certificate2 TransportCa(ECDsa key, string name)
    {
        var request = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(2));
    }

    private static X509Certificate2 TransportLeaf(X509Certificate2 issuer, ECDsa key, bool server)
    {
        var request = new CertificateRequest(server ? "CN=localhost" : "CN=fixture-client", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new(server ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2") }, true));
        if (server) { var names = new SubjectAlternativeNameBuilder(); names.AddDnsName("localhost"); request.CertificateExtensions.Add(names.Build()); }
        using var publicCertificate = request.Create(issuer, DateTimeOffset.UtcNow.AddMinutes(-10), DateTimeOffset.UtcNow.AddDays(1), RandomNumberGenerator.GetBytes(16));
        using var withKey = publicCertificate.CopyWithPrivateKey(key);
        return X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.DefaultKeySet | X509KeyStorageFlags.Exportable);
    }

    private static bool ValidateTransportChain(X509Certificate2 certificate, X509Certificate2 root, string usage)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(usage));
        return chain.Build(certificate);
    }

    private static AsymmetricCipherKeyPair EdKeyPair()
    {
        var generator = new Ed25519KeyPairGenerator(); generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom())); return generator.GenerateKeyPair();
    }

    private static BcCertificate BusinessCa(string name, AsymmetricCipherKeyPair keys, BcCertificate? issuer, AsymmetricKeyParameter? issuerKey)
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.ValueOf(issuer is null ? 1 : 2));
        generator.SetSubjectDN(new X509Name("CN=" + name)); generator.SetIssuerDN(issuer?.SubjectDN ?? new X509Name("CN=" + name));
        generator.SetPublicKey(keys.Public); generator.SetNotBefore(DateTime.UtcNow.AddDays(-1)); generator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        generator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(issuer is null ? 1 : 0));
        generator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
        generator.AddExtension(new DerObjectIdentifier(CsrService.CertTypeOid), true, new DerOctetString(Encoding.UTF8.GetBytes(issuer is null ? "rootCA" : "diagCA")));
        generator.AddExtension(new DerObjectIdentifier(CsrService.TrustGradeOid), true, new DerOctetString(Encoding.UTF8.GetBytes("dev")));
        return generator.Generate(new Asn1SignatureFactory("Ed25519", issuerKey ?? keys.Private));
    }

    private static BcCertificate BusinessLeaf(ParsedCsr csr, PkiTemplate template, BcCertificate issuer, AsymmetricKeyParameter issuerKey)
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(new BigInteger(120, new SecureRandom()));
        generator.SetSubjectDN(csr.Request.GetCertificationRequestInfo().Subject); generator.SetIssuerDN(issuer.SubjectDN); generator.SetPublicKey(csr.Request.GetPublicKey());
        var now = DateTime.UtcNow.AddMinutes(-1); generator.SetNotBefore(now); generator.SetNotAfter(now.AddDays(PkiRoleCatalog.Find(template.DiagUserRole)!.ValidityDays));
        generator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        generator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.NonRepudiation));
        generator.AddExtension(new DerObjectIdentifier(CsrService.CertTypeOid), true, new DerOctetString(Encoding.UTF8.GetBytes("diagUser")));
        generator.AddExtension(new DerObjectIdentifier(CsrService.TrustGradeOid), true, new DerOctetString(Encoding.UTF8.GetBytes(template.TrustGrade)));
        generator.AddExtension(new DerObjectIdentifier(CsrService.DiagRoleOid), true, new DerInteger(new BigInteger(template.DiagUserRole, 16)));
        generator.AddExtension(new DerObjectIdentifier(CsrService.VariantOid), true, new DerOctetString(Convert.FromHexString(csr.VariantId)));
        if (csr.UniqueId is not null) generator.AddExtension(new DerObjectIdentifier(CsrService.UniqueOid), true, new DerUtf8String(csr.UniqueId));
        return generator.Generate(new Asn1SignatureFactory("Ed25519", issuerKey));
    }

    private static string Pem(string type, byte[] bytes) => "-----BEGIN " + type + "-----\n" + Convert.ToBase64String(bytes, Base64FormattingOptions.InsertLineBreaks) + "\n-----END " + type + "-----\n";

    private enum FixtureFault { None, BadSignAuth, MalformedSignature, CorruptSignature, BadMetadataAuth, FalseVerification, BadVerifyAuth, SlowSign, PkiReject, PkiMissingCode }
    private sealed class FixtureState(AsymmetricCipherKeyPair signingKey, BcCertificate issuer, AsymmetricKeyParameter issuerKey)
    {
        public AsymmetricCipherKeyPair SigningKey { get; } = signingKey;
        public BcCertificate Issuer { get; } = issuer;
        public AsymmetricKeyParameter IssuerKey { get; } = issuerKey;
        public PkiTemplate? Template { get; set; }
        public volatile FixtureFault Fault;
        public int SignCalls, VerifyCalls, GetKeyCalls, PkiCalls;
        public string SupplierKeyStatus = "1";
        public byte[] LastData = [];
        public ConcurrentQueue<string> Errors { get; } = new();
    }
}
