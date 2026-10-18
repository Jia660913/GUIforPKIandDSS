using System.Collections.Concurrent;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ZfTools.Data;

namespace ZfTools.Services;

public sealed class SupplierHttpClientFactory(SupplierSecrets secrets) : IDisposable
{
    private readonly ConcurrentDictionary<string, Lazy<ClientLease>> clients = new();

    public HttpClient CreateClient(SupplierConnection connection)
    {
        var errors = SupplierConnectionRules.GetErrors(connection, connection.Module, connection.DssProjectId);
        if (errors.Count > 0) throw new InvalidOperationException(string.Join(" ", errors));
        // Replacing an identity or trust bundle takes effect without restarting the tool.
        var version = string.Join("|", connection.Id, connection.Module, connection.BaseUrl, connection.TimeoutSeconds,
            connection.ClientCertificatePath, connection.ClientPrivateKeyPath, connection.ClientCertificatePassword,
            connection.ServerCaChainPath, connection.ClientCaChainPath, Stamp(connection.ClientCaChainPath), Stamp(connection.ClientCertificatePath), Stamp(connection.ClientPrivateKeyPath), Stamp(connection.ServerCaChainPath));
        var key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(version)));
        var lazy = clients.GetOrAdd(key, _ => new Lazy<ClientLease>(() => Create(connection), LazyThreadSafetyMode.ExecutionAndPublication));
        try { return lazy.Value.Client; }
        catch { clients.TryRemove(key, out _); throw; }
    }

    private ClientLease Create(SupplierConnection connection)
    {
        var password = secrets.Unprotect(connection.ClientCertificatePassword);
        X509Certificate2 certificate;
        var identityChain = new X509Certificate2Collection();
        try
        {
            if (string.IsNullOrWhiteSpace(connection.ClientPrivateKeyPath))
            {
                identityChain = X509CertificateLoader.LoadPkcs12CollectionFromFile(connection.ClientCertificatePath, password, X509KeyStorageFlags.DefaultKeySet);
                var identities = identityChain.Cast<X509Certificate2>().Where(x => x.HasPrivateKey).ToArray();
                if (identities.Length != 1) throw new InvalidOperationException("The PFX must contain exactly one client identity with a private key.");
                certificate = identities[0];
                identityChain.Remove(certificate);
            }
            else
            {
                using var pem = string.IsNullOrEmpty(password)
                    ? X509Certificate2.CreateFromPemFile(connection.ClientCertificatePath, connection.ClientPrivateKeyPath)
                    : X509Certificate2.CreateFromEncryptedPemFile(connection.ClientCertificatePath, password, connection.ClientPrivateKeyPath);
                // Schannel needs a temporary provider-backed key on Windows; dispose it with the client lease.
                certificate = X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.DefaultKeySet);
                identityChain.ImportFromPemFile(connection.ClientCertificatePath);
            }
        }
        catch (Exception ex) when (ex is CryptographicException or IOException or ArgumentException or InvalidOperationException)
        { foreach (var item in identityChain) item.Dispose(); throw new InvalidOperationException("Could not load the configured mTLS identity. Check its format, matching private key and password.", ex); }
        if (!certificate.HasPrivateKey || certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow || certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow)
        {
            certificate.Dispose();
            foreach (var item in identityChain) item.Dispose();
            throw new InvalidOperationException("The mTLS identity must have a private key and be within its validity period.");
        }
        var trust = new X509Certificate2Collection();
        try
        {
            if (!string.IsNullOrWhiteSpace(connection.ClientCaChainPath)) identityChain.ImportFromPemFile(connection.ClientCaChainPath);
            trust.ImportFromPemFile(connection.ServerCaChainPath);
            var roots = trust.Cast<X509Certificate2>().Where(IsRootCa).ToArray();
            if (roots.Length == 0) throw new InvalidOperationException("The server trust bundle must contain a self-issued CA root.");
            var handler = new SocketsHttpHandler
            {
                AllowAutoRedirect = false, PooledConnectionLifetime = TimeSpan.FromMinutes(5),
                ConnectTimeout = TimeSpan.FromSeconds(Math.Min(15, connection.TimeoutSeconds)),
                SslOptions = new SslClientAuthenticationOptions
                {
                    // Bind each new TLS connection to this configured identity, including after credential changes.
                    AllowTlsResume = false,
                    ClientCertificates = new X509CertificateCollection { certificate },
                    ClientCertificateContext = SslStreamCertificateContext.Create(certificate, identityChain, offline: true),
                    RemoteCertificateValidationCallback = (_, serverCertificate, suppliedChain, errors) =>
                    {
                        if (serverCertificate is null || (errors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0) return false;
                        using var leaf = X509CertificateLoader.LoadCertificate(serverCertificate.GetRawCertData());
                        using var chain = new X509Chain();
                        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                        chain.ChainPolicy.CustomTrustStore.AddRange(roots);
                        chain.ChainPolicy.ExtraStore.AddRange(trust);
                        if (suppliedChain is not null)
                            foreach (var element in suppliedChain.ChainElements) chain.ChainPolicy.ExtraStore.Add(element.Certificate);
                        chain.ChainPolicy.ApplicationPolicy.Add(new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1"));
                        // Supplier CRL/OCSP policy is not provided. This validates chain, time, EKU and hostname only.
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        chain.ChainPolicy.DisableCertificateDownloads = true;
                        return chain.Build(leaf);
                    }
                }
            };
            return new ClientLease(new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(connection.TimeoutSeconds) }, certificate, trust, identityChain);
        }
        catch { certificate.Dispose(); foreach (var item in trust) item.Dispose(); foreach (var item in identityChain) item.Dispose(); throw; }
    }

    private static bool IsRootCa(X509Certificate2 cert) => cert.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData) &&
        cert.Extensions.OfType<X509BasicConstraintsExtension>().Any(x => x.CertificateAuthority);
    private static long Stamp(string path) => string.IsNullOrWhiteSpace(path) ? 0 : File.GetLastWriteTimeUtc(path).Ticks;
    public void Dispose() { foreach (var item in clients.Values) if (item.IsValueCreated) item.Value.Dispose(); }
    private sealed record ClientLease(HttpClient Client, X509Certificate2 Identity, X509Certificate2Collection Trust, X509Certificate2Collection IdentityChain) : IDisposable
    {
        public void Dispose() { Client.Dispose(); Identity.Dispose(); foreach (var certificate in Trust) certificate.Dispose(); foreach (var certificate in IdentityChain) certificate.Dispose(); }
    }
}
