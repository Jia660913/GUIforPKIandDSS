using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using ZfTools.Data;

namespace ZfTools.Services;

public sealed record GeneratedCsr(string CsrPem, string PrivateKeyPem, string CommonName);
public sealed record ParsedCsr(string Pem, string CommonName, string VariantId, string? UniqueId, Pkcs10CertificationRequest Request);

public sealed class CsrService
{
    public const int MaximumCsrBytes = 128 * 1024;
    public const string VariantOid = "1.3.6.1.4.1.13159.1.2.589.3.4.1";
    public const string UniqueOid = "1.3.6.1.4.1.13159.1.2.589.3.5.1";
    public const string CertTypeOid = "1.3.6.1.4.1.13159.1.2.589.3.1.1";
    public const string TrustGradeOid = "1.3.6.1.4.1.13159.1.2.589.3.2.1";
    public const string DiagRoleOid = "1.3.6.1.4.1.13159.1.2.589.3.3.1";
    public static readonly IReadOnlySet<string> CustomOids = new HashSet<string> { VariantOid, UniqueOid, CertTypeOid, TrustGradeOid, DiagRoleOid };

    public GeneratedCsr Generate(string variantId, string? uniqueId, string commonName, PkiTemplate template)
    {
        ValidateInput(variantId, uniqueId, commonName, template);
        var generator = new Ed25519KeyPairGenerator();
        generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var pair = generator.GenerateKeyPair();
        // Structured attributes avoid interpreting commas, plus signs or equals signs as new DN fields.
        var subject = new X509Name(new List<DerObjectIdentifier> { X509Name.CN }, new List<string> { commonName });
        var extGen = new X509ExtensionsGenerator();
        extGen.AddExtension(new DerObjectIdentifier(VariantOid), template.VariantCritical, new DerOctetString(Convert.FromHexString(NormalizeVariant(variantId))));
        if (!string.IsNullOrEmpty(uniqueId)) extGen.AddExtension(new DerObjectIdentifier(UniqueOid), template.UniqueCritical, new DerUtf8String(uniqueId));
        if (template.IncludeFixedFieldsInCsr)
        {
            extGen.AddExtension(new DerObjectIdentifier(CertTypeOid), template.FixedFieldsCritical, new DerOctetString(Encoding.UTF8.GetBytes(template.CertType)));
            extGen.AddExtension(new DerObjectIdentifier(TrustGradeOid), template.FixedFieldsCritical, new DerOctetString(Encoding.UTF8.GetBytes(template.TrustGrade)));
            extGen.AddExtension(new DerObjectIdentifier(DiagRoleOid), template.FixedFieldsCritical, new DerInteger(new BigInteger(PkiRoleCatalog.Normalize(template.DiagUserRole)!, 16)));
        }
        var attributes = new AttributePkcs[] { new(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extGen.Generate())) };
        var request = new Pkcs10CertificationRequest("Ed25519", subject, pair.Public, new DerSet(attributes), pair.Private);
        return new(ToPem("CERTIFICATE REQUEST", request.GetEncoded()), ToPem("PRIVATE KEY", PrivateKeyInfoFactory.CreatePrivateKeyInfo(pair.Private).GetEncoded()), commonName);
    }

    // Kept for callers that explicitly need a CSR containing the three fixed fields.
    public GeneratedCsr Generate(string variantId, string? uniqueId, string commonName, string certType, string trustGrade, string diagUserRole) =>
        Generate(variantId, uniqueId, commonName, new PkiTemplate { CertType = certType, TrustGrade = trustGrade, DiagUserRole = diagUserRole, IncludeFixedFieldsInCsr = true });

    public static ParsedCsr ParseAndValidate(string pem, PkiTemplate template)
    {
        try
        {
            var request = ReadRequest(pem);
            if (!request.Verify()) throw new InvalidOperationException("The CSR signature is invalid.");
            if (request.GetPublicKey() is not Ed25519PublicKeyParameters ||
                request.SignatureAlgorithm.Algorithm.Id != EdECObjectIdentifiers.id_Ed25519.Id || request.SignatureAlgorithm.Parameters is not null)
                throw new InvalidOperationException("This tool accepts Ed25519 CSRs only.");
            var info = request.GetCertificationRequestInfo();
            if (info.SubjectPublicKeyInfo.Algorithm.Parameters is not null)
                throw new InvalidOperationException("The Ed25519 public key parameters must be absent.");
            var names = info.Subject.GetValueList(X509Name.CN);
            if (names.Count != 1) throw new InvalidOperationException("The CSR must contain exactly one Common Name.");
            var commonName = names[0];
            var extensionRequests = 0;
            if (info.Attributes is not null)
                foreach (var attribute in info.Attributes)
                {
                    var parsed = AttributePkcs.GetInstance(attribute);
                    if (parsed.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest))
                    {
                        extensionRequests++;
                        if (parsed.AttrValues.Count != 1) throw new InvalidOperationException("The CSR extension request is ambiguous.");
                    }
                }
            if (extensionRequests != 1) throw new InvalidOperationException("The CSR must contain one certificate extension request.");
            var extensions = request.GetRequestedExtensions() ?? throw new InvalidOperationException("The CSR has no requested extensions.");
            foreach (DerObjectIdentifier oid in extensions.ExtensionOids)
                if (!CustomOids.Contains(oid.Id) && template.ExtraExtensionsPolicy != "ignore")
                    throw new InvalidOperationException($"The CSR includes extension {oid.Id}, which is not allowed by this mapping.");
            var variant = Convert.ToHexString(ReadOctets(extensions, VariantOid, 16, true)!);
            var uniqueValue = extensions.GetExtensionParsedValue(new DerObjectIdentifier(UniqueOid));
            string? unique = null;
            if (uniqueValue is not null)
            {
                if (uniqueValue is not DerUtf8String text) throw new InvalidOperationException("ECU Unique ID must be an ASN.1 UTF8String.");
                unique = text.GetString();
                if (string.IsNullOrWhiteSpace(unique)) throw new InvalidOperationException("An included ECU Unique ID must not be empty.");
            }
            ValidateInput(variant, unique, commonName, template);
            ValidateCritical(extensions, VariantOid, template.VariantCritical);
            ValidateCritical(extensions, UniqueOid, template.UniqueCritical);
            ValidateFixedExtensions(extensions, template, template.IncludeFixedFieldsInCsr);
            return new(ToPem("CERTIFICATE REQUEST", request.GetEncoded()), commonName, variant, unique, request);
        }
        catch (InvalidOperationException) { throw; }
        catch (Exception ex) when (ex is ArgumentException or IOException or FormatException or Org.BouncyCastle.Security.GeneralSecurityException)
        {
            throw new InvalidOperationException("The CSR is malformed or uses unsupported encoding.", ex);
        }
    }

    public static void ValidateInput(string variant, string? unique, string commonName, PkiTemplate template)
    {
        var role = PkiRoleCatalog.Find(template.DiagUserRole) ?? throw new InvalidOperationException("The selected diagnostic role is not available.");
        if (template.CertType != "diagUser" || template.TrustGrade is not ("dev" or "field"))
            throw new InvalidOperationException("The certificate mapping has an invalid certificate type or trust grade.");
        if (!PkiService.IsValidVariantId(variant, out var error)) throw new InvalidOperationException(error);
        if (template.VariantExactBytes is < 0 or > 16) throw new InvalidOperationException("The template Variant ID length is invalid.");
        if (template.VariantExactBytes > 0 && NormalizeVariant(variant).Length != template.VariantExactBytes * 2)
            throw new InvalidOperationException($"This template requires an ECU Variant ID of exactly {template.VariantExactBytes} bytes.");
        if (!PkiService.IsValidUniqueId(unique, out error)) throw new InvalidOperationException(error);
        if (role.RequiresUniqueId && string.IsNullOrWhiteSpace(unique)) throw new InvalidOperationException("Development and Claims certificates require an ECU Unique ID.");
        if (string.IsNullOrWhiteSpace(commonName) || Encoding.UTF8.GetByteCount(commonName) > 256 || commonName.Any(char.IsControl))
            throw new InvalidOperationException("Common Name must contain 1–256 UTF-8 bytes without control characters.");
        if (!MatchesPolicy(commonName, template.CommonNamePattern)) throw new InvalidOperationException("Common Name does not match the configured supplier format.");
        if (!string.IsNullOrEmpty(unique) && !MatchesPolicy(unique, template.UniqueIdPattern)) throw new InvalidOperationException("ECU Unique ID does not match the configured supplier format.");
        if (template.ExtraExtensionsPolicy is not ("ignore" or "reject")) throw new InvalidOperationException("The CSR extension policy is invalid.");
    }

    internal static void ValidateFixedExtensions(X509Extensions extensions, PkiTemplate template, bool required, bool checkCritical = true)
    {
        var type = ReadOctets(extensions, CertTypeOid, 8, required);
        var trust = ReadOctets(extensions, TrustGradeOid, 5, required);
        if (type is not null && !type.SequenceEqual(Encoding.UTF8.GetBytes(template.CertType))) throw new InvalidOperationException("Certificate type does not match the selected template.");
        if (trust is not null && !trust.SequenceEqual(Encoding.UTF8.GetBytes(template.TrustGrade))) throw new InvalidOperationException("Trust grade does not match the selected template.");
        var role = extensions.GetExtensionParsedValue(new DerObjectIdentifier(DiagRoleOid));
        if (required && role is null) throw new InvalidOperationException("Diagnostic role is missing.");
        if (role is not null && (role is not DerInteger integer || integer.Value.SignValue < 0 || integer.Value.BitLength > 32 || !integer.Value.Equals(new BigInteger(PkiRoleCatalog.Normalize(template.DiagUserRole)!, 16))))
            throw new InvalidOperationException("Diagnostic role does not match the selected template.");
        if (checkCritical)
            foreach (var oid in new[] { CertTypeOid, TrustGradeOid, DiagRoleOid }) ValidateCritical(extensions, oid, template.FixedFieldsCritical);
    }

    internal static byte[]? ReadOctets(X509Extensions extensions, string oid, int maximumBytes, bool required)
    {
        var value = extensions.GetExtensionParsedValue(new DerObjectIdentifier(oid));
        if (value is null)
        {
            if (required) throw new InvalidOperationException($"Required extension {oid} is missing.");
            return null;
        }
        if (value is not Asn1OctetString octets) throw new InvalidOperationException($"Extension {oid} must be an ASN.1 OCTET STRING.");
        var bytes = octets.GetOctets();
        if (bytes.Length == 0 || bytes.Length > maximumBytes) throw new InvalidOperationException($"Extension {oid} has an invalid length.");
        return bytes;
    }

    private static void ValidateCritical(X509Extensions extensions, string oid, bool critical)
    {
        var extension = extensions.GetExtension(new DerObjectIdentifier(oid));
        if (extension is not null && extension.IsCritical != critical) throw new InvalidOperationException($"The critical flag of extension {oid} does not match the configured CSR policy.");
    }
    private static bool MatchesPolicy(string value, string pattern)
    {
        if (string.IsNullOrEmpty(pattern)) return true;
        try { return Regex.IsMatch(value, "\\A(?:" + pattern + ")\\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)); }
        catch (ArgumentException) { throw new InvalidOperationException("The supplier field-format configuration is invalid."); }
        catch (RegexMatchTimeoutException) { throw new InvalidOperationException("The supplier field-format check exceeded its time limit."); }
    }
    internal static Pkcs10CertificationRequest ReadRequest(string pem)
    {
        if (string.IsNullOrEmpty(pem) || Encoding.UTF8.GetByteCount(pem) > MaximumCsrBytes) throw new InvalidOperationException("The CSR must not exceed 128 KiB.");
        var match = Regex.Match(pem.Trim(), "\\A-----BEGIN (CERTIFICATE REQUEST|NEW CERTIFICATE REQUEST)-----\\s+(?<data>[A-Za-z0-9+/=\\s]+)-----END \\1-----\\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
        if (!match.Success) throw new InvalidOperationException("Upload one public PEM certificate request, without a private key or extra PEM blocks.");
        var der = Convert.FromBase64String(match.Groups["data"].Value);
        var request = new Pkcs10CertificationRequest(der);
        if (!request.GetEncoded("DER").SequenceEqual(der)) throw new InvalidOperationException("The CSR must use canonical DER encoding.");
        return request;
    }
    public static string NormalizeVariant(string value) => Regex.Replace(value, "\\s+", "").ToUpperInvariant();
    public static string? ReadCommonName(string pem)
    {
        try { var names = ReadRequest(pem).GetCertificationRequestInfo().Subject.GetValueList(X509Name.CN); return names.Count == 1 ? names[0] : null; }
        catch { return null; }
    }
    public static bool VerifySignature(string pem) { try { return ReadRequest(pem).Verify(); } catch { return false; } }
    public static bool VerifyAndMatch(string pem, PkiTemplate template, string expectedVariant, string? expectedUnique, out string? commonName, out string? actualUnique, out string error)
    {
        commonName = actualUnique = null;
        try
        {
            var parsed = ParseAndValidate(pem, template);
            if (parsed.VariantId != NormalizeVariant(expectedVariant) || (!string.IsNullOrEmpty(expectedUnique) && parsed.UniqueId != expectedUnique)) throw new InvalidOperationException("The CSR ECU identifiers do not match.");
            commonName = parsed.CommonName; actualUnique = parsed.UniqueId; error = ""; return true;
        }
        catch (InvalidOperationException ex) { error = ex.Message; return false; }
    }
    internal static string ToPem(string type, byte[] value)
    {
        using var writer = new StringWriter();
        var pem = new PemWriter(writer); pem.WriteObject(new PemObject(type, value)); pem.Writer.Flush(); return writer.ToString();
    }
}
