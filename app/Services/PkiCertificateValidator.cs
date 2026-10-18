using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using ZfTools.Data;

namespace ZfTools.Services;

public static class PkiCertificateValidator
{
    public static void Validate(string certificatePem, ParsedCsr csr, PkiTemplate template, string issuerCaChainPath, DateTime? now = null)
    {
        try
        {
            var match = Regex.Match(certificatePem.Trim(), "\\A-----BEGIN CERTIFICATE-----\\s+(?<data>[A-Za-z0-9+/=\\s]+)-----END CERTIFICATE-----\\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
            if (!match.Success) throw new InvalidOperationException("The supplier response must contain exactly one PEM certificate.");
            var bytes = Convert.FromBase64String(match.Groups["data"].Value);
            var leaf = new X509CertificateParser().ReadCertificate(bytes);
            if (leaf is null || !leaf.GetEncoded().SequenceEqual(bytes)) throw new InvalidOperationException("The returned certificate is not canonical DER.");
            if (leaf.GetPublicKey() is not Ed25519PublicKeyParameters key || !key.GetEncoded().SequenceEqual(((Ed25519PublicKeyParameters)csr.Request.GetPublicKey()).GetEncoded()))
                throw new InvalidOperationException("The issued certificate public key does not match the CSR.");
            if (leaf.SigAlgOid != EdECObjectIdentifiers.id_Ed25519.Id) throw new InvalidOperationException("The issued certificate does not use the configured Ed25519 signature algorithm.");
            var extensions = leaf.CertificateStructure.TbsCertificate.Extensions ?? throw new InvalidOperationException("The issued certificate has no extensions.");
            if (leaf.GetBasicConstraints() != -1 || extensions.GetExtension(X509Extensions.BasicConstraints) is null)
                throw new InvalidOperationException("The returned certificate must be a non-CA user certificate.");
            var usage = leaf.GetKeyUsage();
            // The ZF diagnostic certificate specification uses nonRepudiation/contentCommitment.
            if (usage is null || !usage[1] || usage[5] || usage[6]) throw new InvalidOperationException("The returned certificate must permit content commitment and must not permit CA signing.");
            var names = leaf.SubjectDN.GetValueList(X509Name.CN);
            if (names.Count != 1 || names[0] != csr.CommonName) throw new InvalidOperationException("The issued certificate Common Name does not match the CSR.");
            CsrService.ValidateFixedExtensions(extensions, template, true, false);
            var variant = CsrService.ReadOctets(extensions, CsrService.VariantOid, 16, true)!;
            if (Convert.ToHexString(variant) != csr.VariantId) throw new InvalidOperationException("The issued ECU Variant ID does not match the CSR.");
            var uniqueValue = extensions.GetExtensionParsedValue(new DerObjectIdentifier(CsrService.UniqueOid));
            if (uniqueValue is not null && uniqueValue is not DerUtf8String) throw new InvalidOperationException("The issued ECU Unique ID is not an ASN.1 UTF8String.");
            var unique = (uniqueValue as DerUtf8String)?.GetString();
            if (unique != csr.UniqueId) throw new InvalidOperationException("The issued ECU Unique ID does not match the CSR.");
            foreach (DerObjectIdentifier oid in extensions.ExtensionOids)
                if (oid.Id.StartsWith("1.3.6.1.4.1.13159.1.2.589.3.", StringComparison.Ordinal) && !CsrService.CustomOids.Contains(oid.Id))
                    throw new InvalidOperationException("The returned certificate contains an unexpected ZF custom extension.");
            var instant = (now ?? DateTime.UtcNow).ToUniversalTime();
            if (leaf.NotBefore.ToUniversalTime() > instant.AddMinutes(5) || leaf.NotAfter.ToUniversalTime() <= instant)
                throw new InvalidOperationException("The issued certificate is not currently valid.");
            var role = PkiRoleCatalog.Find(template.DiagUserRole) ?? throw new InvalidOperationException("The certificate role mapping is invalid.");
            if (Math.Abs((leaf.NotAfter.ToUniversalTime() - leaf.NotBefore.ToUniversalTime() - TimeSpan.FromDays(role.ValidityDays)).TotalMinutes) > 5)
                throw new InvalidOperationException($"The issued certificate validity does not match the {role.ValidityDays}-day role policy.");
            ValidateChain(leaf, template, issuerCaChainPath, instant);
        }
        catch (InvalidOperationException) { throw; }
        catch (Exception ex) when (ex is ArgumentException or FormatException or IOException or Org.BouncyCastle.Security.GeneralSecurityException)
        {
            throw new InvalidOperationException("The supplier certificate could not be validated against the configured business CA chain.", ex);
        }
    }

    private static void ValidateChain(X509Certificate leaf, PkiTemplate template, string path, DateTime now)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) throw new InvalidOperationException("The PKI business CA chain is not configured.");
        var bundle = new X509CertificateParser().ReadCertificates(File.ReadAllBytes(path)).ToList();
        if (bundle.Count == 0) throw new InvalidOperationException("The business CA bundle contains no certificates.");
        var anchors = new HashSet<TrustAnchor>();
        foreach (var certificate in bundle)
        {
            if (certificate.GetBasicConstraints() < 0) throw new InvalidOperationException("The business CA bundle contains a non-CA certificate.");
            certificate.CheckValidity(now);
            ValidateCaExtensions(certificate, template.TrustGrade);
            if (certificate.SubjectDN.Equivalent(certificate.IssuerDN))
            {
                certificate.Verify(certificate.GetPublicKey());
                anchors.Add(new TrustAnchor(certificate, null));
            }
        }
        if (anchors.Count == 0) throw new InvalidOperationException("The business CA bundle must include a trusted self-signed root.");
        var parameters = new PkixBuilderParameters(anchors, new X509CertStoreSelector { Certificate = leaf })
        {
            IsRevocationEnabled = false,
            Date = now
        };
        parameters.AddStoreCert(CollectionUtilities.CreateStore(bundle.Append(leaf)));
        parameters.AddCertPathChecker(new ZfExtensionChecker(leaf, template.TrustGrade));
        var built = new PkixCertPathBuilder().Build(parameters);
        if (built.CertPath.Certificates.Count != 2) throw new InvalidOperationException("The returned user certificate must chain through one intermediate CA to its root.");
        // Chain, constraints and validity are checked locally. The API has no documented revocation-status operation.
    }

    private static void ValidateCaExtensions(X509Certificate certificate, string trustGrade)
    {
        var ext = certificate.CertificateStructure.TbsCertificate.Extensions;
        if (ext is null) throw new InvalidOperationException("The configured business CA has no extensions.");
        if (certificate.GetPublicKey() is not Ed25519PublicKeyParameters || certificate.SigAlgOid != EdECObjectIdentifiers.id_Ed25519.Id) throw new InvalidOperationException("The configured business CA must use Ed25519.");
        var type = CsrService.ReadOctets(ext, CsrService.CertTypeOid, 8, true)!;
        var trust = CsrService.ReadOctets(ext, CsrService.TrustGradeOid, 5, true)!;
        var expectedType = certificate.SubjectDN.Equivalent(certificate.IssuerDN) ? "rootCA" : "diagCA";
        if (Encoding.UTF8.GetString(type) != expectedType) throw new InvalidOperationException("The configured CA has an unexpected ZF certificate type.");
        if (Encoding.UTF8.GetString(trust) != trustGrade) throw new InvalidOperationException("The business CA trust grade does not match the selected environment.");
    }

    private sealed class ZfExtensionChecker(X509Certificate leaf, string trustGrade) : PkixCertPathChecker
    {
        public override void Init(bool forward) { if (forward) throw new InvalidOperationException("Forward checking is unsupported."); }
        public override bool IsForwardCheckingSupported() => false;
        public override ISet<string> GetSupportedExtensions() => new HashSet<string>(CsrService.CustomOids);
        public override void Check(X509Certificate certificate, ISet<string> unresolvedCritExts)
        {
            if (certificate.Equals(leaf)) foreach (var oid in CsrService.CustomOids) unresolvedCritExts.Remove(oid);
            else
            {
                ValidateCaExtensions(certificate, trustGrade);
                unresolvedCritExts.Remove(CsrService.CertTypeOid);
                unresolvedCritExts.Remove(CsrService.TrustGradeOid);
            }
        }
        public override object Clone() => new ZfExtensionChecker(leaf, trustGrade);
    }
}

