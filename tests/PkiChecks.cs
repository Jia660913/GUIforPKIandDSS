using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;
using ZfTools.Data;
using ZfTools.Services;

public static class PkiChecks
{
    // Standalone runner: the parent harness provides its assertion collector; no supplier traffic.
    public static void Run(Action<bool, string> assert)
    {
        var service = new CsrService();
        var template = new PkiTemplate { DiagUserRole = "00800000", TrustGrade = "dev", IncludeFixedFieldsInCsr = false };
        var generated = service.Generate("0040000100000000", "ECU-100", "ECU,OU=not-a-separate-attribute", template);
        var parsed = CsrService.ParseAndValidate(generated.CsrPem, template);
        assert(parsed.CommonName == "ECU,OU=not-a-separate-attribute" && parsed.Request.GetCertificationRequestInfo().Subject.GetOidList().Count == 1, "PKI structured Common Name does not inject DN attributes");
        assert(parsed.VariantId == "0040000100000000" && parsed.UniqueId == "ECU-100", "PKI upload reads ECU identifiers from CSR");
        assert(parsed.Request.GetRequestedExtensions().GetExtension(new DerObjectIdentifier(CsrService.DiagRoleOid)) is null, "PKI CA-fixed extensions may be absent from CSR");
        Reject(() => service.Generate("00", null, "test", template), "PKI OEM Development requires Unique ID", assert);
        template.DiagUserRole = "80";
        Reject(() => service.Generate("00", null, "test", template), "PKI ZF Development requires Unique ID", assert);
        template.DiagUserRole = "02";
        Reject(() => service.Generate("00", null, "test", template), "PKI Claims requires Unique ID", assert);
        template.DiagUserRole = "00020000";
        Reject(() => service.Generate("00", "ECU", "test", template), "PKI reserved OEM Claims is unavailable", assert);
        template.DiagUserRole = "40";
        assert(CsrService.ParseAndValidate(service.Generate("00", null, "test", template).CsrPem, template).UniqueId is null, "PKI Production accepts absent Unique ID");
        template.VariantExactBytes = 8;
        Reject(() => service.Generate("00", null, "test", template), "PKI configured Variant byte length enforced", assert);
        template.VariantExactBytes = 0;
        Reject(() => service.Generate("000", null, "test", template), "PKI rejects odd-length Variant hex", assert);
        Reject(() => service.Generate("00", new string('é', 17), "test", template), "PKI Unique limit counts UTF-8 bytes", assert);
        Reject(() => CsrService.ParseAndValidate(generated.CsrPem + generated.PrivateKeyPem, template), "PKI rejects private key in CSR upload", assert);
        var der = Convert.FromBase64String(generated.CsrPem.Split("-----")[2]); der[^1] ^= 1;
        Reject(() => CsrService.ParseAndValidate(Pem("CERTIFICATE REQUEST", der), template), "PKI rejects tampered CSR signature", assert);
        template.DiagUserRole = "00800000"; template.IncludeFixedFieldsInCsr = true;
        var fixedCsr = service.Generate("0040000100000000", "ECU-100", "test", template);
        var fixedParsed = CsrService.ParseAndValidate(fixedCsr.CsrPem, template);
        assert(DerInteger.GetInstance(fixedParsed.Request.GetRequestedExtensions().GetExtensionParsedValue(new DerObjectIdentifier(CsrService.DiagRoleOid))).Value.IntValue == 8388608, "PKI preserves OEM role as numeric ASN.1 INTEGER");
        template.DiagUserRole = "80";
        Reject(() => CsrService.ParseAndValidate(fixedCsr.CsrPem, template), "PKI distinguishes OEM and ZF roles", assert);
        template.DiagUserRole = "00800000";
        Reject(() => CsrService.ParseAndValidate(generated.CsrPem, template), "PKI confirmed fixed-field inclusion policy enforced", assert);
        Reject(() => PkiService.ParseSuccessResponse("{\"data\":{\"certificate\":\"abc\"}}"), "PKI requires explicit success code", assert);
        Reject(() => PkiService.ParseSuccessResponse("{\"code\":\"000000\",\"certificate\":\"abc\"}"), "PKI requires data object", assert);
        Reject(() => PkiService.ParseSuccessResponse(JsonSerializer.Serialize(new { code = "000000", data = new { requestId = "supplier-id", certificate = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----" } })), "PKI rejects unwrapped PEM response", assert);

        template.IncludeFixedFieldsInCsr = false;
        var dir = Path.Combine(Path.GetTempPath(), "zf-pki-test-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
        try
        {
            var now = DateTime.UtcNow.AddSeconds(-10);
            var rootKey = KeyPair(); var root = CreateCa("test-root", rootKey, null, null, now, true);
            var issuerKey = KeyPair(); var issuer = CreateCa("test-issuer", issuerKey, root, rootKey.Private, now, false);
            var chainPath = Path.Combine(dir, "ca.pem"); File.WriteAllText(chainPath, Pem("CERTIFICATE", root.GetEncoded()) + Pem("CERTIFICATE", issuer.GetEncoded()));
            var leaf = CreateLeaf(parsed, template, issuer, issuerKey.Private, now, 30);
            var pem = Pem("CERTIFICATE", leaf.GetEncoded());
            PkiCertificateValidator.Validate(pem, parsed, template, chainPath);
            assert(true, "PKI validates Ed25519 leaf, custom critical extensions and three-level CA chain");
            var wrongUsage = CreateLeaf(parsed, template, issuer, issuerKey.Private, now, 30, KeyUsage.DigitalSignature);
            Reject(() => PkiCertificateValidator.Validate(Pem("CERTIFICATE", wrongUsage.GetEncoded()), parsed, template, chainPath), "PKI requires the specified contentCommitment key usage", assert);
            var caUsage = CreateLeaf(parsed, template, issuer, issuerKey.Private, now, 30, KeyUsage.NonRepudiation | KeyUsage.KeyCertSign);
            Reject(() => PkiCertificateValidator.Validate(Pem("CERTIFICATE", caUsage.GetEncoded()), parsed, template, chainPath), "PKI rejects CA signing usage in a user certificate", assert);
            var response = PkiService.ParseSuccessResponse(JsonSerializer.Serialize(new { code = "000000", data = new { requestId = "supplier-id", certificate = Convert.ToBase64String(Encoding.UTF8.GetBytes(pem)) } }));
            assert(response.CertificatePem == pem && response.SupplierRequestId == "supplier-id", "PKI decodes exact documented success envelope and preserves supplier ID");
            var other = CsrService.ParseAndValidate(service.Generate("0040000100000000", "ECU-100", parsed.CommonName, template).CsrPem, template);
            Reject(() => PkiCertificateValidator.Validate(pem, other, template, chainPath), "PKI rejects certificate for another CSR public key", assert);
            var wrongLife = CreateLeaf(parsed, template, issuer, issuerKey.Private, now, 180);
            Reject(() => PkiCertificateValidator.Validate(Pem("CERTIFICATE", wrongLife.GetEncoded()), parsed, template, chainPath), "PKI rejects wrong role validity", assert);
            template.TrustGrade = "field";
            Reject(() => PkiCertificateValidator.Validate(pem, parsed, template, chainPath), "PKI rejects wrong certificate trust grade", assert);
        }
        finally { Directory.Delete(dir, true); }
    }

    private static void Reject(Action action, string message, Action<bool,string> assert)
    {
        try { action(); assert(false, message); }
        catch (Exception ex) when (ex is InvalidOperationException or FormatException or ArgumentException) { assert(true, message); }
    }
    private static AsymmetricCipherKeyPair KeyPair()
    {
        var generator = new Ed25519KeyPairGenerator(); generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom())); return generator.GenerateKeyPair();
    }
    private static X509Certificate CreateCa(string name, AsymmetricCipherKeyPair key, X509Certificate? issuer, AsymmetricKeyParameter? issuerKey, DateTime now, bool root)
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.ValueOf(root ? 1 : 2)); generator.SetSubjectDN(new X509Name("CN=" + name)); generator.SetIssuerDN(issuer?.SubjectDN ?? new X509Name("CN=" + name));
        generator.SetPublicKey(key.Public); generator.SetNotBefore(now.AddDays(-1)); generator.SetNotAfter(now.AddYears(5));
        generator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(root ? 1 : 0));
        generator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
        generator.AddExtension(new DerObjectIdentifier(CsrService.CertTypeOid), true, new DerOctetString(Encoding.UTF8.GetBytes(root ? "rootCA" : "diagCA")));
        generator.AddExtension(new DerObjectIdentifier(CsrService.TrustGradeOid), true, new DerOctetString(Encoding.UTF8.GetBytes("dev")));
        return generator.Generate(new Asn1SignatureFactory("Ed25519", issuerKey ?? key.Private));
    }
    private static X509Certificate CreateLeaf(ParsedCsr csr, PkiTemplate template, X509Certificate issuer, AsymmetricKeyParameter issuerKey, DateTime now, int days, int keyUsage = KeyUsage.NonRepudiation)
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.ValueOf(10)); generator.SetSubjectDN(csr.Request.GetCertificationRequestInfo().Subject); generator.SetIssuerDN(issuer.SubjectDN);
        generator.SetPublicKey(csr.Request.GetPublicKey()); generator.SetNotBefore(now); generator.SetNotAfter(now.AddDays(days));
        generator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false)); generator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(keyUsage));
        generator.AddExtension(new DerObjectIdentifier(CsrService.CertTypeOid), true, new DerOctetString(Encoding.UTF8.GetBytes("diagUser")));
        generator.AddExtension(new DerObjectIdentifier(CsrService.TrustGradeOid), true, new DerOctetString(Encoding.UTF8.GetBytes(template.TrustGrade)));
        generator.AddExtension(new DerObjectIdentifier(CsrService.DiagRoleOid), true, new DerInteger(new BigInteger(template.DiagUserRole, 16)));
        generator.AddExtension(new DerObjectIdentifier(CsrService.VariantOid), true, new DerOctetString(Convert.FromHexString(csr.VariantId)));
        if (csr.UniqueId is not null) generator.AddExtension(new DerObjectIdentifier(CsrService.UniqueOid), true, new DerUtf8String(csr.UniqueId));
        return generator.Generate(new Asn1SignatureFactory("Ed25519", issuerKey));
    }
    private static string Pem(string type, byte[] bytes)
    {
        using var text = new StringWriter(); var writer = new PemWriter(text); writer.WriteObject(new PemObject(type, bytes)); writer.Writer.Flush(); return text.ToString();
    }
}
