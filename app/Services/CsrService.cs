using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using ZfTools.Data;
using BcPemReader = Org.BouncyCastle.Utilities.IO.Pem.PemReader;
using BcPemWriter = Org.BouncyCastle.Utilities.IO.Pem.PemWriter;

namespace ZfTools.Services;

public sealed record GeneratedCsr(string CsrPem, string PrivateKeyPem, string CommonName);

public sealed class CsrService
{
    private const string VariantOid = "1.3.6.1.4.1.13159.1.2.589.3.4.1";
    private const string UniqueOid = "1.3.6.1.4.1.13159.1.2.589.3.5.1";
    private const string CertTypeOid = "1.3.6.1.4.1.13159.1.2.589.3.1.1";
    private const string TrustGradeOid = "1.3.6.1.4.1.13159.1.2.589.3.2.1";
    private const string DiagRoleOid = "1.3.6.1.4.1.13159.1.2.589.3.3.1";

    public GeneratedCsr Generate(string variantId, string? uniqueId, string commonName, string certType, string trustGrade, string diagUserRole)
    {
        var generator = new Ed25519KeyPairGenerator();
        generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var pair = generator.GenerateKeyPair();
        var subject = new X509Name($"CN={commonName}");
        var extGen = new X509ExtensionsGenerator();
        extGen.AddExtension(new DerObjectIdentifier(VariantOid), true, new DerOctetString(Convert.FromHexString(variantId.Replace(" ", ""))));
        if (!string.IsNullOrWhiteSpace(uniqueId)) extGen.AddExtension(new DerObjectIdentifier(UniqueOid), false, new DerUtf8String(uniqueId));
        extGen.AddExtension(new DerObjectIdentifier(CertTypeOid), false, new DerOctetString(Encoding.UTF8.GetBytes(certType)));
        extGen.AddExtension(new DerObjectIdentifier(TrustGradeOid), false, new DerOctetString(Encoding.UTF8.GetBytes(trustGrade)));
        var role = diagUserRole.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? diagUserRole[2..] : diagUserRole;
        extGen.AddExtension(new DerObjectIdentifier(DiagRoleOid), false, new DerInteger(new BigInteger(role, 16)));
        var attributes = new AttributePkcs[]
        {
            new(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extGen.Generate()))
        };
        var csr = new Pkcs10CertificationRequest("Ed25519", subject, pair.Public, new DerSet(attributes), pair.Private);
        return new GeneratedCsr(ToPem("CERTIFICATE REQUEST", csr.GetEncoded()), ToPem("PRIVATE KEY", Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(pair.Private).GetEncoded()), commonName);
    }

    public static string? ReadCommonName(string pem)
    {
        try
        {
            using var reader = new BcPemReader(new StringReader(pem));
            var csr = reader.ReadPemObject();
            if (csr is null) return null;
            var request = new Pkcs10CertificationRequest(csr.Content);
            return request.GetCertificationRequestInfo().Subject.GetValueList(Org.BouncyCastle.Asn1.X509.X509Name.CN).Count > 0
                ? request.GetCertificationRequestInfo().Subject.GetValueList(Org.BouncyCastle.Asn1.X509.X509Name.CN)[0].ToString() : null;
        }
        catch { return null; }
    }

    public static bool VerifySignature(string pem)
    {
        try
        {
            using var reader = new BcPemReader(new StringReader(pem));
            var pemObject = reader.ReadPemObject();
            return pemObject is not null && new Pkcs10CertificationRequest(pemObject.Content).Verify();
        }
        catch { return false; }
    }

    public static bool VerifyAndMatch(string pem, PkiTemplate template, string expectedVariant, string? expectedUnique, out string? commonName, out string? actualUnique, out string error)
    {
        commonName = null;
        actualUnique = null;
        try
        {
            using var reader = new BcPemReader(new StringReader(pem));
            var pemObject = reader.ReadPemObject();
            if (pemObject is null) { error = "CSR 必须是 PEM 格式。"; return false; }
            var csr = new Pkcs10CertificationRequest(pemObject.Content);
            if (!csr.Verify()) { error = "CSR 签名校验失败。"; return false; }
            var subject = csr.GetCertificationRequestInfo().Subject;
            var names = subject.GetValueList(Org.BouncyCastle.Asn1.X509.X509Name.CN);
            commonName = names.Count > 0 ? names[0].ToString() : null;
            var extensions = csr.GetRequestedExtensions();
            if (extensions is null) { error = "CSR 缺少证书扩展请求。"; return false; }
            if (!ReadOctets(extensions, VariantOid).SequenceEqual(Convert.FromHexString(expectedVariant.Replace(" ", "")))) { error = "CSR 中的 ECU Variant ID 与表单输入不一致。"; return false; }
            var uniqueValue = extensions.GetExtensionParsedValue(new DerObjectIdentifier(UniqueOid));
            if (uniqueValue is not null) actualUnique = DerUtf8String.GetInstance(uniqueValue).GetString();
            if (template.RequiresEcuUniqueId && string.IsNullOrWhiteSpace(actualUnique)) { error = "所选 Claims 模板要求 CSR 包含 ECU Unique ID。"; return false; }
            if (!string.IsNullOrWhiteSpace(expectedUnique))
            {
                if (!string.Equals(actualUnique, expectedUnique, StringComparison.Ordinal)) { error = "CSR 中的 ECU Unique ID 与表单输入不一致。"; return false; }
            }
            var certType = ReadOctets(extensions, CertTypeOid);
            var trustGrade = ReadOctets(extensions, TrustGradeOid);
            var roleValue = extensions.GetExtensionParsedValue(new DerObjectIdentifier(DiagRoleOid));
            if (!Encoding.UTF8.GetString(certType).Equals(template.CertType, StringComparison.Ordinal) ||
                !Encoding.UTF8.GetString(trustGrade).Equals(template.TrustGrade, StringComparison.Ordinal) ||
                roleValue is null || !DerInteger.GetInstance(roleValue).Value.Equals(new BigInteger(template.DiagUserRole, 16)))
            {
                error = "CSR 中的证书类型、信任等级或诊断角色与所选模板不一致。";
                return false;
            }
            error = "";
            return true;
        }
        catch (Exception ex)
        {
            error = "无法解析 CSR：" + ex.Message;
            return false;
        }
    }

    private static byte[] ReadOctets(X509Extensions extensions, string oid, bool required = true)
    {
        var value = extensions.GetExtensionParsedValue(new DerObjectIdentifier(oid));
        if (value is null && !required) return [];
        if (value is null) throw new InvalidOperationException("CSR 缺少证书扩展。");
        return DerOctetString.GetInstance(value).GetOctets();
    }

    private static string ToPem(string type, byte[] value)
    {
        using var writer = new StringWriter();
        var pem = new BcPemWriter(writer); pem.WriteObject(new PemObject(type, value)); pem.Writer.Flush();
        return writer.ToString();
    }
}
