using System.Net;
using System.Text;
using System.Text.Json;
using ZfTools.Data;
using ZfTools.Services;

public static class DssProtocolChecks
{
    public static void Run(Action<bool, string> check)
    {
        check(DssProtocol.DecodeInput("hash", "616263", 3).SequenceEqual(DssProtocol.DecodeInput("text", "abc", 3)), "Digest is signed as decoded bytes, not ASCII hexadecimal or a second hash");
        check(Convert.ToHexString(DssProtocol.DecodeInput("text", "中", 3)) == "E4B8AD", "Text uses UTF-8 bytes");
        Throws(() => DssProtocol.DecodeInput("text", "中", 2), check, "Byte limit measures UTF-8 bytes");
        Throws(() => DssProtocol.DecodeInput("hash", "a", 3), check, "Odd hexadecimal is rejected");
        Throws(() => DssProtocol.DecodeInput("hash", "0x61", 3), check, "A hexadecimal prefix is rejected");
        Throws(() => DssProtocol.DecodeInput("other", "abc", 3), check, "Unknown input mode is rejected");
        check(DssProtocol.JavaFormUrlEncode("a b*~中") == "a+b*%7E%E4%B8%AD", "Java form encoding preserves *, encodes ~, and uses + for a space");
        const string payload = "{\"keyName\":\"demo ~* key\",\"signAlgorithm\":\"Ed25519\",\"data\":\"616263\"}";
        check(DssProtocol.BuildRequestSignature(DssProtocol.SignPath, "test-app", "0123456789abcdef", "1700000000000", payload, "test-secret") ==
            "365eee53d838150892e408290c17ca2364adcd52f27cc133d56d0f73fb410b40", "DSS request authentication matches an independently calculated Java URL-encoding fixture");

        var connection = new SupplierConnection
        {
            AppKey = "test-app", DssResponseAuthConfirmed = true,
            ResponseSignatureTemplate = "{method}{path}|{requestNonce}|{requestTimestamp}|{responseNonce}|{responseTimestamp}|{appKey}|{body}|{appSecret}",
            ResponseSignatureEncoding = "utf8"
        };
        using var response = new HttpResponseMessage(HttpStatusCode.OK);
        response.Headers.Add("es-auth-appkey", "test-app");
        response.Headers.Add("es-auth-nonce", "response-nonce");
        response.Headers.Add("es-auth-timestamp", "1700000000010");
        const string body = "{\"verifyResult\":\"true\"}";
        var canonical = "POST" + DssProtocol.VerifyPath + "|request-nonce|1700000000000|response-nonce|1700000000010|test-app|" + body + "|test-secret";
        response.Headers.Add("es-auth-sign", DssProtocol.HashCanonical(canonical, "utf8"));
        check(DssProtocol.AuthenticateResponse(connection, response, DssProtocol.VerifyPath, "request-nonce", "1700000000000", body, "test-secret"), "Configured response signature authenticates the exact body and nonce fields");
        check(!DssProtocol.AuthenticateResponse(connection, response, DssProtocol.VerifyPath, "request-nonce", "1700000000000", body + " ", "test-secret"), "A changed response body is rejected");
        check(!DssProtocol.AuthenticateResponse(connection, response, DssProtocol.VerifyPath, "wrong-nonce", "1700000000000", body, "test-secret"), "A changed request binding is rejected");
        response.Headers.Remove("es-auth-appkey");
        check(!DssProtocol.AuthenticateResponse(connection, response, DssProtocol.VerifyPath, "request-nonce", "1700000000000", body, "test-secret"), "The documented response application header is required");
        connection.DssResponseAuthConfirmed = false;
        check(DssProtocol.ResponseContractErrors(connection).Count > 0, "Unconfirmed response rules block live signing");
        connection.DssResponseAuthConfirmed = true;
        connection.ResponseSignatureTemplate = "{body}{appSecret}{unknown}";
        check(DssProtocol.ResponseContractErrors(connection).Count > 0, "Unknown authentication template tokens are rejected");
        connection.ResponseSignatureTemplate = "{body}{appSecret}{";
        check(DssProtocol.ResponseContractErrors(connection).Count > 0, "Malformed authentication template is rejected");
        connection.ResponseSignatureTemplate = "{appSecret}";
        check(DssProtocol.ResponseContractErrors(connection).Count > 0, "Response authentication must cover the body");

        const string signature = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
        check(DssProtocol.ParseSignature("{\"signData\":\"" + signature + "\"}") == signature.ToUpperInvariant(), "A 64-byte Ed25519 signature is accepted");
        Throws(() => DssProtocol.ParseSignature("{}"), check, "Missing signData is handled safely");
        Throws(() => DssProtocol.ParseSignature("[]"), check, "Non-object DSS response is rejected");
        Throws(() => DssProtocol.ParseSignature("{\"signData\":\"00\"}"), check, "Incorrect signature length is rejected");
        check(DssProtocol.ParseVerification("{\"verifyResult\":\"true\"}"), "Supplier string verification result is accepted");
        check(!DssProtocol.ParseVerification("{\"verifyResult\":true}"), "Unexpected verification response type is rejected");
        var publicDer = Convert.FromHexString("302A300506032B6570032100D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A");
        var publicPem = "-----BEGIN PUBLIC KEY-----\n" + Convert.ToBase64String(publicDer) + "\n-----END PUBLIC KEY-----";
        check(DssProtocol.VerifyEd25519(publicPem, [], signature), "Ed25519 verification accepts RFC 8032 test vector 1");
        check(!DssProtocol.VerifyEd25519(publicPem, Encoding.UTF8.GetBytes("changed"), signature), "Ed25519 verification rejects changed input");
        string Metadata(string name = "known-key", string status = "1", string algorithm = "EdDSA", string type = "asymmetric", string curve = "Ed25519") => JsonSerializer.Serialize(new
        {
            keyName = name, keyAlgorithm = algorithm, keyLength = "256", keyStatus = status, keyType = type, encrycurve = curve,
            publicKey = Convert.ToHexString(publicDer), privateKey = "NEVER_IMPORT_PRIVATE_KEY", secretkey = "NEVER_IMPORT_SECRET_KEY"
        });
        var metadata = DssProtocol.ParseKeyMetadata(Metadata(), "known-key");
        check(metadata.SignAlgorithm == "Ed25519" && metadata.KeyStatus == "1" && metadata.KeyType == "asymmetric" &&
            DssProtocol.VerifyEd25519(metadata.PublicKeyPem, [], signature), "DSS key-get reads documented public DER metadata and normalizes EdDSA/Ed25519");
        check(!JsonSerializer.Serialize(metadata).Contains("NEVER_IMPORT", StringComparison.Ordinal), "DSS metadata excludes private and symmetric key material returned by the supplier");
        Throws(() => DssProtocol.ParseKeyMetadata(Metadata("other-key"), "known-key"), check, "DSS metadata rejects a different returned key name");
        Throws(() => DssProtocol.ParseKeyMetadata(Metadata(status: "invalid"), "known-key"), check, "DSS metadata rejects an unknown supplier key status");
        Throws(() => DssProtocol.ParseKeyMetadata(Metadata(algorithm: "RSA", curve: ""), "known-key"), check, "DSS metadata rejects an algorithm that disagrees with its public key");
        Throws(() => DssProtocol.ParseKeyMetadata(Metadata().Replace("\"keyStatus\":\"1\"", "\"keyStatus\":\"1\",\"keyStatus\":\"2\"", StringComparison.Ordinal), "known-key"), check, "DSS metadata rejects duplicate fields");
        var symmetric = DssProtocol.ParseKeyMetadata(Metadata(algorithm: "AES", type: "symmetry", curve: ""), "known-key");
        check(symmetric.SignAlgorithm == "AES" && symmetric.PublicKeyPem == "", "Symmetric supplier keys remain unsupported public metadata without importing secret keys");
    }

    private static void Throws(Action operation, Action<bool, string> check, string description)
    {
        try { operation(); check(false, description); }
        catch (InvalidOperationException) { check(true, description); }
    }
}
