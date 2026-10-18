using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using ZfTools.Data;

namespace ZfTools.Services;

// Deliberately contains only public metadata. Supplier private/secret key fields are never imported.
public sealed record DssKeyMetadata(string KeyName, string KeyAlgorithm, string Curve, string KeyType,
    string KeyStatus, string KeyLength, string SignAlgorithm, string PublicKeyPem);

/// <summary>The DSS wire protocol. These rules do not apply to PKI.</summary>
public static partial class DssProtocol
{
    public const string SignPath = "/api/kms/v4/key-sign-text";
    public const string VerifyPath = "/api/kms/v4/key-verify-text";
    public const string GetKeyPath = "/api/kms/v4/key-get";
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly HashSet<string> ResponseTokens = ["method", "path", "requestNonce", "requestTimestamp", "responseNonce", "responseTimestamp", "appKey", "body", "appSecret"];

    public static bool MetadataSupportsSigning(DssKey key) => key.SupplierMetadataUpdatedAtUtc is not null &&
        key.SupplierKeyStatus == "1" && key.SupplierKeyType == "asymmetric" && key.SignAlgorithm == "Ed25519" &&
        !string.IsNullOrWhiteSpace(key.PublicKeyPem);

    public static byte[] DecodeInput(string mode, string input, int maximumBytes)
    {
        if (maximumBytes < 1) throw new InvalidOperationException("The signing input limit is not configured correctly.");
        if (string.IsNullOrEmpty(input)) throw new InvalidOperationException("Enter the data to sign.");
        byte[] result;
        if (mode == "hash")
        {
            if (input.Length % 2 != 0 || !input.All(Uri.IsHexDigit))
                throw new InvalidOperationException("Enter a hexadecimal digest with an even number of characters. Spaces and a 0x prefix are not accepted.");
            if (input.Length / 2 > maximumBytes) throw new InvalidOperationException($"Signing input must not exceed {maximumBytes:N0} decoded bytes.");
            result = Convert.FromHexString(input);
        }
        else if (mode == "text")
        {
            try
            {
                if (StrictUtf8.GetByteCount(input) > maximumBytes) throw new InvalidOperationException($"Signing input must not exceed {maximumBytes:N0} UTF-8 bytes.");
                result = StrictUtf8.GetBytes(input);
            }
            catch (EncoderFallbackException) { throw new InvalidOperationException("Text contains an invalid Unicode character."); }
        }
        else throw new InvalidOperationException("Select digest or text input.");
        return result;
    }

    public static string BuildRequestSignature(string path, string appKey, string nonce, string timestamp, string exactJson, string appSecret)
    {
        var canonical = "POST" + path + "es-auth-appkey:" + appKey + "es-auth-nonce:" + nonce +
            "es-auth-timestamp:" + timestamp + "json=" + exactJson + appSecret;
        return HashCanonical(canonical, "java-form");
    }

    public static IReadOnlyList<string> ResponseContractErrors(SupplierConnection connection)
    {
        var errors = new List<string>();
        if (!connection.DssResponseAuthConfirmed) errors.Add("The supplier response authentication rules have not been confirmed for this connection.");
        var template = connection.ResponseSignatureTemplate ?? "";
        if (!template.Contains("{body}", StringComparison.Ordinal) || !template.Contains("{appSecret}", StringComparison.Ordinal))
            errors.Add("The response signature template must include {body} and {appSecret}.");
        var matches = TokenRegex().Matches(template);
        if (matches.Any(x => !ResponseTokens.Contains(x.Groups[1].Value)) || TokenRegex().Replace(template, "").IndexOfAny(['{', '}']) >= 0)
            errors.Add("The response signature template contains an unsupported token or unmatched brace.");
        if (connection.ResponseSignatureEncoding is not ("java-form" or "utf8"))
            errors.Add("Select java-form or utf8 response signature encoding.");
        return errors;
    }

    public static bool AuthenticateResponse(SupplierConnection connection, HttpResponseMessage response, string path,
        string requestNonce, string requestTimestamp, string exactBody, string appSecret)
    {
        if (ResponseContractErrors(connection).Count != 0) return false;
        var signature = Header(response, "es-auth-sign");
        if (signature is null || signature.Length != 64 || !signature.All(Uri.IsHexDigit)) return false;
        var responseAppKey = Header(response, "es-auth-appkey");
        if (!string.Equals(responseAppKey, connection.AppKey, StringComparison.Ordinal)) return false;
        var values = new Dictionary<string, string>
        {
            ["method"] = "POST", ["path"] = path, ["requestNonce"] = requestNonce,
            ["requestTimestamp"] = requestTimestamp, ["responseNonce"] = Header(response, "es-auth-nonce") ?? "",
            ["responseTimestamp"] = Header(response, "es-auth-timestamp") ?? "", ["appKey"] = connection.AppKey,
            ["body"] = exactBody, ["appSecret"] = appSecret
        };
        if (TokenRegex().Matches(connection.ResponseSignatureTemplate).Any(x =>
            x.Groups[1].Value is "responseNonce" or "responseTimestamp" && string.IsNullOrEmpty(values[x.Groups[1].Value]))) return false;
        // Expand once: response data is never interpreted as a second template.
        var canonical = TokenRegex().Replace(connection.ResponseSignatureTemplate, x => values[x.Groups[1].Value]);
        var expected = Convert.FromHexString(HashCanonical(canonical, connection.ResponseSignatureEncoding));
        return CryptographicOperations.FixedTimeEquals(expected, Convert.FromHexString(signature));
    }

    public static string ParseSignature(string json)
    {
        using var parsed = JsonDocument.Parse(json);
        if (parsed.RootElement.ValueKind != JsonValueKind.Object ||
            !parsed.RootElement.TryGetProperty("signData", out var field) || field.ValueKind != JsonValueKind.String)
            throw new InvalidOperationException("The DSS response does not contain a signature.");
        var value = field.GetString();
        if (value is null || value.Length != 128 || !value.All(Uri.IsHexDigit))
            throw new InvalidOperationException("The DSS response must contain a 64-byte Ed25519 signature encoded as hexadecimal.");
        return value.ToUpperInvariant();
    }

    public static DssKeyMetadata ParseKeyMetadata(string json, string expectedKeyName)
    {
        using var parsed = JsonDocument.Parse(json);
        var root = parsed.RootElement;
        if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().GroupBy(x => x.Name, StringComparer.Ordinal).Any(x => x.Count() != 1))
            throw new InvalidOperationException("The DSS key metadata response is invalid.");
        string Field(string name, bool required = true)
        {
            if (!root.TryGetProperty(name, out var value))
            {
                if (!required) return "";
                throw new InvalidOperationException("The DSS key metadata response is incomplete.");
            }
            if (value.ValueKind != JsonValueKind.String) throw new InvalidOperationException("The DSS key metadata response has an invalid field type.");
            var text = value.GetString() ?? "";
            if (text.Length > 256 || text.Any(char.IsControl) || (required && text.Length == 0))
                throw new InvalidOperationException("The DSS key metadata response has an invalid field value.");
            return text;
        }
        var name = Field("keyName");
        if (!string.Equals(name, expectedKeyName, StringComparison.Ordinal))
            throw new InvalidOperationException("The DSS response refers to a different key. No metadata was accepted.");
        var algorithm = Field("keyAlgorithm");
        var curve = Field("encrycurve", false);
        var type = Field("keyType");
        var status = Field("keyStatus");
        var length = Field("keyLength");
        if (status is not ("0" or "1" or "2" or "3") ||
            type is not ("asymmetric" or "symmetry") ||
            !int.TryParse(length, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var bits) || bits < 1)
            throw new InvalidOperationException("The DSS key metadata response has an invalid key status, type or length.");

        var signAlgorithm = algorithm.Equals("EdDSA", StringComparison.OrdinalIgnoreCase) && curve.Equals("Ed25519", StringComparison.OrdinalIgnoreCase)
            ? "Ed25519" : algorithm.Equals("RSA", StringComparison.OrdinalIgnoreCase) ? "RSA" : algorithm;
        var pem = "";
        if (type == "asymmetric")
        {
            if (!root.TryGetProperty("publicKey", out var field) || field.ValueKind != JsonValueKind.String)
                throw new InvalidOperationException("The DSS asymmetric key response does not contain a public key.");
            var hex = field.GetString() ?? "";
            if (hex.Length is < 2 or > 32768 || hex.Length % 2 != 0 || !hex.All(Uri.IsHexDigit))
                throw new InvalidOperationException("The DSS public key is not valid hexadecimal DER.");
            try
            {
                var der = Convert.FromHexString(hex);
                var publicKey = PublicKeyFactory.CreateKey(der);
                if (publicKey.IsPrivate ||
                    (signAlgorithm == "Ed25519" && (publicKey is not Ed25519PublicKeyParameters || bits != 256)) ||
                    (signAlgorithm == "RSA" && publicKey is not RsaKeyParameters))
                    throw new InvalidOperationException();
                pem = "-----BEGIN PUBLIC KEY-----\n" + Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks) + "\n-----END PUBLIC KEY-----\n";
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                throw new InvalidOperationException("The DSS public key does not match valid public key metadata.");
            }
        }
        else if (signAlgorithm == "Ed25519" || signAlgorithm == "RSA")
            throw new InvalidOperationException("The DSS key algorithm does not match the key type.");
        return new(name, algorithm, curve, type, status, length, signAlgorithm, pem);
    }

    public static bool ParseVerification(string json)
    {
        using var parsed = JsonDocument.Parse(json);
        return parsed.RootElement.ValueKind == JsonValueKind.Object &&
            parsed.RootElement.TryGetProperty("verifyResult", out var value) && value.ValueKind == JsonValueKind.String &&
            string.Equals(value.GetString(), "true", StringComparison.Ordinal);
    }

    public static bool VerifyEd25519(string publicKeyPem, byte[] input, string signature)
    {
        try
        {
            using var reader = new StringReader(publicKeyPem);
            if (new PemReader(reader).ReadObject() is not Ed25519PublicKeyParameters publicKey)
                throw new InvalidOperationException("The configured verification key must be an Ed25519 public key in PEM format.");
            var verifier = new Ed25519Signer();
            verifier.Init(false, publicKey);
            verifier.BlockUpdate(input, 0, input.Length);
            return verifier.VerifySignature(Convert.FromHexString(signature));
        }
        catch (Exception ex) when (ex is not InvalidOperationException && ex is not OutOfMemoryException)
        {
            throw new InvalidOperationException("The configured Ed25519 public key could not be read.");
        }
    }

    public static string JavaFormUrlEncode(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        var result = new StringBuilder(bytes.Length);
        foreach (var b in bytes)
        {
            if (b is >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z' or >= (byte)'0' and <= (byte)'9' or (byte)'-' or (byte)'_' or (byte)'.' or (byte)'*') result.Append((char)b);
            else if (b == (byte)' ') result.Append('+');
            else result.Append('%').Append(b.ToString("X2"));
        }
        return result.ToString();
    }

    public static string HashCanonical(string canonical, string encoding) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(encoding == "java-form" ? JavaFormUrlEncode(canonical) : canonical))).ToLowerInvariant();

    private static string? Header(HttpResponseMessage response, string name)
    {
        if (!response.Headers.TryGetValues(name, out var values)) return null;
        var array = values.Take(2).ToArray();
        return array.Length == 1 ? array[0] : null;
    }

    [GeneratedRegex(@"\{([^{}]+)\}", RegexOptions.CultureInvariant)]
    private static partial Regex TokenRegex();
}
