using Microsoft.AspNetCore.DataProtection;
using System.Security.Cryptography;

namespace ZfTools.Services;

public sealed class SupplierSecrets(IDataProtectionProvider provider)
{
    private readonly IDataProtector protector = provider.CreateProtector("ZfTools.SupplierSecrets.v1");
    public string Protect(string value) => string.IsNullOrEmpty(value) ? "" : protector.Protect(value);
    public string Unprotect(string value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        try { return protector.Unprotect(value); }
        catch (CryptographicException)
        {
            throw new InvalidOperationException("The connection credentials cannot be decrypted. Restore the Data Protection key ring or save the credentials again.");
        }
    }
}
