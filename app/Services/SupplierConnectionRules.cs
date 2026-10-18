using ZfTools.Data;

namespace ZfTools.Services;

public static class SupplierConnectionRules
{
    public static IReadOnlyList<string> GetErrors(SupplierConnection? c, ToolModule module, int? projectId = null)
    {
        var errors = new List<string>();
        if (c is null) return ["No supplier connection is mapped. Ask an administrator to configure an existing supplier connection."];
        if (!c.Active) errors.Add("The supplier connection is disabled.");
        if (c.Module != module) errors.Add("The connection belongs to a different tool.");
        if (c.EnvironmentName is not ("development" or "production")) errors.Add("Select a valid supplier environment.");
        if (!Uri.TryCreate(c.BaseUrl, UriKind.Absolute, out var uri) || uri.Scheme != "https" ||
            uri.AbsolutePath != "/" || uri.Query.Length != 0 || uri.Fragment.Length != 0 || uri.UserInfo.Length != 0)
            errors.Add("Configure a supplier HTTPS origin without a path, query or credentials.");
        if (c.TimeoutSeconds is < 1 or > 300) errors.Add("The connection timeout must be between 1 and 300 seconds.");
        if (c.MaxInputBytes is < 1 or > 16 * 1024 * 1024) errors.Add("The input limit must be between 1 byte and 16 MiB, within the supplier's confirmed limit.");
        if (!Existing(c.ClientCertificatePath)) errors.Add("The mTLS certificate file is missing or not configured.");
        if (!string.IsNullOrWhiteSpace(c.ClientPrivateKeyPath) && !Existing(c.ClientPrivateKeyPath)) errors.Add("The mTLS private-key file is missing.");
        if (!string.IsNullOrWhiteSpace(c.ClientCaChainPath) && !Existing(c.ClientCaChainPath)) errors.Add("The mTLS client CA chain file is missing.");
        if (!Existing(c.ServerCaChainPath)) errors.Add("The server CA trust bundle is missing or not configured.");
        if (module == ToolModule.Pki)
        {
            if (c.DssProjectId is not null) errors.Add("A PKI connection cannot belong to a DSS project.");
            if (!Existing(c.IssuerCaChainPath)) errors.Add("The PKI issuing CA bundle is missing or not configured.");
        }
        else
        {
            if (projectId is null || c.DssProjectId != projectId) errors.Add("The connection is not assigned to the authorized project.");
            if (string.IsNullOrWhiteSpace(c.AppKey) || string.IsNullOrWhiteSpace(c.AppSecret)) errors.Add("The project API credentials are not configured.");
        }
        return errors;
    }

    private static bool Existing(string path) => !string.IsNullOrWhiteSpace(path) && Path.IsPathFullyQualified(path) && File.Exists(path);
}
