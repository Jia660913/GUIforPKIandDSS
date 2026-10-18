using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using ZfTools.Data;
using ZfTools.Services;

namespace ZfTools.Pages.Admin;

public class AdminModel(ToolDbContext db, SessionService session, IPasswordHasher<AppUser> hasher, SupplierSecrets secrets, DssService dss) : PageModel
{
    public AppUser? Current { get; private set; }
    public bool IsDss => Current?.Module == ToolModule.Dss;
    public string ModuleLabel => IsDss ? "DSS SIGNING" : "PKI CERTIFICATE";
    public List<AppUser> Users { get; private set; } = [];
    public List<PkiTemplate> Templates { get; private set; } = [];
    public List<DssProject> Projects { get; private set; } = [];
    public List<SupplierConnection> Connections { get; private set; } = [];
    public string? Message { get; private set; }
    public bool MessageIsError { get; private set; }
    public string? SubmittedForm { get; private set; }
    public int? RefreshKeyId { get; private set; }
    [BindProperty, DisplayFormat(ConvertEmptyStringToNull = false)] public string NewUsername { get; set; } = "";
    [BindProperty, DisplayFormat(ConvertEmptyStringToNull = false)] public string NewDisplayName { get; set; } = "";
    [BindProperty, DisplayFormat(ConvertEmptyStringToNull = false)] public string NewPassword { get; set; } = "";
    [BindProperty] public int? NewProjectId { get; set; }
    [BindProperty] public ConnectionForm ConnectionInput { get; set; } = new();
    [BindProperty] public TemplateForm TemplateInput { get; set; } = new();
    [BindProperty] public ProjectForm ProjectInput { get; set; } = new();
    [BindProperty] public KeyForm KeyInput { get; set; } = new();

    public override void OnPageHandlerExecuting(PageHandlerExecutingContext context)
    {
        Response.Headers.CacheControl = "no-store";
        SubmittedForm = context.HandlerMethod?.Name;
        string[] prefixes = SubmittedForm switch
        {
            "CreateUser" => [nameof(NewUsername), nameof(NewDisplayName), nameof(NewPassword), nameof(NewProjectId)],
            "SaveConnection" => [nameof(ConnectionInput)], "SaveTemplate" => [nameof(TemplateInput)],
            "SaveProject" => [nameof(ProjectInput)], "SaveKey" => [nameof(KeyInput)],
            "ToggleUser" or "ResetPassword" or "RefreshKey" => ["id"], "ChangeProject" => ["id", "projectId"], _ => []
        };
        foreach (var item in ModelState)
        {
            if (prefixes.Any(prefix => item.Key.Equals(prefix, StringComparison.OrdinalIgnoreCase)
                || item.Key.StartsWith(prefix + ".", StringComparison.OrdinalIgnoreCase)) || item.Value is null) continue;
            item.Value.Errors.Clear();
            item.Value.ValidationState = ModelValidationState.Valid;
        }
    }

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Forbid();
        Message = TempData["AdminNotice"] as string;
        return Page();
    }

    public async Task<IActionResult> OnPostCreateUserAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Forbid();
        var username = NewUsername.Trim();
        if (!ModelState.IsValid || !Regex.IsMatch(username, "\\A[A-Za-z0-9._@-]{1,80}\\z")
            || NewPassword.Length is < 12 or > 256 || NewDisplayName.Length > 120)
            return Invalid("Enter a username (letters, numbers, dots, underscores, @ or hyphens) and a password of 12–256 characters.");
        if (IsDss && !await db.DssProjects.AnyAsync(x => x.Id == NewProjectId && x.Active, ct))
            return Invalid("Select an active DSS project.");
        if (await db.Users.AnyAsync(x => x.Module == Current!.Module && x.Username.ToLower() == username.ToLower(), ct))
            return Invalid("This username already exists in this tool.");
        var user = new AppUser
        {
            Username = username, DisplayName = string.IsNullOrWhiteSpace(NewDisplayName) ? username : NewDisplayName.Trim(),
            Module = Current!.Module, Role = UserRole.User, DssProjectId = IsDss ? NewProjectId : null, MustChangePassword = true
        };
        user.PasswordHash = hasher.HashPassword(user, NewPassword);
        db.Users.Add(user);
        await SaveAuditAsync("create-user", user.Username, ct);
        return Saved("The tool account was added. The user must change the initial password on first login.");
    }

    public async Task<IActionResult> OnPostToggleUserAsync(int id, CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Forbid();
        if (!ModelState.IsValid) return Invalid("Select a valid tool account.");
        var user = await db.Users.SingleOrDefaultAsync(x => x.Id == id && x.Module == Current!.Module && x.Role == UserRole.User, ct);
        if (user is null) return NotFound();
        user.Active = !user.Active;
        await SaveAuditAsync(user.Active ? "activate-user" : "revoke-user", user.Username, ct);
        return Saved(user.Active ? "The tool account is active." : "Tool access was revoked. Existing certificates and signatures are unaffected.");
    }

    public async Task<IActionResult> OnPostChangeProjectAsync(int id, int projectId, CancellationToken ct)
    {
        if (!await LoadAsync(ct) || !IsDss) return Forbid();
        if (!ModelState.IsValid) return Invalid("Select a valid account and project.");
        var user = await db.Users.SingleOrDefaultAsync(x => x.Id == id && x.Module == ToolModule.Dss && x.Role == UserRole.User, ct);
        var project = await db.DssProjects.SingleOrDefaultAsync(x => x.Id == projectId && x.Active, ct);
        if (user is null || project is null) return Invalid("The account or active project was not found.");
        var previous = user.DssProjectId;
        user.DssProjectId = project.Id;
        await SaveAuditAsync("change-dss-project", $"{user.Username}:{previous}->{project.Code}", ct);
        return Saved($"{user.Username} is now assigned to {project.Code}. Project access is updated immediately.");
    }

    public async Task<IActionResult> OnPostResetPasswordAsync(int id, CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Forbid();
        if (!ModelState.IsValid) return Invalid("Select a valid tool account.");
        var user = await db.Users.SingleOrDefaultAsync(x => x.Id == id && x.Module == Current!.Module && x.Role == UserRole.User, ct);
        if (user is null) return NotFound();
        var password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(18));
        user.PasswordHash = hasher.HashPassword(user, password);
        user.MustChangePassword = true;
        await SaveAuditAsync("reset-password", user.Username, ct);
        Message = $"Temporary password for @{user.Username}: {password}. Share it with the user; it is shown only on this response.";
        return Page();
    }

    public async Task<IActionResult> OnPostSaveConnectionAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Forbid();
        if (!ModelState.IsValid) return Invalid("Check the connection fields below.");
        var input = ConnectionInput;
        var existing = input.Id == 0 ? null : await db.SupplierConnections.SingleOrDefaultAsync(x => x.Id == input.Id && x.Module == Current!.Module, ct);
        if (input.Id != 0 && existing is null) return NotFound();
        if (!ValidEnvironment(input.EnvironmentName)) return Invalid("Choose Development or Production.");
        if (!IsDss && input.DssProjectId is not null) return Invalid("PKI connections do not belong to a project.");
        if (IsDss && !await db.DssProjects.AnyAsync(x => x.Id == input.DssProjectId && (!input.Active || x.Active), ct))
            return Invalid("Choose a DSS project. Enabled connections require an active project.");
        var endpoint = input.BaseUrl.Trim().TrimEnd('/');
        if (endpoint.Length > 0 && (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri)
            || uri.Scheme != Uri.UriSchemeHttps || uri.UserInfo.Length > 0 || uri.AbsolutePath != "/"
            || uri.Query.Length > 0 || uri.Fragment.Length > 0))
            return Invalid("Enter an HTTPS origin such as https://zf.easysec.com.cn:10001, without a path, query or embedded credentials.");
        if (existing is not null && (existing.EnvironmentName != input.EnvironmentName || existing.DssProjectId != input.DssProjectId)
            && (await db.PkiTemplates.AnyAsync(x => x.SupplierConnectionId == existing.Id, ct)
                || await db.DssKeys.AnyAsync(x => x.SupplierConnectionId == existing.Id, ct)))
            return Invalid("This connection already has mappings. Move those mappings before changing its project or environment.");
        if (await db.SupplierConnections.AnyAsync(x => x.Id != input.Id && x.Module == Current!.Module
            && x.EnvironmentName == input.EnvironmentName && x.DssProjectId == input.DssProjectId && x.Name == input.Name.Trim(), ct))
            return Invalid("A connection with this name already exists for this environment and project.");
        if (IsDss && !ValidResponseContract(input.ResponseSignatureTemplate, input.ResponseSignatureEncoding, input.DssResponseAuthConfirmed))
            return Invalid("A confirmed DSS response rule must contain {body} and {appSecret}, use supported tokens, and specify Java form or UTF-8 encoding.");
        var connection = new SupplierConnection
        {
            Id = input.Id, Module = Current!.Module, Name = input.Name.Trim(), EnvironmentName = input.EnvironmentName,
            DssProjectId = IsDss ? input.DssProjectId : null, Active = input.Active, BaseUrl = endpoint,
            ClientCertificatePath = input.ClientCertificatePath.Trim(), ClientPrivateKeyPath = input.ClientPrivateKeyPath.Trim(),
            ClientCaChainPath = input.ClientCaChainPath.Trim(),
            ClientCertificatePassword = input.ClearCertificatePassword ? "" : string.IsNullOrEmpty(input.ClientCertificatePassword) ? existing?.ClientCertificatePassword ?? "" : secrets.Protect(input.ClientCertificatePassword),
            ServerCaChainPath = input.ServerCaChainPath.Trim(), IssuerCaChainPath = IsDss ? "" : input.IssuerCaChainPath.Trim(),
            AppKey = IsDss ? input.AppKey.Trim() : "", AppSecret = IsDss
                ? (string.IsNullOrEmpty(input.AppSecret) ? existing?.AppSecret ?? "" : secrets.Protect(input.AppSecret)) : "",
            DssResponseAuthConfirmed = IsDss && input.DssResponseAuthConfirmed,
            ResponseSignatureTemplate = IsDss ? input.ResponseSignatureTemplate : "",
            ResponseSignatureEncoding = IsDss ? input.ResponseSignatureEncoding : "java-form",
            MaxInputBytes = input.MaxInputBytes, TimeoutSeconds = input.TimeoutSeconds
        };
        if (connection.Active)
        {
            var errors = SupplierConnectionRules.GetErrors(connection, Current.Module, connection.DssProjectId);
            if (errors.Count > 0) return Invalid("Save this connection as disabled until configured: " + string.Join(" ", errors));
            if (IsDss && !connection.DssResponseAuthConfirmed)
                return Invalid("Confirm the existing supplier response-authentication rule before enabling this DSS connection.");
        }
        if (existing is null) db.SupplierConnections.Add(connection);
        else db.Entry(existing).CurrentValues.SetValues(connection);
        await SaveAuditAsync(input.Id == 0 ? "create-supplier-connection" : "update-supplier-connection",
            $"{Current.Module}:{input.Id}:{connection.Name}:{connection.EnvironmentName}:active={connection.Active}", ct);
        return Saved("The local connection configuration was saved. No supplier settings were changed.");
    }

    public async Task<IActionResult> OnPostSaveTemplateAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct) || IsDss) return Forbid();
        if (!ModelState.IsValid) return Invalid("Check the template fields below.");
        var input = TemplateInput;
        var existing = input.Id == 0 ? null : await db.PkiTemplates.SingleOrDefaultAsync(x => x.Id == input.Id && !x.Archived, ct);
        if (input.Id != 0 && existing is null) return NotFound();
        var role = PkiRoleCatalog.Find(input.DiagUserRole);
        if (role is null) return Invalid("Select one of the supported OEM or ZF roles. OEM Claims is not currently available.");
        if (!ValidEnvironment(input.EnvironmentName) || input.ExtraExtensionsPolicy is not ("reject" or "ignore"))
            return Invalid("Choose a valid environment and additional-extension policy.");
        if (!ValidPattern(input.CommonNamePattern) || !ValidPattern(input.UniqueIdPattern))
            return Invalid("Common Name and ECU Unique ID patterns must be valid regular expressions.");
        var connection = input.SupplierConnectionId is null ? null
            : await db.SupplierConnections.SingleOrDefaultAsync(x => x.Id == input.SupplierConnectionId && x.Module == ToolModule.Pki, ct);
        if (input.SupplierConnectionId is not null && (connection is null || connection.EnvironmentName != input.EnvironmentName))
            return Invalid("Choose a PKI connection in the same environment as this template.");
        if (input.Active && (connection is null || !connection.Active || !input.CsrPolicyConfirmed))
            return Invalid("An enabled template requires an enabled connection and a confirmed CSR policy. Save it as disabled while details are pending.");
        if (input.Active && SupplierConnectionRules.GetErrors(connection, ToolModule.Pki).Count > 0)
            return Invalid("Complete the selected PKI connection before enabling this template.");
        if (await db.PkiTemplates.AnyAsync(x => !x.Archived && x.Id != input.Id && x.SupplierConnectionId == input.SupplierConnectionId
            && x.EnvironmentName == input.EnvironmentName && x.CertProfile == input.CertProfile.Trim(), ct))
            return Invalid("This cert_profile already has a mapping on the selected connection and environment.");
        var template = existing ?? new PkiTemplate();
        template.DisplayName = input.DisplayName.Trim(); template.CertProfile = input.CertProfile.Trim();
        template.EnvironmentName = input.EnvironmentName; template.SupplierConnectionId = input.SupplierConnectionId;
        template.Active = input.Active; template.CertType = "diagUser";
        template.TrustGrade = input.EnvironmentName == "production" ? "field" : "dev";
        template.DiagUserRole = role.Hex; template.RequiresEcuUniqueId = role.RequiresUniqueId;
        template.RequiredFields = role.RequiresUniqueId ? "ECUVariantID,ECUUniqueID" : "ECUVariantID";
        template.CsrPolicyConfirmed = input.CsrPolicyConfirmed; template.VariantExactBytes = input.VariantExactBytes;
        template.CommonNamePattern = input.CommonNamePattern.Trim(); template.UniqueIdPattern = input.UniqueIdPattern.Trim();
        template.IncludeFixedFieldsInCsr = input.IncludeFixedFieldsInCsr; template.VariantCritical = input.VariantCritical;
        template.UniqueCritical = input.UniqueCritical; template.FixedFieldsCritical = input.FixedFieldsCritical;
        template.ExtraExtensionsPolicy = input.ExtraExtensionsPolicy;
        if (existing is null) db.PkiTemplates.Add(template);
        await SaveAuditAsync(input.Id == 0 ? "create-pki-template-mapping" : "update-pki-template-mapping",
            $"{input.Id}:{template.CertProfile}:{template.EnvironmentName}:{role.Hex}:active={template.Active}", ct);
        return Saved("The local certificate-template mapping was saved.");
    }

    public async Task<IActionResult> OnPostSaveProjectAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct) || !IsDss) return Forbid();
        if (!ModelState.IsValid) return Invalid("Check the project fields below.");
        var input = ProjectInput;
        var code = input.Code.Trim();
        if (!Regex.IsMatch(code, "\\A[A-Za-z0-9._-]{1,64}\\z")) return Invalid("Use 1–64 letters, numbers, dots, underscores or hyphens for the project code.");
        var project = input.Id == 0 ? new DssProject() : await db.DssProjects.SingleOrDefaultAsync(x => x.Id == input.Id, ct);
        if (project is null) return NotFound();
        if (await db.DssProjects.AnyAsync(x => x.Id != input.Id && x.Code.ToLower() == code.ToLower(), ct)) return Invalid("This DSS project code already exists.");
        project.Code = code; project.DisplayName = input.DisplayName.Trim(); project.Active = input.Active;
        if (input.Id == 0) db.DssProjects.Add(project);
        await SaveAuditAsync(input.Id == 0 ? "create-dss-project-mapping" : "update-dss-project-mapping", $"{code}:active={project.Active}", ct);
        return Saved("Project access was saved. Accounts assigned to a disabled project cannot sign.");
    }

    public async Task<IActionResult> OnPostSaveKeyAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct) || !IsDss) return Forbid();
        if (!ModelState.IsValid) return Invalid("Check the key-mapping fields below.");
        var input = KeyInput;
        if (!ValidEnvironment(input.EnvironmentName) || input.Name.Trim().Any(char.IsControl))
            return Invalid("Choose a valid environment and an exact supplier signing-key name without control characters.");
        var project = await db.DssProjects.SingleOrDefaultAsync(x => x.Id == input.DssProjectId, ct);
        if (project is null || (input.Active && !project.Active)) return Invalid("Choose a project. Enabled keys require an active project.");
        var key = input.Id == 0 ? new DssKey() : await db.DssKeys.SingleOrDefaultAsync(x => x.Id == input.Id && !x.Archived, ct);
        if (key is null) return NotFound();
        var connection = input.SupplierConnectionId is null ? null
            : await db.SupplierConnections.SingleOrDefaultAsync(x => x.Id == input.SupplierConnectionId && x.Module == ToolModule.Dss, ct);
        if (input.SupplierConnectionId is not null && (connection is null || connection.DssProjectId != project.Id || connection.EnvironmentName != input.EnvironmentName))
            return Invalid("The DSS connection must belong to this project and environment.");
        if (input.Active && (connection is null || !connection.Active || !connection.DssResponseAuthConfirmed
            || SupplierConnectionRules.GetErrors(connection, ToolModule.Dss, project.Id).Count > 0))
            return Invalid("An enabled key requires a configured, enabled connection with a confirmed response-authentication rule.");
        var duplicate = await db.DssKeys.AsNoTracking().FirstOrDefaultAsync(x => x.Id != input.Id && x.DssProjectId == project.Id
            && x.EnvironmentName == input.EnvironmentName && x.Name == input.Name.Trim(), ct);
        if (duplicate is not null)
            return Invalid(duplicate.Archived
                ? "This key name belongs to an archived registration retained for history. Register a different supplier signing key."
                : "This key already has a mapping for this project and environment.");
        var supplierIdentityChanged = input.Id == 0 || key.Name != input.Name.Trim() || key.DssProjectId != project.Id
            || key.EnvironmentName != input.EnvironmentName || key.SupplierConnectionId != input.SupplierConnectionId;
        if (supplierIdentityChanged)
        {
            key.SupplierKeyAlgorithm = ""; key.SupplierKeyCurve = ""; key.SupplierKeyType = "";
            key.SupplierKeyStatus = ""; key.SupplierKeyLength = ""; key.SupplierMetadataUpdatedAtUtc = null;
            key.SignAlgorithm = ""; key.PublicKeyPem = "";
        }
        key.DssProjectId = project.Id; key.Name = input.Name.Trim();
        key.EnvironmentName = input.EnvironmentName; key.SupplierConnectionId = input.SupplierConnectionId;
        key.Active = input.Active;
        if (input.Id == 0) db.DssKeys.Add(key);
        await SaveAuditAsync(input.Id == 0 ? "create-dss-key-mapping" : "update-dss-key-mapping",
            $"{project.Code}:{key.Name}:{key.EnvironmentName}:active={key.Active}", ct);
        return Saved("The signing-key registration was saved. Refresh it to read the current supplier details.");
    }

    public async Task<IActionResult> OnPostRefreshKeyAsync(int id, CancellationToken ct)
    {
        if (!await LoadAsync(ct) || !IsDss) return Forbid();
        RefreshKeyId = id;
        if (!ModelState.IsValid) return Invalid("Select a valid registered signing key.");
        var result = await dss.RefreshKeyMetadataAsync(Current!, id, ct);
        if (!result.Success) return Invalid(result.Error ?? "The supplier key details could not be refreshed.");
        return Saved("The key algorithm, public key and status were refreshed from the supplier.");
    }

    public ConnectionEditor ConnectionEditorFor(SupplierConnection? value = null) => new(this,
        SubmittedForm == "SaveConnection" && ConnectionInput.Id == (value?.Id ?? 0) ? ConnectionInput : ConnectionForm.From(value));
    public TemplateEditor TemplateEditorFor(PkiTemplate? value = null) => new(this,
        SubmittedForm == "SaveTemplate" && TemplateInput.Id == (value?.Id ?? 0) ? TemplateInput : TemplateForm.From(value));
    public KeyEditor KeyEditorFor(DssKey? value = null) => new(this,
        SubmittedForm == "SaveKey" && KeyInput.Id == (value?.Id ?? 0) ? KeyInput : KeyForm.From(value));
    public ProjectForm ProjectFormFor(DssProject? value = null) => SubmittedForm == "SaveProject" && ProjectInput.Id == (value?.Id ?? 0) ? ProjectInput : ProjectForm.From(value);
    public static string EnvironmentLabel(string environment) => environment == "production" ? "Production / field" : "Development / dev";
    public string ConnectionState(SupplierConnection connection) => !connection.Active ? "Disabled"
        : SupplierConnectionRules.GetErrors(connection, Current!.Module, connection.DssProjectId).Count > 0
          || (IsDss && DssProtocol.ResponseContractErrors(connection).Count > 0) ? "Configuration incomplete" : "Configured · awaiting live validation";
    public static string TemplateState(PkiTemplate value) => value.SupplierConnectionId is null ? "Unconfigured" : !value.Active ? "Disabled"
        : !value.CsrPolicyConfirmed || value.Connection?.Active != true ? "Configuration incomplete" : "Enabled";
    public static string KeyState(DssKey value) => value.SupplierConnectionId is null ? "Unconfigured" : !value.Active ? "Disabled"
        : SupplierConnectionRules.GetErrors(value.Connection, ToolModule.Dss, value.DssProjectId).Count > 0
          || value.Connection!.EnvironmentName != value.EnvironmentName
          || DssProtocol.ResponseContractErrors(value.Connection!).Count > 0 ? "Configuration incomplete"
        : value.SupplierMetadataUpdatedAtUtc is null ? "Awaiting supplier check"
        : value.SupplierKeyStatus != "1" ? "Supplier key unavailable"
        : !DssProtocol.MetadataSupportsSigning(value) ? "Key not supported for signing" : "Enabled";
    public bool CanRefreshKey(DssKey key) => !key.Archived && key.Connection is { Active: true, Module: ToolModule.Dss } connection
        && connection.DssProjectId == key.DssProjectId && connection.EnvironmentName == key.EnvironmentName
        && SupplierConnectionRules.GetErrors(connection, ToolModule.Dss, key.DssProjectId).Count == 0
        && DssProtocol.ResponseContractErrors(connection).Count == 0;
    public static string SupplierKeySummary(DssKey key)
    {
        if (key.SupplierMetadataUpdatedAtUtc is null) return "Supplier details have not been checked yet. Ed25519 signing is currently supported.";
        var status = key.SupplierKeyStatus switch { "0" => "Pre-active", "1" => "Active", "2" => "Revoked", "3" => "Destroyed", _ => "Unknown" };
        var algorithm = string.IsNullOrEmpty(key.SupplierKeyCurve) ? key.SupplierKeyAlgorithm : $"{key.SupplierKeyAlgorithm} / {key.SupplierKeyCurve}";
        return $"Supplier: {algorithm} · {status}. Last checked {key.SupplierMetadataUpdatedAtUtc.Value:yyyy-MM-dd HH:mm} UTC.";
    }

    private async Task<bool> LoadAsync(CancellationToken ct)
    {
        Current = await session.CurrentAsync(User, ct);
        if (Current?.Role != UserRole.Admin || Current.MustChangePassword) return false;
        Users = await db.Users.AsNoTracking().Include(x => x.DssProject).Where(x => x.Module == Current.Module).OrderBy(x => x.Username).ToListAsync(ct);
        Connections = await db.SupplierConnections.AsNoTracking().Include(x => x.Project).Where(x => x.Module == Current.Module)
            .OrderBy(x => x.EnvironmentName).ThenBy(x => x.Name).ToListAsync(ct);
        if (IsDss) Projects = await db.DssProjects.AsNoTracking().Include(x => x.Keys.Where(key => !key.Archived)).ThenInclude(x => x.Connection).OrderBy(x => x.Code).ToListAsync(ct);
        else Templates = await db.PkiTemplates.AsNoTracking().Include(x => x.Connection).Where(x => !x.Archived).OrderBy(x => x.EnvironmentName).ThenBy(x => x.DisplayName).ToListAsync(ct);
        return true;
    }
    private PageResult Invalid(string message) { MessageIsError = true; Message = message; return Page(); }
    private RedirectToPageResult Saved(string message) { TempData["AdminNotice"] = message; return RedirectToPage(); }
    private async Task SaveAuditAsync(string action, string details, CancellationToken ct)
    { db.AuditRecords.Add(new AuditRecord { UserId = Current!.Id, Action = action, Details = details }); await db.SaveChangesAsync(ct); }
    private static bool ValidEnvironment(string value) => value is "development" or "production";
    private static bool ValidPattern(string pattern)
    { try { _ = new Regex(pattern, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(250)); return true; } catch (ArgumentException) { return false; } }
    private static bool ValidResponseContract(string template, string encoding, bool confirmed)
    {
        if (encoding is not ("java-form" or "utf8")) return false;
        if (string.IsNullOrEmpty(template)) return !confirmed;
        string[] tokens = ["method", "path", "requestNonce", "requestTimestamp", "responseNonce", "responseTimestamp", "appKey", "body", "appSecret"];
        var remainder = template;
        foreach (var token in tokens) remainder = remainder.Replace("{" + token + "}", "", StringComparison.Ordinal);
        return !remainder.Contains('{') && !remainder.Contains('}')
            && (!confirmed || (template.Contains("{body}", StringComparison.Ordinal) && template.Contains("{appSecret}", StringComparison.Ordinal)));
    }
}

public sealed class ConnectionForm
{
    public int Id { get; set; }
    [DisplayFormat(ConvertEmptyStringToNull = false)] [Required, StringLength(160)] public string Name { get; set; } = "";
    public string EnvironmentName { get; set; } = "development";
    public int? DssProjectId { get; set; }
    public bool Active { get; set; }
    [DisplayFormat(ConvertEmptyStringToNull = false)] [StringLength(2048)] public string BaseUrl { get; set; } = "";
    [DisplayFormat(ConvertEmptyStringToNull = false)] [StringLength(2048)] public string ClientCertificatePath { get; set; } = "";
    [DisplayFormat(ConvertEmptyStringToNull = false)] [StringLength(2048)] public string ClientPrivateKeyPath { get; set; } = "";
    [DisplayFormat(ConvertEmptyStringToNull = false)] [StringLength(2048)] public string ClientCaChainPath { get; set; } = "";
    [DisplayFormat(ConvertEmptyStringToNull = false)] [StringLength(1024)] public string ClientCertificatePassword { get; set; } = "";
    public bool ClearCertificatePassword { get; set; }
    [DisplayFormat(ConvertEmptyStringToNull = false)] [StringLength(2048)] public string ServerCaChainPath { get; set; } = "";
    [DisplayFormat(ConvertEmptyStringToNull = false)] [StringLength(2048)] public string IssuerCaChainPath { get; set; } = "";
    [DisplayFormat(ConvertEmptyStringToNull = false)] [StringLength(512)] public string AppKey { get; set; } = "";
    [DisplayFormat(ConvertEmptyStringToNull = false)] [StringLength(4096)] public string AppSecret { get; set; } = "";
    public bool DssResponseAuthConfirmed { get; set; }
    [DisplayFormat(ConvertEmptyStringToNull = false)] [StringLength(8192)] public string ResponseSignatureTemplate { get; set; } = "";
    public string ResponseSignatureEncoding { get; set; } = "java-form";
    [Range(1, 16777216)] public int MaxInputBytes { get; set; } = 1048576;
    [Range(1, 300)] public int TimeoutSeconds { get; set; } = 30;
    public static ConnectionForm From(SupplierConnection? value) => value is null ? new() : new()
    {
        Id = value.Id, Name = value.Name, EnvironmentName = value.EnvironmentName, DssProjectId = value.DssProjectId,
        Active = value.Active, BaseUrl = value.BaseUrl, ClientCertificatePath = value.ClientCertificatePath,
        ClientPrivateKeyPath = value.ClientPrivateKeyPath, ClientCaChainPath = value.ClientCaChainPath, ServerCaChainPath = value.ServerCaChainPath,
        IssuerCaChainPath = value.IssuerCaChainPath, AppKey = value.AppKey, DssResponseAuthConfirmed = value.DssResponseAuthConfirmed,
        ResponseSignatureTemplate = value.ResponseSignatureTemplate, ResponseSignatureEncoding = value.ResponseSignatureEncoding,
        MaxInputBytes = value.MaxInputBytes, TimeoutSeconds = value.TimeoutSeconds
    };
}

public sealed class TemplateForm
{
    public int Id { get; set; }
    [DisplayFormat(ConvertEmptyStringToNull = false)] [Required, StringLength(160)] public string DisplayName { get; set; } = "";
    [DisplayFormat(ConvertEmptyStringToNull = false)] [Required, StringLength(160)] public string CertProfile { get; set; } = "";
    public string EnvironmentName { get; set; } = "development";
    public int? SupplierConnectionId { get; set; }
    public bool Active { get; set; }
    public string DiagUserRole { get; set; } = "00000080";
    public bool CsrPolicyConfirmed { get; set; }
    [Range(0, 16)] public int VariantExactBytes { get; set; }
    [DisplayFormat(ConvertEmptyStringToNull = false)] [StringLength(512)] public string CommonNamePattern { get; set; } = "";
    [DisplayFormat(ConvertEmptyStringToNull = false)] [StringLength(512)] public string UniqueIdPattern { get; set; } = "";
    public bool IncludeFixedFieldsInCsr { get; set; }
    public bool VariantCritical { get; set; } = true;
    public bool UniqueCritical { get; set; }
    public bool FixedFieldsCritical { get; set; }
    public string ExtraExtensionsPolicy { get; set; } = "reject";
    public static TemplateForm From(PkiTemplate? value) => value is null ? new() : new()
    {
        Id = value.Id, DisplayName = value.DisplayName, CertProfile = value.CertProfile, EnvironmentName = value.EnvironmentName,
        SupplierConnectionId = value.SupplierConnectionId, Active = value.Active, DiagUserRole = PkiRoleCatalog.Normalize(value.DiagUserRole) ?? value.DiagUserRole,
        CsrPolicyConfirmed = value.CsrPolicyConfirmed, VariantExactBytes = value.VariantExactBytes,
        CommonNamePattern = value.CommonNamePattern, UniqueIdPattern = value.UniqueIdPattern,
        IncludeFixedFieldsInCsr = value.IncludeFixedFieldsInCsr, VariantCritical = value.VariantCritical,
        UniqueCritical = value.UniqueCritical, FixedFieldsCritical = value.FixedFieldsCritical, ExtraExtensionsPolicy = value.ExtraExtensionsPolicy
    };
}

public sealed class ProjectForm
{
    public int Id { get; set; }
    [DisplayFormat(ConvertEmptyStringToNull = false)] [Required, StringLength(64)] public string Code { get; set; } = "";
    [DisplayFormat(ConvertEmptyStringToNull = false)] [Required, StringLength(160)] public string DisplayName { get; set; } = "";
    public bool Active { get; set; } = true;
    public static ProjectForm From(DssProject? value) => value is null ? new() : new()
    { Id = value.Id, Code = value.Code, DisplayName = value.DisplayName, Active = value.Active };
}

public sealed class KeyForm
{
    public int Id { get; set; }
    [Range(1, int.MaxValue)] public int DssProjectId { get; set; }
    [DisplayFormat(ConvertEmptyStringToNull = false)] [Required, StringLength(128)] public string Name { get; set; } = "";
    public string EnvironmentName { get; set; } = "development";
    public int? SupplierConnectionId { get; set; }
    public bool Active { get; set; }
    public static KeyForm From(DssKey? value) => value is null ? new() : new()
    {
        Id = value.Id, DssProjectId = value.DssProjectId, Name = value.Name,
        EnvironmentName = value.EnvironmentName, SupplierConnectionId = value.SupplierConnectionId, Active = value.Active
    };
}

public sealed record ConnectionEditor(AdminModel Page, ConnectionForm Input);
public sealed record TemplateEditor(AdminModel Page, TemplateForm Input);
public sealed record KeyEditor(AdminModel Page, KeyForm Input);
