using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using ZfTools.Data;
using ZfTools.Services;

namespace ZfTools.Pages.Dss;

[RequestSizeLimit(64 * 1024 * 1024)]
[RequestFormLimits(ValueLengthLimit = 32 * 1024 * 1024)]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public class DssIndexModel(ToolDbContext db, SessionService session, DssService dss, IConfiguration configuration) : PageModel
{
    public DssProject? Project { get; set; }
    public List<DssProject> Projects { get; set; } = [];
    public bool IsAdmin { get; set; }
    public bool IsDemoMode => configuration.GetValue<bool>("Suppliers:Dss:UseMock");
    public int MaximumInputBytes => configuration.GetValue("Dss:MaxInputBytes", 1024 * 1024);
    public List<DssKey> Keys { get; set; } = [];
    public Dictionary<int, bool> ReadyKeys { get; set; } = [];
    public List<string> SupportedAlgorithms => Keys.Where(x => x.SignAlgorithm == "Ed25519")
        .Select(x => x.SignAlgorithm).Distinct().ToList();
    public string? SelectedKeyAlgorithm => Keys.SingleOrDefault(x => x.Id == KeyId)?.SignAlgorithm;
    public bool SelectedKeyIsReady => SelectedKeyAlgorithm == "Ed25519" && KeyId is int keyId &&
        (IsDemoMode || ReadyKeys.GetValueOrDefault(keyId));
    public bool CanSubmit => Keys.Any(x => x.SignAlgorithm == "Ed25519" && (IsDemoMode || ReadyKeys.GetValueOrDefault(x.Id)));
    [BindProperty(SupportsGet = true)] public int? ProjectId { get; set; }
    [BindProperty] public string EnvironmentName { get; set; } = "development";
    [BindProperty] public int? KeyId { get; set; }
    [BindProperty] public string SignAlgorithm { get; set; } = "";
    [BindProperty] public string InputMode { get; set; } = "hash";
    [BindProperty] public string InputValue { get; set; } = "";
    public DssSignResult? Result { get; set; }
    public string? KeyRefreshMessage { get; set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken ct, string? environmentName = null)
    {
        var user = await session.CurrentAsync(User, ct);
        if (user?.Module != ToolModule.Dss) return RedirectToPage("/Index");
        if (environmentName is not null) EnvironmentName = environmentName;
        await LoadAsync(user, ct);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        var user = await session.CurrentAsync(User, ct);
        if (user?.Module != ToolModule.Dss) return RedirectToPage("/Index");
        await LoadAsync(user, ct);
        if (Project is null) ModelState.AddModelError(string.Empty, IsAdmin ? "Select an active project before signing." : "No active project is available for this account.");
        if (KeyId is null) ModelState.AddModelError(nameof(KeyId), "Select a signing key.");
        if (!SupportedAlgorithms.Contains(SignAlgorithm, StringComparer.Ordinal))
            ModelState.AddModelError(nameof(SignAlgorithm), "Select an available signing algorithm. Only Ed25519 is currently enabled.");
        if (KeyId is not null && Keys.SingleOrDefault(x => x.Id == KeyId)?.SignAlgorithm != SignAlgorithm)
            ModelState.AddModelError(nameof(SignAlgorithm), "The selected algorithm must match the signing key.");
        if (!ModelState.IsValid) return Page();
        Result = await dss.SignAsync(user, ProjectId ?? 0, EnvironmentName, KeyId ?? 0, InputMode, InputValue, ct, SignAlgorithm);
        return Page();
    }

    public async Task<IActionResult> OnPostRefreshKeyAsync(CancellationToken ct)
    {
        var user = await session.CurrentAsync(User, ct);
        if (user?.Module != ToolModule.Dss) return RedirectToPage("/Index");
        // Refresh does not submit signing input, but still checks current project authorization.
        ModelState.Clear();
        await LoadAsync(user, ct);
        if (!ModelState.IsValid) return Page();
        if (KeyId is not int keyId || !Keys.Any(x => x.Id == keyId))
        {
            ModelState.AddModelError(nameof(KeyId), "Select a registered key in your project and environment to refresh.");
            return Page();
        }
        var refresh = await dss.RefreshKeyMetadataAsync(user, keyId, ct);
        if (refresh.Success) KeyRefreshMessage = "Key details refreshed from the supplier.";
        else ModelState.AddModelError(string.Empty, refresh.Error ?? "Key details could not be refreshed.");
        await LoadAsync(user, ct);
        SignAlgorithm = SelectedKeyAlgorithm ?? "";
        return Page();
    }

    public async Task<IActionResult> OnGetSignatureAsync(long recordId, CancellationToken ct)
    {
        var user = await session.CurrentAsync(User, ct);
        if (user?.Module != ToolModule.Dss) return Forbid();
        var cutoff = DateTime.UtcNow.AddYears(-1);
        var record = await db.DssSigningRecords.AsNoTracking().SingleOrDefaultAsync(x => x.Id == recordId &&
            x.CreatedAtUtc >= cutoff && (user.Role == UserRole.Admin || x.UserId == user.Id), ct);
        if (record is null) return NotFound();
        if (record.Status != "succeeded" || !record.SignatureVerified || !record.ResponseAuthenticated || record.SignatureValue is null)
            return BadRequest("A verified signature is not available for this record.");
        return File(Encoding.ASCII.GetBytes(record.SignatureValue + "\n"), "text/plain", $"signature-{record.Id}.hex");
    }

    private async Task LoadAsync(AppUser user, CancellationToken ct)
    {
        IsAdmin = user.Role == UserRole.Admin;
        if (EnvironmentName is not ("development" or "production"))
        {
            ModelState.AddModelError(nameof(EnvironmentName), "Select development or production.");
            return;
        }
        if (IsAdmin)
        {
            Projects = await db.DssProjects.AsNoTracking().Where(x => x.Active).OrderBy(x => x.Code).ToListAsync(ct);
        }
        else
        {
            if (ProjectId is not null && ProjectId != user.DssProjectId)
            {
                ModelState.AddModelError(nameof(ProjectId), "Access denied. The selected project is not assigned to your account.");
                return;
            }
            ProjectId = user.DssProjectId;
        }
        Project = await db.DssProjects.AsNoTracking().SingleOrDefaultAsync(x => x.Id == ProjectId && x.Active, ct);
        if (Project is null) return;
        Keys = await db.DssKeys.AsNoTracking().Include(x => x.Connection)
            .Where(x => x.DssProjectId == Project.Id && x.EnvironmentName == EnvironmentName && x.Active && !x.Archived)
            .OrderBy(x => x.Name).ToListAsync(ct);
        foreach (var key in Keys)
            ReadyKeys[key.Id] = DssProtocol.MetadataSupportsSigning(key) && key.Connection is not null &&
                key.Connection.EnvironmentName == EnvironmentName &&
                SupplierConnectionRules.GetErrors(key.Connection, ToolModule.Dss, Project.Id).Count == 0 &&
                DssProtocol.ResponseContractErrors(key.Connection).Count == 0;
    }
}
