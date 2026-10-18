using System.Net;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using ZfTools.Data;
using ZfTools.Services;

namespace ZfTools.Pages.Pki;

[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public class PkiIndexModel(ToolDbContext db, SessionService session, PkiService pki, CsrService csrService, IConfiguration configuration) : PageModel
{
    public List<PkiTemplate> Templates { get; set; } = [];
    public bool IsDemoMode => configuration.GetValue<bool>("Suppliers:Pki:UseMock");
    [BindProperty] public string EnvironmentName { get; set; } = "development";
    [BindProperty] public int? TemplateId { get; set; }
    [BindProperty] public string? EcuVariantId { get; set; }
    [BindProperty] public string? EcuUniqueId { get; set; }
    [BindProperty] public string CsrMode { get; set; } = "generate";
    [BindProperty] public string? CommonName { get; set; }
    [BindProperty] public IFormFile? CsrFile { get; set; }
    [BindProperty] public string? PreparedCsr { get; set; }
    [BindProperty] public bool PrivateKeySaved { get; set; }
    public PkiApplyResult? Result { get; set; }
    public string? GeneratedPrivateKey { get; set; }
    public ParsedCsr? Preview { get; set; }
    public PkiTemplate? SelectedTemplate => Templates.FirstOrDefault(x => x.Id == TemplateId);
    public IReadOnlyList<string> ReadinessErrors => SelectedTemplate is null ? [] : PkiService.GetReadinessErrors(SelectedTemplate);

    public async Task<IActionResult> OnGetAsync(CancellationToken ct, string? environmentName = null)
    {
        if (!await AuthorizedAsync(ct)) return Forbid();
        if (environmentName is not null) EnvironmentName = environmentName;
        if (EnvironmentName is not ("development" or "production")) ModelState.AddModelError(nameof(EnvironmentName), "Select a valid environment.");
        await LoadAsync(ct);
        return Page();
    }

    public async Task<IActionResult> OnPostPreviewAsync(CancellationToken ct)
    {
        if (!await AuthorizedAsync(ct)) return Forbid();
        await LoadAsync(ct);
        var template = ValidateSelection();
        PreparedCsr = null; PrivateKeySaved = false;
        ModelState.Remove(nameof(PreparedCsr)); ModelState.Remove(nameof(PrivateKeySaved));
        if (template is null || !ModelState.IsValid) return Page();
        try
        {
            string pem;
            if (CsrMode == "upload")
            {
                if (CsrFile is null || CsrFile.Length == 0) throw new InvalidOperationException("Select a public CSR file.");
                if (CsrFile.Length > CsrService.MaximumCsrBytes) throw new InvalidOperationException("The CSR file must not exceed 128 KiB.");
                using var reader = new StreamReader(CsrFile.OpenReadStream(), new UTF8Encoding(false, true), true);
                pem = await reader.ReadToEndAsync(ct);
            }
            else
            {
                var generated = csrService.Generate(EcuVariantId ?? "", EcuUniqueId, CommonName ?? "", template);
                pem = generated.CsrPem;
                GeneratedPrivateKey = generated.PrivateKeyPem;
            }
            SetPreview(CsrService.ParseAndValidate(pem, template));
        }
        catch (Exception ex) when (ex is InvalidOperationException or DecoderFallbackException or IOException or ArgumentException)
        {
            ModelState.AddModelError(string.Empty, ex is DecoderFallbackException ? "The CSR file must use UTF-8 PEM text." : ex.Message);
        }
        return Page();
    }

    public Task<IActionResult> OnPostAsync(CancellationToken ct) => OnPostApplyAsync(ct);
    public async Task<IActionResult> OnPostApplyAsync(CancellationToken ct)
    {
        var user = await session.CurrentAsync(User, ct);
        if (user is null || user.Module != ToolModule.Pki) return Forbid();
        await LoadAsync(ct);
        var template = ValidateSelection();
        if (template is null || !ModelState.IsValid) return Page();
        try
        {
            if (string.IsNullOrEmpty(PreparedCsr)) throw new InvalidOperationException("Generate or read the CSR before requesting a certificate.");
            SetPreview(CsrService.ParseAndValidate(PreparedCsr, template));
            if (CsrMode == "generate" && !PrivateKeySaved) throw new InvalidOperationException("Save the private key and confirm before requesting a certificate.");
        }
        catch (InvalidOperationException ex) { ModelState.AddModelError(string.Empty, ex.Message); return Page(); }
        var source = HttpContext.Connection.RemoteIpAddress;
        var sourceIp = source is null ? "" : IPAddress.IsLoopback(source) ? "127.0.0.1" : source.IsIPv4MappedToIPv6 ? source.MapToIPv4().ToString() : source.ToString();
        Result = await pki.ApplyAsync(user, template, Preview!.Pem, Preview.VariantId, Preview.UniqueId, Preview.CommonName, sourceIp, ct);
        if (Result.Status is "succeeded" or "demo" or "unknown")
        {
            PreparedCsr = null; ModelState.Remove(nameof(PreparedCsr));
        }
        return Page();
    }

    private PkiTemplate? ValidateSelection()
    {
        if (EnvironmentName is not ("development" or "production")) ModelState.AddModelError(nameof(EnvironmentName), "Select a valid environment.");
        if (CsrMode is not ("generate" or "upload")) ModelState.AddModelError(nameof(CsrMode), "Select a valid CSR source.");
        var template = Templates.FirstOrDefault(x => x.Id == TemplateId && x.EnvironmentName == EnvironmentName);
        if (template is null) ModelState.AddModelError(nameof(TemplateId), "Select an active certificate template in this environment.");
        return template;
    }
    private void SetPreview(ParsedCsr parsed)
    {
        Preview = parsed; PreparedCsr = parsed.Pem; CommonName = parsed.CommonName; EcuVariantId = parsed.VariantId; EcuUniqueId = parsed.UniqueId;
        foreach (var field in new[] { nameof(PreparedCsr), nameof(CommonName), nameof(EcuVariantId), nameof(EcuUniqueId) }) ModelState.Remove(field);
    }
    private async Task<bool> AuthorizedAsync(CancellationToken ct) => (await session.CurrentAsync(User, ct))?.Module == ToolModule.Pki;
    private async Task LoadAsync(CancellationToken ct) => Templates = await db.PkiTemplates.AsNoTracking().Include(x => x.Connection).Where(x => x.Active && !x.Archived).OrderBy(x => x.EnvironmentName).ThenBy(x => x.DisplayName).ToListAsync(ct);
}
