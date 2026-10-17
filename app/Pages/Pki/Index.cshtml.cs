using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using ZfTools.Data;
using ZfTools.Services;

namespace ZfTools.Pages.Pki;

public sealed record PkiResult(bool Success, string? Certificate, string? RequestId, string? Error);

public class PkiIndexModel(ToolDbContext db, SessionService session, PkiService pki, CsrService csrService, IConfiguration configuration) : PageModel
{
    public List<PkiTemplate> Templates { get; set; } = [];
    public bool IsDemoMode => configuration.GetValue<bool>("Suppliers:Pki:UseMock");
    [BindProperty] public int? TemplateId { get; set; }
    [BindProperty] public string EcuVariantId { get; set; } = "";
    [BindProperty] public string? EcuUniqueId { get; set; }
    [BindProperty] public string CsrMode { get; set; } = "generate";
    [BindProperty] public string? CommonName { get; set; }
    [BindProperty] public IFormFile? CsrFile { get; set; }
    public PkiResult? Result { get; set; }
    public string? GeneratedPrivateKey { get; set; }
    public string? GeneratedCsr { get; set; }

    public async Task OnGetAsync(CancellationToken ct) => await LoadAsync(ct);
    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        await LoadAsync(ct);
        var user = await session.CurrentAsync(User, ct);
        var template = Templates.SingleOrDefault(x => x.Id == TemplateId);
        if (user is null || template is null) ModelState.AddModelError(string.Empty, "请选择有效的证书模板。");
        if (!PkiService.IsValidVariantId(EcuVariantId, out var variantError)) ModelState.AddModelError(nameof(EcuVariantId), variantError);
        else EcuVariantId = System.Text.RegularExpressions.Regex.Replace(EcuVariantId, "\\s+", "");
        if (!PkiService.IsValidUniqueId(EcuUniqueId, out var uniqueError)) ModelState.AddModelError(nameof(EcuUniqueId), uniqueError);
        if (template?.RequiresEcuUniqueId == true && string.IsNullOrWhiteSpace(EcuUniqueId)) ModelState.AddModelError(nameof(EcuUniqueId), "当前 Claims 模板要求 ECU Unique ID。");
        string? csrText = null;
        if (CsrMode == "upload")
        {
            if (CsrFile is null || CsrFile.Length == 0) ModelState.AddModelError(nameof(CsrFile), "请选择 CSR 文件。");
            else if (CsrFile.Length > 128 * 1024) ModelState.AddModelError(nameof(CsrFile), "CSR 文件不能超过 128 KiB。");
            else using (var reader = new StreamReader(CsrFile.OpenReadStream())) csrText = await reader.ReadToEndAsync(ct);
            if (csrText is not null && !CsrService.VerifySignature(csrText)) ModelState.AddModelError(nameof(CsrFile), "CSR 格式无效或签名校验失败。");
        }
        else
        {
            if (string.IsNullOrWhiteSpace(CommonName)) ModelState.AddModelError(nameof(CommonName), "请输入 CSR Common Name。");
            if (ModelState.IsValid)
            {
                var generated = csrService.Generate(EcuVariantId, EcuUniqueId, CommonName!.Trim(), template!.CertType, template.TrustGrade, template.DiagUserRole); GeneratedPrivateKey = generated.PrivateKeyPem; GeneratedCsr = generated.CsrPem; csrText = generated.CsrPem;
            }
        }
        if (CsrMode == "upload" && csrText is not null)
        {
            if (template is not null)
            {
                if (!CsrService.VerifyAndMatch(csrText, template, EcuVariantId, EcuUniqueId, out var parsedCommonName, out var parsedUniqueId, out var csrError)) ModelState.AddModelError(nameof(CsrFile), csrError);
                else { CommonName = parsedCommonName; EcuUniqueId = parsedUniqueId; }
            }
        }
        if (!ModelState.IsValid || user is null || template is null) return Page();
        var sourceIp = HttpContext.Connection.RemoteIpAddress?.MapToIPv4().ToString() ?? "127.0.0.1";
        var response = await pki.ApplyAsync(user, template, csrText!, EcuVariantId, EcuUniqueId, CommonName ?? CsrService.ReadCommonName(csrText!), sourceIp, ct);
        Result = new(response.Success, response.Certificate, response.RequestId, response.Error);
        return Page();
    }
    private async Task LoadAsync(CancellationToken ct) => Templates = await db.PkiTemplates.Where(x => x.Active).OrderBy(x => x.EnvironmentName).ThenBy(x => x.DisplayName).ToListAsync(ct);
}
