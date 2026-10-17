using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using ZfTools.Data;
using ZfTools.Services;

namespace ZfTools.Pages.Dss;

public sealed record DssResult(bool Success, string? Signature, string? Error);

[RequestSizeLimit(3 * 1024 * 1024)]
public class DssIndexModel(ToolDbContext db, SessionService session, DssService dss, IConfiguration configuration) : PageModel
{
    public DssProject? Project { get; set; }
    public bool IsDemoMode => configuration.GetValue<bool>("Suppliers:Dss:UseMock");
    public List<DssKey> Keys { get; set; } = [];
    [BindProperty] public int? KeyId { get; set; }
    [BindProperty] public string InputMode { get; set; } = "hash";
    [BindProperty] public string InputValue { get; set; } = "";
    public DssResult? Result { get; set; }
    public async Task<IActionResult> OnGetAsync(CancellationToken ct) { await LoadAsync(ct); return Page(); }
    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        await LoadAsync(ct);
        var user = await session.CurrentAsync(User, ct);
        if (user?.Module != ToolModule.Dss) return RedirectToPage("/Index");
        if (Project is null) ModelState.AddModelError(string.Empty, "当前账号尚未绑定项目。");
        if (InputValue.Length == 0) ModelState.AddModelError(nameof(InputValue), "请输入要签名的内容。");
        if (InputMode is not ("hash" or "text")) ModelState.AddModelError(nameof(InputMode), "请选择摘要或字符串输入模式。");
        if (InputMode == "hash" && (InputValue.Length % 2 != 0 || !InputValue.All(Uri.IsHexDigit))) ModelState.AddModelError(nameof(InputValue), "摘要必须是偶数位十六进制字符串。");
        if (!ModelState.IsValid) return Page();
        var result = await dss.SignAsync(user!, KeyId ?? 0, InputMode, InputValue, ct);
        Result = new(result.Success, result.Signature, result.Error);
        return Page();
    }
    private async Task LoadAsync(CancellationToken ct)
    {
        var user = await session.CurrentAsync(User, ct);
        if (user?.Module != ToolModule.Dss || user.DssProjectId is null) return;
        Project = await db.DssProjects.AsNoTracking().SingleOrDefaultAsync(x => x.Id == user.DssProjectId && x.Active, ct);
        if (Project is not null) Keys = await db.DssKeys.AsNoTracking().Where(x => x.DssProjectId == Project.Id && x.Active).OrderBy(x => x.Name).ToListAsync(ct);
    }
}
