using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using ZfTools.Data;
using ZfTools.Services;

namespace ZfTools.Pages.History;

public sealed record HistoryItem(long Id, DateTime When, string Kind, string Subject, string Detail, string Status, string User);
public sealed record HistoryDetails(long Id, string Kind, string Status, Dictionary<string, string> Fields, string? Input, string? Result);

public class HistoryModel(ToolDbContext db, SessionService session) : PageModel
{
    public bool IsAdmin { get; set; }
    public List<HistoryItem> Items { get; set; } = [];
    public HistoryDetails? Selected { get; set; }
    [BindProperty(SupportsGet = true)] public int PageNumber { get; set; } = 1;
    [BindProperty(SupportsGet = true)] public long? DetailId { get; set; }
    public int TotalCount { get; set; }
    public int PageCount => Math.Max(1, (TotalCount + 24) / 25);

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        var user = await session.CurrentAsync(User, ct);
        if (user is null) return Challenge();
        IsAdmin = user.Role == UserRole.Admin;
        var cutoff = DateTime.UtcNow.AddYears(-1);
        if (user.Module == ToolModule.Pki)
        {
            var query = db.PkiApplications.AsNoTracking().Where(x => (IsAdmin || x.UserId == user.Id) && x.CreatedAtUtc >= cutoff);
            TotalCount = await query.CountAsync(ct);
            PageNumber = Math.Clamp(PageNumber, 1, PageCount);
            var records = await query.Include(x => x.User).Include(x => x.Template).OrderByDescending(x => x.CreatedAtUtc).ThenByDescending(x => x.Id).Skip((PageNumber - 1) * 25).Take(25).ToListAsync(ct);
            Items = records.Select(x => new HistoryItem(x.Id, x.CreatedAtUtc, "PKI", Pick(x.TemplateNameSnapshot, x.Template?.DisplayName), $"{EnvironmentLabel(x.EnvironmentName)} · Variant {x.EcuVariantId}", x.Status, x.User?.Username ?? "Unavailable account")).ToList();
            if (DetailId is not null)
            {
                var r = await query.Include(x => x.Template).Include(x => x.User).SingleOrDefaultAsync(x => x.Id == DetailId, ct);
                if (r is null) return NotFound();
                Selected = new(r.Id, "PKI", r.Status, new()
                {
                    ["Account"] = r.User?.Username ?? "", ["Time (UTC)"] = r.CreatedAtUtc.ToString("u"),
                    ["Template"] = Pick(r.TemplateNameSnapshot, r.Template?.DisplayName), ["Supplier profile"] = r.CertProfileSnapshot,
                    ["Environment"] = EnvironmentLabel(r.EnvironmentName), ["Connection"] = r.ConnectionNameSnapshot,
                    ["Diagnostic role"] = r.RoleSnapshot, ["Trust grade"] = r.TrustGradeSnapshot,
                    ["Common Name"] = r.CommonName ?? "", ["ECU Variant ID"] = r.EcuVariantId,
                    ["ECU Unique ID"] = r.EcuUniqueId ?? "", ["CSR SHA-256"] = r.CsrSha256,
                    ["Tool request ID"] = r.RequestId ?? "", ["Supplier request ID"] = r.SupplierRequestId,
                    ["Error"] = r.ErrorMessage ?? ""
                }, null, r.CertificatePem);
            }
        }
        else
        {
            var query = db.DssSigningRecords.AsNoTracking().Where(x => (IsAdmin || x.UserId == user.Id) && x.CreatedAtUtc >= cutoff);
            TotalCount = await query.CountAsync(ct);
            PageNumber = Math.Clamp(PageNumber, 1, PageCount);
            var records = await query.Include(x => x.User).Include(x => x.Project).Include(x => x.Key).OrderByDescending(x => x.CreatedAtUtc).ThenByDescending(x => x.Id).Skip((PageNumber - 1) * 25).Take(25).ToListAsync(ct);
            Items = records.Select(x => new HistoryItem(x.Id, x.CreatedAtUtc, "DSS", Pick(x.KeyNameSnapshot, x.Key?.Name), $"{Pick(x.ProjectCodeSnapshot, x.Project?.Code)} · {EnvironmentLabel(x.EnvironmentName)} · {x.InputMode}", x.Status, x.User?.Username ?? "Unavailable account")).ToList();
            if (DetailId is not null)
            {
                var r = await query.Include(x => x.Key).Include(x => x.Project).Include(x => x.User).SingleOrDefaultAsync(x => x.Id == DetailId, ct);
                if (r is null) return NotFound();
                Selected = new(r.Id, "DSS", r.Status, new()
                {
                    ["Account"] = r.User?.Username ?? "", ["Time (UTC)"] = r.CreatedAtUtc.ToString("u"),
                    ["Project"] = Pick(r.ProjectCodeSnapshot, r.Project?.Code), ["Key"] = Pick(r.KeyNameSnapshot, r.Key?.Name),
                    ["Environment"] = EnvironmentLabel(r.EnvironmentName), ["Connection"] = r.ConnectionNameSnapshot,
                    ["Algorithm"] = r.SignAlgorithm, ["Input format"] = r.InputMode,
                    ["Input SHA-256 (audit only)"] = r.InputSha256 ?? "", ["Response authenticated"] = r.ResponseAuthenticated ? "Yes" : "No",
                    ["Signature verified"] = r.SignatureVerified ? "Yes" : "No", ["Error"] = r.ErrorMessage ?? ""
                }, r.InputValue, r.SignatureValue);
            }
        }
        return Page();
    }

    public async Task<IActionResult> OnGetDownloadAsync(long id, string kind, CancellationToken ct)
    {
        var user = await session.CurrentAsync(User, ct);
        if (user is null) return Challenge();
        var admin = user.Role == UserRole.Admin;
        var cutoff = DateTime.UtcNow.AddYears(-1);
        if (user.Module == ToolModule.Pki && kind == "certificate")
        {
            var r = await db.PkiApplications.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id && (admin || x.UserId == user.Id) && x.CreatedAtUtc >= cutoff, ct);
            if (r?.Status != "succeeded" || !r.Succeeded || string.IsNullOrWhiteSpace(r.CertificatePem)) return NotFound();
            return File(Encoding.UTF8.GetBytes(r.CertificatePem), "application/x-pem-file", $"certificate-{id}.pem");
        }
        if (user.Module == ToolModule.Dss && kind is "signature" or "input")
        {
            var r = await db.DssSigningRecords.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id && (admin || x.UserId == user.Id) && x.CreatedAtUtc >= cutoff, ct);
            if (r is null) return NotFound();
            if (kind == "input") return File(Encoding.UTF8.GetBytes(r.InputValue), "text/plain; charset=utf-8", $"input-{id}.txt");
            if (r.Status != "succeeded" || !r.SignatureVerified || !r.ResponseAuthenticated || string.IsNullOrWhiteSpace(r.SignatureValue)) return NotFound();
            return File(Encoding.UTF8.GetBytes(r.SignatureValue), "text/plain; charset=utf-8", $"signature-{id}.hex");
        }
        return NotFound();
    }

    public static string StatusLabel(string status) => status switch
    {
        "succeeded" => "Succeeded", "failed" => "Failed", "unknown" => "Outcome unknown", "pending" => "Pending",
        "demo" => "Demo · no supplier call", _ => "Legacy · not verified"
    };
    public static string EnvironmentLabel(string? value) => value switch { "development" => "Development", "production" => "Production", _ => "Not recorded" };
    private static string Pick(string snapshot, string? fallback) => string.IsNullOrWhiteSpace(snapshot) ? fallback ?? "Unavailable" : snapshot;
}