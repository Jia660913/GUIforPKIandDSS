using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using ZfTools.Data;
using ZfTools.Services;

namespace ZfTools.Pages.History;

public sealed record HistoryItem(DateTime When, string Kind, string Subject, string Detail, bool Success, string User);

public class HistoryModel(ToolDbContext db, SessionService session) : PageModel
{
    public bool IsAdmin { get; set; }
    public List<HistoryItem> Items { get; set; } = [];
    public async Task OnGetAsync(CancellationToken ct)
    {
        var user = await session.CurrentAsync(User, ct); if (user is null) return;
        IsAdmin = user.Role == UserRole.Admin;
        if (user.Module == ToolModule.Pki)
        {
            Items = await db.PkiApplications.AsNoTracking().Include(x => x.User).Include(x => x.Template)
                .Where(x => IsAdmin || x.UserId == user.Id)
                .OrderByDescending(x => x.CreatedAtUtc).Take(500)
                .Select(x => new HistoryItem(x.CreatedAtUtc, "PKI", x.Template!.DisplayName, $"Variant {x.EcuVariantId} · 请求 {x.RequestId}", x.Succeeded, x.User!.Username)).ToListAsync(ct);
        }
        else
        {
            Items = await db.DssSigningRecords.AsNoTracking().Include(x => x.User).Include(x => x.Project).Include(x => x.Key)
                .Where(x => IsAdmin || x.UserId == user.Id)
                .OrderByDescending(x => x.CreatedAtUtc).Take(500)
                .Select(x => new HistoryItem(x.CreatedAtUtc, "DSS", x.Key!.Name, $"{x.Project!.Code} · {x.InputMode} · {x.SignAlgorithm}", x.Succeeded, x.User!.Username)).ToListAsync(ct);
        }
    }
}
