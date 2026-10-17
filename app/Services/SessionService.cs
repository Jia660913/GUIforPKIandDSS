using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using ZfTools.Data;

namespace ZfTools.Services;

public sealed class SessionService(ToolDbContext db)
{
    public int UserId(ClaimsPrincipal principal) => int.Parse(principal.FindFirstValue(ClaimTypes.NameIdentifier)!);
    public ToolModule Module(ClaimsPrincipal principal) => Enum.Parse<ToolModule>(principal.FindFirstValue("module")!);
    public UserRole Role(ClaimsPrincipal principal) => Enum.Parse<UserRole>(principal.FindFirstValue(ClaimTypes.Role)!);
    public bool IsAdmin(ClaimsPrincipal principal) => Role(principal) == UserRole.Admin;

    public async Task<AppUser?> CurrentAsync(ClaimsPrincipal principal, CancellationToken ct = default)
    {
        if (!int.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var id)) return null;
        return await db.Users.Include(x => x.DssProject).SingleOrDefaultAsync(x => x.Id == id && x.Active, ct);
    }
}
